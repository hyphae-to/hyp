/**
 * Real black-box Codex CLI (`codex`) harness driver.
 *
 * Wires the real `codex` binary strictly via `hyp setup --harness codex` + `$CODEX_HOME/config.toml`
 * pointing `[model_providers.fakebrain]` to our loopback `LlmShimServer` (`wire_api = "responses"`).
 *
 * Supports:
 *  - Non-interactive `codex exec --json` + `codex exec resume <threadId>`
 *  - Live interactive `codex` inside a real POSIX PTY (`spawnInPty`) for live `codex queue --thread <uuid>` wakeups!
 */

import { parseJsonLines } from "../util.ts";
import fs from "node:fs";
import path from "node:path";
import { resolveToolBinary } from "../../scripts/provision.mjs";
import type { HypCli } from "../hyp-cli.ts";
import type { LlmShimServer } from "../llm-shim/index.ts";
import { spawnInPty, type PtyProcess } from "../pty.ts";
import type { Sandbox, TrackedProcess } from "../sandbox.ts";
import {
  extractSessionsFromInspect,
  type HarnessBootOptions,
  type HarnessRuntime,
  type RealHarnessAdapter,
} from "./types.ts";

export function resolveCodexBin(): string | null {
  const info = resolveToolBinary("codex", { useHostBins: true, probeVersion: false });
  return info.path;
}

type CodexExecEvent = { type?: string; thread_id?: string; item?: { type?: string; text?: unknown } };

export interface CodexExecResult {
  exitCode: number | null;
  threadId: string | null;
  stdout: string;
  stderr: string;
  events: CodexExecEvent[];
  finalText: string;
}

/** Recursively locates rollout JSONL files under `$CODEX_HOME/sessions/`. */
export function findCodexRolloutFiles(codexHome: string): string[] {
  const root = path.join(codexHome, "sessions");
  if (!fs.existsSync(root)) return [];
  const results: string[] = [];
  const walk = (dir: string) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.isFile() && entry.name.endsWith(".jsonl")) results.push(full);
    }
  };
  walk(root);
  return results;
}

export class CodexHarness {
  readonly sandbox: Sandbox;
  readonly hyp: HypCli;
  readonly shim: LlmShimServer;
  readonly codexBin: string;
  readonly codexHome: string;
  readonly configPath: string;
  readonly hooksPath: string;
  readonly role: string;
  readonly env: Record<string, string>;

  private constructor(init: {
    sandbox: Sandbox;
    hyp: HypCli;
    shim: LlmShimServer;
    codexBin: string;
    codexHome: string;
    configPath: string;
    hooksPath: string;
    role: string;
    env: Record<string, string>;
  }) {
    this.sandbox = init.sandbox;
    this.hyp = init.hyp;
    this.shim = init.shim;
    this.codexBin = init.codexBin;
    this.codexHome = init.codexHome;
    this.configPath = init.configPath;
    this.hooksPath = init.hooksPath;
    this.role = init.role;
    this.env = init.env;
  }

  static async create(options: {
    sandbox: Sandbox;
    hyp: HypCli;
    shim: LlmShimServer;
    codexBin?: string;
    role?: string;
    codexHome?: string;
    runSetup?: boolean;
    extraEnv?: Record<string, string>;
  }): Promise<CodexHarness> {
    const codexBin = options.codexBin ?? resolveCodexBin();
    if (!codexBin) {
      throw new Error("codex binary not found (set CODEX_BIN or install @openai/codex)");
    }

    const role = options.role ?? "codex";
    const codexHome = options.codexHome ?? path.join(options.sandbox.paths.homeDir, ".codex");
    fs.mkdirSync(codexHome, { recursive: true, mode: 0o700 });

    if (options.runSetup !== false) {
      await options.hyp.setup("codex", {
        noSkills: true,
        noCommands: true,
      });
    }

    const defaultCodexHome = path.join(options.sandbox.paths.homeDir, ".codex");
    const configPath = path.join(codexHome, "config.toml");
    const hooksPath = path.join(codexHome, "hooks.json");

    // If using a distinct profile `codexHome` inside sandbox, mirror the `hyp setup` files into it.
    if (codexHome !== defaultCodexHome) {
      for (const rel of ["config.toml", "hooks.json"]) {
        const src = path.join(defaultCodexHome, rel);
        const dst = path.join(codexHome, rel);
        if (fs.existsSync(src) && !fs.existsSync(dst)) {
          fs.copyFileSync(src, dst);
        }
      }
    }

    const existingToml = fs.existsSync(configPath) ? fs.readFileSync(configPath, "utf8") : "";
    const cleanedExisting = existingToml.replace(
      /^# >>> fakebrain >>>[\s\S]*?# <<< fakebrain <<<\n*/m,
      "",
    );
    const fakeBrainBlock = [
      "# >>> fakebrain >>>",
      'model_provider = "fakebrain"',
      'model = "gpt-5-shim"',
      "",
      "[model_providers.fakebrain]",
      'name = "FakeBrain"',
      `base_url = "${options.shim.roleBaseUrl(role)}/v1"`,
      'wire_api = "responses"',
      'env_key = "FAKEBRAIN_API_KEY"',
      "# <<< fakebrain <<<",
      "",
    ].join("\n");
    fs.writeFileSync(configPath, `${fakeBrainBlock}\n${cleanedExisting}`);

    const env = options.sandbox.envWith({
      CODEX_HOME: codexHome,
      FAKEBRAIN_API_KEY: `sk-itest-${role}`,
      HYPHAE_SOCKET: options.hyp.socketPath,
      PATH: `${path.dirname(codexBin)}${path.delimiter}${options.sandbox.env.PATH}`,
      ...(options.extraEnv ?? {}),
    });

    return new CodexHarness({
      sandbox: options.sandbox,
      hyp: options.hyp,
      shim: options.shim,
      codexBin,
      codexHome,
      configPath,
      hooksPath,
      role,
      env,
    });
  }

  /** Spawns a non-interactive `codex exec` (or `codex exec resume <threadId>`) process. */
  spawnExec(
    prompt: string,
    options: {
      resumeThreadId?: string;
      cwd?: string;
      label?: string;
      timeoutMs?: number;
      extraArgs?: string[];
    } = {},
  ): { proc: TrackedProcess; done: Promise<CodexExecResult> } {
    const args = options.resumeThreadId
      ? [
          "exec",
          "resume",
          "--skip-git-repo-check",
          "--dangerously-bypass-approvals-and-sandbox",
          "--dangerously-bypass-hook-trust",
          "--json",
          ...(options.extraArgs ?? []),
          options.resumeThreadId,
          prompt,
        ]
      : [
          "exec",
          "--skip-git-repo-check",
          "--dangerously-bypass-approvals-and-sandbox",
          "--dangerously-bypass-hook-trust",
          "--json",
          ...(options.extraArgs ?? []),
          prompt,
        ];

    const proc = this.sandbox.reaper.spawn(
      options.label ?? `codex-${this.role}`,
      this.codexBin,
      args,
      {
        env: this.env,
        cwd: options.cwd ?? this.sandbox.paths.workspaceDir,
        stdio: ["ignore", "pipe", "pipe"],
      },
    );

    const timeoutMs = options.timeoutMs ?? 45_000;
    const done = (async (): Promise<CodexExecResult> => {
      let timedOut = false;
      const timer = setTimeout(() => {
        timedOut = true;
        void this.sandbox.reaper.kill(proc, 1_500);
      }, timeoutMs);

      try {
        await proc.exitPromise;
      } finally {
        clearTimeout(timer);
      }

      if (timedOut) {
        throw new Error(
          `codex exec (${this.role}) timed out after ${timeoutMs}ms\nSTDOUT:\n${proc.stdout.slice(-3000)}\nSTDERR:\n${proc.stderr.slice(-3000)}`,
        );
      }

      const events = parseJsonLines<CodexExecEvent>(proc.stdout);
      const started = events.find((e) => e?.type === "thread.started");
      const threadId =
        typeof started?.thread_id === "string"
          ? started.thread_id
          : options.resumeThreadId ?? null;
      const agentMessages = events
        .filter((e) => e?.type === "item.completed" && e?.item?.type === "agent_message")
        .map((e) => String(e?.item?.text ?? ""));
      return {
        exitCode: proc.exitCode,
        threadId,
        stdout: proc.stdout,
        stderr: proc.stderr,
        events,
        finalText: agentMessages.join("\n"),
      };
    })();

    return { proc, done };
  }

  async runExec(
    prompt: string,
    options: Parameters<CodexHarness["spawnExec"]>[1] = {},
  ): Promise<CodexExecResult> {
    const { done } = this.spawnExec(prompt, options);
    return done;
  }

  /**
   * Launches an interactive `codex` TUI inside a real POSIX PTY so `hyp daemon` can
   * wake the live thread via real `codex queue --thread <uuid> --message <nudge>`.
   */
  spawnInteractivePty(
    initialPrompt: string,
    options: {
      label?: string;
      cwd?: string;
      extraArgs?: string[];
    } = {},
  ): PtyProcess {
    return spawnInPty(
      this.sandbox,
      options.label ?? `codex-pty-${this.role}`,
      this.codexBin,
      [
        "--dangerously-bypass-approvals-and-sandbox",
        "--dangerously-bypass-hook-trust",
        "--no-alt-screen",
        ...(options.extraArgs ?? []),
        initialPrompt,
      ],
      {
        env: { ...this.env, TERM: "xterm-256color" },
        cwd: options.cwd ?? this.sandbox.paths.workspaceDir,
      },
    );
  }
}

export const codexAdapter: RealHarnessAdapter = {
  id: "codex",
  displayName: "Codex CLI",
  capabilities: {
    nativePushWake: false,
    nudgeOnlyWake: false,
    midStreamInterrupt: false,
    hookToolBoundaries: true,
    explicitHookProvenance: true,
    supportsMultiTurnSession: true,
  },

  checkAvailability(): string | null {
    return resolveCodexBin() ? null : "codex binary not found (set CODEX_BIN)";
  },

  async boot(options: HarnessBootOptions): Promise<HarnessRuntime> {
    const codexBin = resolveCodexBin();
    if (!codexBin) {
      throw new Error("codex binary not found");
    }
    // Non-interactive `codex exec` rollouts are natively guarded against `codex_queue`
    // auto-attach (#35). Live interactive PTY `codex queue --thread` push wakeups are
    // tested end-to-end in `itest/suites/codex.test.ts`.
    await options.hyp.onboard({ nodeId: options.nodeId, noSkills: true, noCommands: true });
    await options.hyp.startDaemon();
    await options.hyp.setup("codex", { noSkills: true, noCommands: true });

    const harnessesByRole = new Map<string, CodexHarness>();
    const getOrCreate = async (role: string): Promise<CodexHarness> => {
      let inst = harnessesByRole.get(role);
      if (!inst) {
        inst = await CodexHarness.create({
          sandbox: options.sandbox,
          hyp: options.hyp,
          shim: options.shim,
          codexBin,
          role,
          codexHome:
            role === options.role
              ? path.join(options.sandbox.paths.homeDir, ".codex")
              : path.join(options.sandbox.paths.homeDir, `.codex-${role}`),
          runSetup: false,
        });
        harnessesByRole.set(role, inst);
      }
      return inst;
    };

    const runtime: HarnessRuntime = {
      adapter: codexAdapter,
      sandbox: options.sandbox,
      hyp: options.hyp,
      shim: options.shim,

      async enrollSession(opts) {
        const cx = await getOrCreate(opts.role);
        const tag = opts.tag ?? `SESSION_${opts.handle.toUpperCase()}`;
        const res = await cx.runExec(`${tag} enroll in mesh as ${opts.handle}`);
        if (res.exitCode !== 0 || !res.threadId) {
          throw new Error(
            `Codex enrollSession(${opts.handle}) failed (exit=${res.exitCode}, threadId=${res.threadId}): ${res.stderr}`,
          );
        }
        // Verify daemon recorded `codex:<uuid>` session.
        const ins = await options.hyp.inspect({ handle: opts.handle, allowFailure: true });
        const row = extractSessionsFromInspect(ins.json)[0];
        return {
          role: opts.role,
          handle: opts.handle,
          sessionId: row?.sessionId ?? `codex:${res.threadId}`,
          nativeId: res.threadId,
          tag,
        };
      },

      async runTurn(session, prompt, opts) {
        const cx = await getOrCreate(session.role);
        const res = await cx.runExec(prompt, {
          resumeThreadId: session.nativeId,
          timeoutMs: opts?.timeoutMs ?? 45_000,
        });
        return {
          ok: res.exitCode === 0,
          exitCode: res.exitCode,
          finalText: res.finalText,
          stdout: res.stdout,
          stderr: res.stderr,
        };
      },

      startTurn(session, prompt, opts) {
        const done = (async () => {
          const cx = await getOrCreate(session.role);
          const { done: p } = cx.spawnExec(prompt, {
            resumeThreadId: session.nativeId,
            timeoutMs: opts?.timeoutMs ?? 45_000,
          });
          const res = await p;
          return {
            ok: res.exitCode === 0,
            exitCode: res.exitCode,
            finalText: res.finalText,
            stdout: res.stdout,
            stderr: res.stderr,
          };
        })();
        return { done };
      },

      async deliverPending(session, opts) {
        await runtime.runTurn(session, opts?.prompt ?? `${session.tag} check pending inbox`, {
          timeoutMs: opts?.timeoutMs ?? 45_000,
        });
      },

      async close() {
        // Per-turn codex exec processes already exited cleanly.
      },
    };

    return runtime;
  },
};
