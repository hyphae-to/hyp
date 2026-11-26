/**
 * Real black-box Claude Code (`claude`) harness driver.
 *
 * Launches real `claude -p --session-id <uuid>` (and `--resume <uuid>`) processes pointed at
 * our loopback `LlmShimServer` via `ANTHROPIC_BASE_URL` with an isolated `CLAUDE_CONFIG_DIR`
 * configured strictly via `hyp setup --harness claude`.
 */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { resolveToolBinary } from "../../scripts/provision.mjs";
import type { HypCli } from "../hyp-cli.ts";
import type { LlmShimServer } from "../llm-shim/index.ts";
import type { Sandbox, TrackedProcess } from "../sandbox.ts";
import type {
  HarnessBootOptions,
  HarnessRuntime,
  RealHarnessAdapter,
} from "./types.ts";

export function resolveClaudeBin(): string | null {
  const info = resolveToolBinary("claude", { useHostBins: true, probeVersion: false });
  return info.path;
}

export interface ClaudeRunResult {
  exitCode: number | null;
  stdout: string;
  stderr: string;
  events: any[];
  hookEvents: any[];
  resultEvent: any | null;
  finalText: string;
}

function parseStreamJsonLines(stdout: string): any[] {
  const events: any[] = [];
  for (const rawLine of stdout.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || !line.startsWith("{")) continue;
    try {
      events.push(JSON.parse(line));
    } catch {
      // ignore non-JSON lines
    }
  }
  return events;
}

export class ClaudeHarness {
  readonly sandbox: Sandbox;
  readonly hyp: HypCli;
  readonly shim: LlmShimServer;
  readonly claudeBin: string;
  readonly configDir: string;
  readonly role: string;
  readonly env: Record<string, string>;

  private constructor(init: {
    sandbox: Sandbox;
    hyp: HypCli;
    shim: LlmShimServer;
    claudeBin: string;
    configDir: string;
    role: string;
    env: Record<string, string>;
  }) {
    this.sandbox = init.sandbox;
    this.hyp = init.hyp;
    this.shim = init.shim;
    this.claudeBin = init.claudeBin;
    this.configDir = init.configDir;
    this.role = init.role;
    this.env = init.env;
  }

  static async create(options: {
    sandbox: Sandbox;
    hyp: HypCli;
    shim: LlmShimServer;
    claudeBin?: string;
    role?: string;
    profileName?: string;
    runSetup?: boolean;
    extraEnv?: Record<string, string>;
  }): Promise<ClaudeHarness> {
    const claudeBin = options.claudeBin ?? resolveClaudeBin();
    if (!claudeBin) {
      throw new Error("claude binary not found (set CLAUDE_BIN or install Claude Code)");
    }

    const role = options.role ?? "claude";
    // Use an isolated profile dir distinct from `$HOME/.claude` so BOTH `hyp setup --claude-config-dir`
    // and real `claude` with `CLAUDE_CONFIG_DIR` agree on `<configDir>/.claude.json` and `<configDir>/settings.json`.
    const profileSlug = options.profileName ?? `claude-${role}`;
    const configDir = path.join(options.sandbox.paths.homeDir, `.${profileSlug}`);
    fs.mkdirSync(configDir, { recursive: true, mode: 0o700 });

    if (options.runSetup !== false) {
      await options.hyp.setup("claude", {
        claudeConfigDir: configDir,
        noSkills: true,
        noCommands: true,
      });
    }

    // Mark onboarding completed in `<configDir>/.claude.json` without clobbering `mcpServers` written by `hyp setup`.
    const claudeJsonPath = path.join(configDir, ".claude.json");
    let claudeJson: Record<string, any> = {};
    try {
      if (fs.existsSync(claudeJsonPath)) {
        claudeJson = JSON.parse(fs.readFileSync(claudeJsonPath, "utf8"));
      }
    } catch {
      claudeJson = {};
    }
    claudeJson.hasCompletedOnboarding = true;
    claudeJson.numStartups = 1;
    claudeJson.projects = {
      ...(claudeJson.projects || {}),
      [options.sandbox.paths.workspaceDir]: {
        allowedTools: [],
        hasTrustDialogAccepted: true,
        hasCompletedProjectOnboarding: true,
        ...((claudeJson.projects || {})[options.sandbox.paths.workspaceDir] || {}),
      },
    };
    fs.writeFileSync(claudeJsonPath, JSON.stringify(claudeJson, null, 2) + "\n");

    const env = options.sandbox.envWith({
      CLAUDE_CONFIG_DIR: configDir,
      ANTHROPIC_BASE_URL: options.shim.roleBaseUrl(role),
      ANTHROPIC_API_KEY: `sk-ant-itest-${role}`,
      CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1",
      DISABLE_AUTOUPDATER: "1",
      DISABLE_TELEMETRY: "1",
      DISABLE_ERROR_REPORTING: "1",
      HYPHAE_SOCKET: options.hyp.socketPath,
      PATH: `${path.dirname(claudeBin)}${path.delimiter}${options.sandbox.env.PATH}`,
      ...(options.extraEnv ?? {}),
    });

    return new ClaudeHarness({
      sandbox: options.sandbox,
      hyp: options.hyp,
      shim: options.shim,
      claudeBin,
      configDir,
      role,
      env,
    });
  }

  /**
   * Spawns a real headless `claude -p` run (`--output-format stream-json --verbose --include-hook-events`)
   * and returns the `TrackedProcess` plus a completion promise so tests can coordinate with `llm-shim` gates!
   */
  spawnPrint(
    prompt: string,
    options: {
      sessionId?: string;
      resume?: boolean;
      maxTurns?: number;
      model?: string;
      tools?: string;
      cwd?: string;
      label?: string;
      extraArgs?: string[];
      timeoutMs?: number;
    } = {},
  ): { sessionId: string; proc: TrackedProcess; done: Promise<ClaudeRunResult> } {
    const sessionId = options.sessionId ?? crypto.randomUUID();
    const args = [
      "-p",
      prompt,
      "--dangerously-skip-permissions",
      "--output-format",
      "stream-json",
      "--verbose",
      "--include-hook-events",
      "--max-turns",
      String(options.maxTurns ?? 12),
      "--model",
      options.model ?? "claude-sonnet-4-5",
    ];
    if (options.resume) {
      args.push("--resume", sessionId);
    } else {
      args.push("--session-id", sessionId);
    }
    if (options.tools !== undefined) {
      args.push("--tools", options.tools);
    }
    if (options.extraArgs) {
      args.push(...options.extraArgs);
    }

    const proc = this.sandbox.reaper.spawn(
      options.label ?? `claude-${this.role}`,
      this.claudeBin,
      args,
      {
        env: this.env,
        cwd: options.cwd ?? this.sandbox.paths.workspaceDir,
        stdio: ["ignore", "pipe", "pipe"],
      },
    );

    const timeoutMs = options.timeoutMs ?? 60_000;
    const done = (async (): Promise<ClaudeRunResult> => {
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
          `claude (${this.role}) timed out after ${timeoutMs}ms\nSTDOUT:\n${proc.stdout.slice(-3000)}\nSTDERR:\n${proc.stderr.slice(-3000)}`,
        );
      }

      const events = parseStreamJsonLines(proc.stdout);
      const hookEvents = events.filter(
        (e) => e?.type === "system" && typeof e?.subtype === "string" && e.subtype.includes("hook"),
      );
      const resultEvent = [...events].reverse().find((e) => e?.type === "result") ?? null;
      const finalText =
        typeof resultEvent?.result === "string"
          ? resultEvent.result
          : events
              .filter((e) => e?.type === "assistant")
              .flatMap((e) => e?.message?.content ?? [])
              .filter((b: any) => b?.type === "text" && typeof b?.text === "string")
              .map((b: any) => b.text)
              .join("");

      return {
        exitCode: proc.exitCode,
        stdout: proc.stdout,
        stderr: proc.stderr,
        events,
        hookEvents,
        resultEvent,
        finalText,
      };
    })();

    return { sessionId, proc, done };
  }

  async runPrint(
    prompt: string,
    options: Parameters<ClaudeHarness["spawnPrint"]>[1] = {},
  ): Promise<ClaudeRunResult & { sessionId: string }> {
    const { sessionId, done } = this.spawnPrint(prompt, options);
    const res = await done;
    return { ...res, sessionId };
  }
}

export const claudeAdapter: RealHarnessAdapter = {
  id: "claude",
  displayName: "Claude Code CLI",
  capabilities: {
    nativePushWake: false,
    nudgeOnlyWake: false,
    midStreamInterrupt: false,
    hookToolBoundaries: true,
    explicitHookProvenance: true,
    supportsMultiTurnSession: true,
  },

  checkAvailability(): string | null {
    return resolveClaudeBin() ? null : "claude binary not found (set CLAUDE_BIN)";
  },

  async boot(options: HarnessBootOptions): Promise<HarnessRuntime> {
    await options.hyp.onboard({ nodeId: options.nodeId, noSkills: true, noCommands: true });
    await options.hyp.startDaemon();

    const harnessesByRole = new Map<string, ClaudeHarness>();
    const getOrCreateHarness = async (role: string): Promise<ClaudeHarness> => {
      let inst = harnessesByRole.get(role);
      if (!inst) {
        inst = await ClaudeHarness.create({
          sandbox: options.sandbox,
          hyp: options.hyp,
          shim: options.shim,
          role,
          profileName: `claude-${role}`,
        });
        harnessesByRole.set(role, inst);
      }
      return inst;
    };

    const runtime: HarnessRuntime = {
      adapter: claudeAdapter,
      sandbox: options.sandbox,
      hyp: options.hyp,
      shim: options.shim,

      async enrollSession(opts) {
        const claude = await getOrCreateHarness(opts.role);
        const uuid = crypto.randomUUID();
        const tag = opts.tag ?? `SESSION_${opts.handle.toUpperCase()}`;
        const res = await claude.runPrint(`${tag} enroll in mesh as ${opts.handle}`, {
          sessionId: uuid,
          maxTurns: 8,
        });
        if (res.exitCode !== 0) {
          throw new Error(`Claude enrollSession(${opts.handle}) failed (exit=${res.exitCode}): ${res.stderr}`);
        }
        return {
          role: opts.role,
          handle: opts.handle,
          sessionId: `claude:${uuid}`,
          nativeId: uuid,
          tag,
        };
      },

      async runTurn(session, prompt, opts) {
        const claude = await getOrCreateHarness(session.role);
        const res = await claude.runPrint(prompt, {
          sessionId: session.nativeId,
          resume: true,
          maxTurns: opts?.maxTurns ?? 10,
          timeoutMs: opts?.timeoutMs ?? 60_000,
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
          const claude = await getOrCreateHarness(session.role);
          const run = claude.spawnPrint(prompt, {
            sessionId: session.nativeId,
            resume: true,
            maxTurns: opts?.maxTurns ?? 10,
            timeoutMs: opts?.timeoutMs ?? 60_000,
          });
          const res = await run.done;
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
          maxTurns: 8,
          timeoutMs: opts?.timeoutMs ?? 45_000,
        });
      },

      async close() {
        // Per-turn CLI processes already exited cleanly.
      },
    };

    return runtime;
  },
};
