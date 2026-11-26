/**
 * Real black-box Google Gemini CLI (`@google/gemini-cli`) harness driver.
 *
 * Wires the real `gemini` binary strictly via `hyp setup --harness gemini`, configuring
 * `security.auth.selectedType = "gemini-api-key"` in `<home>/.gemini/settings.json` and
 * routing model requests to our loopback `LlmShimServer` via `GOOGLE_GEMINI_BASE_URL`
 * + `GEMINI_API_KEY` (zero cloud auth, zero outbound network calls!).
 */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { resolveToolBinary } from "../../scripts/provision.mjs";
import type { HypCli } from "../hyp-cli.ts";
import type { LlmShimServer } from "../llm-shim/index.ts";
import type { Sandbox, TrackedProcess } from "../sandbox.ts";
import {
  extractSessionsFromInspect,
  type HarnessBootOptions,
  type HarnessRuntime,
  type RealHarnessAdapter,
} from "./types.ts";

export function resolveGeminiBin(): string | null {
  const info = resolveToolBinary("gemini", { useHostBins: false, probeVersion: false });
  if (info.path) return info.path;
  const hostInfo = resolveToolBinary("gemini", { useHostBins: true, probeVersion: false });
  return hostInfo.path;
}

export interface GeminiRunResult {
  exitCode: number | null;
  sessionId: string | null;
  stdout: string;
  stderr: string;
  events: any[];
  finalText: string;
}

function parseStreamJson(stdout: string): any[] {
  const events: any[] = [];
  for (const raw of stdout.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || !line.startsWith("{")) continue;
    try {
      events.push(JSON.parse(line));
    } catch {
      // ignore non-JSON lines
    }
  }
  return events;
}

export class GeminiHarness {
  readonly sandbox: Sandbox;
  readonly hyp: HypCli;
  readonly shim: LlmShimServer;
  readonly geminiBin: string;
  readonly homeDir: string;
  readonly settingsPath: string;
  readonly role: string;
  readonly env: Record<string, string>;

  private constructor(init: {
    sandbox: Sandbox;
    hyp: HypCli;
    shim: LlmShimServer;
    geminiBin: string;
    homeDir: string;
    settingsPath: string;
    role: string;
    env: Record<string, string>;
  }) {
    this.sandbox = init.sandbox;
    this.hyp = init.hyp;
    this.shim = init.shim;
    this.geminiBin = init.geminiBin;
    this.homeDir = init.homeDir;
    this.settingsPath = init.settingsPath;
    this.role = init.role;
    this.env = init.env;
  }

  static async create(options: {
    sandbox: Sandbox;
    hyp: HypCli;
    shim: LlmShimServer;
    geminiBin?: string;
    role?: string;
    profileHomeDir?: string;
    runSetup?: boolean;
  }): Promise<GeminiHarness> {
    const geminiBin = options.geminiBin ?? resolveGeminiBin();
    if (!geminiBin) {
      throw new Error(
        "gemini binary not found (run `node itest/scripts/provision.mjs --tools gemini` or set GEMINI_BIN)",
      );
    }

    const role = options.role ?? "gemini";
    const homeDir = options.profileHomeDir ?? options.sandbox.paths.homeDir;
    fs.mkdirSync(homeDir, { recursive: true, mode: 0o700 });

    if (options.runSetup !== false) {
      await options.hyp.exec([
        "setup",
        "--harness",
        "gemini",
        "--home",
        homeDir,
        "--state-dir",
        options.sandbox.paths.hyphaeStateDir,
        "--bin",
        options.hyp.bin,
        "--socket",
        options.hyp.socketPath,
        "--no-skills",
        "--no-commands",
        "--json",
      ]);
    }

    const settingsPath = path.join(homeDir, ".gemini", "settings.json");
    const settings = fs.existsSync(settingsPath)
      ? JSON.parse(fs.readFileSync(settingsPath, "utf8"))
      : {};
    settings.security = {
      ...(settings.security || {}),
      auth: {
        ...(settings.security?.auth || {}),
        selectedType: "gemini-api-key",
      },
    };
    // Strictly assert `hyp setup --harness gemini` wrote `"timeout": 10000` (ms) on all 4 hooks (#31)!
    if (options.runSetup !== false) {
      for (const ev of ["BeforeAgent", "BeforeTool", "AfterTool", "AfterAgent"]) {
        const groups = settings.hooks?.[ev];
        if (!Array.isArray(groups) || groups.length === 0) {
          throw new Error(`hyp setup --harness gemini missing hook '${ev}' in ${settingsPath}`);
        }
        const timeouts = groups.flatMap((g: any) =>
          (Array.isArray(g?.hooks) ? g.hooks : []).map((hk: any) => hk?.timeout),
        );
        if (timeouts.length === 0 || timeouts.some((t: unknown) => t !== 10_000)) {
          throw new Error(
            `Expected hyp setup --harness gemini to write timeout=10000ms on hook '${ev}', got: ${JSON.stringify(timeouts)}`,
          );
        }
      }
    }
    fs.writeFileSync(settingsPath, JSON.stringify(settings, null, 2) + "\n");

    const env = options.sandbox.envWith({
      HOME: homeDir,
      GEMINI_CLI_HOME: homeDir,
      GOOGLE_GEMINI_BASE_URL: options.shim.roleBaseUrl(role),
      GEMINI_API_KEY: `itest-gemini-${role}`,
      HYPHAE_SOCKET: options.hyp.socketPath,
      PATH: `${path.dirname(geminiBin)}${path.delimiter}${options.sandbox.env.PATH}`,
    });

    return new GeminiHarness({
      sandbox: options.sandbox,
      hyp: options.hyp,
      shim: options.shim,
      geminiBin,
      homeDir,
      settingsPath,
      role,
      env,
    });
  }

  spawnPrint(
    prompt: string,
    options: {
      sessionId?: string;
      resume?: string | boolean;
      model?: string;
      cwd?: string;
      label?: string;
      timeoutMs?: number;
      extraArgs?: string[];
    } = {},
  ): { sessionId: string; proc: TrackedProcess; done: Promise<GeminiRunResult> } {
    const sessionId = options.sessionId ?? crypto.randomUUID();
    const args = [
      "-p",
      prompt,
      "--yolo",
      "--skip-trust",
      "--model",
      options.model ?? "gemini-2.5-pro",
      "--output-format",
      "stream-json",
    ];
    if (options.resume) {
      args.push("--resume", typeof options.resume === "string" ? options.resume : "latest");
    } else {
      args.push("--session-id", sessionId);
    }
    if (options.extraArgs) {
      args.push(...options.extraArgs);
    }

    const proc = this.sandbox.reaper.spawn(
      options.label ?? `gemini-${this.role}`,
      this.geminiBin,
      args,
      {
        env: this.env,
        cwd: options.cwd ?? this.sandbox.paths.workspaceDir,
        stdio: ["ignore", "pipe", "pipe"],
      },
    );

    const timeoutMs = options.timeoutMs ?? 45_000;
    const done = (async (): Promise<GeminiRunResult> => {
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
          `gemini (${this.role}) timed out after ${timeoutMs}ms\nSTDOUT:\n${proc.stdout.slice(-2000)}\nSTDERR:\n${proc.stderr.slice(-2000)}`,
        );
      }

      const events = parseStreamJson(proc.stdout);
      const initEv = events.find((e) => e?.type === "init");
      const observedSessionId =
        typeof initEv?.session_id === "string" ? initEv.session_id : sessionId;
      const finalText = events
        .filter((e) => e?.type === "message" && e?.role === "assistant" && typeof e?.content === "string")
        .map((e) => e.content)
        .join("");

      return {
        exitCode: proc.exitCode,
        sessionId: observedSessionId,
        stdout: proc.stdout,
        stderr: proc.stderr,
        events,
        finalText,
      };
    })();

    return { sessionId, proc, done };
  }

  async runPrint(
    prompt: string,
    options: Parameters<GeminiHarness["spawnPrint"]>[1] = {},
  ): Promise<GeminiRunResult> {
    const { done } = this.spawnPrint(prompt, options);
    return done;
  }
}

export const geminiAdapter: RealHarnessAdapter = {
  id: "gemini",
  displayName: "Gemini CLI",
  capabilities: {
    nativePushWake: false,
    nudgeOnlyWake: false,
    midStreamInterrupt: false,
    hookToolBoundaries: true,
    explicitHookProvenance: true,
    supportsMultiTurnSession: true,
  },

  checkAvailability(): string | null {
    return resolveGeminiBin()
      ? null
      : "gemini binary not found (run `node itest/scripts/provision.mjs --tools gemini` or set GEMINI_BIN)";
  },

  async boot(options: HarnessBootOptions): Promise<HarnessRuntime> {
    const geminiBin = resolveGeminiBin();
    if (!geminiBin) {
      throw new Error("gemini binary not found");
    }
    await options.hyp.onboard({ nodeId: options.nodeId, noSkills: true, noCommands: true });
    await options.hyp.startDaemon();

    const harnessesByRole = new Map<string, GeminiHarness>();
    const getOrCreate = async (role: string): Promise<GeminiHarness> => {
      let inst = harnessesByRole.get(role);
      if (!inst) {
        const profileHome =
          role === options.role
            ? options.sandbox.paths.homeDir
            : path.join(options.sandbox.paths.rootDir, `gem-home-${role}`);
        inst = await GeminiHarness.create({
          sandbox: options.sandbox,
          hyp: options.hyp,
          shim: options.shim,
          geminiBin,
          role,
          profileHomeDir: profileHome,
        });
        harnessesByRole.set(role, inst);
      }
      return inst;
    };

    const runtime: HarnessRuntime = {
      adapter: geminiAdapter,
      sandbox: options.sandbox,
      hyp: options.hyp,
      shim: options.shim,

      async enrollSession(opts) {
        const gem = await getOrCreate(opts.role);
        const uuid = crypto.randomUUID();
        const tag = opts.tag ?? `SESSION_${opts.handle.toUpperCase()}`;
        const res = await gem.runPrint(`${tag} enroll in mesh as ${opts.handle}`, {
          sessionId: uuid,
        });
        if (res.exitCode !== 0) {
          throw new Error(
            `Gemini enrollSession(${opts.handle}) failed (exit=${res.exitCode}): ${res.stderr}`,
          );
        }
        const ins = await options.hyp.inspect({ handle: opts.handle, allowFailure: true });
        const row = extractSessionsFromInspect(ins.json)[0];
        const sid = row?.sessionId ?? `gemini:${res.sessionId ?? uuid}`;
        return {
          role: opts.role,
          handle: opts.handle,
          sessionId: sid,
          nativeId: res.sessionId ?? uuid,
          tag,
        };
      },

      async runTurn(session, prompt, opts) {
        const gem = await getOrCreate(session.role);
        const res = await gem.runPrint(prompt, {
          resume: session.nativeId,
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
          const gem = await getOrCreate(session.role);
          const { done: p } = gem.spawnPrint(prompt, {
            resume: session.nativeId,
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
        // Per-turn gemini CLI processes already exited cleanly.
      },
    };

    return runtime;
  },
};
