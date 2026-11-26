/**
 * Real black-box OpenCode (`opencode`) harness driver.
 *
 * Wires real `opencode` (`v2.3.2+`) strictly via `hyp setup --harness opencode` + `OPENCODE_CONFIG`
 * pointing the OpenAI-compatible provider to our loopback `LlmShimServer`.
 *
 * Also exposes `opencodeAdapter: RealHarnessAdapter` (honestly checking OpenCode v2.3.2 plugin
 * compatibility so parity-matrix tracks upstream/Hyphae plugin-API regressions transparently).
 */

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

export function resolveOpenCodeBin(): string | null {
  const info = resolveToolBinary("opencode", { useHostBins: true, probeVersion: false });
  return info.path;
}

export interface OpenCodeRunResult {
  exitCode: number | null;
  sessionId: string | null;
  stdout: string;
  stderr: string;
  events: any[];
  finalText: string;
}

function parseJsonLines(stdout: string): any[] {
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

export class OpenCodeHarness {
  readonly sandbox: Sandbox;
  readonly hyp: HypCli;
  readonly shim: LlmShimServer;
  readonly opencodeBin: string;
  readonly configDir: string;
  readonly configPath: string;
  readonly pluginPath: string;
  readonly role: string;
  readonly env: Record<string, string>;

  private constructor(init: {
    sandbox: Sandbox;
    hyp: HypCli;
    shim: LlmShimServer;
    opencodeBin: string;
    configDir: string;
    configPath: string;
    pluginPath: string;
    role: string;
    env: Record<string, string>;
  }) {
    this.sandbox = init.sandbox;
    this.hyp = init.hyp;
    this.shim = init.shim;
    this.opencodeBin = init.opencodeBin;
    this.configDir = init.configDir;
    this.configPath = init.configPath;
    this.pluginPath = init.pluginPath;
    this.role = init.role;
    this.env = init.env;
  }

  static async create(options: {
    sandbox: Sandbox;
    hyp: HypCli;
    shim: LlmShimServer;
    opencodeBin?: string;
    role?: string;
    runSetup?: boolean;
  }): Promise<OpenCodeHarness> {
    const opencodeBin = options.opencodeBin ?? resolveOpenCodeBin();
    if (!opencodeBin) {
      throw new Error("opencode binary not found (set OPENCODE_BIN or install opencode)");
    }

    const role = options.role ?? "opencode";
    if (options.runSetup !== false) {
      await options.hyp.setup("opencode", {
        noSkills: true,
        noCommands: true,
      });
    }

    const configDir = path.join(options.sandbox.paths.homeDir, ".config", "opencode");
    const configPath = path.join(configDir, "opencode.json");
    const pluginPath = path.join(configDir, "plugins", "hyphae.ts");
    fs.mkdirSync(configDir, { recursive: true });

    const doc = fs.existsSync(configPath)
      ? JSON.parse(fs.readFileSync(configPath, "utf8"))
      : { $schema: "https://opencode.ai/config.json" };

    // Point OpenCode's built-in OpenAI-compatible provider directly to our loopback llm-shim
    // (zero network/npm package downloads required!).
    doc.provider = {
      ...(doc.provider || {}),
      openai: {
        options: {
          baseURL: `${options.shim.roleBaseUrl(role)}/v1`,
          apiKey: `sk-itest-${role}`,
        },
        models: {
          "gpt-4o-mini": {
            name: "FakeBrain Shim",
            tool_call: true,
          },
        },
      },
    };
    doc.model = "openai/gpt-4o-mini";
    fs.writeFileSync(configPath, JSON.stringify(doc, null, 2) + "\n");

    const env = options.sandbox.envWith({
      XDG_CONFIG_HOME: path.join(options.sandbox.paths.homeDir, ".config"),
      OPENCODE_CONFIG: configPath,
      OPENAI_API_KEY: `sk-itest-${role}`,
      HYPHAE_BIN: options.hyp.bin,
      HYPHAE_SOCKET: options.hyp.socketPath,
      PATH: `${path.dirname(opencodeBin)}${path.delimiter}${options.sandbox.env.PATH}`,
    });

    return new OpenCodeHarness({
      sandbox: options.sandbox,
      hyp: options.hyp,
      shim: options.shim,
      opencodeBin,
      configDir,
      configPath,
      pluginPath,
      role,
      env,
    });
  }

  spawnRun(
    prompt: string,
    options: {
      sessionId?: string;
      printLogs?: boolean;
      logLevel?: string;
      timeoutMs?: number;
      label?: string;
    } = {},
  ): { proc: TrackedProcess; done: Promise<OpenCodeRunResult> } {
    const args = [
      "run",
      "--standalone",
      "--auto",
      "--format",
      "json",
      "--model",
      "openai/gpt-4o-mini",
    ];
    if (options.printLogs) {
      args.push("--print-logs", "--log-level", options.logLevel ?? "warn");
    }
    if (options.sessionId) {
      args.push("--session", options.sessionId);
    }
    args.push(prompt);

    const proc = this.sandbox.reaper.spawn(
      options.label ?? `opencode-${this.role}`,
      this.opencodeBin,
      args,
      {
        env: this.env,
        cwd: this.sandbox.paths.workspaceDir,
        stdio: ["ignore", "pipe", "pipe"],
      },
    );

    const timeoutMs = options.timeoutMs ?? 40_000;
    const done = (async (): Promise<OpenCodeRunResult> => {
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
          `opencode run (${this.role}) timed out after ${timeoutMs}ms\nSTDOUT:\n${proc.stdout.slice(-2000)}\nSTDERR:\n${proc.stderr.slice(-2000)}`,
        );
      }

      const events = parseJsonLines(proc.stdout);
      const firstWithSession = events.find((e) => typeof e?.sessionID === "string");
      const sessionId = firstWithSession?.sessionID ?? options.sessionId ?? null;
      const finalText = events
        .filter((e) => e?.type === "text" && typeof e?.part?.text === "string")
        .map((e) => e.part.text)
        .join("");

      return {
        exitCode: proc.exitCode,
        sessionId,
        stdout: proc.stdout,
        stderr: proc.stderr,
        events,
        finalText,
      };
    })();

    return { proc, done };
  }

  async run(
    prompt: string,
    options: Parameters<OpenCodeHarness["spawnRun"]>[1] = {},
  ): Promise<OpenCodeRunResult> {
    const { done } = this.spawnRun(prompt, options);
    return done;
  }
}

export const opencodeAdapter: RealHarnessAdapter = {
  id: "opencode",
  displayName: "OpenCode CLI",
  capabilities: {
    nativePushWake: false,
    nudgeOnlyWake: false,
    midStreamInterrupt: false,
    hookToolBoundaries: true,
    explicitHookProvenance: false,
    supportsMultiTurnSession: true,
  },

  checkAvailability(): string | null {
    const bin = resolveOpenCodeBin();
    if (!bin) return "opencode binary not found (set OPENCODE_BIN)";
    // NEW-ISSUE: OpenCode v2.3.2 rejects `plugins/opencode/hyphae.ts` (`export default HyphaePlugin`)
    // with `PluginModule.LoadError: Plugin must export a default definition with an id and an effect or setup function`
    // AND invokes MCP tools via Code Mode `execute` without firing v1 `tool.execute.before`, causing
    // `caller_unverifiable` on every Hyphae MCP call. Dedicated `opencode.test.ts` asserts this exact
    // real-binary behavior + tests the installed `plugins/hyphae.ts` directly against compiled `hyp`.
    return "NEW-ISSUE: OpenCode v2.3.2 breaks plugins/opencode/hyphae.ts v1 default-function export & Code Mode caller verification (covered in opencode.test.ts)";
  },

  async boot(options: HarnessBootOptions): Promise<HarnessRuntime> {
    await options.hyp.onboard({ nodeId: options.nodeId, noSkills: true, noCommands: true });
    await options.hyp.startDaemon();
    const oc = await OpenCodeHarness.create({
      sandbox: options.sandbox,
      hyp: options.hyp,
      shim: options.shim,
      role: options.role,
    });

    const runtime: HarnessRuntime = {
      adapter: opencodeAdapter,
      sandbox: options.sandbox,
      hyp: options.hyp,
      shim: options.shim,

      async enrollSession(opts) {
        const tag = opts.tag ?? `SESSION_${opts.handle.toUpperCase()}`;
        const res = await oc.run(`${tag} enroll in mesh as ${opts.handle}`);
        const ins = await options.hyp.inspect({ handle: opts.handle, allowFailure: true });
        const row = extractSessionsFromInspect(ins.json)[0];
        if (!row?.enrolled) {
          throw new Error(`OpenCode failed to enroll '${opts.handle}' (exit=${res.exitCode})`);
        }
        return {
          role: opts.role,
          handle: opts.handle,
          sessionId: row.sessionId,
          nativeId: res.sessionId ?? row.sessionId,
          tag,
        };
      },

      async runTurn(session, prompt, opts) {
        const res = await oc.run(prompt, {
          sessionId: session.nativeId,
          timeoutMs: opts?.timeoutMs ?? 40_000,
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
        return { done: runtime.runTurn(session, prompt, opts) };
      },

      async deliverPending(session, opts) {
        await runtime.runTurn(session, opts?.prompt ?? `${session.tag} check inbox`, {
          timeoutMs: opts?.timeoutMs ?? 40_000,
        });
      },

      async close() {
        // Standalone processes already exited cleanly.
      },
    };

    return runtime;
  },
};
