/**
 * Real black-box OpenCode (`opencode`) harness driver.
 *
 * Wires real `opencode` (`v2.3.2+`) strictly via `hyp setup --harness opencode` + `OPENCODE_CONFIG`
 * pointing the OpenAI-compatible provider to our loopback `LlmShimServer`.
 *
 * Exposes `opencodeAdapter: RealHarnessAdapter` for full live P1–P8 cross-harness parity (#30).
 */

import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
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

function pickFreePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.once("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const addr = srv.address();
      const port = addr && typeof addr === "object" ? addr.port : 0;
      srv.close(() => resolve(port));
    });
  });
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
  private serverProc: TrackedProcess | null = null;
  private serverUrl: string | null = null;

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
    configFileName?: string;
    dataDir?: string;
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
    const defaultConfigPath = path.join(configDir, "opencode.json");
    const configPath = path.join(configDir, options.configFileName ?? "opencode.json");
    const pluginPath = path.join(configDir, "plugins", "hyphae.ts");
    fs.mkdirSync(configDir, { recursive: true });

    const baseConfigPath = fs.existsSync(configPath) ? configPath : defaultConfigPath;
    const doc = fs.existsSync(baseConfigPath)
      ? JSON.parse(fs.readFileSync(baseConfigPath, "utf8"))
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

    const serverPassword = `oc-srv-itest-${crypto.randomBytes(10).toString("hex")}`;
    options.sandbox.registerSecret(`opencode-server-password-${role}`, serverPassword);

    const extraDataEnv: Record<string, string> = {};
    if (options.dataDir) {
      fs.mkdirSync(options.dataDir, { recursive: true, mode: 0o700 });
      extraDataEnv.XDG_DATA_HOME = path.join(options.dataDir, "share");
      extraDataEnv.XDG_STATE_HOME = path.join(options.dataDir, "state");
      extraDataEnv.XDG_CACHE_HOME = path.join(options.dataDir, "cache");
    }

    const env = options.sandbox.envWith({
      XDG_CONFIG_HOME: path.join(options.sandbox.paths.homeDir, ".config"),
      ...extraDataEnv,
      OPENCODE_CONFIG: configPath,
      OPENCODE_SERVER_PASSWORD: serverPassword,
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

  /**
   * Starts an isolated loopback `opencode serve` instance inside this sandbox so async
   * plugin turn-end callbacks (`api.event.subscribe` -> `api.session.prompt`) stay alive
   * across turns instead of being torn down immediately by `opencode run --standalone`!
   */
  async startServer(readyTimeoutMs = 20_000): Promise<string> {
    if (this.serverProc && !this.serverProc.exited && this.serverUrl) {
      return this.serverUrl;
    }
    const port = await pickFreePort();
    const url = `http://127.0.0.1:${port}`;
    this.serverProc = this.sandbox.reaper.spawn(
      `opencode-serve-${this.role}`,
      this.opencodeBin,
      [
        "serve",
        "--hostname",
        "127.0.0.1",
        "--port",
        String(port),
        "--print-logs",
        "--log-level",
        "warn",
      ],
      {
        env: this.env,
        cwd: this.sandbox.paths.workspaceDir,
        stdio: ["ignore", "pipe", "pipe"],
      },
    );

    const deadline = Date.now() + readyTimeoutMs;
    while (Date.now() < deadline) {
      if (this.serverProc.exited) {
        throw new Error(
          `opencode serve (${this.role}) exited prematurely (code=${this.serverProc.exitCode}):\nSTDOUT:\n${this.serverProc.stdout}\nSTDERR:\n${this.serverProc.stderr}`,
        );
      }
      if (this.serverProc.stdout.includes("server listening on")) {
        this.serverUrl = url;
        return url;
      }
      await new Promise((r) => setTimeout(r, 100));
    }

    throw new Error(
      `opencode serve (${this.role}) did not become ready within ${readyTimeoutMs}ms\nSTDOUT:\n${this.serverProc.stdout}\nSTDERR:\n${this.serverProc.stderr}`,
    );
  }

  async stopServer(): Promise<void> {
    if (this.serverProc) {
      await this.sandbox.reaper.kill(this.serverProc, 3_000);
      this.serverProc = null;
      this.serverUrl = null;
    }
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
      ...(this.serverUrl ? ["--server", this.serverUrl] : ["--standalone"]),
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
    explicitHookProvenance: true,
    supportsMultiTurnSession: true,
  },

  checkAvailability(): string | null {
    return resolveOpenCodeBin() ? null : "opencode binary not found (set OPENCODE_BIN)";
  },

  async boot(options: HarnessBootOptions): Promise<HarnessRuntime> {
    const opencodeBin = resolveOpenCodeBin();
    if (!opencodeBin) {
      throw new Error("opencode binary not found");
    }
    await options.hyp.onboard({ nodeId: options.nodeId, noSkills: true, noCommands: true });
    await options.hyp.startDaemon();
    await options.hyp.setup("opencode", { noSkills: true, noCommands: true });

    const harnessesByRole = new Map<string, OpenCodeHarness>();
    const getOrCreate = async (role: string): Promise<OpenCodeHarness> => {
      let inst = harnessesByRole.get(role);
      if (!inst) {
        const slug = role.replace(/[^a-zA-Z0-9._-]/g, "_");
        inst = await OpenCodeHarness.create({
          sandbox: options.sandbox,
          hyp: options.hyp,
          shim: options.shim,
          opencodeBin,
          role,
          configFileName: role === options.role ? "opencode.json" : `opencode-${slug}.json`,
          dataDir:
            role === options.role
              ? undefined
              : path.join(options.sandbox.paths.rootDir, `oc-data-${slug}`),
          runSetup: false,
        });
        await inst.startServer();
        harnessesByRole.set(role, inst);
      }
      return inst;
    };

    const runtime: HarnessRuntime = {
      adapter: opencodeAdapter,
      sandbox: options.sandbox,
      hyp: options.hyp,
      shim: options.shim,

      async enrollSession(opts) {
        const oc = await getOrCreate(opts.role);
        const tag = opts.tag ?? `SESSION_${opts.handle.toUpperCase()}`;
        const res = await oc.run(`${tag} enroll in mesh as ${opts.handle}`);
        const ins = await options.hyp.inspect({ handle: opts.handle, allowFailure: true });
        const row = extractSessionsFromInspect(ins.json)[0];
        if (!row?.enrolled) {
          throw new Error(
            `OpenCode failed to enroll '${opts.handle}' (exit=${res.exitCode})\nSTDOUT:\n${res.stdout.slice(-1500)}\nSTDERR:\n${res.stderr.slice(-1500)}`,
          );
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
        const oc = await getOrCreate(session.role);
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
        for (const oc of harnessesByRole.values()) {
          await oc.stopServer();
        }
      },
    };

    return runtime;
  },
};
