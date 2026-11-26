/**
 * Real black-box OpenClaw (`openclaw`) harness driver.
 *
 * Launches a real isolated `openclaw gateway run` pointing to our loopback `LlmShimServer`
 * and wired to the compiled `hyp` binary strictly via `hyp onboard` + `hyp setup --harness openclaw`.
 */

import { execFile } from "node:child_process";
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
  type AdapterSessionHandle,
  type HarnessBootOptions,
  type HarnessRuntime,
  type RealHarnessAdapter,
} from "./types.ts";

export interface OpenClawExecResult {
  exitCode: number;
  stdout: string;
  stderr: string;
  json: any;
}

export function resolveOpenClawBin(): string | null {
  const info = resolveToolBinary("openclaw", { useHostBins: true, probeVersion: false });
  return info.path;
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

function parseTrailingJson(stdout: string): any {
  const trimmed = stdout.trim();
  if (!trimmed) return null;
  try {
    return JSON.parse(trimmed);
  } catch {
    // OpenClaw may print banner/warning lines before JSON object/array.
    for (let i = 0; i < trimmed.length; i += 1) {
      const ch = trimmed[i];
      if (ch === "{" || ch === "[") {
        try {
          return JSON.parse(trimmed.slice(i));
        } catch {
          // keep scanning
        }
      }
    }
    return null;
  }
}

export class OpenClawHarness {
  readonly sandbox: Sandbox;
  readonly hyp: HypCli;
  readonly shim: LlmShimServer;
  readonly openclawBin: string;
  readonly stateDir: string;
  readonly configPath: string;
  readonly gatewayPort: number;
  readonly gatewayToken: string;
  readonly role: string;
  readonly env: Record<string, string>;

  private gatewayProc: TrackedProcess | null = null;

  private constructor(init: {
    sandbox: Sandbox;
    hyp: HypCli;
    shim: LlmShimServer;
    openclawBin: string;
    stateDir: string;
    configPath: string;
    gatewayPort: number;
    gatewayToken: string;
    role: string;
    env: Record<string, string>;
  }) {
    this.sandbox = init.sandbox;
    this.hyp = init.hyp;
    this.shim = init.shim;
    this.openclawBin = init.openclawBin;
    this.stateDir = init.stateDir;
    this.configPath = init.configPath;
    this.gatewayPort = init.gatewayPort;
    this.gatewayToken = init.gatewayToken;
    this.role = init.role;
    this.env = init.env;
  }

  static async create(options: {
    sandbox: Sandbox;
    hyp: HypCli;
    shim: LlmShimServer;
    openclawBin?: string;
    role?: string;
    deliveryMode?: "gateway" | "inbox";
    promptInjection?: boolean;
    nodeId?: string;
  }): Promise<OpenClawHarness> {
    const openclawBin = options.openclawBin ?? resolveOpenClawBin();
    if (!openclawBin) {
      throw new Error("openclaw binary not found (set OPENCLAW_BIN or install openclaw)");
    }

    const stateDir = path.join(options.sandbox.paths.homeDir, ".openclaw");
    fs.mkdirSync(stateDir, { recursive: true, mode: 0o700 });
    const configPath = path.join(stateDir, "openclaw.json");
    const gatewayPort = await pickFreePort();
    const gatewayToken = `oc-gw-itest-${crypto.randomBytes(12).toString("hex")}`;
    const role = options.role ?? "openclaw";
    const deliveryMode = options.deliveryMode ?? "gateway";
    const promptInjection = options.promptInjection ?? false;

    // Register gateway token as a secret so llm-shim Zero Secret Leak Scanner guards it too!
    options.sandbox.registerSecret("openclaw-gateway-token", gatewayToken);

    const env = options.sandbox.envWith({
      OPENCLAW_HOME: options.sandbox.paths.homeDir,
      OPENCLAW_STATE_DIR: stateDir,
      OPENCLAW_CONFIG_PATH: configPath,
      OPENCLAW_GATEWAY_TOKEN: gatewayToken,
      HYPHAE_BIN: options.hyp.bin,
      HYPHAE_SOCKET: options.hyp.socketPath,
      PATH: `${path.dirname(openclawBin)}${path.delimiter}${options.sandbox.env.PATH}`,
    });

    // 1. Run real black-box `hyp onboard` + `hyp setup --harness openclaw`.
    await options.hyp.onboard({
      nodeId: options.nodeId ?? "oc-itest@local",
      harness: "openclaw",
      openclawDelivery: deliveryMode,
      openclawPromptInjection: promptInjection,
      noSkills: true,
    });
    await options.hyp.setup("openclaw", {
      openclawDelivery: deliveryMode,
      openclawPromptInjection: promptInjection,
      noSkills: true,
    });

    // 2. Patch `openclaw.json` with FakeBrain LLM provider and isolated loopback Gateway settings.
    const doc = JSON.parse(fs.readFileSync(configPath, "utf8"));
    doc.gateway = {
      mode: "local",
      port: gatewayPort,
      bind: "loopback",
      auth: {
        mode: "token",
        token: gatewayToken,
      },
    };
    doc.models = {
      mode: "merge",
      providers: {
        fakebrain: {
          baseUrl: `${options.shim.roleBaseUrl(role)}/v1`,
          apiKey: "sk-itest-openclaw",
          api: "openai-completions",
          models: [
            {
              id: "shim-1",
              name: "FakeBrain Shim Model",
              contextWindow: 128000,
              maxTokens: 4096,
            },
          ],
        },
      },
    };
    doc.agents = {
      defaults: {
        model: { primary: "fakebrain/shim-1" },
        workspace: options.sandbox.paths.workspaceDir,
      },
    };
    fs.writeFileSync(configPath, JSON.stringify(doc, null, 2) + "\n");

    return new OpenClawHarness({
      sandbox: options.sandbox,
      hyp: options.hyp,
      shim: options.shim,
      openclawBin,
      stateDir,
      configPath,
      gatewayPort,
      gatewayToken,
      role,
      env,
    });
  }

  exec(
    args: string[],
    options: { timeoutMs?: number; allowFailure?: boolean } = {},
  ): Promise<OpenClawExecResult> {
    return new Promise((resolve, reject) => {
      execFile(
        this.openclawBin,
        args,
        {
          env: this.env,
          cwd: this.sandbox.paths.workspaceDir,
          timeout: options.timeoutMs ?? 60_000,
          maxBuffer: 16 * 1024 * 1024,
        },
        (err, stdout, stderr) => {
          const exitCode =
            err && typeof (err as any).code === "number"
              ? (err as any).code
              : err
                ? 1
                : 0;
          const res: OpenClawExecResult = {
            exitCode,
            stdout: stdout || "",
            stderr: stderr || "",
            json: parseTrailingJson(stdout || ""),
          };
          if (err && !options.allowFailure) {
            reject(
              new Error(
                `openclaw ${args.join(" ")} failed (exit=${exitCode}):\nSTDOUT:\n${res.stdout}\nSTDERR:\n${res.stderr}`,
              ),
            );
            return;
          }
          resolve(res);
        },
      );
    });
  }

  async validateConfig(): Promise<any> {
    const res = await this.exec(["config", "validate", "--json"]);
    return res.json;
  }

  async inspectHyphaePlugin(): Promise<any> {
    const res = await this.exec(["plugins", "inspect", "hyphae", "--runtime", "--json"]);
    return res.json;
  }

  async startGateway(readyTimeoutMs = 30_000): Promise<TrackedProcess> {
    if (this.gatewayProc && !this.gatewayProc.exited) {
      return this.gatewayProc;
    }
    this.gatewayProc = this.sandbox.reaper.spawn(
      "openclaw-gateway",
      this.openclawBin,
      [
        "gateway",
        "run",
        "--port",
        String(this.gatewayPort),
        "--bind",
        "loopback",
        "--auth",
        "token",
        "--token",
        this.gatewayToken,
      ],
      {
        env: this.env,
        cwd: this.sandbox.paths.workspaceDir,
        stdio: ["ignore", "pipe", "pipe"],
      },
    );

    const deadline = Date.now() + readyTimeoutMs;
    let lastDetail = "";
    while (Date.now() < deadline) {
      if (this.gatewayProc.exited) {
        throw new Error(
          `openclaw gateway exited prematurely (code=${this.gatewayProc.exitCode}):\nSTDOUT:\n${this.gatewayProc.stdout}\nSTDERR:\n${this.gatewayProc.stderr}`,
        );
      }
      const logsReady =
        this.gatewayProc.stdout.includes("[gateway] ready") ||
        this.gatewayProc.stderr.includes("[gateway] ready");
      if (logsReady) {
        const probe = await this.exec(
          [
            "gateway",
            "call",
            "health",
            "--port",
            String(this.gatewayPort),
            "--token",
            this.gatewayToken,
            "--json",
            "--timeout",
            "2000",
          ],
          { allowFailure: true, timeoutMs: 5_000 },
        );
        if (probe.exitCode === 0 && probe.json) {
          return this.gatewayProc;
        }
        lastDetail = `${probe.stdout} ${probe.stderr}`.trim().slice(0, 300);
      }
      await new Promise((r) => setTimeout(r, 200));
    }

    throw new Error(
      `openclaw gateway did not become healthy on port ${this.gatewayPort} within ${readyTimeoutMs}ms: ${lastDetail}\nGATEWAY LOG:\n${this.gatewayProc.stdout}\n${this.gatewayProc.stderr}`,
    );
  }

  async stopGateway(): Promise<void> {
    if (this.gatewayProc) {
      await this.sandbox.reaper.kill(this.gatewayProc, 3_000);
      this.gatewayProc = null;
    }
  }

  async gatewayCall(method: string, params: Record<string, unknown> = {}): Promise<any> {
    const res = await this.exec([
      "gateway",
      "call",
      method,
      "--port",
      String(this.gatewayPort),
      "--token",
      this.gatewayToken,
      "--params",
      JSON.stringify(params),
      "--json",
      "--timeout",
      "15000",
    ]);
    return res.json;
  }

  async runAgentTurn(
    sessionKey: string,
    message: string,
    options: { local?: boolean; timeoutSec?: number } = {},
  ): Promise<{ ok: boolean; final: string; raw: any; stdout: string; stderr: string }> {
    const args = [
      "agent",
      ...(options.local ? ["--local"] : []),
      "--session-key",
      sessionKey,
      "--message",
      message,
      "--json",
      "--thinking",
      "off",
      "--timeout",
      String(options.timeoutSec ?? 45),
    ];
    const res = await this.exec(args, { timeoutMs: ((options.timeoutSec ?? 45) + 15) * 1000 });
    const parsed = res.json ?? {};
    const finalText =
      parsed.final ??
      parsed.result?.payloads?.map((p: any) => p?.text || "").join("") ??
      parsed.payloads?.map((p: any) => p?.text || "").join("") ??
      "";
    return {
      ok: parsed.ok !== false && parsed.status !== "error" && !parsed.error,
      final: finalText,
      raw: parsed,
      stdout: res.stdout,
      stderr: res.stderr,
    };
  }

  async listSessions(): Promise<any[]> {
    const res = await this.gatewayCall("sessions.list", {});
    if (Array.isArray(res)) return res;
    if (Array.isArray(res?.sessions)) return res.sessions;
    if (Array.isArray(res?.items)) return res.items;
    return [];
  }

  async deleteSession(sessionKey: string): Promise<any> {
    // Try Gateway RPC `sessions.delete` first; fall back to CLI `openclaw sessions delete`.
    try {
      return await this.gatewayCall("sessions.delete", { key: sessionKey });
    } catch {
      const res = await this.exec(["sessions", "delete", sessionKey, "--json"], {
        allowFailure: true,
      });
      return res.json ?? res.stdout;
    }
  }
}

export const openClawAdapter: RealHarnessAdapter = {
  id: "openclaw",
  displayName: "OpenClaw Gateway",
  capabilities: {
    nativePushWake: true,
    nudgeOnlyWake: true,
    midStreamInterrupt: false,
    hookToolBoundaries: false,
    explicitHookProvenance: true,
    supportsMultiTurnSession: true,
  },

  checkAvailability(): string | null {
    return resolveOpenClawBin() ? null : "openclaw binary not found (set OPENCLAW_BIN)";
  },

  async boot(options: HarnessBootOptions): Promise<HarnessRuntime> {
    const oc = await OpenClawHarness.create({
      sandbox: options.sandbox,
      hyp: options.hyp,
      shim: options.shim,
      role: options.role,
      nodeId: options.nodeId,
      deliveryMode: "gateway",
      promptInjection: false,
    });
    await options.hyp.startDaemon();
    await oc.startGateway();

    const runtime: HarnessRuntime = {
      adapter: openClawAdapter,
      sandbox: options.sandbox,
      hyp: options.hyp,
      shim: options.shim,

      async enrollSession(opts) {
        const key = `agent:main:${opts.handle}`;
        const tag = opts.tag ?? `SESSION_${opts.handle.toUpperCase()}`;
        const res = await oc.runAgentTurn(key, `${tag} enroll in mesh as ${opts.handle}`);
        if (!res.ok) {
          throw new Error(`OpenClaw enrollSession(${opts.handle}) failed: ${JSON.stringify(res)}`);
        }
        return {
          role: opts.role,
          handle: opts.handle,
          sessionId: `openclaw:${key}`,
          nativeId: key,
          tag,
        };
      },

      async runTurn(session, prompt, opts) {
        const res = await oc.runAgentTurn(session.nativeId, prompt, {
          timeoutSec: opts?.timeoutMs ? Math.ceil(opts.timeoutMs / 1000) : 45,
        });
        return {
          ok: res.ok,
          exitCode: res.ok ? 0 : 1,
          finalText: res.final,
          stdout: res.stdout,
          stderr: res.stderr,
        };
      },

      startTurn(session, prompt, opts) {
        return {
          done: runtime.runTurn(session, prompt, opts),
        };
      },

      async deliverPending(_session, _opts) {
        // OpenClaw wakes natively via `hyphae-wake` Gateway push.
      },

      async afterDaemonRestart(sessions) {
        const deadline = Date.now() + 12_000;
        while (Date.now() < deadline) {
          const ins = await options.hyp.inspect({ all: true, allowFailure: true });
          const list = extractSessionsFromInspect(ins.json);
          const allReady = sessions.every((s) =>
            list.some(
              (row) =>
                row.handle === s.handle &&
                row.transportKind === "openclaw_plugin" &&
                row.hasLiveTransport,
            ),
          );
          if (allReady) return;
          await new Promise((r) => setTimeout(r, 200));
        }
        throw new Error("Timed out waiting for OpenClaw hyphae-wake reconnect after daemon restart");
      },

      async close() {
        await oc.stopGateway();
      },
    };

    return runtime;
  },
};
