/**
 * Real black-box Herdr Core (`hc`) orchestrator driver + inner real Claude Code agent.
 *
 * Isolation invariants:
 *  - Boots a dedicated isolated `hc server` strictly inside the per-test Sandbox using
 *    `HOME`, `XDG_CONFIG_HOME`, `XDG_STATE_HOME`, `XDG_DATA_HOME`, `XDG_RUNTIME_DIR`,
 *    `HC_SOCKET=<sandbox>/hc.sock`, and a unique short `HC_SESSION` — NEVER touching
 *    host `~/.config/herdr-core` or any host `hc` server!
 *  - Stops `hc server` cleanly on teardown via `sandbox.onTeardown(...)` AND kills any
 *    remaining spawned children if `hc server stop` fails.
 */

import { tryParseJson } from "../util.ts";
import { execFile, execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { promisify } from "node:util";
import { resolveToolBinary } from "../../scripts/provision.mjs";
import type { HypCli } from "../hyp-cli.ts";
import type { LlmShimServer } from "../llm-shim/index.ts";
import type { Sandbox } from "../sandbox.ts";
import { ClaudeHarness, resolveClaudeBin } from "./claude.ts";
import {
  extractSessionsFromInspect,
  type HarnessBootOptions,
  type HarnessRuntime,
  type RealHarnessAdapter,
} from "./types.ts";

const execFileAsync = promisify(execFile);

export function resolveHcBin(): string | null {
  const info = resolveToolBinary("hc", { useHostBins: true, probeVersion: false });
  return info.path;
}

export interface HcExecResult {
  exitCode: number;
  stdout: string;
  stderr: string;
  json: any;
}

export class HerdrOrchestrator {
  readonly sandbox: Sandbox;
  readonly hcBin: string;
  readonly socketPath: string;
  readonly sessionName: string;
  readonly env: Record<string, string>;
  private started = false;
  private serverPid: number | null = null;

  private constructor(init: {
    sandbox: Sandbox;
    hcBin: string;
    socketPath: string;
    sessionName: string;
    env: Record<string, string>;
  }) {
    this.sandbox = init.sandbox;
    this.hcBin = init.hcBin;
    this.socketPath = init.socketPath;
    this.sessionName = init.sessionName;
    this.env = init.env;
  }

  static async start(options: {
    sandbox: Sandbox;
    hcBin?: string;
    extraPathDirs?: string[];
  }): Promise<HerdrOrchestrator> {
    const hcBin = options.hcBin ?? resolveHcBin();
    if (!hcBin) {
      throw new Error("hc binary not found (set HC_BIN or install herdr-core)");
    }

    const socketPath = path.join(options.sandbox.paths.rootDir, "hc.sock");
    const sessionName = `it${crypto.randomBytes(3).toString("hex")}`;
    const extraDirs = [path.dirname(hcBin), ...(options.extraPathDirs ?? [])];
    const env = options.sandbox.envWith({
      HC_SOCKET: socketPath,
      HC_SESSION: sessionName,
      PATH: `${extraDirs.join(path.delimiter)}${path.delimiter}${options.sandbox.env.PATH}`,
    });

    const orch = new HerdrOrchestrator({
      sandbox: options.sandbox,
      hcBin,
      socketPath,
      sessionName,
      env,
    });

    // Always register cleanup BEFORE starting so even partial failures stop the isolated hc server!
    options.sandbox.onTeardown(() => orch.stop());

    const res = await orch.exec(["server", "start", "--json"]);
    orch.started = true;
    orch.serverPid = typeof res.json?.pid === "number" ? res.json.pid : null;
    return orch;
  }

  async exec(
    args: string[],
    options: { timeoutMs?: number; allowFailure?: boolean; cwd?: string } = {},
  ): Promise<HcExecResult> {
    try {
      const { stdout, stderr } = await execFileAsync(this.hcBin, args, {
        env: this.env,
        cwd: options.cwd ?? this.sandbox.paths.workspaceDir,
        timeout: options.timeoutMs ?? 20_000,
        maxBuffer: 8 * 1024 * 1024,
      });
      return {
        exitCode: 0,
        stdout: stdout || "",
        stderr: stderr || "",
        json: tryParseJson(stdout || ""),
      };
    } catch (err: any) {
      const exitCode = typeof err?.code === "number" ? err.code : 1;
      const res: HcExecResult = {
        exitCode,
        stdout: String(err?.stdout ?? ""),
        stderr: String(err?.stderr ?? ""),
        json: tryParseJson(String(err?.stdout ?? "")),
      };
      if (!options.allowFailure) {
        throw new Error(
          `hc ${args.join(" ")} failed (exit=${exitCode}):\nSTDOUT:\n${res.stdout}\nSTDERR:\n${res.stderr}`,
        );
      }
      return res;
    }
  }

  async runBg(
    name: string,
    argv: string[],
    options: { cwd?: string; extraFlags?: string[] } = {},
  ): Promise<any> {
    const res = await this.exec([
      "run",
      "--bg",
      "--json",
      "--name",
      name,
      "--cwd",
      options.cwd ?? this.sandbox.paths.workspaceDir,
      ...(options.extraFlags ?? []),
      ...argv,
    ]);
    return res.json;
  }

  async get(target: string, options: { allowFailure?: boolean } = {}): Promise<any> {
    const res = await this.exec(["get", "--json", target], {
      allowFailure: options.allowFailure,
    });
    return res.json;
  }

  async ls(): Promise<any> {
    const res = await this.exec(["ls", "--all", "--json"]);
    return res.json;
  }

  async send(target: string, text: string, options: { force?: boolean; ifState?: string } = {}): Promise<any> {
    const args = ["send", "--json"];
    if (options.force) args.push("--force");
    if (options.ifState) args.push("--if", options.ifState);
    args.push(target, text);
    const res = await this.exec(args);
    return res.json;
  }

  async interrupt(target: string, timeoutSec = 8): Promise<any> {
    const res = await this.exec(["interrupt", "--json", "--timeout", String(timeoutSec), target]);
    return res.json;
  }

  async kill(target: string, options: { allowFailure?: boolean } = {}): Promise<any> {
    const res = await this.exec(["kill", "--json", target], {
      allowFailure: options.allowFailure,
    });
    return res.json;
  }

  async read(target: string): Promise<string> {
    const res = await this.exec(["read", target], { allowFailure: true });
    return res.stdout;
  }

  /**
   * Launches a real interactive Claude Code instance inside a Herdr PTY terminal wired to `llm-shim`
   * and `hyp`, waits until `hc get --json` reports `status.app` + `status.state === "idle"`.
   */
  async launchInteractiveClaude(options: {
    name: string;
    hyp: HypCli;
    shim: LlmShimServer;
    role: string;
    claudeBin?: string;
    readyTimeoutMs?: number;
  }): Promise<{
    claude: ClaudeHarness;
    terminalAddress: string;
    terminalName: string;
    info: any;
  }> {
    const claude = await ClaudeHarness.create({
      sandbox: this.sandbox,
      hyp: options.hyp,
      shim: options.shim,
      claudeBin: options.claudeBin,
      role: options.role,
      profileName: `claude-hc-${options.role}`,
      extraEnv: {
        HC_SOCKET: this.socketPath,
        HC_SESSION: this.sessionName,
        TERM: "xterm-256color",
      },
    });

    // Pre-approve the synthetic loopback ANTHROPIC_API_KEY and bypass-permissions modal in
    // `<configDir>/.claude.json` so interactive Claude boots straight to the live idle prompt!
    const claudeJsonPath = path.join(claude.configDir, ".claude.json");
    const doc = JSON.parse(fs.readFileSync(claudeJsonPath, "utf8"));
    const apiKey = claude.env.ANTHROPIC_API_KEY;
    doc.customApiKeyResponses = {
      approved: [apiKey.slice(-20)],
      rejected: [],
    };
    doc.bypassPermissionsModeAccepted = true;
    fs.writeFileSync(claudeJsonPath, JSON.stringify(doc, null, 2) + "\n");

    const wrapperPath = path.join(
      this.sandbox.paths.binDir,
      `hc-claude-${options.name.replace(/[^a-zA-Z0-9._-]/g, "_")}.sh`,
    );
    const envExports = Object.entries(claude.env)
      .map(([k, v]) => `export ${k}=${JSON.stringify(v)}`)
      .join("\n");
    fs.writeFileSync(
      wrapperPath,
      [
        "#!/bin/sh",
        envExports,
        `exec ${JSON.stringify(claude.claudeBin)} --dangerously-skip-permissions --model claude-sonnet-4-5 "$@"`,
      ].join("\n") + "\n",
      { mode: 0o700 },
    );

    const runInfo = await this.runBg(options.name, [wrapperPath]);
    const address = String(runInfo?.address ?? options.name);

    const deadline = Date.now() + (options.readyTimeoutMs ?? 25_000);
    let lastInfo: any = null;
    while (Date.now() < deadline) {
      lastInfo = await this.get(address, { allowFailure: true });
      if (
        lastInfo?.state === "live" &&
        lastInfo?.status?.app &&
        (lastInfo?.status?.state === "idle" || lastInfo?.status?.state === "done")
      ) {
        return {
          claude,
          terminalAddress: address,
          terminalName: options.name,
          info: lastInfo,
        };
      }
      await new Promise((r) => setTimeout(r, 250));
    }

    const screen = await this.read(address);
    throw new Error(
      `Herdr inner Claude '${options.name}' (${address}) did not become idle within ${options.readyTimeoutMs ?? 25_000}ms\nLAST GET: ${JSON.stringify(lastInfo)}\nSCREEN:\n${screen.slice(-1500)}`,
    );
  }

  async waitForAgentState(
    target: string,
    states: string[],
    timeoutMs = 15_000,
  ): Promise<any> {
    const deadline = Date.now() + timeoutMs;
    let last: any = null;
    while (Date.now() < deadline) {
      last = await this.get(target, { allowFailure: true });
      const st = last?.status?.state;
      if (typeof st === "string" && states.includes(st)) {
        return last;
      }
      await new Promise((r) => setTimeout(r, 150));
    }
    throw new Error(
      `Timed out waiting for Herdr terminal '${target}' to reach state [${states.join("|")}] (last=${JSON.stringify(last)})`,
    );
  }

  async stop(): Promise<void> {
    if (!this.started) return;
    this.started = false;
    const termPids: number[] = [];
    try {
      const list = await this.ls().catch(() => null);
      const terms: any[] = Array.isArray(list)
        ? list
        : (list?.terminals ?? list?.items ?? []);
      for (const term of terms) {
        if (typeof term?.pid === "number" && term.pid > 0) {
          termPids.push(term.pid);
        }
        if (term?.address) {
          await this.kill(term.address, { allowFailure: true }).catch(() => {});
        }
      }
    } catch {
      // ignore
    }
    for (const pid of termPids) {
      try {
        process.kill(-pid, "SIGTERM");
      } catch {
        try {
          process.kill(pid, "SIGTERM");
        } catch {
          // already exited
        }
      }
    }
    try {
      await this.exec(["server", "stop", "--json"], { allowFailure: true, timeoutMs: 5_000 });
    } catch {
      // ignore
    }
    if (this.serverPid && this.serverPid > 0) {
      try {
        process.kill(this.serverPid, 0);
        process.kill(this.serverPid, "SIGKILL");
      } catch {
        // already exited
      }
    }
    // Herdr Core spawns PTY holders (`herdr-core hold --socket <sandboxRoot>/hc.holder.*.sock`)
    // in detached POSIX sessions (`setsid`) so terminals survive `hc server restart`.
    // Reap any lingering holders or inner `hyp mcp` children strictly matching this sandbox's unique rootDir!
    await new Promise((r) => setTimeout(r, 150));
    const rootMarker = this.sandbox.paths.rootDir;
    const findStrays = (): number[] => {
      try {
        const out = execFileSync("ps", ["-axo", "pid=,command="], { encoding: "utf8" });
        const pids: number[] = [];
        for (const line of out.split(/\r?\n/)) {
          if (!line.includes(rootMarker)) continue;
          if (
            !line.includes("herdr-core") &&
            !line.includes("hc-claude-") &&
            !line.includes(" mcp ")
          ) {
            continue;
          }
          const m = line.trim().match(/^(\d+)\s+/);
          if (!m) continue;
          const pid = Number(m[1]);
          if (pid > 1 && pid !== process.pid && pid !== process.ppid) {
            pids.push(pid);
          }
        }
        return pids;
      } catch {
        return [];
      }
    };
    const strays = findStrays();
    for (const pid of strays) {
      try {
        process.kill(pid, "SIGTERM");
      } catch {
        // ignore
      }
    }
    if (strays.length > 0) {
      await new Promise((r) => setTimeout(r, 200));
      for (const pid of findStrays()) {
        try {
          process.kill(pid, "SIGKILL");
        } catch {
          // ignore
        }
      }
    }
  }
}

export const herdrClaudeAdapter: RealHarnessAdapter = {
  id: "herdr-claude",
  displayName: "Herdr (hc) + Claude Code",
  capabilities: {
    nativePushWake: true,
    nudgeOnlyWake: true,
    midStreamInterrupt: true,
    hookToolBoundaries: true,
    explicitHookProvenance: true,
    supportsMultiTurnSession: true,
  },

  checkAvailability(): string | null {
    if (!resolveHcBin()) return "hc binary not found (set HC_BIN)";
    if (!resolveClaudeBin()) return "claude binary not found (set CLAUDE_BIN)";
    return null;
  },

  async boot(options: HarnessBootOptions): Promise<HarnessRuntime> {
    const hcBin = resolveHcBin()!;
    const claudeBin = resolveClaudeBin()!;
    const herdr = await HerdrOrchestrator.start({
      sandbox: options.sandbox,
      hcBin,
      extraPathDirs: [path.dirname(claudeBin)],
    });

    await options.hyp.onboard({ nodeId: options.nodeId, noSkills: true, noCommands: true });
    await options.hyp.startDaemon({ env: herdr.env });

    let termSeq = 0;

    const runtime: HarnessRuntime = {
      adapter: herdrClaudeAdapter,
      sandbox: options.sandbox,
      hyp: options.hyp,
      shim: options.shim,

      async enrollSession(opts) {
        termSeq += 1;
        const termName = `w${termSeq}-${opts.handle.replace(/[^a-z0-9_-]/gi, "").slice(0, 16)}`;
        const tag = opts.tag ?? `SESSION_${opts.handle.toUpperCase()}`;
        const launched = await herdr.launchInteractiveClaude({
          name: termName,
          hyp: options.hyp,
          shim: options.shim,
          role: opts.role,
          claudeBin,
        });

        await herdr.send(launched.terminalAddress, `${tag} enroll in mesh as ${opts.handle}`);

        const deadline = Date.now() + 25_000;
        let enrolledRow: any = null;
        while (Date.now() < deadline) {
          const ins = await options.hyp.inspect({ handle: opts.handle, allowFailure: true });
          const row = extractSessionsFromInspect(ins.json)[0];
          if (row?.enrolled && row?.transportKind === "herdr" && row?.hasLiveTransport) {
            enrolledRow = row;
            break;
          }
          await new Promise((r) => setTimeout(r, 250));
        }
        if (!enrolledRow) {
          throw new Error(`Herdr+Claude failed to enroll handle '${opts.handle}' with transportKind=herdr`);
        }
        await herdr.waitForAgentState(launched.terminalAddress, ["idle", "done"], 15_000);
        return {
          role: opts.role,
          handle: opts.handle,
          sessionId: enrolledRow.sessionId,
          nativeId: launched.terminalAddress,
          tag,
        };
      },

      async runTurn(session, prompt, opts) {
        const before = options.shim.getTurns(session.role).length;
        await herdr.send(session.nativeId, prompt);
        await options.shim.awaitTurn(
          session.role,
          (t) => t.id > 0 && options.shim.getTurns(session.role).length > before,
          opts?.timeoutMs ?? 25_000,
        );
        await herdr.waitForAgentState(session.nativeId, ["idle", "done"], opts?.timeoutMs ?? 25_000);
        return { ok: true, exitCode: 0, finalText: "" };
      },

      startTurn(session, prompt, opts) {
        const done = (async () => {
          await herdr.send(session.nativeId, prompt);
          await herdr.waitForAgentState(
            session.nativeId,
            ["idle", "done"],
            opts?.timeoutMs ?? 35_000,
          );
          return { ok: true, exitCode: 0, finalText: "" };
        })();
        return { done };
      },

      async deliverPending(_session, _opts) {
        // Herdr wakes natively via `hc send` / `hc interrupt` daemon push.
      },

      async afterDaemonRestart(sessions) {
        // Strictly verify automatic startup transport rehydration (#34) — even for sessions
        // with 0 pending items (e.g. `beta`) — with ZERO manual hook re-ping!
        const deadline = Date.now() + 10_000;
        let lastList: any[] = [];
        while (Date.now() < deadline) {
          const ins = await options.hyp.inspect({ all: true, allowFailure: true });
          lastList = extractSessionsFromInspect(ins.json);
          if (
            sessions.every((s) =>
              lastList.some(
                (r) =>
                  r.handle === s.handle &&
                  r.transportKind === "herdr" &&
                  r.hasLiveTransport === true,
              ),
            )
          ) {
            return;
          }
          await new Promise((r) => setTimeout(r, 200));
        }
        throw new Error(
          `Timed out waiting for automatic Herdr transport rehydration (#34) after daemon restart: ${JSON.stringify(lastList)}`,
        );
      },

      async close() {
        await herdr.stop();
      },
    };

    return runtime;
  },
};
