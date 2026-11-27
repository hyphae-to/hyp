/**
 * Strict black-box CLI driver over the compiled `hyp` binary (`HYP_BIN`).
 *
 * Never imports internal Rust code — every action goes through `HYP_BIN` subprocesses,
 * stdio MCP JSON-RPC 2.0 (`hyp mcp`), or local daemon `connector.sock` NDJSON.
 */

import { tryParseJson } from "./util.ts";
import { execFile } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { runInteractivePtyCommand } from "./pty.ts";
import { REPO_ROOT } from "./sandbox.ts";
import type { Sandbox, TrackedProcess } from "./sandbox.ts";

export interface ExecResult {
  exitCode: number;
  stdout: string;
  stderr: string;
  json: any;
}

export interface DaemonController {
  handle: TrackedProcess;
  configPath: string;
  socketPath: string;
  stop: () => Promise<void>;
  restart: () => Promise<void>;
}

/**
 * Resolves the compiled `hyp` binary path strictly from `HYP_BIN` or the local
 * repository `target/{debug,release}/hyp`.
 */
export function resolveHypBin(): string {
  const envBin = process.env.HYP_BIN?.trim();
  if (envBin) {
    const fromCwd = path.resolve(envBin);
    if (fs.existsSync(fromCwd)) {
      return fromCwd;
    }
    if (!path.isAbsolute(envBin)) {
      const fromRepo = path.resolve(REPO_ROOT, envBin);
      if (fs.existsSync(fromRepo)) {
        return fromRepo;
      }
    }
    throw new Error(`HYP_BIN does not exist: ${fromCwd}`);
  }
  const exe = process.platform === "win32" ? "hyp.exe" : "hyp";
  for (const profile of ["debug", "release"]) {
    const candidate = path.join(REPO_ROOT, "target", profile, exe);
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }
  throw new Error(
    `Compiled 'hyp' binary not found. Build with 'cargo build --bin hyp' or set HYP_BIN=/path/to/hyp.`,
  );
}

/**
 * Sends a single NDJSON RPC frame to `connector.sock` (or Windows `.addr`).
 */
export function daemonRpc(
  socketPath: string,
  packet: Record<string, unknown>,
  timeoutMs = 5_000,
): Promise<any> {
  return new Promise((resolve, reject) => {
    const conn = net.createConnection(socketPath);
    let buf = "";
    const timer = setTimeout(() => {
      conn.destroy();
      reject(new Error(`daemon RPC '${String(packet.type)}' timed out after ${timeoutMs}ms`));
    }, timeoutMs);

    conn.on("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });
    conn.on("connect", () => {
      conn.write(`${JSON.stringify(packet)}\n`);
    });
    conn.on("data", (chunk: Buffer) => {
      buf += chunk.toString("utf8");
      const nl = buf.indexOf("\n");
      if (nl !== -1) {
        clearTimeout(timer);
        conn.end();
        try {
          resolve(JSON.parse(buf.slice(0, nl)));
        } catch (err) {
          reject(err);
        }
      }
    });
  });
}

/**
 * Real black-box stdio JSON-RPC 2.0 MCP client wrapping `HYP_BIN mcp`.
 */
export class HypMcpClient {
  readonly tracked: TrackedProcess;
  private nextId = 1;
  private pending = new Map<
    number,
    { resolve: (msg: any) => void; reject: (err: Error) => void; timer: NodeJS.Timeout }
  >();
  private buf = "";
  readonly notifications: any[] = [];

  constructor(sandbox: Sandbox, hypBin: string, args: string[], label = "hyp-mcp") {
    this.tracked = sandbox.reaper.spawn(label, hypBin, args, {
      env: sandbox.env,
      stdio: ["pipe", "pipe", "pipe"],
    });
    this.tracked.child.stdout?.on("data", (chunk: Buffer) => {
      this.buf += chunk.toString("utf8");
      let nl: number;
      while ((nl = this.buf.indexOf("\n")) !== -1) {
        const line = this.buf.slice(0, nl).trim();
        this.buf = this.buf.slice(nl + 1);
        if (!line) continue;
        try {
          const msg = JSON.parse(line);
          if (msg.id !== undefined && this.pending.has(msg.id)) {
            const entry = this.pending.get(msg.id)!;
            this.pending.delete(msg.id);
            clearTimeout(entry.timer);
            entry.resolve(msg);
          } else if (msg.method) {
            this.notifications.push(msg);
          }
        } catch {
          // ignore non-JSON debug lines
        }
      }
    });
    this.tracked.child.once("exit", () => {
      for (const [id, entry] of this.pending.entries()) {
        this.pending.delete(id);
        clearTimeout(entry.timer);
        entry.reject(
          new Error(
            `hyp mcp exited before response (code=${this.tracked.exitCode}): ${this.tracked.stderr}`,
          ),
        );
      }
    });
  }

  request(method: string, params: Record<string, unknown> = {}, timeoutMs = 15_000): Promise<any> {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`MCP request '${method}' timed out after ${timeoutMs}ms`));
      }, timeoutMs);
      this.pending.set(id, { resolve, reject, timer });
      this.tracked.child.stdin?.write(
        `${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`,
      );
    });
  }

  async initialize(clientName = "hyphae-itest"): Promise<any> {
    const res = await this.request("initialize", {
      protocolVersion: "2024-11-05",
      capabilities: {},
      clientInfo: { name: clientName, version: "1.0.0" },
    });
    if (!res.result) {
      throw new Error(`MCP initialize failed: ${JSON.stringify(res)}`);
    }
    this.tracked.child.stdin?.write(
      `${JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })}\n`,
    );
    return res.result;
  }

  async listTools(): Promise<any[]> {
    const res = await this.request("tools/list", {});
    return res.result?.tools ?? [];
  }

  async callTool(
    name: string,
    args: Record<string, unknown> = {},
  ): Promise<{ text: string; json: any; isError: boolean; raw: any }> {
    const res = await this.request("tools/call", { name, arguments: args });
    if (!res.result) {
      throw new Error(`MCP tools/call '${name}' protocol error: ${JSON.stringify(res)}`);
    }
    const text = (res.result.content || []).map((c: any) => c?.text || "").join("");
    return {
      text,
      json: tryParseJson(text, true),
      isError: Boolean(res.result.isError),
      raw: res.result,
    };
  }

  async close(): Promise<void> {
    try {
      this.tracked.child.stdin?.end();
    } catch {
      // ignore
    }
    await new Promise((r) => setTimeout(r, 30));
    if (!this.tracked.exited) {
      this.tracked.child.kill("SIGTERM");
    }
  }
}

export class HypCli {
  readonly bin: string;
  readonly sandbox: Sandbox;
  private activeDaemon: DaemonController | null = null;

  constructor(sandbox: Sandbox, binPath?: string) {
    this.sandbox = sandbox;
    this.bin = binPath ?? resolveHypBin();
  }

  get nodeConfigPath(): string {
    return path.join(this.sandbox.paths.hyphaeStateDir, "node.json");
  }

  get socketPath(): string {
    return this.sandbox.paths.socketPath;
  }

  exec(
    args: string[],
    options: {
      input?: string;
      env?: Record<string, string>;
      timeoutMs?: number;
      allowFailure?: boolean;
      cwd?: string;
    } = {},
  ): Promise<ExecResult> {
    return new Promise((resolve, reject) => {
      const child = execFile(
        this.bin,
        args,
        {
          env: options.env ?? this.sandbox.env,
          cwd: options.cwd ?? this.sandbox.paths.workspaceDir,
          timeout: options.timeoutMs ?? 30_000,
          maxBuffer: 8 * 1024 * 1024,
        },
        (err, stdout, stderr) => {
          const exitCode =
            err && typeof (err as any).code === "number"
              ? (err as any).code
              : err
                ? 1
                : 0;
          const result: ExecResult = {
            exitCode,
            stdout: stdout || "",
            stderr: stderr || "",
            json: tryParseJson(stdout || "", true),
          };
          if (err && !options.allowFailure) {
            reject(
              new Error(
                `hyp ${args.join(" ")} failed (exit=${exitCode}):\nSTDOUT:\n${result.stdout}\nSTDERR:\n${result.stderr}`,
              ),
            );
            return;
          }
          resolve(result);
        },
      );
      if (child.stdin) {
        if (options.input !== undefined) {
          child.stdin.end(options.input);
        } else {
          // Close stdin immediately so commands that inspect optional piped stdin
          // (such as `hyp emit`) do not block forever waiting for EOF.
          child.stdin.end();
        }
      }
    });
  }

  async onboard(options: {
    nodeId?: string;
    harness?: string;
    openclawDelivery?: "gateway" | "inbox";
    openclawPromptInjection?: boolean;
    noSkills?: boolean;
    noCommands?: boolean;
    extraArgs?: string[];
  } = {}): Promise<ExecResult> {
    const args = [
      "onboard",
      "--yes",
      "--no-start",
      "--node-id",
      options.nodeId ?? "itest@local",
      "--home",
      this.sandbox.paths.homeDir,
      "--state-dir",
      this.sandbox.paths.hyphaeStateDir,
      "--bin",
      this.bin,
      "--json",
    ];
    if (options.harness) args.push("--harness", options.harness);
    if (options.openclawDelivery) args.push("--openclaw-delivery", options.openclawDelivery);
    if (options.openclawPromptInjection === true) args.push("--openclaw-prompt-injection");
    if (options.openclawPromptInjection === false) args.push("--no-openclaw-prompt-injection");
    if (options.noSkills) args.push("--no-skills");
    if (options.noCommands) args.push("--no-commands");
    if (options.extraArgs) args.push(...options.extraArgs);
    return this.exec(args);
  }

  async setup(
    harness: string,
    options: {
      claudeConfigDir?: string;
      openclawDelivery?: "gateway" | "inbox";
      openclawPromptInjection?: boolean;
      noSkills?: boolean;
      noCommands?: boolean;
      extraArgs?: string[];
    } = {},
  ): Promise<ExecResult> {
    const args = [
      "setup",
      "--harness",
      harness,
      "--home",
      this.sandbox.paths.homeDir,
      "--state-dir",
      this.sandbox.paths.hyphaeStateDir,
      "--bin",
      this.bin,
      "--socket",
      this.socketPath,
      "--json",
    ];
    if (options.claudeConfigDir) args.push("--claude-config-dir", options.claudeConfigDir);
    if (options.openclawDelivery) args.push("--openclaw-delivery", options.openclawDelivery);
    if (options.openclawPromptInjection === true) args.push("--openclaw-prompt-injection");
    if (options.openclawPromptInjection === false) args.push("--no-openclaw-prompt-injection");
    if (options.noSkills) args.push("--no-skills");
    if (options.noCommands) args.push("--no-commands");
    if (options.extraArgs) args.push(...options.extraArgs);
    return this.exec(args);
  }

  async waitReady(timeoutMs = 10_000): Promise<any> {
    const deadline = Date.now() + timeoutMs;
    let lastErr: unknown;
    while (Date.now() < deadline) {
      try {
        const res = await daemonRpc(this.socketPath, { type: "daemon.status" }, 1_000);
        if (res && res.ok) return res;
      } catch (err) {
        lastErr = err;
      }
      await new Promise((r) => setTimeout(r, 50));
    }
    throw new Error(
      `hyp daemon did not become ready at ${this.socketPath} within ${timeoutMs}ms (lastErr=${String(lastErr)})`,
    );
  }

  async startDaemon(options: {
    configPath?: string;
    nodeId?: string;
    extraArgs?: string[];
    env?: Record<string, string>;
    readyTimeoutMs?: number;
  } = {}): Promise<DaemonController> {
    const configPath = options.configPath ?? this.nodeConfigPath;
    const spawnDaemon = () => {
      const args = [
        "daemon",
        "--state-dir",
        this.sandbox.paths.hyphaeStateDir,
        "--socket",
        this.socketPath,
      ];
      if (fs.existsSync(configPath)) {
        args.push("--config", configPath);
      } else if (options.nodeId) {
        args.push("--node-id", options.nodeId);
      }
      if (options.extraArgs) args.push(...options.extraArgs);
      return this.sandbox.reaper.spawn("daemon", this.bin, args, {
        env: options.env ?? this.sandbox.env,
        cwd: this.sandbox.paths.workspaceDir,
        stdio: ["ignore", "pipe", "pipe"],
      });
    };

    let handle = spawnDaemon();
    await this.waitReady(options.readyTimeoutMs ?? 10_000);

    // Register best-effort `hyp-inspect.json` capture before teardown on failure.
    this.sandbox.addForensicsProvider("hyp-inspect.json", async () => {
      try {
        const res = await this.inspect({ all: true, allowFailure: true });
        return res.json ?? { stdout: res.stdout, stderr: res.stderr, exitCode: res.exitCode };
      } catch (err) {
        return { error: String(err) };
      }
    });

    const controller: DaemonController = {
      get handle() {
        return handle;
      },
      configPath,
      socketPath: this.socketPath,
      stop: async () => {
        await this.sandbox.reaper.kill(handle, 3_000);
      },
      restart: async () => {
        await this.sandbox.reaper.kill(handle, 3_000);
        // Clean stale socket if daemon was force-killed.
        try {
          fs.rmSync(this.socketPath, { force: true });
        } catch {
          // ignore
        }
        handle = spawnDaemon();
        await this.waitReady(options.readyTimeoutMs ?? 10_000);
      },
    };
    this.activeDaemon = controller;
    return controller;
  }

  async stopDaemon(): Promise<void> {
    if (this.activeDaemon) {
      await this.activeDaemon.stop();
      this.activeDaemon = null;
    }
  }

  async restartDaemon(): Promise<void> {
    if (!this.activeDaemon) {
      throw new Error("restartDaemon() called when no active daemon controller exists");
    }
    await this.activeDaemon.restart();
  }

  /** Stores a secret strictly over stdin (never argv) and registers it with the Sandbox leak scanner. */
  async secretSet(name: string, value: string): Promise<ExecResult> {
    this.sandbox.registerSecret(name, value);
    return this.exec(
      ["secret", "set", name, "--state-dir", this.sandbox.paths.hyphaeStateDir, "--json"],
      { input: `${value}\n` },
    );
  }

  async inspect(
    options: { session?: string; handle?: string; all?: boolean; allowFailure?: boolean } = {},
  ): Promise<ExecResult> {
    const args = ["inspect", "--socket", this.socketPath, "--json"];
    if (options.session) args.push("--session", options.session);
    else if (options.handle) args.push("--handle", options.handle);
    else args.push("--all");
    return this.exec(args, { allowFailure: options.allowFailure });
  }

  async status(options: { allowFailure?: boolean } = {}): Promise<ExecResult> {
    return this.exec(
      ["status", "--state-dir", this.sandbox.paths.hyphaeStateDir, "--json"],
      { allowFailure: options.allowFailure },
    );
  }

  async doctor(options: { allowFailure?: boolean } = {}): Promise<ExecResult> {
    return this.exec(
      ["doctor", "--state-dir", this.sandbox.paths.hyphaeStateDir, "--json"],
      { allowFailure: options.allowFailure },
    );
  }

  async session(subArgs: string[], options: { allowFailure?: boolean } = {}): Promise<ExecResult> {
    return this.exec(["session", ...subArgs, "--socket", this.socketPath, "--json"], {
      allowFailure: options.allowFailure,
    });
  }

  async plugin(subArgs: string[], options: { allowFailure?: boolean } = {}): Promise<ExecResult> {
    return this.exec(
      ["plugin", ...subArgs, "--state-dir", this.sandbox.paths.hyphaeStateDir, "--json"],
      { allowFailure: options.allowFailure },
    );
  }

  async gate(subArgs: string[], options: { allowFailure?: boolean } = {}): Promise<ExecResult> {
    return this.exec(
      ["gate", ...subArgs, "--state-dir", this.sandbox.paths.hyphaeStateDir, "--json"],
      { allowFailure: options.allowFailure },
    );
  }

  /**
   * Executes human-CLI-only `hyp gate init ...` inside a real POSIX PTY and confirms
   * any interactive `[y/N]` prompt cleanly.
   */
  async gateInitPty(
    subArgs: string[],
    options: { timeoutMs?: number } = {},
  ): Promise<{ exitCode: number | null; output: string }> {
    const args = ["gate", "init", ...subArgs, "--state-dir", this.sandbox.paths.hyphaeStateDir];
    return runInteractivePtyCommand(this.sandbox, "hyp-gate-init", this.bin, args, {
      env: this.sandbox.env,
      promptPattern: /\[y\/N\]|confirm|proceed|lock/i,
      inputOnMatch: "y\n",
      timeoutMs: options.timeoutMs ?? 15_000,
    });
  }

  async inboxCli(subArgs: string[], options: { allowFailure?: boolean } = {}): Promise<ExecResult> {
    return this.exec(
      ["inbox", ...subArgs, "--state-dir", this.sandbox.paths.hyphaeStateDir, "--json"],
      { allowFailure: options.allowFailure },
    );
  }

  /**
   * Executes human-CLI-only `hyp inbox approve <receipt>` inside a real POSIX PTY and
   * confirms the interactive `[y/N]` prompt, proving both fail-closed non-TTY guard and live wake.
   */
  async approveQuarantinedPty(
    receipt: string,
    options: { reviewer?: string; timeoutMs?: number } = {},
  ): Promise<{ exitCode: number | null; output: string }> {
    const args = [
      "inbox",
      "approve",
      receipt,
      "--state-dir",
      this.sandbox.paths.hyphaeStateDir,
      "--reviewer",
      options.reviewer ?? "itest-human",
    ];
    return runInteractivePtyCommand(this.sandbox, "hyp-inbox-approve", this.bin, args, {
      env: this.sandbox.env,
      promptPattern: /\[y\/N\]|Approve quarantined item/i,
      inputOnMatch: "y\n",
      timeoutMs: options.timeoutMs ?? 15_000,
    });
  }

  async emit(subArgs: string[], options: { allowFailure?: boolean } = {}): Promise<ExecResult> {
    return this.exec(
      ["emit", ...subArgs, "--state-dir", this.sandbox.paths.hyphaeStateDir, "--json"],
      { allowFailure: options.allowFailure },
    );
  }

  daemonRpc(packet: Record<string, unknown>, timeoutMs = 5_000): Promise<any> {
    return daemonRpc(this.socketPath, packet, timeoutMs);
  }

  /**
   * Opens a real black-box `hyp mcp --ephemeral` peer session enrolled under `handle`,
   * allowing tests to send DMs or read inboxes strictly through the compiled binary.
   */
  async openPeer(
    handle: string,
    options: { backend?: string; label?: string } = {},
  ): Promise<{
    handle: string;
    client: HypMcpClient;
    joinResult: any;
    send: (to: string, text: string, extra?: Record<string, unknown>) => Promise<any>;
    inbox: (args?: Record<string, unknown>) => Promise<any>;
    mesh: (args: Record<string, unknown>) => Promise<any>;
    close: () => Promise<void>;
  }> {
    const args = ["mcp", this.socketPath, "--ephemeral"];
    if (options.backend) args.push("--backend", options.backend);
    const client = new HypMcpClient(this.sandbox, this.bin, args, options.label ?? `peer-${handle}`);
    await client.initialize(`peer-${handle}`);
    const joinRes = await client.callTool("hyp_mesh", { action: "join", handle });
    if (joinRes.isError) {
      await client.close();
      throw new Error(`Peer '${handle}' failed to join mesh: ${joinRes.text}`);
    }
    return {
      handle,
      client,
      joinResult: joinRes.json ?? joinRes.text,
      send: async (to: string, text: string, extra: Record<string, unknown> = {}) => {
        const res = await client.callTool("hyp_send", { to, text, ...extra });
        if (res.isError) {
          throw new Error(`hyp_send(${handle} -> ${to}) failed: ${res.text}`);
        }
        return res.json ?? res.text;
      },
      inbox: async (inboxArgs: Record<string, unknown> = { ack: true }) => {
        const res = await client.callTool("hyp_inbox", inboxArgs);
        if (res.isError) {
          throw new Error(`hyp_inbox(${handle}) failed: ${res.text}`);
        }
        return res.json ?? res.text;
      },
      mesh: async (meshArgs: Record<string, unknown>) => {
        const res = await client.callTool("hyp_mesh", meshArgs);
        if (res.isError) {
          throw new Error(`hyp_mesh(${handle}) failed: ${res.text}`);
        }
        return res.json ?? res.text;
      },
      close: () => client.close(),
    };
  }

  /** One-shot helper: sends a DM from `fromHandle` to `to` via real `hyp mcp --ephemeral`, leaving cleanly on exit. */
  async send(
    fromHandle: string,
    to: string,
    text: string,
    extra: Record<string, unknown> = {},
  ): Promise<any> {
    const peer = await this.openPeer(fromHandle);
    try {
      return await peer.send(to, text, extra);
    } finally {
      try {
        await peer.mesh({ action: "leave" });
      } catch {
        // ignore if daemon stopped
      }
      await peer.close();
    }
  }

  /** Reads a peer's inbox via real `hyp mcp --ephemeral`, leaving cleanly on exit. */
  async inbox(handle: string, args: Record<string, unknown> = { ack: false }): Promise<any> {
    const peer = await this.openPeer(handle);
    try {
      return await peer.inbox(args);
    } finally {
      try {
        await peer.mesh({ action: "leave" });
      } catch {
        // ignore
      }
      await peer.close();
    }
  }
}
