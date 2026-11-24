import { spawn, type ChildProcess, type ChildProcessWithoutNullStreams } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { createInterface } from "node:readline";
import { daemonRpc, handleHookPayload, type HookEvent } from "../../../src/hooks.ts";
import { object } from "../../../src/protocol.ts";
import { setupOpenClaw, type RuntimePaths, type SetupResult } from "../../../src/setup.ts";
import { devRuntime } from "../harness/drivers.ts";
import { waitFor } from "../harness/topology.ts";

export interface OpenClawToolResult {
  readonly text: string;
  readonly isError: boolean;
  json<T = unknown>(): T;
}

export interface OpenClawMcpTool {
  readonly name: string;
  readonly description: string;
  readonly inputSchema: Record<string, unknown>;
}

export interface OpenClawServerSpec {
  readonly command: string;
  readonly args: string[];
}

export interface OpenClawWaitOptions {
  readonly sessionId?: string;
  readonly handle?: string;
  readonly timeoutSeconds?: number;
  readonly env?: NodeJS.ProcessEnv;
}

export interface OpenClawWaitHandle {
  readonly proc: ChildProcess;
  readonly output: Promise<{ readonly code: number | null; readonly stdout: string; readonly stderr: string }>;
  /** Waits until the daemon registers this waiter as a live transport (or the waiter exits early). */
  waitUntilReady(timeoutMs?: number): Promise<void>;
  stop(): void;
}

export interface OpenClawWatchOptions {
  readonly sessionId?: string;
  readonly handle?: string;
  readonly env?: NodeJS.ProcessEnv;
}

export interface OpenClawWatchHandle {
  readonly proc: ChildProcess;
  readonly lines: string[];
  waitUntilReady(timeoutMs?: number): Promise<void>;
  waitForLine(predicate: (line: string) => boolean, timeoutMs?: number): Promise<string>;
  stop(): void;
}

export interface OpenClawHookOptions {
  /** Execute via real `hyp hook openclaw <event>` subprocess (default) or in-process `handleHookPayload`. */
  readonly mode?: "cli" | "direct";
  readonly timeoutMs?: number;
  /** Auto-fill `session_id` from the session's raw UUID when payload does not specify a session ID (default: true). */
  readonly autoAttachSessionId?: boolean;
}

export interface OpenClawCapabilities {
  readonly sessionId: string;
  readonly backend: string;
  readonly modes: string[];
  readonly deliveryMode: "full" | "notify";
  readonly unread: number;
  readonly mutes: number;
  readonly routers: string[];
  readonly inbound: string;
}

export interface VirtualOpenClawEnvOptions {
  readonly scope?: "user" | "project";
  readonly homeDir: string;
  readonly projectDir?: string;
  readonly socketPath?: string;
  readonly runtime?: RuntimePaths;
  /** Optional pre-seeded `openclaw.json` content written before `setupOpenClaw` runs. */
  readonly seedConfig?: Record<string, unknown> | string;
  /** Whether to run `setupOpenClaw` immediately during construction (default: true). */
  readonly runSetup?: boolean;
  /** Extra environment variables merged into isolated OpenClaw child processes. */
  readonly env?: NodeJS.ProcessEnv;
}

export interface OpenSessionOptions {
  /** Automatically call `hyp_capabilities` on boot to populate `sessionId` (default: true). */
  readonly eagerCapabilities?: boolean;
  readonly env?: NodeJS.ProcessEnv;
}

function buildIsolatedOpenClawEnv(homeDir: string, extra?: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const xdgConfig = join(homeDir, ".config");
  const xdgData = join(homeDir, ".local", "share");
  const xdgCache = join(homeDir, ".cache");
  const xdgState = join(homeDir, ".local", "state");
  mkdirSync(xdgConfig, { recursive: true });

  const env: NodeJS.ProcessEnv = {
    ...process.env,
    HOME: homeDir,
    XDG_CONFIG_HOME: xdgConfig,
    XDG_DATA_HOME: xdgData,
    XDG_CACHE_HOME: xdgCache,
    XDG_STATE_HOME: xdgState,
  };
  delete env.HC_TERMINAL_ID;
  delete env.ANTIGRAVITY_SOURCE_METADATA;
  delete env.CLAUDE_SESSION_ID;
  delete env.CODEX_THREAD_ID;
  delete env.HYPHAE_SOCKET;
  delete env.AGENTS_MESH_SOCKET;
  return { ...env, ...(extra ?? {}) };
}

function resolveSocketFromArgs(args: readonly string[], fallback?: string): string | undefined {
  const mcpIdx = args.indexOf("mcp");
  if (mcpIdx >= 0) {
    const candidate = args[mcpIdx + 1];
    if (typeof candidate === "string" && candidate.length > 0 && !candidate.startsWith("-")) {
      return candidate;
    }
  }
  return fallback;
}

function runCliHook(
  runtime: RuntimePaths,
  socketPath: string,
  event: HookEvent,
  payload: Record<string, unknown>,
  env: NodeJS.ProcessEnv,
  timeoutMs = 10_000,
): Promise<Record<string, unknown>> {
  return new Promise((resolvePromise, rejectPromise) => {
    const proc = spawn(runtime.nodeBin, [runtime.cliScript, "hook", "openclaw", event, "--socket", socketPath], {
      env,
      stdio: ["pipe", "pipe", "pipe"],
    });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    proc.stdout.on("data", (d: Buffer) => out.push(d));
    proc.stderr.on("data", (d: Buffer) => err.push(d));

    const timer = setTimeout(() => {
      try { proc.kill("SIGKILL"); } catch {}
      rejectPromise(new Error(`OpenClaw hook '${event}' timed out after ${timeoutMs}ms`));
    }, timeoutMs).unref();

    proc.once("error", (error) => {
      clearTimeout(timer);
      rejectPromise(error);
    });
    proc.once("exit", (code) => {
      clearTimeout(timer);
      const stdout = Buffer.concat(out).toString("utf8").trim();
      const stderr = Buffer.concat(err).toString("utf8").trim();
      if (code !== 0) {
        rejectPromise(new Error(`OpenClaw hook '${event}' exited ${code}: ${stderr || stdout}`));
        return;
      }
      if (!stdout) {
        resolvePromise({});
        return;
      }
      try {
        const parsed: unknown = JSON.parse(stdout);
        if (!object(parsed)) {
          rejectPromise(new Error(`Expected JSON object from OpenClaw hook '${event}', got: ${stdout}`));
          return;
        }
        resolvePromise(parsed);
      } catch (error) {
        rejectPromise(new Error(`Failed to parse OpenClaw hook '${event}' JSON stdout (${stdout}): ${error instanceof Error ? error.message : String(error)}`));
      }
    });

    proc.stdin.end(JSON.stringify(payload));
  });
}

function killChildProcess(proc: ChildProcess): Promise<void> {
  return new Promise((resolvePromise) => {
    if (proc.exitCode !== null || proc.killed) {
      resolvePromise();
      return;
    }
    const timer = setTimeout(() => {
      try { if (proc.exitCode === null) proc.kill("SIGKILL"); } catch {}
      resolvePromise();
    }, 1_500).unref();
    proc.once("exit", () => {
      clearTimeout(timer);
      resolvePromise();
    });
    try { proc.kill("SIGTERM"); } catch {
      clearTimeout(timer);
      resolvePromise();
    }
  });
}

/**
 * A live OpenClaw MCP orchestrator session spawned strictly from `openclaw.json`'s
 * `mcp.servers.hyphae` (`command` + `args`) speaking real JSON-RPC 2.0 over stdio.
 */
export class OpenClawSession {
  readonly command: string;
  readonly args: readonly string[];
  readonly socketPath: string | undefined;
  readonly notifications: Record<string, unknown>[] = [];
  readonly stderr: string[] = [];

  readonly #proc: ChildProcessWithoutNullStreams;
  readonly #runtime: RuntimePaths;
  readonly #env: NodeJS.ProcessEnv;
  readonly #pending = new Map<number, { resolve: (msg: Record<string, unknown>) => void; reject: (err: Error) => void }>();
  readonly #children = new Set<ChildProcess>();

  #nextId = 0;
  #initResult: Record<string, unknown> | undefined;
  #sessionId: string | null = null;
  #capabilities: OpenClawCapabilities | null = null;
  #closed = false;

  constructor(opts: {
    readonly command: string;
    readonly args: readonly string[];
    readonly socketPath?: string;
    readonly runtime: RuntimePaths;
    readonly env: NodeJS.ProcessEnv;
    readonly cwd?: string;
  }) {
    this.command = opts.command;
    this.args = [...opts.args];
    this.socketPath = opts.socketPath ?? resolveSocketFromArgs(opts.args) ?? opts.env.HYPHAE_SOCKET;
    this.#runtime = opts.runtime;
    this.#env = opts.env;

    this.#proc = spawn(opts.command, [...opts.args], {
      cwd: opts.cwd,
      env: opts.env,
      stdio: ["pipe", "pipe", "pipe"],
    });
    this.#proc.stderr.on("data", (chunk: Buffer) => this.stderr.push(chunk.toString("utf8")));
    this.#proc.once("exit", (code, signal) => {
      for (const [id, entry] of this.#pending) {
        this.#pending.delete(id);
        entry.reject(new Error(`OpenClaw MCP subprocess exited unexpectedly (code=${code}, signal=${signal}): ${this.stderr.join("")}`));
      }
    });

    const rl = createInterface({ input: this.#proc.stdout });
    rl.on("error", () => {});
    rl.on("line", (line) => {
      if (!line.trim()) return;
      let msg: unknown;
      try { msg = JSON.parse(line); } catch { return; }
      if (!object(msg)) return;
      if (typeof msg.id === "number") {
        const entry = this.#pending.get(msg.id);
        if (entry) {
          this.#pending.delete(msg.id);
          entry.resolve(msg);
        }
      } else {
        this.notifications.push(msg);
      }
    });
  }

  get initResult(): Record<string, unknown> | undefined {
    return this.#initResult;
  }

  get sessionId(): string | null {
    return this.#sessionId;
  }

  get rawSessionId(): string | null {
    if (!this.#sessionId) return null;
    return this.#sessionId.startsWith("openclaw:") ? this.#sessionId.slice("openclaw:".length) : this.#sessionId;
  }

  get capabilities(): OpenClawCapabilities | null {
    return this.#capabilities;
  }

  async initialize(): Promise<Record<string, unknown>> {
    const res = await this.request("initialize", {
      protocolVersion: "2025-06-18",
      capabilities: {},
      clientInfo: { name: "openclaw-gateway-virtual", version: "1.0.0" },
    });
    this.#proc.stdin.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n");
    this.#initResult = res;
    return res;
  }

  request(method: string, params: Record<string, unknown> = {}, timeoutMs = 10_000): Promise<Record<string, unknown>> {
    if (this.#closed) return Promise.reject(new Error(`OpenClaw session already closed (method: ${method})`));
    const id = ++this.#nextId;
    return new Promise((resolvePromise, rejectPromise) => {
      const timer = setTimeout(() => {
        this.#pending.delete(id);
        rejectPromise(new Error(`OpenClaw MCP request '${method}' timed out after ${timeoutMs}ms (stderr: ${this.stderr.join("")})`));
      }, timeoutMs).unref();
      this.#pending.set(id, {
        resolve: (msg) => {
          clearTimeout(timer);
          resolvePromise(msg);
        },
        reject: (err) => {
          clearTimeout(timer);
          rejectPromise(err);
        },
      });
      this.#proc.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
    });
  }

  async listTools(): Promise<OpenClawMcpTool[]> {
    const res = await this.request("tools/list");
    const result = object(res.result) ? res.result : {};
    if (!Array.isArray(result.tools)) return [];
    return result.tools.filter(object).map((entry) => ({
      name: String(entry.name ?? ""),
      description: String(entry.description ?? ""),
      inputSchema: object(entry.inputSchema) ? entry.inputSchema : {},
    }));
  }

  async callTool(
    name: string,
    args: Record<string, unknown> = {},
    meta?: Record<string, unknown>,
  ): Promise<OpenClawToolResult> {
    const res = await this.request("tools/call", {
      name,
      arguments: args,
      ...(meta ? { _meta: meta } : {}),
    });
    const result = object(res.result) ? res.result : {};
    const content = Array.isArray(result.content) && object(result.content[0]) ? result.content[0] : {};
    const text = String(content.text ?? "");
    const isError = result.isError === true;

    if (name === "hyp_capabilities" && !isError) {
      try {
        const parsed = JSON.parse(text) as OpenClawCapabilities;
        if (object(parsed) && typeof parsed.sessionId === "string") {
          this.#sessionId = parsed.sessionId;
          this.#capabilities = parsed;
        }
      } catch {}
    }

    return {
      text,
      isError,
      json: <T = unknown>() => JSON.parse(text) as T,
    };
  }

  async getCapabilities(): Promise<OpenClawCapabilities> {
    const res = await this.callTool("hyp_capabilities", {});
    if (res.isError) throw new Error(`hyp_capabilities failed: ${res.text}`);
    return res.json<OpenClawCapabilities>();
  }

  async ensureSessionId(): Promise<string> {
    if (this.#sessionId) return this.#sessionId;
    const caps = await this.getCapabilities();
    return caps.sessionId;
  }

  spawnWait(opts: OpenClawWaitOptions = {}): OpenClawWaitHandle {
    const socketPath = this.socketPath;
    if (!socketPath) throw new Error("Cannot spawn `hyp wait`: no socketPath configured on OpenClawSession");
    const targetSession = opts.sessionId ?? (opts.handle ? undefined : this.#sessionId ?? undefined);
    const args = [this.#runtime.cliScript, "wait", "--socket", socketPath];
    if (targetSession) args.push("--session", targetSession);
    if (opts.handle) args.push("--handle", opts.handle);
    if (opts.timeoutSeconds !== undefined) args.push("--timeout", String(opts.timeoutSeconds));

    const proc = spawn(this.#runtime.nodeBin, args, {
      env: opts.env ? { ...this.#env, ...opts.env } : this.#env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    this.#children.add(proc);
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    proc.stdout?.on("data", (d: Buffer) => out.push(d));
    proc.stderr?.on("data", (d: Buffer) => err.push(d));

    const output = new Promise<{ readonly code: number | null; readonly stdout: string; readonly stderr: string }>((resolvePromise) => {
      proc.once("exit", (code) => {
        this.#children.delete(proc);
        resolvePromise({
          code,
          stdout: Buffer.concat(out).toString("utf8"),
          stderr: Buffer.concat(err).toString("utf8"),
        });
      });
    });

    const waitUntilReady = async (timeoutMs = 6_000): Promise<void> => {
      await waitFor(
        async () => {
          if (proc.exitCode !== null) return true;
          if (targetSession) {
            const status = await daemonRpc(socketPath, { type: "session.status", sessionId: targetSession }, 1_000);
            return status.ok && status.result?.hasLiveTransport === true;
          }
          if (opts.handle) {
            const status = await daemonRpc(socketPath, { type: "daemon.status" }, 1_000);
            const sessions = status.ok && Array.isArray(status.result?.sessions) ? status.result.sessions : [];
            const match = sessions.find((s) => object(s) && s.handle === opts.handle);
            return Boolean(match && object(match) && match.hasLiveTransport === true);
          }
          return false;
        },
        { timeoutMs, intervalMs: 40, label: `OpenClaw hyp wait ready (${targetSession ?? opts.handle ?? "unknown"})` },
      );
    };

    return {
      proc,
      output,
      waitUntilReady,
      stop() {
        if (proc.exitCode === null) {
          try { proc.kill("SIGTERM"); } catch {}
        }
      },
    };
  }

  spawnWatch(opts: OpenClawWatchOptions = {}): OpenClawWatchHandle {
    const socketPath = this.socketPath;
    if (!socketPath) throw new Error("Cannot spawn `hyp watch`: no socketPath configured on OpenClawSession");
    const targetSession = opts.sessionId ?? (opts.handle ? undefined : this.#sessionId ?? undefined);
    const args = [this.#runtime.cliScript, "watch", "--socket", socketPath];
    if (targetSession) args.push("--session", targetSession);
    if (opts.handle) args.push("--handle", opts.handle);

    const proc = spawn(this.#runtime.nodeBin, args, {
      env: opts.env ? { ...this.#env, ...opts.env } : this.#env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    this.#children.add(proc);
    const lines: string[] = [];
    const waiters = new Set<(line: string) => void>();
    const rl = createInterface({ input: proc.stdout! });
    rl.on("error", () => {});
    rl.on("line", (line) => {
      if (!line.trim()) return;
      lines.push(line);
      for (const fn of waiters) fn(line);
    });
    proc.once("exit", () => this.#children.delete(proc));

    const waitUntilReady = async (timeoutMs = 6_000): Promise<void> => {
      await waitFor(
        async () => {
          if (proc.exitCode !== null) return true;
          if (targetSession) {
            const status = await daemonRpc(socketPath, { type: "session.status", sessionId: targetSession }, 1_000);
            return status.ok && status.result?.hasLiveTransport === true;
          }
          if (opts.handle) {
            const status = await daemonRpc(socketPath, { type: "daemon.status" }, 1_000);
            const sessions = status.ok && Array.isArray(status.result?.sessions) ? status.result.sessions : [];
            const match = sessions.find((s) => object(s) && s.handle === opts.handle);
            return Boolean(match && object(match) && match.hasLiveTransport === true);
          }
          return false;
        },
        { timeoutMs, intervalMs: 40, label: `OpenClaw hyp watch ready (${targetSession ?? opts.handle ?? "unknown"})` },
      );
    };

    return {
      proc,
      lines,
      waitUntilReady,
      waitForLine(predicate, timeoutMs = 6_000) {
        const existing = lines.find(predicate);
        if (existing) return Promise.resolve(existing);
        return new Promise<string>((resolvePromise, rejectPromise) => {
          const timer = setTimeout(() => {
            waiters.delete(onLine);
            rejectPromise(new Error(`Timed out waiting for OpenClaw hyp watch line (saw ${lines.length} line(s))`));
          }, timeoutMs).unref();
          const onLine = (line: string) => {
            if (predicate(line)) {
              clearTimeout(timer);
              waiters.delete(onLine);
              resolvePromise(line);
            }
          };
          waiters.add(onLine);
        });
      },
      stop() {
        if (proc.exitCode === null) {
          try { proc.kill("SIGTERM"); } catch {}
        }
      },
    };
  }

  async runHook(
    event: HookEvent,
    payload: Record<string, unknown> = {},
    opts: OpenClawHookOptions = {},
  ): Promise<Record<string, unknown>> {
    const socketPath = this.socketPath;
    if (!socketPath) throw new Error("Cannot run OpenClaw hook: no socketPath configured");

    const hasExplicitSession =
      "session_id" in payload || "sessionId" in payload || "thread_id" in payload || "threadId" in payload;
    const effectivePayload: Record<string, unknown> =
      opts.autoAttachSessionId === false || hasExplicitSession || !this.rawSessionId
        ? { ...payload }
        : { session_id: this.rawSessionId, ...payload };

    if (opts.mode === "direct") {
      return handleHookPayload(effectivePayload, {
        harness: "openclaw",
        event,
        socketPath,
        explicitSocket: socketPath,
        cliPath: `${this.#runtime.nodeBin} ${this.#runtime.cliScript}`,
      });
    }
    return runCliHook(this.#runtime, socketPath, event, effectivePayload, this.#env, opts.timeoutMs);
  }

  async close(): Promise<void> {
    if (this.#closed) return;
    this.#closed = true;

    const childCloses = [...this.#children].map((child) => killChildProcess(child));
    this.#children.clear();
    await Promise.all(childCloses);

    await new Promise<void>((resolvePromise) => {
      if (this.#proc.exitCode !== null) {
        resolvePromise();
        return;
      }
      const timer = setTimeout(() => {
        try { if (this.#proc.exitCode === null) this.#proc.kill("SIGKILL"); } catch {}
        resolvePromise();
      }, 1_500).unref();
      this.#proc.once("exit", () => {
        clearTimeout(timer);
        resolvePromise();
      });
      this.#proc.stdin.end();
    });
  }
}

/**
 * Virtual OpenClaw Gateway & Orchestrator host environment:
 * - Runs `setupOpenClaw(...)` into an isolated user or project directory (preserving seeded gateway settings)
 * - Parses the exact generated `openclaw.json` (`mcp.servers.hyphae.command` & `args`)
 * - Spawns one or more concurrent live JSON-RPC 2.0 MCP subprocesses directly from that config
 * - Exposes clean helpers for tool calls, blocking `hyp wait`, streaming `hyp watch`, and `hyp hook openclaw <event>`
 */
export class VirtualOpenClawEnv {
  readonly scope: "user" | "project";
  readonly homeDir: string;
  readonly projectDir: string;
  readonly baseDir: string;
  readonly configPath: string;
  readonly skillPath: string;
  readonly socketPath: string | undefined;
  readonly runtime: RuntimePaths;
  readonly sessions: OpenClawSession[] = [];

  readonly #env: NodeJS.ProcessEnv;
  #setupResult: SetupResult | undefined;

  constructor(options: VirtualOpenClawEnvOptions) {
    this.scope = options.scope ?? "user";
    this.homeDir = resolve(options.homeDir);
    this.projectDir = resolve(options.projectDir ?? options.homeDir);
    this.baseDir = this.scope === "project" ? join(this.projectDir, ".openclaw") : join(this.homeDir, ".openclaw");
    this.configPath = join(this.baseDir, "openclaw.json");
    this.skillPath = join(this.baseDir, "skills", "hyphae", "SKILL.md");
    this.socketPath = options.socketPath;
    this.runtime = options.runtime ?? devRuntime();
    this.#env = buildIsolatedOpenClawEnv(this.homeDir, options.env);

    mkdirSync(this.homeDir, { recursive: true, mode: 0o700 });
    if (this.scope === "project") mkdirSync(this.projectDir, { recursive: true, mode: 0o700 });

    if (options.seedConfig !== undefined) {
      mkdirSync(dirname(this.configPath), { recursive: true, mode: 0o700 });
      const raw = typeof options.seedConfig === "string"
        ? options.seedConfig
        : JSON.stringify(options.seedConfig, null, 2) + "\n";
      writeFileSync(this.configPath, raw, "utf8");
    }

    if (options.runSetup !== false) {
      this.setup();
    }
  }

  get setupResult(): SetupResult | undefined {
    return this.#setupResult;
  }

  get primarySession(): OpenClawSession | undefined {
    return this.sessions[0];
  }

  get sessionId(): string | null {
    return this.primarySession?.sessionId ?? null;
  }

  /** Runs `setupOpenClaw` against this virtual OpenClaw environment (safe to call repeatedly for idempotency tests). */
  setup(): SetupResult {
    this.#setupResult = setupOpenClaw({
      scope: this.scope,
      homeDir: this.homeDir,
      projectDir: this.projectDir,
      socketPath: this.socketPath,
      runtime: this.runtime,
    });
    return this.#setupResult;
  }

  readConfig(): Record<string, unknown> {
    const parsed: unknown = JSON.parse(readFileSync(this.configPath, "utf8"));
    if (!object(parsed)) throw new Error(`Expected JSON object in ${this.configPath}`);
    return parsed;
  }

  /** Parses the exact `mcp.servers.hyphae` command & args generated inside `openclaw.json`. */
  readHyphaeServerConfig(): OpenClawServerSpec {
    const doc = this.readConfig();
    if (!object(doc.mcp) || !object(doc.mcp.servers) || !object(doc.mcp.servers.hyphae)) {
      throw new Error(`Missing mcp.servers.hyphae in ${this.configPath}`);
    }
    const entry = doc.mcp.servers.hyphae;
    if (typeof entry.command !== "string" || entry.command.length === 0) {
      throw new Error(`Invalid mcp.servers.hyphae.command in ${this.configPath}`);
    }
    if (!Array.isArray(entry.args) || !entry.args.every((item): item is string => typeof item === "string")) {
      throw new Error(`Invalid mcp.servers.hyphae.args in ${this.configPath}`);
    }
    return { command: entry.command, args: [...entry.args] };
  }

  readSkill(): string {
    return readFileSync(this.skillPath, "utf8");
  }

  /**
   * Spawns a fresh live OpenClaw MCP subprocess from the exact `openclaw.json` server entry.
   * Calling this multiple times boots independent concurrent `openclaw:<uuid>` sessions from the same config.
   */
  async openSession(opts: OpenSessionOptions = {}): Promise<OpenClawSession> {
    const server = this.readHyphaeServerConfig();
    const session = new OpenClawSession({
      command: server.command,
      args: server.args,
      socketPath: this.socketPath,
      runtime: this.runtime,
      env: opts.env ? { ...this.#env, ...opts.env } : this.#env,
      cwd: this.projectDir,
    });
    this.sessions.push(session);
    try {
      await session.initialize();
      if (opts.eagerCapabilities !== false) {
        await session.getCapabilities();
      }
      return session;
    } catch (error) {
      await session.close().catch(() => {});
      const idx = this.sessions.indexOf(session);
      if (idx >= 0) this.sessions.splice(idx, 1);
      throw error;
    }
  }

  async #ensurePrimary(): Promise<OpenClawSession> {
    return this.primarySession ?? this.openSession();
  }

  async listTools(): Promise<OpenClawMcpTool[]> {
    return (await this.#ensurePrimary()).listTools();
  }

  async callTool(
    name: string,
    args: Record<string, unknown> = {},
    meta?: Record<string, unknown>,
  ): Promise<OpenClawToolResult> {
    return (await this.#ensurePrimary()).callTool(name, args, meta);
  }

  spawnWait(opts: OpenClawWaitOptions = {}): OpenClawWaitHandle {
    const primary = this.primarySession;
    if (!primary) throw new Error("Open an OpenClaw session via openSession() or callTool() before spawnWait()");
    return primary.spawnWait(opts);
  }

  spawnWatch(opts: OpenClawWatchOptions = {}): OpenClawWatchHandle {
    const primary = this.primarySession;
    if (!primary) throw new Error("Open an OpenClaw session via openSession() or callTool() before spawnWatch()");
    return primary.spawnWatch(opts);
  }

  async runHook(
    event: HookEvent,
    payload: Record<string, unknown> = {},
    opts: OpenClawHookOptions = {},
  ): Promise<Record<string, unknown>> {
    const primary = this.primarySession;
    if (primary) return primary.runHook(event, payload, opts);
    const socketPath = this.socketPath ?? this.#env.HYPHAE_SOCKET;
    if (!socketPath) throw new Error("Cannot run OpenClaw hook: no socketPath configured");
    if (opts.mode === "direct") {
      return handleHookPayload(payload, {
        harness: "openclaw",
        event,
        socketPath,
        explicitSocket: socketPath,
        cliPath: `${this.runtime.nodeBin} ${this.runtime.cliScript}`,
      });
    }
    return runCliHook(this.runtime, socketPath, event, payload, this.#env, opts.timeoutMs);
  }

  async close(): Promise<void> {
    const sessions = [...this.sessions];
    this.sessions.length = 0;
    await Promise.all(sessions.map((session) => session.close().catch(() => {})));
  }
}
