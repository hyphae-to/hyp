import { spawn, type ChildProcess, type ChildProcessWithoutNullStreams } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { loadConfig, type Config } from "../../../src/config.ts";
import { RouterCore } from "../../../src/core/router/core.ts";
import { serveRouter, type RunningRouter } from "../../../src/core/router/server.ts";
import { startDaemon, type RunningDaemon } from "../../../src/daemon.ts";
import { object } from "../../../src/protocol.ts";
import { writeSecret } from "../../../src/secrets.ts";
import { buildStreamTopicMap, RouterStreamHost } from "../../../src/streams.ts";
import type { RouterStreamConfig } from "../../../src/config.ts";

export function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = createServer();
    srv.listen(0, "127.0.0.1", () => {
      const addr = srv.address();
      srv.close(() => {
        if (addr && typeof addr === "object") resolve(addr.port);
        else reject(new Error("Could not allocate ephemeral loopback port"));
      });
    });
  });
}

/** Polls `predicate` until it returns a truthy value or throws a descriptive error on timeout. */
export async function waitFor<T>(
  predicate: () => Promise<T | null | undefined | false> | T | null | undefined | false,
  options: { readonly timeoutMs?: number; readonly intervalMs?: number; readonly label?: string } = {},
): Promise<T> {
  const timeoutMs = options.timeoutMs ?? 6_000;
  const intervalMs = options.intervalMs ?? 50;
  const deadline = Date.now() + timeoutMs;
  let lastError: unknown;
  while (Date.now() < deadline) {
    try {
      const value = await predicate();
      if (value) return value;
    } catch (err) {
      lastError = err;
    }
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  const detail = lastError instanceof Error ? ` (last error: ${lastError.message})` : "";
  throw new Error(`Timed out after ${timeoutMs}ms waiting for ${options.label ?? "condition"}${detail}`);
}

/** JSON-RPC 2.0 client over stdio driving a real `hyp mcp` subprocess. */
export class McpClient {
  readonly #proc: ChildProcessWithoutNullStreams;
  readonly #pending = new Map<number, (msg: Record<string, unknown>) => void>();
  readonly notifications: Record<string, unknown>[] = [];
  readonly stderr: string[] = [];
  #nextId = 0;

  constructor(socketPath: string, extraArgs: string[] = [], env: NodeJS.ProcessEnv = process.env) {
    this.#proc = spawn(process.execPath, [join(process.cwd(), "src", "cli.ts"), "mcp", socketPath, ...extraArgs], {
      env,
      stdio: ["pipe", "pipe", "pipe"],
    });
    this.#proc.stderr.on("data", (d: Buffer) => this.stderr.push(d.toString("utf8")));
    createInterface({ input: this.#proc.stdout }).on("line", (line) => {
      if (!line.trim()) return;
      let msg: unknown;
      try { msg = JSON.parse(line); } catch { return; }
      if (!object(msg)) return;
      if (typeof msg.id === "number") {
        const resolve = this.#pending.get(msg.id);
        if (resolve) {
          this.#pending.delete(msg.id);
          resolve(msg);
        }
      } else {
        this.notifications.push(msg);
      }
    });
  }

  async initialize(): Promise<Record<string, unknown>> {
    const res = await this.request("initialize", {
      protocolVersion: "2025-06-18",
      capabilities: {},
      clientInfo: { name: "hyphae-integration-test", version: "1" },
    });
    this.#proc.stdin.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n");
    return res;
  }

  request(method: string, params: Record<string, unknown> = {}, timeoutMs = 8_000): Promise<Record<string, unknown>> {
    const id = ++this.#nextId;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.#pending.delete(id);
        reject(new Error(`MCP request ${method} timed out`));
      }, timeoutMs).unref();
      this.#pending.set(id, (msg) => {
        clearTimeout(timer);
        resolve(msg);
      });
      this.#proc.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
    });
  }

  async callTool(
    name: string,
    args: Record<string, unknown>,
    meta?: Record<string, unknown>,
  ): Promise<{ text: string; isError: boolean; json(): unknown }> {
    const res = await this.request("tools/call", {
      name,
      arguments: args,
      ...(meta ? { _meta: meta } : {}),
    });
    const result = object(res.result) ? res.result : {};
    const content = Array.isArray(result.content) && object(result.content[0]) ? result.content[0] : {};
    const text = String(content.text ?? "");
    return {
      text,
      isError: result.isError === true,
      json: () => JSON.parse(text),
    };
  }

  close(): Promise<void> {
    return new Promise((resolve) => {
      if (this.#proc.exitCode !== null) { resolve(); return; }
      this.#proc.once("exit", () => resolve());
      this.#proc.stdin.end();
      setTimeout(() => { if (this.#proc.exitCode === null) this.#proc.kill("SIGKILL"); }, 1_000).unref();
    });
  }
}

export interface ManagedRouter {
  readonly name: string;
  readonly dbPath: string;
  readonly core: RouterCore;
  readonly url: string;
  readonly port: number;
  readonly tokens: Map<string, string>;
  readonly streams?: RouterStreamHost;
  /** Provision a connector token on this router (idempotent per connectorId in this fixture). */
  addConnector(connectorId: string): string;
  /** Stop the HTTP router server while keeping SQLite intact, then restart on the exact same port. */
  restart(): Promise<void>;
  close(): Promise<void>;
}

export interface RouterSpec {
  readonly name: string;
  readonly port?: number;
  readonly topics?: ReadonlyMap<string, readonly string[]>;
  readonly streams?: readonly RouterStreamConfig[];
}

export interface ConnectorLinkSpec {
  readonly name: string;
  readonly router: ManagedRouter;
}

export interface ConnectorDaemonSpec {
  readonly connectorId: string;
  readonly links: readonly ConnectorLinkSpec[];
  /** Optional raw JSON `plugins` array (resolved via `loadConfig` including `0600` `{ secret }` refs!). */
  readonly rawPlugins?: readonly Record<string, unknown>[];
  /** Optional raw JSON `localRouter` block (resolved via `loadConfig`). */
  readonly rawLocalRouter?: Record<string, unknown>;
  /** Optional secrets written with strict `0600` permissions before `loadConfig` runs. */
  readonly secrets?: Readonly<Record<string, string>>;
}

export interface ManagedConnector {
  readonly connectorId: string;
  readonly configDir: string;
  readonly configPath: string;
  readonly daemon: RunningDaemon;
  readonly socketPath: string;
  /** Spawn a real blocking `hyp wait` CLI process for a session or handle. */
  spawnWait(opts: { sessionId?: string; handle?: string; env?: NodeJS.ProcessEnv; timeoutSeconds?: number }): {
    readonly proc: ChildProcess;
    readonly output: Promise<{ code: number | null; stdout: string; stderr: string }>;
  };
  /** Spawn a real streaming `hyp watch` CLI process for a session or handle. */
  spawnWatch(opts: { sessionId?: string; handle?: string }): {
    readonly proc: ChildProcess;
    readonly lines: string[];
    waitForLine(predicate: (line: string) => boolean, timeoutMs?: number): Promise<string>;
    stop(): void;
  };
  /** Open a shared `hyp mcp` client against this daemon. */
  openMcp(extraArgs?: string[], env?: NodeJS.ProcessEnv): Promise<McpClient>;
  stop(): Promise<void>;
}

/**
 * Ephemeral multi-router, multi-connector test topology manager.
 * Guarantees isolated temp dirs, `port: 0` loopback bindings, strict `0600` credentials,
 * and deterministic teardown of every process, socket, server, and directory.
 */
export class MeshTopology {
  readonly rootDir: string;
  readonly #routers: ManagedRouter[] = [];
  readonly #connectors: ManagedConnector[] = [];
  readonly #children = new Set<ChildProcess>();
  readonly #mcpClients = new Set<McpClient>();
  readonly #closers: Array<() => Promise<void> | void> = [];

  constructor(prefix = "hi-") {
    // Keep temp path short so `<dir>/c0/s/connector.sock` stays well under macOS's 104-byte Unix socket path limit.
    const shortPrefix = prefix.length > 8 ? `hi-` : prefix;
    this.rootDir = mkdtempSync(join(tmpdir(), shortPrefix));
  }

  /** Register an arbitrary resource (e.g. dummy LLM server or mock Slack server) for automatic cleanup. */
  track(close: () => Promise<void> | void): void {
    this.#closers.push(close);
  }

  subDir(name: string): string {
    const path = join(this.rootDir, name);
    mkdirSync(path, { recursive: true, mode: 0o700 });
    return path;
  }

  async addRouter(spec: RouterSpec): Promise<ManagedRouter> {
    const routerDir = this.subDir(`router-${spec.name}`);
    const dbPath = join(routerDir, "router.sqlite");
    const topicMap = spec.streams && spec.streams.length > 0
      ? buildStreamTopicMap(spec.streams, spec.topics)
      : spec.topics;

    let core = new RouterCore({
      dbPath,
      ...(topicMap ? { topics: topicMap } : {}),
    });
    let server: RunningRouter = await serveRouter({
      core,
      host: "127.0.0.1",
      port: spec.port ?? 0,
    });
    const boundPort = Number(new URL(server.url).port);
    let streamHost: RouterStreamHost | undefined;
    if (spec.streams && spec.streams.length > 0) {
      streamHost = new RouterStreamHost(core, server.url, spec.streams);
      await streamHost.start();
    }

    const tokens = new Map<string, string>();
    const managed: ManagedRouter = {
      name: spec.name,
      dbPath,
      get core() { return core; },
      get url() { return server.url; },
      port: boundPort,
      tokens,
      get streams() { return streamHost; },
      addConnector(connectorId: string) {
        const existing = tokens.get(connectorId);
        if (existing) return existing;
        const token = core.addConnector(connectorId);
        tokens.set(connectorId, token);
        return token;
      },
      async restart() {
        if (streamHost) await streamHost.stop();
        await server.close();
        core.close();
        core = new RouterCore({
          dbPath,
          ...(topicMap ? { topics: topicMap } : {}),
        });
        server = await serveRouter({ core, host: "127.0.0.1", port: boundPort });
        if (spec.streams && spec.streams.length > 0) {
          streamHost = new RouterStreamHost(core, server.url, spec.streams);
          await streamHost.start();
        }
      },
      async close() {
        if (streamHost) {
          await streamHost.stop().catch(() => {});
          streamHost = undefined;
        }
        await server.close().catch(() => {});
        try { core.close(); } catch {}
      },
    };

    this.#routers.push(managed);
    return managed;
  }

  async addConnector(spec: ConnectorDaemonSpec): Promise<ManagedConnector> {
    const configDir = this.subDir(`c${this.#connectors.length}`);
    const stateDir = join(configDir, "s");
    mkdirSync(stateDir, { recursive: true, mode: 0o700 });

    if (spec.secrets) {
      for (const [name, value] of Object.entries(spec.secrets)) {
        writeSecret(name, value, configDir);
      }
    }

    let config: Config;
    const configPath = join(configDir, "connector.json");

    if (spec.rawPlugins || spec.rawLocalRouter) {
      const routersJson = spec.links.map((link) => {
        const token = link.router.addConnector(spec.connectorId);
        const tokenFile = join(configDir, `${link.name}.token`);
        writeFileSync(tokenFile, token + "\n", { mode: 0o600 });
        chmodSync(tokenFile, 0o600);
        return { name: link.name, url: link.router.url, tokenFile };
      });
      writeFileSync(
        configPath,
        JSON.stringify(
          {
            connectorId: spec.connectorId,
            stateDir: "s",
            routers: routersJson,
            ...(spec.rawLocalRouter ? { localRouter: spec.rawLocalRouter } : {}),
            ...(spec.rawPlugins ? { plugins: spec.rawPlugins } : {}),
          },
          null,
          2,
        ),
        { mode: 0o600 },
      );
      chmodSync(configPath, 0o600);
      config = loadConfig(configPath);
    } else {
      config = {
        connectorId: spec.connectorId,
        directory: stateDir,
        routers: spec.links.map((link) => ({
          name: link.name,
          url: link.router.url,
          token: link.router.addConnector(spec.connectorId),
        })),
      };
    }

    const daemon = await startDaemon(config, { quiet: true });
    const cliScript = join(process.cwd(), "src", "cli.ts");

    const managed: ManagedConnector = {
      connectorId: spec.connectorId,
      configDir,
      configPath,
      daemon,
      socketPath: daemon.socketPath,
      spawnWait: (opts) => {
        const args = [cliScript, "wait", "--socket", daemon.socketPath];
        if (opts.sessionId) args.push("--session", opts.sessionId);
        if (opts.handle) args.push("--handle", opts.handle);
        if (opts.timeoutSeconds !== undefined) args.push("--timeout", String(opts.timeoutSeconds));
        const proc = spawn(process.execPath, args, {
          env: opts.env ?? process.env,
          stdio: ["ignore", "pipe", "pipe"],
        });
        this.#children.add(proc);
        const out: Buffer[] = [];
        const err: Buffer[] = [];
        proc.stdout?.on("data", (d: Buffer) => out.push(d));
        proc.stderr?.on("data", (d: Buffer) => err.push(d));
        const output = new Promise<{ code: number | null; stdout: string; stderr: string }>((resolve) => {
          proc.once("exit", (code) => {
            this.#children.delete(proc);
            resolve({
              code,
              stdout: Buffer.concat(out).toString("utf8"),
              stderr: Buffer.concat(err).toString("utf8"),
            });
          });
        });
        return { proc, output };
      },
      spawnWatch: (opts) => {
        const args = [cliScript, "watch", "--socket", daemon.socketPath];
        if (opts.sessionId) args.push("--session", opts.sessionId);
        if (opts.handle) args.push("--handle", opts.handle);
        const proc = spawn(process.execPath, args, { stdio: ["ignore", "pipe", "pipe"] });
        this.#children.add(proc);
        const lines: string[] = [];
        const waiters = new Set<(line: string) => void>();
        createInterface({ input: proc.stdout! }).on("line", (line) => {
          if (!line.trim()) return;
          lines.push(line);
          for (const fn of waiters) fn(line);
        });
        proc.once("exit", () => this.#children.delete(proc));
        return {
          proc,
          lines,
          waitForLine(predicate, timeoutMs = 6_000) {
            const existing = lines.find(predicate);
            if (existing) return Promise.resolve(existing);
            return new Promise<string>((resolve, reject) => {
              const timer = setTimeout(() => {
                waiters.delete(onLine);
                reject(new Error(`Timed out waiting for hyp watch line (saw ${lines.length} line(s))`));
              }, timeoutMs).unref();
              const onLine = (line: string) => {
                if (predicate(line)) {
                  clearTimeout(timer);
                  waiters.delete(onLine);
                  resolve(line);
                }
              };
              waiters.add(onLine);
            });
          },
          stop() {
            if (proc.exitCode === null) proc.kill("SIGTERM");
          },
        };
      },
      openMcp: async (extraArgs = [], env = process.env) => {
        const client = new McpClient(daemon.socketPath, extraArgs, env);
        this.#mcpClients.add(client);
        await client.initialize();
        return client;
      },
      stop: () => daemon.stop(),
    };

    this.#connectors.push(managed);
    return managed;
  }

  async cleanup(): Promise<void> {
    for (const child of [...this.#children]) {
      try { child.kill("SIGTERM"); } catch {}
    }
    this.#children.clear();

    for (const client of [...this.#mcpClients]) {
      await client.close().catch(() => {});
    }
    this.#mcpClients.clear();

    for (const close of [...this.#closers].reverse()) {
      await Promise.resolve(close()).catch(() => {});
    }
    this.#closers.length = 0;

    for (const connector of [...this.#connectors].reverse()) {
      await connector.stop().catch(() => {});
    }
    this.#connectors.length = 0;

    for (const router of [...this.#routers].reverse()) {
      await router.close().catch(() => {});
    }
    this.#routers.length = 0;

    rmSync(this.rootDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
  }
}
