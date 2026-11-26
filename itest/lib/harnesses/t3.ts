/**
 * Real black-box T3 Code (`t3 serve`) orchestrator driver + schema-pinned loopback contract fallback.
 *
 * Drives the real installed `t3` binary in a strictly isolated `--base-dir` inside the per-test
 * `Sandbox` (tracked by `ProcessReaper` `-pgid` kill; never touches host `~/.t3`!):
 *  - `t3 project add --base-dir <t3Dir> <wsDir>`
 *  - `t3 serve --mode desktop --host 127.0.0.1 --port <P> --base-dir <t3Dir> --no-browser <wsDir>`
 *  - `t3 auth session issue --base-dir <t3Dir> --token-only`
 *  - Authentic `GET /api/auth/session`, `POST /api/auth/websocket-ticket`, and Effect RPC over WS
 *    (`/ws?wsTicket=...&orchestrationProtocol=2`: `orchestration.getThreadProjection`,
 *    `orchestration.dispatchCommand`).
 *
 * When `t3` is unavailable (e.g., Linux CI without the `t3` binary), `T3ContractMockServer`
 * provides a schema-pinned loopback HTTP + RFC 6455 WS + `statev2.sqlite` contract fallback
 * matching real T3 orchestration protocol v2 byte-for-byte.
 */

import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { resolveToolBinary } from "../../scripts/provision.mjs";
import { getFreePort, readHttpBody, waitUntil, writeJson } from "../mocks/helpers.ts";
import { LoopbackWsServer } from "../mocks/ws-server.ts";
import type { Sandbox, TrackedProcess } from "../sandbox.ts";

export function resolveT3Bin(): string | null {
  const info = resolveToolBinary("t3", { useHostBins: true, probeVersion: false });
  return info.path;
}

export interface HttpResponseLite {
  status: number;
  text: string;
  json: any;
}

function loopbackHttpRequest(
  url: string,
  options: { method?: string; headers?: Record<string, string>; body?: string; timeoutMs?: number } = {},
): Promise<HttpResponseLite> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      url,
      {
        method: options.method ?? "GET",
        headers: options.headers ?? {},
        timeout: options.timeoutMs ?? 5_000,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf8");
          let json: any = null;
          try {
            json = JSON.parse(text);
          } catch {
            json = null;
          }
          resolve({ status: res.statusCode ?? 0, text, json });
        });
      },
    );
    req.on("error", reject);
    req.on("timeout", () => req.destroy(new Error(`HTTP ${options.method ?? "GET"} ${url} timed out`)));
    if (options.body) req.write(options.body);
    req.end();
  });
}

export interface T3DispatchedMessage {
  messageId: string;
  threadId: string;
  role: string;
  text: string;
  payload: any;
}

export interface T3BackendHandle {
  readonly kind: "real" | "contract-mock";
  readonly baseDir: string;
  readonly dbPath: string;
  readonly serverUrl: string;
  readonly projectId: string;
  readonly bearerToken: string;
  probeSession(token?: string): Promise<HttpResponseLite>;
  requestWebsocketTicket(token?: string): Promise<HttpResponseLite>;
  createThread(title?: string): Promise<string>;
  archiveThread(threadId: string): Promise<void>;
  deleteThread(threadId: string): Promise<void>;
  getThreadProjection(threadId: string): Promise<any>;
  bindProviderSession(providerSessionId: string, threadId: string): void;
  readDispatchedMessages(threadId: string): T3DispatchedMessage[];
  waitForDispatchedMessage(
    threadId: string,
    predicate: (msg: T3DispatchedMessage) => boolean,
    timeoutMs?: number,
  ): Promise<T3DispatchedMessage>;
  close(): Promise<void>;
}

/**
 * Runs a real isolated `t3 serve` server inside `sandbox` with its own `--base-dir`.
 */
export class RealT3Server implements T3BackendHandle {
  readonly kind = "real" as const;
  readonly sandbox: Sandbox;
  readonly t3Bin: string;
  readonly baseDir: string;
  readonly dbPath: string;
  readonly port: number;
  readonly serverUrl: string;
  readonly projectId: string;
  readonly bearerToken: string;
  readonly env: Record<string, string>;
  readonly proc: TrackedProcess;

  private constructor(init: {
    sandbox: Sandbox;
    t3Bin: string;
    baseDir: string;
    dbPath: string;
    port: number;
    serverUrl: string;
    projectId: string;
    bearerToken: string;
    env: Record<string, string>;
    proc: TrackedProcess;
  }) {
    this.sandbox = init.sandbox;
    this.t3Bin = init.t3Bin;
    this.baseDir = init.baseDir;
    this.dbPath = init.dbPath;
    this.port = init.port;
    this.serverUrl = init.serverUrl;
    this.projectId = init.projectId;
    this.bearerToken = init.bearerToken;
    this.env = init.env;
    this.proc = init.proc;
  }

  static async start(options: {
    sandbox: Sandbox;
    t3Bin?: string;
    baseDir?: string;
    projectTitle?: string;
  }): Promise<RealT3Server> {
    const t3Bin = options.t3Bin ?? resolveT3Bin();
    if (!t3Bin) {
      throw new Error("t3 binary not found (set T3_BIN or install t3)");
    }

    const baseDir = options.baseDir ?? path.join(options.sandbox.paths.rootDir, "t3");
    fs.mkdirSync(baseDir, { recursive: true, mode: 0o700 });
    const dbPath = path.join(baseDir, "userdata", "statev2.sqlite");

    const env = options.sandbox.envWith({
      T3CODE_HOME: baseDir,
      PATH: `${path.dirname(t3Bin)}${path.delimiter}${options.sandbox.env.PATH}`,
    });

    // 1. Bootstrap a real project in the isolated `statev2.sqlite` via `t3 project add`.
    execFileSync(
      t3Bin,
      [
        "project",
        "add",
        "--base-dir",
        baseDir,
        "--title",
        options.projectTitle ?? "Hyphae Blackbox T3 Project",
        options.sandbox.paths.workspaceDir,
      ],
      {
        env,
        cwd: options.sandbox.paths.workspaceDir,
        encoding: "utf8",
        timeout: 15_000,
        stdio: ["ignore", "pipe", "pipe"],
      },
    );

    const readDb = new DatabaseSync(dbPath, { readOnly: true });
    let projectId = "";
    try {
      const row = readDb
        .prepare("SELECT project_id FROM projection_projects ORDER BY created_at DESC LIMIT 1")
        .get() as { project_id?: string } | undefined;
      projectId = row?.project_id ?? "";
    } finally {
      readDb.close();
    }
    if (!projectId) {
      throw new Error(`t3 project add succeeded but no row found in projection_projects (${dbPath})`);
    }

    // 2. Boot real isolated `t3 serve` in its own POSIX process group tracked by ProcessReaper.
    const port = await getFreePort();
    const serverUrl = `http://127.0.0.1:${port}`;
    const proc = options.sandbox.reaper.spawn(
      "t3-serve",
      t3Bin,
      [
        "serve",
        "--mode",
        "desktop",
        "--host",
        "127.0.0.1",
        "--port",
        String(port),
        "--base-dir",
        baseDir,
        "--no-browser",
        "--log-ws-events",
        options.sandbox.paths.workspaceDir,
      ],
      {
        env,
        cwd: options.sandbox.paths.workspaceDir,
        stdio: ["ignore", "pipe", "pipe"],
      },
    );

    // Wait for `Listening on` log + successful HTTP probe on `/api/auth/session`.
    await waitUntil(
      async () => {
        if (proc.exited) {
          throw new Error(
            `t3 serve exited prematurely (code=${proc.exitCode}):\nSTDOUT:\n${proc.stdout}\nSTDERR:\n${proc.stderr}`,
          );
        }
        const readyText =
          proc.stdout.includes("Listening on") ||
          proc.stderr.includes("Listening on") ||
          proc.stdout.includes("T3 Code server is ready");
        if (!readyText) return false;
        try {
          const probe = await loopbackHttpRequest(`${serverUrl}/api/auth/session`, { timeoutMs: 1_500 });
          return probe.status === 200;
        } catch {
          return false;
        }
      },
      `t3 serve ready on ${serverUrl}`,
      15_000,
      100,
    );

    // 3. Issue a genuine scoped bearer session token via `t3 auth session issue`.
    const bearerToken = execFileSync(
      t3Bin,
      ["auth", "session", "issue", "--base-dir", baseDir, "--label", "hyphae-itest", "--token-only"],
      {
        env,
        cwd: options.sandbox.paths.workspaceDir,
        encoding: "utf8",
        timeout: 10_000,
        stdio: ["ignore", "pipe", "pipe"],
      },
    ).trim();
    if (!bearerToken) {
      throw new Error("t3 auth session issue returned empty bearer token");
    }
    options.sandbox.registerSecret("t3-bearer-token", bearerToken);

    const server = new RealT3Server({
      sandbox: options.sandbox,
      t3Bin,
      baseDir,
      dbPath,
      port,
      serverUrl,
      projectId,
      bearerToken,
      env,
      proc,
    });
    options.sandbox.onTeardown(() => server.close());
    return server;
  }

  probeSession(token?: string): Promise<HttpResponseLite> {
    const headers: Record<string, string> = {};
    if (token) headers.Authorization = `Bearer ${token}`;
    return loopbackHttpRequest(`${this.serverUrl}/api/auth/session`, { headers });
  }

  requestWebsocketTicket(token?: string): Promise<HttpResponseLite> {
    const headers: Record<string, string> = {};
    if (token) headers.Authorization = `Bearer ${token}`;
    return loopbackHttpRequest(`${this.serverUrl}/api/auth/websocket-ticket`, {
      method: "POST",
      headers,
    });
  }

  async effectRpc(tag: string, payload: Record<string, unknown>, token = this.bearerToken): Promise<any> {
    const ticketRes = await this.requestWebsocketTicket(token);
    if (ticketRes.status !== 200 || !ticketRes.json?.ticket) {
      throw new Error(
        `T3 /api/auth/websocket-ticket failed (HTTP ${ticketRes.status}): ${ticketRes.text}`,
      );
    }
    const wsUrl = `ws://127.0.0.1:${this.port}/ws?wsTicket=${encodeURIComponent(ticketRes.json.ticket)}&orchestrationProtocol=2`;
    const ws = new WebSocket(wsUrl);
    try {
      await new Promise<void>((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error(`T3 WS connect timed out (${wsUrl})`)), 5_000);
        ws.addEventListener("open", () => {
          clearTimeout(timer);
          resolve();
        });
        ws.addEventListener("error", (ev) => {
          clearTimeout(timer);
          reject(new Error(`T3 WS error: ${String((ev as any)?.message ?? ev)}`));
        });
      });

      const reqId = crypto.randomUUID();
      return await new Promise<any>((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error(`T3 RPC '${tag}' timed out`)), 8_000);
        const onMsg = (ev: MessageEvent) => {
          try {
            const msg = JSON.parse(String(ev.data));
            if (msg?._tag === "Exit" && msg.requestId === reqId) {
              clearTimeout(timer);
              ws.removeEventListener("message", onMsg);
              resolve(msg);
            }
          } catch {
            // ignore non-JSON frames
          }
        };
        ws.addEventListener("message", onMsg);
        ws.send(
          JSON.stringify({
            _tag: "Request",
            id: reqId,
            tag,
            payload,
            headers: [],
          }),
        );
      });
    } finally {
      try {
        ws.close();
      } catch {
        // ignore
      }
    }
  }

  async createThread(title = "Hyphae T3 Thread"): Promise<string> {
    const threadId = `thr-${crypto.randomUUID()}`;
    const res = await this.effectRpc("orchestration.dispatchCommand", {
      type: "thread.create",
      commandId: crypto.randomUUID(),
      createdBy: "system",
      creationSource: "mcp",
      threadId,
      projectId: this.projectId,
      title,
      modelSelection: { provider: "claudeAgent", model: "claude-sonnet-4-5" },
      runtimeMode: "full-access",
      interactionMode: "default",
      branch: null,
      worktreePath: null,
    });
    if (res?.exit?._tag !== "Success") {
      throw new Error(`T3 thread.create failed: ${JSON.stringify(res)}`);
    }
    return threadId;
  }

  async archiveThread(threadId: string): Promise<void> {
    const res = await this.effectRpc("orchestration.dispatchCommand", {
      type: "thread.archive",
      commandId: crypto.randomUUID(),
      createdBy: "system",
      creationSource: "mcp",
      threadId,
    });
    if (res?.exit?._tag !== "Success") {
      throw new Error(`T3 thread.archive failed: ${JSON.stringify(res)}`);
    }
  }

  async deleteThread(threadId: string): Promise<void> {
    const res = await this.effectRpc("orchestration.dispatchCommand", {
      type: "thread.delete",
      commandId: crypto.randomUUID(),
      createdBy: "system",
      creationSource: "mcp",
      threadId,
    });
    if (res?.exit?._tag !== "Success") {
      throw new Error(`T3 thread.delete failed: ${JSON.stringify(res)}`);
    }
  }

  async getThreadProjection(threadId: string): Promise<any> {
    return this.effectRpc("orchestration.getThreadProjection", { threadId });
  }

  /**
   * Inserts a provider-session binding row into `orchestration_v2_projection_provider_session_bindings`
   * matching what T3 writes when a Claude/Codex provider child attaches to `threadId`, enabling
   * Hyphae's strictly read-only `resolve_t3_thread_by_provider_session()` auto-detection!
   */
  bindProviderSession(providerSessionId: string, threadId: string): void {
    const db = new DatabaseSync(this.dbPath);
    try {
      db.exec("PRAGMA busy_timeout = 5000;");
      db.prepare(
        "INSERT OR REPLACE INTO orchestration_v2_projection_provider_session_bindings (provider_session_id, thread_id) VALUES (?, ?)",
      ).run(providerSessionId, threadId);
    } finally {
      db.close();
    }
  }

  readDispatchedMessages(threadId: string): T3DispatchedMessage[] {
    const db = new DatabaseSync(this.dbPath, { readOnly: true });
    try {
      const rows = db
        .prepare(
          "SELECT message_id, thread_id, role, payload_json FROM orchestration_v2_projection_messages WHERE thread_id = ? ORDER BY created_at ASC",
        )
        .all(threadId) as Array<{
        message_id: string;
        thread_id: string;
        role: string;
        payload_json: string;
      }>;
      return rows.map((r) => {
        let payload: any = {};
        try {
          payload = JSON.parse(r.payload_json);
        } catch {
          payload = {};
        }
        return {
          messageId: r.message_id,
          threadId: r.thread_id,
          role: r.role,
          text: typeof payload?.text === "string" ? payload.text : r.payload_json,
          payload,
        };
      });
    } finally {
      db.close();
    }
  }

  waitForDispatchedMessage(
    threadId: string,
    predicate: (msg: T3DispatchedMessage) => boolean,
    timeoutMs = 15_000,
  ): Promise<T3DispatchedMessage> {
    return waitUntil(
      () => {
        const msgs = this.readDispatchedMessages(threadId);
        return msgs.find(predicate) ?? false;
      },
      `T3 dispatched message on thread ${threadId}`,
      timeoutMs,
      80,
    );
  }

  async close(): Promise<void> {
    await this.sandbox.reaper.kill(this.proc, 3_000);
  }
}

// ============================================================================
// Schema-Pinned Loopback Contract Fallback (CI without `t3` binary & Active-Run Tests)
// ============================================================================

export interface T3ContractThreadState {
  threadId: string;
  projectId: string;
  title: string;
  archivedAt: string | null;
  deletedAt: string | null;
  activeRun?: {
    id: string;
    status: "preparing" | "starting" | "running" | "waiting" | "completed";
    supportsActiveSteering: boolean;
  } | null;
}

export interface RecordedT3Rpc {
  tag: string;
  payload: any;
}

/**
 * Schema-pinned loopback T3 Code contract server implementing the exact `statev2.sqlite`
 * v2 projection tables, `/api/auth/session`, `/api/auth/websocket-ticket`, and Effect RPC
 * (`/ws?wsTicket=...&orchestrationProtocol=2`).
 *
 * Used strictly as:
 *  1. Fallback when the `t3` binary is absent on CI runners, AND
 *  2. Deterministic active-run state injector for testing `queue_after_active` vs
 *     `steer_active` vs `restart_active` dispatch modes!
 */
export class T3ContractMockServer implements T3BackendHandle {
  readonly kind = "contract-mock" as const;
  readonly baseDir: string;
  readonly dbPath: string;
  readonly serverUrl: string;
  readonly projectId: string;
  readonly bearerToken: string;
  readonly wsServer: LoopbackWsServer;
  readonly recordedRpcs: RecordedT3Rpc[] = [];
  readonly dispatchedCommands: any[] = [];
  readonly authRequests: Array<{ path: string; method: string; authHeader: string | undefined; status: number }> = [];

  private readonly threads = new Map<string, T3ContractThreadState>();
  private readonly messagesByThread = new Map<string, T3DispatchedMessage[]>();
  private readonly validTickets = new Set<string>();

  private constructor(init: {
    baseDir: string;
    dbPath: string;
    projectId: string;
    bearerToken: string;
    wsServer: LoopbackWsServer;
  }) {
    this.baseDir = init.baseDir;
    this.dbPath = init.dbPath;
    this.serverUrl = init.wsServer.baseHttpUrl;
    this.projectId = init.projectId;
    this.bearerToken = init.bearerToken;
    this.wsServer = init.wsServer;
  }

  static async start(options: {
    sandbox: Sandbox;
    baseDir?: string;
    bearerToken?: string;
  }): Promise<T3ContractMockServer> {
    const baseDir = options.baseDir ?? path.join(options.sandbox.paths.rootDir, "t3-contract");
    const userdataDir = path.join(baseDir, "userdata");
    fs.mkdirSync(userdataDir, { recursive: true, mode: 0o700 });
    const dbPath = path.join(userdataDir, "statev2.sqlite");
    const projectId = `proj-${crypto.randomUUID()}`;
    const bearerToken = options.bearerToken ?? `t3-contract-${crypto.randomBytes(16).toString("hex")}`;
    options.sandbox.registerSecret("t3-contract-token", bearerToken);

    // Seed authentic T3 orchestration v2 schema matching `t3 v0.0.46`.
    const db = new DatabaseSync(dbPath);
    try {
      db.exec(`
        PRAGMA journal_mode = WAL;
        CREATE TABLE IF NOT EXISTS orchestration_v2_projection_threads (
          thread_id TEXT PRIMARY KEY,
          project_id TEXT NOT NULL,
          title TEXT NOT NULL,
          default_provider TEXT NOT NULL DEFAULT 'claudeAgent',
          runtime_mode TEXT NOT NULL DEFAULT 'full-access',
          interaction_mode TEXT NOT NULL DEFAULT 'default',
          active_provider_thread_id TEXT,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL,
          archived_at TEXT,
          deleted_at TEXT,
          payload_json TEXT NOT NULL DEFAULT '{}'
        );
        CREATE TABLE IF NOT EXISTS orchestration_v2_projection_provider_session_bindings (
          provider_session_id TEXT NOT NULL,
          thread_id TEXT NOT NULL,
          PRIMARY KEY (provider_session_id, thread_id)
        );
        CREATE TABLE IF NOT EXISTS orchestration_v2_projection_messages (
          message_id TEXT PRIMARY KEY,
          thread_id TEXT NOT NULL,
          run_id TEXT,
          node_id TEXT,
          role TEXT NOT NULL,
          streaming INTEGER NOT NULL DEFAULT 0,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL,
          payload_json TEXT NOT NULL
        );
      `);
    } finally {
      db.close();
    }

    let instance!: T3ContractMockServer;

    const wsServer = await LoopbackWsServer.start({
      httpHandler: async (req, res) => {
        const parsed = new URL(req.url ?? "/", "http://127.0.0.1");
        const authHeader = req.headers.authorization;
        const isAuthed = authHeader === `Bearer ${bearerToken}`;

        if (req.method === "GET" && parsed.pathname === "/api/auth/session") {
          instance.authRequests.push({ path: parsed.pathname, method: "GET", authHeader, status: 200 });
          writeJson(res, 200, {
            authenticated: isAuthed,
            auth: {
              policy: "desktop-managed-local",
              sessionMethods: ["bearer-access-token"],
            },
          });
          return;
        }

        if (req.method === "POST" && parsed.pathname === "/api/auth/websocket-ticket") {
          await readHttpBody(req).catch(() => null);
          if (!isAuthed) {
            instance.authRequests.push({ path: parsed.pathname, method: "POST", authHeader, status: 401 });
            writeJson(res, 401, { error: "Unauthorized" });
            return;
          }
          const ticket = `wst_${crypto.randomBytes(16).toString("hex")}`;
          instance.validTickets.add(ticket);
          instance.authRequests.push({ path: parsed.pathname, method: "POST", authHeader, status: 200 });
          writeJson(res, 200, {
            ticket,
            expiresAt: new Date(Date.now() + 300_000).toISOString(),
          });
          return;
        }

        writeJson(res, 404, { error: "Not Found" });
      },
      validateUpgrade: (req) => {
        const parsed = new URL(req.url ?? "/", "http://127.0.0.1");
        if (parsed.pathname !== "/ws") return 404;
        const ticket = parsed.searchParams.get("wsTicket") ?? "";
        if (!instance.validTickets.has(ticket)) return 401;
        instance.validTickets.delete(ticket);
        return null;
      },
      onConnection: (conn) => {
        conn.onMessage((_text, parsed) => {
          if (!parsed || parsed._tag !== "Request") return;
          instance.recordedRpcs.push({ tag: parsed.tag, payload: parsed.payload });
          const reqId = parsed.id;

          if (parsed.tag === "orchestration.getThreadProjection") {
            const threadId = parsed.payload?.threadId;
            const thr = instance.threads.get(threadId);
            if (!thr) {
              conn.sendJson({
                _tag: "Exit",
                requestId: reqId,
                exit: {
                  _tag: "Failure",
                  cause: [
                    {
                      _tag: "Fail",
                      error: {
                        _tag: "OrchestrationV2GetThreadProjectionError",
                        threadId,
                        message: `No orchestration projection exists for thread ${threadId}.`,
                        cause: {
                          name: "OrchestratorProjectionError",
                          cause: {
                            name: "ProjectionStoreThreadNotFoundError",
                            message: `No orchestration projection exists for thread ${threadId}.`,
                          },
                        },
                      },
                    },
                  ],
                },
              });
              return;
            }

            const runs: any[] = [];
            const providerThreads: any[] = [];
            const providerSessions: any[] = [];
            if (thr.activeRun) {
              const ptId = `pt-${thr.threadId}`;
              const psId = `ps-${thr.threadId}`;
              runs.push({
                id: thr.activeRun.id,
                status: thr.activeRun.status,
                providerThreadId: ptId,
              });
              providerThreads.push({ id: ptId, providerSessionId: psId });
              providerSessions.push({
                id: psId,
                capabilities: {
                  turns: { supportsActiveSteering: thr.activeRun.supportsActiveSteering },
                },
              });
            }

            conn.sendJson({
              _tag: "Exit",
              requestId: reqId,
              exit: {
                _tag: "Success",
                value: {
                  thread: {
                    id: thr.threadId,
                    projectId: thr.projectId,
                    title: thr.title,
                    archivedAt: thr.archivedAt,
                    deletedAt: thr.deletedAt,
                  },
                  runs,
                  providerThreads,
                  providerSessions,
                },
              },
            });
            return;
          }

          if (parsed.tag === "orchestration.dispatchCommand") {
            const cmd = parsed.payload ?? {};
            instance.dispatchedCommands.push(cmd);
            const thr = instance.threads.get(cmd.threadId);
            if (!thr) {
              conn.sendJson({
                _tag: "Exit",
                requestId: reqId,
                exit: {
                  _tag: "Failure",
                  cause: [
                    {
                      _tag: "Fail",
                      error: {
                        _tag: "OrchestrationV2DispatchCommandError",
                        message: `No orchestration projection exists for thread ${cmd.threadId}.`,
                        cause: { name: "ProjectionStoreThreadNotFoundError" },
                      },
                    },
                  ],
                },
              });
              return;
            }

            if (cmd.type === "message.dispatch") {
              const msg: T3DispatchedMessage = {
                messageId: cmd.messageId ?? crypto.randomUUID(),
                threadId: cmd.threadId,
                role: "user",
                text: String(cmd.text ?? ""),
                payload: cmd,
              };
              const list = instance.messagesByThread.get(cmd.threadId) ?? [];
              list.push(msg);
              instance.messagesByThread.set(cmd.threadId, list);
              instance.persistMessageRow(msg);
            }

            conn.sendJson({
              _tag: "Exit",
              requestId: reqId,
              exit: { _tag: "Success", value: { sequence: instance.dispatchedCommands.length } },
            });
          }
        });
      },
    });

    instance = new T3ContractMockServer({
      baseDir,
      dbPath,
      projectId,
      bearerToken,
      wsServer,
    });
    options.sandbox.onTeardown(() => instance.close());
    return instance;
  }

  private persistThreadRow(thr: T3ContractThreadState): void {
    const now = new Date().toISOString();
    const db = new DatabaseSync(this.dbPath);
    try {
      db.prepare(
        `INSERT OR REPLACE INTO orchestration_v2_projection_threads
         (thread_id, project_id, title, created_at, updated_at, archived_at, deleted_at, payload_json)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      ).run(
        thr.threadId,
        thr.projectId,
        thr.title,
        now,
        now,
        thr.archivedAt,
        thr.deletedAt,
        JSON.stringify({ id: thr.threadId, title: thr.title }),
      );
    } finally {
      db.close();
    }
  }

  private persistMessageRow(msg: T3DispatchedMessage): void {
    const now = new Date().toISOString();
    const db = new DatabaseSync(this.dbPath);
    try {
      db.prepare(
        `INSERT OR REPLACE INTO orchestration_v2_projection_messages
         (message_id, thread_id, role, streaming, created_at, updated_at, payload_json)
         VALUES (?, ?, ?, 0, ?, ?, ?)`,
      ).run(msg.messageId, msg.threadId, msg.role, now, now, JSON.stringify(msg.payload));
    } finally {
      db.close();
    }
  }

  setActiveRun(
    threadId: string,
    activeRun: T3ContractThreadState["activeRun"],
  ): void {
    const thr = this.threads.get(threadId);
    if (!thr) throw new Error(`Unknown threadId ${threadId}`);
    thr.activeRun = activeRun;
  }

  probeSession(token?: string): Promise<HttpResponseLite> {
    const headers: Record<string, string> = {};
    if (token) headers.Authorization = `Bearer ${token}`;
    return loopbackHttpRequest(`${this.serverUrl}/api/auth/session`, { headers });
  }

  requestWebsocketTicket(token?: string): Promise<HttpResponseLite> {
    const headers: Record<string, string> = {};
    if (token) headers.Authorization = `Bearer ${token}`;
    return loopbackHttpRequest(`${this.serverUrl}/api/auth/websocket-ticket`, {
      method: "POST",
      headers,
    });
  }

  async createThread(title = "Hyphae T3 Contract Thread"): Promise<string> {
    const threadId = `thr-${crypto.randomUUID()}`;
    const thr: T3ContractThreadState = {
      threadId,
      projectId: this.projectId,
      title,
      archivedAt: null,
      deletedAt: null,
      activeRun: null,
    };
    this.threads.set(threadId, thr);
    this.persistThreadRow(thr);
    return threadId;
  }

  async archiveThread(threadId: string): Promise<void> {
    const thr = this.threads.get(threadId);
    if (!thr) throw new Error(`Unknown threadId ${threadId}`);
    thr.archivedAt = new Date().toISOString();
    this.persistThreadRow(thr);
  }

  async deleteThread(threadId: string): Promise<void> {
    const thr = this.threads.get(threadId);
    if (!thr) throw new Error(`Unknown threadId ${threadId}`);
    thr.deletedAt = new Date().toISOString();
    this.persistThreadRow(thr);
  }

  async getThreadProjection(threadId: string): Promise<any> {
    const thr = this.threads.get(threadId);
    if (!thr) return { exit: { _tag: "Failure" } };
    return { exit: { _tag: "Success", value: { thread: thr } } };
  }

  bindProviderSession(providerSessionId: string, threadId: string): void {
    const db = new DatabaseSync(this.dbPath);
    try {
      db.prepare(
        "INSERT OR REPLACE INTO orchestration_v2_projection_provider_session_bindings (provider_session_id, thread_id) VALUES (?, ?)",
      ).run(providerSessionId, threadId);
    } finally {
      db.close();
    }
  }

  readDispatchedMessages(threadId: string): T3DispatchedMessage[] {
    return [...(this.messagesByThread.get(threadId) ?? [])];
  }

  waitForDispatchedMessage(
    threadId: string,
    predicate: (msg: T3DispatchedMessage) => boolean,
    timeoutMs = 15_000,
  ): Promise<T3DispatchedMessage> {
    return waitUntil(
      () => {
        const msgs = this.readDispatchedMessages(threadId);
        return msgs.find(predicate) ?? false;
      },
      `T3 contract dispatched message on thread ${threadId}`,
      timeoutMs,
      50,
    );
  }

  async close(): Promise<void> {
    await this.wsServer.close();
  }
}

/**
 * Starts real `t3 serve` when installed, or falls back cleanly to `T3ContractMockServer` ONLY
 * when the `t3` binary is absent (e.g., Linux CI runners without T3 installed).
 */
export async function startT3Backend(options: {
  sandbox: Sandbox;
  requireReal?: boolean;
}): Promise<T3BackendHandle> {
  const t3Bin = resolveT3Bin();
  if (t3Bin) {
    return RealT3Server.start({ sandbox: options.sandbox, t3Bin });
  }
  if (options.requireReal) {
    throw new Error("Real t3 binary required but not found (set T3_BIN)");
  }
  return T3ContractMockServer.start({ sandbox: options.sandbox });
}
