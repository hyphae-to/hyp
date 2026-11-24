import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import type { AttemptOutcome, Backend } from "./delivery.ts";
import { delivered, hold, normalizeMeshToolName, object, reject, type Mode } from "./protocol.ts";
import { readSecret } from "./secrets.ts";

export const DEFAULT_T3_URL = "http://127.0.0.1:3773";
export const DEFAULT_T3_TOKEN_SECRET = "t3-auth-token";
const T3_ORCHESTRATION_PROTOCOL = "2";

export interface T3Config {
  readonly url: string;
  readonly baseDir: string;
  readonly tokenSecret?: string;
  readonly token?: string;
  readonly bin?: string;
}

export function defaultT3BaseDir(homeDir = homedir()): string {
  const envHome = process.env.T3CODE_HOME?.trim();
  return envHome && envHome.length > 0 ? envHome : join(homeDir, ".t3");
}

export function t3StateDbPath(baseDir: string): string {
  return join(baseDir, "userdata", "statev2.sqlite");
}

export function normalizeT3ServerUrl(raw: string): string {
  const url = new URL(raw);
  const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  if (
    !(url.protocol === "https:" || (url.protocol === "http:" && loopback)) ||
    url.username ||
    url.password ||
    url.pathname !== "/" ||
    url.search ||
    url.hash
  ) {
    throw new Error("T3 Code server URL must be an HTTPS origin or loopback HTTP origin (e.g. http://127.0.0.1:3773)");
  }
  return url.origin;
}

function openT3DbReadOnly(baseDir: string): DatabaseSync | null {
  const dbPath = t3StateDbPath(baseDir);
  if (!existsSync(dbPath)) return null;
  try {
    return new DatabaseSync(dbPath, { readOnly: true });
  } catch {
    return null;
  }
}

function tableExists(db: DatabaseSync, name: string): boolean {
  try {
    const row = db.prepare("SELECT 1 AS ok FROM sqlite_master WHERE type = 'table' AND name = ?").get(name);
    return row !== undefined;
  } catch {
    return false;
  }
}

export type T3ThreadLookupResult =
  | { readonly ok: true; readonly threadId: string }
  | { readonly ok: false; readonly code: "caller_not_found" | "caller_ambiguous"; readonly message: string };

/**
 * Resolves a provider session/thread ID (e.g. Claude `session_id` or Codex `thread_id`)
 * to its owning active T3 Code `thread_id` via T3's read-only `statev2.sqlite` projections.
 * Fails closed (`caller_ambiguous`) if multiple active T3 threads match.
 */
export function resolveT3ThreadByProviderSession(
  providerSessionOrThreadId: string,
  baseDir: string,
): T3ThreadLookupResult {
  if (!providerSessionOrThreadId || providerSessionOrThreadId.length > 256) {
    return { ok: false, code: "caller_not_found", message: "Empty provider session ID" };
  }
  const db = openT3DbReadOnly(baseDir);
  if (!db) {
    return { ok: false, code: "caller_not_found", message: `T3 state DB not found under ${baseDir}` };
  }
  try {
    const matched = new Set<string>();
    const hasV2Threads = tableExists(db, "orchestration_v2_projection_threads");

    if (hasV2Threads && tableExists(db, "orchestration_v2_projection_provider_session_bindings")) {
      const rows = db
        .prepare(
          `SELECT DISTINCT b.thread_id
           FROM orchestration_v2_projection_provider_session_bindings b
           JOIN orchestration_v2_projection_threads t ON t.thread_id = b.thread_id
           WHERE b.provider_session_id = ? AND t.deleted_at IS NULL AND t.archived_at IS NULL`,
        )
        .all(providerSessionOrThreadId) as Array<{ thread_id: unknown }>;
      for (const r of rows) {
        if (typeof r.thread_id === "string" && r.thread_id.length > 0) matched.add(r.thread_id);
      }
    }

    if (hasV2Threads && tableExists(db, "orchestration_v2_projection_provider_threads")) {
      const rows = db
        .prepare(
          `SELECT DISTINCT p.thread_id
           FROM orchestration_v2_projection_provider_threads p
           JOIN orchestration_v2_projection_threads t ON t.thread_id = p.thread_id
           WHERE (p.provider_thread_id = ? OR p.provider_session_id = ?)
             AND t.deleted_at IS NULL AND t.archived_at IS NULL`,
        )
        .all(providerSessionOrThreadId, providerSessionOrThreadId) as Array<{ thread_id: unknown }>;
      for (const r of rows) {
        if (typeof r.thread_id === "string" && r.thread_id.length > 0) matched.add(r.thread_id);
      }
    }

    if (tableExists(db, "projection_thread_sessions") && tableExists(db, "projection_threads")) {
      const rows = db
        .prepare(
          `SELECT DISTINCT s.thread_id
           FROM projection_thread_sessions s
           JOIN projection_threads t ON t.thread_id = s.thread_id
           WHERE (s.provider_session_id = ? OR s.provider_thread_id = ?)
             AND t.deleted_at IS NULL AND t.archived_at IS NULL`,
        )
        .all(providerSessionOrThreadId, providerSessionOrThreadId) as Array<{ thread_id: unknown }>;
      for (const r of rows) {
        if (typeof r.thread_id === "string" && r.thread_id.length > 0) matched.add(r.thread_id);
      }
    }

    if (matched.size === 1) {
      return { ok: true, threadId: [...matched][0]! };
    }
    if (matched.size > 1) {
      return {
        ok: false,
        code: "caller_ambiguous",
        message: `Provider session ${providerSessionOrThreadId} matched ${matched.size} active T3 threads`,
      };
    }
    return {
      ok: false,
      code: "caller_not_found",
      message: `No active T3 thread bound to provider session ${providerSessionOrThreadId}`,
    };
  } catch {
    return { ok: false, code: "caller_not_found", message: "Failed to query T3 state database" };
  } finally {
    try { db.close(); } catch {}
  }
}

/** Verifies that an explicit T3 thread ID exists and is not deleted or archived. */
export function verifyT3ThreadExists(threadId: string, baseDir: string): boolean {
  if (!threadId || threadId.length > 200) return false;
  const db = openT3DbReadOnly(baseDir);
  if (!db) return false;
  try {
    if (tableExists(db, "orchestration_v2_projection_threads")) {
      const row = db
        .prepare("SELECT 1 AS ok FROM orchestration_v2_projection_threads WHERE thread_id = ? AND deleted_at IS NULL AND archived_at IS NULL")
        .get(threadId);
      if (row !== undefined) return true;
    }
    if (tableExists(db, "projection_threads")) {
      const row = db
        .prepare("SELECT 1 AS ok FROM projection_threads WHERE thread_id = ? AND deleted_at IS NULL AND archived_at IS NULL")
        .get(threadId);
      if (row !== undefined) return true;
    }
    return false;
  } catch {
    return false;
  } finally {
    try { db.close(); } catch {}
  }
}

function payloadMatchesCall(payloadJson: string, callId: string, normalizedTool: string): boolean {
  if (!payloadJson.includes(callId)) return false;
  try {
    const parsed: unknown = JSON.parse(payloadJson);
    const stack: unknown[] = [parsed];
    let sawCallId = false;
    let sawTool = false;
    while (stack.length > 0) {
      const cur = stack.pop();
      if (typeof cur === "string") {
        if (cur === callId) sawCallId = true;
        if (normalizeMeshToolName(cur) === normalizedTool) sawTool = true;
      } else if (Array.isArray(cur)) {
        for (const item of cur) stack.push(item);
      } else if (object(cur)) {
        for (const v of Object.values(cur)) stack.push(v);
      }
      if (sawCallId && sawTool) return true;
    }
    return sawCallId && sawTool;
  } catch {
    return false;
  }
}

function lookupT3CallOnce(baseDir: string, callId: string, normalizedTool: string): T3ThreadLookupResult {
  const db = openT3DbReadOnly(baseDir);
  if (!db) {
    return { ok: false, code: "caller_not_found", message: `T3 state DB not found under ${baseDir}` };
  }
  try {
    const matched = new Set<string>();
    const likePattern = `%${callId.replace(/[%_\\]/g, "\\$&")}%`;

    if (tableExists(db, "orchestration_v2_projection_turn_items") && tableExists(db, "orchestration_v2_projection_threads")) {
      const rows = db
        .prepare(
          `SELECT i.thread_id, i.status, i.payload_json
           FROM orchestration_v2_projection_turn_items i
           JOIN orchestration_v2_projection_threads t ON t.thread_id = i.thread_id
           WHERE i.payload_json LIKE ? ESCAPE '\\'
             AND t.deleted_at IS NULL AND t.archived_at IS NULL
             AND LOWER(i.status) NOT IN ('completed', 'succeeded', 'failed', 'cancelled', 'error')`,
        )
        .all(likePattern) as Array<{ thread_id: unknown; payload_json: unknown }>;
      for (const r of rows) {
        if (typeof r.thread_id === "string" && typeof r.payload_json === "string" && payloadMatchesCall(r.payload_json, callId, normalizedTool)) {
          matched.add(r.thread_id);
        }
      }
    }

    if (matched.size === 0 && tableExists(db, "projection_thread_activities") && tableExists(db, "projection_threads")) {
      const rows = db
        .prepare(
          `SELECT a.thread_id, a.payload_json
           FROM projection_thread_activities a
           JOIN projection_threads t ON t.thread_id = a.thread_id
           WHERE a.payload_json LIKE ? ESCAPE '\\'
             AND t.deleted_at IS NULL AND t.archived_at IS NULL
           ORDER BY a.created_at DESC
           LIMIT 20`,
        )
        .all(likePattern) as Array<{ thread_id: unknown; payload_json: unknown }>;
      for (const r of rows) {
        if (typeof r.thread_id === "string" && typeof r.payload_json === "string" && payloadMatchesCall(r.payload_json, callId, normalizedTool)) {
          matched.add(r.thread_id);
        }
      }
    }

    if (matched.size === 1) return { ok: true, threadId: [...matched][0]! };
    if (matched.size > 1) {
      return {
        ok: false,
        code: "caller_ambiguous",
        message: `T3 call ${callId} matched ${matched.size} active threads`,
      };
    }
    return { ok: false, code: "caller_not_found", message: `No in-flight T3 call found for ${normalizedTool} (${callId})` };
  } catch {
    return { ok: false, code: "caller_not_found", message: "Failed to query T3 turn items" };
  } finally {
    try { db.close(); } catch {}
  }
}

/**
 * Authoritative per-call T3 Code caller verification directly against T3's `statev2.sqlite`
 * projections (`orchestration_v2_projection_turn_items` / `projection_thread_activities`),
 * verifying an in-flight tool call matching both `callId` and the exact normalized `hyp_*` tool name.
 */
export async function resolveT3CallerByCallId(
  callId: string,
  tool: string,
  t3: T3Config,
  configDir?: string,
  timeoutMs = 600,
): Promise<
  | { readonly ok: true; readonly sessionId: string; readonly backend: Backend }
  | { readonly ok: false; readonly code: "caller_unverifiable" | "caller_not_found" | "caller_ambiguous"; readonly message: string }
> {
  const normalizedTool = normalizeMeshToolName(tool);
  if (!normalizedTool) {
    return { ok: false, code: "caller_unverifiable", message: `Unknown mesh tool ${tool}` };
  }
  const deadline = Date.now() + timeoutMs;
  let delay = 40;
  while (true) {
    const res = lookupT3CallOnce(t3.baseDir, callId, normalizedTool);
    if (res.ok) {
      return {
        ok: true,
        sessionId: `t3:${res.threadId}`,
        backend: {
          kind: "t3",
          threadId: res.threadId,
          serverUrl: t3.url,
          baseDir: t3.baseDir,
          ...(t3.tokenSecret ? { tokenSecret: t3.tokenSecret } : {}),
          ...(configDir ? { configDir } : {}),
        },
      };
    }
    if (res.code === "caller_ambiguous") return res;
    if (Date.now() + delay > deadline) return res;
    await new Promise<void>((r) => setTimeout(r, delay));
    delay = Math.min(delay * 2, 200);
  }
}

/** Issues a scoped T3 Code bearer session token via `t3 auth session issue --token-only`. */
export function issueT3BearerToken(baseDir: string, t3Bin = "t3"): string {
  const out = execFileSync(
    t3Bin,
    ["auth", "session", "issue", "--base-dir", baseDir, "--token-only", "--label", "hyphae"],
    { encoding: "utf8", timeout: 10_000, stdio: ["ignore", "pipe", "pipe"] },
  ).trim();
  if (!out || out.length < 16) {
    throw new Error("`t3 auth session issue` returned an empty token");
  }
  return out;
}

export interface T3ProbeResult {
  readonly ok: boolean;
  readonly authenticated?: boolean;
  readonly error?: string;
}

/** Probes a running T3 Code server's `/api/auth/session` endpoint. */
export async function probeT3Server(serverUrl: string, token?: string, timeoutMs = 2_500): Promise<T3ProbeResult> {
  try {
    const headers: Record<string, string> = {};
    if (token) headers.authorization = `Bearer ${token}`;
    const res = await fetch(`${serverUrl}/api/auth/session`, {
      headers,
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!res.ok) return { ok: false, error: `HTTP ${res.status}` };
    const body = (await res.json().catch(() => null)) as unknown;
    const authenticated = object(body) && body.authenticated === true;
    return { ok: true, authenticated };
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error.message : String(error) };
  }
}

interface T3RpcResponse {
  readonly ok: boolean;
  readonly value?: unknown;
  readonly errorTag?: string;
  readonly errorName?: string;
  readonly errorMessage?: string;
}

function parseEffectExit(msg: Record<string, unknown>): T3RpcResponse {
  const exit = object(msg.exit) ? msg.exit : undefined;
  if (exit?._tag === "Success") {
    return { ok: true, value: exit.value };
  }
  const cause = Array.isArray(exit?.cause) ? exit.cause : [];
  for (const entry of cause) {
    if (!object(entry)) continue;
    if (entry._tag === "Fail" && object(entry.error)) {
      const err = entry.error;
      const inner = object(err.cause) && object(err.cause.cause) ? err.cause.cause : object(err.cause) ? err.cause : undefined;
      return {
        ok: false,
        errorTag: typeof err._tag === "string" ? err._tag : undefined,
        errorName: typeof inner?.name === "string" ? inner.name : undefined,
        errorMessage: typeof err.message === "string" ? err.message : undefined,
      };
    }
    if (entry._tag === "Die") {
      return {
        ok: false,
        errorTag: "Die",
        errorMessage: typeof entry.defect === "string" ? entry.defect : JSON.stringify(entry.defect),
      };
    }
  }
  return { ok: false, errorMessage: "Unknown T3 RPC error" };
}

class T3WsRpcClient {
  readonly #ws: WebSocket;
  readonly #pending = new Map<string, { resolve: (res: T3RpcResponse) => void; reject: (err: Error) => void; timer: NodeJS.Timeout }>();

  private constructor(ws: WebSocket) {
    this.#ws = ws;
    ws.addEventListener("message", (ev) => {
      let msg: unknown;
      try { msg = JSON.parse(String(ev.data)); } catch { return; }
      if (!object(msg) || msg._tag !== "Exit" || typeof msg.requestId !== "string") return;
      const pending = this.#pending.get(msg.requestId);
      if (!pending) return;
      this.#pending.delete(msg.requestId);
      clearTimeout(pending.timer);
      pending.resolve(parseEffectExit(msg));
    });
    ws.addEventListener("close", () => {
      for (const [id, pending] of this.#pending) {
        clearTimeout(pending.timer);
        pending.reject(new Error("T3 WebSocket closed"));
        this.#pending.delete(id);
      }
    });
  }

  static async connect(serverUrl: string, token: string, timeoutMs = 8_000): Promise<
    | { readonly ok: true; readonly client: T3WsRpcClient }
    | { readonly ok: false; readonly reason: "t3_server_unreachable" | "t3_auth_failed" }
  > {
    let ticket: string;
    try {
      const res = await fetch(`${serverUrl}/api/auth/websocket-ticket`, {
        method: "POST",
        headers: { authorization: `Bearer ${token}` },
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (res.status === 401 || res.status === 403) {
        return { ok: false, reason: "t3_auth_failed" };
      }
      if (!res.ok) {
        return { ok: false, reason: "t3_server_unreachable" };
      }
      const body = (await res.json()) as unknown;
      if (!object(body) || typeof body.ticket !== "string" || body.ticket.length === 0) {
        return { ok: false, reason: "t3_auth_failed" };
      }
      ticket = body.ticket;
    } catch {
      return { ok: false, reason: "t3_server_unreachable" };
    }

    const wsUrl = new URL(serverUrl);
    wsUrl.protocol = wsUrl.protocol === "https:" ? "wss:" : "ws:";
    wsUrl.pathname = "/ws";
    wsUrl.searchParams.set("wsTicket", ticket);
    wsUrl.searchParams.set("orchestrationProtocol", T3_ORCHESTRATION_PROTOCOL);

    return await new Promise((resolve) => {
      let settled = false;
      const ws = new WebSocket(wsUrl.toString());
      const timer = setTimeout(() => {
        if (settled) return;
        settled = true;
        try { ws.close(); } catch {}
        resolve({ ok: false, reason: "t3_server_unreachable" });
      }, timeoutMs).unref();

      ws.addEventListener("open", () => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve({ ok: true, client: new T3WsRpcClient(ws) });
      });
      ws.addEventListener("error", () => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve({ ok: false, reason: "t3_server_unreachable" });
      });
    });
  }

  request(tag: string, payload: Record<string, unknown>, timeoutMs = 15_000): Promise<T3RpcResponse> {
    const id = randomUUID();
    return new Promise((resolve, rejectPromise) => {
      const timer = setTimeout(() => {
        this.#pending.delete(id);
        rejectPromise(new Error(`T3 RPC ${tag} timed out`));
      }, timeoutMs).unref();
      this.#pending.set(id, { resolve, reject: rejectPromise, timer });
      try {
        this.#ws.send(JSON.stringify({ _tag: "Request", id, tag, payload, headers: [] }));
      } catch (error) {
        this.#pending.delete(id);
        clearTimeout(timer);
        rejectPromise(error instanceof Error ? error : new Error(String(error)));
      }
    });
  }

  close(): void {
    try { this.#ws.close(); } catch {}
  }
}

export interface DeliverToT3Options {
  readonly serverUrl: string;
  readonly threadId: string;
  readonly text: string;
  readonly mode: Mode;
  readonly token?: string;
  readonly tokenSecret?: string;
  readonly configDir?: string;
  readonly timeoutMs?: number;
}

function isThreadNotFoundError(res: T3RpcResponse): boolean {
  return (
    res.errorName === "ProjectionStoreThreadNotFoundError" ||
    (typeof res.errorMessage === "string" && /No orchestration projection exists|thread.*not found/i.test(res.errorMessage))
  );
}

/**
 * Delivers a Hyphae message/event directly into a T3 Code thread via T3's orchestration protocol v2
 * WebSocket RPC (`orchestration.getThreadProjection` + `orchestration.dispatchCommand` `message.dispatch`).
 *
 * - Idle thread -> `{ type: "start_immediately" }`
 * - Active run + `mode: "queue"` -> `{ type: "queue_after_active" }`
 * - Active run + `mode: "interrupt"` -> `{ type: "steer_active", targetRunId }` when the active
 *   provider session supports active steering, otherwise `{ type: "restart_active", targetRunId }`
 */
export async function deliverToT3Thread(options: DeliverToT3Options): Promise<AttemptOutcome> {
  let token = options.token?.trim();
  if (!token) {
    const secretName = options.tokenSecret ?? DEFAULT_T3_TOKEN_SECRET;
    try {
      token = readSecret(secretName, options.configDir);
    } catch {
      return hold("t3_auth_missing");
    }
  }
  if (!token) return hold("t3_auth_missing");

  const conn = await T3WsRpcClient.connect(options.serverUrl, token, options.timeoutMs ?? 8_000);
  if (!conn.ok) return hold(conn.reason);

  const { client } = conn;
  try {
    const projectionRes = await client.request(
      "orchestration.getThreadProjection",
      { threadId: options.threadId },
      options.timeoutMs ?? 12_000,
    );
    if (!projectionRes.ok) {
      if (isThreadNotFoundError(projectionRes)) return reject("t3_thread_not_found");
      return hold("t3_projection_unavailable");
    }

    const projection = object(projectionRes.value) ? projectionRes.value : {};
    const thread = object(projection.thread) ? projection.thread : undefined;
    if (thread && (thread.deletedAt !== null && thread.deletedAt !== undefined)) {
      return reject("t3_thread_deleted");
    }

    const runs = Array.isArray(projection.runs) ? projection.runs.filter(object) : [];
    const activeStatuses = new Set(["preparing", "starting", "running", "waiting"]);
    let activeRun: Record<string, unknown> | undefined;
    for (let i = runs.length - 1; i >= 0; i--) {
      const r = runs[i]!;
      if (typeof r.status === "string" && activeStatuses.has(r.status) && typeof r.id === "string") {
        activeRun = r;
        break;
      }
    }

    let supportsActiveSteering = false;
    if (activeRun && typeof activeRun.providerThreadId === "string") {
      const pThreads = Array.isArray(projection.providerThreads) ? projection.providerThreads.filter(object) : [];
      const pSessions = Array.isArray(projection.providerSessions) ? projection.providerSessions.filter(object) : [];
      const pt = pThreads.find((t) => t.id === activeRun!.providerThreadId);
      const ps = pt && typeof pt.providerSessionId === "string"
        ? pSessions.find((s) => s.id === pt.providerSessionId)
        : undefined;
      const turns = ps && object(ps.capabilities) && object(ps.capabilities.turns) ? ps.capabilities.turns : undefined;
      supportsActiveSteering = turns?.supportsActiveSteering === true;
    }

    let dispatchMode: Record<string, unknown>;
    let interrupted = false;
    if (!activeRun) {
      dispatchMode = { type: "start_immediately" };
    } else if (options.mode === "queue") {
      dispatchMode = { type: "queue_after_active" };
    } else if (supportsActiveSteering) {
      dispatchMode = { type: "steer_active", targetRunId: activeRun.id };
      interrupted = true;
    } else {
      dispatchMode = { type: "restart_active", targetRunId: activeRun.id };
      interrupted = true;
    }

    const dispatchRes = await client.request(
      "orchestration.dispatchCommand",
      {
        type: "message.dispatch",
        commandId: randomUUID(),
        createdBy: "system",
        creationSource: "mcp",
        threadId: options.threadId,
        messageId: randomUUID(),
        text: options.text,
        attachments: [],
        dispatchMode,
      },
      options.timeoutMs ?? 15_000,
    );

    if (dispatchRes.ok) {
      return interrupted ? { ...delivered, interrupted: true } : delivered;
    }
    if (isThreadNotFoundError(dispatchRes)) return reject("t3_thread_not_found");
    return reject("t3_dispatch_failed");
  } catch {
    return hold("t3_server_unreachable");
  } finally {
    client.close();
  }
}
