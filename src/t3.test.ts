import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { createServer, type IncomingMessage } from "node:http";
import type { Duplex } from "node:stream";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";
import { parseBackend } from "./config.ts";
import { createDelivery, usesDurableMailbox } from "./delivery.ts";
import { writeSecretDetailed } from "./secrets.ts";
import {
  deliverToT3Thread,
  normalizeT3ServerUrl,
  resolveT3CallerByCallId,
  resolveT3ThreadByProviderSession,
  t3StateDbPath,
  verifyT3ThreadExists,
} from "./t3.ts";

function makeMockT3Db(baseDir: string): DatabaseSync {
  const dbPath = t3StateDbPath(baseDir);
  mkdirSync(join(baseDir, "userdata"), { recursive: true, mode: 0o700 });
  const db = new DatabaseSync(dbPath);
  db.exec(`
    CREATE TABLE orchestration_v2_projection_threads (
      thread_id TEXT PRIMARY KEY,
      deleted_at TEXT,
      archived_at TEXT
    );
    CREATE TABLE orchestration_v2_projection_provider_session_bindings (
      provider_session_id TEXT NOT NULL,
      thread_id TEXT NOT NULL,
      PRIMARY KEY (provider_session_id, thread_id)
    );
    CREATE TABLE orchestration_v2_projection_provider_threads (
      provider_thread_id TEXT PRIMARY KEY,
      thread_id TEXT,
      provider_session_id TEXT
    );
    CREATE TABLE orchestration_v2_projection_turn_items (
      turn_item_id TEXT PRIMARY KEY,
      thread_id TEXT NOT NULL,
      status TEXT NOT NULL,
      payload_json TEXT NOT NULL
    );
    CREATE TABLE projection_threads (
      thread_id TEXT PRIMARY KEY,
      deleted_at TEXT,
      archived_at TEXT
    );
    CREATE TABLE projection_thread_sessions (
      thread_id TEXT PRIMARY KEY,
      provider_session_id TEXT,
      provider_thread_id TEXT
    );
  `);
  return db;
}

/** Tiny RFC 6455 WebSocket frame encoder/decoder (text frames) for mock T3 RPC tests. */
function encodeWsTextFrame(text: string): Buffer {
  const payload = Buffer.from(text, "utf8");
  if (payload.length < 126) {
    return Buffer.concat([Buffer.from([0x81, payload.length]), payload]);
  }
  const header = Buffer.alloc(4);
  header[0] = 0x81;
  header[1] = 126;
  header.writeUInt16BE(payload.length, 2);
  return Buffer.concat([header, payload]);
}

function decodeWsClientFrames(buf: Buffer): { frames: string[]; rest: Buffer } {
  const frames: string[] = [];
  let offset = 0;
  while (offset + 2 <= buf.length) {
    const opcode = buf[offset]! & 0x0f;
    const masked = (buf[offset + 1]! & 0x80) !== 0;
    let len = buf[offset + 1]! & 0x7f;
    let pos = offset + 2;
    if (len === 126) {
      if (pos + 2 > buf.length) break;
      len = buf.readUInt16BE(pos);
      pos += 2;
    } else if (len === 127) {
      if (pos + 8 > buf.length) break;
      len = Number(buf.readBigUInt64BE(pos));
      pos += 8;
    }
    const maskLen = masked ? 4 : 0;
    if (pos + maskLen + len > buf.length) break;
    const mask = masked ? buf.subarray(pos, pos + 4) : null;
    pos += maskLen;
    const data = Buffer.from(buf.subarray(pos, pos + len));
    if (mask) {
      for (let i = 0; i < data.length; i++) data[i] = data[i]! ^ mask[i % 4]!;
    }
    if (opcode === 0x01) frames.push(data.toString("utf8"));
    offset = pos + len;
  }
  return { frames, rest: buf.subarray(offset) };
}

interface MockT3ServerHandle {
  url: string;
  receivedCommands: Array<Record<string, unknown>>;
  close(): Promise<void>;
}

async function startMockT3Server(options: {
  expectedToken: string;
  projections: Record<string, unknown>;
  rejectMissingThread?: boolean;
}): Promise<MockT3ServerHandle> {
  const receivedCommands: Array<Record<string, unknown>> = [];
  const sockets = new Set<Duplex>();
  const server = createServer((req, res) => {
    const auth = req.headers.authorization;
    if (req.url === "/api/auth/session") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ authenticated: auth === `Bearer ${options.expectedToken}` }));
      return;
    }
    if (req.method === "POST" && req.url === "/api/auth/websocket-ticket") {
      if (auth !== `Bearer ${options.expectedToken}`) {
        res.writeHead(401, { "content-type": "application/json" }).end(JSON.stringify({ error: "unauthorized" }));
        return;
      }
      res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ ticket: "ws-ticket-ok" }));
      return;
    }
    res.writeHead(404).end();
  });

  server.on("upgrade", (req: IncomingMessage, socket: Duplex) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
    const url = new URL(req.url ?? "/", "http://127.0.0.1");
    if (url.pathname !== "/ws" || url.searchParams.get("wsTicket") !== "ws-ticket-ok" || url.searchParams.get("orchestrationProtocol") !== "2") {
      socket.write("HTTP/1.1 426 Upgrade Required\r\n\r\n");
      socket.destroy();
      return;
    }
    const key = req.headers["sec-websocket-key"] ?? "";
    const accept = createHash("sha1").update(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest("base64");
    socket.write(
      `HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`,
    );
    let buf: Buffer = Buffer.alloc(0);
    socket.on("data", (chunk: Buffer) => {
      buf = Buffer.concat([buf, chunk]);
      const decoded = decodeWsClientFrames(buf);
      buf = Buffer.from(decoded.rest);
      for (const raw of decoded.frames) {
        const reqMsg = JSON.parse(raw) as { id: string; tag: string; payload: Record<string, unknown> };
        if (reqMsg.tag === "orchestration.getThreadProjection") {
          const tid = String(reqMsg.payload.threadId ?? "");
          const proj = options.projections[tid];
          if (!proj) {
            socket.write(
              encodeWsTextFrame(
                JSON.stringify({
                  _tag: "Exit",
                  requestId: reqMsg.id,
                  exit: {
                    _tag: "Failure",
                    cause: [
                      {
                        _tag: "Fail",
                        error: {
                          _tag: "OrchestrationV2GetThreadProjectionError",
                          message: `No orchestration projection exists for thread ${tid}.`,
                          cause: { cause: { name: "ProjectionStoreThreadNotFoundError" } },
                        },
                      },
                    ],
                  },
                }),
              ),
            );
          } else {
            socket.write(encodeWsTextFrame(JSON.stringify({ _tag: "Exit", requestId: reqMsg.id, exit: { _tag: "Success", value: proj } })));
          }
          continue;
        }
        if (reqMsg.tag === "orchestration.dispatchCommand") {
          receivedCommands.push(reqMsg.payload);
          socket.write(
            encodeWsTextFrame(JSON.stringify({ _tag: "Exit", requestId: reqMsg.id, exit: { _tag: "Success", value: { sequence: receivedCommands.length } } })),
          );
        }
      }
    });
  });

  await new Promise<void>((res) => server.listen(0, "127.0.0.1", res));
  const addr = server.address();
  const port = typeof addr === "object" && addr ? addr.port : 0;
  return {
    url: `http://127.0.0.1:${port}`,
    receivedCommands,
    async close() {
      for (const s of sockets) s.destroy();
      await new Promise<void>((res) => server.close(() => res()));
    },
  };
}

test("T3 thread identification resolves provider session bindings and in-flight turn_items and fails closed on deleted/ambiguous threads", async () => {
  const baseDir = mkdtempSync(join(tmpdir(), "hyphae-t3-id-"));
  try {
    const db = makeMockT3Db(baseDir);
    try {
      db.prepare("INSERT INTO orchestration_v2_projection_threads (thread_id, deleted_at, archived_at) VALUES (?, NULL, NULL)").run("t3-thread-live");
      db.prepare("INSERT INTO orchestration_v2_projection_threads (thread_id, deleted_at, archived_at) VALUES (?, '2026-01-01', NULL)").run("t3-thread-deleted");
      db.prepare("INSERT INTO orchestration_v2_projection_threads (thread_id, deleted_at, archived_at) VALUES (?, NULL, NULL)").run("t3-thread-ambig-1");
      db.prepare("INSERT INTO orchestration_v2_projection_threads (thread_id, deleted_at, archived_at) VALUES (?, NULL, NULL)").run("t3-thread-ambig-2");

      db.prepare("INSERT INTO orchestration_v2_projection_provider_session_bindings (provider_session_id, thread_id) VALUES (?, ?)").run("claude-sess-1", "t3-thread-live");
      db.prepare("INSERT INTO orchestration_v2_projection_provider_session_bindings (provider_session_id, thread_id) VALUES (?, ?)").run("claude-sess-deleted", "t3-thread-deleted");
      db.prepare("INSERT INTO orchestration_v2_projection_provider_session_bindings (provider_session_id, thread_id) VALUES (?, ?)").run("claude-sess-ambig", "t3-thread-ambig-1");
      db.prepare("INSERT INTO orchestration_v2_projection_provider_session_bindings (provider_session_id, thread_id) VALUES (?, ?)").run("claude-sess-ambig", "t3-thread-ambig-2");

      db.prepare("INSERT INTO orchestration_v2_projection_provider_threads (provider_thread_id, thread_id, provider_session_id) VALUES (?, ?, ?)").run(
        "codex-thr-99",
        "t3-thread-live",
        "codex-sess-99",
      );

      db.prepare("INSERT INTO orchestration_v2_projection_turn_items (turn_item_id, thread_id, status, payload_json) VALUES (?, ?, ?, ?)").run(
        "item-1",
        "t3-thread-live",
        "in_progress",
        JSON.stringify({ callId: "call_live_123", tool: "mcp__hyphae__hyp_join" }),
      );
      db.prepare("INSERT INTO orchestration_v2_projection_turn_items (turn_item_id, thread_id, status, payload_json) VALUES (?, ?, ?, ?)").run(
        "item-done",
        "t3-thread-live",
        "completed",
        JSON.stringify({ callId: "call_done_456", tool: "hyp_join" }),
      );
    } finally {
      db.close();
    }

    assert.equal(verifyT3ThreadExists("t3-thread-live", baseDir), true);
    assert.equal(verifyT3ThreadExists("t3-thread-deleted", baseDir), false);
    assert.equal(verifyT3ThreadExists("missing", baseDir), false);

    const byClaude = resolveT3ThreadByProviderSession("claude-sess-1", baseDir);
    assert.deepEqual(byClaude, { ok: true, threadId: "t3-thread-live" });

    const byCodex = resolveT3ThreadByProviderSession("codex-thr-99", baseDir);
    assert.deepEqual(byCodex, { ok: true, threadId: "t3-thread-live" });

    const deleted = resolveT3ThreadByProviderSession("claude-sess-deleted", baseDir);
    assert.equal(deleted.ok, false);
    if (!deleted.ok) assert.equal(deleted.code, "caller_not_found");

    const ambig = resolveT3ThreadByProviderSession("claude-sess-ambig", baseDir);
    assert.equal(ambig.ok, false);
    if (!ambig.ok) assert.equal(ambig.code, "caller_ambiguous");

    const byCall = await resolveT3CallerByCallId("call_live_123", "hyp_join", { url: "http://127.0.0.1:3773", baseDir }, undefined, 100);
    assert.equal(byCall.ok, true);
    if (byCall.ok) {
      assert.equal(byCall.sessionId, "t3:t3-thread-live");
      assert.equal(byCall.backend.kind, "t3");
    }

    // Completed call must not match; wrong tool must not match.
    const completedCall = await resolveT3CallerByCallId("call_done_456", "hyp_join", { url: "http://127.0.0.1:3773", baseDir }, undefined, 80);
    assert.equal(completedCall.ok, false);
    const wrongTool = await resolveT3CallerByCallId("call_live_123", "hyp_send", { url: "http://127.0.0.1:3773", baseDir }, undefined, 80);
    assert.equal(wrongTool.ok, false);
  } finally {
    rmSync(baseDir, { recursive: true, force: true });
  }
});

test("T3 delivery adapter selects start_immediately, queue_after_active, steer_active, restart_active and handles auth/offline/missing-thread errors", async () => {
  const cfgDir = mkdtempSync(join(tmpdir(), "hyphae-t3-deliv-"));
  const server = await startMockT3Server({
    expectedToken: "t3-secret-token-xyz",
    projections: {
      "thr-idle": { thread: { id: "thr-idle", deletedAt: null }, runs: [], providerThreads: [], providerSessions: [] },
      "thr-steer": {
        thread: { id: "thr-steer", deletedAt: null },
        runs: [{ id: "run-1", status: "running", providerThreadId: "pt-1" }],
        providerThreads: [{ id: "pt-1", providerSessionId: "ps-1" }],
        providerSessions: [{ id: "ps-1", capabilities: { turns: { supportsActiveSteering: true } } }],
      },
      "thr-restart": {
        thread: { id: "thr-restart", deletedAt: null },
        runs: [{ id: "run-2", status: "running", providerThreadId: "pt-2" }],
        providerThreads: [{ id: "pt-2", providerSessionId: "ps-2" }],
        providerSessions: [{ id: "ps-2", capabilities: { turns: { supportsActiveSteering: false, supportsSteeringByInterruptRestart: true } } }],
      },
    },
  });

  try {
    writeSecretDetailed("t3-auth-token", "t3-secret-token-xyz", cfgDir);

    // 1. Idle thread -> start_immediately
    const idleOutcome = await deliverToT3Thread({
      serverUrl: server.url,
      threadId: "thr-idle",
      text: "wake idle thread",
      mode: "queue",
      tokenSecret: "t3-auth-token",
      configDir: cfgDir,
    });
    assert.deepEqual(idleOutcome, { outcome: "delivered" });
    assert.deepEqual(server.receivedCommands.at(-1)?.dispatchMode, { type: "start_immediately" });

    // 2. Active thread + queue -> queue_after_active
    const qOutcome = await deliverToT3Thread({
      serverUrl: server.url,
      threadId: "thr-steer",
      text: "queued follow-up",
      mode: "queue",
      tokenSecret: "t3-auth-token",
      configDir: cfgDir,
    });
    assert.deepEqual(qOutcome, { outcome: "delivered" });
    assert.deepEqual(server.receivedCommands.at(-1)?.dispatchMode, { type: "queue_after_active" });

    // 3. Active thread + interrupt + supportsActiveSteering -> steer_active + interrupted: true
    const steerOutcome = await deliverToT3Thread({
      serverUrl: server.url,
      threadId: "thr-steer",
      text: "urgent alert",
      mode: "interrupt",
      tokenSecret: "t3-auth-token",
      configDir: cfgDir,
    });
    assert.deepEqual(steerOutcome, { outcome: "delivered", interrupted: true });
    assert.deepEqual(server.receivedCommands.at(-1)?.dispatchMode, { type: "steer_active", targetRunId: "run-1" });

    // 4. Active thread + interrupt + no active steering -> restart_active + interrupted: true
    const restartOutcome = await deliverToT3Thread({
      serverUrl: server.url,
      threadId: "thr-restart",
      text: "urgent restart",
      mode: "interrupt",
      tokenSecret: "t3-auth-token",
      configDir: cfgDir,
    });
    assert.deepEqual(restartOutcome, { outcome: "delivered", interrupted: true });
    assert.deepEqual(server.receivedCommands.at(-1)?.dispatchMode, { type: "restart_active", targetRunId: "run-2" });

    // 5. Missing thread -> rejected (t3_thread_not_found)
    const missing = await deliverToT3Thread({
      serverUrl: server.url,
      threadId: "thr-missing",
      text: "hello",
      mode: "queue",
      tokenSecret: "t3-auth-token",
      configDir: cfgDir,
    });
    assert.deepEqual(missing, { outcome: "rejected", reason: "t3_thread_not_found" });

    // 6. Wrong token -> hold (t3_auth_failed)
    const badAuth = await deliverToT3Thread({
      serverUrl: server.url,
      threadId: "thr-idle",
      text: "hello",
      mode: "queue",
      token: "wrong-token",
    });
    assert.deepEqual(badAuth, { outcome: "hold", reason: "t3_auth_failed" });

    // 7. Integration with parseBackend + usesDurableMailbox + createDelivery
    const backend = parseBackend({
      kind: "t3",
      threadId: "thr-idle",
      serverUrl: server.url,
      tokenSecret: "t3-auth-token",
      configDir: cfgDir,
    });
    assert.equal(usesDurableMailbox(backend), false);
    const delivery = createDelivery(backend, () => undefined);
    assert.deepEqual(delivery.modes, ["queue", "interrupt"]);
    const viaDelivery = await delivery.deliver("via createDelivery", "queue", (fn) => fn());
    assert.deepEqual(viaDelivery, { outcome: "delivered" });

    // 8. Origin validation rejects insecure non-loopback HTTP
    assert.throws(() => normalizeT3ServerUrl("http://192.168.1.50:3773"), /HTTPS origin or loopback/);
    assert.equal(normalizeT3ServerUrl("https://t3.example.ts.net"), "https://t3.example.ts.net");
  } finally {
    await server.close();
    rmSync(cfgDir, { recursive: true, force: true });
  }
});
