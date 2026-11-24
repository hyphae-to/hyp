import { createHash, createHmac, randomUUID } from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { Duplex } from "node:stream";
import { signatureHeader } from "../../../src/core/github/signature.ts";
import { object } from "../../../src/protocol.ts";

const WS_MAGIC = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

async function readBody(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk)));
  return Buffer.concat(chunks).toString("utf8");
}

function encodeWsFrame(opcode: number, payload: Buffer): Buffer {
  const len = payload.length;
  let header: Buffer;
  if (len < 126) {
    header = Buffer.alloc(2);
    header[0] = 0x80 | opcode;
    header[1] = len;
  } else if (len < 65536) {
    header = Buffer.alloc(4);
    header[0] = 0x80 | opcode;
    header[1] = 126;
    header.writeUInt16BE(len, 2);
  } else {
    header = Buffer.alloc(10);
    header[0] = 0x80 | opcode;
    header[1] = 127;
    header.writeBigUInt64BE(BigInt(len), 2);
  }
  return Buffer.concat([header, payload]);
}

function parseWsFrames(buffer: Buffer): { frames: Array<{ opcode: number; payload: Buffer }>; rest: Buffer } {
  const frames: Array<{ opcode: number; payload: Buffer }> = [];
  let offset = 0;
  while (offset + 2 <= buffer.length) {
    const b0 = buffer[offset];
    const b1 = buffer[offset + 1];
    const opcode = b0 & 0x0f;
    const masked = (b1 & 0x80) !== 0;
    let payloadLen = b1 & 0x7f;
    let pos = offset + 2;
    if (payloadLen === 126) {
      if (pos + 2 > buffer.length) break;
      payloadLen = buffer.readUInt16BE(pos);
      pos += 2;
    } else if (payloadLen === 127) {
      if (pos + 8 > buffer.length) break;
      payloadLen = Number(buffer.readBigUInt64BE(pos));
      pos += 8;
    }
    const maskLen = masked ? 4 : 0;
    if (pos + maskLen + payloadLen > buffer.length) break;
    const mask = masked ? buffer.subarray(pos, pos + 4) : null;
    pos += maskLen;
    const raw = Buffer.from(buffer.subarray(pos, pos + payloadLen));
    if (mask) {
      for (let i = 0; i < raw.length; i++) raw[i] ^= mask[i & 3];
    }
    frames.push({ opcode, payload: raw });
    offset = pos + payloadLen;
  }
  return { frames, rest: buffer.subarray(offset) };
}

export interface MockSlackOptions {
  readonly appToken: string;
  readonly botToken: string;
  readonly botUserId?: string;
  readonly teamId?: string;
}

export interface MockSlackPostedMessage {
  readonly channel: string;
  readonly text: string;
  readonly thread_ts?: string;
  readonly ts: string;
}

export interface MockSlackServer {
  readonly apiBaseUrl: string;
  readonly wsUrl: string;
  readonly authCalls: string[];
  readonly ackedEnvelopes: string[];
  readonly postedMessages: MockSlackPostedMessage[];
  /** Wait until the Slack plugin completes auth.test + Socket Mode WebSocket handshake. */
  waitForConnected(timeoutMs?: number): Promise<void>;
  /** Push a Slack Socket Mode `events_api` envelope to connected plugin(s) and return its `envelope_id`. */
  pushEvent(event: Record<string, unknown>, envelopeId?: string): string;
  /** Wait until the Slack plugin sends a Socket Mode ack for `envelopeId`. */
  waitForAck(envelopeId: string, timeoutMs?: number): Promise<void>;
  /** Inject (or clear with `null`) an upstream Slack Web API error for `chat.postMessage`. */
  setPostError(error: string | null): void;
  /** Wait until at least `minCount` accepted `chat.postMessage` calls have been recorded. */
  waitForPost(minCount?: number, timeoutMs?: number): Promise<MockSlackPostedMessage[]>;
  close(): Promise<void>;
}

/**
 * Zero-dependency loopback Slack Web API + Socket Mode WebSocket server on `127.0.0.1`
 * for end-to-end testing of the real `plugins/slack/index.mjs` bridge.
 */
export async function startMockSlackServer(options: MockSlackOptions): Promise<MockSlackServer> {
  const botUserId = options.botUserId ?? "UBOT123";
  const teamId = options.teamId ?? "TTEAM99";
  const authCalls: string[] = [];
  const ackedEnvelopes: string[] = [];
  const postedMessages: MockSlackPostedMessage[] = [];
  const sockets = new Set<Duplex>();
  const pendingEnvelopes: string[] = [];
  const connectWaiters = new Set<() => void>();
  const ackWaiters = new Map<string, Set<() => void>>();
  const postWaiters = new Set<() => void>();
  let postError: string | null = null;
  let postSeq = 0;

  let port = 0;

  const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    const raw = await readBody(req);
    const url = new URL(req.url ?? "/", "http://127.0.0.1");
    const auth = req.headers.authorization ?? "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";

    if (req.method === "POST" && url.pathname === "/api/auth.test") {
      authCalls.push(token);
      if (token !== options.botToken) {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: false, error: "invalid_auth" }));
        return;
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true, user_id: botUserId, team_id: teamId }));
      return;
    }

    if (req.method === "POST" && url.pathname === "/api/apps.connections.open") {
      if (token !== options.appToken) {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: false, error: "invalid_auth" }));
        return;
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true, url: `ws://127.0.0.1:${port}/ws` }));
      return;
    }

    if (req.method === "POST" && url.pathname === "/api/chat.postMessage") {
      if (token !== options.botToken) {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: false, error: "invalid_auth" }));
        return;
      }
      if (postError !== null) {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: false, error: postError }));
        return;
      }
      let parsed: unknown = null;
      try {
        parsed = JSON.parse(raw);
      } catch {}
      const channel = object(parsed) && typeof parsed.channel === "string" ? parsed.channel : "";
      const text = object(parsed) && typeof parsed.text === "string" ? parsed.text : "";
      const threadTs = object(parsed) && typeof parsed.thread_ts === "string" ? parsed.thread_ts : undefined;
      if (!channel) {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: false, error: "channel_not_found" }));
        return;
      }
      if (!text) {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: false, error: "no_text" }));
        return;
      }
      const ts = `${Math.floor(Date.now() / 1000)}.${String(++postSeq).padStart(6, "0")}`;
      const record: MockSlackPostedMessage = {
        channel,
        text,
        ...(threadTs !== undefined ? { thread_ts: threadTs } : {}),
        ts,
      };
      postedMessages.push(record);
      for (const wake of postWaiters) wake();
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true, channel, ts }));
      return;
    }

    res.writeHead(404, { "content-type": "application/json" });
    res.end(JSON.stringify({ ok: false, error: "unknown_method" }));
  });

  server.on("upgrade", (req, socket) => {
    const key = req.headers["sec-websocket-key"];
    if (typeof key !== "string") {
      socket.destroy();
      return;
    }
    const accept = createHash("sha1").update(key + WS_MAGIC).digest("base64");
    socket.write(
      "HTTP/1.1 101 Switching Protocols\r\n" +
      "Upgrade: websocket\r\n" +
      "Connection: Upgrade\r\n" +
      `Sec-WebSocket-Accept: ${accept}\r\n\r\n`,
    );
    sockets.add(socket);

    // Send Socket Mode hello frame like real Slack does.
    socket.write(encodeWsFrame(0x1, Buffer.from(JSON.stringify({ type: "hello", num_connections: sockets.size }), "utf8")));
    while (pendingEnvelopes.length > 0) {
      const next = pendingEnvelopes.shift()!;
      socket.write(encodeWsFrame(0x1, Buffer.from(next, "utf8")));
    }
    for (const wake of connectWaiters) wake();
    connectWaiters.clear();

    let rx: Buffer = Buffer.alloc(0);
    socket.on("data", (chunk: Buffer) => {
      rx = Buffer.concat([rx, chunk]);
      const { frames, rest } = parseWsFrames(rx);
      rx = rest;
      for (const frame of frames) {
        if (frame.opcode === 0x8) {
          socket.write(encodeWsFrame(0x8, Buffer.alloc(0)));
          socket.end();
        } else if (frame.opcode === 0x9) {
          socket.write(encodeWsFrame(0xa, frame.payload));
        } else if (frame.opcode === 0x1) {
          try {
            const parsed: unknown = JSON.parse(frame.payload.toString("utf8"));
            if (object(parsed) && typeof parsed.envelope_id === "string") {
              ackedEnvelopes.push(parsed.envelope_id);
              const waiters = ackWaiters.get(parsed.envelope_id);
              if (waiters) {
                for (const wake of waiters) wake();
                ackWaiters.delete(parsed.envelope_id);
              }
            }
          } catch {}
        }
      }
    });
    socket.on("close", () => sockets.delete(socket));
    socket.on("error", () => sockets.delete(socket));
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Failed to bind mock Slack server");
  port = address.port;

  return {
    apiBaseUrl: `http://127.0.0.1:${port}/api`,
    wsUrl: `ws://127.0.0.1:${port}/ws`,
    authCalls,
    ackedEnvelopes,
    postedMessages,
    async waitForConnected(timeoutMs = 8_000) {
      if (sockets.size > 0) return;
      await new Promise<void>((resolve, reject) => {
        const timer = setTimeout(() => {
          connectWaiters.delete(onConnect);
          reject(new Error("Timed out waiting for Slack plugin WebSocket connection"));
        }, timeoutMs).unref();
        const onConnect = () => {
          clearTimeout(timer);
          resolve();
        };
        connectWaiters.add(onConnect);
      });
    },
    pushEvent(event, envelopeId = `env_${randomUUID()}`) {
      const frame = JSON.stringify({
        envelope_id: envelopeId,
        type: "events_api",
        accepts_response_payload: false,
        payload: { team_id: teamId, event },
      });
      if (sockets.size === 0) {
        pendingEnvelopes.push(frame);
      } else {
        const encoded = encodeWsFrame(0x1, Buffer.from(frame, "utf8"));
        for (const sock of sockets) sock.write(encoded);
      }
      return envelopeId;
    },
    async waitForAck(envelopeId, timeoutMs = 5_000) {
      if (ackedEnvelopes.includes(envelopeId)) return;
      await new Promise<void>((resolve, reject) => {
        const timer = setTimeout(() => {
          ackWaiters.get(envelopeId)?.delete(onAck);
          reject(new Error(`Timed out waiting for Slack ack of ${envelopeId}`));
        }, timeoutMs).unref();
        const onAck = () => {
          clearTimeout(timer);
          resolve();
        };
        let set = ackWaiters.get(envelopeId);
        if (!set) {
          set = new Set();
          ackWaiters.set(envelopeId, set);
        }
        set.add(onAck);
      });
    },
    setPostError(error) {
      postError = error;
    },
    async waitForPost(minCount = 1, timeoutMs = 8_000) {
      if (postedMessages.length >= minCount) return postedMessages;
      await new Promise<void>((resolve, reject) => {
        const timer = setTimeout(() => {
          postWaiters.delete(onPost);
          reject(new Error(`Timed out waiting for ${minCount} Slack chat.postMessage call(s) (saw ${postedMessages.length})`));
        }, timeoutMs).unref();
        const onPost = () => {
          if (postedMessages.length >= minCount) {
            clearTimeout(timer);
            postWaiters.delete(onPost);
            resolve();
          }
        };
        postWaiters.add(onPost);
      });
      return postedMessages;
    },
    close: () =>
      new Promise<void>((resolve) => {
        for (const sock of sockets) sock.destroy();
        sockets.clear();
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}

export interface TelegramUpdate {
  readonly update_id: number;
  readonly message?: {
    readonly message_id: number;
    readonly date?: number;
    readonly chat: { readonly id: number; readonly type: string };
    readonly from: { readonly id: number; readonly username?: string; readonly first_name?: string; readonly last_name?: string };
    readonly text?: string;
  };
  readonly edited_message?: {
    readonly message_id: number;
    readonly date?: number;
    readonly chat: { readonly id: number; readonly type: string };
    readonly from: { readonly id: number; readonly username?: string; readonly first_name?: string; readonly last_name?: string };
    readonly text?: string;
  };
}

export interface MockTelegramSentMessage {
  readonly chat_id: string;
  readonly text: string;
  readonly reply_to_message_id?: number;
  readonly message_id: number;
}

export interface MockTelegramServer {
  readonly apiBaseUrl: string;
  readonly pollOffsets: number[];
  readonly sentMessages: MockTelegramSentMessage[];
  pushUpdate(update: TelegramUpdate): void;
  waitForPoll(minCalls?: number, timeoutMs?: number): Promise<void>;
  /** Inject (or clear with `null`) an upstream Telegram Bot API error for `sendMessage`. */
  setSendError(description: string | null, status?: number): void;
  /** Wait until at least `minCount` accepted `sendMessage` calls have been recorded. */
  waitForSent(minCount?: number, timeoutMs?: number): Promise<MockTelegramSentMessage[]>;
  close(): Promise<void>;
}

/**
 * Loopback Telegram Bot API (`POST /bot<token>/getUpdates` & `POST /bot<token>/sendMessage`) server
 * on `127.0.0.1` for end-to-end testing of the real `plugins/telegram/index.mjs` bridge.
 */
export async function startMockTelegramServer(botToken: string, pollHoldMs = 120): Promise<MockTelegramServer> {
  const queue: TelegramUpdate[] = [];
  const pollOffsets: number[] = [];
  const sentMessages: MockTelegramSentMessage[] = [];
  const updateWaiters = new Set<() => void>();
  const pollWaiters = new Set<() => void>();
  const sendWaiters = new Set<() => void>();
  let sendError: { readonly description: string; readonly status: number } | null = null;
  let nextMessageId = 0;

  const wakeUpdateWaiters = () => {
    for (const wake of updateWaiters) wake();
    updateWaiters.clear();
  };

  const server = createServer(async (req, res) => {
    const raw = await readBody(req);
    const url = new URL(req.url ?? "/", "http://127.0.0.1");
    const getUpdatesPath = `/bot${botToken}/getUpdates`;
    const sendMessagePath = `/bot${botToken}/sendMessage`;

    if (req.method === "POST" && url.pathname === sendMessagePath) {
      if (sendError !== null) {
        res.writeHead(sendError.status, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: false, error_code: sendError.status, description: sendError.description }));
        return;
      }
      let parsed: unknown = null;
      try {
        parsed = JSON.parse(raw);
      } catch {}
      const chatId =
        object(parsed) && (typeof parsed.chat_id === "string" || typeof parsed.chat_id === "number")
          ? String(parsed.chat_id)
          : "";
      const text = object(parsed) && typeof parsed.text === "string" ? parsed.text : "";
      const replyToMessageId =
        object(parsed) && typeof parsed.reply_to_message_id === "number" && Number.isInteger(parsed.reply_to_message_id)
          ? parsed.reply_to_message_id
          : undefined;
      if (!chatId || !text) {
        res.writeHead(400, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: false, error_code: 400, description: "Bad Request: chat_id and text are required" }));
        return;
      }
      const message_id = ++nextMessageId;
      const record: MockTelegramSentMessage = {
        chat_id: chatId,
        text,
        ...(replyToMessageId !== undefined ? { reply_to_message_id: replyToMessageId } : {}),
        message_id,
      };
      sentMessages.push(record);
      for (const wake of sendWaiters) wake();
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true, result: { message_id } }));
      return;
    }

    if (req.method !== "POST" || url.pathname !== getUpdatesPath) {
      res.writeHead(401, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: false, description: "Unauthorized" }));
      return;
    }

    let offset = 0;
    try {
      const parsed: unknown = JSON.parse(raw);
      if (object(parsed) && typeof parsed.offset === "number") offset = parsed.offset;
    } catch {}
    pollOffsets.push(offset);
    for (const wake of pollWaiters) wake();

    const pickDue = () => queue.filter((u) => u.update_id >= offset);
    let due = pickDue();
    if (due.length === 0) {
      await new Promise<void>((resolve) => {
        const timer = setTimeout(() => {
          updateWaiters.delete(onUpdate);
          resolve();
        }, pollHoldMs).unref();
        const onUpdate = () => {
          clearTimeout(timer);
          resolve();
        };
        updateWaiters.add(onUpdate);
      });
      due = pickDue();
    }

    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ ok: true, result: due }));
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Failed to bind mock Telegram server");

  return {
    apiBaseUrl: `http://127.0.0.1:${address.port}`,
    pollOffsets,
    sentMessages,
    pushUpdate(update) {
      queue.push(update);
      wakeUpdateWaiters();
    },
    async waitForPoll(minCalls = 1, timeoutMs = 8_000) {
      if (pollOffsets.length >= minCalls) return;
      await new Promise<void>((resolve, reject) => {
        const timer = setTimeout(() => {
          pollWaiters.delete(onPoll);
          reject(new Error(`Timed out waiting for ${minCalls} Telegram getUpdates polls (saw ${pollOffsets.length})`));
        }, timeoutMs).unref();
        const onPoll = () => {
          if (pollOffsets.length >= minCalls) {
            clearTimeout(timer);
            pollWaiters.delete(onPoll);
            resolve();
          }
        };
        pollWaiters.add(onPoll);
      });
    },
    setSendError(description, status = 400) {
      sendError = description === null ? null : { description, status };
    },
    async waitForSent(minCount = 1, timeoutMs = 8_000) {
      if (sentMessages.length >= minCount) return sentMessages;
      await new Promise<void>((resolve, reject) => {
        const timer = setTimeout(() => {
          sendWaiters.delete(onSend);
          reject(new Error(`Timed out waiting for ${minCount} Telegram sendMessage call(s) (saw ${sentMessages.length})`));
        }, timeoutMs).unref();
        const onSend = () => {
          if (sentMessages.length >= minCount) {
            clearTimeout(timer);
            sendWaiters.delete(onSend);
            resolve();
          }
        };
        sendWaiters.add(onSend);
      });
      return sentMessages;
    },
    close: () =>
      new Promise<void>((resolve) => {
        wakeUpdateWaiters();
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}

export interface GithubDeliveryInput {
  readonly receiverUrl: string;
  readonly secret: string;
  readonly event: string;
  readonly deliveryId?: string;
  readonly payload: Record<string, unknown>;
  /** Set to a bogus signature string (or `null` to omit header) to test 401 rejection. */
  readonly overrideSignature?: string | null;
}

/** Sends a realistic signed (or deliberately tampered) GitHub webhook POST to a `github-webhook` receiver. */
export async function deliverGithubWebhook(input: GithubDeliveryInput): Promise<{ status: number; body: unknown }> {
  const raw = JSON.stringify(input.payload);
  const sig = input.overrideSignature === undefined ? signatureHeader(input.secret, raw) : input.overrideSignature;
  const headers: Record<string, string> = {
    "content-type": "application/json",
    "x-github-event": input.event,
    "x-github-delivery": input.deliveryId ?? randomUUID(),
  };
  if (sig !== null) headers["x-hub-signature-256"] = sig;

  const url = input.receiverUrl.endsWith("/hooks/github") ? input.receiverUrl : `${input.receiverUrl}/hooks/github`;
  const res = await fetch(url, { method: "POST", headers, body: raw });
  const body: unknown = await res.json().catch(() => null);
  return { status: res.status, body };
}

/** Build a realistic GitHub `pull_request` webhook payload normalized cleanly by Hyphae's GitHub receiver. */
export function makeGithubPullRequestPayload(opts: {
  readonly repo: string;
  readonly number: number;
  readonly title: string;
  readonly action?: string;
  readonly author?: string;
  readonly branch?: string;
  readonly body?: string;
  readonly labels?: readonly string[];
}): Record<string, unknown> {
  return {
    action: opts.action ?? "opened",
    number: opts.number,
    repository: { full_name: opts.repo, default_branch: "main" },
    sender: { login: opts.author ?? "alice", type: "User" },
    pull_request: {
      number: opts.number,
      title: opts.title,
      body: opts.body ?? "",
      state: "open",
      draft: false,
      html_url: `https://github.com/${opts.repo}/pull/${opts.number}`,
      labels: (opts.labels ?? []).map((name) => ({ name })),
      assignees: [],
      head: { ref: opts.branch ?? `fix/pr-${opts.number}`, sha: "abc1234567890" },
      base: { ref: "main" },
    },
  };
}

export interface SignedWebhookDeliveryInput {
  readonly url: string;
  readonly secret?: string;
  readonly deliveryId?: string;
  readonly payload: Record<string, unknown>;
  /** Set to a bogus signature string (or `null` to omit) to test 401 rejection. */
  readonly overrideSignature?: string | null;
  /** Retry briefly while the child webhook plugin HTTP server binds its loopback port. */
  readonly waitForReadyMs?: number;
}

/** Sends a signed (or tampered) JSON webhook POST to a `webhook-stream` or `webhook` bridge endpoint. */
export async function deliverSignedWebhook(input: SignedWebhookDeliveryInput): Promise<{ status: number; body: unknown }> {
  const raw = JSON.stringify(input.payload);
  const sig =
    input.overrideSignature !== undefined
      ? input.overrideSignature
      : input.secret
        ? `sha256=${createHmac("sha256", input.secret).update(raw).digest("hex")}`
        : null;
  const headers: Record<string, string> = {
    "content-type": "application/json",
    "x-delivery-id": input.deliveryId ?? randomUUID(),
  };
  if (sig !== null) headers["x-webhook-signature-256"] = sig;

  const deadline = Date.now() + (input.waitForReadyMs ?? 5_000);
  while (true) {
    try {
      const res = await fetch(input.url, { method: "POST", headers, body: raw });
      const body: unknown = await res.json().catch(() => null);
      return { status: res.status, body };
    } catch (err) {
      if (Date.now() >= deadline) throw err;
      await new Promise((r) => setTimeout(r, 80));
    }
  }
}

/** Build a Prometheus Alertmanager-style CloudEvent envelope for `webhook-stream`. */
export function makePrometheusAlertPayload(opts: {
  readonly alertname: string;
  readonly severity: "critical" | "warning" | "info";
  readonly service: string;
  readonly summary: string;
  readonly status?: "firing" | "resolved";
}): Record<string, unknown> {
  return {
    type: opts.status === "resolved" ? "com.prometheus.alert.resolved" : "com.prometheus.alert.firing",
    source: `prometheus/${opts.service}`,
    subject: `${opts.service}/${opts.alertname}`,
    data: {
      status: opts.status ?? "firing",
      alertname: opts.alertname,
      severity: opts.severity,
      service: opts.service,
      summary: opts.summary,
    },
  };
}
