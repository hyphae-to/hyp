/**
 * Coupled loopback AgentMail WebSocket + REST catch-up wire-mock (`127.0.0.1:0`).
 *
 * Faithfully reproduces real AgentMail semantics & Blind Spot B3 edge cases:
 *  - Outbound WS (`ws://127.0.0.1:<port>/v0?api_key=<key>`): validates `api_key`, handles
 *    `subscribe` -> `subscribed`, and pushes `event` frames (`message.received`, etc.)
 *  - REST catch-up (`GET /v0/inboxes`, `GET /v0/inboxes/:id`, `GET /v0/inboxes/:id/messages`):
 *    validates `Authorization: Bearer <key>`, enforces **inclusive** `after` cursor semantics
 *    (`Date.parse(msg.timestamp) >= Date.parse(after)`) by default, and supports multi-page
 *    `next_page_token` pagination.
 *  - Explicit **B3 fault-injection mode (`armInterleaveOnNextRestCatchup`)**: the exact moment a
 *    client requests `GET /v0/inboxes/:id/messages`, pushes a live WS `event` frame *mid-REST
 *    catch-up* (before returning the REST page) to prove the plugin freezes cursor advancement
 *    during catch-up with zero skipped messages and zero duplicate deliveries!
 */

import { waitUntil, writeJson } from "./helpers.ts";
import { LoopbackWsServer } from "./ws-server.ts";
import type { WsConnection } from "./ws-server.ts";

export interface AgentMailMessage {
  inbox_id: string;
  thread_id: string;
  message_id: string;
  from: string;
  to: string[];
  cc?: string[];
  subject: string;
  preview: string;
  text?: string;
  html?: string;
  labels: string[];
  timestamp: string;
  size?: number;
  attachments?: Array<Record<string, unknown>>;
}

export interface RecordedAgentMailRest {
  method: string;
  pathname: string;
  searchParams: Record<string, string>;
  authorization: string | null;
  status: number;
}

export interface AgentMailMockOptions {
  apiKey: string;
  inboxes?: string[];
  /** Number of messages per REST catch-up page (default 100). */
  pageSize?: number;
  /** Enforce inclusive `>=` `after` cursor semantics (default: true, matching real AgentMail / B3). */
  inclusiveAfterCursor?: boolean;
}

export class AgentMailMockServer {
  readonly wsServer: LoopbackWsServer;
  readonly wsUrl: string;
  readonly apiBase: string;
  readonly apiKey: string;

  readonly subscribes: Array<{ connId: number; frame: Record<string, any> }> = [];
  readonly restRequests: RecordedAgentMailRest[] = [];

  private readonly inboxes: string[];
  private readonly messagesByInbox = new Map<string, AgentMailMessage[]>();
  private readonly pageSize: number;
  private readonly inclusiveAfterCursor: boolean;
  private nextEventSeq = 1;
  private interleavedLiveQueue: Array<{
    inboxId: string;
    message: AgentMailMessage;
    delayRestMs: number;
  }> = [];

  private constructor(wsServer: LoopbackWsServer, options: AgentMailMockOptions) {
    this.wsServer = wsServer;
    this.wsUrl = `${wsServer.baseWsUrl}/v0`;
    this.apiBase = wsServer.baseHttpUrl;
    this.apiKey = options.apiKey;
    this.inboxes = [...(options.inboxes ?? ["billing@agentmail.to"])];
    this.pageSize = options.pageSize ?? 100;
    this.inclusiveAfterCursor = options.inclusiveAfterCursor !== false;

    for (const inbox of this.inboxes) {
      this.messagesByInbox.set(inbox, []);
    }

    wsServer.setOnConnection((conn) => {
      conn.onMessage((_text, parsed) => {
        if (!parsed || typeof parsed !== "object") return;
        if (parsed.type === "subscribe") {
          this.subscribes.push({ connId: conn.id, frame: parsed });
          conn.sendJson({
            type: "subscribed",
            event_types: parsed.event_types ?? ["message.received"],
            ...(parsed.inbox_ids ? { inbox_ids: parsed.inbox_ids } : {}),
            ...(parsed.pod_ids ? { pod_ids: parsed.pod_ids } : {}),
          });
        }
      });
    });
  }

  static async start(options: AgentMailMockOptions): Promise<AgentMailMockServer> {
    let instance!: AgentMailMockServer;

    const wsServer = await LoopbackWsServer.start({
      validateUpgrade: (req) => {
        const parsed = new URL(req.url ?? "/", "http://127.0.0.1");
        if (parsed.pathname !== "/v0") return 404;
        if (parsed.searchParams.get("api_key") !== options.apiKey) return 401;
        return null;
      },
      httpHandler: async (req, res) => {
        const url = new URL(req.url ?? "/", "http://127.0.0.1");
        const auth =
          typeof req.headers.authorization === "string" ? req.headers.authorization : null;
        const paramsObj = Object.fromEntries(url.searchParams.entries());

        if (auth !== `Bearer ${options.apiKey}`) {
          instance.restRequests.push({
            method: req.method ?? "GET",
            pathname: url.pathname,
            searchParams: paramsObj,
            authorization: auth,
            status: 401,
          });
          writeJson(res, 401, { name: "Unauthorized", message: "Invalid API key" });
          return;
        }

        if (req.method === "GET" && url.pathname === "/v0/inboxes") {
          instance.restRequests.push({
            method: "GET",
            pathname: url.pathname,
            searchParams: paramsObj,
            authorization: auth,
            status: 200,
          });
          writeJson(res, 200, {
            inboxes: instance.inboxes.map((id) => ({ inbox_id: id, status: "active" })),
            next_page_token: null,
          });
          return;
        }

        const singleInbox = /^\/v0\/inboxes\/([^/]+)$/.exec(url.pathname);
        if (req.method === "GET" && singleInbox) {
          const inboxId = decodeURIComponent(singleInbox[1]);
          const exists = instance.inboxes.includes(inboxId);
          const status = exists ? 200 : 404;
          instance.restRequests.push({
            method: "GET",
            pathname: url.pathname,
            searchParams: paramsObj,
            authorization: auth,
            status,
          });
          if (!exists) {
            writeJson(res, 404, { name: "NotFound", message: `Inbox ${inboxId} not found` });
            return;
          }
          writeJson(res, 200, { inbox_id: inboxId, status: "active" });
          return;
        }

        const msgList = /^\/v0\/inboxes\/([^/]+)\/messages$/.exec(url.pathname);
        if (req.method === "GET" && msgList) {
          const inboxId = decodeURIComponent(msgList[1]);

          // B3 fault-injection: fire live WS event(s) MID-REST catch-up before responding!
          const toInterleave = instance.interleavedLiveQueue.filter((item) => item.inboxId === inboxId);
          if (toInterleave.length > 0) {
            instance.interleavedLiveQueue = instance.interleavedLiveQueue.filter(
              (item) => item.inboxId !== inboxId,
            );
            let maxDelay = 0;
            for (const item of toInterleave) {
              instance.pushLiveMessage(item.message, { alsoStoreInRest: false });
              if (item.delayRestMs > maxDelay) maxDelay = item.delayRestMs;
            }
            if (maxDelay > 0) {
              await new Promise((r) => setTimeout(r, maxDelay));
            }
          }

          const all = [...(instance.messagesByInbox.get(inboxId) ?? [])];
          const afterRaw = url.searchParams.get("after");
          const afterMs = afterRaw ? Date.parse(afterRaw) : Number.NaN;
          const labelsParam = url.searchParams.get("labels");
          const ascending = url.searchParams.get("ascending") === "true";
          const limit = Math.min(
            Number(url.searchParams.get("limit") ?? instance.pageSize) || instance.pageSize,
            instance.pageSize,
          );
          const offset = Number(url.searchParams.get("page_token") ?? "0") || 0;

          let filtered = all.filter((m) => {
            if (!Number.isNaN(afterMs)) {
              const t = Date.parse(m.timestamp);
              if (instance.inclusiveAfterCursor ? t < afterMs : t <= afterMs) {
                return false;
              }
            }
            if (labelsParam && !m.labels.includes(labelsParam)) {
              return false;
            }
            return true;
          });

          filtered.sort((a, b) =>
            ascending
              ? Date.parse(a.timestamp) - Date.parse(b.timestamp)
              : Date.parse(b.timestamp) - Date.parse(a.timestamp),
          );

          const page = filtered.slice(offset, offset + limit);
          const nextOffset = offset + page.length;
          const nextPageToken = nextOffset < filtered.length ? String(nextOffset) : null;

          instance.restRequests.push({
            method: "GET",
            pathname: url.pathname,
            searchParams: paramsObj,
            authorization: auth,
            status: 200,
          });
          writeJson(res, 200, {
            count: page.length,
            messages: page,
            ...(nextPageToken ? { next_page_token: nextPageToken } : {}),
          });
          return;
        }

        instance.restRequests.push({
          method: req.method ?? "GET",
          pathname: url.pathname,
          searchParams: paramsObj,
          authorization: auth,
          status: 404,
        });
        writeJson(res, 404, { name: "NotFound", message: "Not Found" });
      },
    });

    instance = new AgentMailMockServer(wsServer, options);
    return instance;
  }

  /** Adds a message to REST history (e.g., mail that arrived while the WS was disconnected). */
  addStoredMessage(msg: AgentMailMessage): void {
    if (!this.inboxes.includes(msg.inbox_id)) {
      this.inboxes.push(msg.inbox_id);
    }
    const list = this.messagesByInbox.get(msg.inbox_id) ?? [];
    if (!list.some((existing) => existing.message_id === msg.message_id)) {
      list.push(msg);
      this.messagesByInbox.set(msg.inbox_id, list);
    }
  }

  /** Pushes a live `event` frame over all active WebSocket connections (and optionally stores in REST). */
  pushLiveMessage(
    msg: AgentMailMessage,
    opts: { eventType?: string; eventId?: string; alsoStoreInRest?: boolean } = {},
  ): string {
    if (opts.alsoStoreInRest !== false) {
      this.addStoredMessage(msg);
    }
    const eventId = opts.eventId ?? `evt_am_${this.nextEventSeq++}`;
    const frame = {
      type: "event",
      event_type: opts.eventType ?? "message.received",
      event_id: eventId,
      message: msg,
      thread: { inbox_id: msg.inbox_id, thread_id: msg.thread_id },
    };
    for (const conn of this.wsServer.activeConnections) {
      conn.sendJson(frame);
    }
    return eventId;
  }

  /**
   * **Blind Spot B3 Fault-Injection Mode:**
   * Arms a live WS message (also stored in REST so both paths carry the same message ID)
   * that will be pushed over the active WS connection THE EXACT MOMENT the client starts its
   * REST catch-up (`GET /v0/inboxes/:id/messages`), delaying the REST response by `delayRestMs`
   * so the live WS event is guaranteed to be processed mid-catch-up!
   */
  armInterleaveOnNextRestCatchup(msg: AgentMailMessage, delayRestMs = 120): void {
    this.addStoredMessage(msg);
    this.interleavedLiveQueue.push({
      inboxId: msg.inbox_id,
      message: msg,
      delayRestMs,
    });
  }

  /** Forces all active WS clients to disconnect (simulating a drop or network blip). */
  disconnectActiveClients(code = 1012, reason = "service restart"): void {
    for (const conn of this.wsServer.activeConnections) {
      conn.close(code, reason);
    }
  }

  waitForSubscribe(minCount = 1, timeoutMs = 15_000): Promise<Array<{ connId: number; frame: Record<string, any> }>> {
    return waitUntil(
      () => (this.subscribes.length >= minCount ? this.subscribes : false),
      `agentmail subscribe count >= ${minCount}`,
      timeoutMs,
    );
  }

  waitForConnections(count = 1, timeoutMs = 15_000): Promise<WsConnection[]> {
    return this.wsServer.waitForConnections(count, timeoutMs);
  }

  close(): Promise<void> {
    return this.wsServer.close();
  }
}
