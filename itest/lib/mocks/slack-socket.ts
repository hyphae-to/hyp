/**
 * Loopback Slack HTTP Web API + RFC 6455 Socket Mode WebSocket wire-mock (`127.0.0.1:0`).
 *
 * Implements:
 *  - HTTP Web API (`SLACK_API_BASE`):
 *    - `POST /auth.test` (validates `botToken`)
 *    - `POST /apps.connections.open` (validates `appToken`, returns `ws://127.0.0.1:<port>/ws`)
 *    - `POST /chat.postMessage` (records outbound text + `thread_ts`)
 *    - `POST /reactions.add` & `POST /reactions.remove` (records emoji shortcodes)
 *  - Socket Mode WebSocket:
 *    - Emits `hello` on connect
 *    - Pushes `events_api` envelopes with unique `envelope_id` and tracks client ACKs
 *    - Supports `disconnect` frame injection to test clean backoff reconnects
 */

import { readHttpBody, waitUntil, writeJson } from "./helpers.ts";
import { LoopbackWsServer } from "./ws-server.ts";
import type { WsConnection } from "./ws-server.ts";

export interface RecordedSlackPost {
  channel: string;
  text: string;
  thread_ts?: string;
  ts: string;
  raw: Record<string, any>;
}

export interface RecordedSlackReaction {
  action: "add" | "remove";
  channel: string;
  timestamp: string;
  name: string;
}

export interface SlackSocketMockOptions {
  appToken: string;
  botToken: string;
  botUserId?: string;
  teamId?: string;
}

export class SlackSocketMockServer {
  readonly wsServer: LoopbackWsServer;
  readonly apiBase: string;
  readonly wsUrl: string;
  readonly appToken: string;
  readonly botToken: string;
  readonly botUserId: string;
  readonly teamId: string;

  readonly postedMessages: RecordedSlackPost[] = [];
  readonly reactions: RecordedSlackReaction[] = [];
  readonly ackedEnvelopeIds: string[] = [];
  readonly authTestCalls: number[] = [];
  readonly connectionsOpened: number[] = [];

  private nextEnvelopeSeq = 1;
  private nextTsSeq = 1;

  private constructor(wsServer: LoopbackWsServer, options: SlackSocketMockOptions) {
    this.wsServer = wsServer;
    this.apiBase = wsServer.baseHttpUrl;
    this.wsUrl = `${wsServer.baseWsUrl}/ws`;
    this.appToken = options.appToken;
    this.botToken = options.botToken;
    this.botUserId = options.botUserId ?? "U_HYPHAE_BOT";
    this.teamId = options.teamId ?? "T_ITEST";

    wsServer.setOnConnection((conn) => {
      conn.sendJson({
        type: "hello",
        num_connections: wsServer.connections.length,
        debug_info: { host: "slack-mock-local" },
      });
      conn.onMessage((_text, parsed) => {
        if (parsed && typeof parsed.envelope_id === "string") {
          this.ackedEnvelopeIds.push(parsed.envelope_id);
        }
      });
    });
  }

  static async start(options: SlackSocketMockOptions): Promise<SlackSocketMockServer> {
    let instance!: SlackSocketMockServer;

    const wsServer = await LoopbackWsServer.start({
      httpHandler: async (req, res) => {
        const url = new URL(req.url ?? "/", "http://127.0.0.1");
        const method = url.pathname.replace(/^\/+/, "");
        const auth = String(req.headers.authorization ?? "");
        const raw = await readHttpBody(req);
        let body: Record<string, any> = {};
        if (raw.length > 0) {
          try {
            body = JSON.parse(raw.toString("utf8"));
          } catch {
            body = {};
          }
        }

        if (method === "apps.connections.open") {
          if (auth !== `Bearer ${options.appToken}`) {
            writeJson(res, 200, { ok: false, error: "invalid_auth" });
            return;
          }
          instance.connectionsOpened.push(Date.now());
          writeJson(res, 200, { ok: true, url: instance.wsUrl });
          return;
        }

        // All other Web API methods require the bot token (`xoxb-...`).
        if (auth !== `Bearer ${options.botToken}`) {
          writeJson(res, 200, { ok: false, error: "invalid_auth" });
          return;
        }

        if (method === "auth.test") {
          instance.authTestCalls.push(Date.now());
          writeJson(res, 200, {
            ok: true,
            url: "https://itest.slack.com/",
            team: "Itest Workspace",
            user: "hyphae_bot",
            team_id: instance.teamId,
            user_id: instance.botUserId,
          });
          return;
        }

        if (method === "chat.postMessage") {
          const ts = `1700000100.${String(instance.nextTsSeq++).padStart(6, "0")}`;
          instance.postedMessages.push({
            channel: String(body.channel ?? ""),
            text: String(body.text ?? ""),
            thread_ts: typeof body.thread_ts === "string" ? body.thread_ts : undefined,
            ts,
            raw: body,
          });
          writeJson(res, 200, {
            ok: true,
            channel: String(body.channel ?? ""),
            ts,
          });
          return;
        }

        if (method === "reactions.add" || method === "reactions.remove") {
          instance.reactions.push({
            action: method === "reactions.add" ? "add" : "remove",
            channel: String(body.channel ?? ""),
            timestamp: String(body.timestamp ?? ""),
            name: String(body.name ?? ""),
          });
          writeJson(res, 200, { ok: true });
          return;
        }

        writeJson(res, 200, { ok: false, error: `unknown_method:${method}` });
      },
    });

    instance = new SlackSocketMockServer(wsServer, options);
    return instance;
  }

  get latestConnection(): WsConnection | undefined {
    const active = this.wsServer.activeConnections;
    return active.at(-1);
  }

  /** Pushes a Slack Socket Mode `events_api` message / app_mention envelope over the active WS. */
  pushMessageEvent(opts: {
    user: string;
    channel: string;
    text: string;
    channelType?: "im" | "channel";
    type?: "message" | "app_mention";
    ts?: string;
    threadTs?: string;
    envelopeId?: string;
  }): { envelopeId: string; ts: string } {
    const conn = this.latestConnection;
    if (!conn) {
      throw new Error("SlackSocketMockServer has no active WebSocket connection");
    }
    const envelopeId = opts.envelopeId ?? `env-${this.nextEnvelopeSeq++}`;
    const ts = opts.ts ?? `1700000000.${String(this.nextTsSeq++).padStart(6, "0")}`;
    conn.sendJson({
      envelope_id: envelopeId,
      type: "events_api",
      accepts_response_payload: false,
      payload: {
        team_id: this.teamId,
        type: "event_callback",
        event: {
          type: opts.type ?? "message",
          user: opts.user,
          channel: opts.channel,
          channel_type: opts.channelType ?? (opts.channel.startsWith("D") ? "im" : "channel"),
          text: opts.text,
          ts,
          ...(opts.threadTs ? { thread_ts: opts.threadTs } : {}),
        },
      },
    });
    return { envelopeId, ts };
  }

  /** Injects a Socket Mode `disconnect` frame to verify plugin reconnect behavior. */
  sendDisconnect(reason = "refresh_requested"): void {
    const conn = this.latestConnection;
    if (!conn) {
      throw new Error("SlackSocketMockServer has no active WebSocket connection to disconnect");
    }
    conn.sendJson({ type: "disconnect", reason });
  }

  waitForConnections(count = 1, timeoutMs = 15_000): Promise<WsConnection[]> {
    return this.wsServer.waitForConnections(count, timeoutMs);
  }

  waitForAck(envelopeId: string, timeoutMs = 10_000): Promise<string> {
    return waitUntil(
      () => (this.ackedEnvelopeIds.includes(envelopeId) ? envelopeId : false),
      `slack envelope ack '${envelopeId}'`,
      timeoutMs,
      15,
    );
  }

  waitForPostMessage(
    predicate: (m: RecordedSlackPost) => boolean,
    timeoutMs = 15_000,
  ): Promise<RecordedSlackPost> {
    return waitUntil(
      () => this.postedMessages.find(predicate) ?? false,
      "slack chat.postMessage",
      timeoutMs,
    );
  }

  waitForReaction(
    predicate: (r: RecordedSlackReaction) => boolean,
    timeoutMs = 15_000,
  ): Promise<RecordedSlackReaction> {
    return waitUntil(
      () => this.reactions.find(predicate) ?? false,
      "slack reaction",
      timeoutMs,
    );
  }

  close(): Promise<void> {
    return this.wsServer.close();
  }
}
