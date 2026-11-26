/**
 * Stateful loopback Telegram Bot API wire-mock (`127.0.0.1:0`).
 *
 * Implements:
 *  - `getMe` (bot identity lookup for `hyp plugin install` / default target resolution)
 *  - `getUpdates` with stateful offset filtering + non-spinning wait wakeups
 *  - `sendMessage` with recorded calls, reply_to_message_id tracking, and chunk inspection
 *  - `setMessageReaction` with recorded emoji reaction calls
 *  - Injectable `429 Too Many Requests` with `parameters.retry_after` + `Retry-After` header
 */

import http from "node:http";
import { closeHttpServer, readHttpBody, waitUntil, writeJson } from "./helpers.ts";

export interface TelegramUpdateRecord {
  update_id: number;
  message?: Record<string, any>;
  edited_message?: Record<string, any>;
}

export interface RecordedSendMessage {
  chat_id: string | number;
  text: string;
  reply_to_message_id?: number;
  message_id: number;
  raw: Record<string, any>;
}

export interface RecordedReaction {
  chat_id: string | number;
  message_id: number;
  reaction: any[];
  raw: Record<string, any>;
}

export interface RecordedGetUpdates {
  offset: number;
  timeout?: number;
  allowed_updates?: string[];
  returnedIds: number[];
}

export interface TelegramMockOptions {
  botToken: string;
  botUsername?: string;
  botFirstName?: string;
  botId?: number;
  /** Max time a `getUpdates` call waits when no updates are pending (default 200ms). */
  longPollHoldMs?: number;
}

export class TelegramMockServer {
  readonly server: http.Server;
  readonly port: number;
  readonly baseUrl: string;
  readonly botToken: string;
  readonly sentMessages: RecordedSendMessage[] = [];
  readonly reactions: RecordedReaction[] = [];
  readonly getUpdatesCalls: RecordedGetUpdates[] = [];
  readonly getMeCalls: number[] = [];

  private readonly updates: TelegramUpdateRecord[] = [];
  private readonly updateWaiters: Array<() => void> = [];
  private readonly nextFault429 = new Map<string, number>();
  private nextUpdateId = 100;
  private nextOutboundMsgId = 5000;
  private closed = false;

  private constructor(server: http.Server, port: number, options: TelegramMockOptions) {
    this.server = server;
    this.port = port;
    this.baseUrl = `http://127.0.0.1:${port}`;
    this.botToken = options.botToken;
  }

  static async start(options: TelegramMockOptions): Promise<TelegramMockServer> {
    let instance!: TelegramMockServer;
    const holdMs = options.longPollHoldMs ?? 200;

    const server = http.createServer(async (req, res) => {
      const url = new URL(req.url ?? "/", "http://127.0.0.1");
      const match = /^\/bot([^/]+)\/([A-Za-z0-9_]+)$/.exec(url.pathname);
      if (!match) {
        writeJson(res, 404, { ok: false, error_code: 404, description: "Not Found" });
        return;
      }
      const [, token, method] = match;
      if (token !== options.botToken) {
        writeJson(res, 401, { ok: false, error_code: 401, description: "Unauthorized" });
        return;
      }

      const raw = await readHttpBody(req);
      let body: Record<string, any> = {};
      if (raw.length > 0) {
        try {
          body = JSON.parse(raw.toString("utf8"));
        } catch {
          body = {};
        }
      }

      if (instance.nextFault429.has(method)) {
        const retryAfter = instance.nextFault429.get(method)!;
        instance.nextFault429.delete(method);
        writeJson(
          res,
          429,
          {
            ok: false,
            error_code: 429,
            description: `Too Many Requests: retry after ${retryAfter}`,
            parameters: { retry_after: retryAfter },
          },
          { "retry-after": String(retryAfter) },
        );
        return;
      }

      if (method === "getMe") {
        instance.getMeCalls.push(Date.now());
        writeJson(res, 200, {
          ok: true,
          result: {
            id: options.botId ?? 123456789,
            is_bot: true,
            first_name: options.botFirstName ?? "Hyphae Test Bot",
            username: options.botUsername ?? "hyphae_itest_bot",
          },
        });
        return;
      }

      if (method === "getUpdates") {
        const offset = typeof body.offset === "number" ? body.offset : Number(body.offset ?? 0);
        let ready = instance.updates.filter((u) => u.update_id >= offset);
        if (ready.length === 0 && !instance.closed) {
          await new Promise<void>((resolve) => {
            const timer = setTimeout(resolve, holdMs);
            timer.unref?.();
            instance.updateWaiters.push(() => {
              clearTimeout(timer);
              resolve();
            });
          });
          ready = instance.updates.filter((u) => u.update_id >= offset);
        }
        instance.getUpdatesCalls.push({
          offset,
          timeout: typeof body.timeout === "number" ? body.timeout : undefined,
          allowed_updates: Array.isArray(body.allowed_updates) ? body.allowed_updates : undefined,
          returnedIds: ready.map((u) => u.update_id),
        });
        writeJson(res, 200, { ok: true, result: ready });
        return;
      }

      if (method === "sendMessage") {
        const msgId = instance.nextOutboundMsgId++;
        instance.sentMessages.push({
          chat_id: body.chat_id,
          text: String(body.text ?? ""),
          reply_to_message_id:
            typeof body.reply_to_message_id === "number" ? body.reply_to_message_id : undefined,
          message_id: msgId,
          raw: body,
        });
        writeJson(res, 200, {
          ok: true,
          result: {
            message_id: msgId,
            chat: { id: Number(body.chat_id) || body.chat_id, type: "private" },
            date: Math.floor(Date.now() / 1000),
            text: String(body.text ?? ""),
          },
        });
        return;
      }

      if (method === "setMessageReaction") {
        instance.reactions.push({
          chat_id: body.chat_id,
          message_id: Number(body.message_id),
          reaction: Array.isArray(body.reaction) ? body.reaction : [],
          raw: body,
        });
        writeJson(res, 200, { ok: true, result: true });
        return;
      }

      writeJson(res, 404, { ok: false, error_code: 404, description: `Unknown method: ${method}` });
    });

    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", () => resolve());
    });
    const addr = server.address();
    const port = typeof addr === "object" && addr ? addr.port : 0;
    instance = new TelegramMockServer(server, port, options);
    return instance;
  }

  /** Injects a one-shot HTTP 429 `retry_after` response for the next call to `method`. */
  failNextWith429(method: "sendMessage" | "setMessageReaction" | "getUpdates", retryAfterSec = 1): void {
    this.nextFault429.set(method, retryAfterSec);
  }

  /** Enqueues a new inbound Telegram message (or edited message) and wakes any active long-poll. */
  enqueueMessage(opts: {
    chatId: number;
    userId: number;
    text: string;
    username?: string;
    firstName?: string;
    lastName?: string;
    chatType?: string;
    messageId?: number;
    updateId?: number;
    edited?: boolean;
  }): { updateId: number; messageId: number } {
    const updateId = opts.updateId ?? this.nextUpdateId++;
    if (updateId >= this.nextUpdateId) this.nextUpdateId = updateId + 1;
    const messageId = opts.messageId ?? updateId;
    const msg = {
      message_id: messageId,
      date: Math.floor(Date.now() / 1000),
      chat: { id: opts.chatId, type: opts.chatType ?? "private" },
      from: {
        id: opts.userId,
        is_bot: false,
        first_name: opts.firstName ?? "Alice",
        ...(opts.lastName ? { last_name: opts.lastName } : {}),
        ...(opts.username ? { username: opts.username } : {}),
      },
      text: opts.text,
    };
    const record: TelegramUpdateRecord = opts.edited
      ? { update_id: updateId, edited_message: msg }
      : { update_id: updateId, message: msg };
    this.updates.push(record);
    for (const wake of this.updateWaiters.splice(0)) wake();
    return { updateId, messageId };
  }

  waitForGetUpdatesOffset(minOffset: number, timeoutMs = 15_000): Promise<RecordedGetUpdates> {
    return waitUntil(
      () => this.getUpdatesCalls.find((c) => c.offset >= minOffset) ?? false,
      `telegram getUpdates offset >= ${minOffset}`,
      timeoutMs,
    );
  }

  waitForSentMessage(
    predicate: (m: RecordedSendMessage) => boolean,
    timeoutMs = 15_000,
  ): Promise<RecordedSendMessage> {
    return waitUntil(
      () => this.sentMessages.find(predicate) ?? false,
      "telegram sendMessage",
      timeoutMs,
    );
  }

  waitForReaction(
    predicate: (r: RecordedReaction) => boolean,
    timeoutMs = 15_000,
  ): Promise<RecordedReaction> {
    return waitUntil(
      () => this.reactions.find(predicate) ?? false,
      "telegram setMessageReaction",
      timeoutMs,
    );
  }

  async close(): Promise<void> {
    this.closed = true;
    for (const wake of this.updateWaiters.splice(0)) wake();
    await closeHttpServer(this.server);
  }
}
