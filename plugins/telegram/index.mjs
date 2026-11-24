#!/usr/bin/env node
/**
 * Built-in zero-dependency Telegram Bot long-polling plugin for hyphae / t3-mesh (Node 24+).
 *
 * Configuration via env:
 *   TELEGRAM_BOT_TOKEN_FILE or TELEGRAM_BOT_TOKEN  - Bot token from @BotFather
 *   TELEGRAM_TARGET                                - Target name (defaults to first target in hello)
 *   TELEGRAM_ALLOWED_CHATS                         - Optional comma-separated numeric chat IDs allowlist
 *   TELEGRAM_ALLOWED_USERS                         - Optional comma-separated numeric user IDs allowlist
 *   TELEGRAM_DEFAULT_CHAT                          - Optional default numeric chat ID for outbound hyp_plugin_post
 *   TELEGRAM_API_BASE                              - Optional API base URL override (default https://api.telegram.org)
 *   TELEGRAM_STATE_FILE                            - Optional path to persist polling offset JSON
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { MeshPluginClient } from "../sdk/client.mjs";

function readToken() {
  const file = process.env.TELEGRAM_BOT_TOKEN_FILE;
  if (file) return readFileSync(file, "utf8").trim();
  const value = process.env.TELEGRAM_BOT_TOKEN?.trim();
  if (value) return value;
  throw new Error('Set TELEGRAM_BOT_TOKEN (via { "secret": "<name>" }) or TELEGRAM_BOT_TOKEN_FILE');
}

const csvSet = (name) => {
  const raw = process.env[name]?.trim();
  return raw ? new Set(raw.split(",").map((v) => v.trim()).filter(Boolean)) : null;
};

const token = readToken();
const allowedChats = csvSet("TELEGRAM_ALLOWED_CHATS");
const allowedUsers = csvSet("TELEGRAM_ALLOWED_USERS");
const allowAll = process.env.TELEGRAM_ALLOW_ALL === "1";
const stateFile = process.env.TELEGRAM_STATE_FILE;

function resolveApiBase(raw, fallback) {
  const value = (raw?.trim() || fallback).replace(/\/+$/, "");
  const parsed = new URL(value);
  const loopback = ["127.0.0.1", "localhost", "[::1]"].includes(parsed.hostname);
  if (parsed.protocol !== "https:" && !(parsed.protocol === "http:" && loopback)) {
    throw new Error(`TELEGRAM_API_BASE must use https:// or loopback http:// (got ${value})`);
  }
  return value;
}

const apiBase = resolveApiBase(process.env.TELEGRAM_API_BASE, "https://api.telegram.org");
let lastChatId = process.env.TELEGRAM_DEFAULT_CHAT?.trim() || null;

if (!allowedChats && !allowedUsers && !allowAll) {
  throw new Error("Refusing to start Telegram bridge without TELEGRAM_ALLOWED_USERS or TELEGRAM_ALLOWED_CHATS (set TELEGRAM_ALLOW_ALL=1 to explicitly allow any Telegram user)");
}

const mesh = new MeshPluginClient({
  onDeliveryFailed: (msg) => console.error(`telegram plugin delivery_failed target=${msg.target} reason=${msg.reason}`),
  onPost: async (params) => {
    const text = typeof params.text === "string" ? params.text.trim() : "";
    if (!text) throw new Error("text is required");
    const rawChat = params.chatId ?? params.to ?? params.channel ?? lastChatId;
    const chatId = rawChat !== undefined && rawChat !== null ? String(rawChat).trim() : "";
    if (!chatId) {
      throw new Error("No Telegram chatId specified and no recent inbound chat to reply to (pass chatId or set TELEGRAM_DEFAULT_CHAT)");
    }
    if (allowedChats && !allowedChats.has(chatId)) {
      throw new Error(`Chat '${chatId}' is not in TELEGRAM_ALLOWED_CHATS`);
    }
    const rawReplyTo = params.replyTo !== undefined && params.replyTo !== null ? String(params.replyTo).trim() : "";
    const replyToMessageId = rawReplyTo && /^\d+$/.test(rawReplyTo) ? Number(rawReplyTo) : undefined;
    const res = await fetch(`${apiBase}/bot${token}/sendMessage`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        chat_id: chatId,
        text,
        ...(replyToMessageId !== undefined ? { reply_to_message_id: replyToMessageId } : {}),
      }),
      signal: AbortSignal.timeout(15_000),
    });
    const body = await res.json();
    if (!res.ok || !body.ok) {
      throw new Error(`Telegram sendMessage failed: ${body.description ?? res.status}`);
    }
    return { ok: true, chatId, messageId: body.result?.message_id ?? null };
  },
});
const hello = await mesh.ready;
const target = process.env.TELEGRAM_TARGET ?? hello.targets[0];
if (!target || !hello.targets.includes(target)) {
  throw new Error(`Target '${target}' not in configured targets: ${hello.targets.join(", ")}`);
}

let offset = 0;
if (stateFile && existsSync(stateFile)) {
  try {
    const saved = JSON.parse(readFileSync(stateFile, "utf8"));
    if (typeof saved.offset === "number" && Number.isInteger(saved.offset)) offset = saved.offset;
  } catch {}
}

function saveOffset(next) {
  offset = next;
  if (!stateFile) return;
  mkdirSync(dirname(stateFile), { recursive: true, mode: 0o700 });
  writeFileSync(stateFile, JSON.stringify({ offset }) + "\n", { mode: 0o600 });
}

let backoff = 1000;
while (true) {
  try {
    const res = await fetch(`${apiBase}/bot${token}/getUpdates`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ offset, timeout: 30, allowed_updates: ["message", "edited_message"] }),
      signal: AbortSignal.timeout(40_000),
    });
    const body = await res.json();
    if (!body.ok || !Array.isArray(body.result)) {
      throw new Error(`Telegram getUpdates failed: ${body.description ?? res.status}`);
    }
    backoff = 1000;
    for (const update of body.result) {
      const nextOffset = Number(update.update_id) + 1;
      const msg = update.message ?? update.edited_message;
      if (msg) {
        const chatId = String(msg.chat?.id ?? "");
        const userId = String(msg.from?.id ?? "");
        if ((!allowedChats || allowedChats.has(chatId)) && (!allowedUsers || allowedUsers.has(userId))) {
          if (chatId) lastChatId = chatId;
          const text = String(msg.text ?? msg.caption ?? "").slice(0, 4000);
          const event = {
            specversion: "1.0",
            id: String(update.update_id),
            source: `telegram/${target}`,
            type: update.edited_message ? "com.telegram.message.edited" : "com.telegram.message",
            subject: `${chatId}/${msg.message_id}`,
            time: new Date((msg.date ?? Math.floor(Date.now() / 1000)) * 1000).toISOString(),
            datacontenttype: "application/json",
            data: {
              update_id: update.update_id,
              message_id: msg.message_id,
              chat_id: msg.chat?.id ?? null,
              chat_type: msg.chat?.type ?? null,
              from_id: msg.from?.id ?? null,
              from_username: msg.from?.username ?? null,
              from_name: [msg.from?.first_name, msg.from?.last_name].filter(Boolean).join(" ") || null,
              reply_to_message_id: msg.reply_to_message?.message_id ?? null,
              text,
            },
          };
          const reply = await mesh.send(target, event);
          if (reply.type === "nack" && reply.error === "unavailable") {
            throw new Error("Mesh store temporarily unavailable; retrying update");
          }
        }
      }
      saveOffset(nextOffset);
    }
  } catch (error) {
    console.error(`telegram poll error: ${error instanceof Error ? error.message : String(error)}`);
    await new Promise((r) => setTimeout(r, backoff));
    backoff = Math.min(backoff * 2, 30_000);
  }
}
