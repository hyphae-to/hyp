#!/usr/bin/env node
/**
 * Built-in zero-dependency Telegram Bot long-polling plugin for Hyphae (Node 24+).
 *
 * Configuration via env:
 *   TELEGRAM_BOT_TOKEN_FILE or TELEGRAM_BOT_TOKEN  - Bot token from @BotFather
 *   TELEGRAM_TARGET                                - Target name (defaults to first target in hello)
 *   TELEGRAM_ALLOWED_CHATS                         - Optional comma-separated numeric chat IDs allowlist
 *   TELEGRAM_ALLOWED_USERS                         - Optional comma-separated numeric user IDs allowlist
 *   TELEGRAM_DEFAULT_CHAT / TELEGRAM_CHAT_ID       - Optional default numeric chat ID for outbound hyp_send replies
 *   TELEGRAM_API_BASE                              - Optional API base URL override (default https://api.telegram.org)
 *   TELEGRAM_STATE_FILE                            - Optional path to persist polling offset JSON (defaults to $HYPHAE_STATE_DIR/telegram-offset.json when HYPHAE_STATE_DIR is set)
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { MeshPluginClient, PluginRpcError, RPC_UNAVAILABLE } from "../sdk/client.mjs";

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
const stateFile =
  process.env.TELEGRAM_STATE_FILE ||
  (process.env.HYPHAE_STATE_DIR ? join(process.env.HYPHAE_STATE_DIR, "telegram-offset.json") : "");

function resolveApiBase(raw, fallback) {
  const value = (raw?.trim() || fallback).replace(/\/+$/, "");
  const parsed = new URL(value);
  const loopback = ["127.0.0.1", "localhost", "[::1]"].includes(parsed.hostname);
  if (parsed.protocol !== "https:" && !(parsed.protocol === "http:" && loopback)) {
    throw new Error(`TELEGRAM_API_BASE must use https:// or loopback http:// (got ${value})`);
  }
  return value;
}

function pickNonEmpty(...values) {
  for (const v of values) {
    if (v !== undefined && v !== null) {
      const s = String(v).trim();
      if (s) return s;
    }
  }
  return "";
}

function chunkText(text, maxLen = 4096) {
  if (typeof text !== "string" || text.length === 0) return [];
  if (text.length <= maxLen) return [text];
  const chunks = [];
  let remaining = text;
  while (remaining.length > maxLen) {
    let cut = maxLen;
    const prevCode = remaining.charCodeAt(cut - 1);
    if (prevCode >= 0xd800 && prevCode <= 0xdbff) {
      cut -= 1;
    }
    const minBreak = Math.floor(maxLen * 0.5);
    if (remaining[cut] !== "\n" && remaining[cut] !== " ") {
      const nlIdx = remaining.lastIndexOf("\n", cut - 1);
      if (nlIdx >= minBreak) {
        cut = nlIdx + 1;
      } else {
        const spIdx = remaining.lastIndexOf(" ", cut - 1);
        if (spIdx >= minBreak) {
          cut = spIdx + 1;
        }
      }
    }
    const part = remaining.slice(0, cut).trimEnd();
    if (part.length > 0) {
      chunks.push(part);
    }
    remaining = remaining.slice(cut).replace(/^[ \t\n]+/, "");
    if (remaining.length === 0) break;
  }
  if (remaining.length > 0) {
    chunks.push(remaining);
  }
  return chunks;
}

const apiBase = resolveApiBase(process.env.TELEGRAM_API_BASE, "https://api.telegram.org");

async function telegramPost(method, payload) {
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const res = await fetch(`${apiBase}/bot${token}/${method}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(15_000),
    });
    let body = {};
    try {
      body = await res.json();
    } catch {}
    if (res.status === 429 && attempt === 0) {
      const retryAfterSec = Number(body?.parameters?.retry_after ?? res.headers.get("retry-after") ?? 1);
      const clampedSec = Math.min(Math.max(Number.isFinite(retryAfterSec) ? retryAfterSec : 1, 0), 10);
      await new Promise((r) => setTimeout(r, clampedSec * 1000));
      continue;
    }
    if (!res.ok || !body.ok) {
      throw new Error(`Telegram ${method} failed: ${body.description ?? res.status}`);
    }
    return body;
  }
}
const defaultChatId = pickNonEmpty(process.env.TELEGRAM_DEFAULT_CHAT, process.env.TELEGRAM_CHAT_ID) || null;
const seenAllowedChats = new Set();
for (const envChat of [process.env.TELEGRAM_DEFAULT_CHAT, process.env.TELEGRAM_CHAT_ID]) {
  const clean = pickNonEmpty(envChat);
  if (clean) seenAllowedChats.add(clean);
}
if (allowedChats) {
  for (const chatId of allowedChats) {
    seenAllowedChats.add(chatId);
  }
}
const lastMessageIdByChat = new Map();

if (!allowedChats && !allowedUsers && !allowAll) {
  throw new Error("Refusing to start Telegram bridge without TELEGRAM_ALLOWED_USERS or TELEGRAM_ALLOWED_CHATS (set TELEGRAM_ALLOW_ALL=1 to explicitly allow any Telegram user)");
}

const mesh = new MeshPluginClient({
  onDeliveryFailed: (msg) => console.error(`telegram plugin delivery_failed target=${msg.target} reason=${msg.reason}`),
  onPost: async (params) => {
    const hasReaction = typeof params.reaction === "string";
    const reaction = hasReaction ? params.reaction.trim() : "";
    const text = typeof params.text === "string" ? params.text.trim() : "";
    if (!hasReaction && !text) throw new Error("text or reaction is required");
    const explicitChatId = pickNonEmpty(params.chatId, params.to, params.channel);
    let chatId = explicitChatId;
    if (!chatId) {
      if (defaultChatId) {
        chatId = defaultChatId;
      } else if (seenAllowedChats.size > 1) {
        throw new Error(
          "Multiple Telegram chats have been seen/configured; specify an explicit chatId or set TELEGRAM_DEFAULT_CHAT / TELEGRAM_CHAT_ID",
        );
      } else if (seenAllowedChats.size === 1) {
        chatId = seenAllowedChats.values().next().value;
      } else {
        throw new Error(
          "No Telegram chatId specified and no recent inbound chat to reply to (pass chatId or set TELEGRAM_DEFAULT_CHAT)",
        );
      }
    }
    if (allowedChats && !allowedChats.has(chatId)) {
      throw new Error(`Chat '${chatId}' is not in TELEGRAM_ALLOWED_CHATS`);
    }
    if (!seenAllowedChats.has(chatId)) {
      throw new Error(
        `Chat '${chatId}' is not an allowed or previously seen Telegram chat (configure TELEGRAM_ALLOWED_CHATS or TELEGRAM_DEFAULT_CHAT)`,
      );
    }
    const rawReplyTo = params.replyTo !== undefined && params.replyTo !== null ? String(params.replyTo).trim() : "";
    const parsedReplyTo = rawReplyTo && /^\d+$/.test(rawReplyTo) ? Number(rawReplyTo) : undefined;
    const replyToMessageId =
      parsedReplyTo !== undefined && Number.isSafeInteger(parsedReplyTo) && parsedReplyTo > 0
        ? parsedReplyTo
        : undefined;
    if (hasReaction && rawReplyTo && replyToMessageId === undefined) {
      throw new Error(`Invalid Telegram message_id in replyTo: '${rawReplyTo}'`);
    }

    let targetMessageId;
    if (hasReaction) {
      targetMessageId = replyToMessageId ?? lastMessageIdByChat.get(chatId);
      if (targetMessageId === undefined || targetMessageId === null) {
        throw new Error(`No message_id specified via replyTo and no recent inbound message in chat '${chatId}' to react to`);
      }
      await telegramPost("setMessageReaction", {
        chat_id: chatId,
        message_id: targetMessageId,
        reaction: reaction ? [{ type: "emoji", emoji: reaction }] : [],
      });
    }

    let messageId = null;
    const messageIds = [];
    if (text) {
      const chunks = chunkText(text, 4096);
      for (let i = 0; i < chunks.length; i += 1) {
        const body = await telegramPost("sendMessage", {
          chat_id: chatId,
          text: chunks[i],
          ...(i === 0 && replyToMessageId !== undefined ? { reply_to_message_id: replyToMessageId } : {}),
        });
        const id = body.result?.message_id ?? null;
        if (i === 0) messageId = id;
        if (id !== null) messageIds.push(id);
      }
    }

    return {
      ok: true,
      chatId,
      ...(hasReaction ? { reacted: true, reaction, reactedMessageId: targetMessageId } : {}),
      ...(text
        ? {
            messageId,
            ...(messageIds.length > 1 ? { messageIds, chunks: messageIds.length } : {}),
          }
        : {}),
    };
  },
});
function redactToken(msg) {
  const s = String(msg ?? "");
  return token ? s.replaceAll(token, "[REDACTED]") : s;
}

const hello = await mesh.ready;
const target = pickNonEmpty(process.env.TELEGRAM_TARGET, hello.targets?.[0]);
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
let pollAbort = null;
let cancelBackoff = null;
let wakeRequested = false;

mesh.onWake(() => {
  wakeRequested = true;
  backoff = 1000;
  if (pollAbort) {
    const ac = pollAbort;
    pollAbort = null;
    ac.abort(new Error("system.wake"));
  }
  if (cancelBackoff) {
    const cancel = cancelBackoff;
    cancelBackoff = null;
    cancel();
  }
});

while (true) {
  wakeRequested = false;
  const ac = new AbortController();
  pollAbort = ac;
  try {
    const res = await fetch(`${apiBase}/bot${token}/getUpdates`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ offset, timeout: 30, allowed_updates: ["message", "edited_message"] }),
      signal: AbortSignal.any([AbortSignal.timeout(40_000), ac.signal]),
    });
    if (pollAbort === ac) pollAbort = null;
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
          if (chatId) {
            seenAllowedChats.add(chatId);
          }
          if (typeof msg.message_id === "number" && Number.isSafeInteger(msg.message_id) && msg.message_id > 0) {
            if (chatId) {
              lastMessageIdByChat.set(chatId, msg.message_id);
              if (lastMessageIdByChat.size > 1000) {
                lastMessageIdByChat.delete(lastMessageIdByChat.keys().next().value);
              }
            }
          }
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
          try {
            await mesh.send(target, event);
          } catch (error) {
            if (!(error instanceof PluginRpcError) || error.code === RPC_UNAVAILABLE) throw error;
            console.error(`telegram event rejected: ${error.message}`);
          }
        }
      }
      saveOffset(nextOffset);
    }
  } catch (error) {
    if (pollAbort === ac) pollAbort = null;
    if (wakeRequested) {
      wakeRequested = false;
      backoff = 1000;
      continue;
    }
    console.error(`telegram poll error: ${redactToken(error instanceof Error ? error.message : String(error))}`);
    await new Promise((resolve) => {
      const timer = setTimeout(() => {
        cancelBackoff = null;
        resolve();
      }, backoff);
      cancelBackoff = () => {
        clearTimeout(timer);
        resolve();
      };
    });
    if (wakeRequested) {
      wakeRequested = false;
      backoff = 1000;
    } else {
      backoff = Math.min(backoff * 2, 30_000);
    }
  }
}
