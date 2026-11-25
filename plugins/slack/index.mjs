#!/usr/bin/env node
/**
 * Built-in zero-dependency Slack Socket Mode plugin for Hyphae (Node 24+).
 *
 * Configuration via env:
 *   SLACK_APP_TOKEN_FILE or SLACK_APP_TOKEN  - xapp-... Socket Mode token
 *   SLACK_BOT_TOKEN_FILE or SLACK_BOT_TOKEN  - xoxb-... Bot User OAuth token
 *   SLACK_TARGET                             - Target name (defaults to first target in hello)
 *   SLACK_ALLOWED_USERS                      - Optional comma-separated Slack user IDs allowlist
 *   SLACK_ALLOWED_CHANNELS                   - Optional comma-separated channel IDs allowlist
 *   SLACK_DEFAULT_CHANNEL                    - Optional default channel ID for outbound hyp_plugin_post
 *   SLACK_API_BASE                           - Optional API base URL override (default https://slack.com/api)
 */
import { readFileSync } from "node:fs";
import { MeshPluginClient } from "../sdk/client.mjs";

function readSecret(fileEnv, valEnv) {
  const file = process.env[fileEnv];
  if (file) return readFileSync(file, "utf8").trim();
  const value = process.env[valEnv]?.trim();
  if (value) return value;
  throw new Error(`Set ${valEnv} (via { "secret": "<name>" }) or ${fileEnv}`);
}

const csvSet = (name) => {
  const raw = process.env[name]?.trim();
  return raw ? new Set(raw.split(",").map((v) => v.trim()).filter(Boolean)) : null;
};

const appToken = readSecret("SLACK_APP_TOKEN_FILE", "SLACK_APP_TOKEN");
const botToken = readSecret("SLACK_BOT_TOKEN_FILE", "SLACK_BOT_TOKEN");
const allowedUsers = csvSet("SLACK_ALLOWED_USERS");
const allowedChannels = csvSet("SLACK_ALLOWED_CHANNELS");
const allowAll = process.env.SLACK_ALLOW_ALL === "1";

function resolveApiBase(raw, fallback) {
  const value = (raw?.trim() || fallback).replace(/\/+$/, "");
  const parsed = new URL(value);
  const loopback = ["127.0.0.1", "localhost", "[::1]"].includes(parsed.hostname);
  if (parsed.protocol !== "https:" && !(parsed.protocol === "http:" && loopback)) {
    throw new Error(`SLACK_API_BASE must use https:// or loopback http:// (got ${value})`);
  }
  return value;
}

const apiBase = resolveApiBase(process.env.SLACK_API_BASE, "https://slack.com/api");
let lastChannel = process.env.SLACK_DEFAULT_CHANNEL?.trim() || null;
let lastThreadTs = null;
let lastTs = null;
const lastTsByChannel = new Map();

const SLACK_EMOJI_MAP = new Map([
  ["👍", "thumbsup"],
  ["👎", "thumbsdown"],
  ["❤️", "heart"],
  ["❤", "heart"],
  ["🔥", "fire"],
  ["🎉", "tada"],
  ["👀", "eyes"],
  ["✅", "white_check_mark"],
  ["🚀", "rocket"],
  ["🙏", "pray"],
  ["😄", "smile"],
  ["😊", "smile"],
  ["🤔", "thinking_face"],
  ["💯", "100"],
  ["⚡", "zap"],
  ["⚡️", "zap"],
  ["⚠️", "warning"],
  ["⚠", "warning"],
  ["❌", "x"],
]);

function normalizeSlackReaction(raw) {
  const trimmed = raw.trim();
  if (!trimmed) return "";
  const mapped = SLACK_EMOJI_MAP.get(trimmed) ?? SLACK_EMOJI_MAP.get(trimmed.replace(/\uFE0F/g, ""));
  if (mapped) return mapped;
  const stripped = trimmed.replace(/^:+|:+$/g, "").toLowerCase();
  if (/^[a-z0-9_+-]+$/.test(stripped)) return stripped;
  throw new Error(
    `Unsupported Slack reaction '${trimmed}'; pass a Slack shortcode (e.g. thumbsup, rocket) or common Unicode emoji`,
  );
}

if (!allowedUsers && !allowedChannels && !allowAll) {
  throw new Error("Refusing to start Slack bridge without SLACK_ALLOWED_USERS or SLACK_ALLOWED_CHANNELS (set SLACK_ALLOW_ALL=1 to explicitly allow any workspace member)");
}

async function slackApi(method, token, payload) {
  const res = await fetch(`${apiBase}/${method}`, {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json; charset=utf-8" },
    ...(payload ? { body: JSON.stringify(payload) } : {}),
  });
  const body = await res.json();
  if (!body.ok) throw new Error(`Slack ${method} failed: ${body.error ?? res.status}`);
  return body;
}

const mesh = new MeshPluginClient({
  onDeliveryFailed: (msg) => console.error(`slack plugin delivery_failed target=${msg.target} reason=${msg.reason}`),
  onPost: async (params) => {
    const hasReaction = typeof params.reaction === "string";
    const hasRemoveReaction = typeof params.removeReaction === "string" && params.removeReaction.trim().length > 0;
    const text = typeof params.text === "string" ? params.text.trim() : "";
    if (!hasReaction && !hasRemoveReaction && !text) throw new Error("text or reaction is required");
    const channel =
      (typeof params.channel === "string" && params.channel.trim()) ||
      (typeof params.chatId === "string" && params.chatId.trim()) ||
      (typeof params.to === "string" && params.to.trim()) ||
      lastChannel;
    if (!channel) {
      throw new Error("No Slack channel specified and no recent inbound channel to reply to (pass channel or set SLACK_DEFAULT_CHANNEL)");
    }
    if (allowedChannels && !allowedChannels.has(channel)) {
      throw new Error(`Channel '${channel}' is not in SLACK_ALLOWED_CHANNELS`);
    }

    const replyTo = typeof params.replyTo === "string" && params.replyTo.trim() ? params.replyTo.trim() : undefined;
    const explicitThreadTs =
      typeof params.threadTs === "string" && params.threadTs.trim() ? params.threadTs.trim() : undefined;
    const threadTs = explicitThreadTs || replyTo;

    let didReact = false;
    let isRemove = false;
    let reactionName = "";
    let targetTs;
    if (hasReaction || hasRemoveReaction) {
      isRemove = params.remove === true || (hasRemoveReaction && (!hasReaction || !params.reaction.trim()));
      const rawEmoji = hasReaction && params.reaction.trim() ? params.reaction : hasRemoveReaction ? params.removeReaction : "";
      reactionName = normalizeSlackReaction(rawEmoji);
      if (!reactionName) {
        throw new Error("Slack reactions.remove requires an emoji name (pass reaction with remove: true)");
      }
      targetTs = replyTo || explicitThreadTs || lastTsByChannel.get(channel) || lastTs;
      if (!targetTs) {
        throw new Error("No message timestamp specified via replyTo/threadTs and no recent inbound message to react to");
      }
      await slackApi(isRemove ? "reactions.remove" : "reactions.add", botToken, {
        channel,
        timestamp: targetTs,
        name: reactionName,
      });
      didReact = true;
    }

    let postRes = null;
    if (text) {
      postRes = await slackApi("chat.postMessage", botToken, {
        channel,
        text,
        ...(threadTs ? { thread_ts: threadTs } : {}),
      });
    }

    return {
      ok: true,
      channel: postRes?.channel ?? channel,
      ...(didReact ? { reacted: !isRemove, removed: isRemove, reaction: reactionName, reactedTs: targetTs } : {}),
      ...(text ? { ts: postRes?.ts ?? null } : {}),
    };
  },
});
const hello = await mesh.ready;
const target = process.env.SLACK_TARGET ?? hello.targets[0];
if (!target || !hello.targets.includes(target)) {
  throw new Error(`Target '${target}' not in configured targets: ${hello.targets.join(", ")}`);
}

const auth = await slackApi("auth.test", botToken);
const botUserId = auth.user_id;
const teamId = auth.team_id ?? "slack";
const mentionRe = new RegExp(`<@${botUserId}>\\s*`, "g");
const seen = new Set();
const activeThreads = new Set();

async function handleEnvelope(envelope) {
  if (envelope.type !== "events_api") return;
  const ev = envelope.payload?.event;
  if (!ev || (ev.type !== "message" && ev.type !== "app_mention")) return;
  if ((ev.subtype && ev.subtype !== "file_share") || ev.bot_id || ev.user === botUserId) return;

  const user = ev.user ?? "";
  const channel = ev.channel ?? "";
  const ts = ev.ts ?? "";
  if (allowedUsers && !allowedUsers.has(user)) return;
  if (allowedChannels && !allowedChannels.has(channel)) return;

  const dedupKey = `${channel}:${ts}`;
  if (seen.has(dedupKey)) return;
  seen.add(dedupKey);
  if (seen.size > 2000) seen.delete(seen.values().next().value);

  const isDm = ev.channel_type === "im" || channel.startsWith("D");
  let via = null;
  if (ev.type === "app_mention") {
    via = "mention";
    activeThreads.add(`${channel}:${ev.thread_ts ?? ts}`);
  } else if (isDm) {
    via = "dm";
  } else if (ev.thread_ts && activeThreads.has(`${channel}:${ev.thread_ts}`)) {
    via = "thread";
  }
  if (!via) return;

  lastChannel = channel;
  lastThreadTs = ev.thread_ts ?? ts;
  if (ts) {
    lastTs = ts;
    if (channel) {
      lastTsByChannel.set(channel, ts);
      if (lastTsByChannel.size > 1000) {
        lastTsByChannel.delete(lastTsByChannel.keys().next().value);
      }
    }
  }
  const text = String(ev.text ?? "").replace(mentionRe, "").trim().slice(0, 4000);
  const event = {
    specversion: "1.0",
    id: `${channel}-${ts}`,
    source: `slack/${teamId}`,
    type: isDm ? "com.slack.message.im" : "com.slack.message.channel",
    subject: `${channel}/${ts}`,
    time: new Date().toISOString(),
    datacontenttype: "application/json",
    data: {
      user,
      channel,
      channel_type: isDm ? "dm" : "channel",
      via,
      ts,
      thread_ts: ev.thread_ts ?? null,
      text,
    },
  };
  await mesh.send(target, event);
}

let backoff = 1000;
while (true) {
  try {
    const opened = await slackApi("apps.connections.open", appToken);
    backoff = 1000;
    await new Promise((resolve) => {
      const ws = new WebSocket(opened.url);
      ws.addEventListener("message", (msg) => {
        let envelope;
        try { envelope = JSON.parse(String(msg.data)); } catch { return; }
        if (envelope.envelope_id) {
          ws.send(JSON.stringify({ envelope_id: envelope.envelope_id }));
        }
        if (envelope.type === "disconnect") {
          ws.close();
          return;
        }
        void handleEnvelope(envelope).catch((err) => console.error(`slack handle error: ${err.message}`));
      });
      ws.addEventListener("close", () => resolve());
      ws.addEventListener("error", () => resolve());
    });
  } catch (error) {
    console.error(`slack socket error: ${error instanceof Error ? error.message : String(error)}`);
  }
  await new Promise((r) => setTimeout(r, backoff));
  backoff = Math.min(backoff * 2, 30_000);
}
