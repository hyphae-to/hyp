#!/usr/bin/env node
/**
 * Built-in zero-dependency Slack Socket Mode plugin for Hyphae (Node 24+).
 *
 * Configuration via env:
 *   SLACK_APP_TOKEN_FILE or SLACK_APP_TOKEN  - xapp-... Socket Mode token
 *   SLACK_BOT_TOKEN_FILE or SLACK_BOT_TOKEN  - xoxb-... Bot User OAuth token
 *   SLACK_TARGET                             - Target name (defaults to first target in hello)
 *   SLACK_ALLOWLIST_FILE                     - Optional JSON allowlist with owner, allowed users and channels
 *   SLACK_ALLOWED_USERS                      - Optional comma-separated Slack user IDs allowlist
 *   SLACK_ALLOWED_CHANNELS                   - Optional comma-separated channel IDs allowlist
 *   SLACK_DEFAULT_CHANNEL                    - Optional default channel ID for outbound hyp_send
 *   SLACK_API_BASE                           - Optional API base URL override (default https://slack.com/api)
 */
import { readFileSync, statSync } from "node:fs";
import { openSlackState, slackChoiceHandler } from "./actions.mjs";
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
const topLevelChannels = csvSet("SLACK_TOP_LEVEL_CHANNELS");
const allowAll = process.env.SLACK_ALLOW_ALL === "1";
const allowlistFile = process.env.SLACK_ALLOWLIST_FILE;

function readAllowlist() {
  if (allowlistFile === undefined) return null;

  // Never fall back to the environment or a previous snapshot on a failed read.
  const invalid = () => new Error("SLACK_ALLOWLIST_FILE must be a readable JSON allowlist with owner, allowed users, and channels");
  let config;
  try {
    if (!statSync(allowlistFile).isFile()) throw invalid();
    config = JSON.parse(readFileSync(allowlistFile, "utf8"));
  } catch {
    throw invalid();
  }

  if (!config || !Array.isArray(config.allowed) || !Array.isArray(config.channels)) {
    throw invalid();
  }
  const people = new Map();
  function addPerson(person, role) {
    if (
      typeof person?.id !== "string" || !/^[UW][A-Z0-9]+$/.test(person.id) ||
      typeof person.name !== "string" || !person.name.trim() || people.has(person.id)
    ) {
      throw invalid();
    }
    people.set(person.id, { from_name: person.name.trim(), role });
  }
  addPerson(config.owner, "owner");
  for (const person of config.allowed) addPerson(person, "allowed");
  if (!config.channels.every((id) => typeof id === "string" && /^[CGD][A-Z0-9]+$/.test(id))) {
    throw invalid();
  }
  return { people, channels: new Set(config.channels) };
}

function allowsDm(user, channel, allowlist) {
  if (!user || (allowlist && !allowlist.people.has(user))) return false;
  if (allowedUsers) return allowedUsers.has(user);
  // With channel-only env configuration, retain explicitly listed DM conversations.
  if (allowedChannels) return allowedChannels.has(channel);
  return allowlist !== null || allowAll;
}


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
const pickNonEmpty = (...values) => {
  for (const v of values) {
    if (v !== undefined && v !== null) {
      const s = String(v).trim();
      if (s) return s;
    }
  }
  return "";
};
const defaultChannel = pickNonEmpty(process.env.SLACK_DEFAULT_CHANNEL, process.env.SLACK_CHANNEL_ID) || null;
const seenAllowedChannels = new Set();
for (const envChannel of [process.env.SLACK_DEFAULT_CHANNEL, process.env.SLACK_CHANNEL_ID]) {
  const clean = pickNonEmpty(envChannel);
  if (clean) seenAllowedChannels.add(clean);
}
if (allowedChannels) {
  for (const ch of allowedChannels) {
    seenAllowedChannels.add(ch);
  }
}
const admittedDms = new Map();
const lastTsByChannel = new Map();
const lastReactionByMsg = new Map();

function chunkText(text, maxLen = 3900) {
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

if (!readAllowlist() && !allowedUsers && !allowedChannels && !allowAll) {
  throw new Error("Refusing to start Slack bridge without SLACK_ALLOWLIST_FILE, SLACK_ALLOWED_USERS or SLACK_ALLOWED_CHANNELS (set SLACK_ALLOW_ALL=1 to explicitly allow any workspace member)");
}

function canPostTo(channel, allowlist) {
  const dmUser = admittedDms.get(channel);
  if (dmUser) return allowsDm(dmUser, channel, allowlist);
  if (allowedChannels && !allowedChannels.has(channel)) return false;
  if (allowlist) return !channel.startsWith("D") && allowlist.channels.has(channel);
  return seenAllowedChannels.has(channel);
}

async function slackApi(method, token, payload) {
  const form = payload instanceof URLSearchParams;
  const res = await fetch(`${apiBase}/${method}`, {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, "content-type": form ? "application/x-www-form-urlencoded" : "application/json; charset=utf-8" },
    ...(payload ? { body: form ? payload : JSON.stringify(payload) } : {}),
    signal: AbortSignal.timeout(15_000),
  });
  const body = await res.json();
  if (!body.ok) throw new Error(`Slack ${method} failed: ${body.error ?? res.status}`);
  return body;
}

const slackReady = Promise.withResolvers();
const mesh = new MeshPluginClient({
  onDeliveryFailed: (msg) => console.error(`slack plugin delivery_failed target=${msg.target} reason=${msg.reason}`),
  onPost: async (params) => {
    await slackReady.promise;
    const hasReaction = typeof params.reaction === "string" || typeof params.emoji === "string";
    const rawReactionArg =
      typeof params.reaction === "string"
        ? params.reaction
        : typeof params.emoji === "string"
          ? params.emoji
          : "";
    const hasRemoveReaction = typeof params.removeReaction === "string" && params.removeReaction.trim().length > 0;
    const text = typeof params.text === "string" ? params.text.trim() : "";
    if (!hasReaction && !hasRemoveReaction && !text) throw new Error("text or reaction is required");
    const allowlist = readAllowlist();
    let channel = pickNonEmpty(params.channel, params.chatId, params.to, defaultChannel);
    if (!channel) {
      const candidates = new Set([...seenAllowedChannels, ...admittedDms.keys(), ...(allowlist?.channels ?? [])]);
      const eligible = [...candidates].filter((candidate) => canPostTo(candidate, allowlist));
      if (eligible.length > 1) {
        throw new Error(
          "Multiple Slack channels have been seen/configured; specify an explicit channel or set SLACK_DEFAULT_CHANNEL / SLACK_CHANNEL_ID",
        );
      }
      [channel] = eligible;
      if (!channel) {
        throw new Error(
          "No Slack channel specified and no recent inbound channel to reply to (pass channel or set SLACK_DEFAULT_CHANNEL)",
        );
      }
    }
    if (!canPostTo(channel, allowlist)) {
      throw new Error(
        `Channel '${channel}' is not an allowed or previously seen Slack channel (configure SLACK_ALLOWLIST_FILE, SLACK_ALLOWED_CHANNELS or SLACK_DEFAULT_CHANNEL)`,
      );
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
      targetTs = replyTo || explicitThreadTs || lastTsByChannel.get(channel);
      if (!targetTs) {
        throw new Error(`No message timestamp specified via replyTo/threadTs and no recent inbound message in channel '${channel}' to react to`);
      }
      const msgKey = `${channel}:${targetTs}`;
      const trimmedReaction = rawReactionArg.trim();
      const emptyRemoval = hasReaction && trimmedReaction === "" && !hasRemoveReaction;
      isRemove = params.remove === true || emptyRemoval || (hasRemoveReaction && !trimmedReaction);
      const rawEmoji = trimmedReaction
        ? trimmedReaction
        : hasRemoveReaction
          ? params.removeReaction
          : isRemove
            ? (lastReactionByMsg.get(msgKey) ?? "")
            : "";
      reactionName = normalizeSlackReaction(rawEmoji);
      if (!reactionName) {
        throw new Error("Slack reactions.remove requires an emoji name (pass reaction with remove: true)");
      }
      await slackApi(isRemove ? "reactions.remove" : "reactions.add", botToken, {
        channel,
        timestamp: targetTs,
        name: reactionName,
      });
      if (isRemove) {
        if (lastReactionByMsg.get(msgKey) === reactionName) {
          lastReactionByMsg.delete(msgKey);
        }
      } else {
        lastReactionByMsg.delete(msgKey);
        lastReactionByMsg.set(msgKey, reactionName);
        if (lastReactionByMsg.size > 2000) {
          lastReactionByMsg.delete(lastReactionByMsg.keys().next().value);
        }
      }
      didReact = true;
    }

    let postRes = null;
    const sentTs = [];
    if (text) {
      const chunks = chunkText(text, 3900);
      for (let i = 0; i < chunks.length; i += 1) {
        const res = await slackApi("chat.postMessage", botToken, {
          channel,
          text: chunks[i],
          ...(threadTs ? { thread_ts: threadTs } : {}),
        });
        if (!channel.startsWith("D") && isTimestamp(threadTs ?? res.ts)) {
          try {
            rememberThread(channel, threadTs ?? res.ts);
          } catch {
            console.error("Slack message was posted but thread membership could not be saved");
          }
        }
        if (i === 0) postRes = res;
        if (res?.ts) sentTs.push(res.ts);
      }
    }

    return {
      ok: true,
      channel: postRes?.channel ?? channel,
      ...(didReact ? { reacted: !isRemove, removed: isRemove, reaction: reactionName, reactedTs: targetTs } : {}),
      ...(text
        ? {
            ts: postRes?.ts ?? null,
            ...(sentTs.length > 1 ? { timestamps: sentTs, chunks: sentTs.length } : {}),
          }
        : {}),
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
const isTimestamp = (value) => typeof value === "string" && /^\d{1,16}\.\d{1,10}$/.test(value);
const pendingLookups = new Map();

function rememberThread(channel, ts) {
  slackState().prepare("INSERT OR IGNORE INTO threads(channel,ts) VALUES (?,?)").run(channel, ts);
}

function belongsToBot(message) {
  return (typeof botUserId === "string" && botUserId === message?.user) ||
    (typeof auth.bot_id === "string" && auth.bot_id === message?.bot_id);
}

async function followsThread(channel, rootTs) {
  if (!isTimestamp(rootTs)) return false;
  if (slackState().prepare("SELECT 1 FROM threads WHERE channel=? AND ts=?").get(channel, rootTs)) return true;
  const key = channel + ":" + rootTs;
  if (pendingLookups.has(key)) return pendingLookups.get(key);
  const lookup = (async () => {
    try {
      const page = await slackApi("conversations.history", botToken, new URLSearchParams({
        channel, oldest: rootTs, latest: rootTs, inclusive: "true", limit: "1",
      }));
      const root = page.messages?.[0];
      if (root?.ts !== rootTs || (root.thread_ts && root.thread_ts !== rootTs) || !belongsToBot(root)) return false;
      rememberThread(channel, rootTs);
      return true;
    } catch {
      console.error("Slack thread parent could not be verified; reply was not forwarded");
      return false;
    }
  })();
  pendingLookups.set(key, lookup);
  try { return await lookup; } finally { pendingLookups.delete(key); }
}

function admittedSender(user, channel, isDm, allowlist) {
  if (isDm) return allowsDm(user, channel, allowlist);
  return (!allowlist || (allowlist.people.has(user) && allowlist.channels.has(channel))) &&
    (!allowedUsers || allowedUsers.has(user)) && (!allowedChannels || allowedChannels.has(channel));
}

let state;
function slackState() {
  if (!state) {
    state = openSlackState(process.env.HYPHAE_STATE_DIR, teamId, botUserId, target);
    state.exec("CREATE TABLE IF NOT EXISTS threads (channel TEXT NOT NULL, ts TEXT NOT NULL, PRIMARY KEY(channel,ts))");
  }
  return state;
}
const handleClick = slackChoiceHandler({
  team: auth.team_id, bot: botUserId, botId: auth.bot_id,
  state: slackState,
  sender: (user, channel) => {
    const allowlist = readAllowlist();
    return admittedSender(user, channel, channel.startsWith("D"), allowlist)
      ? allowlist?.people.get(user) ?? {} : null;
  },
  update: (params) => slackApi("chat.update", botToken, params),
  send: async (event) => {
    await mesh.send(target, event);
    if (event.data.channel_type === "dm") admittedDms.set(event.data.channel, event.data.user);
    else seenAllowedChannels.add(event.data.channel);
  },
  redactInboundData: (data) => data,
});

async function handleEnvelope(envelope) {
  if (envelope.type !== "events_api") return;
  const ev = envelope.payload?.event;
  if (!ev || (ev.type !== "message" && ev.type !== "app_mention")) return;
  if (envelope.payload.team_id && envelope.payload.team_id !== auth.team_id) return;
  if (belongsToBot(ev)) {
    const channel = ev.channel;
    const root = ev.thread_ts ?? ev.ts;
    if (ev.type === "message" && (!ev.subtype || ev.subtype === "bot_message" || ev.subtype === "file_share") &&
        typeof channel === "string" && /^[CG][A-Z0-9]+$/.test(channel) && isTimestamp(root)) {
      const policy = readAllowlist();
      if ((!policy || policy.channels.has(channel)) && (!allowedChannels || allowedChannels.has(channel))) rememberThread(channel, root);
    }
    return;
  }
  if ((ev.subtype && ev.subtype !== "file_share") || ev.bot_id || ev.bot_profile) return;

  const user = ev.user ?? "";
  const channel = ev.channel ?? "";
  const ts = ev.ts ?? "";
  if (typeof user !== "string" || typeof channel !== "string" || !channel) return;
  const isDm = ev.channel_type === "im" || channel.startsWith("D");
  const allowlist = readAllowlist();
  const person = allowlist?.people.get(user);
  if (!admittedSender(user, channel, isDm, allowlist)) return;

  let via = null;
  if (ev.type === "app_mention") {
    via = "mention";
    if (isTimestamp(ev.thread_ts ?? ts)) rememberThread(channel, ev.thread_ts ?? ts);
  } else if (isDm) {
    via = "dm";
  } else if (ev.thread_ts && await followsThread(channel, ev.thread_ts)) {
    via = "thread";
  } else if (!ev.thread_ts && topLevelChannels?.has(channel)) {
    via = "channel";
  }
  if (!via) return;

  const dedupKey = `${channel}:${ts}`;
  if (seen.has(dedupKey)) return;
  seen.add(dedupKey);
  if (seen.size > 2000) seen.delete(seen.values().next().value);


  if (isDm) {
    admittedDms.set(channel, user);
  } else {
    seenAllowedChannels.add(channel);
  }
  if (ts && channel) {
    lastTsByChannel.set(channel, ts);
    if (lastTsByChannel.size > 1000) {
      lastTsByChannel.delete(lastTsByChannel.keys().next().value);
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
      ...person,
      channel,
      channel_type: isDm ? "dm" : "channel",
      via,
      ts,
      thread_ts: ev.thread_ts ?? null,
      text,
    },
  };
  try { await mesh.send(target, event); } catch (error) { seen.delete(dedupKey); throw error; }
}

let backoff = 1000;
let abortActiveSocket = null;
let cancelBackoff = null;
let wakeRequested = false;

mesh.onWake(() => {
  wakeRequested = true;
  backoff = 1000;
  if (abortActiveSocket) {
    const abort = abortActiveSocket;
    abortActiveSocket = null;
    abort();
  }
  if (cancelBackoff) {
    const cancel = cancelBackoff;
    cancelBackoff = null;
    cancel();
  }
});

slackReady.resolve();
while (true) {
  wakeRequested = false;
  try {
    const opened = await slackApi("apps.connections.open", appToken);
    backoff = 1000;
    await new Promise((resolve) => {
      let settled = false;
      const ws = new WebSocket(opened.url);
      const finish = () => {
        if (settled) return;
        settled = true;
        if (abortActiveSocket === abort) {
          abortActiveSocket = null;
        }
        resolve();
      };
      const abort = () => {
        try {
          ws.close();
        } catch {}
        finish();
      };
      abortActiveSocket = abort;
      if (wakeRequested) {
        abort();
        return;
      }
      ws.addEventListener("message", (msg) => {
        if (settled) return;
        let envelope;
        try { envelope = JSON.parse(String(msg.data)); } catch { return; }
        if (envelope.type === "interactive") {
          void handleClick(envelope.payload).then(() => {
            if (envelope.envelope_id && ws.readyState === WebSocket.OPEN) {
              ws.send(JSON.stringify({ envelope_id: envelope.envelope_id }));
            }
          }).catch(() => console.error("Slack button handling failed; leaving envelope unacknowledged for retry"));
          return;
        }
        if (envelope.envelope_id) {
          ws.send(JSON.stringify({ envelope_id: envelope.envelope_id }));
        }
        if (envelope.type === "disconnect") {
          ws.close();
          return;
        }
        void handleEnvelope(envelope).catch((err) => console.error(`slack handle error: ${err.message}`));
      });
      ws.addEventListener("close", finish);
      ws.addEventListener("error", finish);
    });
  } catch (error) {
    console.error(`slack socket error: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (wakeRequested) {
    wakeRequested = false;
    backoff = 1000;
    continue;
  }
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
