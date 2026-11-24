#!/usr/bin/env node
/**
 * Built-in zero-dependency Slack Socket Mode plugin for hyphae / t3-mesh (Node 24+).
 *
 * Configuration via env:
 *   SLACK_APP_TOKEN_FILE or SLACK_APP_TOKEN  - xapp-... Socket Mode token
 *   SLACK_BOT_TOKEN_FILE or SLACK_BOT_TOKEN  - xoxb-... Bot User OAuth token
 *   SLACK_TARGET                             - Target name (defaults to first target in hello)
 *   SLACK_ALLOWED_USERS                      - Optional comma-separated Slack user IDs allowlist
 *   SLACK_ALLOWED_CHANNELS                   - Optional comma-separated channel IDs allowlist
 */
import { readFileSync } from "node:fs";
import { MeshPluginClient } from "../sdk/client.mjs";

function readSecret(fileEnv, valEnv) {
  const file = process.env[fileEnv];
  if (file) return readFileSync(file, "utf8").trim();
  const value = process.env[valEnv]?.trim();
  if (value) return value;
  throw new Error(`Set ${fileEnv} (recommended, 0600 file) or ${valEnv}`);
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

if (!allowedUsers && !allowedChannels && !allowAll) {
  throw new Error("Refusing to start Slack bridge without SLACK_ALLOWED_USERS or SLACK_ALLOWED_CHANNELS (set SLACK_ALLOW_ALL=1 to explicitly allow any workspace member)");
}

const mesh = new MeshPluginClient({
  onDeliveryFailed: (msg) => console.error(`slack plugin delivery_failed target=${msg.target} reason=${msg.reason}`),
});
const hello = await mesh.ready;
const target = process.env.SLACK_TARGET ?? hello.targets[0];
if (!target || !hello.targets.includes(target)) {
  throw new Error(`Target '${target}' not in configured targets: ${hello.targets.join(", ")}`);
}

async function slackApi(method, token) {
  const res = await fetch(`https://slack.com/api/${method}`, {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json; charset=utf-8" },
  });
  const body = await res.json();
  if (!body.ok) throw new Error(`Slack ${method} failed: ${body.error ?? res.status}`);
  return body;
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
