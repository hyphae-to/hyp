import { createHash } from "node:crypto";
import { closeSync, mkdirSync, openSync } from "node:fs";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";

const timestamp = (s) => typeof s === "string" && /^\d{1,16}\.\d{1,10}$/.test(s);
const text = (s, max) => typeof s === "string" && s.length > 0 && s.length <= max;
const escapeSlack = (s) => s.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");

// Only provider identifiers and progress are kept. A redelivery supplies the original payload.
export function openSlackState(stateDir, team, bot, target) {
  let path = ":memory:";
  if (stateDir) {
    const location = join(stateDir, "slack");
    mkdirSync(location, { mode: 0o700, recursive: true });
    const binding = createHash("sha256").update(JSON.stringify([team, bot, target])).digest("hex");
    path = join(location, binding + ".sqlite");
    closeSync(openSync(path, "a", 0o600));
  }
  const db = new DatabaseSync(path);
  db.exec(`CREATE TABLE IF NOT EXISTS clicks (
    channel TEXT NOT NULL, ts TEXT NOT NULL, winner TEXT NOT NULL, phase TEXT NOT NULL,
    PRIMARY KEY(channel,ts)
  )`);
  return db;
}

function originalChoice(payload, action) {
  const block = payload.message.blocks.find((b) => b?.block_id === action.block_id);
  const elements = block?.type === "actions" && Array.isArray(block.elements) ? block.elements : [block?.accessory];
  const element = elements.find((el) => el?.type === action.type && el?.action_id === action.action_id);
  if (!element || element.url || action.url) return null;
  const selection = action.type === "static_select" ? action.selected_option : action;
  const value = selection?.value ?? "";
  let original = element;
  if (action.type === "static_select") {
    const options = element.options ?? element.option_groups?.flatMap((g) => g.options);
    original = Array.isArray(options) && options.find((option) => option?.value === value);
    if (!original) return null;
  } else if ((element.value ?? "") !== value) return null;
  const label = original.text?.text ?? selection?.text?.text ?? value;
  if (!text(label, 2000) || typeof value !== "string" || value.length > 2000) return null;
  return { value, label };
}

function recordedBlocks(blocks, label, user) {
  const kept = blocks.filter((block) => block.type !== "actions").map((block) => {
    if (!block.accessory?.action_id) return block;
    const { accessory: _control, ...rest } = block;
    return rest;
  });
  return [...kept, { type: "context", elements: [
    { type: "mrkdwn", text: `:white_check_mark: *${escapeSlack(label)}*, chosen by <@${user}>` },
  ] }];
}

export function slackChoiceHandler({ team, bot, botId, state, sender, update, send, redactInboundData }) {
  const active = new Map();
  return async function handle(payload) {
    if (payload?.type !== "block_actions" || !team || payload.team?.id !== team || !bot ||
        !(payload.message?.user === bot || (botId && payload.message?.bot_id === botId)) || payload.container?.type !== "message" ||
        !Array.isArray(payload.actions) || payload.actions.length !== 1 || !Array.isArray(payload.message.blocks)) return;
    const user = payload.user?.id;
    const channel = payload.channel?.id;
    const ts = payload.message.ts;
    const action = payload.actions[0];
    if (!text(user, 64) || !/^[UW][A-Z0-9]+$/.test(user) || user === bot ||
        !text(channel, 64) || !/^[CGD][A-Z0-9]+$/.test(channel) || channel !== payload.container.channel_id ||
        !timestamp(ts) || ts !== payload.container.message_ts || !timestamp(action?.action_ts) ||
        !["button", "static_select"].includes(action.type) || !text(action.action_id, 255) || !text(action.block_id, 255)) return;
    const person = sender(user, channel);
    if (!person) return;
    const choice = originalChoice(payload, action);
    if (!choice) return;
    const db = state();
    const key = channel + ":" + ts;
    if (active.has(key)) return active.get(key);
    const actionTs = action.action_ts;
    const winner = createHash("sha256")
      .update(JSON.stringify([actionTs, user, action.block_id, action.action_id, choice.value, choice.label]))
      .digest("hex");
    db.prepare("INSERT OR IGNORE INTO clicks VALUES (?, ?, ?, 'pending')").run(channel, ts, winner);
    const record = db.prepare("SELECT phase,winner FROM clicks WHERE channel=? AND ts=?").get(channel, ts);
    if (record.winner !== winner || record.phase === "sent") return;
    const work = (async () => {
      const data = redactInboundData({ ...person, user, channel, channel_type: channel.startsWith("D") ? "dm" : "channel",
        via: "action", ts, thread_ts: timestamp(payload.message.thread_ts) ? payload.message.thread_ts : "-",
        action_id: action.action_id, label: choice.label, value: choice.value,
        text: `[clicked] ${choice.label} (action_id=${action.action_id}, value=${choice.value})`,
      });
      if (record.phase === "pending") {
        const { secret_removed: _secretRemoved, ...message } = redactInboundData({
          channel, ts, text: payload.message.text ?? "", blocks: recordedBlocks(payload.message.blocks, data.label, user),
        });
        await update(message);
        db.prepare("UPDATE clicks SET phase='updated' WHERE channel=? AND ts=?").run(channel, ts);
      }
      await send({ specversion: "1.0", id: `choice-${channel}-${ts}-${actionTs}`, source: `slack/${team}`,
        type: "com.slack.block.action", subject: `${channel}/${ts}`, datacontenttype: "application/json", data });
      db.prepare("UPDATE clicks SET phase='sent' WHERE channel=? AND ts=?").run(channel, ts);
    })();
    active.set(key, work);
    try { await work; } finally { active.delete(key); }
  };
}
