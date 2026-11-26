#!/usr/bin/env node
/**
 * Zero-dependency AgentMail event source for Hyphae (Node 24+).
 *
 * Holds one outbound WebSocket to AgentMail, so it needs no public URL and
 * runs equally on a laptop behind NAT or on a hub. Each AgentMail event becomes
 * one CloudEvent carrying routing metadata and a short preview only; the full
 * body stays in AgentMail until an agent fetches it deliberately.
 *
 * A WebSocket has no replay, so every (re)connect also catches up over the REST
 * API: mail received since the last delivered message of each inbox is listed
 * and published. Received mail is keyed by message ID on both paths, so the node
 * drops anything that arrives twice. This covers reconnects, restarts and time
 * the machine spent asleep; the first run starts at "now" and replays nothing.
 *
 * Configuration via env:
 *   AGENTMAIL_API_KEY / AGENTMAIL_API_KEY_FILE  - AgentMail API key (required)
 *   AGENTMAIL_INBOXES        - Comma-separated inbox IDs to subscribe to (default: all the key can read)
 *   AGENTMAIL_PODS           - Comma-separated pod IDs to subscribe to
 *   AGENTMAIL_EVENT_TYPES    - Comma-separated event types (default: message.received)
 *   AGENTMAIL_PREVIEW_CHARS  - Max preview characters per event (default 280; 0 = metadata only)
 *   AGENTMAIL_CATCH_UP       - "0" disables the REST catch-up (default on)
 *   AGENTMAIL_WS_URL         - WebSocket endpoint (default wss://ws.agentmail.to/v0; EU: wss://ws.agentmail.eu/v0)
 *   AGENTMAIL_API_BASE       - REST endpoint (default https://api.agentmail.to; EU: https://api.agentmail.eu)
 *   AGENTMAIL_STATE_FILE     - Cursor file (defaults to $HYPHAE_STATE_DIR/agentmail-state.json)
 *   AGENTMAIL_TARGET         - Target name (defaults to first target in hello)
 */
import {
  boundKeys, clip, connectSource, envInt, envList, envString, fetchJson, requireSecretEnv, resolveBaseUrl, sleep, StateFile,
} from "../sdk/source-kit.mjs";

const apiKey = requireSecretEnv("AGENTMAIL_API_KEY");
const wsBase = resolveBaseUrl("AGENTMAIL_WS_URL", "wss://ws.agentmail.to/v0", { websocket: true });
const apiBase = resolveBaseUrl("AGENTMAIL_API_BASE", "https://api.agentmail.to");
const inboxIds = envList("AGENTMAIL_INBOXES");
const podIds = envList("AGENTMAIL_PODS");
const eventTypes = envList("AGENTMAIL_EVENT_TYPES");
if (eventTypes.length === 0) eventTypes.push("message.received");
for (const type of eventTypes) {
  if (!/^[a-z][a-z0-9_.]{2,63}$/.test(type)) throw new Error(`AGENTMAIL_EVENT_TYPES has an invalid event type '${type}'`);
}
const previewChars = envInt("AGENTMAIL_PREVIEW_CHARS", 280, { max: 4000 });
const catchUpEnabled = envString("AGENTMAIL_CATCH_UP", "1") !== "0" && eventTypes.includes("message.received");
const state = new StateFile("AGENTMAIL", "agentmail-state.json");
if (!state.data.cursors || typeof state.data.cursors !== "object") state.data.cursors = {};
// Message IDs already delivered at exactly the cursor timestamp. AgentMail's `after` filter includes
// the cursor instant itself, so without this every reconnect would re-list the last delivered message.
if (!state.data.atCursor || typeof state.data.atCursor !== "object") state.data.atCursor = {};

const { target, publish } = await connectSource("AGENTMAIL", "agentmail");

const strings = (value, max = 20) => (Array.isArray(value) ? value.filter((v) => typeof v === "string").slice(0, max).map((v) => clip(v, 320)) : []);
const isoOrNull = (value) => (typeof value === "string" && !Number.isNaN(Date.parse(value)) ? new Date(value).toISOString() : null);

/** One CloudEvent for a message. Received mail is keyed by message ID so live and catch-up copies dedupe. */
function messageEvent(eventType, message, { eventId = null, replayed = false } = {}) {
  const inboxId = clip(message.inbox_id ?? "", 320);
  const messageId = typeof message.message_id === "string" ? clip(message.message_id, 320) : "";
  const stableId = eventType === "message.received" && inboxId && messageId ? `agentmail:${inboxId}:${messageId}` : eventId;
  if (!stableId) return null;
  return {
    id: clip(stableId, 700),
    source: `agentmail/${inboxId || "account"}`,
    type: `to.agentmail.${eventType}`,
    ...(message.thread_id ? { subject: clip(`${message.thread_id}/${messageId}`, 256) } : {}),
    time: isoOrNull(message.timestamp) ?? new Date().toISOString(),
    data: {
      event_type: eventType,
      event_id: eventId ? clip(eventId, 200) : null,
      inbox_id: inboxId || null,
      thread_id: message.thread_id ? clip(message.thread_id, 200) : null,
      message_id: messageId || null,
      from: typeof message.from === "string" ? clip(message.from, 320) : null,
      to: strings(message.to),
      cc: strings(message.cc),
      subject: clip(message.subject ?? "", 300),
      preview: clip(message.preview ?? message.extracted_text ?? message.text ?? "", previewChars),
      labels: strings(message.labels, 50),
      attachments: Array.isArray(message.attachments) ? message.attachments.length : 0,
      size: Number.isFinite(message.size) ? message.size : null,
      replayed,
    },
  };
}

/** Records `messageId` as delivered and moves the inbox cursor forward to `timestamp` (never backwards). */
function advanceCursor(inboxId, timestamp, messageId = "") {
  const iso = isoOrNull(timestamp);
  if (!inboxId || !iso) return;
  const current = state.data.cursors[inboxId];
  const delta = current ? Date.parse(iso) - Date.parse(current) : 1;
  if (delta < 0) return;
  if (delta > 0) {
    state.data.cursors[inboxId] = iso;
    state.data.atCursor[inboxId] = [];
    boundKeys(state.data.cursors, 500);
    boundKeys(state.data.atCursor, 500);
  }
  const ids = Array.isArray(state.data.atCursor[inboxId]) ? state.data.atCursor[inboxId] : (state.data.atCursor[inboxId] = []);
  if (messageId && !ids.includes(messageId)) ids.push(messageId);
  if (ids.length > 200) ids.splice(0, ids.length - 200);
  state.save();
}

/** True when the catch-up listing returned a message this plugin already delivered. */
function alreadyDelivered(inboxId, message) {
  const cursor = state.data.cursors[inboxId];
  const at = Date.parse(message.timestamp ?? "");
  if (!cursor || Number.isNaN(at)) return false;
  if (at < Date.parse(cursor)) return true;
  return at === Date.parse(cursor) && (state.data.atCursor[inboxId] ?? []).includes(message.message_id);
}

// Every publish, live or catch-up, runs through one queue so events reach the node in order and a
// failed publish never lets a later one advance the cursor past it.
let queue = Promise.resolve();
const enqueue = (task) => {
  const run = queue.then(task);
  queue = run.catch(() => {});
  return run;
};

const rest = (path) => fetchJson(`${apiBase}${path}`, { headers: { authorization: `Bearer ${apiKey}` } });

async function watchedInboxes() {
  if (inboxIds.length > 0) return inboxIds;
  const found = [];
  let pageToken = "";
  for (let page = 0; page < 10; page += 1) {
    const params = new URLSearchParams({ limit: "100" });
    if (pageToken) params.set("page_token", pageToken);
    const body = await rest(`/v0/inboxes?${params}`);
    for (const inbox of Array.isArray(body?.inboxes) ? body.inboxes : []) {
      if (typeof inbox?.inbox_id === "string" && inbox.status !== "deactivated") found.push(inbox.inbox_id);
    }
    if (typeof body?.next_page_token !== "string" || !body.next_page_token) break;
    pageToken = body.next_page_token;
  }
  return found;
}

/** Publishes mail each inbox received after its cursor, oldest first. Returns how many were new to the node. */
async function catchUp() {
  let delivered = 0;
  for (const inboxId of await watchedInboxes()) {
    if (!state.data.cursors[inboxId]) {
      // First sight of this inbox: start at "now" so existing mail is never replayed.
      advanceCursor(inboxId, new Date().toISOString());
      continue;
    }
    let pageToken = "";
    for (let page = 0; page < 20; page += 1) {
      const params = new URLSearchParams({ after: state.data.cursors[inboxId], ascending: "true", limit: "100", labels: "received" });
      if (pageToken) params.set("page_token", pageToken);
      const body = await rest(`/v0/inboxes/${encodeURIComponent(inboxId)}/messages?${params}`);
      for (const message of Array.isArray(body?.messages) ? body.messages : []) {
        if (!message || typeof message.message_id !== "string") continue;
        const labels = Array.isArray(message.labels) ? message.labels : [];
        if (!labels.includes("received") || alreadyDelivered(inboxId, message)) continue;
        const event = messageEvent("message.received", { ...message, inbox_id: message.inbox_id ?? inboxId }, { replayed: true });
        if (!event) continue;
        const status = await enqueue(() => publish(event));
        if (status === "stored") delivered += 1;
        advanceCursor(inboxId, message.timestamp, message.message_id);
      }
      if (typeof body?.next_page_token !== "string" || !body.next_page_token) break;
      pageToken = body.next_page_token;
    }
  }
  return delivered;
}

/** One connection lifetime; resolves when the socket closes for any reason. */
function runSocket() {
  return new Promise((resolve) => {
    const ws = new WebSocket(`${wsBase}?api_key=${encodeURIComponent(apiKey)}`);
    // After one failed publish nothing else from this connection is published: later events must
    // not move the cursor past the one that failed. The reconnect's catch-up redelivers them all.
    let failed = false;
    // While the catch-up is listing missed mail, live mail must not move the cursor: it would jump
    // past messages the catch-up has not published yet. Live advances are held and applied only
    // once the catch-up has finished; if it fails they are dropped and the connection is recycled,
    // so the next catch-up starts again from the unchanged cursor.
    let cursorFrozen = false;
    const held = [];
    ws.addEventListener("open", () => {
      ws.send(JSON.stringify({
        type: "subscribe",
        event_types: eventTypes,
        ...(inboxIds.length > 0 ? { inbox_ids: inboxIds } : {}),
        ...(podIds.length > 0 ? { pod_ids: podIds } : {}),
      }));
    });
    ws.addEventListener("message", (msg) => {
      if (typeof msg.data !== "string") return;
      let frame;
      try {
        frame = JSON.parse(msg.data);
      } catch {
        return;
      }
      if (frame?.type === "subscribed") {
        console.error(`agentmail plugin subscribed (${eventTypes.join(", ")}) -> target ${target}`);
        // Catch up only once the live subscription is confirmed, so nothing can fall between the two.
        if (catchUpEnabled) {
          cursorFrozen = true;
          catchUp()
            .then((count) => {
              if (count > 0) console.error(`agentmail plugin caught up on ${count} message(s) received while disconnected`);
              cursorFrozen = false;
              for (const [inboxId, timestamp, messageId] of held.splice(0)) advanceCursor(inboxId, timestamp, messageId);
            })
            .catch((error) => {
              console.error(`agentmail plugin catch-up failed (reconnecting to retry): ${error instanceof Error ? error.message : String(error)}`);
              ws.close();
            });
        }
      } else if (frame?.type === "error") {
        console.error(`agentmail plugin server error: ${clip(frame.name ?? "", 80)} ${clip(frame.message ?? "", 200)}`);
      } else if (frame?.type === "event") {
        const eventType = typeof frame.event_type === "string" ? frame.event_type : "";
        const eventId = typeof frame.event_id === "string" ? frame.event_id : "";
        const message = frame.message && typeof frame.message === "object" ? frame.message : {};
        if (!eventId || !/^[a-z][a-z0-9_.]{2,63}$/.test(eventType)) return;
        const event = messageEvent(eventType, message, { eventId });
        if (!event) return;
        enqueue(async () => {
          if (failed) return;
          try {
            await publish(event);
          } catch (error) {
            // Set inside the queued task, so the very next queued event already sees it.
            failed = true;
            console.error(`agentmail plugin publish failed: ${error instanceof Error ? error.message : String(error)}`);
            ws.close();
            return;
          }
          if (eventType !== "message.received") return;
          if (cursorFrozen) held.push([event.data.inbox_id, message.timestamp, event.data.message_id]);
          else advanceCursor(event.data.inbox_id, message.timestamp, event.data.message_id);
        });
      }
    });
    ws.addEventListener("error", () => {
      // The error event carries no safe detail (the URL holds the API key); close handles reconnection.
    });
    ws.addEventListener("close", (event) => resolve(event.code));
  });
}

let backoff = 1000;
while (true) {
  const started = Date.now();
  const code = await runSocket();
  if (Date.now() - started > 60_000) backoff = 1000;
  console.error(`agentmail plugin socket closed (code ${code}); reconnecting in ${Math.round(backoff / 1000)}s`);
  if (Date.now() - started < 5_000) {
    // A socket that dies during the handshake gives no reason. Ask the REST API the same question
    // with the same key, so the log says whether the key or an inbox was refused (status and
    // AgentMail's short message only; never the key).
    const probe = inboxIds.length > 0 ? `/v0/inboxes/${encodeURIComponent(inboxIds[0])}` : "/v0/inboxes?limit=1";
    try {
      await rest(probe);
      console.error("agentmail plugin: the REST API accepts this key, so the WebSocket endpoint itself is refusing the connection (check AGENTMAIL_WS_URL matches the account's region)");
    } catch (error) {
      console.error(`agentmail plugin: AgentMail refused the key or inbox over REST too: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  await sleep(backoff);
  backoff = Math.min(backoff * 2, 60_000);
}
