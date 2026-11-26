#!/usr/bin/env node
/**
 * Zero-dependency Gmail event source for Hyphae (Node 24+).
 *
 * Outbound only: polls Gmail's history API with the user's own OAuth refresh token, so it
 * needs no public URL and no Cloud Pub/Sub topic, and no third party sits between Google
 * and this node. Each new message becomes one CloudEvent with sender, subject and Gmail's
 * short snippet. Message bodies are never fetched.
 *
 * One-time consent (run where a browser can reach the loopback port):
 *   node ../sdk/google-oauth.mjs auth --client-file <client_secret.json> --scopes gmail
 *
 * Configuration via env:
 *   GOOGLE_CLIENT_ID          - OAuth client ID (Desktop app) (required)
 *   GOOGLE_CLIENT_SECRET      - OAuth client secret, when the client has one
 *   GOOGLE_REFRESH_TOKEN / GOOGLE_REFRESH_TOKEN_FILE - Refresh token from the consent step (required)
 *   GMAIL_LABELS              - Comma-separated label IDs to watch (default INBOX)
 *   GMAIL_POLL_SECONDS        - Poll interval (default 60, min 20)
 *   GMAIL_PREVIEW_CHARS       - Max snippet characters per event (default 200; 0 = metadata only)
 *   GMAIL_API_BASE            - API base (default https://gmail.googleapis.com)
 *   GMAIL_STATE_FILE          - Cursor file (defaults to $HYPHAE_STATE_DIR/gmail-state.json)
 *   GMAIL_TARGET              - Target name (defaults to first target in hello)
 */
import { googleAccessTokenProvider } from "../sdk/google-oauth.mjs";
import {
  boundKeys, clip, connectSource, envInt, envList, fetchJson, HttpError, pollForever, resolveBaseUrl, StateFile,
} from "../sdk/source-kit.mjs";

const accessToken = googleAccessTokenProvider();
const apiBase = resolveBaseUrl("GMAIL_API_BASE", "https://gmail.googleapis.com");
const labels = envList("GMAIL_LABELS");
if (labels.length === 0) labels.push("INBOX");
for (const label of labels) if (!/^[A-Za-z0-9_-]{1,100}$/.test(label)) throw new Error(`GMAIL_LABELS has an invalid label ID '${label}'`);
const intervalMs = envInt("GMAIL_POLL_SECONDS", 60, { min: 20, max: 3600 }) * 1000;
const previewChars = envInt("GMAIL_PREVIEW_CHARS", 200, { max: 1000 });
const state = new StateFile("GMAIL", "gmail-state.json");
const { target, publish } = await connectSource("GMAIL", "gmail");

const users = `${apiBase}/gmail/v1/users/me`;
const api = async (path) => fetchJson(`${users}${path}`, { headers: { authorization: `Bearer ${await accessToken()}` } });

let account = "";
async function baseline() {
  const profile = await api("/profile");
  if (typeof profile?.historyId !== "string" && typeof profile?.historyId !== "number") throw new Error("unexpected profile response");
  account = clip(profile.emailAddress ?? "", 320);
  return String(profile.historyId);
}

const header = (message, name) => {
  const found = (message.payload?.headers ?? []).find((h) => typeof h?.name === "string" && h.name.toLowerCase() === name);
  return typeof found?.value === "string" ? found.value : "";
};

async function newMessageIds(label, startHistoryId) {
  const ids = [];
  let latest = startHistoryId;
  let pageToken = "";
  for (let page = 0; page < 20; page += 1) {
    const params = new URLSearchParams({ startHistoryId, historyTypes: "messageAdded", labelId: label, maxResults: "100" });
    if (pageToken) params.set("pageToken", pageToken);
    const body = await api(`/history?${params}`);
    for (const record of Array.isArray(body?.history) ? body.history : []) {
      for (const added of Array.isArray(record?.messagesAdded) ? record.messagesAdded : []) {
        const message = added?.message;
        if (!message || typeof message.id !== "string") continue;
        const labelIds = Array.isArray(message.labelIds) ? message.labelIds : [];
        if (labelIds.includes("DRAFT") || (labelIds.includes("SENT") && !labelIds.includes("INBOX"))) continue;
        ids.push(message.id);
      }
    }
    if (body?.historyId !== undefined) latest = String(body.historyId);
    if (typeof body?.nextPageToken !== "string" || !body.nextPageToken) break;
    pageToken = body.nextPageToken;
  }
  return { ids, latest };
}

if (typeof state.data.historyId !== "string") {
  // First run starts at the mailbox's current position: existing mail is never replayed.
  state.data = { historyId: await baseline(), seen: {} };
  state.save();
} else {
  await baseline();
}
if (!state.data.seen || typeof state.data.seen !== "object") state.data.seen = {};
console.error(`gmail plugin polling ${labels.join(", ")} every ${intervalMs / 1000}s -> target ${target}`);

await pollForever("gmail", intervalMs, async () => {
  const ids = new Set();
  let latest = state.data.historyId;
  try {
    for (const label of labels) {
      const result = await newMessageIds(label, state.data.historyId);
      for (const id of result.ids) ids.add(id);
      if (BigInt(result.latest) > BigInt(latest)) latest = result.latest;
    }
  } catch (error) {
    if (error instanceof HttpError && error.status === 404) {
      // Gmail keeps history for about a week. After a longer gap the cursor is gone, so the
      // plugin re-baselines at "now" and says so instead of replaying or failing forever.
      state.data.historyId = await baseline();
      state.save();
      console.error("gmail plugin history cursor expired; resumed from the current mailbox position (mail received during the gap was not delivered)");
      return;
    }
    throw error;
  }
  for (const id of ids) {
    if (state.data.seen[id]) continue;
    let message;
    try {
      message = await api(`/messages/${encodeURIComponent(id)}?format=metadata&metadataHeaders=From&metadataHeaders=To&metadataHeaders=Subject&metadataHeaders=Date`);
    } catch (error) {
      if (error instanceof HttpError && error.status === 404) continue; // deleted before we looked
      throw error;
    }
    const internalMs = Number(message.internalDate);
    await publish({
      id: `gmail:${account}:${id}`,
      source: `gmail/${account || "me"}`,
      type: "com.google.gmail.message.received",
      subject: clip(`${message.threadId ?? ""}/${id}`, 256),
      time: Number.isFinite(internalMs) && internalMs > 0 ? new Date(internalMs).toISOString() : new Date().toISOString(),
      data: {
        account: account || null,
        message_id: id,
        thread_id: clip(message.threadId ?? "", 64) || null,
        from: clip(header(message, "from"), 320),
        to: clip(header(message, "to"), 500),
        subject: clip(header(message, "subject"), 300),
        preview: clip(message.snippet ?? "", previewChars),
        labels: (Array.isArray(message.labelIds) ? message.labelIds : []).filter((l) => typeof l === "string").slice(0, 30),
        unread: Array.isArray(message.labelIds) ? message.labelIds.includes("UNREAD") : null,
        size: Number.isFinite(message.sizeEstimate) ? message.sizeEstimate : null,
      },
    });
    state.data.seen[id] = 1;
    boundKeys(state.data.seen, 500);
    state.save();
  }
  if (latest !== state.data.historyId) {
    state.data.historyId = latest;
    state.save();
  }
});
