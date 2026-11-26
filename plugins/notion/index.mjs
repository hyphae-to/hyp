#!/usr/bin/env node
/**
 * Zero-dependency Notion event source for Hyphae (Node 24+).
 *
 * Two transports, chosen with NOTION_MODE:
 *   poll (default) - outbound only. Polls the search API for pages the integration can see,
 *                    newest edit first, and emits page.created / page.updated events.
 *   webhook        - receives Notion integration webhooks (pages, databases, comments) on a
 *                    local port. Use on a hub or behind a tunnel.
 *
 * Events carry IDs, titles and URLs only. Page content stays in Notion.
 *
 * Configuration via env:
 *   NOTION_MODE             - "poll" (default) or "webhook"
 *   NOTION_TARGET           - Target name (defaults to first target in hello)
 *  poll:
 *   NOTION_TOKEN / _FILE    - Internal integration token (required)
 *   NOTION_POLL_SECONDS     - Poll interval (default 60, min 20)
 *   NOTION_VERSION          - Notion-Version header (default 2022-06-28)
 *   NOTION_API_BASE         - API base (default https://api.notion.com)
 *   NOTION_STATE_FILE       - State file (defaults to $HYPHAE_STATE_DIR/notion-state.json)
 *  webhook:
 *   NOTION_VERIFICATION_TOKEN / _FILE - Subscription verification token used to verify X-Notion-Signature.
 *                             When unset, the plugin starts in setup mode: it accepts Notion's one-time
 *                             verification request, saves the token to NOTION_VERIFICATION_TOKEN_FILE
 *                             (default $HYPHAE_STATE_DIR/notion-verification-token, 0600) and publishes
 *                             nothing until that token exists.
 *   NOTION_WEBHOOK_HOST / NOTION_WEBHOOK_PORT / NOTION_WEBHOOK_PATH - default 127.0.0.1:8798/notion
 *   NOTION_WEBHOOK_FUNNEL         - 443, 8443 or 10000: publish this path through Tailscale Funnel on that port and log the public URL
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import {
  boundKeys, clip, connectSource, envInt, envString, fetchJson, hmacHex, pollForever, requireSecretEnv,
  resolveBaseUrl, safeEqual, StateFile, startWebhookServer,
} from "../sdk/source-kit.mjs";

const mode = envString("NOTION_MODE", "poll");
if (mode !== "poll" && mode !== "webhook") throw new Error(`NOTION_MODE must be 'poll' or 'webhook' (got '${mode}')`);

function pageTitle(page) {
  const props = page.properties && typeof page.properties === "object" ? Object.values(page.properties) : [];
  const title = props.find((p) => p && p.type === "title" && Array.isArray(p.title));
  return clip((title?.title ?? []).map((t) => (typeof t?.plain_text === "string" ? t.plain_text : "")).join(""), 300);
}

function parentOf(parent) {
  if (!parent || typeof parent !== "object") return { parent_type: null, parent_id: null };
  const type = clip(parent.type ?? "", 40);
  const id = parent[type] ?? parent.id ?? null;
  return { parent_type: type || null, parent_id: typeof id === "string" ? clip(id, 64) : null };
}

if (mode === "poll") {
  const token = requireSecretEnv("NOTION_TOKEN");
  const apiBase = resolveBaseUrl("NOTION_API_BASE", "https://api.notion.com");
  const version = envString("NOTION_VERSION", "2022-06-28");
  if (!/^\d{4}-\d{2}-\d{2}$/.test(version)) throw new Error("NOTION_VERSION must look like 2022-06-28");
  const intervalMs = envInt("NOTION_POLL_SECONDS", 60, { min: 20, max: 3600 }) * 1000;
  const state = new StateFile("NOTION", "notion-state.json");
  const { target, publish } = await connectSource("NOTION", "notion");

  if (typeof state.data.cursor !== "string" || Number.isNaN(Date.parse(state.data.cursor))) {
    state.data = { cursor: new Date().toISOString(), seen: {} };
    state.save();
  }
  if (!state.data.seen || typeof state.data.seen !== "object") state.data.seen = {};
  console.error(`notion plugin polling every ${intervalMs / 1000}s -> target ${target}`);

  const headers = { authorization: `Bearer ${token}`, "notion-version": version };

  await pollForever("notion", intervalMs, async () => {
    // Notion rounds last_edited_time to the minute, so the cursor comparison is inclusive and
    // `seen` (page id -> last emitted edit time) removes the repeats that inclusiveness returns.
    const cursorMs = Date.parse(state.data.cursor);
    const changed = [];
    let startCursor;
    for (let page = 0; page < 5; page += 1) {
      const body = await fetchJson(`${apiBase}/v1/search`, {
        method: "POST",
        headers,
        body: {
          filter: { property: "object", value: "page" },
          sort: { timestamp: "last_edited_time", direction: "descending" },
          page_size: 50,
          ...(startCursor ? { start_cursor: startCursor } : {}),
        },
      });
      const results = Array.isArray(body?.results) ? body.results : null;
      if (!results) throw new Error("unexpected search response");
      let reachedOld = false;
      for (const item of results) {
        const editedMs = Date.parse(item?.last_edited_time ?? "");
        if (!item || item.object !== "page" || typeof item.id !== "string" || Number.isNaN(editedMs)) continue;
        if (editedMs < cursorMs) {
          reachedOld = true;
          break;
        }
        if (state.data.seen[item.id] !== item.last_edited_time) changed.push(item);
      }
      if (reachedOld || !body.has_more || typeof body.next_cursor !== "string") break;
      startCursor = body.next_cursor;
    }
    changed.sort((a, b) => Date.parse(a.last_edited_time) - Date.parse(b.last_edited_time));
    for (const item of changed) {
      const created = Date.parse(item.created_time ?? "") >= cursorMs && state.data.seen[item.id] === undefined;
      const action = item.in_trash || item.archived || item.is_archived ? "deleted" : created ? "created" : "updated";
      await publish({
        id: `notion:${item.id}:${item.last_edited_time}`,
        source: "notion/workspace",
        type: `so.notion.page.${action}`,
        subject: item.id,
        time: new Date(Date.parse(item.last_edited_time)).toISOString(),
        data: {
          action,
          entity_type: "page",
          page_id: item.id,
          title: pageTitle(item),
          url: clip(item.url ?? "", 500) || null,
          created_time: item.created_time ?? null,
          last_edited_time: item.last_edited_time,
          edited_by: clip(item.last_edited_by?.id ?? "", 64) || null,
          ...parentOf(item.parent),
        },
      });
      state.data.seen[item.id] = item.last_edited_time;
      boundKeys(state.data.seen, 1000);
      state.data.cursor = item.last_edited_time;
      state.save();
    }
  });
} else {
  const tokenFile =
    envString("NOTION_VERIFICATION_TOKEN_FILE") ||
    (process.env.HYPHAE_STATE_DIR ? join(process.env.HYPHAE_STATE_DIR, "notion-verification-token") : "");
  let secret = envString("NOTION_VERIFICATION_TOKEN");
  if (!secret && tokenFile && existsSync(tokenFile)) secret = readFileSync(tokenFile, "utf8").trim();
  if (!secret && !tokenFile) {
    throw new Error("Set NOTION_VERIFICATION_TOKEN, or NOTION_VERIFICATION_TOKEN_FILE / HYPHAE_STATE_DIR so setup mode can save Notion's verification token");
  }
  const { target, publish } = await connectSource("NOTION", "notion");
  const TYPE = /^[a-z_]+(\.[a-z_]+){1,4}$/;
  if (!secret) console.error(`notion plugin in setup mode: waiting for Notion's verification request (token will be saved to ${tokenFile})`);

  await startWebhookServer({
    prefix: "NOTION",
    name: "notion",
    defaultPort: 8798,
    defaultPath: "/notion",
    // Setup handshake: only honoured while no token is known, so it cannot replace a pinned secret.
    preVerify: (raw, body) => {
      if (secret) return false;
      const keys = Object.keys(body);
      const candidate = body.verification_token;
      if (keys.length !== 1 || typeof candidate !== "string" || !/^[A-Za-z0-9_-]{16,256}$/.test(candidate)) return false;
      mkdirSync(dirname(tokenFile), { recursive: true, mode: 0o700 });
      writeFileSync(tokenFile, candidate + "\n", { mode: 0o600 });
      secret = candidate;
      console.error(`notion plugin saved the verification token to ${tokenFile}; paste it into Notion's Verify dialog to activate the subscription`);
      return true;
    },
    verify: (raw, headers) => secret !== "" && safeEqual(String(headers["x-notion-signature"] ?? "").trim().toLowerCase(), `sha256=${hmacHex("sha256", secret, raw)}`),
    handle: async (body) => {
      const type = String(body.type ?? "");
      const eventId = typeof body.id === "string" ? body.id : "";
      if (!TYPE.test(type) || !eventId) return "ignored";
      const entity = body.entity && typeof body.entity === "object" ? body.entity : {};
      const data = body.data && typeof body.data === "object" ? body.data : {};
      const parent = data.parent && typeof data.parent === "object" ? data.parent : {};
      const authors = Array.isArray(body.authors) ? body.authors : [];
      return publish({
        id: `notion:${clip(eventId, 100)}`,
        source: `notion/${clip(body.workspace_id ?? "workspace", 64)}`,
        type: `so.notion.${type}`,
        ...(entity.id ? { subject: clip(entity.id, 256) } : {}),
        time: !Number.isNaN(Date.parse(body.timestamp ?? "")) ? new Date(body.timestamp).toISOString() : new Date().toISOString(),
        data: {
          action: type.split(".").slice(1).join("."),
          entity_type: clip(entity.type ?? "", 40) || null,
          entity_id: clip(entity.id ?? "", 64) || null,
          page_id: entity.type === "page" ? clip(entity.id ?? "", 64) : clip(data.page_id ?? "", 64) || null,
          workspace_id: clip(body.workspace_id ?? "", 64) || null,
          workspace_name: clip(body.workspace_name ?? "", 200) || null,
          parent_type: clip(parent.type ?? "", 40) || null,
          parent_id: clip(parent.id ?? "", 64) || null,
          author_ids: authors.slice(0, 10).map((a) => clip(a?.id ?? "", 64)).filter(Boolean),
          author_type: clip(authors[0]?.type ?? "", 20) || null,
          attempt: Number.isFinite(body.attempt_number) ? body.attempt_number : null,
        },
      });
    },
  });
  console.error(`notion plugin webhook ready -> target ${target}`);
}
