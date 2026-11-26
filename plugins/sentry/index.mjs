#!/usr/bin/env node
/**
 * Zero-dependency Sentry event source for Hyphae (Node 24+).
 *
 * Two transports, chosen with SENTRY_MODE:
 *   poll (default) - outbound only. Polls the organization issues API and emits one event per
 *                    newly seen issue. Works behind NAT and on a hub alike.
 *   webhook        - receives Sentry internal-integration webhooks (issues, errors, issue and
 *                    metric alerts, comments) on a local port. Use on a hub or behind a tunnel.
 *
 * Configuration via env:
 *   SENTRY_MODE               - "poll" (default) or "webhook"
 *   SENTRY_TARGET             - Target name (defaults to first target in hello)
 *  poll:
 *   SENTRY_AUTH_TOKEN / _FILE - Auth token with event:read (required)
 *   SENTRY_ORG                - Organization slug (required)
 *   SENTRY_PROJECTS           - Comma-separated project slugs or IDs (default: all accessible)
 *   SENTRY_ENVIRONMENTS       - Comma-separated environment names
 *   SENTRY_QUERY              - Issue search query (default: is:unresolved)
 *   SENTRY_POLL_SECONDS       - Poll interval (default 60, min 15)
 *   SENTRY_API_BASE           - API base (default https://sentry.io; e.g. https://de.sentry.io or self-hosted)
 *   SENTRY_STATE_FILE         - Cursor file (defaults to $HYPHAE_STATE_DIR/sentry-state.json)
 *  webhook:
 *   SENTRY_CLIENT_SECRET / _FILE - Integration Client Secret used to verify Sentry-Hook-Signature (required)
 *   SENTRY_WEBHOOK_HOST / SENTRY_WEBHOOK_PORT / SENTRY_WEBHOOK_PATH - default 127.0.0.1:8796/sentry
 *   SENTRY_WEBHOOK_FUNNEL         - 443, 8443 or 10000: publish this path through Tailscale Funnel on that port and log the public URL
 */
import {
  boundKeys, clip, connectSource, envInt, envList, envString, fetchJson, hmacHex, pollForever, requireSecretEnv,
  resolveBaseUrl, safeEqual, sha256Hex, StateFile, startWebhookServer,
} from "../sdk/source-kit.mjs";

const mode = envString("SENTRY_MODE", "poll");
if (mode !== "poll" && mode !== "webhook") throw new Error(`SENTRY_MODE must be 'poll' or 'webhook' (got '${mode}')`);

const SLUG = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$/;

function issueData(issue, extra = {}) {
  const project = issue.project && typeof issue.project === "object" ? issue.project : {};
  return {
    issue_id: issue.id !== undefined ? String(issue.id) : null,
    short_id: issue.shortId ? clip(issue.shortId, 100) : null,
    title: clip(issue.title ?? issue.metadata?.title ?? "", 300),
    culprit: clip(issue.culprit ?? "", 300),
    level: clip(issue.level ?? "", 20) || null,
    status: clip(issue.status ?? "", 40) || null,
    substatus: clip(issue.substatus ?? "", 60) || null,
    project: clip(project.slug ?? "", 100) || null,
    platform: clip(issue.platform ?? project.platform ?? "", 40) || null,
    first_seen: issue.firstSeen ?? null,
    last_seen: issue.lastSeen ?? null,
    count: issue.count !== undefined ? Number(issue.count) || 0 : null,
    user_count: Number.isFinite(issue.userCount) ? issue.userCount : null,
    unhandled: typeof issue.isUnhandled === "boolean" ? issue.isUnhandled : null,
    url: clip(issue.permalink ?? issue.web_url ?? "", 500) || null,
    ...extra,
  };
}

if (mode === "poll") {
  const token = requireSecretEnv("SENTRY_AUTH_TOKEN");
  const org = envString("SENTRY_ORG");
  if (!SLUG.test(org)) throw new Error("Set SENTRY_ORG to your Sentry organization slug");
  const apiBase = resolveBaseUrl("SENTRY_API_BASE", "https://sentry.io");
  const projects = envList("SENTRY_PROJECTS");
  const environments = envList("SENTRY_ENVIRONMENTS");
  for (const value of projects) if (!SLUG.test(value)) throw new Error(`SENTRY_PROJECTS has an invalid project '${value}'`);
  const query = envString("SENTRY_QUERY", "is:unresolved");
  const intervalMs = envInt("SENTRY_POLL_SECONDS", 60, { min: 15, max: 3600 }) * 1000;
  const state = new StateFile("SENTRY", "sentry-state.json");
  const { target, publish } = await connectSource("SENTRY", "sentry");

  const params = new URLSearchParams({ query, sort: "new", limit: "50", statsPeriod: "14d" });
  for (const project of projects) params.append("project", project);
  for (const environment of environments) params.append("environment", environment);
  const url = `${apiBase}/api/0/organizations/${encodeURIComponent(org)}/issues/?${params}`;

  // First run baselines at "now": issues that already exist are not replayed into agent inboxes.
  if (typeof state.data.cursor !== "string" || Number.isNaN(Date.parse(state.data.cursor))) {
    state.data = { cursor: new Date().toISOString(), seen: {} };
    state.save();
  }
  if (!state.data.seen || typeof state.data.seen !== "object") state.data.seen = {};
  console.error(`sentry plugin polling ${org} every ${intervalMs / 1000}s -> target ${target}`);

  await pollForever("sentry", intervalMs, async () => {
    const issues = await fetchJson(url, { headers: { authorization: `Bearer ${token}` } });
    if (!Array.isArray(issues)) throw new Error("unexpected issues response");
    const cursorMs = Date.parse(state.data.cursor);
    const fresh = issues
      .filter((issue) => issue && typeof issue === "object" && issue.id !== undefined)
      .filter((issue) => Date.parse(issue.firstSeen ?? "") > cursorMs && !state.data.seen[String(issue.id)])
      .sort((a, b) => Date.parse(a.firstSeen) - Date.parse(b.firstSeen));
    for (const issue of fresh) {
      const project = clip(issue.project?.slug ?? "", 100);
      await publish({
        id: `sentry:${org}:issue:${issue.id}:created`,
        source: `sentry/${org}${project ? `/${project}` : ""}`,
        type: "io.sentry.issue.created",
        subject: clip(issue.shortId ?? String(issue.id), 256),
        time: new Date(Date.parse(issue.firstSeen)).toISOString(),
        data: issueData(issue, { resource: "issue", action: "created", org }),
      });
      state.data.seen[String(issue.id)] = 1;
      boundKeys(state.data.seen, 500);
      state.save();
    }
    if (fresh.length > 0) {
      // Keep a one-minute overlap: Sentry can surface an issue slightly after its firstSeen time,
      // and `seen` suppresses anything the overlap returns twice.
      state.data.cursor = new Date(Date.parse(fresh.at(-1).firstSeen) - 60_000).toISOString();
      state.save();
    }
  });
} else {
  const secret = requireSecretEnv("SENTRY_CLIENT_SECRET");
  const { target, publish } = await connectSource("SENTRY", "sentry");
  const RESOURCE = /^[a-z][a-z0-9_]{1,40}$/;

  await startWebhookServer({
    prefix: "SENTRY",
    name: "sentry",
    defaultPort: 8796,
    defaultPath: "/sentry",
    verify: (raw, headers) => safeEqual(String(headers["sentry-hook-signature"] ?? "").trim().toLowerCase(), hmacHex("sha256", secret, raw)),
    handle: async (body, raw, headers) => {
      const resource = String(headers["sentry-hook-resource"] ?? "").trim().toLowerCase();
      if (!RESOURCE.test(resource)) return "ignored";
      if (resource === "installation") return "ignored";
      const action = RESOURCE.test(String(body.action ?? "")) ? String(body.action) : "received";
      const data = body.data && typeof body.data === "object" ? body.data : {};
      const actor = body.actor && typeof body.actor === "object" ? body.actor : {};
      const base = { resource, action, actor_type: clip(actor.type ?? "", 40) || null, actor_name: clip(actor.name ?? "", 100) || null };

      let fields;
      let subject;
      if (resource === "issue" && data.issue) {
        fields = issueData(data.issue, base);
        subject = data.issue.shortId ?? String(data.issue.id ?? "");
      } else if (resource === "error" && data.error) {
        const err = data.error;
        fields = { ...base, issue_id: err.issue_id !== undefined ? String(err.issue_id) : null, title: clip(err.title ?? "", 300), culprit: clip(err.culprit ?? "", 300), level: clip(err.level ?? "", 20) || null, platform: clip(err.platform ?? "", 40) || null, project: err.project !== undefined ? String(err.project) : null, event_id: clip(err.event_id ?? "", 64) || null, url: clip(err.web_url ?? "", 500) || null };
        subject = err.event_id ?? "";
      } else if (resource === "event_alert" && data.event) {
        const ev = data.event;
        fields = { ...base, rule: clip(data.triggered_rule ?? "", 200) || null, issue_id: ev.issue_id !== undefined ? String(ev.issue_id) : null, title: clip(ev.title ?? "", 300), culprit: clip(ev.culprit ?? "", 300), level: clip(ev.level ?? "", 20) || null, platform: clip(ev.platform ?? "", 40) || null, event_id: clip(ev.event_id ?? "", 64) || null, url: clip(ev.web_url ?? "", 500) || null };
        subject = data.triggered_rule ?? "";
      } else if (resource === "metric_alert") {
        const alert = data.metric_alert && typeof data.metric_alert === "object" ? data.metric_alert : {};
        fields = { ...base, rule: clip(alert.alert_rule?.name ?? alert.title ?? "", 200) || null, title: clip(data.description_title ?? alert.title ?? "", 300), text: clip(data.description_text ?? "", 500), url: clip(data.web_url ?? "", 500) || null };
        subject = alert.alert_rule?.name ?? "";
      } else if (resource === "comment") {
        fields = { ...base, issue_id: data.issue_id !== undefined ? String(data.issue_id) : null, project: clip(data.project_slug ?? "", 100) || null, text: clip(data.comment ?? "", 500) };
        subject = String(data.issue_id ?? "");
      } else {
        fields = { ...base, title: clip(data.title ?? "", 300) };
        subject = "";
      }
      // Sentry's Request-ID header is unsigned, so the dedupe key comes from the signed body instead.
      return publish({
        id: `sentry:sha256:${sha256Hex(raw)}`,
        source: `sentry/${clip(fields.project ?? "org", 100)}`,
        type: `io.sentry.${resource}.${action}`,
        ...(subject ? { subject: clip(subject, 256) } : {}),
        time: new Date().toISOString(),
        data: fields,
      });
    },
  });
  console.error(`sentry plugin webhook ready -> target ${target}`);
}
