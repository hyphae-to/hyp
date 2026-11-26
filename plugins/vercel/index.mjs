#!/usr/bin/env node
/**
 * Zero-dependency Vercel event source for Hyphae (Node 24+).
 *
 * Two transports, chosen with VERCEL_MODE:
 *   poll (default) - outbound only. Polls the deployments API and emits an event when a
 *                    deployment appears and when it reaches READY, ERROR or CANCELED.
 *   webhook        - receives Vercel account or integration webhooks on a local port.
 *
 * Configuration via env:
 *   VERCEL_MODE             - "poll" (default) or "webhook"
 *   VERCEL_TARGET           - Target name (defaults to first target in hello)
 *  poll:
 *   VERCEL_TOKEN / _FILE    - Vercel access token (required)
 *   VERCEL_TEAM_ID          - Team ID to query (or VERCEL_TEAM_SLUG); omit for a personal account
 *   VERCEL_PROJECTS         - Comma-separated project names or IDs to keep (default: all)
 *   VERCEL_ENVIRONMENT      - "production" or "preview" to keep only that environment
 *   VERCEL_POLL_SECONDS     - Poll interval (default 30, min 10)
 *   VERCEL_API_BASE         - API base (default https://api.vercel.com)
 *   VERCEL_STATE_FILE       - State file (defaults to $HYPHAE_STATE_DIR/vercel-state.json)
 *  webhook:
 *   VERCEL_WEBHOOK_SECRET / _FILE - Webhook secret used to verify x-vercel-signature (required)
 *   VERCEL_WEBHOOK_HOST / VERCEL_WEBHOOK_PORT / VERCEL_WEBHOOK_PATH - default 127.0.0.1:8797/vercel
 *   VERCEL_WEBHOOK_FUNNEL         - 443, 8443 or 10000: publish this path through Tailscale Funnel on that port and log the public URL
 */
import {
  boundKeys, clip, connectSource, envInt, envList, envString, fetchJson, hmacHex, pollForever, requireSecretEnv,
  resolveBaseUrl, safeEqual, StateFile, startWebhookServer,
} from "../sdk/source-kit.mjs";

const mode = envString("VERCEL_MODE", "poll");
if (mode !== "poll" && mode !== "webhook") throw new Error(`VERCEL_MODE must be 'poll' or 'webhook' (got '${mode}')`);

function gitFields(meta) {
  const m = meta && typeof meta === "object" ? meta : {};
  return {
    branch: clip(m.githubCommitRef ?? m.gitlabCommitRef ?? m.bitbucketCommitRef ?? "", 200) || null,
    commit_sha: clip(m.githubCommitSha ?? m.gitlabCommitSha ?? m.bitbucketCommitSha ?? "", 64) || null,
    commit_message: clip(m.githubCommitMessage ?? m.gitlabCommitMessage ?? m.bitbucketCommitMessage ?? "", 300) || null,
    commit_author: clip(m.githubCommitAuthorLogin ?? m.githubCommitAuthorName ?? m.gitlabCommitAuthorLogin ?? "", 100) || null,
    repo: m.githubOrg && m.githubRepo ? clip(`${m.githubOrg}/${m.githubRepo}`, 200) : null,
  };
}

if (mode === "poll") {
  const token = requireSecretEnv("VERCEL_TOKEN");
  const apiBase = resolveBaseUrl("VERCEL_API_BASE", "https://api.vercel.com");
  const projects = new Set(envList("VERCEL_PROJECTS"));
  const environment = envString("VERCEL_ENVIRONMENT");
  if (environment && environment !== "production" && environment !== "preview") {
    throw new Error("VERCEL_ENVIRONMENT must be 'production' or 'preview'");
  }
  const intervalMs = envInt("VERCEL_POLL_SECONDS", 30, { min: 10, max: 3600 }) * 1000;
  const state = new StateFile("VERCEL", "vercel-state.json");
  const { target, publish } = await connectSource("VERCEL", "vercel");

  const params = new URLSearchParams({ limit: "50" });
  if (envString("VERCEL_TEAM_ID")) params.set("teamId", envString("VERCEL_TEAM_ID"));
  else if (envString("VERCEL_TEAM_SLUG")) params.set("slug", envString("VERCEL_TEAM_SLUG"));
  const url = `${apiBase}/v7/deployments?${params}`;

  const TERMINAL = { READY: "succeeded", ERROR: "error", CANCELED: "canceled" };
  if (!Number.isFinite(state.data.since)) state.data = { since: Date.now(), states: {} };
  if (!state.data.states || typeof state.data.states !== "object") state.data.states = {};
  console.error(`vercel plugin polling deployments every ${intervalMs / 1000}s -> target ${target}`);

  const emit = async (dep, action, phase) => {
    const env = dep.target === "production" ? "production" : "preview";
    await publish({
      id: `vercel:${dep.uid}:${action}`,
      source: `vercel/${clip(dep.name ?? "project", 100)}`,
      type: `com.vercel.deployment.${action}`,
      subject: clip(dep.uid, 256),
      time: new Date().toISOString(),
      data: {
        action,
        deployment_id: clip(dep.uid, 100),
        project: clip(dep.name ?? "", 100) || null,
        project_id: clip(dep.projectId ?? "", 100) || null,
        environment: env,
        state: phase,
        url: dep.url ? `https://${clip(dep.url, 300)}` : null,
        inspector_url: clip(dep.inspectorUrl ?? "", 500) || null,
        error_code: clip(dep.errorCode ?? "", 100) || null,
        error_message: clip(dep.errorMessage ?? "", 300) || null,
        creator: clip(dep.creator?.username ?? dep.creator?.githubLogin ?? "", 100) || null,
        ...gitFields(dep.meta),
      },
    });
  };

  await pollForever("vercel", intervalMs, async () => {
    const body = await fetchJson(url, { headers: { authorization: `Bearer ${token}` } });
    const deployments = Array.isArray(body?.deployments) ? body.deployments : null;
    if (!deployments) throw new Error("unexpected deployments response");
    const relevant = deployments
      .filter((dep) => dep && typeof dep.uid === "string" && Number.isFinite(dep.created ?? dep.createdAt))
      .filter((dep) => projects.size === 0 || projects.has(dep.name) || projects.has(dep.projectId))
      .filter((dep) => !environment || (dep.target === "production" ? "production" : "preview") === environment)
      .sort((a, b) => (a.created ?? a.createdAt) - (b.created ?? b.createdAt));
    for (const dep of relevant) {
      const phase = String(dep.readyState ?? dep.state ?? "");
      const known = state.data.states[dep.uid];
      if (known === undefined) {
        // Deployments created before this plugin first ran are tracked silently, never replayed.
        if ((dep.created ?? dep.createdAt) > state.data.since) {
          await emit(dep, "created", phase);
          if (TERMINAL[phase]) await emit(dep, TERMINAL[phase], phase);
        }
      } else if (known !== phase && TERMINAL[phase]) {
        await emit(dep, TERMINAL[phase], phase);
      }
      if (known !== phase) {
        state.data.states[dep.uid] = phase;
        boundKeys(state.data.states, 400);
        state.save();
      }
    }
  });
} else {
  const secret = requireSecretEnv("VERCEL_WEBHOOK_SECRET");
  const { target, publish } = await connectSource("VERCEL", "vercel");
  const TYPE = /^[a-z][a-z0-9-]*(\.[a-z0-9-]+){1,5}$/;

  await startWebhookServer({
    prefix: "VERCEL",
    name: "vercel",
    defaultPort: 8797,
    defaultPath: "/vercel",
    verify: (raw, headers) => safeEqual(String(headers["x-vercel-signature"] ?? "").trim().toLowerCase(), hmacHex("sha1", secret, raw)),
    handle: async (body) => {
      const type = String(body.type ?? "");
      const deliveryId = typeof body.id === "string" ? body.id : "";
      if (!TYPE.test(type) || !deliveryId) return "ignored";
      const payload = body.payload && typeof body.payload === "object" ? body.payload : {};
      const dep = payload.deployment && typeof payload.deployment === "object" ? payload.deployment : {};
      const project = clip(dep.name ?? payload.project?.name ?? payload.name ?? "", 100);
      return publish({
        id: `vercel:${clip(deliveryId, 200)}`,
        source: `vercel/${project || "account"}`,
        type: `com.vercel.${type}`,
        ...(dep.id ? { subject: clip(dep.id, 256) } : {}),
        time: Number.isFinite(body.createdAt) ? new Date(body.createdAt).toISOString() : new Date().toISOString(),
        data: {
          action: type.split(".").slice(1).join("."),
          deployment_id: clip(dep.id ?? "", 100) || null,
          project: project || null,
          project_id: clip(payload.project?.id ?? payload.projectId ?? "", 100) || null,
          environment: type.startsWith("deployment.") ? (payload.target === "production" ? "production" : "preview") : null,
          url: dep.url ? `https://${clip(dep.url, 300)}` : null,
          inspector_url: clip(payload.links?.deployment ?? "", 500) || null,
          team_id: clip(payload.team?.id ?? "", 100) || null,
          user_id: clip(payload.user?.id ?? "", 100) || null,
          ...gitFields(dep.meta),
        },
      });
    },
  });
  console.error(`vercel plugin webhook ready -> target ${target}`);
}
