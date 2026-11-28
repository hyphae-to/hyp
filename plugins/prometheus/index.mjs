#!/usr/bin/env node
/**
 * Built-in zero-dependency Prometheus Alertmanager v4 webhook stream plugin for Hyphae (Node 24+).
 * Turns Alertmanager webhook POST payloads into filterable CloudEvents 1.0 on fd 3.
 *
 * Configuration via env:
 *   PROMETHEUS_HOST                                                 - Bind host (default 127.0.0.1)
 *   PROMETHEUS_PORT                                                 - Bind port (default 8793)
 *   PROMETHEUS_PATH                                                 - Webhook path (default /alerts)
 *   PROMETHEUS_MAX_BODY_BYTES                                      - Maximum request body size (default 1048576)
 *   PROMETHEUS_TOPIC                                                - Target topic (default "alerts" or AGENTS_MESH_TOPIC)
 *   PROMETHEUS_BEARER_TOKEN_FILE or PROMETHEUS_BEARER_TOKEN         - Bearer token for Authorization header
 *   PROMETHEUS_BASIC_AUTH_FILE or PROMETHEUS_BASIC_AUTH             - Basic auth credentials ("user:pass") for Authorization header
 *   PROMETHEUS_WEBHOOK_SECRET_FILE or PROMETHEUS_WEBHOOK_SECRET     - HMAC-SHA256 secret for X-Webhook-Signature-256
 *   PROMETHEUS_ALLOW_UNSIGNED                                       - Set to "1" to explicitly allow unsigned loopback-only webhooks (NEVER permitted on non-loopback binds)
 */
import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { MeshPluginClient, PluginRpcError, RPC_INVALID_EVENT, RPC_TOO_LARGE } from "../sdk/client.mjs";
import { answerWebhookReadiness, envInt, readWebhookBody } from "../sdk/source-kit.mjs";

const maxBodyBytes = envInt("PROMETHEUS_MAX_BODY_BYTES", 1024 * 1024, { min: 1 });
const MAX_SAFE_DATA_BYTES = 7_500;
const MAX_ATTRIBUTE_CHARS = 256;
const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;
const COMPARE_HMAC_KEY = randomBytes(32);

function isLoopbackHost(h) {
  const normalized = String(h ?? "").trim().toLowerCase().replace(/^\[|\]$/g, "");
  return normalized === "127.0.0.1" || normalized === "localhost" || normalized === "::1";
}

function readOptionalSecret(fileEnv, valEnv) {
  const file = process.env[fileEnv]?.trim();
  if (file) {
    const value = readFileSync(file, "utf8").trim();
    return value || null;
  }
  const value = process.env[valEnv]?.trim();
  return value || null;
}

function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const tagA = createHmac("sha256", COMPARE_HMAC_KEY).update(a, "utf8").digest();
  const tagB = createHmac("sha256", COMPARE_HMAC_KEY).update(b, "utf8").digest();
  return timingSafeEqual(tagA, tagB);
}

function isPlainObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (!isPlainObject(value)) return JSON.stringify(value);
  return `{${Object.keys(value).sort().map((key) =>
    `${JSON.stringify(key)}:${canonicalJson(value[key])}`
  ).join(",")}}`;
}

function normalizeRfc3339(raw) {
  if (typeof raw !== "string") return null;
  const trimmed = raw.trim();
  if (!trimmed || trimmed.startsWith("0001-01-01") || !RFC3339.test(trimmed)) return null;
  if (Number.isNaN(Date.parse(trimmed))) return null;
  return trimmed.slice(0, 256);
}

function sendJson(res, status, body, extraHeaders = {}) {
  res
    .writeHead(status, { "content-type": "application/json; charset=utf-8", ...extraHeaders })
    .end(JSON.stringify(body));
}

// Match serde_json's supported nesting range before walking untrusted JSON.
function withinJsonDepth(value, remaining = 127) {
  if (value === null || typeof value !== "object") return true;
  return remaining > 0 && Object.values(value).every((child) => withinJsonDepth(child, remaining - 1));
}

function fitDataBytes(data) {
  if (Buffer.byteLength(JSON.stringify(data), "utf8") <= MAX_SAFE_DATA_BYTES) {
    return data;
  }
  const compact = {
    ...data,
    ...(typeof data.summary === "string" ? { summary: data.summary.slice(0, 512) } : {}),
    ...(typeof data.description === "string" ? { description: data.description.slice(0, 1024) } : {}),
    annotations: Object.fromEntries(
      Object.entries(data.annotations ?? {}).map(([k, v]) => [k, String(v).slice(0, 512)]),
    ),
  };
  if (Buffer.byteLength(JSON.stringify(compact), "utf8") <= MAX_SAFE_DATA_BYTES) {
    return compact;
  }
  return {
    status: data.status,
    alertname: data.alertname,
    severity: data.severity,
    ...(data.service !== undefined ? { service: data.service } : {}),
    ...(data.instance !== undefined ? { instance: data.instance } : {}),
    ...(typeof data.summary === "string" ? { summary: data.summary.slice(0, 512) } : {}),
    ...(typeof data.description === "string" ? { description: data.description.slice(0, 1024) } : {}),
    startsAt: data.startsAt,
    endsAt: data.endsAt,
    receiver: data.receiver,
    truncated: true,
  };
}

const host = process.env.PROMETHEUS_HOST?.trim() || "127.0.0.1";
const port = Number(process.env.PROMETHEUS_PORT ?? "8793");
if (!Number.isInteger(port) || port < 0 || port > 65535) {
  throw new Error(`Invalid PROMETHEUS_PORT: ${process.env.PROMETHEUS_PORT}`);
}
const rawPath = process.env.PROMETHEUS_PATH?.trim() || "/alerts";
const expectedPath = rawPath.startsWith("/") ? rawPath : `/${rawPath}`;

const bearerToken = readOptionalSecret("PROMETHEUS_BEARER_TOKEN_FILE", "PROMETHEUS_BEARER_TOKEN");
const basicAuth = readOptionalSecret("PROMETHEUS_BASIC_AUTH_FILE", "PROMETHEUS_BASIC_AUTH");
const webhookSecret = readOptionalSecret("PROMETHEUS_WEBHOOK_SECRET_FILE", "PROMETHEUS_WEBHOOK_SECRET");
const allowUnsigned = process.env.PROMETHEUS_ALLOW_UNSIGNED === "1";

if (!bearerToken && !basicAuth && !webhookSecret) {
  if (!isLoopbackHost(host)) {
    throw new Error(
      `Refusing to start Prometheus plugin on non-loopback host '${host}' without PROMETHEUS_BEARER_TOKEN, PROMETHEUS_BASIC_AUTH, or PROMETHEUS_WEBHOOK_SECRET (unsigned mode is never permitted on non-loopback interfaces)`,
    );
  }
  if (!allowUnsigned) {
    throw new Error(
      "Refusing to start Prometheus plugin without PROMETHEUS_BEARER_TOKEN, PROMETHEUS_BASIC_AUTH, or PROMETHEUS_WEBHOOK_SECRET (set PROMETHEUS_ALLOW_UNSIGNED=1 to explicitly allow unsigned loopback-only webhooks)",
    );
  }
}

const expectedBasicB64 = basicAuth ? Buffer.from(basicAuth, "utf8").toString("base64") : null;

const mesh = new MeshPluginClient({
  onDeliveryFailed: (msg) =>
    console.error(`prometheus plugin delivery_failed target=${msg.target} reason=${msg.reason}`),
});
const hello = await mesh.ready;
const topic =
  process.env.PROMETHEUS_TOPIC?.trim() ||
  process.env.AGENTS_MESH_TOPIC?.trim() ||
  (hello.targets.includes("alerts") ? "alerts" : hello.targets[0]);
if (!topic || !hello.targets.includes(topic)) {
  throw new Error(`Topic '${topic}' not in configured targets: ${hello.targets.join(", ")}`);
}

async function handleRequest(req, res) {
  if (answerWebhookReadiness(req, res, expectedPath, (bearerToken || basicAuth || webhookSecret) && isLoopbackHost(host))) return;
  const path = (req.url ?? "").split("?")[0];

  if (req.method === "GET" && path === "/health") {
    sendJson(res, 200, { ok: true });
    return;
  }

  if (path !== expectedPath) {
    sendJson(res, 404, { error: "not_found" });
    return;
  }

  if (req.method !== "POST") {
    sendJson(res, 405, { error: "method_not_allowed" });
    return;
  }

  // When both Bearer and Basic are configured, both read the single HTTP Authorization header:
  // accept if EITHER configured scheme matches in constant time (matching Rust PrometheusWebhookAdapter).
  if (bearerToken || expectedBasicB64) {
    const authHeader = typeof req.headers["authorization"] === "string" ? req.headers["authorization"] : "";
    let bearerOk = false;
    if (bearerToken) {
      const match = /^Bearer\s+(.+)$/i.exec(authHeader);
      bearerOk = Boolean(match && safeEqual(match[1], bearerToken));
    }
    let basicOk = false;
    if (expectedBasicB64) {
      const match = /^Basic\s+(.+)$/i.exec(authHeader);
      basicOk = Boolean(match && safeEqual(match[1].trim(), expectedBasicB64));
    }
    if (!bearerOk && !basicOk) {
      sendJson(res, 401, { error: "unauthorized" });
      return;
    }
  }

  const raw = await readWebhookBody(req, maxBodyBytes);
  if (raw === undefined) return;
  if (raw === null) {
    sendJson(res, 413, { error: "payload_too_large" }, { connection: "close" });
    return;
  }

  if (webhookSecret) {
    const sigHeader = req.headers["x-webhook-signature-256"];
    const expected = "sha256=" + createHmac("sha256", webhookSecret).update(raw).digest("hex");
    if (typeof sigHeader !== "string" || !safeEqual(sigHeader.toLowerCase(), expected)) {
      sendJson(res, 401, { error: "invalid_signature" });
      return;
    }
  }

  let payload;
  try {
    payload = JSON.parse(raw.toString("utf8"));
  } catch {
    sendJson(res, 400, { error: "invalid_json" });
    return;
  }

  if (!withinJsonDepth(payload)) {
    sendJson(res, 400, { error: "invalid_json" });
    return;
  }

  if (!isPlainObject(payload) || !Array.isArray(payload.alerts)) {
    sendJson(res, 400, { error: "invalid_alertmanager_payload" });
    return;
  }

  const commonLabels = isPlainObject(payload.commonLabels) ? payload.commonLabels : {};
  const commonAnnotations = isPlainObject(payload.commonAnnotations) ? payload.commonAnnotations : {};

  let count = 0;
  let failureStatus = 0;
  if (!payload.alerts.every(isPlainObject)) {
    sendJson(res, 400, { error: "invalid_alert_entry" });
    return;
  }
  for (const alert of payload.alerts) {
    const alertLabels = isPlainObject(alert.labels) ? alert.labels : {};
    const alertAnnotations = isPlainObject(alert.annotations) ? alert.annotations : {};
    const labels = { ...commonLabels, ...alertLabels };
    const annotations = { ...commonAnnotations, ...alertAnnotations };

    const status = alert.status === "resolved" ? "resolved" : "firing";
    const alertname =
      typeof labels.alertname === "string" && labels.alertname.trim() ? labels.alertname.trim() : "Alert";
    const severity =
      typeof labels.severity === "string" && labels.severity.trim() ? labels.severity.trim() : "unknown";
    const service =
      (typeof labels.service === "string" && labels.service.trim()) ||
      (typeof labels.job === "string" && labels.job.trim()) ||
      undefined;
    const instance =
      (typeof labels.instance === "string" && labels.instance.trim()) || undefined;
    const fingerprint =
      typeof alert.fingerprint === "string" && alert.fingerprint.trim()
        ? alert.fingerprint.trim()
        : createHash("sha256").update(canonicalJson(labels)).digest("hex").slice(0, 16);

    const startsAt = typeof alert.startsAt === "string" ? alert.startsAt : "";
    const endsAt = typeof alert.endsAt === "string" ? alert.endsAt : "";
    const eventTime = normalizeRfc3339(status === "resolved" ? endsAt : startsAt);
    const subject = `severity=${severity}/${alertname}`.slice(0, 256);

    const rawData = {
      status,
      alertname,
      severity,
      ...(service !== undefined ? { service } : {}),
      ...(instance !== undefined ? { instance } : {}),
      ...(typeof annotations.summary === "string" ? { summary: annotations.summary } : {}),
      ...(typeof annotations.description === "string" ? { description: annotations.description } : {}),
      labels,
      annotations,
      ...(typeof alert.startsAt === "string" ? { startsAt: alert.startsAt } : {}),
      // A firing alert can carry a moving expiry. Only a resolution has a final end time.
      ...(status === "resolved" && typeof alert.endsAt === "string" ? { endsAt: alert.endsAt } : {}),
      ...(typeof alert.generatorURL === "string" ? { generatorURL: alert.generatorURL } : {}),
      ...(typeof payload.receiver === "string" ? { receiver: payload.receiver } : {}),
      ...(typeof payload.externalURL === "string" ? { externalURL: payload.externalURL } : {}),
    };

    const revision = createHash("sha256").update(canonicalJson([fingerprint, rawData])).digest("hex");
    const idPrefix = Buffer.byteLength(fingerprint) <= 64 ? fingerprint : "alert";
    const event = {
      specversion: "1.0",
      id: `${idPrefix}:${status}:${revision}`,
      type: status === "resolved" ? "io.prometheus.alert.resolved" : "io.prometheus.alert.firing",
      source: "prometheus/alertmanager",
      subject,
      ...(eventTime ? { time: eventTime } : {}),
      ...(alertname && Buffer.byteLength(alertname, "utf8") <= MAX_ATTRIBUTE_CHARS ? { alertname } : {}),
      ...(severity && Buffer.byteLength(severity, "utf8") <= MAX_ATTRIBUTE_CHARS ? { severity } : {}),
      ...(service && Buffer.byteLength(service, "utf8") <= MAX_ATTRIBUTE_CHARS ? { service } : {}),
      datacontenttype: "application/json",
      data: fitDataBytes(rawData),
    };

    try {
      await mesh.send(topic, event);
      count += 1;
    } catch (error) {
      console.error(`prometheus mesh send error: ${error instanceof Error ? error.message : String(error)}`);
      const invalid = error instanceof PluginRpcError && [RPC_TOO_LARGE, RPC_INVALID_EVENT].includes(error.code);
      failureStatus = Math.max(failureStatus, invalid ? 422 : 503);
    }
  }

  if (failureStatus) {
    sendJson(res, failureStatus, {
      ok: false,
      error: failureStatus === 503 ? "mesh_unavailable" : "invalid_event",
      alerts: count,
      failed: payload.alerts.length - count,
    });
  } else {
    sendJson(res, 200, { ok: true, alerts: count });
  }
}

const server = createServer((req, res) => {
  handleRequest(req, res).catch(() => {
    if (res.destroyed || res.writableEnded) return;
    if (res.headersSent) res.destroy();
    else res.writeHead(400, { "content-type": "application/json" }).end('{"error":"invalid_request"}');
  });
});

server.on("error", (error) => {
  console.error(`prometheus server error: ${error instanceof Error ? error.message : String(error)}`);
  process.exit(1);
});

let shuttingDown = false;
function shutdown(signal = "SIGTERM") {
  if (shuttingDown) return;
  shuttingDown = true;
  const finish = () => {
    process.removeListener("SIGTERM", shutdown);
    process.removeListener("SIGINT", shutdown);
    try {
      process.kill(process.pid, signal);
    } catch {
      process.exit(0);
    }
  };
  server.close(finish);
  server.closeAllConnections?.();
  setTimeout(finish, 2_000).unref();
}
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);

server.listen(port, host, () => {
  const addr = server.address();
  const actualPort = addr && typeof addr === "object" ? addr.port : port;
  console.error(
    `prometheus plugin ready protocol=alertmanager-v4 listen=http://${host}:${actualPort}${expectedPath} topic=${topic}`,
  );
});
