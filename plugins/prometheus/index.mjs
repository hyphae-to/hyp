#!/usr/bin/env node
/**
 * Built-in zero-dependency Prometheus Alertmanager v4 webhook stream plugin for Hyphae (Node 24+).
 * Turns Alertmanager webhook POST payloads into filterable CloudEvents 1.0 on fd 3.
 *
 * Configuration via env:
 *   PROMETHEUS_HOST                                         - Bind host (default 127.0.0.1)
 *   PROMETHEUS_PORT                                         - Bind port (default 8793)
 *   PROMETHEUS_PATH                                         - Webhook path (default /alerts)
 *   PROMETHEUS_TOPIC                                        - Target topic (default "alerts" or AGENTS_MESH_TOPIC)
 *   PROMETHEUS_BEARER_TOKEN_FILE or PROMETHEUS_BEARER_TOKEN - Optional Bearer token for Authorization header
 *   PROMETHEUS_WEBHOOK_SECRET_FILE or PROMETHEUS_WEBHOOK_SECRET - Optional HMAC-SHA256 secret for X-Webhook-Signature-256
 */
import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { MeshPluginClient } from "../sdk/client.mjs";

const MAX_BODY_BYTES = 1024 * 1024;
const MAX_SAFE_DATA_BYTES = 7_500;
const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;

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
  const bufA = Buffer.from(a, "utf8");
  const bufB = Buffer.from(b, "utf8");
  if (bufA.length !== bufB.length) return false;
  return timingSafeEqual(bufA, bufB);
}

function isPlainObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
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

async function readRawBody(req, maxBytes) {
  const contentLength = Number(req.headers["content-length"]);
  if (Number.isFinite(contentLength) && contentLength > maxBytes) {
    return null;
  }
  const chunks = [];
  let bytes = 0;
  for await (const chunk of req) {
    bytes += chunk.length;
    if (bytes > maxBytes) {
      return null;
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
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
const webhookSecret = readOptionalSecret("PROMETHEUS_WEBHOOK_SECRET_FILE", "PROMETHEUS_WEBHOOK_SECRET");

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

const server = createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", "http://localhost");

  if (req.method === "GET" && url.pathname === "/health") {
    sendJson(res, 200, { ok: true });
    return;
  }

  if (url.pathname !== expectedPath) {
    sendJson(res, 404, { error: "not_found" });
    return;
  }

  if (req.method !== "POST") {
    sendJson(res, 405, { error: "method_not_allowed" });
    return;
  }

  if (bearerToken) {
    const authHeader = req.headers["authorization"];
    const match = typeof authHeader === "string" ? /^Bearer\s+(.+)$/i.exec(authHeader) : null;
    if (!match || !safeEqual(match[1], bearerToken)) {
      sendJson(res, 401, { error: "unauthorized" });
      return;
    }
  }

  const raw = await readRawBody(req, MAX_BODY_BYTES);
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

  if (!isPlainObject(payload) || !Array.isArray(payload.alerts)) {
    sendJson(res, 400, { error: "invalid_alertmanager_payload" });
    return;
  }

  const commonLabels = isPlainObject(payload.commonLabels) ? payload.commonLabels : {};
  const commonAnnotations = isPlainObject(payload.commonAnnotations) ? payload.commonAnnotations : {};

  let count = 0;
  for (const alert of payload.alerts) {
    if (!isPlainObject(alert)) {
      sendJson(res, 400, { error: "invalid_alert_entry" });
      return;
    }

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
        : createHash("sha256").update(JSON.stringify(labels)).digest("hex").slice(0, 16);

    const startsAt = typeof alert.startsAt === "string" ? alert.startsAt : "";
    const endsAt = typeof alert.endsAt === "string" ? alert.endsAt : "";
    const eventTime = normalizeRfc3339(status === "resolved" ? endsAt : startsAt) ?? new Date().toISOString();
    const eventId = `${fingerprint}:${status}:${startsAt}`.slice(0, 256);
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
      ...(typeof alert.endsAt === "string" ? { endsAt: alert.endsAt } : {}),
      ...(typeof alert.generatorURL === "string" ? { generatorURL: alert.generatorURL } : {}),
      ...(typeof payload.receiver === "string" ? { receiver: payload.receiver } : {}),
      ...(typeof payload.externalURL === "string" ? { externalURL: payload.externalURL } : {}),
    };

    const event = {
      specversion: "1.0",
      id: eventId,
      type: status === "resolved" ? "io.prometheus.alert.resolved" : "io.prometheus.alert.firing",
      source: "prometheus/alertmanager",
      subject,
      time: eventTime,
      datacontenttype: "application/json",
      data: fitDataBytes(rawData),
    };

    try {
      const reply = await mesh.send(topic, event);
      if (reply.type === "ack") {
        count += 1;
      } else {
        console.error(`prometheus mesh nack id=${eventId} error=${reply.error ?? reply.reason ?? "unknown"}`);
        if (reply.error === "unavailable" || reply.reason === "unavailable") {
          sendJson(res, 503, { ok: false, error: "mesh_unavailable", alerts: count });
          return;
        }
      }
    } catch (error) {
      console.error(`prometheus mesh send error: ${error instanceof Error ? error.message : String(error)}`);
      sendJson(res, 503, { ok: false, error: "mesh_error", alerts: count });
      return;
    }
  }

  sendJson(res, 200, { ok: true, alerts: count });
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
