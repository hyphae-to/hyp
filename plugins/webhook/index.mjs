#!/usr/bin/env node
/**
 * Built-in zero-dependency local HTTP webhook plugin for Hyphae (Node 24+).
 * Turns any loopback/tailnet webhook POST into a validated CloudEvent on fd 3.
 *
 * Configuration via env:
 *   WEBHOOK_HOST            - Bind host (default 127.0.0.1)
 *   WEBHOOK_PORT            - Bind port (default 8795)
 *   WEBHOOK_PATH            - Expected path (default /webhook)
 *   WEBHOOK_TARGET          - Target name (defaults to first target in hello)
 *   WEBHOOK_SECRET / WEBHOOK_SECRET_FILE - Required HMAC-SHA256 secret (verified via X-Webhook-Signature-256: sha256=<hex>)
 *   WEBHOOK_ALLOW_UNSIGNED  - Set to "1" to explicitly allow unsigned loopback-only webhooks (NEVER permitted on non-loopback binds)
 *   WEBHOOK_SOURCE          - CloudEvent source attribute (default webhook/local)
 *   WEBHOOK_EVENT_TYPE      - CloudEvent type attribute (default com.webhook.received)
 *   WEBHOOK_POST_URL        - Optional outbound callback URL for hyp_plugin_post replies
 */
import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { MeshPluginClient } from "../sdk/client.mjs";

const REPLAY_WINDOW_MS = 5 * 60 * 1000;

function isLoopbackHost(h) {
  const normalized = String(h ?? "").trim().toLowerCase().replace(/^\[|\]$/g, "");
  return normalized === "127.0.0.1" || normalized === "localhost" || normalized === "::1";
}

function parseWebhookTimestampMs(raw) {
  if (raw === undefined || raw === null) return null;
  const str = String(raw).trim();
  if (!str) return null;
  if (/^\d+(?:\.\d+)?$/.test(str)) {
    const num = Number(str);
    if (!Number.isFinite(num) || num <= 0) return null;
    return num < 1e12 ? Math.round(num * 1000) : Math.round(num);
  }
  const parsed = Date.parse(str);
  return Number.isNaN(parsed) ? null : parsed;
}

const host = process.env.WEBHOOK_HOST?.trim() || "127.0.0.1";
const port = Number(process.env.WEBHOOK_PORT ?? "8795");
const expectedPath = process.env.WEBHOOK_PATH ?? "/webhook";
const secret =
  process.env.WEBHOOK_SECRET?.trim() ||
  (process.env.WEBHOOK_SECRET_FILE ? readFileSync(process.env.WEBHOOK_SECRET_FILE, "utf8").trim() : null);
const allowUnsigned = process.env.WEBHOOK_ALLOW_UNSIGNED === "1";
const defaultSource = process.env.WEBHOOK_SOURCE ?? "webhook/local";
const defaultType = process.env.WEBHOOK_EVENT_TYPE ?? "com.webhook.received";
const postUrl = process.env.WEBHOOK_POST_URL?.trim() || null;

if (!secret) {
  if (!isLoopbackHost(host)) {
    throw new Error(
      `Refusing to start webhook plugin on non-loopback host '${host}' without WEBHOOK_SECRET or WEBHOOK_SECRET_FILE (unsigned mode is never permitted on non-loopback interfaces)`,
    );
  }
  if (!allowUnsigned) {
    throw new Error(
      "Refusing to start webhook plugin without WEBHOOK_SECRET or WEBHOOK_SECRET_FILE (set WEBHOOK_ALLOW_UNSIGNED=1 to explicitly allow unsigned loopback-only webhooks)",
    );
  }
}

const mesh = new MeshPluginClient({
  onPost: async (params) => {
    if (!postUrl) {
      throw new Error("post_not_configured: set WEBHOOK_POST_URL to enable outbound webhook replies");
    }
    const text = typeof params.text === "string" ? params.text : "";
    if (!text.trim()) throw new Error("text is required");
    const payload = {
      target: params.target ?? target,
      text,
      ...(params.channel ? { channel: params.channel } : {}),
      ...(params.chatId ? { chatId: params.chatId } : {}),
      ...(params.to ? { to: params.to } : {}),
      ...(params.threadTs ? { threadTs: params.threadTs } : {}),
      ...(params.replyTo ? { replyTo: params.replyTo } : {}),
      timestamp: new Date().toISOString(),
    };
    const raw = JSON.stringify(payload);
    const headers = { "content-type": "application/json" };
    if (secret) {
      headers["x-webhook-signature-256"] = "sha256=" + createHmac("sha256", secret).update(raw).digest("hex");
    }
    const res = await fetch(postUrl, {
      method: "POST",
      headers,
      body: raw,
      signal: AbortSignal.timeout(10_000),
    });
    if (!res.ok) throw new Error(`Webhook post failed with HTTP ${res.status}`);
    return { ok: true, status: res.status };
  },
});
const hello = await mesh.ready;
const target = process.env.WEBHOOK_TARGET ?? hello.targets[0];
if (!target || !hello.targets.includes(target)) {
  throw new Error(`Target '${target}' not in configured targets: ${hello.targets.join(", ")}`);
}

const server = createServer(async (req, res) => {
  if (req.method !== "POST" || (req.url ?? "").split("?")[0] !== expectedPath) {
    res.writeHead(404).end();
    return;
  }
  const chunks = [];
  let bytes = 0;
  for await (const chunk of req) {
    bytes += chunk.length;
    if (bytes > 65_536) {
      res.writeHead(413).end('{"error":"too_large"}');
      return;
    }
    chunks.push(chunk);
  }
  const raw = Buffer.concat(chunks);
  const rawTsHeader =
    typeof req.headers["x-webhook-timestamp"] === "string"
      ? req.headers["x-webhook-timestamp"].trim()
      : "";
  if (rawTsHeader) {
    const tsMs = parseWebhookTimestampMs(rawTsHeader);
    if (tsMs === null || Math.abs(Date.now() - tsMs) > REPLAY_WINDOW_MS) {
      res.writeHead(401, { "content-type": "application/json" }).end('{"error":"timestamp_out_of_window"}');
      return;
    }
  }
  if (secret) {
    const header = String(req.headers["x-webhook-signature-256"] ?? "").trim().toLowerCase();
    const hmac = createHmac("sha256", secret);
    if (rawTsHeader) {
      hmac.update(`${rawTsHeader}.`);
    }
    hmac.update(raw);
    const expected = "sha256=" + hmac.digest("hex");
    if (header.length !== expected.length || !timingSafeEqual(Buffer.from(header), Buffer.from(expected))) {
      res.writeHead(401, { "content-type": "application/json" }).end('{"error":"bad_signature"}');
      return;
    }
  }
  let parsed;
  try { parsed = JSON.parse(raw.toString("utf8")); } catch { parsed = { raw: raw.toString("utf8").slice(0, 4000) }; }
  const obj = typeof parsed === "object" && parsed !== null && !Array.isArray(parsed) ? parsed : { value: parsed };
  if (!rawTsHeader) {
    const payloadTsRaw = obj.timestamp ?? obj.time;
    if (payloadTsRaw !== undefined && payloadTsRaw !== null && String(payloadTsRaw).trim() !== "") {
      const payloadTsMs = parseWebhookTimestampMs(payloadTsRaw);
      if (payloadTsMs === null || Math.abs(Date.now() - payloadTsMs) > REPLAY_WINDOW_MS) {
        res.writeHead(401, { "content-type": "application/json" }).end('{"error":"timestamp_out_of_window"}');
        return;
      }
    }
  }
  const eventType = typeof obj.type === "string" && obj.type.length > 0 && obj.type.length <= 128 ? obj.type : defaultType;
  const eventSource = typeof obj.source === "string" && obj.source.length > 0 && obj.source.length <= 256 ? obj.source : defaultSource;
  const eventSubject = typeof obj.subject === "string" && obj.subject.length > 0 && obj.subject.length <= 256 ? obj.subject : undefined;
  const data = typeof obj.data === "object" && obj.data !== null ? obj.data : obj;
  // Derive deterministic event ID from SHA-256 of (optional signed timestamp + raw body)
  // rather than trusting unsigned headers like x-delivery-id or x-request-id.
  const idHash = createHash("sha256");
  if (rawTsHeader) {
    idHash.update(`${rawTsHeader}.`);
  }
  idHash.update(raw);
  const id = `sha256:${idHash.digest("hex")}`;
  const event = {
    specversion: "1.0",
    id,
    source: eventSource,
    type: eventType,
    ...(eventSubject ? { subject: eventSubject } : {}),
    time: new Date().toISOString(),
    datacontenttype: "application/json",
    data,
  };
  try {
    const reply = await mesh.send(target, event);
    if (reply.type === "ack") {
      res.writeHead(202, { "content-type": "application/json" }).end(JSON.stringify({ status: reply.status, id }));
    } else {
      res.writeHead(reply.error === "unavailable" ? 503 : 400, { "content-type": "application/json" }).end(JSON.stringify(reply));
    }
  } catch (error) {
    res.writeHead(503, { "content-type": "application/json" }).end(JSON.stringify({ error: String(error) }));
  }
});

server.listen(port, host, () => {
  console.error(`webhook plugin listening on http://${host}:${port}${expectedPath} -> target ${target}`);
});
