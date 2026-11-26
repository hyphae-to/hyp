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
 *   WEBHOOK_MAX_BODY_BYTES  - Maximum request body size (default 65536)
 *   WEBHOOK_SIGNATURE_HEADER - Signature header name (default X-Webhook-Signature-256)
 *   WEBHOOK_LEGACY_NATIVE  - Use the retired Rust source’s payload and event ID contract when set to 1
 *   WEBHOOK_POST_URL        - Optional outbound callback URL for hyp_plugin_post replies
 */
import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { MeshPluginClient, PluginRpcError, RPC_UNAVAILABLE } from "../sdk/client.mjs";
import { answerWebhookReadiness, envInt } from "../sdk/source-kit.mjs";

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
const port = envInt("WEBHOOK_PORT", 8795, { max: 65_535 });
const expectedPath = process.env.WEBHOOK_PATH ?? "/webhook";
const secret =
  process.env.WEBHOOK_SECRET?.trim() ||
  (process.env.WEBHOOK_SECRET_FILE ? readFileSync(process.env.WEBHOOK_SECRET_FILE, "utf8").trim() : null);
const allowUnsigned = process.env.WEBHOOK_ALLOW_UNSIGNED === "1";
const defaultSource = process.env.WEBHOOK_SOURCE ?? "webhook/local";
const defaultType = process.env.WEBHOOK_EVENT_TYPE ?? "com.webhook.received";
const postUrl = process.env.WEBHOOK_POST_URL?.trim() || null;
const maxBodyBytes = envInt("WEBHOOK_MAX_BODY_BYTES", 65_536, { min: 1 });
const signatureHeader = process.env.WEBHOOK_SIGNATURE_HEADER?.trim().toLowerCase() || "x-webhook-signature-256";
if (!/^[a-z0-9!#$%&'*+.^_`|~-]+$/.test(signatureHeader)) throw new Error("Invalid WEBHOOK_SIGNATURE_HEADER");
const nativeCompat = process.env.WEBHOOK_LEGACY_NATIVE === "1";

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
  if (answerWebhookReadiness(req, res, expectedPath, secret && isLoopbackHost(host))) return;
  if (req.method !== "POST" || (req.url ?? "").split("?")[0] !== expectedPath) {
    res.writeHead(404).end();
    return;
  }
  const length = Number(req.headers["content-length"]);
  if (Number.isFinite(length) && length > maxBodyBytes) {
    res.writeHead(413, { connection: "close" }).end('{"error":"too_large"}');
    return;
  }
  const chunks = [];
  let bytes = 0;
  for await (const chunk of req) {
    bytes += chunk.length;
    if (bytes > maxBodyBytes) {
      res.writeHead(413, { connection: "close" }).end('{"error":"too_large"}');
      return;
    }
    chunks.push(chunk);
  }
  const raw = Buffer.concat(chunks);
  const rawTsHeader =
    typeof req.headers["x-webhook-timestamp"] === "string"
      ? req.headers["x-webhook-timestamp"].trim()
      : "";
  if (req.headers["x-webhook-timestamp"] !== undefined) {
    const tsMs = parseWebhookTimestampMs(rawTsHeader);
    if (tsMs === null || Math.abs(Date.now() - tsMs) > REPLAY_WINDOW_MS) {
      res.writeHead(401, { "content-type": "application/json" }).end('{"error":"timestamp_out_of_window"}');
      return;
    }
  }
  if (secret) {
    const header = String(req.headers[signatureHeader] ?? "").trim().toLowerCase();
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
  if (!rawTsHeader && !nativeCompat) {
    const payloadTsRaw = obj.timestamp ?? obj.time;
    if (payloadTsRaw !== undefined && payloadTsRaw !== null && String(payloadTsRaw).trim() !== "") {
      const payloadTsMs = parseWebhookTimestampMs(payloadTsRaw);
      if (payloadTsMs === null || Math.abs(Date.now() - payloadTsMs) > REPLAY_WINDOW_MS) {
        res.writeHead(401, { "content-type": "application/json" }).end('{"error":"timestamp_out_of_window"}');
        return;
      }
    }
  }
  const eventType = typeof obj.type === "string" && obj.type.length > 0 && Buffer.byteLength(obj.type) <= 128 ? obj.type : defaultType;
  const eventSource = typeof obj.source === "string" && obj.source.length > 0 && Buffer.byteLength(obj.source) <= 256 ? obj.source : defaultSource;
  const eventSubject = typeof obj.subject === "string" && obj.subject.length > 0 && Buffer.byteLength(obj.subject) <= 256 ? obj.subject : undefined;
  const data = typeof obj.data === "object" && obj.data !== null &&
    (!nativeCompat || !Array.isArray(obj.data)) ? obj.data : obj;
  // Derive deterministic event ID from SHA-256 of (optional signed timestamp + raw body)
  // rather than trusting unsigned headers like x-delivery-id or x-request-id.
  const idHash = createHash("sha256");
  if (rawTsHeader) {
    idHash.update(`${rawTsHeader}.`);
  }
  idHash.update(raw);
  const id = (nativeCompat ? "wh-" : "sha256:") + idHash.digest("hex");
  const isCloudEvent = obj.specversion === "1.0" && ["id", "source", "type"].every(
    (key) => typeof obj[key] === "string" && obj[key].length > 0,
  );
  const event = nativeCompat && isCloudEvent
    ? { time: new Date().toISOString(), ...obj, id, hyphaesourcekind: "external-webhook" }
    : {
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
    res.writeHead(202, { "content-type": "application/json" }).end(JSON.stringify({ status: reply.status, id }));
  } catch (error) {
    const status = error instanceof PluginRpcError && error.code !== RPC_UNAVAILABLE ? 400 : 503;
    res.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify({ error: error.message, ...(error instanceof PluginRpcError ? { code: error.code } : {}) }));
  }
});

server.listen(port, host, () => {
  const bound = server.address();
  const actualPort = typeof bound === "object" && bound ? bound.port : port;
  console.error(`webhook plugin listening on http://${host}:${actualPort}${expectedPath} -> target ${target}`);
});
