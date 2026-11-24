#!/usr/bin/env node
/**
 * Built-in zero-dependency local HTTP webhook plugin for hyphae / t3-mesh (Node 24+).
 * Turns any loopback/tailnet webhook POST into a validated CloudEvent on fd 3.
 *
 * Configuration via env:
 *   WEBHOOK_HOST         - Bind host (default 127.0.0.1)
 *   WEBHOOK_PORT         - Bind port (default 8795)
 *   WEBHOOK_PATH         - Expected path (default /webhook)
 *   WEBHOOK_TARGET       - Target name (defaults to first target in hello)
 *   WEBHOOK_SECRET_FILE  - Optional 0600 file containing HMAC-SHA256 secret (verified via X-Webhook-Signature-256: sha256=<hex>)
 *   WEBHOOK_SOURCE       - CloudEvent source attribute (default webhook/local)
 *   WEBHOOK_EVENT_TYPE   - CloudEvent type attribute (default com.webhook.received)
 */
import { createHmac, randomUUID, timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { MeshPluginClient } from "../sdk/client.mjs";

const host = process.env.WEBHOOK_HOST ?? "127.0.0.1";
const port = Number(process.env.WEBHOOK_PORT ?? "8795");
const expectedPath = process.env.WEBHOOK_PATH ?? "/webhook";
const secret =
  process.env.WEBHOOK_SECRET?.trim() ||
  (process.env.WEBHOOK_SECRET_FILE ? readFileSync(process.env.WEBHOOK_SECRET_FILE, "utf8").trim() : null);
const defaultSource = process.env.WEBHOOK_SOURCE ?? "webhook/local";
const defaultType = process.env.WEBHOOK_EVENT_TYPE ?? "com.webhook.received";

const mesh = new MeshPluginClient();
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
  if (secret) {
    const header = String(req.headers["x-webhook-signature-256"] ?? "");
    const expected = "sha256=" + createHmac("sha256", secret).update(raw).digest("hex");
    if (header.length !== expected.length || !timingSafeEqual(Buffer.from(header), Buffer.from(expected))) {
      res.writeHead(401).end('{"error":"bad_signature"}');
      return;
    }
  }
  let parsed;
  try { parsed = JSON.parse(raw.toString("utf8")); } catch { parsed = { raw: raw.toString("utf8").slice(0, 4000) }; }
  const obj = typeof parsed === "object" && parsed !== null && !Array.isArray(parsed) ? parsed : { value: parsed };
  const eventType = typeof obj.type === "string" && obj.type.length > 0 && obj.type.length <= 128 ? obj.type : defaultType;
  const eventSource = typeof obj.source === "string" && obj.source.length > 0 && obj.source.length <= 256 ? obj.source : defaultSource;
  const eventSubject = typeof obj.subject === "string" && obj.subject.length > 0 && obj.subject.length <= 256 ? obj.subject : undefined;
  const data = typeof obj.data === "object" && obj.data !== null ? obj.data : obj;
  const id = String(req.headers["x-delivery-id"] ?? req.headers["x-request-id"] ?? obj.id ?? randomUUID()).slice(0, 128);
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
