/**
 * Zero-dependency helpers shared by the official Hyphae event-source plugins
 * (agentmail, sentry, gmail, google-calendar, vercel, notion). Node 24+.
 *
 * Everything here is transport plumbing: env/secret reading, fail-closed URL
 * validation, private state files, bounded HTTP, signed webhook receivers and
 * the fd-3 publish loop. Provider-specific normalization lives in each plugin.
 */
import { execFile } from "node:child_process";
import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { dirname, join } from "node:path";
import { MeshPluginClient } from "./client.mjs";

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "::1", "[::1]"]);

export function isLoopbackHost(host) {
  return LOOPBACK_HOSTS.has(String(host ?? "").trim().toLowerCase());
}

/** Reads `<NAME>_FILE` (trimmed file content) or `<NAME>`; returns "" when neither is set. */
export function readSecretEnv(name) {
  const file = process.env[`${name}_FILE`]?.trim();
  if (file) return readFileSync(file, "utf8").trim();
  return process.env[name]?.trim() ?? "";
}

export function requireSecretEnv(name) {
  const value = readSecretEnv(name);
  if (!value) throw new Error(`Set ${name} (via { "secret": "<name>" }) or ${name}_FILE`);
  return value;
}

export function envString(name, fallback = "") {
  const value = process.env[name]?.trim();
  return value ? value : fallback;
}

export function envList(name) {
  const raw = process.env[name]?.trim();
  return raw ? raw.split(",").map((v) => v.trim()).filter(Boolean) : [];
}

export function envInt(name, fallback, { min = 0, max = Number.MAX_SAFE_INTEGER } = {}) {
  const raw = process.env[name]?.trim();
  if (!raw) return fallback;
  if (!/^\d+$/.test(raw)) throw new Error(`${name} must be a non-negative integer (got '${raw}')`);
  const value = Number(raw);
  if (value < min || value > max) throw new Error(`${name} must be between ${min} and ${max} (got ${value})`);
  return value;
}

/** Accepts only `https://` (or `wss://`) and loopback `http://` (`ws://`) bases; strips trailing slashes. */
export function resolveBaseUrl(name, fallback, { websocket = false } = {}) {
  const value = envString(name, fallback).replace(/\/+$/, "");
  const parsed = new URL(value);
  const secure = websocket ? "wss:" : "https:";
  const plain = websocket ? "ws:" : "http:";
  if (parsed.protocol !== secure && !(parsed.protocol === plain && isLoopbackHost(parsed.hostname))) {
    throw new Error(`${name} must use ${secure}// or loopback ${plain}// (got ${parsed.protocol}//${parsed.host})`);
  }
  return value;
}

/** Cuts untrusted provider text to `max` characters without splitting a surrogate pair. */
export function clip(value, max) {
  if (value === undefined || value === null || max <= 0) return "";
  const text = String(value);
  if (text.length <= max) return text;
  let cut = max;
  const code = text.charCodeAt(cut - 1);
  if (code >= 0xd800 && code <= 0xdbff) cut -= 1;
  return text.slice(0, cut);
}

export function sha256Hex(...parts) {
  const hash = createHash("sha256");
  for (const part of parts) hash.update(part);
  return hash.digest("hex");
}

export function hmacHex(algorithm, secret, raw) {
  return createHmac(algorithm, secret).update(raw).digest("hex");
}

/** Constant-time comparison of two ASCII strings (length mismatch returns false). */
export function safeEqual(a, b) {
  const left = Buffer.from(String(a ?? ""));
  const right = Buffer.from(String(b ?? ""));
  return left.length === right.length && timingSafeEqual(left, right);
}

export const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Private JSON state (`0700` dir / `0600` file, atomic rename). Path comes from
 * `<PREFIX>_STATE_FILE`, else `$HYPHAE_STATE_DIR/<fileName>`; with neither set
 * the state lives in memory only and a restart starts from "now".
 */
export class StateFile {
  #path;
  data;

  constructor(prefix, fileName) {
    this.#path =
      envString(`${prefix}_STATE_FILE`) ||
      (process.env.HYPHAE_STATE_DIR ? join(process.env.HYPHAE_STATE_DIR, fileName) : "");
    this.data = {};
    if (this.#path && existsSync(this.#path)) {
      try {
        const parsed = JSON.parse(readFileSync(this.#path, "utf8"));
        if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) this.data = parsed;
      } catch {
        // Corrupt state is treated as absent: the plugin re-baselines instead of crashing.
      }
    }
  }

  get persistent() {
    return this.#path !== "";
  }

  save() {
    if (!this.#path) return;
    mkdirSync(dirname(this.#path), { recursive: true, mode: 0o700 });
    const tmp = `${this.#path}.tmp`;
    writeFileSync(tmp, JSON.stringify(this.data) + "\n", { mode: 0o600 });
    renameSync(tmp, this.#path);
  }
}

/** Keeps the newest `max` keys of an insertion-ordered plain object (bounded dedupe memory). */
export function boundKeys(map, max) {
  const keys = Object.keys(map);
  for (let i = 0; i < keys.length - max; i += 1) delete map[keys[i]];
  return map;
}

export class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

/**
 * Bounded JSON request: 20 s timeout, one retry on 429/503 honouring
 * `Retry-After` (capped at 30 s). Error messages carry the status and a short
 * provider message only, never request headers or tokens.
 */
export async function fetchJson(url, { method = "GET", headers = {}, body, timeoutMs = 20_000 } = {}) {
  for (let attempt = 0; ; attempt += 1) {
    const res = await fetch(url, {
      method,
      headers: { accept: "application/json", ...(body !== undefined ? { "content-type": "application/json" } : {}), ...headers },
      body: body === undefined ? undefined : typeof body === "string" ? body : JSON.stringify(body),
      signal: AbortSignal.timeout(timeoutMs),
    });
    if ((res.status === 429 || res.status === 503) && attempt === 0) {
      const retryAfter = Number(res.headers.get("retry-after") ?? 2);
      await sleep(Math.min(Math.max(Number.isFinite(retryAfter) ? retryAfter : 2, 1), 30) * 1000);
      continue;
    }
    const text = await res.text();
    let parsed = null;
    try {
      parsed = text ? JSON.parse(text) : null;
    } catch {
      parsed = null;
    }
    if (!res.ok) {
      const detail = parsed?.error?.message ?? parsed?.error_description ?? parsed?.message ?? parsed?.detail ?? parsed?.error ?? "";
      throw new HttpError(res.status, `HTTP ${res.status}${detail ? `: ${clip(typeof detail === "string" ? detail : JSON.stringify(detail), 200)}` : ""}`);
    }
    return parsed;
  }
}

/**
 * Connects the fd-3 channel and resolves the publish target (`<PREFIX>_TARGET`
 * or the first configured target). `publish` resolves to `"stored"` or
 * `"duplicate"` and throws when the node is temporarily unable to store, so
 * callers keep their cursor and retry instead of dropping the event.
 */
export async function connectSource(prefix, name) {
  const mesh = new MeshPluginClient({
    onDeliveryFailed: (msg) => console.error(`${name} plugin delivery_failed target=${msg.target} reason=${msg.reason}`),
  });
  const hello = await mesh.ready;
  const target = envString(`${prefix}_TARGET`) || hello.targets[0];
  if (!target || !hello.targets.includes(target)) {
    throw new Error(`Target '${target}' not in configured targets: ${hello.targets.join(", ")}`);
  }
  const publish = async (event) => {
    const reply = await mesh.send(target, { specversion: "1.0", datacontenttype: "application/json", ...event });
    if (reply.type === "ack") return reply.status ?? "stored";
    if (reply.error === "unavailable") throw new Error("Hyphae node temporarily unavailable; will retry");
    console.error(`${name} plugin event rejected: ${clip(reply.error ?? "unknown", 200)}`);
    return "rejected";
  };
  return { mesh, target, publish };
}

/** Runs `tick` forever every `intervalMs`, backing off (capped at 5 min) while it keeps failing. */
export async function pollForever(name, intervalMs, tick) {
  let backoff = intervalMs;
  while (true) {
    try {
      await tick();
      backoff = intervalMs;
    } catch (error) {
      console.error(`${name} poll error: ${error instanceof Error ? error.message : String(error)}`);
      backoff = Math.min(Math.max(backoff * 2, 5_000), 300_000);
    }
    await sleep(backoff);
  }
}

const FUNNEL_PORTS = new Set(["443", "8443", "10000"]);

/**
 * The host CLI owns provider discovery and route changes. This compatibility
 * adapter supports existing *_WEBHOOK_FUNNEL plugin configurations.
 */
export async function tailscaleFunnel({ funnelPort, localPort, path }) {
  const target = `http://127.0.0.1:${localPort}${path}`;
  const args = ["deploy", "webhook", "--provider", "tailscale", "--local-target", target, "--funnel-port", funnelPort, "--json"];
  return new Promise((resolve, reject) => {
    execFile(envString("HYPHAE_BIN", "hyp"), args, { timeout: 70_000, maxBuffer: 262_144, windowsHide: true }, (error, stdout) => {
      let reply;
      try {
        reply = JSON.parse(stdout);
      } catch {
        return reject(new Error("Run hyp deploy webhook on this host to inspect Funnel prerequisites."));
      }
      if (error || reply?.ok !== true || typeof reply.data?.publicUrl !== "string") {
        return reject(new Error(clip(reply?.error?.message ?? "Run hyp deploy webhook to inspect Funnel prerequisites.", 200)));
      }
      resolve(reply.data.publicUrl);
    });
  });
}

/**
 * Signed webhook receiver for hub or tunnel deployments. Binds
 * `<PREFIX>_WEBHOOK_HOST` (default `127.0.0.1`) : `<PREFIX>_WEBHOOK_PORT` and
 * serves POST `<PREFIX>_WEBHOOK_PATH`. There is no unsigned mode: `verify`
 * must return true for the raw body before `handle` ever parses it.
 *
 * `preVerify(raw, parsed)` is an optional hook for providers with an unsigned
 * setup handshake (Notion); returning true answers 200 without publishing.
 *
 * `<PREFIX>_WEBHOOK_FUNNEL=443|8443|10000` additionally asks the local Tailscale client to
 * expose this path on a dedicated HTTPS port and logs the resulting URL. The host helper
 * preserves the receiver path. A failed Funnel setup leaves the signed listener on loopback.
 */
export function startWebhookServer({ prefix, name, defaultPort, defaultPath, maxBodyBytes = 1_048_576, verify, handle, preVerify }) {
  const host = envString(`${prefix}_WEBHOOK_HOST`, "127.0.0.1");
  const port = envInt(`${prefix}_WEBHOOK_PORT`, defaultPort, { min: 0, max: 65_535 });
  const path = envString(`${prefix}_WEBHOOK_PATH`, defaultPath);
  if (!/^\/[A-Za-z0-9._~/-]*$/.test(path)) throw new Error(`${prefix}_WEBHOOK_PATH must be an absolute URL path (got '${clip(path, 60)}')`);
  const funnelPort = envString(`${prefix}_WEBHOOK_FUNNEL`);
  if (funnelPort) {
    if (!FUNNEL_PORTS.has(funnelPort)) throw new Error(`${prefix}_WEBHOOK_FUNNEL must be 443, 8443 or 10000 (got '${clip(funnelPort, 20)}')`);
    if (host !== "127.0.0.1") throw new Error(`${prefix}_WEBHOOK_FUNNEL requires the listener to stay on loopback (${prefix}_WEBHOOK_HOST is '${clip(host, 60)}')`);
  }
  const reply = (res, status, body) => res.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify(body));

  const server = createServer(async (req, res) => {
    try {
      const requestPath = (req.url ?? "").split("?")[0];
      if (requestPath !== path) return reply(res, 404, { error: "not_found" });
      if (req.method === "OPTIONS") return res.writeHead(204, { "x-hyphae-webhook-receiver": "signed" }).end();
      if (req.method !== "POST") return reply(res, 404, { error: "not_found" });
      const chunks = [];
      let bytes = 0;
      for await (const chunk of req) {
        bytes += chunk.length;
        if (bytes > maxBodyBytes) return reply(res, 413, { error: "too_large" });
        chunks.push(chunk);
      }
      const raw = Buffer.concat(chunks);
      let parsed = null;
      if (preVerify) {
        try {
          parsed = JSON.parse(raw.toString("utf8"));
        } catch {
          parsed = null;
        }
        if (parsed && (await preVerify(raw, parsed))) return reply(res, 200, { status: "setup" });
      }
      if (!verify(raw, req.headers)) return reply(res, 401, { error: "bad_signature" });
      if (parsed === null) {
        try {
          parsed = JSON.parse(raw.toString("utf8"));
        } catch {
          return reply(res, 400, { error: "invalid_json" });
        }
      }
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return reply(res, 400, { error: "invalid_json" });
      const status = await handle(parsed, raw, req.headers);
      return reply(res, 202, { status: status ?? "ignored" });
    } catch (error) {
      console.error(`${name} webhook error: ${error instanceof Error ? error.message : String(error)}`);
      if (!res.headersSent) reply(res, 503, { error: "unavailable" });
    }
  });

  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => {
      const bound = server.address();
      console.error(`${name} plugin webhook listening on http://${host}:${bound.port}${path}`);
      if (funnelPort) {
        tailscaleFunnel({ funnelPort, localPort: bound.port, path })
          .then((url) => console.error(`${name} plugin public webhook URL (Tailscale Funnel): ${url}`))
          .catch((error) => console.error(`${name} plugin could not enable Tailscale Funnel (listener stays local-only): ${error.message}`));
      }
      resolve({ server, port: bound.port, path });
    });
  });
}
