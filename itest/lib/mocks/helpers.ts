/**
 * Shared crypto, HTTP, polling, and port helpers for Phase 3 loopback wire-mocks
 * and black-box E2E suites (zero external dependencies, Node 24+ ESM).
 */

import crypto from "node:crypto";
import type http from "node:http";
import net from "node:net";

/** Computes lowercase hex HMAC (`sha256` or `sha1`) over raw UTF-8 string or Buffer. */
export function hmacHex(
  algorithm: "sha256" | "sha1",
  secret: string | Buffer,
  raw: string | Buffer,
): string {
  return crypto.createHmac(algorithm, secret).update(raw).digest("hex");
}

/** Computes lowercase hex SHA-256 over one or more UTF-8 strings or Buffers. */
export function sha256Hex(...parts: Array<string | Buffer>): string {
  const hash = crypto.createHash("sha256");
  for (const part of parts) hash.update(part);
  return hash.digest("hex");
}

/**
 * Mutates an otherwise valid hex signature (with or without a prefix like `sha256=`)
 * by flipping the lowest bit of the final hex nibble.
 */
export function flipHexBit(sig: string): string {
  if (!sig || sig.length === 0) return "0";
  const last = sig.at(-1)!;
  const parsed = Number.parseInt(last, 16);
  if (Number.isNaN(parsed)) {
    return `${sig.slice(0, -1)}0`;
  }
  return `${sig.slice(0, -1)}${(parsed ^ 1).toString(16)}`;
}

/** Reads an incoming HTTP request body into a raw Buffer (bounded to 16 MiB). */
export async function readHttpBody(
  req: http.IncomingMessage,
  maxBytes = 16 * 1024 * 1024,
): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of req) {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    total += buf.length;
    if (total > maxBytes) {
      throw new Error(`Mock server body exceeded ${maxBytes} bytes`);
    }
    chunks.push(buf);
  }
  return Buffer.concat(chunks);
}

/** Writes a JSON HTTP response with optional extra headers. */
export function writeJson(
  res: http.ServerResponse,
  status: number,
  body: unknown,
  headers: Record<string, string> = {},
): void {
  const raw = JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": String(Buffer.byteLength(raw)),
    ...headers,
  });
  res.end(raw);
}

/** Reserves a free loopback TCP port on `127.0.0.1` and releases it immediately. */
export function getFreePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.unref();
    srv.once("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const addr = srv.address();
      const port = typeof addr === "object" && addr ? addr.port : 0;
      srv.close((err) => (err ? reject(err) : resolve(port)));
    });
  });
}

/** Polls `predicate` until it returns a truthy value or throws on timeout. */
export async function waitUntil<T>(
  predicate: () => Promise<T | false | null | undefined> | T | false | null | undefined,
  label: string,
  timeoutMs = 15_000,
  intervalMs = 25,
): Promise<T> {
  const deadline = Date.now() + timeoutMs;
  let lastErr: unknown;
  while (Date.now() < deadline) {
    try {
      const val = await predicate();
      if (val) return val;
    } catch (err) {
      lastErr = err;
    }
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  const suffix = lastErr ? ` (lastErr=${String(lastErr)})` : "";
  throw new Error(`Timed out waiting for ${label} after ${timeoutMs}ms${suffix}`);
}

/** Cleanly closes a Node `http.Server` including all keep-alive connections. */
export function closeHttpServer(server: http.Server): Promise<void> {
  return new Promise((resolve) => {
    try {
      server.closeAllConnections?.();
    } catch {
      // ignore
    }
    server.close(() => resolve());
  });
}
