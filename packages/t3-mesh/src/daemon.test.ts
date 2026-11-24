import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import type { Duplex } from "node:stream";
import * as Schema from "effect/Schema";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { daemonMetadata } from "./mcp/shim.ts";
import { primaryLinkOptions } from "./daemon.ts";

async function listen(server: Server): Promise<string> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("missing HTTP address");
  return `http://127.0.0.1:${address.port}`;
}

test("daemon completes the T3 handshake and starts primary inbox while an extra PUT stalls", { timeout: 8000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "t3-mesh-daemon-startup-"));
  const extraPut = Promise.withResolvers<void>();
  const primaryInbox = Promise.withResolvers<void>();
  let primaryPuts = 0;
  let extraHandles = 0;
  const primary = createServer((request, response) => {
    if (request.url === "/v1/subscriptions") primaryPuts += 1;
    request.resume();
    if (request.url === "/v1/inbox") {
      response.writeHead(200, { "content-type": "text/event-stream" });
      response.write(": connected\n\n");
      primaryInbox.resolve();
      return;
    }
    response.setHeader("content-type", "application/json");
    response.end('{"unknownTopics":[]}');
  });
  const extra = createServer((request, response) => {
    if (request.url === "/v1/subscriptions") { extraPut.resolve(); request.resume(); return; }
    if (request.url === "/v1/handles") extraHandles += 1;
    response.end("{}");
  });
  // Minimal T3 transport fixture: real HTTP auth-ticket exchange, WebSocket upgrade and RPC
  // shell snapshot. The primary inbox cannot open until T3Connection accepts this handshake.
  const upgraded: Duplex[] = [];
  const descriptor = { environmentId: "env", label: "test", platform: { os: "linux", arch: "x64" },
    serverVersion: "test", capabilities: { repositoryIdentity: true }, orchestrationProtocolVersion: 2 };
  const t3 = createServer((request, response) => {
    if (request.url === "/.well-known/t3/environment") response.end(JSON.stringify(descriptor));
    else if (request.url === "/api/auth/websocket-ticket") response.end('{"ticket":"test-ticket"}');
    else response.writeHead(404).end();
  });
  t3.on("upgrade", (request, socket) => {
    upgraded.push(socket);
    const accept = createHash("sha1").update(`${request.headers["sec-websocket-key"]}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`).digest("base64");
    socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`);
    let buffer = Buffer.alloc(0);
    socket.on("data", (chunk: Buffer) => {
      buffer = Buffer.concat([buffer, chunk]);
      while (buffer.length >= 2) {
        const opcode = buffer[0]! & 0x0f;
        const short = buffer[1]! & 0x7f;
        const headerSize = short === 126 ? 4 : 2;
        if (buffer.length < headerSize) return;
        const size = short === 126 ? buffer.readUInt16BE(2) : short;
        if (buffer.length < headerSize + 4 + size) return;
        const mask = buffer.subarray(headerSize, headerSize + 4);
        const payload = Buffer.from(buffer.subarray(headerSize + 4, headerSize + 4 + size));
        buffer = buffer.subarray(headerSize + 4 + size);
        if (opcode === 8) { socket.destroy(); return; }
        if (opcode !== 1) continue;
        for (let i = 0; i < payload.length; i++) payload[i] = payload[i]! ^ mask[i % 4]!;
        const rpc = Schema.decodeUnknownOption(Schema.Struct({ _tag: Schema.Literal("Request"), id: Schema.Union([Schema.String, Schema.Number]), tag: Schema.String }))(JSON.parse(payload.toString()));
        if (rpc._tag === "None" || rpc.value.tag !== "orchestration.subscribeShell") continue;
        const data = Buffer.from(JSON.stringify({ _tag: "Chunk", requestId: rpc.value.id, values: [{ kind: "snapshot",
          snapshot: { schemaVersion: 1, snapshotSequence: 1, threads: [], archivedThreads: [], projects: [] },
        }] }));
        const frame = Buffer.alloc(4);
        frame[0] = 0x81;
        frame[1] = 126;
        frame.writeUInt16BE(data.length, 2);
        socket.write(Buffer.concat([frame, data]));
      }
    });
  });
  const servers = [primary, extra, t3];
  const [primaryUrl, extraUrl, t3Url] = await Promise.all(servers.map(listen));
  writeFileSync(join(dir, "router.token"), "test-primary", { mode: 0o600 });
  writeFileSync(join(dir, "extra.token"), "test-extra", { mode: 0o600 });
  writeFileSync(join(dir, "t3-token.json"), JSON.stringify({ token: "test-t3", expiresAt: new Date(Date.now() + 30 * 86400_000).toISOString() }), { mode: 0o600 });
  writeFileSync(join(dir, "config.json"), JSON.stringify({
    connectorId: "test@host", t3: { url: t3Url, home: dir }, router: { mode: "http", url: primaryUrl, tokenFile: "router.token" },
    eventRouters: [{ name: "private", url: extraUrl, tokenFile: "extra.token" }],
  }));
  const child = spawn(process.execPath, [new URL("./cli.ts", import.meta.url).pathname, "daemon", "--config", join(dir, "config.json")], { stdio: ["ignore", "ignore", "pipe"] });
  let log = "";
  child.stderr.on("data", (chunk: Buffer) => { log += chunk.toString(); });
  const deadline = Promise.withResolvers<never>();
  const timer = setTimeout(() => deadline.reject(new Error(`daemon startup stalled: ${log}`)), 5000);
  try {
    const stopped = once(child, "exit").then(() => { throw new Error(`daemon exited during startup: ${log}`); });
    await Promise.race([Promise.all([extraPut.promise, primaryInbox.promise]), stopped, deadline.promise]);
    assert.ok(primaryPuts > 0, "primary synchronization completed while the extra request remained unanswered");
    assert.equal(extraHandles, 0);
    const metadata = await daemonMetadata(join(dir, "daemon.sock"));
    assert.match(metadata.instructions, /Event routers: primary \(default\), private/);
  } finally {
    clearTimeout(timer);
    if (child.exitCode === null && child.signalCode === null) { child.kill("SIGTERM"); await once(child, "exit"); }
    await Promise.all(servers.map((server) => new Promise<void>((resolve) => {
      if (server === t3) for (const socket of upgraded) socket.destroy();
      server.closeAllConnections();
      server.close(() => resolve());
    })));
    rmSync(dir, { recursive: true, force: true });
  }
});

// client.test.ts proves rejectRedirects blocks the 307; this pins which configs turn it on.
test("primary link rejects redirects only when event routers are configured", () => {
  assert.equal(primaryLinkOptions({}).rejectRedirects, false);
  assert.equal(primaryLinkOptions({ eventRouters: [] }).rejectRedirects, false);
  assert.equal(primaryLinkOptions({ eventRouters: [{ name: "private", url: "http://127.0.0.1:8793", token: "t" }] }).rejectRedirects, true);
});
