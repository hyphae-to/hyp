import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import type { Duplex } from "node:stream";
import * as Schema from "effect/Schema";
import { OrchestrationV2ThreadShellJson, type OrchestrationV2ShellSnapshot } from "@t3tools/contracts";
import { applyShellItem, T3Connection, type ShellEntry } from "./connection.ts";

// A real thread shell entry recorded from stock T3 .2676.
const thread = Schema.decodeUnknownSync(OrchestrationV2ThreadShellJson)(
  JSON.parse(readFileSync(new URL("./fixtures/thread-shell.json", import.meta.url), "utf8")),
);

const emptySnapshot: OrchestrationV2ShellSnapshot = {
  schemaVersion: 1,
  snapshotSequence: 1,
  threads: [],
  archivedThreads: [],
  projects: [],
};

test("an enrichment snapshot does not clear threads", () => {
  const shell = new Map<string, ShellEntry>([[thread.id, { thread, location: "active" }]]);
  const ready = applyShellItem(shell, {
    kind: "snapshot",
    snapshot: emptySnapshot,
    resolvedRepositoryIdentityRoots: [],
  });
  assert.equal(ready, false);
  assert.equal(shell.size, 1);
});

test("an authoritative snapshot replaces threads", () => {
  const shell = new Map<string, ShellEntry>([[thread.id, { thread, location: "active" }]]);
  assert.equal(applyShellItem(shell, { kind: "snapshot", snapshot: emptySnapshot }), true);
  assert.equal(shell.size, 0);
  applyShellItem(shell, { kind: "snapshot", snapshot: { ...emptySnapshot, threads: [thread] } });
  assert.equal(shell.get(thread.id)?.location, "active");
});

const listen = async (server: Server): Promise<string> => {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
};

test("open gives up on a server that accepts but never answers", async () => {
  const server = createServer(() => {});
  try {
    const url = await listen(server);
    await assert.rejects(T3Connection.open(url, "token", 300), /no answer from T3 within 0.3s \(environment descriptor\)/);
  } finally {
    server.closeAllConnections();
    server.close();
  }
});

test("open gives up when the WebSocket opens but no shell snapshot arrives", async () => {
  const descriptor = {
    environmentId: "env",
    label: "test",
    platform: { os: "linux", arch: "x64" },
    serverVersion: "test",
    capabilities: { repositoryIdentity: true },
    orchestrationProtocolVersion: 2,
  };
  const server = createServer((request, response) => {
    if (request.url === "/.well-known/t3/environment") response.end(JSON.stringify(descriptor));
    else if (request.url === "/api/auth/websocket-ticket") response.end(JSON.stringify({ ticket: "ticket" }));
    else response.writeHead(404).end();
  });
  // Completes the WebSocket handshake, then stays silent, like a T3 still recovering. Upgraded
  // sockets are detached from the server, so they are destroyed explicitly below.
  const upgraded: Duplex[] = [];
  server.on("upgrade", (request, socket) => {
    upgraded.push(socket);
    const accept = createHash("sha1")
      .update(`${request.headers["sec-websocket-key"]}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`)
      .digest("base64");
    socket.write(
      `HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`,
    );
  });
  try {
    const url = await listen(server);
    await assert.rejects(T3Connection.open(url, "token", 1000), /no answer from T3 within 1s \(first shell snapshot\)/);
  } finally {
    for (const socket of upgraded) socket.destroy();
    server.closeAllConnections();
    server.close();
  }
});
