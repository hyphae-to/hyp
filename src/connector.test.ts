import assert from "node:assert/strict";
import { once } from "node:events";
import { createServer, type ServerResponse } from "node:http";
import { test } from "node:test";
import { Connector } from "./connector.ts";
import { delivered } from "./protocol.ts";
import { State } from "./state.ts";

test("sessions share router enrollment but keep handles and inbox acknowledgement independent", { timeout: 5000 }, async () => {
  const acked: unknown[] = [];
  const handleSets: unknown[] = [];
  let connected: (response: ServerResponse) => void = () => {};
  const inbox = new Promise<ServerResponse>((resolve) => { connected = resolve; });
  const lifecycle = new AbortController();
  const server = createServer(async (request, response) => {
    if (request.url === "/v1/inbox") {
      response.writeHead(200, { "content-type": "text/event-stream" });
      response.flushHeaders();
      connected(response);
      return;
    }
    const received: Buffer[] = [];
    for await (const chunk of request) received.push(Buffer.from(chunk));
    if (request.url === "/v1/messages/item/ack") acked.push(JSON.parse(Buffer.concat(received).toString()));
    if (request.url === "/v1/handles") handleSets.push(JSON.parse(Buffer.concat(received).toString()).handles);
    response.writeHead(200, { "content-type": "application/json" });
    response.end('{"unknownTopics":[]}');
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const serverAddress = server.address();
  assert.ok(serverAddress && typeof serverAddress === "object");
  const state = new State(":memory:", "test");
  state.register("a", { kind: "claude" });
  state.register("b", { kind: "claude" });
  const connector = new Connector({
    connectorId: "receiver", directory: "unused",
    routers: [{ name: "primary", url: `http://127.0.0.1:${serverAddress.port}`, token: "scratch" }],
  }, state, () => undefined);
  const loop = connector.run(lifecycle.signal);
  try {
    const stream = await inbox;
    assert.deepEqual(await connector.call("a", "hyp_join", { handle: "me" }), { address: "receiver/me" });
    assert.deepEqual(await connector.call("b", "hyp_join", { handle: "other" }), { address: "receiver/other" });
    await assert.rejects(connector.call("b", "hyp_join", { handle: "me" }), /belongs to another session/);
    assert.deepEqual(handleSets, [[], ["me"], ["me", "other"]]);
    const args = { key: "watch:ci", topic: "github", filters: [] };
    await connector.call("a", "hyp_subscribe", args);
    await connector.call("b", "hyp_subscribe", args);
    assert.equal(state.subscriptions().length, 2);
    const item = { id: "item", kind: "message", from: "sender/peer", to: "receiver/me", text: "hello" };
    const frame = `data: ${JSON.stringify(item)}\n\n`;
    for (let count = 1; count <= 2; count++) {
      stream.write(frame);
      await new Promise<void>((resolve, reject) => {
        const deadline = Date.now() + 1500;
        const wait = setInterval(() => {
          if (acked.length === count || Date.now() > deadline) {
            clearInterval(wait);
            if (acked.length === count) resolve();
            else reject(new Error("No acknowledgement from connector"));
          }
        }, 10);
      });
    }
    const mailbox = await connector.call("a", "hyp_inbox", {}) as { items: { receipt: string }[] };
    assert.equal(mailbox.items.length, 1);
    const [itemReceipt] = mailbox.items;
    assert.ok(itemReceipt);
    assert.deepEqual(await connector.call("b", "hyp_inbox", { acknowledge: [itemReceipt.receipt] }), { deliveryMode: "full", unread: 0, items: [] });
    assert.deepEqual(await connector.call("a", "hyp_inbox", {}), mailbox);
    assert.deepEqual(await connector.call("a", "hyp_inbox", { acknowledge: [itemReceipt.receipt] }), { deliveryMode: "full", unread: 0, items: [] });
    assert.deepEqual(acked, [delivered, delivered]);
  } finally {
    lifecycle.abort();
    server.closeAllConnections();
    server.close();
    await loop;
    await connector.drain();
    state.close();
  }
});
