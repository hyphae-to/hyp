import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { decodeInboxItem, HttpRouterLink } from "./client.ts";

const message = { id: "m1", from: "a@host/alpha", to: "b@host/beta", text: "hi", sentAt: "2026-10-07T00:00:00Z" };

test("items without kind, or kind message, are messages", () => {
  assert.deepEqual(decodeInboxItem(message), { kind: "message", ...message, origin: null });
  assert.deepEqual(decodeInboxItem({ kind: "message", ...message }), { kind: "message", ...message, origin: null });
});

test("event batches keep only valid CloudEvents", () => {
  const event = {
    specversion: "1.0",
    id: "d1",
    source: "github.com/bayfold/infra",
    type: "com.github.ping",
    datacontenttype: "application/json",
    data: {},
  };
  const item = decodeInboxItem({
    kind: "event",
    id: "b1",
    subscriptionId: "s1",
    topic: "github",
    events: [event, { ...event, data: "not an object" }, null],
    sentAt: "2026-10-07T00:00:00Z",
  });
  assert.equal(item.kind, "event");
  assert.deepEqual(item.kind === "event" ? item.events : null, [event]);
  assert.throws(() => decodeInboxItem({ kind: "event", id: "b1" }));
});

/** A stand-in router: `inbox` writes the SSE stream; acks are recorded. A route answering null hangs. */
const fakeRouter = async (routes: (request: IncomingMessage, response: ServerResponse) => boolean) => {
  const server = createServer((request, response) => {
    void routes(request, response);
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  const port = typeof address === "object" && address !== null ? address.port : 0;
  return {
    url: `http://127.0.0.1:${port}`,
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
};

const readBody = async (request: IncomingMessage): Promise<string> => {
  let text = "";
  for await (const chunk of request) text += String(chunk);
  return text;
};

test("router requests time out instead of hanging", async () => {
  const router = await fakeRouter(() => true); // accepts and never answers
  const link = new HttpRouterLink(router.url, "t3m_x", { requestTimeoutMs: 200 });
  try {
    const started = Date.now();
    const synced = await link.setSubscriptions([]);
    assert.equal(synced.ok ? "ok" : synced.error, "router_unavailable");
    assert.ok(Date.now() - started < 2_000);
  } finally {
    await router.close();
  }
});

test("an inbox item the connector cannot decode is rejected, so it does not block its queue", async () => {
  const acks: Array<{ id: string; body: unknown }> = [];
  const router = await fakeRouter((request, response) => {
    const ack = /^\/v1\/messages\/([^/]+)\/ack$/.exec(request.url ?? "");
    if (request.url === "/v1/inbox") {
      response.writeHead(200, { "content-type": "text/event-stream" });
      response.write(`event: event\ndata: ${JSON.stringify({ kind: "event", id: "b1", topic: "github" })}\n\n`);
      response.write(`event: message\ndata: ${JSON.stringify({ id: "m1", text: 5 })}\n\n`);
      response.write("event: message\ndata: {not json\n\n");
      return true;
    }
    void readBody(request).then((body) => {
      if (ack?.[1] !== undefined) acks.push({ id: decodeURIComponent(ack[1]), body: JSON.parse(body) });
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ unknownTopics: [] }));
    });
    return true;
  });
  const link = new HttpRouterLink(router.url, "t3m_x");
  const delivered: string[] = [];
  try {
    link.start(async (item) => {
      delivered.push(item.id);
      return { kind: "delivered" };
    });
    const deadline = Date.now() + 5_000;
    while (acks.length < 2 && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 20));
    assert.deepEqual(
      acks.sort((a, b) => a.id.localeCompare(b.id)),
      [
        { id: "b1", body: { outcome: "rejected", reason: "undecodable" } },
        { id: "m1", body: { outcome: "rejected", reason: "undecodable" } },
      ],
    );
    assert.deepEqual(delivered, []);
  } finally {
    await link.stop();
    await router.close();
  }
});

test("subscription PUTs serialize reconnect replay with newer desired sets before timeout", async () => {
  const replayStarted = Promise.withResolvers<void>();
  const releaseReplay = Promise.withResolvers<void>();
  const puts: unknown[] = [];
  let applied: unknown;
  const router = await fakeRouter((request, response) => {
    if (request.url === "/v1/inbox") {
      response.writeHead(200, { "content-type": "text/event-stream" });
      response.write(": connected\n\n");
      return true;
    }
    void (async () => {
      const body: unknown = JSON.parse(await readBody(request));
      if (request.url === "/v1/subscriptions") {
        puts.push(body);
        if (puts.length === 2) {
          replayStarted.resolve();
          await releaseReplay.promise;
        }
        applied = body;
      }
      response.writeHead(200, { "content-type": "application/json" }).end('{"unknownTopics":[]}');
    })();
    return true;
  });
  const link = new HttpRouterLink(router.url, "t3m_x");
  const spec = (id: string) => [{ id, topic: "github", filters: [], coalesceSeconds: 0 }];
  try {
    await link.setSubscriptions(spec("old"));
    link.start(async () => ({ kind: "delivered" }));
    await replayStarted.promise;
    const newer = link.setSubscriptions(spec("newer"));
    const latest = link.setSubscriptions(spec("latest"));
    assert.equal(puts.length, 2, "tool writes stay queued behind the reconnect replay");
    releaseReplay.resolve();
    await Promise.all([newer, latest]);
    assert.deepEqual(applied, { subscriptions: spec("latest") });
    assert.deepEqual(puts, [
      { subscriptions: spec("old") }, { subscriptions: spec("old") },
      { subscriptions: spec("latest") }, { subscriptions: spec("latest") },
    ], "queued writes read the current desired set on starting");
  } finally {
    releaseReplay.resolve();
    await link.stop();
    await router.close();
  }
});

test("event-only links reconnect after stream closure without any handle writes", async () => {
  const reconnected = Promise.withResolvers<void>();
  const paths: string[] = [];
  let inboxes = 0;
  const router = await fakeRouter((request, response) => {
    paths.push(request.url ?? "");
    if (request.url === "/v1/inbox") {
      inboxes += 1;
      response.writeHead(200, { "content-type": "text/event-stream" });
      response.write(": connected\n\n");
      if (inboxes === 1) response.end();
      else reconnected.resolve();
    } else response.writeHead(200, { "content-type": "application/json" }).end('{"unknownTopics":[]}');
    return true;
  });
  const link = new HttpRouterLink(router.url, "t3m_x", { name: "private", eventOnly: true });
  try {
    await link.setHandles(["must-not-register"]);
    link.start(async () => ({ kind: "delivered" }));
    await reconnected.promise;
    assert.equal(inboxes, 2);
    assert.deepEqual(paths, ["/v1/subscriptions", "/v1/inbox", "/v1/subscriptions", "/v1/inbox"]);
  } finally {
    await link.stop();
    await router.close();
  }
});

test("links with event routing reject redirects; primary-only follows as before", async () => {
  let forwarded = 0;
  const destination = await fakeRouter((request, response) => {
    forwarded += 1;
    request.resume();
    response.writeHead(200, { "content-type": "application/json" }).end('{"unknownTopics":[]}');
    return true;
  });
  const redirector = await fakeRouter((request, response) => {
    request.resume();
    response.writeHead(307, { location: `${destination.url}${request.url ?? "/"}` }).end();
    return true;
  });
  const extra = new HttpRouterLink(redirector.url, "t3m_extra", { name: "private", eventOnly: true });
  const primary = new HttpRouterLink(redirector.url, "t3m_primary");
  const guardedPrimary = new HttpRouterLink(redirector.url, "t3m_primary", { rejectRedirects: true });
  try {
    const set = [{ id: "private-subscription", topic: "github", filters: [{ exact: { repo: "bowd/private" } }], coalesceSeconds: 0 }];
    const failed = await extra.setSubscriptions(set);
    assert.equal(failed.ok ? "ok" : failed.error, "router_unavailable");
    assert.equal(await extra.subscriptionStatus(), null);
    await assert.rejects(extra.peers());
    await assert.rejects(extra.fetchTransfer("private-transfer"));
    const transfer = await extra.sendTransfer({ payload: '{"id":"private-transfer"}', sig: "test" }, Buffer.from("test"));
    assert.equal(transfer.ok ? "ok" : transfer.error, "router_unavailable");
    const primaryRefused = await guardedPrimary.setSubscriptions(set);
    assert.equal(primaryRefused.ok ? "ok" : primaryRefused.error, "router_unavailable");
    assert.equal(forwarded, 0, "a primary link with event routers also rejects redirects");
    assert.equal((await primary.setSubscriptions(set)).ok, true);
    assert.equal(forwarded, 1, "primary redirect behavior is unchanged");
  } finally {
    await extra.stop();
    await primary.stop();
    await guardedPrimary.stop();
    await redirector.close();
    await destination.close();
  }
});
