import { test } from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { HttpRouterLink } from "./client.ts";
import { RouterCore } from "./core.ts";
import { serveRouter } from "./server.ts";
import type { InboundEventBatch, InboundMessage, InboundOutcome, InboxItem } from "./types.ts";

const waitFor = async (condition: () => boolean, timeoutMs = 5000) => {
  const deadline = Date.now() + timeoutMs;
  while (!condition()) {
    if (Date.now() > deadline) throw new Error("timed out");
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
};

test("routes between two connectors over HTTP, with store-and-forward", async () => {
  const core = new RouterCore({ dbPath: ":memory:" });
  const router = await serveRouter({ core, host: "127.0.0.1", port: 0 });
  const a = new HttpRouterLink(router.url, core.addConnector("a@host"));
  const b = new HttpRouterLink(router.url, core.addConnector("b@host"));
  try {
    await a.setHandles(["alpha"]);
    await b.setHandles(["beta"]);

    // b is not listening yet: the message is stored.
    const origin = { environmentId: "env-a", threadId: "thread-1" };
    const sent = await a.send({ id: "m1", fromHandle: "alpha", to: "b@host/beta", text: "hello", origin });
    assert.deepEqual(sent, { ok: true, status: "stored" });

    const received: InboundMessage[] = [];
    let outcome: InboundOutcome = { kind: "hold", reason: "not ready" };
    b.start(async (item) => {
      if (item.kind === "message") received.push(item);
      return outcome;
    });
    await waitFor(() => received.length === 1);
    assert.equal(received[0]?.from, "a@host/alpha");
    assert.equal(received[0]?.text, "hello");
    assert.deepEqual(received[0]?.origin, origin);

    // Held: not offered again before the hold retry time.
    outcome = { kind: "delivered" };
    core.tick();
    assert.equal(received.length, 1);

    const peers = await a.peers();
    assert.deepEqual(
      peers.map((peer) => [peer.address, peer.online]),
      [
        ["a@host/alpha", false],
        ["b@host/beta", true],
      ],
    );

    const spoof = await a.send({ id: "m2", fromHandle: "beta", to: "b@host/beta", text: "x", origin: null });
    assert.equal(spoof.ok ? "ok" : spoof.error, "invalid");
    const unknown = await a.send({ id: "m3", fromHandle: "alpha", to: "b@host/nobody", text: "x", origin: null });
    assert.equal(unknown.ok ? "ok" : unknown.error, "unknown_recipient");

    const bad = new HttpRouterLink(router.url, "t3m_wrong");
    const unauthorized = await bad.send({ id: "m4", fromHandle: "alpha", to: "b@host/beta", text: "x", origin: null });
    assert.equal(unauthorized.ok, false);
  } finally {
    await a.stop();
    await b.stop();
    await router.close();
    core.close();
  }
});

test("publishes events over HTTP and delivers batches on the inbox stream", async () => {
  const hub = "github-hub@bayfold-co-ops";
  const core = new RouterCore({ dbPath: ":memory:", topics: new Map([["github", [hub]]]) });
  const router = await serveRouter({ core, host: "127.0.0.1", port: 0 });
  const connectorToken = core.addConnector("b@host");
  const publisherToken = core.events.addPublisher(hub, ["github"]);
  const call = (method: string, path: string, token: string | null, body?: unknown) =>
    fetch(`${router.url}${path}`, {
      method,
      headers: {
        ...(token === null ? {} : { authorization: `Bearer ${token}` }),
        "content-type": "application/json",
      },
      ...(body === undefined ? {} : { body: typeof body === "string" ? body : JSON.stringify(body) }),
    });
  const event = (id: string, data: Record<string, unknown> = {}) => ({
    specversion: "1.0",
    id,
    source: "github.com/bayfold/infra",
    type: "com.github.ping",
    datacontenttype: "application/json",
    data: { number: null, ...data },
  });
  try {
    const subscriptionId = "6f0c1e9e-6a59-4b8e-9d6e-2b7b8f3f0c11";
    const put = await call("PUT", "/v1/subscriptions", connectorToken, {
      subscriptions: [{ id: subscriptionId, topic: "github", filters: [], coalesceSeconds: 0 }],
    });
    assert.equal(put.status, 200);
    assert.deepEqual(await put.json(), { subscriptions: 1, unknownTopics: [] });
    const badFilter = await call("PUT", "/v1/subscriptions", connectorToken, {
      subscriptions: [{ id: subscriptionId, topic: "github", filters: [{ exact: {} }], coalesceSeconds: 0 }],
    });
    assert.equal(badFilter.status, 400);
    assert.deepEqual(await badFilter.json(), {
      error: "invalid_filter",
      message: "expected an object of attribute: string, with at least one key",
      id: subscriptionId,
      path: "filters[0].exact",
    });

    const published = await call("POST", "/v1/events?topic=github", publisherToken, event("d1"));
    assert.equal(published.status, 202);
    assert.deepEqual(await published.json(), { status: "stored", matched: 1 });
    const again = await call("POST", "/v1/events?topic=github", publisherToken, event("d1"));
    assert.equal(again.status, 202);
    const conflict = await call("POST", "/v1/events?topic=github", publisherToken, event("d1", { number: 2 }));
    assert.equal(conflict.status, 409);
    assert.equal(((await conflict.json()) as { error: string }).error, "id_conflict");

    const statuses = async (path: string, token: string | null, body: unknown = event("d2")) =>
      (await call("POST", path, token, body)).status;
    assert.equal(await statuses("/v1/events?topic=github", null), 401);
    assert.equal(await statuses("/v1/events?topic=github", "t3p_wrong"), 401);
    assert.equal(await statuses("/v1/events?topic=github", connectorToken), 403, "connector tokens cannot publish");
    // Grant before topic: an ungranted topic is 403 whether or not it exists.
    assert.equal(await statuses("/v1/events?topic=gitlab", publisherToken), 403);
    assert.equal(await statuses("/v1/events", publisherToken), 403);
    const gitlabToken = core.events.addPublisher("gitlab-hub@host", ["gitlab"]);
    assert.equal(await statuses("/v1/events?topic=gitlab", gitlabToken), 404, "granted but not configured");
    const notJson = await call("POST", "/v1/events?topic=github", publisherToken, "{not json");
    assert.equal(notJson.status, 400);
    assert.equal(((await notJson.json()) as { error: string }).error, "invalid_event");
    assert.equal(await statuses("/v1/events?topic=github", publisherToken, { ...event("d2"), data: [] }), 400);
    assert.equal(await statuses("/v1/events?topic=github", publisherToken, event("d2", { text: "x".repeat(9000) })), 413);
    assert.equal(await statuses("/v1/events?topic=github", publisherToken, event("d2", { text: "x".repeat(40_000) })), 413);
    // Publisher tokens can do nothing else.
    assert.equal((await call("GET", "/v1/peers", publisherToken)).status, 401);
    assert.equal((await call("PUT", "/v1/subscriptions", publisherToken, { subscriptions: [] })).status, 401);
    assert.equal((await call("GET", "/v1/inbox", publisherToken)).status, 401);
    assert.equal((await call("PUT", "/v1/handles", publisherToken, { handles: ["x"] })).status, 401);
    assert.equal((await call("POST", "/v1/messages", publisherToken, { id: "m", fromHandle: "x", to: "b@host/x", text: "x" })).status, 401);
    assert.equal((await call("POST", "/v1/messages/m/ack", publisherToken, { outcome: "delivered" })).status, 401);

    const response = await call("GET", "/v1/inbox", connectorToken);
    assert.ok(response.body !== null);
    const reader = response.body.pipeThrough(new TextDecoderStream()).getReader();
    let text = "";
    while (!/event: event\ndata: .*\n\n/.test(text)) {
      const chunk = await reader.read();
      if (chunk.done) break;
      text += chunk.value;
    }
    const data = /event: event\ndata: (.*)\n\n/.exec(text)?.[1];
    const item = JSON.parse(data ?? "null") as { kind: string; id: string; subscriptionId: string; events: { id: string }[] };
    assert.equal(item.kind, "event");
    assert.equal(item.subscriptionId, subscriptionId);
    assert.deepEqual(
      item.events.map((delivered) => delivered.id),
      ["d1"],
    );
    const ack = await call("POST", `/v1/messages/${item.id}/ack`, connectorToken, { outcome: "delivered" });
    assert.equal(ack.status, 200);
    await reader.cancel();
  } finally {
    await router.close();
    core.close();
  }
});

test("the router keeps serving when another connection holds the write lock past a tick", async () => {
  const dir = mkdtempSync(join(tmpdir(), "t3-mesh-lock-"));
  const dbPath = join(dir, "router.db");
  const hub = "github-hub@bayfold-co-ops";
  const core = new RouterCore({ dbPath, topics: new Map([["github", [hub]]]) });
  const router = await serveRouter({ core, host: "127.0.0.1", port: 0 });
  const publisher = core.events.addPublisher(hub, ["github"]);
  core.addConnector("b@host");
  core.events.setSubscriptions("b@host", [{ id: randomUUID(), topic: "github", filters: [], coalesceSeconds: 1 }]);
  const batches: InboundEventBatch[] = [];
  const detach = core.attach("b@host", (item) => {
    if (item.kind === "event") batches.push(item);
  });
  const other = new DatabaseSync(dbPath);
  try {
    const event = {
      specversion: "1.0",
      id: "d1",
      source: "github.com/bayfold/infra",
      type: "com.github.ping",
      datacontenttype: "application/json",
      data: {},
    };
    const published = await fetch(`${router.url}/v1/events?topic=github`, {
      method: "POST",
      headers: { authorization: `Bearer ${publisher}`, "content-type": "application/json" },
      body: JSON.stringify(event),
    });
    assert.equal(published.status, 202);
    // The window ends while the lock is held: at least one tick waits out the busy timeout and fails.
    other.exec("BEGIN IMMEDIATE");
    await new Promise((resolve) => setTimeout(resolve, 3_500));
    assert.equal(batches.length, 0);
    other.exec("ROLLBACK");
    await waitFor(() => batches.length === 1);
    assert.equal((await fetch(`${router.url}/v1/peers`)).status, 401, "still serving");
  } finally {
    other.close();
    detach();
    await router.close();
    core.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a stopped link shows offline and receives what was stored once started again", async () => {
  const core = new RouterCore({ dbPath: ":memory:" });
  const router = await serveRouter({ core, host: "127.0.0.1", port: 0 });
  const a = new HttpRouterLink(router.url, core.addConnector("a@host"));
  const b = new HttpRouterLink(router.url, core.addConnector("b@host"));
  const online = async () => (await a.peers()).find((peer) => peer.address === "b@host/beta")?.online;
  const received: string[] = [];
  const deliver = async (item: InboxItem): Promise<InboundOutcome> => {
    if (item.kind === "message") received.push(item.text);
    return { kind: "delivered" };
  };
  try {
    await a.setHandles(["alpha"]);
    await b.setHandles(["beta"]);
    b.start(deliver);
    b.start(deliver); // a second start is a no-op
    await waitFor(() => core.peers().some((peer) => peer.address === "b@host/beta" && peer.online));

    await b.stop();
    await waitFor(() => core.peers().some((peer) => peer.address === "b@host/beta" && !peer.online));
    assert.equal(await online(), false);
    await a.send({ id: "m1", fromHandle: "alpha", to: "b@host/beta", text: "while stopped", origin: null });
    await new Promise((resolve) => setTimeout(resolve, 200));
    assert.deepEqual(received, []);

    b.start(deliver);
    await waitFor(() => received.length === 1);
    assert.deepEqual(received, ["while stopped"]);
    assert.equal(await online(), true);
  } finally {
    await a.stop();
    await b.stop();
    await router.close();
    core.close();
  }
});
