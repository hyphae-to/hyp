import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer as createHttpServer } from "node:http";
import { randomUUID } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { connect, createServer, type Socket } from "node:net";
import { RouterCore } from "../router/core.ts";
import { serveRouter } from "../router/server.ts";
import type { InboundEventBatch } from "../router/types.ts";
import { DEFAULT_RECEIVER_LIMITS, serveReceiver, type ReceiverLimits } from "./receiver.ts";
import { signatureHeader } from "./signature.ts";

const HUB = "github-hub@bayfold-co-ops";
const SECRET = "test webhook secret";

interface Fixture {
  readonly event: string;
  readonly delivery: string;
  readonly payload: unknown;
}
const fixturesDir = new URL("./fixtures/", import.meta.url);
const fixtures = readdirSync(fixturesDir)
  .filter((name) => name.endsWith(".json"))
  .map((name) => JSON.parse(readFileSync(new URL(name, fixturesDir), "utf8")) as Fixture);

const closedPort = () =>
  new Promise<number>((resolve) => {
    const server = createServer();
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      const port = typeof address === "object" && address !== null ? address.port : 0;
      server.close(() => resolve(port));
    });
  });

/** Opens a raw connection, so tests can send what fetch would not: malformed targets, lying lengths, nothing at all. */
const open = (url: string) =>
  new Promise<{ socket: Socket; received: () => string; closed: Promise<void> }>((resolve, reject) => {
    const { hostname, port } = new URL(url);
    let text = "";
    const socket = connect(Number(port), hostname);
    const closed = new Promise<void>((done) => socket.once("close", () => done()));
    socket.setEncoding("utf8");
    socket.on("data", (chunk: string) => {
      text += chunk;
    });
    socket.on("error", () => {});
    socket.once("connect", () => resolve({ socket, received: () => text, closed }));
    socket.once("error", reject);
  });

/** Sends raw bytes and returns everything received until the server closes the connection. */
const raw = async (url: string, request: string) => {
  const connection = await open(url);
  connection.socket.write(request);
  await connection.closed;
  return connection.received();
};

const statusOf = (response: string) => Number(/^HTTP\/1\.1 (\d{3})/.exec(response)?.[1] ?? 0);

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

const setup = async (limits?: ReceiverLimits) => {
  const core = new RouterCore({ dbPath: ":memory:", topics: new Map([["github", [HUB]]]) });
  const router = await serveRouter({ core, host: "127.0.0.1", port: 0 });
  const token = core.events.addPublisher(HUB, ["github"]);
  core.addConnector("b@host");
  core.events.setSubscriptions("b@host", [{ id: randomUUID(), topic: "github", filters: [], coalesceSeconds: 0 }]);
  const batches: InboundEventBatch[] = [];
  const detach = core.attach("b@host", (item) => {
    if (item.kind !== "event") return;
    batches.push(item);
    queueMicrotask(() => core.ack("b@host", item.id, { kind: "delivered" }));
  });
  const receiver = await serveReceiver({
    host: "127.0.0.1",
    port: 0,
    routerUrl: router.url,
    topic: "github",
    secret: SECRET,
    token,
    ...(limits === undefined ? {} : { limits }),
  });
  const post = (
    body: string | Buffer,
    headers: Record<string, string | undefined> = {},
    path = "/hooks/github",
  ) =>
    fetch(`${receiver.url}${path}`, {
      method: "POST",
      headers: Object.fromEntries(Object.entries(headers).filter((entry): entry is [string, string] => entry[1] !== undefined)),
      body: typeof body === "string" ? body : new Uint8Array(body),
    });
  const deliver = (fixture: Fixture, overrides: Record<string, string | undefined> = {}, payload: unknown = fixture.payload) => {
    const body = JSON.stringify(payload);
    return post(body, {
      "content-type": "application/json",
      "x-github-event": fixture.event,
      "x-github-delivery": fixture.delivery,
      "x-hub-signature-256": signatureHeader(SECRET, body),
      ...overrides,
    });
  };
  return {
    core,
    token,
    batches,
    post,
    deliver,
    receiverUrl: receiver.url,
    close: async () => {
      detach();
      await receiver.close();
      await router.close();
      core.close();
    },
  };
};

const fixtureFor = (event: string): Fixture => {
  const found = fixtures.find((fixture) => fixture.event === event);
  if (found === undefined) throw new Error(`no fixture for ${event}`);
  return found;
};

test("publishes every fixture through the router and answers 202", async () => {
  const { deliver, batches, close } = await setup();
  try {
    for (const fixture of fixtures) {
      const response = await deliver(fixture);
      assert.equal(response.status, 202, fixture.delivery);
    }
    const delivered = batches.flatMap((batch) => batch.events.map((event) => event.id));
    assert.deepEqual(delivered.sort(), fixtures.map((fixture) => fixture.delivery).sort());
    // No raw GitHub fields reach subscribers.
    assert.ok(batches.every((batch) => batch.events.every((event) => !("payload" in event.data) && !("zen" in event.data))));
  } finally {
    await close();
  }
});

test("redelivery is 202 again; different content under the same delivery ID is 200", async () => {
  const { deliver, batches, close } = await setup();
  try {
    const fixture = fixtureFor("ping");
    assert.equal((await deliver(fixture)).status, 202);
    assert.equal((await deliver(fixture)).status, 202);
    const changed = { ...(fixture.payload as Record<string, unknown>), sender: { login: "someone", type: "User" } };
    assert.equal((await deliver(fixture, {}, changed)).status, 200);
    await new Promise((resolve) => setTimeout(resolve, 20));
    assert.equal(batches.length, 1, "published once");
  } finally {
    await close();
  }
});

test("refuses bad or missing signatures with 401 and publishes nothing", async () => {
  const { deliver, post, batches, close } = await setup();
  try {
    const fixture = fixtureFor("pull_request");
    const body = JSON.stringify(fixture.payload);
    const headers = { "content-type": "application/json", "x-github-event": "pull_request", "x-github-delivery": fixture.delivery };
    assert.equal((await deliver(fixture, { "x-hub-signature-256": undefined })).status, 401);
    assert.equal((await deliver(fixture, { "x-hub-signature-256": signatureHeader("wrong", body) })).status, 401);
    assert.equal((await deliver(fixture, { "x-hub-signature-256": "sha1=0123" })).status, 401);
    assert.equal((await post(`${body} `, { ...headers, "x-hub-signature-256": signatureHeader(SECRET, body) })).status, 401);
    assert.equal(batches.length, 0);
  } finally {
    await close();
  }
});

test("answers 200 for events that are not published", async () => {
  const { deliver, batches, close } = await setup();
  try {
    const fixture = fixtureFor("pull_request");
    const edited = { ...(fixture.payload as Record<string, unknown>), action: "edited" };
    const response = await deliver(fixture, {}, edited);
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { status: "ignored" });
    assert.equal((await deliver({ ...fixture, event: "star" })).status, 200);
    assert.equal(batches.length, 0);
  } finally {
    await close();
  }
});

test("rejects other paths, methods, missing headers, other content types and oversized bodies", async () => {
  const { deliver, post, receiverUrl, close } = await setup();
  try {
    const fixture = fixtureFor("ping");
    assert.equal((await post("{}", {}, "/")).status, 404);
    assert.equal((await post("{}", {}, "/hooks/github/x")).status, 404);
    assert.equal((await fetch(`${receiverUrl}/hooks/github`)).status, 405);
    assert.equal((await deliver(fixture, { "x-github-event": undefined })).status, 400);
    assert.equal((await deliver(fixture, { "x-github-delivery": undefined })).status, 400);
    assert.equal((await deliver(fixture, { "x-github-delivery": "../../etc" })).status, 400);
    const form = `payload=${encodeURIComponent(JSON.stringify(fixture.payload))}`;
    const formResponse = await post(form, {
      "content-type": "application/x-www-form-urlencoded",
      "x-github-event": "ping",
      "x-github-delivery": fixture.delivery,
      "x-hub-signature-256": signatureHeader(SECRET, form),
    });
    assert.equal(formResponse.status, 400);
  } finally {
    await close();
  }
});

test("refuses a body over the limit by its Content-Length, before reading it", async () => {
  const { receiverUrl, close } = await setup();
  try {
    // A small body under a large declared length: answered without waiting for the rest.
    const response = await raw(
      receiverUrl,
      `POST /hooks/github HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n` +
        `Content-Length: ${DEFAULT_RECEIVER_LIMITS.maxBodyBytes + 1}\r\n\r\n{}`,
    );
    assert.equal(statusOf(response), 413);
  } finally {
    await close();
  }
});

test("survives request targets that are not URLs", async () => {
  const { deliver, receiverUrl, close } = await setup();
  try {
    for (const target of ["//[/hooks/github", "http://a:99999/x", "*", "/hooks/github%"]) {
      const response = await raw(receiverUrl, `GET ${target} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n`);
      assert.ok([400, 404].includes(statusOf(response)), `${target}: ${response.split("\r\n")[0]}`);
    }
    assert.equal((await deliver(fixtureFor("ping"))).status, 202, "still serving");
  } finally {
    await close();
  }
});

const SMALL_LIMITS: ReceiverLimits = {
  maxBodyBytes: 1000,
  maxBytesInFlight: 2000,
  maxConnections: 4,
  requestTimeoutMs: 500,
  checkIntervalMs: 100,
};

/** Retries a raw request until it gets the wanted status: the held requests reach the handler asynchronously. */
const eventually = async (attempt: () => Promise<number>, wanted: number) => {
  const deadline = Date.now() + 3_000;
  let status = 0;
  while (Date.now() < deadline) {
    status = await attempt();
    if (status === wanted) return status;
    await sleep(20);
  }
  return status;
};

test("503 once the bodies in flight reach the budget; space frees as they finish", async () => {
  const { receiverUrl, close } = await setup(SMALL_LIMITS);
  const head = (length: number) =>
    `POST /hooks/github HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: ${length}\r\n\r\n`;
  const small = () => raw(receiverUrl, `${head(2)}{}`).then(statusOf);
  try {
    // Two slow senders declare 1000 bytes each and send none of them.
    const holders = [await open(receiverUrl), await open(receiverUrl)];
    for (const holder of holders) holder.socket.write(head(1000));
    assert.equal(await eventually(small, 503), 503);
    for (const holder of holders) holder.socket.destroy();
    assert.equal(await eventually(small, 401), 401, "unsigned, but read again");
  } finally {
    await close();
  }
});

test("caps connections and closes requests that do not finish in time", async () => {
  const { receiverUrl, close } = await setup(SMALL_LIMITS);
  try {
    // A sender that never finishes its headers is closed after the request timeout.
    const slow = await open(receiverUrl);
    slow.socket.write("POST /hooks/github HTTP/1.1\r\nHost: x\r\n");
    const started = Date.now();
    await slow.closed;
    assert.ok(Date.now() - started < 2_000, "closed by the timeout");

    const idle = await Promise.all(Array.from({ length: SMALL_LIMITS.maxConnections }, () => open(receiverUrl)));
    await sleep(50);
    const extra = await open(receiverUrl);
    await extra.closed;
    assert.equal(extra.received(), "", "dropped without an answer");
    for (const connection of idle) connection.socket.destroy();
    await sleep(50);
    const status = await raw(receiverUrl, "GET /x HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").then(statusOf);
    assert.equal(status, 404, "accepts connections again");
  } finally {
    await close();
  }
});

test("503 when the router is down or refuses the token", async () => {
  const fixture = fixtureFor("ping");
  const body = JSON.stringify(fixture.payload);
  const headers = {
    "content-type": "application/json",
    "x-github-event": "ping",
    "x-github-delivery": fixture.delivery,
    "x-hub-signature-256": signatureHeader(SECRET, body),
  };
  const down = await serveReceiver({
    host: "127.0.0.1",
    port: 0,
    routerUrl: `http://127.0.0.1:${await closedPort()}`,
    topic: "github",
    secret: SECRET,
    token: "t3p_unused",
  });
  try {
    assert.equal((await fetch(`${down.url}/hooks/github`, { method: "POST", headers, body })).status, 503);
  } finally {
    await down.close();
  }

  const { token, close } = await setup();
  const core = new RouterCore({ dbPath: ":memory:", topics: new Map([["github", [HUB]]]) });
  const router = await serveRouter({ core, host: "127.0.0.1", port: 0 });
  const wrongToken = await serveReceiver({ host: "127.0.0.1", port: 0, routerUrl: router.url, topic: "github", secret: SECRET, token });
  try {
    assert.equal((await fetch(`${wrongToken.url}/hooks/github`, { method: "POST", headers, body })).status, 503);
  } finally {
    await wrongToken.close();
    await router.close();
    core.close();
    await close();
  }
});

test("refuses a plain-http router that is not on loopback, and an empty secret", async () => {
  const options = { host: "127.0.0.1", port: 0, topic: "github", secret: SECRET, token: "t3p_x" };
  await assert.rejects(serveReceiver({ ...options, routerUrl: "http://router.example:8790" }), /https or loopback/);
  await assert.rejects(serveReceiver({ ...options, routerUrl: "http://127.0.0.1:8790", secret: "" }), /secret is empty/);
});


test("publishing refuses a router redirect without forwarding the GitHub event", async () => {
  let forwarded = 0;
  const destination = createHttpServer((request, response) => {
    forwarded += 1;
    request.resume();
    response.writeHead(202, { "content-type": "application/json" }).end('{"status":"stored","matched":0}');
  });
  const redirector = createHttpServer((request, response) => {
    request.resume();
    const address = destination.address();
    if (address === null || typeof address === "string") throw new Error("no redirect destination");
    response.writeHead(307, { location: `http://127.0.0.1:${address.port}/v1/events?topic=github` }).end();
  });
  await Promise.all([destination, redirector].map((server) => new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve))));
  const address = redirector.address();
  if (address === null || typeof address === "string") throw new Error("no router address");
  const receiver = await serveReceiver({ host: "127.0.0.1", port: 0, routerUrl: `http://127.0.0.1:${address.port}`, topic: "github", secret: SECRET, token: "t3p_test" });
  try {
    const fixture = fixtureFor("ping");
    const body = JSON.stringify(fixture.payload);
    const response = await fetch(`${receiver.url}/hooks/github`, { method: "POST", body, headers: {
      "content-type": "application/json", "x-github-event": fixture.event, "x-github-delivery": fixture.delivery,
      "x-hub-signature-256": signatureHeader(SECRET, body),
    } });
    assert.equal(response.status, 503);
    assert.equal(forwarded, 0);
  } finally {
    await receiver.close();
    await Promise.all([redirector, destination].map((server) => new Promise<void>((resolve) => {
      server.closeAllConnections();
      server.close(() => resolve());
    })));
  }
});
