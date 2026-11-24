import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { DEFAULT_LIMITS, RouterCore } from "./core.ts";
import type { InboundMessage } from "./types.ts";

test("an error in the first offer after attach goes to onDeferredError when given", async () => {
  const errors: unknown[] = [];
  const core = new RouterCore({ dbPath: ":memory:", onDeferredError: (error) => errors.push(error) });
  core.attach("a@host", () => undefined);
  core.close();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(errors.length, 1);
});

const setup = () => {
  let now = 1_000_000;
  const core = new RouterCore({ dbPath: ":memory:", now: () => now });
  const tokenA = core.addConnector("a@host");
  core.addConnector("b@host");
  core.setHandles("a@host", ["alpha"]);
  core.setHandles("b@host", ["beta"]);
  const offered: InboundMessage[] = [];
  return {
    core,
    tokenA,
    offered,
    attachB: () =>
      core.attach("b@host", (item) => {
        if (item.kind === "message") offered.push(item);
      }),
    advance: (ms: number) => {
      now += ms;
    },
  };
};
const send = (id: string, text = "hi") => ({ id, fromHandle: "alpha", to: "b@host/beta", text, origin: null });

test("authenticates tokens and revokes them", () => {
  const { core, tokenA } = setup();
  assert.equal(core.authenticate(tokenA), "a@host");
  assert.equal(core.authenticate("nope"), null);
  assert.equal(core.revokeConnector("a@host"), true);
  assert.equal(core.authenticate(tokenA), null);
  assert.deepEqual(
    core.peers().map((peer) => peer.address),
    ["b@host/beta"],
  );
});

test("stamps the sender and refuses unenrolled senders and recipients", () => {
  const { core, offered, attachB } = setup();
  attachB();
  assert.deepEqual(core.submit("a@host", send("1")), { ok: true, status: "stored" });
  const spoofed = core.submit("a@host", { ...send("2"), fromHandle: "beta" });
  assert.equal(spoofed.ok ? "ok" : spoofed.error, "invalid");
  const unknown = core.submit("a@host", { ...send("3"), to: "b@host/gamma" });
  assert.equal(unknown.ok ? "ok" : unknown.error, "unknown_recipient");
  return Promise.resolve().then(() => assert.equal(offered[0]?.from, "a@host/alpha"));
});

test("send is idempotent per id and refuses changed content", () => {
  const { core } = setup();
  assert.equal(core.submit("a@host", send("1")).ok, true);
  assert.equal(core.submit("a@host", send("1")).ok, true);
  const conflict = core.submit("a@host", send("1", "changed"));
  assert.equal(conflict.ok ? "ok" : conflict.error, "id_conflict");
});

test("offers one message per recipient at a time, in order", async () => {
  const { core, offered, attachB } = setup();
  core.submit("a@host", send("1"));
  core.submit("a@host", send("2"));
  attachB();
  await Promise.resolve();
  assert.deepEqual(
    offered.map((message) => message.id),
    ["1"],
  );
  core.ack("b@host", "1", { kind: "delivered" });
  assert.deepEqual(
    offered.map((message) => message.id),
    ["1", "2"],
  );
});

test("a hold blocks the queue until the retry time", async () => {
  const { core, offered, attachB, advance } = setup();
  attachB();
  core.submit("a@host", send("1"));
  core.ack("b@host", "1", { kind: "hold", reason: "policy:stopped" });
  core.tick();
  assert.equal(offered.length, 1);
  advance(DEFAULT_LIMITS.holdRetryMs);
  core.tick();
  assert.deepEqual(
    offered.map((message) => message.id),
    ["1", "1"],
  );
});

test("only the recipient's connector can ack", () => {
  const { core, attachB } = setup();
  attachB();
  core.submit("a@host", send("1"));
  assert.equal(core.ack("a@host", "1", { kind: "delivered" }), false);
  assert.equal(core.ack("b@host", "1", { kind: "delivered" }), true);
});

test("caps accepted messages per recipient per hour", () => {
  const { core, advance } = setup();
  for (let i = 0; i < 30; i++) assert.equal(core.submit("a@host", send(`m${i}`)).ok, true);
  const capped = core.submit("a@host", send("m30"));
  assert.equal(capped.ok ? "ok" : capped.error, "rate_limited");
  advance(60 * 60 * 1000 + 1);
  assert.equal(core.submit("a@host", send("m31")).ok, true);
});

test("expires undelivered messages", () => {
  const { core, offered, attachB, advance } = setup();
  core.submit("a@host", send("1"));
  advance(DEFAULT_LIMITS.ttlMs);
  core.tick();
  attachB();
  core.tick();
  assert.equal(offered.length, 0);
});

test("drops pending messages when the recipient handle leaves", () => {
  const { core, offered, attachB } = setup();
  core.submit("a@host", send("1"));
  core.setHandles("b@host", []);
  core.setHandles("b@host", ["beta"]);
  attachB();
  core.tick();
  assert.equal(offered.length, 0);
});

test("opens a database created by the router before events, keeping its connectors and messages", () => {
  const dir = mkdtempSync(join(tmpdir(), "t3-mesh-upgrade-"));
  try {
    const dbPath = join(dir, "router.db");
    // The schema the deployed router (main before events) creates, before its own added columns.
    const old = new DatabaseSync(dbPath);
    old.exec(`
      PRAGMA journal_mode = WAL;
      CREATE TABLE connectors (id TEXT PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE, created_at INTEGER NOT NULL, revoked_at INTEGER);
      CREATE TABLE handles (connector_id TEXT NOT NULL REFERENCES connectors(id), handle TEXT NOT NULL, PRIMARY KEY (connector_id, handle));
      CREATE TABLE messages (
        id TEXT PRIMARY KEY, from_addr TEXT NOT NULL, to_addr TEXT NOT NULL, text TEXT NOT NULL, digest TEXT NOT NULL,
        sent_at INTEGER NOT NULL, state TEXT NOT NULL CHECK (state IN ('pending', 'delivered', 'rejected', 'expired')),
        reason TEXT, hold_until INTEGER NOT NULL DEFAULT 0, settled_at INTEGER
      );
      CREATE INDEX messages_pending ON messages (to_addr, sent_at) WHERE state = 'pending';
      CREATE INDEX messages_recent ON messages (to_addr, sent_at);
    `);
    const token = "t3m_existing";
    const hash = createHash("sha256").update(token).digest("hex");
    old.prepare("INSERT INTO connectors (id, token_hash, created_at) VALUES (?, ?, ?)").run("b@host", hash, 1);
    old.prepare("INSERT INTO handles (connector_id, handle) VALUES (?, ?)").run("b@host", "beta");
    old
      .prepare("INSERT INTO messages (id, from_addr, to_addr, text, digest, sent_at, state) VALUES (?, ?, ?, ?, ?, ?, 'pending')")
      .run("m1", "a@host/alpha", "b@host/beta", "kept", "d", Date.now());
    old.close();

    const hub = "github-hub@bayfold-co-ops";
    const core = new RouterCore({ dbPath, topics: new Map([["github", [hub]]]) });
    try {
      assert.equal(core.authenticate(token), "b@host");
      const offered: InboundMessage[] = [];
      const detach = core.attach("b@host", (item) => {
        if (item.kind === "message") offered.push(item);
      });
      core.tick();
      detach();
      assert.deepEqual(
        offered.map((message) => [message.id, message.text, message.origin]),
        [["m1", "kept", null]],
      );
      core.events.addPublisher(hub, ["github"]);
      core.events.setSubscriptions("b@host", [{ id: randomUUID(), topic: "github", filters: [], coalesceSeconds: 0 }]);
      const published = core.events.publish({ id: hub, topics: new Set(["github"]) }, "github", {
        specversion: "1.0",
        id: "d1",
        source: "github.com/bayfold/infra",
        type: "com.github.ping",
        datacontenttype: "application/json",
        data: {},
      });
      assert.deepEqual(published, { ok: true, status: "stored", matched: 1 });
    } finally {
      core.close();
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
