import { test } from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { RouterCore, type RouterCoreOptions } from "./core.ts";
import { DEFAULT_EVENT_LIMITS, type Publisher } from "./events.ts";
import type { InboundEventBatch, InboxItem } from "./types.ts";

const HUB = "github-hub@bayfold-co-ops";
const topics = new Map([["github", [HUB]]]);

const ghEvent = (id: string, data: Record<string, unknown> = {}, attributes: Record<string, string> = {}) => ({
  specversion: "1.0",
  id,
  source: "github.com/bayfold/infra",
  type: "com.github.pull_request.labeled",
  subject: "pull/9",
  time: new Date().toISOString(),
  datacontenttype: "application/json",
  repo: "bayfold/infra",
  action: "labeled",
  actor: "bowd",
  ...attributes,
  data: { number: 9, labels: ["agent:infra"], signed_by: null, ...data },
});

const setup = (options: Partial<RouterCoreOptions> = {}) => {
  let now = 1_000_000;
  const core = new RouterCore({ dbPath: ":memory:", topics, now: () => now, ...options });
  core.addConnector("b@host");
  core.events.addPublisher(HUB, ["github"]);
  const publisher: Publisher = { id: HUB, topics: new Set(["github"]) };
  const batches: InboundEventBatch[] = [];
  return {
    core,
    publisher,
    batches,
    publish: (event: unknown) => core.events.publish(publisher, "github", event),
    subscribe: (filters: unknown = [], coalesceSeconds = 0, id: string = randomUUID()) => {
      const result = core.events.setSubscriptions("b@host", [{ id, topic: "github", filters, coalesceSeconds }]);
      assert.equal(result.ok, true);
      return id;
    },
    attach: () =>
      core.attach("b@host", (item: InboxItem) => {
        if (item.kind === "event") batches.push(item);
      }),
    advance: (ms: number) => {
      now += ms;
    },
  };
};

const ids = (batch: InboundEventBatch | undefined) => batch?.events.map((event) => event.id);

test("publishes to matching subscriptions only, and answers with the match count", () => {
  const { core, publish, attach, batches } = setup();
  const infra = randomUUID();
  const other = randomUUID();
  core.events.setSubscriptions("b@host", [
    { id: infra, topic: "github", filters: [{ exact: { "data.labels": "agent:infra" } }], coalesceSeconds: 0 },
    { id: other, topic: "github", filters: [{ exact: { "data.labels": "agent:ops" } }], coalesceSeconds: 0 },
  ]);
  attach();
  assert.deepEqual(publish(ghEvent("d1")), { ok: true, status: "stored", matched: 1 });
  assert.equal(batches.length, 1);
  assert.equal(batches[0]?.subscriptionId, infra);
  assert.equal(batches[0]?.topic, "github");
  assert.deepEqual(ids(batches[0]), ["d1"]);
  assert.deepEqual(publish(ghEvent("d2", { labels: [] })), { ok: true, status: "stored", matched: 0 });
});

test("publish checks grant, topic and event", () => {
  const { core, publisher } = setup();
  // The grant is checked first, so an ungranted topic does not reveal whether it exists.
  const ungranted = core.events.publish(publisher, "gitlab", ghEvent("d1"));
  assert.equal(ungranted.ok ? "ok" : ungranted.error, "not_granted");
  const unknown = core.events.publish({ id: HUB, topics: new Set(["github", "gitlab"]) }, "gitlab", ghEvent("d1"));
  assert.equal(unknown.ok ? "ok" : unknown.error, "unknown_topic");
  // Granted by token but not configured for the topic, and the reverse.
  const stranger: Publisher = { id: "someone@else", topics: new Set(["github"]) };
  const notConfigured = core.events.publish(stranger, "github", ghEvent("d1"));
  assert.equal(notConfigured.ok ? "ok" : notConfigured.error, "not_granted");
  const notGranted = core.events.publish({ id: HUB, topics: new Set() }, "github", ghEvent("d1"));
  assert.equal(notGranted.ok ? "ok" : notGranted.error, "not_granted");
  const invalid = core.events.publish(publisher, "github", { ...ghEvent("d1"), specversion: "0.3" });
  assert.equal(invalid.ok ? "ok" : invalid.error, "invalid_event");
  const big = core.events.publish(publisher, "github", ghEvent("d1", { text: "x".repeat(9000) }));
  assert.equal(big.ok ? "ok" : big.error, "too_large");
});

test("publishing is idempotent on (topic, publisher, source, id), ignoring time", () => {
  const { publish, subscribe, attach, batches, core } = setup();
  subscribe();
  attach();
  assert.deepEqual(publish(ghEvent("d1")), { ok: true, status: "stored", matched: 1 });
  // Redelivery with a new receipt time: same result, not published again.
  assert.deepEqual(publish({ ...ghEvent("d1"), time: "2030-01-01T00:00:00Z" }), {
    ok: true,
    status: "stored",
    matched: 1,
  });
  const conflict = publish(ghEvent("d1", { number: 10 }));
  assert.equal(conflict.ok ? "ok" : conflict.error, "id_conflict");
  // Same id from another source is another event.
  assert.equal(publish({ ...ghEvent("d1"), source: "github.com/bayfold/t3-mesh" }).ok, true);
  core.ack("b@host", batches[0]?.id ?? "", { kind: "delivered" });
  assert.deepEqual(batches.map(ids), [["d1"], ["d1"]]);
  assert.deepEqual(
    batches.map((batch) => batch.events[0]?.source),
    ["github.com/bayfold/infra", "github.com/bayfold/t3-mesh"],
  );
});

test("subscriptions created after an event never see it", () => {
  const { publish, subscribe, attach, batches, core } = setup();
  publish(ghEvent("d1"));
  subscribe();
  attach();
  core.tick();
  assert.equal(batches.length, 0);
});

test("a trailing window closes coalesceSeconds after the last event", () => {
  const { core, publish, subscribe, attach, batches, advance } = setup();
  subscribe([], 30);
  attach();
  publish(ghEvent("d1"));
  advance(20_000);
  publish(ghEvent("d2"));
  advance(20_000);
  core.tick();
  assert.equal(batches.length, 0, "still open: 20 s since the last event");
  advance(10_000);
  core.tick();
  assert.deepEqual(batches.map(ids), [["d1", "d2"]]);
});

test("an event after the window ended starts a new batch even before the tick", () => {
  const { core, publish, subscribe, attach, batches, advance } = setup();
  subscribe([], 30);
  attach();
  publish(ghEvent("d1"));
  advance(31_000);
  publish(ghEvent("d2"));
  assert.deepEqual(batches.map(ids), [["d1"]]);
  core.ack("b@host", batches[0]?.id ?? "", { kind: "delivered" });
  advance(30_000);
  core.tick();
  assert.deepEqual(batches.map(ids), [["d1"], ["d2"]]);
});

test("a batch closes 5 minutes after its first event even if events keep coming", () => {
  const { core, publish, subscribe, attach, batches, advance } = setup();
  subscribe([], 600);
  attach();
  for (let i = 0; i < 11; i++) {
    publish(ghEvent(`d${i}`));
    advance(30_000);
    core.tick();
  }
  assert.equal(batches.length, 1);
  assert.equal(batches[0]?.events.length, 10);
});

test("a batch closes at 20 events", () => {
  const { publish, subscribe, attach, batches } = setup();
  subscribe([], 600);
  attach();
  for (let i = 0; i < 21; i++) publish(ghEvent(`d${i}`));
  assert.equal(batches.length, 1);
  assert.equal(batches[0]?.events.length, 20);
});

test("coalesceSeconds 0 closes every event into its own batch, delivered one at a time", () => {
  const { core, publish, subscribe, attach, batches } = setup();
  subscribe([], 0);
  publish(ghEvent("d1"));
  publish(ghEvent("d2"));
  attach();
  core.tick();
  assert.deepEqual(batches.map(ids), [["d1"]]);
  core.ack("b@host", batches[0]?.id ?? "", { kind: "delivered" });
  assert.deepEqual(batches.map(ids), [["d1"], ["d2"]]);
});

test("open and pending batches survive a router restart", () => {
  const dir = mkdtempSync(join(tmpdir(), "t3-mesh-events-"));
  try {
    const dbPath = join(dir, "router.db");
    let now = 1_000_000;
    const first = new RouterCore({ dbPath, topics, now: () => now });
    first.addConnector("b@host");
    first.events.addPublisher(HUB, ["github"]);
    const publisher: Publisher = { id: HUB, topics: new Set(["github"]) };
    const pendingSub = randomUUID();
    const openSub = randomUUID();
    first.events.setSubscriptions("b@host", [
      { id: pendingSub, topic: "github", filters: [], coalesceSeconds: 0 },
      { id: openSub, topic: "github", filters: [], coalesceSeconds: 60 },
    ]);
    first.events.publish(publisher, "github", ghEvent("d1"));
    first.close();

    now += 1000;
    const second = new RouterCore({ dbPath, topics, now: () => now });
    const batches: InboundEventBatch[] = [];
    const detach = second.attach("b@host", (item) => {
      if (item.kind === "event") batches.push(item);
    });
    second.tick();
    assert.deepEqual(
      batches.map((batch) => [batch.subscriptionId, ids(batch)]),
      [[pendingSub, ["d1"]]],
    );
    // The open window continues across the restart, and idempotency keys persist.
    assert.deepEqual(second.events.publish(publisher, "github", ghEvent("d1")), { ok: true, status: "stored", matched: 2 });
    second.events.publish(publisher, "github", ghEvent("d2"));
    now += 60_000;
    second.tick();
    assert.deepEqual(
      batches.filter((batch) => batch.subscriptionId === openSub).map(ids),
      [["d1", "d2"]],
    );
    detach();
    second.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("at most 100 pending batches per subscription; the oldest is dropped", () => {
  const { core, publish, subscribe, attach, batches } = setup();
  subscribe([], 0);
  for (let i = 0; i < 101; i++) assert.equal(publish(ghEvent(`d${i}`)).ok, true, "publishers are never refused");
  attach();
  core.tick();
  assert.deepEqual(batches.map(ids), [["d1"]]);
});

test("the wake cap delays batches without dropping them", () => {
  const { core, publish, subscribe, attach, batches, advance } = setup({
    eventLimits: { ...DEFAULT_EVENT_LIMITS, maxBatchesPerHourPerSubscription: 2 },
  });
  subscribe([], 0);
  attach();
  for (let i = 0; i < 3; i++) publish(ghEvent(`d${i}`));
  core.ack("b@host", batches[0]?.id ?? "", { kind: "delivered" });
  core.ack("b@host", batches[1]?.id ?? "", { kind: "delivered" });
  assert.equal(batches.length, 2);
  advance(60 * 60 * 1000 - 1);
  core.tick();
  assert.equal(batches.length, 2);
  advance(2);
  core.tick();
  assert.deepEqual(batches.map(ids), [["d0"], ["d1"], ["d2"]]);
});

test("rejected batches are not counted by the wake cap", () => {
  const { core, publish, subscribe, attach, batches } = setup({
    eventLimits: { ...DEFAULT_EVENT_LIMITS, maxBatchesPerHourPerSubscription: 1 },
  });
  subscribe([], 0);
  attach();
  publish(ghEvent("d0"));
  publish(ghEvent("d1"));
  core.ack("b@host", batches[0]?.id ?? "", { kind: "rejected", reason: "policy:archived" });
  assert.deepEqual(batches.map(ids), [["d0"], ["d1"]]);
});

test("a subscription can override the maximum batch age and the wake cap", () => {
  const { core, publish, attach, batches, advance } = setup();
  const capped = randomUUID();
  const plain = randomUUID();
  const result = core.events.setSubscriptions("b@host", [
    { id: capped, topic: "github", filters: [], coalesceSeconds: 600, maxBatchAgeMs: 30_000, maxBatchesPerHour: 1 },
    { id: plain, topic: "github", filters: [], coalesceSeconds: 600 },
  ]);
  assert.equal(result.ok, true);
  attach();
  publish(ghEvent("d0"));
  advance(30_000);
  core.tick();
  assert.deepEqual(
    batches.map((batch) => [batch.subscriptionId, ids(batch)]),
    [[capped, ["d0"]]],
    "closed after its own 30 s; the other keeps the router-wide 5 minutes",
  );
  core.ack("b@host", batches[0]?.id ?? "", { kind: "delivered" });
  publish(ghEvent("d1"));
  advance(30_000);
  core.tick();
  assert.equal(batches.length, 1, "over its wake cap of 1 per hour");
  advance(5 * 60 * 1000);
  core.tick();
  assert.deepEqual(
    batches.map((batch) => batch.subscriptionId),
    [capped, plain],
  );
  assert.deepEqual(
    core.events.pendingSummary("b@host").map((summary) => [summary.subscriptionId, summary.pending]).sort(),
    [[capped, 1], [plain, 1]].sort(),
    "the capped one waiting, the plain one offered",
  );
  core.ack("b@host", batches[1]?.id ?? "", { kind: "delivered" });
  advance(60 * 60 * 1000);
  core.tick();
  assert.deepEqual(batches.map(ids).slice(-1), [["d1"]]);
  assert.equal(batches.at(-1)?.subscriptionId, capped);
});

test("per-subscription limits must be positive integers; changing them keeps batches", () => {
  const { core, publish, subscribe, attach, batches } = setup();
  const id = subscribe([], 0);
  publish(ghEvent("d0"));
  const set = (limits: { maxBatchAgeMs?: number; maxBatchesPerHour?: number }) =>
    core.events.setSubscriptions("b@host", [{ id, topic: "github", filters: [], coalesceSeconds: 0, ...limits }]);
  assert.equal(set({ maxBatchAgeMs: 0 }).ok, false);
  assert.equal(set({ maxBatchesPerHour: 1.5 }).ok, false);
  assert.equal(set({ maxBatchesPerHour: 120 }).ok, true);
  attach();
  core.tick();
  assert.deepEqual(batches.map(ids), [["d0"]]);
});

test("hold re-offers after the retry time; ack timeouts re-offer; only the subscriber may ack", () => {
  const { core, publish, subscribe, attach, batches, advance } = setup();
  core.addConnector("c@host");
  subscribe([], 0);
  attach();
  publish(ghEvent("d1"));
  const id = batches[0]?.id ?? "";
  assert.equal(core.ack("c@host", id, { kind: "delivered" }), false);
  assert.equal(core.ack("b@host", id, { kind: "hold", reason: "t3_unavailable" }), true);
  core.tick();
  assert.equal(batches.length, 1);
  advance(30_000);
  core.tick();
  assert.equal(batches.length, 2);
  advance(60_000);
  core.tick();
  assert.equal(batches.length, 3, "unanswered offer repeated");
  assert.equal(core.ack("b@host", id, { kind: "delivered" }), true);
  assert.equal(core.ack("b@host", id, { kind: "delivered" }), false);
});

test("batches expire after 24 hours", () => {
  const { core, publish, subscribe, attach, batches, advance } = setup();
  subscribe([], 0);
  publish(ghEvent("d1"));
  advance(DEFAULT_EVENT_LIMITS.retentionMs);
  core.tick();
  attach();
  core.tick();
  assert.equal(batches.length, 0);
});

test("changing filters keeps pending batches; removing a subscription deletes them", () => {
  const { core, publish, subscribe, attach, batches } = setup();
  const id = subscribe([], 0);
  publish(ghEvent("d1"));
  publish(ghEvent("d2"));
  subscribe([{ exact: { actor: "nobody" } }], 0, id);
  attach();
  core.tick();
  assert.deepEqual(batches.map(ids), [["d1"]]);
  assert.deepEqual(publish(ghEvent("d3")), { ok: true, status: "stored", matched: 0 }, "new filters apply");
  core.events.setSubscriptions("b@host", []);
  assert.equal(core.ack("b@host", batches[0]?.id ?? "", { kind: "delivered" }), false, "batches already offered are gone");
  core.tick();
  assert.equal(batches.length, 1);
});

test("checks the subscription set", () => {
  const { core } = setup();
  const set = (subscriptions: Parameters<typeof core.events.setSubscriptions>[1], connector = "b@host") =>
    core.events.setSubscriptions(connector, subscriptions);
  const sub = (fields: Partial<{ id: string; topic: string; filters: unknown; coalesceSeconds: number }> = {}) => ({
    id: randomUUID(),
    topic: "github",
    filters: [],
    coalesceSeconds: 30,
    ...fields,
  });
  const error = (result: ReturnType<typeof set>) => (result.ok ? "ok" : result.error);
  assert.equal(error(set([sub({ id: "not-a-uuid" })])), "invalid");
  assert.equal(error(set([sub({ topic: "Bad Topic" })])), "invalid");
  assert.equal(error(set([sub({ coalesceSeconds: 601 })])), "invalid");
  assert.equal(error(set([sub({ coalesceSeconds: 1.5 })])), "invalid");
  assert.equal(error(set([sub({ coalesceSeconds: -1 })])), "invalid");
  const duplicate = randomUUID();
  assert.equal(error(set([sub({ id: duplicate }), sub({ id: duplicate })])), "invalid");
  const badFilter = set([sub({ filters: [{ exact: { "data.x": 1 } }] })]);
  assert.deepEqual(badFilter.ok ? null : [badFilter.error, badFilter.path], ["invalid_filter", 'filters[0].exact["data.x"]']);
  assert.equal(error(set(Array.from({ length: 201 }, () => sub()))), "too_many_subscriptions");
  assert.equal(error(set(Array.from({ length: 200 }, () => sub()))), "ok");
  // Another connector cannot take over a subscription ID.
  core.addConnector("c@host");
  const taken = randomUUID();
  assert.equal(error(set([sub({ id: taken })])), "ok");
  assert.equal(error(set([sub({ id: taken })], "c@host")), "id_conflict");
  // Unknown topics are kept but reported.
  const result = set([sub({ topic: "gitlab" }), sub()]);
  assert.deepEqual(result, { ok: true, unknownTopics: ["gitlab"] });
});

test("revoking a connector removes its subscriptions", () => {
  const { core, publish, subscribe } = setup();
  subscribe();
  assert.equal(core.revokeConnector("b@host"), true);
  assert.deepEqual(publish(ghEvent("d1")), { ok: true, status: "stored", matched: 0 });
});

test("publisher tokens are hashed, revocable and separate from connector tokens", () => {
  const core = new RouterCore({ dbPath: ":memory:", topics });
  const connectorToken = core.addConnector("b@host");
  const token = core.events.addPublisher(HUB, ["github"]);
  assert.match(token, /^t3p_/);
  assert.deepEqual(core.events.authenticatePublisher(token), { id: HUB, topics: new Set(["github"]) });
  assert.equal(core.authenticate(token), null, "publisher tokens are not connector tokens");
  assert.equal(core.events.authenticatePublisher(connectorToken), null, "connector tokens are not publisher tokens");
  assert.throws(() => core.events.addPublisher(HUB, ["github"]), /revoke it first/);
  assert.throws(() => core.events.addPublisher("b@host", ["github"]), /is a connector/);
  assert.throws(() => core.addConnector(HUB), /is a publisher/);
  assert.throws(() => core.events.addPublisher("x@host", ["Bad"]), /invalid topic/);
  assert.deepEqual(core.events.unprovisionedPublishers(), []);
  assert.equal(core.events.revokePublisher(HUB), true);
  assert.equal(core.events.revokePublisher(HUB), false);
  assert.equal(core.events.authenticatePublisher(token), null);
  assert.deepEqual(core.events.unprovisionedPublishers(), [{ topic: "github", publisher: HUB }]);
  // A revoked publisher can be issued a new token.
  const renewed = core.events.addPublisher(HUB, ["github"]);
  assert.equal(core.events.authenticatePublisher(renewed)?.id, HUB);
  assert.equal(core.events.authenticatePublisher(token), null);
});

test("audits the event lifecycle without event data", () => {
  const dir = mkdtempSync(join(tmpdir(), "t3-mesh-audit-"));
  try {
    const auditPath = join(dir, "audit.jsonl");
    const { core, publish, subscribe, attach, batches } = setup({ auditPath });
    subscribe([], 0);
    attach();
    publish(ghEvent("d1", { text: "SECRET-ish body text" }));
    core.ack("b@host", batches[0]?.id ?? "", { kind: "delivered" });
    publish(ghEvent("d2"));
    core.ack("b@host", batches[1]?.id ?? "", { kind: "rejected", reason: "policy:archived" });
    const text = readFileSync(auditPath, "utf8");
    assert.doesNotMatch(text, /SECRET-ish/);
    const events = text
      .trim()
      .split("\n")
      .map((line) => (JSON.parse(line) as { event: string }).event)
      .filter((event) => event.startsWith("event."));
    assert.deepEqual(events, [
      "event.matched",
      "event.batch_closed",
      "event.published",
      "event.delivered",
      "event.matched",
      "event.batch_closed",
      "event.published",
      "event.rejected",
    ]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

const withDir = (body: (dir: string) => void) => {
  const dir = mkdtempSync(join(tmpdir(), "t3-mesh-events-"));
  try {
    body(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
};

const auditEvents = (auditPath: string) =>
  existsSync(auditPath)
    ? readFileSync(auditPath, "utf8")
        .trim()
        .split("\n")
        .map((line) => JSON.parse(line) as { event: string; batch?: string; reason?: string })
    : [];

test("the pending cap never drops the batch in flight", () => {
  withDir((dir) => {
    const auditPath = join(dir, "audit.jsonl");
    const { core, publish, subscribe, attach, batches } = setup({
      auditPath,
      eventLimits: { ...DEFAULT_EVENT_LIMITS, maxPendingBatchesPerSubscription: 2 },
    });
    subscribe([], 0);
    attach();
    publish(ghEvent("e1"));
    const offered = batches[0]?.id ?? "";
    publish(ghEvent("e2"));
    publish(ghEvent("e3"));
    // e1 is in flight, so e2's batch is the oldest that may go.
    const dropped = auditEvents(auditPath).filter((line) => line.event === "event.dropped");
    assert.deepEqual(dropped.map((line) => line.reason), ["queue_full"]);
    assert.notEqual(dropped[0]?.batch, offered);
    assert.equal(core.ack("b@host", offered, { kind: "delivered" }), true, "the in-flight batch still settles");
    assert.deepEqual(batches.map(ids), [["e1"], ["e3"]]);
  });
});

test("changing a subscription's topic deletes its pending batches", () => {
  withDir((dir) => {
    const auditPath = join(dir, "audit.jsonl");
    const { core, publish, subscribe, attach, batches } = setup({
      auditPath,
      topics: new Map([...topics, ["ci", [HUB]]]),
    });
    const id = subscribe([], 0);
    publish(ghEvent("d1"));
    assert.equal(core.events.setSubscriptions("b@host", [{ id, topic: "ci", filters: [], coalesceSeconds: 0 }]).ok, true);
    attach();
    core.tick();
    assert.equal(batches.length, 0);
    const dropped = auditEvents(auditPath).filter((line) => line.event === "event.dropped");
    assert.deepEqual(dropped.map((line) => line.reason), ["topic_changed"]);
  });
});

test("the same source and id from another publisher is another event", () => {
  const other = "other-hub@host";
  const { core, publish, subscribe, attach, batches } = setup({ topics: new Map([["github", [HUB, other]]]) });
  core.events.addPublisher(other, ["github"]);
  subscribe([], 0);
  attach();
  assert.deepEqual(publish(ghEvent("d1")), { ok: true, status: "stored", matched: 1 });
  // Different content under the same (source, id) would be id_conflict for one publisher.
  const second = core.events.publish({ id: other, topics: new Set(["github"]) }, "github", ghEvent("d1", { number: 10 }));
  assert.deepEqual(second, { ok: true, status: "stored", matched: 1 });
  core.ack("b@host", batches[0]?.id ?? "", { kind: "delivered" });
  assert.deepEqual(batches.map(ids), [["d1"], ["d1"]]);
});

test("an event nobody matched keeps its key but not its body", () => {
  withDir((dir) => {
    const dbPath = join(dir, "router.db");
    const { publish } = setup({ dbPath });
    publish(ghEvent("d1"));
    const db = new DatabaseSync(dbPath);
    try {
      assert.deepEqual({ ...db.prepare("SELECT id, body, matched FROM events").get() }, { id: "d1", body: null, matched: 0 });
    } finally {
      db.close();
    }
    assert.deepEqual(publish(ghEvent("d1")), { ok: true, status: "stored", matched: 0 }, "still idempotent");
    assert.equal(publish(ghEvent("d1", { number: 10 })).ok, false, "still checked for conflicts");
  });
});

test("a rolled-back publish leaves no audit lines", () => {
  withDir((dir) => {
    const dbPath = join(dir, "router.db");
    const auditPath = join(dir, "audit.jsonl");
    const { publish, subscribe } = setup({ dbPath, auditPath });
    subscribe([], 0);
    const db = new DatabaseSync(dbPath);
    try {
      // Fails the last statement of the publish transaction, after its batch audit lines were produced.
      db.exec("CREATE TRIGGER fail_publish BEFORE UPDATE OF matched ON events BEGIN SELECT RAISE(ABORT, 'boom'); END");
      assert.throws(() => publish(ghEvent("d1")), /boom/);
      assert.equal(db.prepare("SELECT COUNT(*) AS n FROM events").get()?.["n"], 0);
    } finally {
      db.close();
    }
    assert.deepEqual(
      auditEvents(auditPath).filter((line) => line.event.startsWith("event.")),
      [],
    );
  });
});

test("tick takes no write lock when nothing is due", () => {
  withDir((dir) => {
    const dbPath = join(dir, "router.db");
    const { core, publish, subscribe, advance } = setup({ dbPath });
    subscribe([], 60);
    core.tick(); // the first tick prunes
    publish(ghEvent("d1")); // opens a 60 s window
    const other = new DatabaseSync(dbPath);
    try {
      other.exec("BEGIN IMMEDIATE");
      advance(30_000);
      core.tick(); // the window is still open and pruning is not due: no lock needed
      other.exec("ROLLBACK");
    } finally {
      other.close();
    }
  });
});

test("a message and an event batch are in flight together", () => {
  const { core, publish, subscribe } = setup();
  core.addConnector("a@host");
  core.setHandles("a@host", ["alpha"]);
  core.setHandles("b@host", ["beta"]);
  subscribe([], 0);
  const offered: InboxItem[] = [];
  core.attach("b@host", (item) => offered.push(item));
  assert.deepEqual(core.submit("a@host", { id: "m1", fromHandle: "alpha", to: "b@host/beta", text: "hi", origin: null }), {
    ok: true,
    status: "stored",
  });
  publish(ghEvent("d1"));
  assert.deepEqual(offered.map((item) => [item.kind, item.id === "m1"]), [
    ["message", true],
    ["event", false],
  ]);
  const batchId = offered[1]?.id ?? "";
  // Each ack settles only its own item, and neither blocks the other's next item.
  assert.equal(core.ack("b@host", batchId, { kind: "delivered" }), true);
  publish(ghEvent("d2"));
  assert.equal(offered.length, 3, "the next batch is offered while the message is still in flight");
  assert.equal(core.ack("b@host", "m1", { kind: "delivered" }), true);
  assert.equal(core.ack("b@host", "m1", { kind: "delivered" }), false);
  assert.equal(core.ack("b@host", batchId, { kind: "delivered" }), false);
});
