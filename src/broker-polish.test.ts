import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { test } from "node:test";
import {
  dataJson,
  formatEventDelivery,
  promptSafeJson,
  pruneEmptyFields,
} from "./core/eventDelivery.ts";
import { issueGrant, parsePairingCode, signBinding } from "./core/identity/grant.ts";
import { generatePrivateKey, rawPublicKey } from "./core/identity/keys.ts";
import { formatPluginDelivery } from "./core/plugins/delivery.ts";
import { Plugins } from "./core/plugins/plugins.ts";
import { LocalEvents } from "./core/plugins/store.ts";
import type { CloudEvent } from "./core/router/cloudevent.ts";
import { RouterCore } from "./core/router/core.ts";
import { DEFAULT_EVENT_LIMITS, EventRouter, type Publisher } from "./core/router/events.ts";
import { checkFilters, matchesFilters, type Filter } from "./core/router/filter.ts";
import { serveRouter } from "./core/router/server.ts";
import { fromRouterOutcome, toRouterOutcome, type InboundEventBatch, type InboundOutcome } from "./core/router/types.ts";
import { seal } from "./core/transfer/seal.ts";
import { PluginHost } from "./plugins.ts";
import {
  delivered,
  formatItem,
  fromRouterOutcome as protocolFromRouterOutcome,
  hold,
  promptSafeJson as protocolPromptSafeJson,
  pruneEmptyFields as protocolPruneEmptyFields,
  reject,
  toRouterOutcome as protocolToRouterOutcome,
  type Outcome,
} from "./protocol.ts";
import { State } from "./state.ts";

const makeEvent = (overrides: Partial<CloudEvent> & { id: string; source?: string; type?: string }): CloudEvent => ({
  specversion: "1.0",
  source: "test/source",
  type: "com.test.event",
  datacontenttype: "application/json",
  data: { ok: true },
  ...overrides,
});

// ============================================================================
// 1. Collapse local.db into state.sqlite
// ============================================================================

test("LocalEvents and PluginHost share State.database() in state.sqlite with zero local.db or unused router tables", async () => {
  const dir = mkdtempSync(join(tmpdir(), "hyphae-polish-localdb-"));
  const statePath = join(dir, "state.sqlite");
  const state = new State(statePath, "alex@laptop");
  try {
    state.register("antigravity:s1", { kind: "antigravity" });
    state.setHandle("antigravity:s1", "alex");

    let now = 1_700_000_000_000;
    const local = new LocalEvents({
      db: state.database(),
      now: () => now,
      plugins: [
        {
          name: "slack",
          exec: process.execPath,
          args: [],
          env: {},
          cwd: dir,
          targets: [{ name: "ops", threadId: "handle:alex", coalesceSeconds: 2, maxWaitSeconds: 10, wakesPerHour: 60 }],
        },
      ],
    });

    // Zero local.db file and zero transfers/ directory created
    assert.equal(existsSync(join(dir, "local.db")), false);
    assert.equal(existsSync(join(dir, "transfers")), false);

    // Inspect tables inside state.sqlite: event tables exist, unused RouterCore tables MUST NOT exist
    const tables = (
      state.database().prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all() as Array<{ name: string }>
    ).map((r) => r.name);
    for (const required of ["sessions", "mailbox", "subscriptions", "events", "batches", "batch_events"]) {
      assert.ok(tables.includes(required), `Expected table '${required}' in state.sqlite`);
    }
    for (const forbidden of ["connectors", "handles", "messages", "grants", "transfers"]) {
      assert.equal(tables.includes(forbidden), false, `Unused RouterCore table '${forbidden}' must not exist in state.sqlite`);
    }

    // Publish, coalesce, deliver, and ack through LocalEvents
    const received: InboundEventBatch[] = [];
    local.attach(async (batch) => {
      received.push(batch);
      return { kind: "delivered" };
    });

    assert.equal(local.nextDeadlineMs(), null, "idle LocalEvents must report null deadline");

    const pub = local.publish("slack", "ops", makeEvent({ id: "sl-1", source: "slack/C1", type: "com.slack.msg", data: { text: "hi" } }));
    assert.deepEqual(pub, { ok: true, status: "stored" });
    const dup = local.publish("slack", "ops", makeEvent({ id: "sl-1", source: "slack/C1", type: "com.slack.msg", data: { text: "hi" } }));
    assert.deepEqual(dup, { ok: true, status: "duplicate" });

    assert.equal(local.nextDeadlineMs(), now + 2_000, "open batch coalesce deadline must be exact");
    assert.equal(received.length, 0);

    // Advance clock to exact coalesce deadline and tick
    now += 2_000;
    local.tick();
    await new Promise((r) => setTimeout(r, 20));
    assert.equal(received.length, 1);
    assert.equal(received[0]!.events.length, 1);
    assert.equal(received[0]!.events[0]!.id, "sl-1");
    assert.deepEqual(local.route(received[0]!.subscriptionId), { plugin: "slack", target: "ops" });

    // Closing LocalEvents MUST NOT close caller-owned state.database()
    local.close();
    assert.equal(state.session("antigravity:s1")?.handle, "alex");
    state.setHandle("antigravity:s1", "alex-still-open");
    assert.equal(state.session("antigravity:s1")?.handle, "alex-still-open");

    // Also verify PluginHost constructs Plugins on state.database() without creating local.db
    const host = new PluginHost(dir, [
      {
        name: "noop",
        exec: process.execPath,
        args: ["-e", "setInterval(() => {}, 10000)"],
        env: {},
        cwd: dir,
        targets: [{ name: "inbox", handle: "alex-still-open", coalesceSeconds: 0, maxWaitSeconds: 5, wakesPerHour: 60 }],
      },
    ], state);
    assert.equal(existsSync(join(dir, "local.db")), false, "PluginHost must never create local.db");
    await host.stop();
    // State remains usable after PluginHost.stop()
    assert.equal(state.byHandle("alex-still-open")?.id, "antigravity:s1");

    // Standalone Plugins requires either db or dbPath
    assert.throws(() => new Plugins({ plugins: [] }), /requires either db or dbPath/);
  } finally {
    state.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("LocalEvents with standalone dbPath handles ack-timeout redelivery and closes its own DB", async () => {
  const dir = mkdtempSync(join(tmpdir(), "hyphae-polish-standalone-"));
  const dbPath = join(dir, "standalone.sqlite");
  let now = 1_700_000_000_000;
  try {
    const local = new LocalEvents({
      dbPath,
      now: () => now,
      ackTimeoutMs: 5_000,
      plugins: [
        {
          name: "hook",
          exec: process.execPath,
          args: [],
          env: {},
          cwd: dir,
          targets: [{ name: "t1", threadId: "s1", coalesceSeconds: 0, maxWaitSeconds: 5, wakesPerHour: 60 }],
        },
      ],
    });

    let attempts = 0;
    const deferredResolvers: Array<(o: InboundOutcome) => void> = [];
    local.attach((_batch) => {
      attempts++;
      if (attempts === 1) {
        return new Promise<InboundOutcome>((resolve) => {
          deferredResolvers.push(resolve);
        });
      }
      return Promise.resolve({ kind: "delivered" });
    });

    // Wait for attach microtask
    await new Promise((r) => setTimeout(r, 10));
    local.publish("hook", "t1", makeEvent({ id: "ev-ack-1" }));
    assert.equal(attempts, 1);
    assert.equal(local.nextDeadlineMs(), now + 5_000, "in-flight ack timeout must govern nextDeadlineMs()");

    // Advance past ack timeout -> tick re-offers the unanswered batch
    now += 5_000;
    local.tick();
    await new Promise((r) => setTimeout(r, 15));
    assert.equal(attempts, 2);
    assert.equal(local.backlog().length, 0);

    // Late answer from first attempt is safely ignored
    deferredResolvers[0]?.({ kind: "hold", reason: "late" });
    await new Promise((r) => setTimeout(r, 10));
    local.close();
    assert.equal(existsSync(dbPath), true);
    assert.equal(existsSync(join(dir, "transfers")), false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ============================================================================
// 2. Exact Deadline Scheduling (EventRouter, TransferStore, RouterCore, serveRouter)
// ============================================================================

test("EventRouter and RouterCore nextDeadlineMs() report null when idle and exact deadlines across all states", () => {
  const dir = mkdtempSync(join(tmpdir(), "hyphae-polish-deadlines-"));
  const dbPath = join(dir, "router.sqlite");
  let now = 1_700_000_000_000;

  const adminKey = generatePrivateKey("ed25519");
  const adminPubRaw = rawPublicKey(adminKey);

  const core = new RouterCore({
    dbPath,
    now: () => now,
    adminKey: adminPubRaw,
    topics: new Map([["deploy", ["ci"]]]),
    limits: {
      ttlMs: 100_000,
      maxPendingPerRecipient: 50,
      maxPerHourPerRecipient: 50,
      holdRetryMs: 15_000,
      ackTimeoutMs: 25_000,
      settledRetentionMs: 500_000,
    },
    eventLimits: {
      ...DEFAULT_EVENT_LIMITS,
      retentionMs: 200_000,
      idempotencyMs: 1_000_000,
      maxBatchAgeMs: 10_000,
      maxBatchesPerHourPerSubscription: 1,
    },
  });

  try {
    let scheduleNotifications = 0;
    core.setScheduleListener(() => {
      scheduleNotifications++;
    });

    assert.equal(core.now(), now);
    assert.equal(core.events.nextDeadlineMs(), null, "fresh EventRouter must be idle");
    assert.equal(core.transfers.nextDeadlineMs(), null, "fresh TransferStore must be idle");
    assert.equal(core.nextDeadlineMs(), null, "fresh RouterCore must be idle");

    core.addConnector("c1");
    core.setHandles("c1", ["alice"]);
    assert.ok(scheduleNotifications > 0);

    const subId = randomUUID();
    const subRes = core.events.setSubscriptions("c1", [
      { id: subId, topic: "deploy", filters: [], coalesceSeconds: 4 },
    ]);
    assert.equal(subRes.ok, true);
    assert.equal(core.nextDeadlineMs(), null, "subscriptions with no events must still be idle");

    // --- (a) Open event batch coalesce deadline & maxBatchAgeMs clamp ---
    const pub: Publisher = { id: "ci", topics: new Set(["deploy"]) };
    const beforePubNotifications = scheduleNotifications;
    core.events.publish(pub, "deploy", makeEvent({ id: "e1" }));
    assert.ok(scheduleNotifications > beforePubNotifications);
    assert.equal(core.events.nextDeadlineMs(), now + 4_000, "coalesce window deadline");
    assert.equal(core.nextDeadlineMs(), now + 4_000);

    // Publish again at +3s -> last_event_at + 4s = +7s (< maxBatchAgeMs +10s)
    now += 3_000;
    core.events.publish(pub, "deploy", makeEvent({ id: "e2" }));
    assert.equal(core.events.nextDeadlineMs(), now + 4_000);

    // Publish again at +3.5s (total +6.5s, still within 4s coalesce window from +3s) ->
    // last_event_at + 4s = +10.5s > opened_at + 10s -> clamped to +10s!
    now += 3_500;
    core.events.publish(pub, "deploy", makeEvent({ id: "e3" }));
    assert.equal(core.events.nextDeadlineMs(), 1_700_000_000_000 + 10_000, "maxBatchAgeMs must clamp coalesce extension");

    // Close the batch at opened_at + 10s
    now = 1_700_000_000_000 + 10_000;
    core.tick();
    // Batch is now pending (no connector attached) -> deadline is pending expiry (opened_at + retentionMs)
    assert.equal(core.events.nextDeadlineMs(), 1_700_000_000_000 + 200_000, "pending batch expiry deadline");

    // --- (b) Attach connector -> offered batch sets inFlight ackTimeoutMs deadline ---
    const offered: string[] = [];
    const detach = core.attach("c1", (item) => {
      offered.push(item.id);
    });
    // Wait for attach's queueMicrotask by running tick (or flushing microtasks)
    core.tick();
    assert.equal(offered.length, 1);
    const batch1Id = offered[0]!;
    assert.equal(core.nextDeadlineMs(), now + 25_000, "in-flight ackTimeoutMs must be earliest deadline");

    // --- (c) Hold batch -> hold_until deadline ---
    assert.equal(core.ack("c1", batch1Id, { kind: "hold", reason: "busy" }), true);
    assert.equal(core.events.nextDeadlineMs(), now + 15_000, "held batch hold_until deadline");
    assert.equal(core.nextDeadlineMs(), now + 15_000);

    // Advance to hold_until -> re-offered -> deliver it (hits hourly wake cap of 1!)
    now += 15_000;
    core.tick();
    assert.equal(offered.length, 2);
    assert.equal(core.ack("c1", batch1Id, { kind: "delivered" }), true);

    // --- (d) Wake-cap unblock & event-body prune deadline ---
    // Publish a second batch that closes immediately (coalesceSeconds = 0)
    const sub2 = core.events.setSubscriptions("c1", [
      { id: subId, topic: "deploy", filters: [], coalesceSeconds: 0 },
    ]);
    assert.equal(sub2.ok, true);
    now += 1_000;
    core.events.publish(pub, "deploy", makeEvent({ id: "e4" }));
    // Subscription is at wake cap (1/hour), so batch2 cannot be offered yet.
    // Earliest EventRouter deadline is e1's event-body strip at t0 + retentionMs (200_000).
    assert.equal(offered.length, 2, "wake-capped batch must not be offered yet");
    assert.equal(core.events.nextDeadlineMs(), 1_700_000_000_000 + 200_000);

    // --- (e) Direct messages: pending expiry, hold_until, inFlight, settled prune ---
    core.submit("c1", { id: "msg-1", fromHandle: "alice", to: "c1/alice", text: "hi", origin: null });
    assert.equal(offered.includes("msg-1"), true);
    assert.equal(core.nextDeadlineMs(), now + 25_000, "message inFlight ackTimeoutMs");
    core.ack("c1", "msg-1", { kind: "hold", reason: "wait" });
    assert.equal(core.nextDeadlineMs(), now + 15_000, "message hold_until");

    // --- (f) TransferStore expiry and hold_until deadlines ---
    const aliceSign = generatePrivateKey("ed25519");
    const aliceBox = generatePrivateKey("x25519");
    const bobSign = generatePrivateKey("ed25519");
    const bobBox = generatePrivateKey("x25519");

    const pairConnector = (connectorId: string, signingKey: ReturnType<typeof generatePrivateKey>, encryptionKey: ReturnType<typeof generatePrivateKey>) => {
      const issued = issueGrant(adminKey, connectorId, ["files:send", "files:receive"], 60_000, new Date(now));
      assert.equal(core.pairing.addGrant(issued.signed).ok, true);
      const parsedCode = parsePairingCode(issued.code);
      assert.ok(parsedCode);
      const binding = signBinding(issued.grant, parsedCode, signingKey, encryptionKey, new Date(now));
      assert.equal(core.pairing.pair(issued.grant.id, { binding }).ok, true);
    };
    pairConnector("alice", aliceSign, aliceBox);
    pairConnector("bob", bobSign, bobBox);

    const txId = randomUUID();
    const txExpiresAt = now + 5_000;
    const sealed = seal(
      { id: txId, type: "files", from: "alice", to: "bob", toHandle: "inbox", ttlMs: 5_000 },
      Buffer.from("secret payload"),
      aliceSign,
      rawPublicKey(bobBox),
      new Date(now),
    );
    const txRes = core.transfers.submit("alice", txId, sealed.header, sealed.ciphertext);
    assert.equal(txRes.ok, true);
    assert.equal(core.transfers.nextDeadlineMs(), txExpiresAt, "transfer expires_at deadline");
    assert.equal(core.nextDeadlineMs(), txExpiresAt, "RouterCore must combine TransferStore deadline");

    // Test transfer hold_until < expires_at
    const tx2Id = randomUUID();
    const sealed2 = seal(
      { id: tx2Id, type: "files", from: "alice", to: "bob", toHandle: "inbox", ttlMs: 60_000 },
      Buffer.from("secret payload 2"),
      aliceSign,
      rawPublicKey(bobBox),
      new Date(now),
    );
    assert.equal(core.transfers.submit("alice", tx2Id, sealed2.header, sealed2.ciphertext).ok, true);
    // Expire tx1 so only tx2 remains
    now = txExpiresAt;
    core.transfers.tick();
    assert.equal(core.transfers.nextDeadlineMs(), now - 5_000 + 60_000);
    // Hold tx2 -> hold_until = now + 15_000 (< expires_at)
    assert.equal(core.transfers.ack("bob", tx2Id, { kind: "hold", reason: "later" }), true);
    assert.equal(core.transfers.nextDeadlineMs(), now + 15_000, "transfer hold_until deadline");

    detach();
  } finally {
    core.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("EventRouter.nextDeadlineMs() computes exact wake-cap unblock time and returns null after full retention prune", () => {
  const db = new DatabaseSync(":memory:");
  db.exec("PRAGMA foreign_keys = ON;");
  EventRouter.migrate(db);
  let now = 1_700_000_000_000;
  const HOUR_MS = 60 * 60 * 1000;

  const events = new EventRouter(db, {
    topics: new Map([["t", ["p"]]]),
    limits: {
      ...DEFAULT_EVENT_LIMITS,
      retentionMs: 24 * HOUR_MS,
      idempotencyMs: 48 * HOUR_MS,
      maxBatchesPerHourPerSubscription: 2,
    },
    holdRetryMs: 30_000,
    now: () => now,
    audit: () => {},
    ready: () => {},
    inFlight: () => false,
  });

  try {
    const subId = randomUUID();
    events.setSubscriptions("c1", [{ id: subId, topic: "t", filters: [], coalesceSeconds: 0 }]);
    const pub: Publisher = { id: "p", topics: new Set(["t"]) };

    // Deliver 2 batches at t=0 and t=10_000 -> hits cap=2
    const t0 = now;
    events.publish(pub, "t", makeEvent({ id: "w1" }));
    const [b1] = events.dueBatches("c1", () => false);
    assert.ok(b1);
    events.ack("c1", b1.id, { kind: "delivered" });

    now += 10_000;
    events.publish(pub, "t", makeEvent({ id: "w2" }));
    const [b2] = events.dueBatches("c1", () => false);
    assert.ok(b2);
    events.ack("c1", b2.id, { kind: "delivered" });

    // Publish 3rd batch -> pending, blocked by hourly wake cap!
    now += 5_000;
    events.publish(pub, "t", makeEvent({ id: "w3" }));
    assert.equal(events.dueBatches("c1", () => false).length, 0);
    assert.equal(events.nextDeadlineMs(), t0 + HOUR_MS, "wake-cap unblock must equal oldest delivered + 1 hour");

    // Advance to exact wake-cap unblock timestamp -> batch 3 becomes due immediately!
    now = t0 + HOUR_MS;
    const dueNow = events.dueBatches("c1", () => false);
    assert.equal(dueNow.length, 1);
    assert.equal(dueNow[0]!.events[0]!.id, "w3");
    events.ack("c1", dueNow[0]!.id, { kind: "delivered" });

    // After all batches are settled, nextDeadlineMs() equals earliest retention prune (t0 + 24h)
    assert.equal(events.nextDeadlineMs(), t0 + 24 * HOUR_MS);

    // Advance past retentionMs + idempotencyMs and tick -> everything pruned, DB returns null!
    now = t0 + 50 * HOUR_MS;
    events.tick();
    assert.equal(events.nextDeadlineMs(), null, "after pruning all settled batches and events, nextDeadlineMs() must return null");
  } finally {
    db.close();
  }
});

test("serveRouter closes a 150ms coalesced batch accurately without 1 Hz polling", { timeout: 10_000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "hyphae-polish-server-"));
  const dbPath = join(dir, "router.sqlite");
  const core = new RouterCore({
    dbPath,
    topics: new Map([["fast", ["pub"]]]),
    eventLimits: {
      ...DEFAULT_EVENT_LIMITS,
      maxBatchAgeMs: 150,
    },
  });
  const connToken = core.addConnector("c1");
  const pubToken = core.events.addPublisher("pub", ["fast"]);
  const router = await serveRouter({ core, host: "127.0.0.1", port: 0 });
  const ac = new AbortController();

  try {
    // Subscribe with coalesceSeconds=10 so maxBatchAgeMs=150ms governs closing
    const subId = randomUUID();
    const putSub = await fetch(`${router.url}/v1/subscriptions`, {
      method: "PUT",
      headers: { authorization: `Bearer ${connToken}`, "content-type": "application/json" },
      body: JSON.stringify({
        subscriptions: [{ id: subId, topic: "fast", filters: [], coalesceSeconds: 10 }],
      }),
    });
    assert.equal(putSub.status, 200);

    // Open SSE inbox stream
    const sseRes = await fetch(`${router.url}/v1/inbox`, {
      headers: { authorization: `Bearer ${connToken}` },
      signal: ac.signal,
    });
    assert.equal(sseRes.status, 200);
    assert.ok(sseRes.body);
    const reader = sseRes.body.getReader();
    const decoder = new TextDecoder();

    // Read initial `: connected\n\n`
    const firstChunk = await reader.read();
    assert.ok(decoder.decode(firstChunk.value).includes(": connected"));

    // Publish event and measure exact arrival latency of the 150ms coalesced batch
    const sentAt = performance.now();
    const pubRes = await fetch(`${router.url}/v1/events?topic=fast`, {
      method: "POST",
      headers: { authorization: `Bearer ${pubToken}`, "content-type": "application/json" },
      body: JSON.stringify(makeEvent({ id: "fast-1" })),
    });
    assert.equal(pubRes.status, 202);

    let buffer = "";
    let batchPayload: { id: string; events: Array<{ id: string }> } | null = null;
    while (batchPayload === null) {
      const { value, done } = await reader.read();
      assert.equal(done, false);
      buffer += decoder.decode(value, { stream: true });
      const idx = buffer.indexOf("\n\n");
      if (idx !== -1) {
        const frame = buffer.slice(0, idx);
        buffer = buffer.slice(idx + 2);
        const dataLine = frame.split("\n").find((l) => l.startsWith("data: "));
        if (dataLine) batchPayload = JSON.parse(dataLine.slice(6)) as { id: string; events: Array<{ id: string }> };
      }
    }
    const elapsedMs = performance.now() - sentAt;
    assert.equal(batchPayload.events[0]?.id, "fast-1");
    assert.ok(elapsedMs >= 130, `Batch closed too early (${elapsedMs.toFixed(1)}ms < 130ms)`);
    assert.ok(elapsedMs < 650, `Expected ~150ms exact deadline scheduling, took ${elapsedMs.toFixed(1)}ms (looks like 1 Hz polling)`);

    // Ack delivered via HTTP (exercises server.ts toRouterOutcome)
    const ackRes = await fetch(`${router.url}/v1/messages/${encodeURIComponent(batchPayload.id)}/ack`, {
      method: "POST",
      headers: { authorization: `Bearer ${connToken}`, "content-type": "application/json" },
      body: JSON.stringify(delivered),
    });
    assert.equal(ackRes.status, 200);
  } finally {
    ac.abort();
    await router.close();
    core.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

// ============================================================================
// 3. Compiled Filter AST Cache & PRAGMA data_version Invalidation
// ============================================================================

test("EventRouter Filter AST cache avoids re-parsing on repeated publishes and invalidates on local + external writes", () => {
  const dir = mkdtempSync(join(tmpdir(), "hyphae-polish-cache-"));
  const dbPath = join(dir, "events.sqlite");
  const core = new RouterCore({
    dbPath,
    topics: new Map([
      ["github", ["gh"]],
      ["ci", ["runner"]],
    ]),
  });
  const extDb = new DatabaseSync(dbPath);
  extDb.exec("PRAGMA busy_timeout = 2000;");

  try {
    core.addConnector("c1");
    core.addConnector("c2");

    const subA = randomUUID();
    const subB = randomUUID();
    const filtersA: Filter[] = [
      {
        all: [
          { exact: { repo: "hyphae-to/hyp" } },
          { any: [{ prefix: { type: "com.github.pull_request." } }, { exact: { "data.urgent": "true" } }] },
          { not: { suffix: { subject: "/draft" } } },
        ],
      },
    ];
    const filtersB: Filter[] = [{ prefix: { repo: "hyphae-to/" } }];

    assert.equal(core.events.setSubscriptions("c1", [{ id: subA, topic: "github", filters: filtersA, coalesceSeconds: 60 }]).ok, true);
    assert.equal(core.events.setSubscriptions("c2", [{ id: subB, topic: "github", filters: filtersB, coalesceSeconds: 60 }]).ok, true);

    const ghPub: Publisher = { id: "gh", topics: new Set(["github"]) };

    // Reference uncached oracle reading SQLite directly
    const referenceMatched = (topic: string, event: CloudEvent): number => {
      const rows = extDb.prepare("SELECT filters FROM subscriptions WHERE topic = ?").all(topic) as Array<{ filters: string }>;
      let count = 0;
      for (const row of rows) {
        const checked = checkFilters(JSON.parse(row.filters));
        if (checked.ok && matchesFilters(checked.filters, event)) count++;
      }
      return count;
    };

    const sampleEvents: CloudEvent[] = [
      makeEvent({ id: "gh-1", source: "github.com/hyphae-to/hyp", type: "com.github.pull_request.opened", subject: "pull/1", repo: "hyphae-to/hyp", data: { urgent: false } }),
      makeEvent({ id: "gh-2", source: "github.com/hyphae-to/hyp", type: "com.github.pull_request.opened", subject: "pull/2/draft", repo: "hyphae-to/hyp", data: { urgent: false } }),
      makeEvent({ id: "gh-3", source: "github.com/hyphae-to/hyp", type: "com.github.issue.opened", subject: "issues/3", repo: "hyphae-to/hyp", data: { urgent: true } }),
      makeEvent({ id: "gh-4", source: "github.com/hyphae-to/other", type: "com.github.pull_request.opened", subject: "pull/4", repo: "hyphae-to/other", data: {} }),
      makeEvent({ id: "gh-5", source: "github.com/other/repo", type: "com.github.pull_request.opened", subject: "pull/5", repo: "other/repo", data: {} }),
    ];

    // Warm cache on first publish, then verify subsequent publishes perform ZERO JSON.parse calls
    const first = core.events.publish(ghPub, "github", sampleEvents[0]);
    assert.equal(first.ok, true);
    if (first.ok) assert.equal(first.matched, referenceMatched("github", sampleEvents[0]!));

    const origParse = JSON.parse;
    let parseCalls = 0;
    JSON.parse = ((...args: Parameters<typeof JSON.parse>) => {
      parseCalls++;
      return origParse(...args);
    }) as typeof JSON.parse;
    try {
      for (const ev of sampleEvents.slice(1)) {
        const res = core.events.publish(ghPub, "github", ev);
        assert.equal(res.ok, true);
        if (res.ok) assert.equal(res.matched, referenceMatchedCount(ev));
      }
      assert.equal(parseCalls, 0, "warm Filter AST cache must not invoke JSON.parse on repeated publishes");
    } finally {
      JSON.parse = origParse;
    }

    function referenceMatchedCount(ev: CloudEvent): number {
      const saved = JSON.parse;
      JSON.parse = origParse;
      try {
        return referenceMatched("github", ev);
      } finally {
        JSON.parse = saved;
      }
    }

    // 1. Same-connection setSubscriptions invalidation
    assert.equal(
      core.events.setSubscriptions("c1", [
        { id: subA, topic: "github", filters: [{ exact: { repo: "other/repo" } }], coalesceSeconds: 60 },
      ]).ok,
      true,
    );
    const evAfterUpdate = makeEvent({ id: "gh-6", source: "github.com/other/repo", type: "com.github.push", repo: "other/repo" });
    const resAfterUpdate = core.events.publish(ghPub, "github", evAfterUpdate);
    assert.equal(resAfterUpdate.ok, true);
    if (resAfterUpdate.ok) assert.equal(resAfterUpdate.matched, referenceMatched("github", evAfterUpdate));
    assert.equal(resAfterUpdate.ok && resAfterUpdate.matched, 1);

    // 2. Same-connection removeConnector invalidation
    core.events.removeConnector("c2");
    const evAfterRevoke = makeEvent({ id: "gh-7", source: "github.com/hyphae-to/other", type: "com.github.push", repo: "hyphae-to/other" });
    const resAfterRevoke = core.events.publish(ghPub, "github", evAfterRevoke);
    assert.equal(resAfterRevoke.ok, true);
    if (resAfterRevoke.ok) assert.equal(resAfterRevoke.matched, 0);

    // 3. External-connection SQLite UPDATE/INSERT/DELETE invalidation via PRAGMA data_version
    const extSubId = randomUUID();
    extDb
      .prepare(
        "INSERT INTO subscriptions (id, connector_id, topic, filters, coalesce_seconds, created_at) VALUES (?, ?, ?, ?, ?, ?)",
      )
      .run(extSubId, "c2", "github", JSON.stringify([{ exact: { repo: "external/live" } }]), 60, Date.now());

    const evExtInsert = makeEvent({ id: "gh-8", source: "github.com/external/live", type: "com.github.push", repo: "external/live" });
    const resExtInsert = core.events.publish(ghPub, "github", evExtInsert);
    assert.equal(resExtInsert.ok, true);
    if (resExtInsert.ok) {
      assert.equal(resExtInsert.matched, 1, "PRAGMA data_version must invalidate cache after external INSERT");
      assert.equal(resExtInsert.matched, referenceMatched("github", evExtInsert));
    }

    // External UPDATE changes filter to a different repo
    extDb
      .prepare("UPDATE subscriptions SET filters = ? WHERE id = ?")
      .run(JSON.stringify([{ exact: { repo: "external/renamed" } }]), extSubId);

    const evExtOld = makeEvent({ id: "gh-9", source: "github.com/external/live", type: "com.github.push", repo: "external/live" });
    const evExtNew = makeEvent({ id: "gh-10", source: "github.com/external/renamed", type: "com.github.push", repo: "external/renamed" });
    const resExtOld = core.events.publish(ghPub, "github", evExtOld);
    const resExtNew = core.events.publish(ghPub, "github", evExtNew);
    assert.equal(resExtOld.ok && resExtOld.matched, 0, "PRAGMA data_version must invalidate cache after external UPDATE");
    assert.equal(resExtNew.ok && resExtNew.matched, 1);

    // External DELETE removes subscription completely
    extDb.prepare("DELETE FROM subscriptions WHERE id = ?").run(extSubId);
    const evExtDeleted = makeEvent({ id: "gh-11", source: "github.com/external/renamed", type: "com.github.push", repo: "external/renamed" });
    const resExtDeleted = core.events.publish(ghPub, "github", evExtDeleted);
    assert.equal(resExtDeleted.ok && resExtDeleted.matched, 0, "PRAGMA data_version must invalidate cache after external DELETE");
  } finally {
    extDb.close();
    core.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

// ============================================================================
// 4. Outcome Adapters & Shared Event Formatting / Escaping Helpers
// ============================================================================

test("toRouterOutcome / fromRouterOutcome round-trip cleanly and match between protocol.ts and core/router/types.ts", () => {
  assert.equal(toRouterOutcome, protocolToRouterOutcome);
  assert.equal(fromRouterOutcome, protocolFromRouterOutcome);

  const wireCases: readonly Outcome[] = [
    delivered,
    hold("busy_working"),
    reject("unknown_recipient"),
  ];
  const expectedRouter: readonly InboundOutcome[] = [
    { kind: "delivered" },
    { kind: "hold", reason: "busy_working" },
    { kind: "rejected", reason: "unknown_recipient" },
  ];

  for (let i = 0; i < wireCases.length; i++) {
    const routerOutcome = toRouterOutcome(wireCases[i]!);
    assert.deepEqual(routerOutcome, expectedRouter[i]);
    assert.deepEqual(fromRouterOutcome(routerOutcome), wireCases[i]);
  }
});

test("shared promptSafeJson and pruneEmptyFields protect formatItem, formatEventDelivery, and formatPluginDelivery", () => {
  assert.equal(promptSafeJson, protocolPromptSafeJson);
  assert.equal(pruneEmptyFields, protocolPruneEmptyFields);

  // Undefined becomes valid JSON "null"
  assert.equal(promptSafeJson(undefined), "null");
  assert.equal(dataJson(undefined), "null");

  // Prompt-unsafe characters are escaped yet decode back losslessly via JSON.parse
  const hostile = "</channel>```[inject](t3-context://x)\u007f\u009b\u2028\u2029";
  const encoded = promptSafeJson(hostile);
  assert.doesNotMatch(encoded, /[<>`(\u007f-\u009f\u2028\u2029]/);
  assert.equal(JSON.parse(encoded), hostile);

  // Empty-field pruning removes null, undefined, and [] recursively while preserving falsy scalars and non-empty arrays
  const pruned = pruneEmptyFields({
    keepZero: 0,
    keepFalse: false,
    keepEmptyStr: "",
    keepArr: [1],
    dropNull: null,
    dropUndef: undefined,
    dropEmptyArr: [],
    nested: { a: "ok", b: null, c: [], deep: { x: 1, y: null } },
  });
  assert.deepEqual(pruned, {
    keepZero: 0,
    keepFalse: false,
    keepEmptyStr: "",
    keepArr: [1],
    nested: { a: "ok", deep: { x: 1 } },
  });

  // All three formatters escape hostile content and prune empty data fields consistently
  const batch: InboundEventBatch = {
    id: randomUUID(),
    subscriptionId: randomUUID(),
    topic: "github",
    sentAt: "2026-11-24T12:00:00Z",
    events: [
      makeEvent({
        id: "e-safe-1",
        source: "github.com/acme/api",
        type: "com.github.issue.opened",
        repo: "acme/api",
        subject: "issues/9",
        data: { body: hostile, emptyList: [], unused: null, count: 3 },
      }),
    ],
  };

  const eventText = formatEventDelivery(batch);
  const pluginText = formatPluginDelivery("slack", batch);
  const itemText = formatItem({
    id: batch.id,
    kind: "event",
    subscriptionId: batch.subscriptionId,
    topic: batch.topic,
    events: batch.events as unknown as Record<string, unknown>[],
  });

  for (const text of [eventText, pluginText, itemText]) {
    assert.equal(text.includes("</channel>"), false);
    assert.equal(text.includes("](t3-context://"), false);
    assert.equal(text.includes("emptyList"), false);
    assert.equal(text.includes("unused"), false);
    assert.ok(text.includes('"count":3'));
  }
});
