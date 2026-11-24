import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ToolResponse } from "./ipc.ts";
import { HttpRouterLink } from "./router/client.ts";
import { RouterCore } from "./router/core.ts";
import { serveRouter } from "./router/server.ts";
import type { InboundEventBatch, InboxItem, RouterLink, SubscriptionSpec, SubscriptionSync } from "./router/types.ts";
import { EnrollmentStore } from "./store.ts";
import { Subscriptions } from "./subscriptions.ts";
import { forkedSubscriptions, forkNote, forkProgressPath, recreateArgs, recreateForkedSubscriptions, recreateNotes, recreateOnce } from "./fork.ts";
import { MAX_SUBSCRIPTIONS_PER_THREAD } from "./tools.ts";
import { optsOutOfAutoSettle } from "./tidy.ts";

const HUB = "github-hub@bayfold-co-ops";

const waitFor = async (condition: () => boolean, timeoutMs = 5000) => {
  const deadline = Date.now() + timeoutMs;
  while (!condition()) {
    if (Date.now() > deadline) throw new Error("timed out");
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
};

const ghEvent = (id: string, labels: string[]) => ({
  specversion: "1.0",
  id,
  source: "github.com/bayfold/infra",
  type: "com.github.pull_request.labeled",
  subject: "pull/9",
  datacontenttype: "application/json",
  repo: "bayfold/infra",
  data: { number: 9, labels },
});

const result = (response: ToolResponse): unknown => {
  if (!response.ok) throw new Error(`${response.error.code}: ${response.error.message}`);
  return response.result;
};
const code = (response: ToolResponse): string => (response.ok ? "ok" : response.error.code);
const idOf = (response: ToolResponse): string => (result(response) as { id: string }).id;
let keys = 0;
/** mesh_subscribe needs a key; a fresh one per call adds a subscription, as these tests expect. */
const nextKey = (): string => `watch:bayfold/infra#${(keys += 1)}`;

const setup = async () => {
  const dir = mkdtempSync(join(tmpdir(), "t3-mesh-subs-"));
  const core = new RouterCore({ dbPath: ":memory:", topics: new Map([["github", [HUB]]]) });
  const router = await serveRouter({ core, host: "127.0.0.1", port: 0 });
  const link = new HttpRouterLink(router.url, core.addConnector("b@host"));
  const publisher = { id: HUB, topics: new Set(["github"]) };
  core.events.addPublisher(HUB, ["github"]);
  const statePath = join(dir, "state.json");
  const subscriptions = new Subscriptions(EnrollmentStore.load(statePath), link);
  return {
    core,
    link,
    statePath,
    subscriptions,
    publish: (event: unknown) => core.events.publish(publisher, "github", event),
    close: async () => {
      await link.stop();
      await router.close();
      core.close();
      rmSync(dir, { recursive: true, force: true });
    },
  };
};

test("subscribes, delivers matching batches with the thread's subscription, and unsubscribes", async () => {
  const { link, subscriptions, publish, statePath, close } = await setup();
  try {
    const subscribed = await subscriptions.subscribe("thread-a", {
      key: nextKey(),
      topic: "github",
      filters: [{ exact: { "data.labels": "agent:infra" } }],
      coalesceSeconds: 0,
    });
    const id = idOf(subscribed);
    assert.equal(subscriptions.threadOf(id), "thread-a");
    assert.deepEqual(
      (result(subscriptions.list("thread-a")) as { subscriptions: Array<{ id: string; topic: string }> }).subscriptions.map(
        (subscription) => [subscription.id, subscription.topic],
      ),
      [[id, "github"]],
    );
    assert.deepEqual(result(subscriptions.list("thread-b")), { subscriptions: [] });
    // Persisted with the thread; the router never sees thread IDs.
    const state = JSON.parse(readFileSync(statePath, "utf8")) as { subscriptions: Array<{ threadId: string }> };
    assert.equal(state.subscriptions[0]?.threadId, "thread-a");

    const received: InboundEventBatch[] = [];
    link.start(async (item: InboxItem) => {
      if (item.kind === "event") received.push(item);
      return { kind: "delivered" };
    });
    assert.deepEqual(publish(ghEvent("d1", ["agent:infra"])), { ok: true, status: "stored", matched: 1 });
    assert.deepEqual(publish(ghEvent("d2", ["agent:ops"])), { ok: true, status: "stored", matched: 0 });
    await waitFor(() => received.length === 1);
    assert.equal(received[0]?.subscriptionId, id);
    assert.deepEqual(received[0]?.events.map((event) => event.id), ["d1"]);

    assert.deepEqual(result(await subscriptions.unsubscribe("thread-b", { id })), { removed: false }, "not its subscription");
    assert.deepEqual(result(await subscriptions.unsubscribe("thread-a", { id })), { removed: true });
    assert.equal(subscriptions.threadOf(id), undefined);
    assert.deepEqual(publish(ghEvent("d3", ["agent:infra"])), { ok: true, status: "stored", matched: 0 });
  } finally {
    await close();
  }
});

test("refuses bad subscriptions without storing them", async () => {
  const { subscriptions, publish, close } = await setup();
  try {
    assert.equal(code(await subscriptions.subscribe("t", { key: nextKey(), topic: "gitlab", filters: [] })), "unknown_topic");
    assert.equal(code(await subscriptions.subscribe("t", { key: nextKey(), topic: "Bad Name", filters: [] })), "unknown_topic");
    const badFilter = await subscriptions.subscribe("t", { key: nextKey(), topic: "github", filters: [{ exact: { "data.x": 1 } }] });
    assert.equal(code(badFilter), "invalid_filter");
    assert.ok(!badFilter.ok && badFilter.error.message.startsWith('filters[0].exact["data.x"]: '));
    assert.equal(code(await subscriptions.subscribe("t", { key: nextKey(), topic: "github", filters: [], coalesceSeconds: 601 })), "invalid");
    assert.equal(code(await subscriptions.subscribe("t", { key: nextKey(), topic: "github" })), "invalid");
    assert.equal(subscriptions.count(), 0);
    // The rolled-back unknown-topic subscription is gone at the router too.
    assert.deepEqual(publish(ghEvent("d1", [])), { ok: true, status: "stored", matched: 0 });
  } finally {
    await close();
  }
});

test("router_unavailable when the router is down; nothing is stored", async () => {
  const dir = mkdtempSync(join(tmpdir(), "t3-mesh-subs-"));
  try {
    const link = new HttpRouterLink("http://127.0.0.1:9", "t3m_x");
    const subscriptions = new Subscriptions(EnrollmentStore.load(join(dir, "state.json")), link);
    assert.equal(code(await subscriptions.subscribe("t", { key: nextKey(), topic: "github", filters: [] })), "router_unavailable");
    assert.equal(subscriptions.count(), 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("at most 20 subscriptions per thread; defaults coalesceSeconds to 30", async () => {
  const { subscriptions, close } = await setup();
  try {
    for (let i = 0; i < 20; i++) assert.equal(code(await subscriptions.subscribe("t", { key: nextKey(), topic: "github", filters: [] })), "ok");
    assert.equal(code(await subscriptions.subscribe("t", { key: nextKey(), topic: "github", filters: [] })), "too_many_subscriptions");
    assert.equal(code(await subscriptions.subscribe("other", { key: nextKey(), topic: "github", filters: [] })), "ok");
    const listed = result(subscriptions.list("other")) as { subscriptions: Array<{ coalesceSeconds: number }> };
    assert.equal(listed.subscriptions[0]?.coalesceSeconds, 30);
  } finally {
    await close();
  }
});

test("concurrent subscribes all reach the router", async () => {
  const { subscriptions, publish, close } = await setup();
  try {
    const responses = await Promise.all(
      Array.from({ length: 5 }, (_, i) => subscriptions.subscribe(`t${i}`, { key: nextKey(), topic: "github", filters: [] })),
    );
    assert.deepEqual(responses.map(code), ["ok", "ok", "ok", "ok", "ok"]);
    assert.deepEqual(publish(ghEvent("d1", [])), { ok: true, status: "stored", matched: 5 });
  } finally {
    await close();
  }
});

test("prunes subscriptions of gone threads and re-sends the set", async () => {
  const { subscriptions, publish, close } = await setup();
  try {
    idOf(await subscriptions.subscribe("archived", { key: nextKey(), topic: "github", filters: [] }));
    const kept = idOf(await subscriptions.subscribe("active", { key: nextKey(), topic: "github", filters: [] }));
    await subscriptions.prune((threadId) => threadId === "archived");
    assert.equal(subscriptions.count(), 1);
    assert.equal(subscriptions.threadOf(kept), "active");
    assert.deepEqual(publish(ghEvent("d1", [])), { ok: true, status: "stored", matched: 1 });
  } finally {
    await close();
  }
});

test("the link re-sends the subscription set when it reconnects", async () => {
  const { core, link, subscriptions, publish, close } = await setup();
  try {
    idOf(await subscriptions.subscribe("t", { key: nextKey(), topic: "github", filters: [] }));
    // The router forgets the set (as after a restore); the inbox loop restores it on connect.
    core.events.setSubscriptions("b@host", []);
    assert.deepEqual(publish(ghEvent("d1", [])), { ok: true, status: "stored", matched: 0 });
    link.start(async () => ({ kind: "delivered" }));
    await waitFor(() => {
      const published = publish(ghEvent(`probe-${Date.now()}`, []));
      return published.ok && published.matched === 1;
    });
  } finally {
    await close();
  }
});

test("state files without subscriptions still load", () => {
  const dir = mkdtempSync(join(tmpdir(), "t3-mesh-state-"));
  try {
    const path = join(dir, "state.json");
    writeFileSync(path, JSON.stringify({ version: 1, enrollments: [{ threadId: "t", handle: "h", joinedAt: "x" }] }));
    const store = EnrollmentStore.load(path);
    assert.deepEqual(store.handles(), ["h"]);
    assert.deepEqual(store.subscriptions(), []);
    store.addSubscription({ id: "s", threadId: "t", topic: "github", filters: [], coalesceSeconds: 30, createdAt: "x" });
    const reloaded = EnrollmentStore.load(path);
    assert.deepEqual(reloaded.subscriptions().map((subscription) => subscription.id), ["s"]);
    assert.deepEqual(reloaded.handles(), ["h"]);
    assert.equal(reloaded.removeSubscription("other", "s"), false);
    assert.equal(reloaded.removeSubscription("t", "s"), true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

/** A router link that answers each PUT with `answer(set)` and records the sets. */
const fakeLink = (answer: (set: readonly SubscriptionSpec[]) => SubscriptionSync, wait?: () => Promise<void>) => {
  const puts: Array<readonly string[]> = [];
  const link: RouterLink = {
    setHandles: async () => {},
    setSubscriptions: async (set) => {
      puts.push(set.map((spec) => spec.id));
      if (wait !== undefined) await wait();
      return answer(set);
    },
    send: async () => ({ ok: false, error: "router_unavailable", message: "fake" }),
    peers: async () => [],
    subscriptionStatus: async () => null,
    start: () => {},
    stop: async () => {},
    directory: async () => null,
    sendTransfer: async () => ({ ok: false, error: "unsupported", message: "fake" }),
    fetchTransfer: async () => Buffer.alloc(0),
  };
  return { link, puts };
};

const withState = async (body: (statePath: string) => Promise<void>) => {
  const dir = mkdtempSync(join(tmpdir(), "t3-mesh-subs-"));
  try {
    await body(join(dir, "state.json"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
};

test("a PUT that fails while the stream stays up is retried on the sweep", async () => {
  await withState(async (statePath) => {
    let up = true;
    const { link, puts } = fakeLink(() =>
      up ? { ok: true, unknownTopics: [] } : { ok: false, error: "router_unavailable", message: "down" },
    );
    const subscriptions = new Subscriptions(EnrollmentStore.load(statePath), link);
    const id = idOf(await subscriptions.subscribe("thread-a", { key: nextKey(), topic: "github", filters: [] }));
    await subscriptions.retrySync();
    assert.equal(puts.length, 1, "nothing to retry while in sync");
    up = false;
    assert.deepEqual(result(await subscriptions.unsubscribe("thread-a", { id })), { removed: true });
    up = true;
    await subscriptions.retrySync();
    assert.deepEqual(puts, [[id], [], []], "the smaller set is sent again");
    await subscriptions.retrySync();
    assert.equal(puts.length, 3, "and only until it succeeds");
  });
});

test("a stored subscription the router refuses is dropped, and does not block new ones", async () => {
  await withState(async (statePath) => {
    let refused: string | null = null;
    const { link, puts } = fakeLink((set) =>
      refused !== null && set.some((spec) => spec.id === refused)
        ? { ok: false, error: "invalid_filter", message: "filters no longer valid", id: refused, path: "filters[0]" }
        : { ok: true, unknownTopics: [] },
    );
    const store = EnrollmentStore.load(statePath);
    const subscriptions = new Subscriptions(store, link);
    const old = idOf(await subscriptions.subscribe("thread-a", { key: nextKey(), topic: "github", filters: [] }));
    refused = old;
    const fresh = idOf(await subscriptions.subscribe("thread-b", { key: nextKey(), topic: "github", filters: [] }));
    assert.equal(store.subscription(old), undefined, "the refused one is gone");
    assert.equal(store.subscription(fresh)?.threadId, "thread-b");
    assert.deepEqual(puts.at(-1), [fresh]);
    // A refusal of the new subscription itself is still the caller's error, and changes nothing stored.
    const { link: refusing } = fakeLink((set) => {
      const candidate = set.find((spec) => spec.id !== fresh);
      return candidate === undefined
        ? { ok: true, unknownTopics: [] }
        : { ok: false, error: "invalid_filter", message: "bad", id: candidate.id };
    });
    const other = new Subscriptions(store, refusing);
    assert.equal(code(await other.subscribe("thread-c", { key: nextKey(), topic: "github", filters: [] })), "invalid_filter");
    assert.deepEqual(store.subscriptions().map((subscription) => subscription.id), [fresh]);
  });
});

test("a fork carries every subscription with a key, keyless ones from before included, and the target recreates them", async () => {
  const source = await setup();
  const target = await setup();
  try {
    const store = EnrollmentStore.load(source.statePath);
    const filters = [{ exact: { subject: "pull/9" } }];
    const subscriptions = new Subscriptions(store, source.link);
    const keyed = idOf(await subscriptions.subscribe("thread-a", { key: "assignment:bayfold/infra#8", topic: "github", filters }));
    // Stored before keys were required: no key.
    store.addSubscription({ id: "11111111-1111-4111-8111-111111111111", threadId: "thread-a", topic: "github", filters, coalesceSeconds: 30, createdAt: "2026-11-01T00:00:00.000Z" });
    const forked = forkedSubscriptions(store.subscriptionsOf("thread-a"));
    assert.deepEqual(forked.map((f) => f.key).sort(), ["assignment:bayfold/infra#8", "legacy:11111111-1111-4111-8111-111111111111"]);
    assert.ok(keyed.length > 0);
    // The target recreates both, keys kept; a fork from an older connector, without keys, still recreates.
    const forkId = "22222222-2222-4222-8222-222222222222";
    const older = [{ topic: "github", filters, coalesceSeconds: 30 }];
    for (const [index, each] of [...forked, ...older].entries()) {
      assert.equal(code(await target.subscriptions.subscribe("thread-b", recreateArgs(forkId, index, each))), "ok");
    }
    const listed = result(target.subscriptions.list("thread-b")) as { subscriptions: Array<{ key?: string }> };
    assert.deepEqual(listed.subscriptions.map((sub) => sub.key).sort(), [
      "assignment:bayfold/infra#8",
      `forked:${forkId}-2`,
      "legacy:11111111-1111-4111-8111-111111111111",
    ]);
  } finally {
    await source.close();
    await target.close();
  }
});

const ASSIGNMENT = "assignment:bayfold/infra#8";
const forkedSub = (key: string, subject: string) => ({ key, topic: "github", filters: [{ exact: { subject } }], coalesceSeconds: 30 });
/** Records auto-settle calls; fails them while `failing` is set. */
const autoSettle = () => {
  const calls: Array<{ enabled: boolean; subscriptionId: string }> = [];
  const control = { failing: false };
  const set = async (_threadId: string, enabled: boolean, subscriptionId: string): Promise<string | null> => {
    calls.push({ enabled, subscriptionId });
    return control.failing ? "T3 is not connected" : null;
  };
  return { calls, control, set };
};

test("role subscribe opts out, warns on failure, and retries with the same subscription ID", async () => {
  await withState(async (statePath) => {
    const { link } = fakeLink(() => ({ ok: true, unknownTopics: [] }));
    const subscriptions = new Subscriptions(EnrollmentStore.load(statePath), link);
    const settle = autoSettle();
    settle.control.failing = true;
    const args = { key: "role:release", topic: "github", filters: [] };
    const subscribed = await subscriptions.subscribeWithAutoSettle("release", args, settle.set);
    const id = idOf(subscribed);
    assert.deepEqual(result(subscribed), {
      id, outcome: "created", filters: [], warning: "T3 auto-settle could not be turned off: T3 is not connected",
    });
    settle.control.failing = false;
    assert.deepEqual(result(await subscriptions.subscribeWithAutoSettle("release", args, settle.set)), {
      id, outcome: "unchanged", filters: [],
    });
    assert.deepEqual(settle.calls, [{ enabled: false, subscriptionId: id }, { enabled: false, subscriptionId: id }]);
    await subscriptions.subscribeWithAutoSettle("release", { ...args, key: "watch:release" }, settle.set);
    assert.equal(settle.calls.length, 2, "ordinary watches do not opt out");
    assert.equal(code(await subscriptions.subscribeWithAutoSettle("release", { ...args, filters: [{ nonsense: {} }] }, settle.set)), "invalid_filter");
    assert.equal(settle.calls.length, 2, "a refused subscribe does not opt out");
  });
});

test("unsubscribe re-enables only after the last role or assignment leaves, in either order", async () => {
  for (const order of [[ASSIGNMENT, "role:release", "role:lead"], ["role:lead", "role:release", ASSIGNMENT]]) {
    await withState(async (statePath) => {
      const { link } = fakeLink(() => ({ ok: true, unknownTopics: [] }));
      const subscriptions = new Subscriptions(EnrollmentStore.load(statePath), link);
      const settle = autoSettle();
      const ids = new Map<string, string>();
      for (const key of [...order, "watch:release"]) {
        ids.set(key, idOf(await subscriptions.subscribeWithAutoSettle("release", { key, topic: "github", filters: [] }, settle.set)));
      }
      settle.calls.length = 0;
      assert.deepEqual(result(await subscriptions.unsubscribeWithAutoSettle("other", { key: order[0] }, settle.set)), { removed: false });
      assert.deepEqual(result(await subscriptions.unsubscribeWithAutoSettle("release", { key: "role:missing" }, settle.set)), { removed: false });
      assert.equal(code(await subscriptions.unsubscribeWithAutoSettle("release", {}, settle.set)), "invalid");
      assert.deepEqual(settle.calls, []);
      for (const [index, key] of order.entries()) {
        // Exercise both accepted unsubscribe selectors.
        const args = index === 1 ? { id: ids.get(key) } : { key };
        assert.deepEqual(result(await subscriptions.unsubscribeWithAutoSettle("release", args, settle.set)), { removed: true });
        assert.deepEqual(settle.calls, index === order.length - 1 ? [{ enabled: true, subscriptionId: ids.get(key) }] : []);
      }
      assert.deepEqual(subscriptions.keysOf("release"), ["watch:release"], "an ordinary watch does not prolong protection");
      await subscriptions.unsubscribeWithAutoSettle("release", { key: "watch:release" }, settle.set);
      assert.equal(settle.calls.length, 1, "ordinary unsubscribe does not change auto-settlement");
    });
  }
});

test("a fork's source re-enables auto-settle once if it held a role or assignment, and not for watches only", async () => {
  const target = await setup();
  try {
    const cases: Array<{ thread: string; keys: string[]; protectedKey: string | null }> = [
      { thread: "role-only", keys: ["role:release", "watch:x#1"], protectedKey: "role:release" },
      { thread: "both", keys: [ASSIGNMENT, "role:lead", "watch:x#2"], protectedKey: ASSIGNMENT },
      { thread: "watches", keys: ["watch:x#3", "watch:x#4"], protectedKey: null },
    ];
    for (const { thread, keys, protectedKey } of cases) {
      for (const key of keys) assert.equal(code(await target.subscriptions.subscribe(thread, forkedSub(key, "pull/9"))), "ok");
      const ids = new Map(
        (result(target.subscriptions.list(thread)) as { subscriptions: Array<{ id: string; key?: string }> }).subscriptions.map((sub) => [sub.key, sub.id]),
      );
      const settle = autoSettle();
      assert.equal(await target.subscriptions.pruneThreadWithAutoSettle(thread, settle.set), keys.length);
      assert.deepEqual(result(target.subscriptions.list(thread)), { subscriptions: [] }, `${thread}: all removed`);
      const expected = protectedKey === null ? [] : [{ enabled: true, subscriptionId: ids.get(protectedKey) ?? "" }];
      assert.deepEqual(settle.calls, expected, `${thread}: one re-enable only when a role or assignment was held`);
    }
  } finally {
    await target.close();
  }
});

test("only the exact role: and assignment: prefixes opt a thread out of auto-settle", () => {
  for (const key of ["role:release", "role:lead-ci", ASSIGNMENT]) assert.equal(optsOutOfAutoSettle(key), true, key);
  for (const key of ["roles:x", "role", "rolex:y", "Role:x", "assignments:o/r#1", "watch:role:x", "watch:x#1", undefined]) {
    assert.equal(optsOutOfAutoSettle(key), false, String(key));
  }
});

test("a fork's target opts role keys out, reports failures, and retries held keys after a stop", async () => {
  await withState(async (statePath) => {
    const { link } = fakeLink(() => ({ ok: true, unknownTopics: [] }));
    const store = EnrollmentStore.load(statePath);
    const subscriptions = new Subscriptions(store, link);
    const settle = autoSettle();
    settle.control.failing = true;
    const forkId = "66666666-6666-4666-8666-666666666666";
    const thread = `mesh-fork:${forkId}`;
    const forked = [forkedSub("role:release", "pull/9"), forkedSub("watch:release", "pull/9")];
    const recreated = await recreateForkedSubscriptions(subscriptions, settle.set, thread, forkId, forked, new Set(), [], () => {});
    const id = store.subscriptionsOf(thread).find((subscription) => subscription.key === "role:release")?.id;
    assert.ok(id !== undefined);
    assert.equal(recreated.recreated, 2);
    assert.deepEqual(settle.calls, [{ enabled: false, subscriptionId: id }]);
    assert.deepEqual(recreated.optOutFailed, [{ key: "role:release", reason: "T3 is not connected" }]);
    assert.match(recreateNotes(recreated).optOut ?? "", /role:release \(T3 is not connected\)/);
    settle.control.failing = false;
    const retried = await recreateForkedSubscriptions(subscriptions, settle.set, thread, forkId, forked, new Set(recreated.done), store.subscriptionsOf(thread), () => {});
    assert.deepEqual(retried.optOutFailed, []);
    assert.deepEqual(settle.calls, [{ enabled: false, subscriptionId: id }, { enabled: false, subscriptionId: id }]);
    assert.equal(store.subscriptionsOf(thread).length, 2);
  });
});

test("a fork's target names what it could not recreate, opts each assignment out, and records each key as stored", async () => {
  const target = await setup();
  try {
    const store = EnrollmentStore.load(target.statePath);
    const subscriptions = new Subscriptions(store, target.link);
    const settle = autoSettle();
    settle.control.failing = true;
    const forkId = "77777777-7777-4777-8777-777777777777";
    const thread = `mesh-fork:${forkId}`;
    const forked = [
      forkedSub("watch:bayfold/infra#12", "pull/12"),
      forkedSub(ASSIGNMENT, "pull/9"),
      { key: "Not A Key", topic: "github", filters: [], coalesceSeconds: 30 },
      { key: "watch:bayfold/infra#13", topic: "github", filters: [{ nonsense: { subject: "pull/13" } }], coalesceSeconds: 30 },
    ];
    const recorded: Array<readonly string[]> = [];
    const result = await recreateForkedSubscriptions(subscriptions, settle.set, thread, forkId, forked, new Set(), store.subscriptionsOf(thread), (done) =>
      recorded.push(done),
    );
    assert.equal(result.recreated, 2);
    assert.deepEqual(recorded, [["watch:bayfold/infra#12"], ["watch:bayfold/infra#12", ASSIGNMENT]], "each key recorded once stored");
    assert.deepEqual(result.done, ["watch:bayfold/infra#12", ASSIGNMENT]);
    assert.deepEqual(result.failed, [
      { key: null, code: "invalid" },
      { key: "watch:bayfold/infra#13", code: "invalid_filter" },
    ]);
    const assignmentId = store.subscriptionsOf(thread).find((s) => s.key === ASSIGNMENT)?.id;
    assert.ok(assignmentId !== undefined);
    assert.deepEqual(settle.calls, [{ enabled: false, subscriptionId: assignmentId }]);
    assert.deepEqual(result.optOutFailed, [{ key: ASSIGNMENT, reason: "T3 is not connected" }]);
    const notes = recreateNotes(result);
    assert.match(notes.notMoved ?? "", /one with an invalid key \(invalid\), watch:bayfold\/infra#13 \(invalid_filter\); call mesh_subscribe with the same key/);
    assert.doesNotMatch(notes.notMoved ?? "", /Not A Key/, "a string that is not a key is not echoed");
    assert.match(notes.optOut ?? "", /auto-settle could not be turned off for assignment:bayfold\/infra#8 \(T3 is not connected\)/);
    assert.deepEqual(recreateNotes({ failed: [], optOutFailed: [] }), { notMoved: null, optOut: null });
  } finally {
    await target.close();
  }
});

test("a fork recreates once: a later offer reuses the outcome and undoes nothing; a run cut short finishes without creating its done keys again", async () => {
  const target = await setup();
  const dir = mkdtempSync(join(tmpdir(), "t3-mesh-fork-progress-"));
  try {
    const store = EnrollmentStore.load(target.statePath);
    const subscriptions = new Subscriptions(store, target.link);
    const settle = autoSettle();
    const forkId = "88888888-8888-4888-8888-888888888888";
    const thread = `mesh-fork:${forkId}`;
    const progress = forkProgressPath(dir, forkId);
    // The thread is two short of its limit, so the third forked subscription fails.
    for (let i = 0; i < MAX_SUBSCRIPTIONS_PER_THREAD - 2; i += 1) {
      assert.equal(code(await subscriptions.subscribe(thread, forkedSub(`watch:own#${i}`, `pull/${100 + i}`))), "ok");
    }
    const forked = [forkedSub(ASSIGNMENT, "pull/9"), forkedSub("watch:bayfold/infra#12", "pull/12"), forkedSub("watch:bayfold/infra#14", "pull/14")];
    let runs = 0;
    const run = (done: ReadonlySet<string>, record: (done: readonly string[]) => void) => {
      runs += 1;
      return recreateForkedSubscriptions(subscriptions, settle.set, thread, forkId, forked, done, store.subscriptionsOf(thread), record);
    };
    const first = await recreateOnce(progress, run);
    assert.deepEqual(first.failed, [{ key: "watch:bayfold/infra#14", code: "too_many_subscriptions" }]);

    // After the first turn, the agent drops the assignment, narrows the watch and frees a slot.
    assert.equal(code(await subscriptions.unsubscribe(thread, { key: ASSIGNMENT })), "ok");
    const narrowed = [{ exact: { subject: "pull/12", type: "com.github.pull_request.closed" } }];
    assert.equal(code(await subscriptions.subscribe(thread, { key: "watch:bayfold/infra#12", topic: "github", filters: narrowed })), "ok");
    assert.equal(code(await subscriptions.unsubscribe(thread, { key: "watch:own#0" })), "ok");

    // The fork is offered again (its result could not be sent): the same outcome, nothing run.
    const again = await recreateOnce(progress, run);
    assert.equal(runs, 1);
    assert.deepEqual(again, first, "the same outcome, so the same first-turn text");
    const keys = store.subscriptionsOf(thread).map((s) => s.key);
    assert.ok(!keys.includes(ASSIGNMENT), "the removed assignment stays removed");
    assert.ok(!keys.includes("watch:bayfold/infra#14"), "a failure is left for the agent, as its first turn says");
    assert.deepEqual(store.subscriptionsOf(thread).find((s) => s.key === "watch:bayfold/infra#12")?.filters, narrowed);
    assert.equal(settle.calls.length, 1);

    // Another fork whose first run stops after two keys are stored (the daemon stopped).
    const other = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
    const otherThread = `mesh-fork:${other}`;
    const second = "assignment:bayfold/infra#16";
    const otherForked = [forkedSub(ASSIGNMENT, "pull/9"), forkedSub(second, "pull/16"), forkedSub("watch:bayfold/infra#15", "pull/15")];
    const otherProgress = forkProgressPath(dir, other);
    await assert.rejects(
      recreateOnce(otherProgress, (done, record) =>
        recreateForkedSubscriptions(subscriptions, settle.set, otherThread, other, otherForked.slice(0, 2), done, store.subscriptionsOf(otherThread), record).then(() => {
          throw new Error("stopped");
        }),
      ),
    );
    const firstId = store.subscriptionsOf(otherThread).find((s) => s.key === ASSIGNMENT)?.id;
    assert.ok(firstId !== undefined);
    // Say one of them is removed before the next offer.
    assert.equal(code(await subscriptions.unsubscribe(otherThread, { key: second })), "ok");
    const callsBefore = settle.calls.length;
    // The next offer finishes the run: recorded keys are not created again; a held one gets its opt-out again.
    const finished = await recreateOnce(otherProgress, (done, record) =>
      recreateForkedSubscriptions(subscriptions, settle.set, otherThread, other, otherForked, done, store.subscriptionsOf(otherThread), record),
    );
    assert.equal(finished.recreated, 3);
    assert.deepEqual(store.subscriptionsOf(otherThread).map((s) => s.key).sort(), [ASSIGNMENT, "watch:bayfold/infra#15"], "the removed one stays removed");
    assert.equal(store.subscriptionsOf(otherThread).find((s) => s.key === ASSIGNMENT)?.id, firstId);
    assert.deepEqual(settle.calls.slice(callsBefore), [{ enabled: false, subscriptionId: firstId }]);
  } finally {
    await target.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("an offer of a fork that overlaps a recreate still running joins it, and a later one reuses its outcome", async () => {
  const target = await setup();
  const dir = mkdtempSync(join(tmpdir(), "t3-mesh-fork-overlap-"));
  try {
    const store = EnrollmentStore.load(target.statePath);
    const subscriptions = new Subscriptions(store, target.link);
    const forkId = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
    const thread = `mesh-fork:${forkId}`;
    const progress = forkProgressPath(dir, forkId);
    const second = "assignment:bayfold/infra#16";
    const forked = [forkedSub(ASSIGNMENT, "pull/9"), forkedSub(second, "pull/16")];
    // The first assignment's opt-out hangs, as when T3 is slow to answer, until released.
    let release = (): void => {};
    const slow = new Promise<void>((resolve) => {
      release = resolve;
    });
    const optOuts: string[] = [];
    const setAutoSettle = async (_threadId: string, _enabled: boolean, subscriptionId: string): Promise<string | null> => {
      optOuts.push(subscriptionId);
      if (optOuts.length === 1) await slow;
      return null;
    };
    let runs = 0;
    const run = (done: ReadonlySet<string>, record: (done: readonly string[]) => void) => {
      runs += 1;
      return recreateForkedSubscriptions(subscriptions, setAutoSettle, thread, forkId, forked, done, store.subscriptionsOf(thread), record);
    };
    const firstOffer = recreateOnce(progress, run);
    await waitFor(() => optOuts.length === 1);
    // The router offers the transfer again while the first run waits.
    const overlapping = recreateOnce(progress, run);
    release();
    const [first, joined] = await Promise.all([firstOffer, overlapping]);
    assert.equal(runs, 1, "the overlapping offer joined the run");
    assert.deepEqual(joined, first);
    const secondId = store.subscriptionsOf(thread).find((s) => s.key === second)?.id;
    assert.ok(secondId !== undefined);

    // After the first turn the agent removes the second assignment; another offer recreates nothing.
    assert.equal(code(await subscriptions.unsubscribe(thread, { key: second })), "ok");
    assert.deepEqual(await recreateOnce(progress, run), first);
    assert.equal(runs, 1);
    assert.deepEqual(store.subscriptionsOf(thread).map((s) => s.key), [ASSIGNMENT], "the removed assignment stays removed");
    assert.equal(optOuts.length, 2, "one opt-out per assignment, none repeated");
  } finally {
    await target.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a fork's recreate never overwrites a mesh_subscribe the thread makes while it runs", async () => {
  await withState(async (statePath) => {
    let release = (): void => {};
    let gated = false;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    let entered = (): void => {};
    const firstPut = new Promise<void>((resolve) => {
      entered = resolve;
    });
    const { link } = fakeLink(() => ({ ok: true, unknownTopics: [] }), async () => {
      if (gated) return;
      gated = true;
      entered();
      await gate;
    });
    const store = EnrollmentStore.load(statePath);
    const subscriptions = new Subscriptions(store, link);
    const settle = autoSettle();
    const forkId = "99999999-9999-4999-8999-999999999999";
    const thread = `mesh-fork:${forkId}`;
    const forked = [forkedSub("watch:bayfold/infra#1", "pull/1"), forkedSub("watch:bayfold/infra#2", "pull/2")];
    const recreate = recreateForkedSubscriptions(subscriptions, settle.set, thread, forkId, forked, new Set(), store.subscriptionsOf(thread), () => {});
    await firstPut;
    // While the first recreate waits on the router, a call for the second key arrives on the thread.
    const narrowed = [{ exact: { subject: "pull/2", type: "com.github.pull_request.closed" } }];
    const agent = subscriptions.subscribe(thread, { key: "watch:bayfold/infra#2", topic: "github", filters: narrowed });
    release();
    assert.equal(code(await agent), "ok");
    const result = await recreate;
    assert.equal(result.recreated, 2);
    assert.deepEqual(store.subscriptionsOf(thread).find((s) => s.key === "watch:bayfold/infra#2")?.filters, narrowed, "that call's filters win");
  });
});

test("subscribeIfMissing calls onHeld inside the queue, before a change queued behind it runs", async () => {
  const { subscriptions, close } = await setup();
  const keysOf = (threadId: string): Array<string | undefined> =>
    (result(subscriptions.list(threadId)) as { subscriptions: Array<{ key?: string }> }).subscriptions.map((sub) => sub.key);
  try {
    const seen: Array<Array<string | undefined>> = [];
    const created = subscriptions.subscribeIfMissing("t", forkedSub("watch:x#1", "pull/1"), () => seen.push(keysOf("t")));
    const removed = subscriptions.unsubscribe("t", { key: "watch:x#1" });
    assert.equal(code(await created), "ok");
    assert.equal(code(await removed), "ok");
    assert.deepEqual(seen, [["watch:x#1"]], "held when onHeld ran; the unsubscribe ran after it");
    assert.deepEqual(result(subscriptions.list("t")), { subscriptions: [] });
    // Kept: an existing key is returned as it is, and onHeld still runs.
    const narrowed = [{ exact: { subject: "pull/2", type: "com.github.pull_request.closed" } }];
    assert.equal(code(await subscriptions.subscribe("t", { key: "watch:x#2", topic: "github", filters: narrowed })), "ok");
    let kept = 0;
    const again = await subscriptions.subscribeIfMissing("t", forkedSub("watch:x#2", "pull/2"), () => {
      kept += 1;
    });
    assert.equal((result(again) as { outcome: string }).outcome, "kept");
    assert.equal(kept, 1);
    assert.deepEqual(keysOf("t"), ["watch:x#2"]);
  } finally {
    await close();
  }
});

test("a call without a key is refused and adds nothing", async () => {
  const { subscriptions, close } = await setup();
  try {
    assert.equal(code(await subscriptions.subscribe("t", { topic: "github", filters: [] })), "invalid");
    assert.deepEqual(result(subscriptions.list("t")), { subscriptions: [] });
  } finally {
    await close();
  }
});

test("event routers get only their subscription subsets, with unknown names refused", async () => {
  await withState(async (statePath) => {
    const primary = fakeLink(() => ({ ok: true, unknownTopics: [] }));
    const extra = fakeLink(() => ({ ok: true, unknownTopics: [] }));
    const store = EnrollmentStore.load(statePath);
    const subscriptions = new Subscriptions(store, primary.link, new Map([["private", extra.link]]));
    const args = { key: nextKey(), topic: "github", filters: [] };
    const p = idOf(await subscriptions.subscribe("t", args));
    const e = idOf(await subscriptions.subscribe("t", { ...args, key: nextKey(), router: "private" }));
    await subscriptions.sync();
    assert.deepEqual(primary.puts, [[p], [p]]);
    assert.deepEqual(extra.puts, [[e], [e]]);
    assert.equal(store.subscription(p)?.router, undefined);
    assert.equal(store.subscription(e)?.router, "private");
    assert.equal(subscriptions.owns(p, "private"), false);
    assert.equal(subscriptions.owns(e, "primary"), false);
    assert.equal(subscriptions.owns(e, "private"), true);
    const unknown = await subscriptions.subscribe("t", { ...args, router: "missing" });
    assert.ok(!unknown.ok);
    assert.equal(unknown.error.code, "unknown_router");
    assert.match(unknown.error.message, /configured routers: primary, private/);
    const listed = result(subscriptions.list("t")) as { subscriptions: Array<{ router: string }> };
    assert.deepEqual(listed.subscriptions.map((subscription) => subscription.router), ["primary", "private"]);
  });
});

test("a refusal restores only its router, and an existing key cannot change router", async () => {
  await withState(async (statePath) => {
    const primary = fakeLink(() => ({ ok: true, unknownTopics: [] }));
    let refuse = false;
    const extra = fakeLink(() => ({ ok: true, unknownTopics: refuse ? ["github"] : [] }));
    const store = EnrollmentStore.load(statePath);
    const subscriptions = new Subscriptions(store, primary.link, new Map([["private", extra.link]]));
    const args = { key: nextKey(), topic: "github", filters: [] };
    const id = idOf(await subscriptions.subscribe("t", args));
    const moved = await subscriptions.subscribe("t", { ...args, router: "private" });
    assert.ok(!moved.ok);
    assert.equal(moved.error.message, `unsubscribe ${args.key} first, then subscribe with the new router`);
    assert.deepEqual(primary.puts, [[id]]);
    assert.deepEqual(extra.puts, [], "router changes do not send any PUT");
    refuse = true;
    assert.equal(code(await subscriptions.subscribe("t", { ...args, key: nextKey(), router: "private" })), "unknown_topic");
    assert.deepEqual(primary.puts, [[id]], "another router's refusal leaves primary untouched");
    assert.deepEqual(extra.puts.at(-1), []);
    assert.equal(store.subscription(id)?.router, undefined);
    refuse = false;
    await subscriptions.unsubscribe("t", { id });
    const replacement = idOf(await subscriptions.subscribe("t", { ...args, router: "private" }));
    assert.notEqual(replacement, id);
    assert.equal(store.subscription(replacement)?.router, "private");
  });
});

test("pruning spans routers, and retrySync only retries failed links", async () => {
  await withState(async (statePath) => {
    const primary = fakeLink(() => ({ ok: true, unknownTopics: [] }));
    let up = true;
    const extra = fakeLink(() => up ? { ok: true, unknownTopics: [] } : { ok: false, error: "router_unavailable", message: "down" });
    const store = EnrollmentStore.load(statePath);
    const subscriptions = new Subscriptions(store, primary.link, new Map([["private", extra.link]]));
    const args = { topic: "github", filters: [] };
    await subscriptions.subscribe("gone", { ...args, key: nextKey() });
    await subscriptions.subscribe("gone", { ...args, key: nextKey(), router: "private" });
    const kept = idOf(await subscriptions.subscribe("kept", { ...args, key: nextKey(), router: "private" }));
    up = false;
    await subscriptions.prune((thread) => thread === "gone");
    assert.deepEqual(store.subscriptions().map(({ id }) => id), [kept]);
    assert.deepEqual(primary.puts.at(-1), []);
    assert.deepEqual(extra.puts.at(-1), [kept]);
    const primaryPuts = primary.puts.length;
    const extraPuts = extra.puts.length;
    up = true;
    await subscriptions.retrySync();
    assert.equal(primary.puts.length, primaryPuts);
    assert.equal(extra.puts.length, extraPuts + 1);
    await subscriptions.retrySync();
    assert.equal(extra.puts.length, extraPuts + 1);
    await subscriptions.pruneThreadWithAutoSettle("kept", autoSettle().set);
    assert.deepEqual(extra.puts.at(-1), []);
  });
});

test("a refusal naming another router's subscription cannot prune it", async () => {
  await withState(async (statePath) => {
    const primary = fakeLink(() => ({ ok: true, unknownTopics: [] }));
    let refused: string | undefined;
    const extra = fakeLink(() => refused === undefined
      ? { ok: true, unknownTopics: [] }
      : { ok: false, error: "invalid_filter", message: "bad", id: refused });
    const store = EnrollmentStore.load(statePath);
    const subscriptions = new Subscriptions(store, primary.link, new Map([["private", extra.link]]));
    const id = idOf(await subscriptions.subscribe("t", { key: nextKey(), topic: "github", filters: [] }));
    refused = id;
    await subscriptions.sync();
    assert.equal(store.subscription(id)?.threadId, "t");
  });
});

test("delivery status merges by router; one failed router gives null only for its own subscriptions", async () => {
  await withState(async (statePath) => {
    const primary = fakeLink(() => ({ ok: true, unknownTopics: [] }));
    const extra = fakeLink(() => ({ ok: true, unknownTopics: [] }));
    const store = EnrollmentStore.load(statePath);
    const subscriptions = new Subscriptions(store, primary.link, new Map([["private", extra.link]]));
    const p = idOf(await subscriptions.subscribe("t", { key: nextKey(), topic: "github", filters: [] }));
    const e = idOf(await subscriptions.subscribe("t", { key: nextKey(), topic: "github", filters: [], router: "private" }));
    const status = (id: string, pending: number) => ({ id, pending, oldestPendingAt: null, heldReason: null, delivered: 0, lastDeliveredAt: null, rejected: {}, dropped: {}, lastDroppedAt: null });
    primary.link.subscriptionStatus = async () => [status(p, 2), status(e, 99)];
    extra.link.subscriptionStatus = async () => [status(e, 3)];
    const list = async () => (result(await subscriptions.listWithDelivery("t")) as {
      subscriptions: Array<{ router: string; delivery: { pending: number } | null }>;
    }).subscriptions;
    assert.deepEqual((await list()).map(({ delivery }) => delivery?.pending), [2, 3]);
    extra.link.subscriptionStatus = async () => { throw new Error("down"); };
    assert.deepEqual((await list()).map(({ delivery }) => delivery?.pending ?? null), [2, null]);
    primary.link.subscriptionStatus = async () => null;
    extra.link.subscriptionStatus = async () => [status(e, 3)];
    assert.deepEqual((await list()).map(({ delivery }) => delivery?.pending ?? null), [null, 3]);
  });
});

test("old subscription state round-trips without adding a primary router field", async () => {
  await withState(async (statePath) => {
    const subscription = { id: "old", threadId: "t", topic: "github", filters: [], coalesceSeconds: 30, createdAt: "then", key: "watch:old" };
    writeFileSync(statePath, JSON.stringify({ version: 1, enrollments: [], subscriptions: [subscription] }));
    const store = EnrollmentStore.load(statePath);
    assert.deepEqual(store.subscription("old"), subscription);
    store.join("t", "t"); // Forces a state write without changing the old subscription.
    const saved = JSON.parse(readFileSync(statePath, "utf8")) as { subscriptions: unknown[] };
    assert.deepEqual(saved.subscriptions, [subscription]);
    assert.deepEqual(EnrollmentStore.load(statePath).subscriptions(), [subscription]);
    store.addSubscription({ ...subscription, router: "primary" });
    assert.deepEqual(EnrollmentStore.load(statePath).subscriptions(), [subscription], "an explicit primary is also omitted on disk");
  });
});

test("forks carry only primary subscriptions, report extras in the existing note and keep them on source", async () => {
  await withState(async (statePath) => {
    const primary = fakeLink(() => ({ ok: true, unknownTopics: [] }));
    const extra = fakeLink(() => ({ ok: true, unknownTopics: [] }));
    const store = EnrollmentStore.load(statePath);
    const subscriptions = new Subscriptions(store, primary.link, new Map([["private", extra.link]]));
    const source = [undefined, "private"].map((router, index) => ({
      id: `source-${index}`, threadId: "source", key: `assignment:source-${index}`, topic: "github", filters: [], coalesceSeconds: 0, createdAt: "then",
      ...(router === undefined ? {} : { router }),
    }));
    for (const sub of source) store.addSubscription(sub);
    assert.deepEqual(forkedSubscriptions(source), [
      { key: "assignment:source-0", topic: "github", filters: [], coalesceSeconds: 0 },
    ], "the v1 payload contains no extra subscriptions or router field");
    const note = forkNote("handoff", source);
    assert.match(note, /"key":"assignment:source-1","router":"private","topic":"github"/);
    assert.match(note, /only after the destination connector has that router configured/);
    assert.match(note, /Always pass router explicitly/);
    assert.equal(forkNote("handoff", [source[0]!]), "handoff", "primary handoff notes stay unchanged");
    const settle = autoSettle();
    assert.equal(await subscriptions.pruneThreadWithAutoSettle("source", settle.set, "primary"), 1);
    assert.deepEqual(store.subscriptionsOf("source"), [source[1]]);
    assert.deepEqual(settle.calls, [], "the source stays protected by its extra-router assignment");
  });
});

test("two in-process routers deliver their own events; a private-router outage leaves primary delivery working", { timeout: 10_000 }, async () => {
  const primary = await setup();
  const extra = await setup();
  let extraClosed = false;
  try {
    const store = EnrollmentStore.load(primary.statePath);
    const subscriptions = new Subscriptions(store, primary.link, new Map([["private", extra.link]]));
    const p = idOf(await subscriptions.subscribe("company", { key: "watch:company", topic: "github", filters: [{ exact: { repo: "bayfold/infra" } }], coalesceSeconds: 0 }));
    const e = idOf(await subscriptions.subscribe("personal", { key: "watch:personal", router: "private", topic: "github", filters: [{ exact: { repo: "bowd/personal" } }], coalesceSeconds: 0 }));
    const received: Array<{ router: string; subscriptionId: string; eventIds: string[] }> = [];
    for (const [name, link] of [["primary", primary.link], ["private", extra.link]] as const) {
      link.start(async (item) => {
        if (item.kind !== "event" || !subscriptions.owns(item.subscriptionId, name)) return { kind: "rejected", reason: "wrong_router" };
        received.push({ router: name, subscriptionId: item.subscriptionId, eventIds: item.events.map(({ id }) => id) });
        return { kind: "delivered" };
      });
    }
    const personal = { ...ghEvent("same-id", []), repo: "bowd/personal", source: "github.com/bowd/personal" };
    assert.deepEqual(extra.publish(personal), { ok: true, status: "stored", matched: 1 });
    assert.deepEqual(primary.publish(ghEvent("same-id", [])), { ok: true, status: "stored", matched: 1 });
    await waitFor(() => received.length === 2);
    assert.deepEqual(received.sort((a, b) => a.router.localeCompare(b.router)), [
      { router: "primary", subscriptionId: p, eventIds: ["same-id"] },
      { router: "private", subscriptionId: e, eventIds: ["same-id"] },
    ]);
    assert.equal(primary.core.events.deliveryStatus("b@host").some((sub) => sub.id === e), false, "private subscription never reached primary");
    await extra.close();
    extraClosed = true;
    assert.deepEqual(primary.publish(ghEvent("after-outage", [])), { ok: true, status: "stored", matched: 1 });
    await waitFor(() => received.length === 3);
    assert.equal(received[2]?.router, "primary");
    assert.equal(code(await subscriptions.subscribe("company", { key: "watch:another", topic: "github", filters: [] })), "ok");
    const status = result(await subscriptions.listWithDelivery("personal")) as { subscriptions: Array<{ delivery: unknown }> };
    assert.equal(status.subscriptions[0]?.delivery, null);
  } finally {
    await primary.close();
    if (!extraClosed) await extra.close();
  }
});

test("extra subscriptions live outside the legacy state array and are invisible to a downgraded connector", async () => {
  await withState(async (statePath) => {
    const store = EnrollmentStore.load(statePath);
    const primary = { id: "primary", threadId: "t", topic: "github", filters: [], coalesceSeconds: 30, createdAt: "then", key: "watch:company" };
    const extra = { ...primary, id: "extra", key: "watch:personal", router: "private" };
    store.addSubscription(primary);
    store.addSubscription(extra);
    const saved = JSON.parse(readFileSync(statePath, "utf8")) as { subscriptions: unknown[]; eventRouterSubscriptions: unknown[] };
    assert.deepEqual(saved.subscriptions, [primary]);
    assert.deepEqual(saved.eventRouterSubscriptions, [extra]);
    assert.deepEqual(EnrollmentStore.load(statePath).subscriptions(), [primary, extra]);
    // The pre-event-router decoder (d6ee440): unknown top-level keys are ignored by Effect Schema.
    const Schema = await import("effect/Schema");
    const legacyState = Schema.Struct({ version: Schema.Literal(1), enrollments: Schema.Array(Schema.Unknown), subscriptions: Schema.Array(Schema.Struct({
      id: Schema.String, threadId: Schema.String, topic: Schema.String, filters: Schema.Array(Schema.Unknown), coalesceSeconds: Schema.Number,
      createdAt: Schema.String, key: Schema.optionalKey(Schema.String), updatedAt: Schema.optionalKey(Schema.String),
    })) });
    const downgraded = Schema.decodeUnknownSync(legacyState)(saved);
    assert.deepEqual(downgraded.subscriptions, [primary], "old code can only re-register the primary subscription");
    assert.equal(Object.hasOwn(downgraded, "eventRouterSubscriptions"), false);
  });
});

test("primary-only subscription responses match fixtures captured from d6ee440", async () => {
  await withState(async (statePath) => {
    const fixture = JSON.parse(readFileSync(new URL("./fixtures/subscriptions-primary.json", import.meta.url), "utf8")) as { list: unknown; withDelivery: unknown };
    writeFileSync(statePath, readFileSync(new URL("./fixtures/state-primary.json", import.meta.url)));
    const { link } = fakeLink(() => ({ ok: true, unknownTopics: [] }));
    const subscriptions = new Subscriptions(EnrollmentStore.load(statePath), link);
    assert.equal(JSON.stringify(subscriptions.list("primary-thread")), JSON.stringify(fixture.list));
    assert.equal(JSON.stringify(await subscriptions.listWithDelivery("primary-thread")), JSON.stringify(fixture.withDelivery));
  });
});

test("an extra router's stalled retry cannot block primary subscribe or unused-router status", { timeout: 5000 }, async () => {
  await withState(async (statePath) => {
    const primary = fakeLink(() => ({ ok: true, unknownTopics: [] }));
    const retryStarted = Promise.withResolvers<void>();
    const releaseRetry = Promise.withResolvers<void>();
    const extra = fakeLink(() => ({ ok: false, error: "router_unavailable", message: "down" }));
    const subscriptions = new Subscriptions(EnrollmentStore.load(statePath), primary.link, new Map([["private", extra.link]]));
    await subscriptions.sync("private");
    extra.link.setSubscriptions = async () => {
      retryStarted.resolve();
      await releaseRetry.promise;
      return { ok: true, unknownTopics: [] };
    };
    let extraStatuses = 0;
    extra.link.subscriptionStatus = async () => { extraStatuses += 1; await releaseRetry.promise; return null; };
    const retry = subscriptions.retrySync();
    try {
      await retryStarted.promise;
      assert.equal(code(await subscriptions.subscribe("primary-thread", { key: nextKey(), topic: "github", filters: [] })), "ok");
      await subscriptions.listWithDelivery("primary-thread");
      await subscriptions.listWithDelivery("no-subscriptions");
      assert.equal(extraStatuses, 0, "status only queries routers used by the caller");
    } finally {
      releaseRetry.resolve();
      await retry;
    }
  });
});

test("simultaneous new keys cannot create the same thread key on different routers", { timeout: 5000 }, async () => {
  await withState(async (statePath) => {
    const held = Promise.withResolvers<void>();
    const started = Promise.withResolvers<void>();
    const primary = fakeLink(() => ({ ok: true, unknownTopics: [] }));
    const extra = fakeLink(() => ({ ok: true, unknownTopics: [] }), async () => { started.resolve(); await held.promise; });
    const store = EnrollmentStore.load(statePath);
    const subscriptions = new Subscriptions(store, primary.link, new Map([["private", extra.link]]));
    const args = { key: "watch:same", topic: "github", filters: [] };
    const pending = subscriptions.subscribe("t", { ...args, router: "private" });
    try {
      await started.promise;
      const conflicting = await subscriptions.subscribe("t", args);
      assert.ok(!conflicting.ok);
      assert.equal(conflicting.error.message, "unsubscribe watch:same first, then subscribe with the new router");
      assert.equal(code(await subscriptions.subscribe("t", { ...args, key: "watch:unrelated" })), "ok");
    } finally {
      held.resolve();
      await pending;
    }
    assert.equal(store.subscriptionsOf("t").filter((sub) => sub.key === args.key).length, 1);
  });
});

test("an absent-key unsubscribe does not queue behind primary and delete a later private subscription", async () => {
  await withState(async (statePath) => {
    const started = Promise.withResolvers<void>();
    const release = Promise.withResolvers<void>();
    const primary = fakeLink(() => ({ ok: true, unknownTopics: [] }), async () => { started.resolve(); await release.promise; });
    const extra = fakeLink(() => ({ ok: true, unknownTopics: [] }));
    const store = EnrollmentStore.load(statePath);
    const subscriptions = new Subscriptions(store, primary.link, new Map([["private", extra.link]]));
    const blocked = subscriptions.sync("primary");
    try {
      await started.promise;
      assert.deepEqual(result(await subscriptions.unsubscribe("t", { key: "watch:later" })), { removed: false });
      const id = idOf(await subscriptions.subscribe("t", { key: "watch:later", topic: "github", filters: [], router: "private" }));
      release.resolve();
      await blocked;
      assert.equal(store.subscription(id)?.router, "private");
    } finally {
      release.resolve();
      await blocked;
    }
  });
});

test("a queued unsubscribe rechecks router ownership before deleting a replacement row", async () => {
  await withState(async (statePath) => {
    const started = Promise.withResolvers<void>();
    const release = Promise.withResolvers<void>();
    const primary = fakeLink(() => ({ ok: true, unknownTopics: [] }), async () => { started.resolve(); await release.promise; });
    const extra = fakeLink(() => ({ ok: true, unknownTopics: [] }));
    const store = EnrollmentStore.load(statePath);
    const old = { id: "old", threadId: "t", key: "watch:key", topic: "github", filters: [], coalesceSeconds: 0, createdAt: "then" };
    store.addSubscription(old);
    const subscriptions = new Subscriptions(store, primary.link, new Map([["private", extra.link]]));
    const blocked = subscriptions.sync("primary");
    await started.promise;
    const removing = subscriptions.unsubscribe("t", { key: old.key });
    try {
      store.removeSubscription("t", old.id);
      store.addSubscription({ ...old, id: "replacement", router: "private" });
      release.resolve();
      assert.deepEqual(result(await removing), { removed: false });
      assert.equal(store.subscription("replacement")?.router, "private");
    } finally {
      release.resolve();
      await blocked;
    }
  });
});

test("21 concurrent primary subscriptions accept the first 20 and refuse the 21st", async () => {
  await withState(async (statePath) => {
    const { link } = fakeLink(() => ({ ok: true, unknownTopics: [] }));
    const subscriptions = new Subscriptions(EnrollmentStore.load(statePath), link);
    const replies = await Promise.all(Array.from({ length: 21 }, (_, i) =>
      subscriptions.subscribe("t", { key: `watch:${i}`, topic: "github", filters: [] }),
    ));
    assert.deepEqual(replies.map(code), [...Array<string>(20).fill("ok"), "too_many_subscriptions"]);
  });
});

test("a queued primary subscribe cannot take a key that private owned when the call arrived", async () => {
  await withState(async (statePath) => {
    const started = Promise.withResolvers<void>();
    const release = Promise.withResolvers<void>();
    const primary = fakeLink(() => ({ ok: true, unknownTopics: [] }), async () => { started.resolve(); await release.promise; });
    const extra = fakeLink(() => ({ ok: true, unknownTopics: [] }));
    const store = EnrollmentStore.load(statePath);
    const subscriptions = new Subscriptions(store, primary.link, new Map([["private", extra.link]]));
    const args = { key: "watch:private", topic: "github", filters: [{ exact: { repo: "bowd/private" } }] };
    await subscriptions.subscribe("t", { ...args, router: "private" });
    const blocked = subscriptions.sync("primary");
    try {
      await started.promise;
      const changing = subscriptions.subscribe("t", args);
      await subscriptions.unsubscribe("t", { key: args.key });
      release.resolve();
      await blocked;
      const response = await changing;
      assert.ok(!response.ok);
      assert.equal(response.error.message, "unsubscribe watch:private first, then subscribe with the new router");
      assert.deepEqual(primary.puts, [[]], "the private filter never reaches primary after its queue drains");
      assert.equal(store.subscriptionsOf("t").length, 0);
    } finally {
      release.resolve();
      await blocked;
    }
  });
});

test("a definitive refusal frees quota before its own serialized rollback finishes", async () => {
  await withState(async (statePath) => {
    const rollback = Promise.withResolvers<void>();
    const release = Promise.withResolvers<void>();
    const primary = fakeLink(() => ({ ok: true, unknownTopics: [] }));
    const extra = fakeLink(() => ({ ok: true, unknownTopics: [] }));
    let puts = 0;
    extra.link.setSubscriptions = async (set) => {
      puts += 1;
      const candidate = set[0];
      if (candidate !== undefined) return { ok: false, error: "invalid_filter", message: "refused", id: candidate.id };
      rollback.resolve();
      await release.promise;
      return { ok: true, unknownTopics: [] };
    };
    const store = EnrollmentStore.load(statePath);
    const subscriptions = new Subscriptions(store, primary.link, new Map([["private", extra.link]]));
    for (let i = 0; i < 19; i++) await subscriptions.subscribe("t", { key: `watch:${i}`, topic: "github", filters: [] });
    const refused = subscriptions.subscribe("t", { key: "watch:refused", router: "private", topic: "github", filters: [] });
    try {
      await rollback.promise;
      assert.equal(code(await subscriptions.subscribe("t", { key: "watch:last", topic: "github", filters: [] })), "ok");
      assert.equal(store.subscriptionsOf("t").length, 20);
      assert.equal(puts, 2, "rollback remains on the extra link's queue");
    } finally {
      release.resolve();
      assert.equal(code(await refused), "invalid_filter");
    }
  });
});

test("a mode-only update persists under the same event-router subscription without another PUT", async () => {
  await withState(async (statePath) => {
    const primary = fakeLink(() => ({ ok: true, unknownTopics: [] }));
    const privateLink = fakeLink(() => ({ ok: true, unknownTopics: [] }));
    const subscriptions = new Subscriptions(EnrollmentStore.load(statePath), primary.link, new Map([["private", privateLink.link]]));
    const args = { key: "watch:private", topic: "github", router: "private", filters: [] };
    const id = idOf(await subscriptions.subscribe("thread", args));
    assert.equal(subscriptions.modeOf(id), "queue");
    assert.equal(idOf(await subscriptions.subscribe("thread", { ...args, mode: "interrupt" })), id);
    await subscriptions.subscribe("thread", args);
    assert.deepEqual(privateLink.puts, [[id]]);
    assert.deepEqual(primary.puts, []);
    assert.equal(EnrollmentStore.load(statePath).subscription(id)?.mode, "interrupt");
  });
});
