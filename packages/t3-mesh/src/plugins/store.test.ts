import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import type { PluginConfig, PluginTarget } from "../config.ts";
import type { InboundEventBatch } from "../router/types.ts";
import { LocalEvents } from "./store.ts";

const target = (fields: Partial<PluginTarget> = {}): PluginTarget => ({
  name: "moneypenny",
  threadId: "thread-1",
  coalesceSeconds: 5,
  maxWaitSeconds: 30,
  wakesPerHour: 120,
  ...fields,
});
const plugin = (name: string, targets: PluginTarget[]): PluginConfig => ({
  name,
  exec: "/bin/true",
  args: [],
  env: {},
  cwd: "/",
  targets,
});
const event = (id: string, fields: Record<string, unknown> = {}) => ({
  specversion: "1.0",
  id,
  source: "slack/T1/D1",
  type: "com.slack.message",
  datacontenttype: "application/json",
  data: { text: `message ${id}` },
  ...fields,
});

const setup = (plugins: PluginConfig[], dbPath = ":memory:") => {
  let now = 1_000_000;
  const events = new LocalEvents({ dbPath, plugins, now: () => now });
  const batches: InboundEventBatch[] = [];
  return {
    events,
    batches,
    advance: (ms: number) => {
      now += ms;
      events.tick();
    },
    /** Moves the clock without ticking. */
    skip: (ms: number) => {
      now += ms;
    },
    attach: () =>
      events.attach(async (batch) => {
        batches.push(batch);
        return { kind: "delivered" };
      }),
  };
};

const settle = () => new Promise((resolve) => setImmediate(resolve));
const ids = (batch: InboundEventBatch | undefined) => batch?.events.map((item) => item.id);

test("stores, answers duplicates (ignoring time) and conflicts, and refuses unknown targets", () => {
  const { events } = setup([plugin("slack", [target()])]);
  assert.deepEqual(events.publish("slack", "moneypenny", event("e1", { time: "2026-10-08T10:00:00Z" })), {
    ok: true,
    status: "stored",
  });
  assert.deepEqual(events.publish("slack", "moneypenny", event("e1", { time: "2026-10-08T10:05:00Z" })), {
    ok: true,
    status: "duplicate",
  });
  const conflict = events.publish("slack", "moneypenny", event("e1", { data: { text: "edited" } }));
  assert.equal(conflict.ok ? "ok" : conflict.error, "id_conflict");
  const unknown = events.publish("slack", "q", event("e2"));
  assert.equal(unknown.ok ? "ok" : unknown.error, "unknown_target");
  const other = events.publish("github", "moneypenny", event("e2"));
  assert.equal(other.ok ? "ok" : other.error, "unknown_target", "targets belong to their plugin");
  const large = events.publish("slack", "moneypenny", event("e3", { data: { text: "x".repeat(9000) } }));
  assert.deepEqual(large, { ok: false, error: "too_large", message: "data is 9011 bytes; limit 8192" });
  const invalid = events.publish("slack", "moneypenny", "text");
  assert.equal(invalid.ok ? "ok" : invalid.error, "invalid_event");
  events.close();
});

test("the publisher attribute is stamped plugin:<name>, overwriting the plugin's", async () => {
  const { events, batches, advance, attach } = setup([plugin("slack", [target({ coalesceSeconds: 0 })])]);
  events.publish("slack", "moneypenny", event("e1", { publisher: "github-hub" }));
  attach();
  advance(0);
  await settle();
  assert.equal(batches[0]?.events[0]?.["publisher"], "plugin:slack");
  assert.deepEqual(events.route(batches[0]?.subscriptionId ?? ""), { plugin: "slack", target: "moneypenny" });
  events.close();
});

test("a target's batch closes coalesceSeconds after its last event or maxWaitSeconds after its first", async () => {
  const { events, batches, advance, attach } = setup([plugin("slack", [target({ coalesceSeconds: 5, maxWaitSeconds: 12 })])]);
  attach();
  for (let i = 0; i < 4; i++) {
    events.publish("slack", "moneypenny", event(`e${i}`));
    advance(4_000);
  }
  await settle();
  assert.deepEqual(batches.map(ids), [["e0", "e1", "e2"]], "closed 12 s after the first event");
  advance(5_000);
  await settle();
  assert.deepEqual(batches.map(ids), [["e0", "e1", "e2"], ["e3"]], "closed 5 s after the last");
  events.close();
});

test("wakesPerHour caps delivered batches per target; others are not affected", async () => {
  const { events, batches, advance, attach } = setup([
    plugin("slack", [target({ coalesceSeconds: 0, wakesPerHour: 2 }), target({ name: "q", coalesceSeconds: 0 })]),
  ]);
  attach();
  for (let i = 0; i < 3; i++) {
    events.publish("slack", "moneypenny", event(`e${i}`));
    await settle();
  }
  events.publish("slack", "q", event("q1"));
  await settle();
  assert.deepEqual(batches.map(ids), [["e0"], ["e1"], ["q1"]]);
  assert.deepEqual(
    events.backlog().map(({ plugin: name, target: to, pending }) => [name, to, pending]),
    [["slack", "moneypenny", 1]],
  );
  advance(60 * 60 * 1000);
  await settle();
  assert.deepEqual(batches.map(ids).slice(-1), [["e2"]]);
  events.close();
});

test("batches wait while detached and survive a restart", async () => {
  const dir = mkdtempSync(join(tmpdir(), "t3-mesh-local-"));
  try {
    const dbPath = join(dir, "local.db");
    const plugins = [plugin("slack", [target({ coalesceSeconds: 0 })])];
    const first = setup(plugins, dbPath);
    first.events.publish("slack", "moneypenny", event("e1"));
    first.events.close();
    const second = setup(plugins, dbPath);
    assert.equal(second.events.publish("slack", "moneypenny", event("e1")).ok, true);
    assert.deepEqual(second.events.publish("slack", "moneypenny", event("e1")), { ok: true, status: "duplicate" });
    second.attach();
    second.advance(0);
    await settle();
    assert.deepEqual(second.batches.map(ids), [["e1"]]);
    second.events.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

/** Runs `body` with log lines (stderr) captured; returns the events logged. */
async function logsOf(body: () => Promise<void>): Promise<Array<Readonly<Record<string, unknown>>>> {
  const lines: Array<Readonly<Record<string, unknown>>> = [];
  const original = process.stderr.write;
  process.stderr.write = ((chunk: string | Uint8Array) => {
    for (const text of String(chunk).split("\n")) {
      if (!text.startsWith("{")) continue;
      const value: unknown = JSON.parse(text);
      if (typeof value === "object" && value !== null && !Array.isArray(value)) lines.push({ ...value });
    }
    return true;
  }) as typeof process.stderr.write;
  try {
    await body();
  } finally {
    process.stderr.write = original;
  }
  return lines;
}

test("a failing ack is logged as plugin.store_failed, never thrown", async () => {
  const logs = await logsOf(async () => {
    const { events } = setup([plugin("slack", [target({ coalesceSeconds: 0 })])]);
    let release: () => void = () => undefined;
    const answered = new Promise<void>((resolve) => {
      release = resolve;
    });
    events.attach(async () => {
      await answered;
      return { kind: "delivered" };
    });
    events.publish("slack", "moneypenny", event("e1"));
    await settle();
    // The database goes away while the batch is being delivered.
    events.close();
    release();
    await settle();
  });
  assert.deepEqual(
    logs.filter((line) => line["event"] === "plugin.store_failed").map((line) => line["operation"]),
    ["ack"],
  );
});

test("a failing tick (database locked) is logged as plugin.store_failed and retried", async () => {
  const dir = mkdtempSync(join(tmpdir(), "t3-mesh-local-"));
  try {
    const dbPath = join(dir, "local.db");
    const { events, skip } = setup([plugin("slack", [target({ coalesceSeconds: 5 })])], dbPath);
    events.publish("slack", "moneypenny", event("e1"));
    const locker = new DatabaseSync(dbPath);
    locker.exec("BEGIN IMMEDIATE");
    const logs = await logsOf(async () => {
      // The open batch is due, so the tick needs the write lock and waits out the 2 s busy timeout.
      skip(10_000);
      events.start();
      await new Promise((resolve) => setTimeout(resolve, 3_500));
    });
    locker.exec("ROLLBACK");
    locker.close();
    const failed = logs.filter((line) => line["event"] === "plugin.store_failed");
    assert.ok(failed.length >= 1);
    assert.equal(failed[0]?.["operation"], "tick");
    assert.match(String(failed[0]?.["error"]), /locked/);
    events.tick();
    assert.deepEqual(
      events.backlog().map((entry) => entry.pending),
      [1],
      "the next tick closes the batch",
    );
    events.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("held and rejected batches follow the router's ack semantics", async () => {
  const { events, advance } = setup([plugin("slack", [target({ coalesceSeconds: 0 })])]);
  const offered: string[] = [];
  let answer: "hold" | "rejected" = "hold";
  events.attach(async (batch) => {
    offered.push(batch.id);
    return answer === "hold" ? { kind: "hold", reason: "policy:busy" } : { kind: "rejected", reason: "policy:archived" };
  });
  events.publish("slack", "moneypenny", event("e1"));
  await settle();
  assert.equal(offered.length, 1);
  advance(10_000);
  await settle();
  assert.equal(offered.length, 1, "held for 30 s");
  answer = "rejected";
  advance(30_000);
  await settle();
  assert.equal(offered.length, 2);
  assert.deepEqual(events.backlog(), []);
  events.close();
});
