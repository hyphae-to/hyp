import { test } from "node:test";
import assert from "node:assert/strict";
import {
  decide,
  restartPermission,
  shortRunId,
  type Observation,
  type RestartPermission,
  type ThreadRecord,
} from "./watchdog.ts";
import type { ActiveRun } from "./t3/stateDb.ts";

const now = new Date("2026-11-02T12:00:00.000Z");
const hourAgo = "2026-11-02T11:00:00.000Z";
const allowed: RestartPermission = { kind: "allowed" };
const run = (n: number) => `run:thread:bb2681a8:ordinal:${n}`;

const leadRun: ActiveRun = { runId: run(13458), status: "running", startedAt: "2026-11-02T10:29:00.000Z", lastItemAt: null };
const stuckLead: Observation = {
  threadId: "bb2681a8",
  title: "Bayfold Lead",
  oldestQueuedRunId: run(13465),
  oldestQueuedAt: "2026-11-02T10:30:00.000Z",
  queued: 3,
  held: 0,
  activeRun: leadRun,
  lastStartedRunId: run(13458),
  holdCause: null,
};
const seen = (stage: ThreadRecord["stage"], overrides: Partial<ThreadRecord> = {}): ThreadRecord => ({
  oldestQueuedRunId: stuckLead.oldestQueuedRunId,
  lastStartedRunId: stuckLead.lastStartedRunId,
  since: hourAgo,
  stage,
  ...overrides,
});
const kinds = (steps: readonly { readonly kind: string }[]) => steps.map((step) => step.kind);

test("a new queue is only watched", () => {
  const decision = decide(stuckLead, undefined, now, allowed);
  assert.deepEqual(decision.steps, []);
  assert.equal(decision.record.stage, "watching");
  assert.equal(decision.record.since, now.toISOString());
});

test("a queue that has not moved for a pass gets its active run interrupted, then a message", () => {
  const decision = decide(stuckLead, seen("watching"), now, allowed);
  assert.deepEqual(kinds(decision.steps), ["interrupt", "message"]);
  assert.deepEqual(decision.steps[0], { kind: "interrupt", runId: run(13458) });
  assert.equal(decision.record.stage, "acted");
  assert.equal(decision.record.since, hourAgo);
  const message = decision.steps[1];
  assert.ok(message?.kind === "message" && message.text.startsWith("watchdog: resuming queue"));
});

test("the interrupt resumes a restart's hold but not a Stop's", () => {
  const restartHeld = { ...stuckLead, held: 3, holdCause: { kind: "restart", at: hourAgo, commandId: "c" } } as const;
  assert.deepEqual(kinds(decide(restartHeld, seen("watching"), now, allowed).steps), ["interrupt", "resume", "message"]);
  const stopHeld = { ...stuckLead, held: 3, holdCause: { kind: "stop", at: hourAgo, commandId: "c" } } as const;
  assert.deepEqual(kinds(decide(stopHeld, seen("watching"), now, allowed).steps), ["interrupt", "message"]);
});

test("a new oldest run or a newly started run means the queue moved", () => {
  const newOldest = decide({ ...stuckLead, oldestQueuedRunId: run(13466) }, seen("acted"), now, allowed);
  assert.deepEqual(newOldest.steps, []);
  assert.equal(newOldest.record.stage, "watching");
  const started = decide({ ...stuckLead, lastStartedRunId: run(13470) }, seen("acted"), now, allowed);
  assert.deepEqual(started.steps, []);
  assert.equal(started.record.stage, "watching");
  assert.equal(started.record.since, now.toISOString());
});

const twoHoursAgo = "2026-11-02T10:00:00.000Z";

test("still stuck after the interrupt restarts T3, once", () => {
  const decision = decide(stuckLead, seen("acted", { since: twoHoursAgo }), now, allowed);
  assert.deepEqual(kinds(decision.steps), ["restart"]);
  assert.equal(decision.record.stage, "restarted");
  const after = decide(stuckLead, decision.record, now, allowed);
  assert.deepEqual(after.steps, []);
  assert.equal(after.record.stage, "left");
  assert.ok(after.alert !== null);
  assert.deepEqual(decide(stuckLead, after.record, now, allowed).steps, []);
});

test("a refused restart alerts and leaves the queue", () => {
  const refused: RestartPermission = { kind: "refused", reason: "macOS: alert only" };
  const decision = decide(stuckLead, seen("acted", { since: twoHoursAgo }), now, refused);
  assert.deepEqual(decision.steps, []);
  assert.equal(decision.record.stage, "left");
  assert.match(decision.alert ?? "", /macOS: alert only/);
});

test("a held queue with no active run is resumed only after a restart", () => {
  const idle = { ...stuckLead, activeRun: null, held: 3 };
  const restart = decide({ ...idle, holdCause: { kind: "restart", at: hourAgo, commandId: "c" } }, seen("watching"), now, allowed);
  assert.deepEqual(kinds(restart.steps), ["resume"]);
  const stop = decide({ ...idle, holdCause: { kind: "stop", at: hourAgo, commandId: "c" } }, seen("watching"), now, allowed);
  assert.deepEqual(stop.steps, []);
  assert.equal(stop.record.stage, "left");
  assert.equal(stop.alert, null);
  const other = decide({ ...idle, holdCause: { kind: "unknown" } }, seen("watching"), now, allowed);
  assert.deepEqual(other.steps, []);
});

test("a queue with nothing active and nothing held is kicked with a resume, then left with an alert", () => {
  const stranded = { ...stuckLead, activeRun: null };
  const first = decide(stranded, seen("watching"), now, allowed);
  assert.deepEqual(kinds(first.steps), ["resume"]);
  const second = decide(stranded, first.record, new Date("2026-11-02T13:00:00.000Z"), allowed);
  assert.deepEqual(second.steps, []);
  assert.equal(second.record.stage, "left");
  assert.ok(second.alert !== null);
});

test("a queue whose oldest message is over 24h old when first seen is left alone, with one alert", () => {
  const old = { ...stuckLead, oldestQueuedAt: "2026-10-18T20:38:02.441Z", activeRun: null, held: 1 };
  const first = decide(old, undefined, now, allowed);
  assert.equal(first.record.stage, "ignored");
  assert.ok(first.alert !== null);
  const again = decide(old, first.record, now, allowed);
  assert.equal(again.record.stage, "ignored");
  assert.equal(again.alert, null);
  assert.deepEqual(again.steps, []);
  // Other runs moving behind it do not make it new.
  const moving = decide({ ...old, lastStartedRunId: run(99) }, again.record, now, allowed);
  assert.equal(moving.record.stage, "ignored");
});

test("an old queue seen growing from a young one is still acted on", () => {
  const decision = decide(
    { ...stuckLead, oldestQueuedAt: "2026-11-01T06:00:00.000Z" },
    seen("watching", { since: "2026-11-01T11:00:00.000Z" }),
    now,
    allowed,
  );
  assert.deepEqual(kinds(decision.steps), ["interrupt", "message"]);
});

test("passes run close together do not escalate", () => {
  const recent = seen("watching", { since: "2026-11-02T11:58:00.000Z" });
  const early = decide(stuckLead, recent, now, allowed);
  assert.deepEqual(early.steps, []);
  assert.equal(early.record.stage, "watching");
  assert.equal(early.record.since, recent.since);
  // An hour after the first sighting the interrupt is due, but a restart needs the queue still for longer.
  const acted = decide(stuckLead, seen("acted", { since: hourAgo }), now, allowed);
  assert.deepEqual(acted.steps, []);
  assert.equal(acted.record.stage, "acted");
  assert.deepEqual(
    kinds(decide(stuckLead, seen("acted", { since: "2026-11-02T10:00:00.000Z" }), now, allowed).steps),
    ["restart"],
  );
});

test("a run that is still changing is not interrupted or restarted, however long the queue waits", () => {
  const busy = { ...stuckLead, activeRun: { ...leadRun, lastItemAt: "2026-11-02T11:50:00.000Z" } };
  for (const stage of ["watching", "acted"] as const) {
    const decision = decide(busy, seen(stage, { since: "2026-11-02T08:00:00.000Z" }), now, allowed);
    assert.deepEqual(decision.steps, []);
    assert.equal(decision.record.stage, stage);
  }
  // Silent for over an hour: acted on. With the guard off, only the queue counts.
  const silent = { ...stuckLead, activeRun: { ...leadRun, lastItemAt: "2026-11-02T10:45:00.000Z" } };
  assert.deepEqual(kinds(decide(silent, seen("watching"), now, allowed).steps), ["interrupt", "message"]);
  assert.deepEqual(kinds(decide(busy, seen("watching"), now, allowed, 0).steps), ["interrupt", "message"]);
});

test("restarts are refused on macOS, without the unit, and within 6h of the last one", () => {
  const linux = { darwin: false, unitPresent: true, unit: "t3code.service" };
  assert.deepEqual(restartPermission(null, now, linux), { kind: "allowed" });
  assert.equal(restartPermission(null, now, { ...linux, darwin: true }).kind, "refused");
  assert.equal(restartPermission(null, now, { ...linux, unitPresent: false }).kind, "refused");
  assert.equal(restartPermission("2026-11-02T07:00:00.000Z", now, linux).kind, "refused");
  assert.deepEqual(restartPermission("2026-11-02T05:59:00.000Z", now, linux), { kind: "allowed" });
});

test("short run IDs keep the ordinal suffix", () => {
  assert.equal(shortRunId("run:thread:thread%3Adelegated-task%3Ax:ordinal:121"), "ordinal:121");
});
