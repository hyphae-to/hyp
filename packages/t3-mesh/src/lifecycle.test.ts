import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import * as DateTime from "effect/DateTime";
import * as Schema from "effect/Schema";
import { OrchestrationV2ThreadShellJson, type OrchestrationV2ThreadShell } from "@t3tools/contracts";
import { buildStatus, statusProblem } from "./statusExport.ts";
import type { ShellEntry } from "./t3/connection.ts";
import { planTidy } from "./tidy.ts";

// Parked builders and the status export (docs/builder-subscriptions.md E3–E4), on a real
// thread shell recorded from stock T3, with a fake clock instead of waiting an hour.

const base = Schema.decodeUnknownSync(OrchestrationV2ThreadShellJson)(
  JSON.parse(readFileSync(new URL("./t3/fixtures/thread-shell.json", import.meta.url), "utf8")),
);
const NOW = Date.parse("2026-11-09T20:00:00Z");
const at = (minutesAgo: number) => DateTime.makeUnsafe(new Date(NOW - minutesAgo * 60_000));
const KEY = "assignment:bayfold/monorepo#4045";

const child = (id: string, overrides: Partial<OrchestrationV2ThreadShell> = {}): ShellEntry => ({
  location: "active",
  thread: {
    ...base,
    id,
    status: "completed",
    activeRunId: null,
    activityRunStatus: null,
    pendingRuntimeRequest: null,
    pendingBackgroundTasks: [],
    pinnedAt: null,
    settledAt: null,
    settledOverride: null,
    latestRunStopRequested: false,
    createdAt: at(300),
    latestRunStartedAt: at(70),
    latestRunCompletedAt: at(66),
    latestUserMessageAt: at(70),
    lineage: { ...base.lineage, parentThreadId: "lead", relationshipToParent: "subagent", rootThreadId: "lead" },
    ...overrides,
  } as OrchestrationV2ThreadShell,
});
const busy = (id: string) => child(id, { status: "running", activeRunId: `run:${id}` } as Partial<OrchestrationV2ThreadShell>);

test("tidy: a child parked on an assignment stays unsettled past 65 idle minutes; others settle as before", () => {
  const keys = new Map<string, string[]>([
    ["parked", [KEY]],
    ["settled-by-user", [KEY]],
    ["other-key", ["watch:something"]],
  ]);
  const plan = planTidy({
    entries: [
      child("parked"),
      child("idle"),
      child("other-key"),
      child("recent", { latestRunCompletedAt: at(10) }),
      child("settled-by-user", { settledOverride: "settled", settledAt: at(5) }),
      child("pinned-parked", { pinnedAt: at(400) }),
      busy("working"),
    ],
    now: NOW,
    minIdleMinutes: 60,
    keysOf: (id) => keys.get(id) ?? (id === "pinned-parked" ? [KEY] : []),
  });
  assert.deepEqual(plan.toSettle.map((e) => e.thread.id).sort(), ["idle", "other-key"]);
  assert.deepEqual(plan.toUnpin.map((e) => e.thread.id), ["pinned-parked"]);
  assert.deepEqual(Object.fromEntries(plan.holds), { "parked on an assignment": 2, recent: 1, working: 1 });
  // A user's settlement is neither undone nor counted as held.
  assert.ok(!plan.toSettle.some((e) => e.thread.id === "settled-by-user"));
});

test("tidy: role subscriptions hold idle children with their own reason; a user's settlement still wins", () => {
  const plan = planTidy({
    entries: [
      child("role"),
      child("both"),
      child("settled-role", { settledOverride: "settled", settledAt: at(5) }),
      child("idle"),
    ],
    now: NOW,
    minIdleMinutes: 60,
    keysOf: (id) => id === "idle" ? [] : id === "both" ? ["role:lead", KEY] : ["role:release"],
  });
  assert.deepEqual(plan.toSettle.map((entry) => entry.thread.id), ["idle"]);
  assert.deepEqual(Object.fromEntries(plan.holds), { "holds a role subscription": 1, "parked on an assignment": 1 });
});

test("status export: busy, parked and interrupted threads (standing ones too), nothing else; unknown while disconnected", () => {
  const keys = new Map<string, string[]>([
    ["parked", [KEY]],
    ["stopped", [KEY]],
    ["settled", [KEY]],
    ["idle-role", ["role:release"]],
    ["lead", ["role:lead"]],
  ]);
  const entries = [
    busy("w1"),
    child("parked"),
    child("stopped", { status: "interrupted", latestRunStopRequested: true }),
    child("idle"),
    child("idle-role"),
    child("settled", { settledOverride: "settled", settledAt: at(1) }),
    child("lead", { status: "interrupted", latestRunStopRequested: true }),
    child("stopping", { status: "running", activeRunId: "run:stopping", latestRunStopRequested: true } as Partial<OrchestrationV2ThreadShell>),
    child("old-settled", { status: "interrupted", latestRunStopRequested: true, settledOverride: "settled", settledAt: at(1) }),
  ];
  const status = buildStatus({ connector: "bogdan@solace", now: NOW, shells: entries, keysOf: (id) => keys.get(id) ?? [] });
  assert.deepEqual(status.counts, { busy: 2, parked: 1, interrupted: 3 });
  assert.deepEqual(
    status.threads.map((t) => [t.threadId, t.state, t.interruptRequested, t.assignments]),
    [
      ["w1", "busy", false, []],
      ["parked", "idle", false, [KEY]],
      ["stopped", "stopped", true, [KEY]],
      ["settled", "settled", false, [KEY]],
      ["lead", "stopped", true, []],
      ["stopping", "busy", true, []],
    ],
  );
  assert.equal(status.t3ObservedAt, status.generatedAt);
  const offline = buildStatus({ connector: "bogdan@solace", now: NOW, shells: null, keysOf: () => [] });
  assert.equal(offline.t3ObservedAt, null);
  assert.deepEqual(offline.threads, []);
});

test("a status reader treats unreadable, stale, future-dated or disconnected output as unknown", () => {
  const written = (now: number, connected = true) =>
    JSON.stringify(buildStatus({ connector: "c", now, shells: connected ? [] : null, keysOf: () => [] }));
  assert.equal(statusProblem(written(NOW), NOW + 5_000), null);
  assert.equal(statusProblem(written(NOW), NOW + 61_000), "status is stale");
  assert.equal(statusProblem(written(NOW + 5_000), NOW), "status is stale", "future-dated");
  assert.equal(statusProblem(written(NOW, false), NOW), "the connector was not connected to T3");
  assert.equal(statusProblem("{", NOW), "status is not readable JSON");
  assert.equal(statusProblem("[]", NOW), "status is not a status object");
});
