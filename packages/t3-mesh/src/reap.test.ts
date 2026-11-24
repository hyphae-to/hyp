import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import * as DateTime from "effect/DateTime";
import * as Schema from "effect/Schema";
import { OrchestrationV2ThreadShellJson, type OrchestrationV2ThreadShell } from "@t3tools/contracts";
import { planReap, worktreeInUse } from "./reap.ts";
import type { ShellEntry } from "./t3/connection.ts";

// Old builder subtrees on a real thread shell recorded from stock T3, with a fake clock.

const base = Schema.decodeUnknownSync(OrchestrationV2ThreadShellJson)(
  JSON.parse(readFileSync(new URL("./t3/fixtures/thread-shell.json", import.meta.url), "utf8")),
);
const NOW = Date.parse("2026-11-13T09:00:00Z");
const daysAgo = (days: number) => DateTime.makeUnsafe(new Date(NOW - days * 86_400_000));

/** A settled thread idle for `idle` days under `parent`. */
const thread = (id: string, title: string, parent: string | null, idle = 10, overrides: Partial<OrchestrationV2ThreadShell> = {}): ShellEntry => ({
  location: "active",
  thread: {
    ...base,
    id,
    title,
    status: "completed",
    activeRunId: null,
    activityRunStatus: null,
    pendingRuntimeRequest: null,
    pendingBackgroundTasks: [],
    pinnedAt: null,
    archivedAt: null,
    deletedAt: null,
    settledAt: daysAgo(idle),
    settledOverride: null,
    createdAt: daysAgo(idle + 1),
    updatedAt: daysAgo(idle),
    latestRunStartedAt: daysAgo(idle),
    latestRunCompletedAt: daysAgo(idle),
    latestUserMessageAt: daysAgo(idle),
    lastVisitedAt: null,
    lineage:
      parent === null
        ? { ...base.lineage, parentThreadId: null, relationshipToParent: null, rootThreadId: null }
        : { ...base.lineage, parentThreadId: parent, relationshipToParent: "subagent", rootThreadId: "lead" },
    ...overrides,
  } as OrchestrationV2ThreadShell,
});

const ids = (entries: readonly ShellEntry[]) => entries.map((e) => e.thread.id);
const ROOT = "/home/bogdan/.t3/worktrees";
const plan = (entries: ShellEntry[], keys: Record<string, string[]> = {}, maxThreads = 100) =>
  planReap({ entries, now: NOW, minIdleDays: 7, keysOf: (id) => keys[id] ?? [], maxThreads, worktreesRoot: ROOT });

test("reap: each child of a top-level thread goes with its whole subtree, children first; top-level threads stay", () => {
  const result = plan([
    thread("lead", "Bayfold Lead Gen1", null, 30),
    thread("b1", "builder-4482: lending docs train", "lead"),
    thread("r1", "Review PR #4500 r1 (builder-4482)", "b1"),
    thread("r1x", "helper under a review", "r1"),
    thread("b1b", "builder-4490: retry started by b1", "b1"),
    thread("research", "Map seal/backfill/check RPC usage", "lead"),
    thread("orphan", "child of an archived agent (not in the shell)", "archived-agent"),
  ]);
  assert.deepEqual(
    result.toDelete.map((s) => [s.parentTitle, ids(s.order)]),
    [
      ["Bayfold Lead Gen1", ["r1x", "r1", "b1b", "b1"]],
      ["Bayfold Lead Gen1", ["research"]],
      [null, ["orphan"]],
    ],
  );
  assert.deepEqual(Object.fromEntries(result.holds), {});
});

test("reap: one thread that must stay keeps its whole group", () => {
  const cases: Array<[string, Partial<OrchestrationV2ThreadShell>, Record<string, string[]>, string]> = [
    ["recently opened", { lastVisitedAt: daysAgo(1) }, {}, "recent"],
    ["recent message", { latestUserMessageAt: daysAgo(3) }, {}, "recent"],
    ["recent run", { latestRunCompletedAt: daysAgo(2) }, {}, "recent"],
    ["not settled", { settledAt: null }, {}, "not settled"],
    ["un-settled by the user", { settledOverride: "active" }, {}, "not settled"],
    ["pinned", { pinnedAt: daysAgo(20) }, {}, "pinned"],
    ["running", { status: "running", activeRunId: "run:x" } as Partial<OrchestrationV2ThreadShell>, {}, "working"],
    ["parked", {}, { child: ["assignment:bayfold/monorepo#4045"] }, "parked on an assignment"],
    ["other subscription", {}, { child: ["watch:ci"] }, "subscribed"],
  ];
  for (const [name, overrides, keys, reason] of cases) {
    const result = plan([thread("b", "builder-1: x", "lead"), thread("child", "Review", "b", 10, overrides)], keys);
    assert.deepEqual(result.toDelete, [], name);
    assert.deepEqual(Object.fromEntries(result.holds), { [reason]: 1 }, name);
  }
});

test("reap: archived counts as settled; any title makes a group; a forked thread's own lineage is not a subagent", () => {
  const result = plan([
    thread("archived", "builder-2: y", "lead", 10, { archivedAt: daysAgo(9), settledAt: null }),
    thread("review", "Review #2350 round 1 (builder-2334)", "lead"),
    thread("fork", "a fork", "lead", 10, {
      lineage: { ...base.lineage, parentThreadId: "lead", relationshipToParent: "fork", rootThreadId: "lead" },
    } as Partial<OrchestrationV2ThreadShell>),
  ]);
  assert.deepEqual(result.toDelete.map((s) => s.root.thread.id), ["archived", "review"]);
});

test("reap: oldest first within --max-threads; an oversized subtree still goes alone", () => {
  const entries = [
    thread("new", "builder-3: new", "lead", 8),
    thread("old", "builder-4: old", "lead", 30),
    thread("old-r", "Review", "old", 30),
    thread("mid", "builder-5: mid", "lead", 15),
  ];
  const capped = plan(entries, {}, 3);
  assert.deepEqual(capped.toDelete.map((s) => s.root.thread.id), ["old", "mid"]);
  assert.equal(capped.deferred, 1);
  const tiny = plan(entries, {}, 1);
  assert.deepEqual(tiny.toDelete.map((s) => s.root.thread.id), ["old"]);
  assert.equal(tiny.deferred, 2);
});

test("reap: a lineage cycle is kept; a deep chain is deleted deepest first", () => {
  assert.deepEqual(plan([thread("a", "builder-6: a", "b"), thread("b", "Review", "a")]).toDelete, []);
  const chain = plan([thread("c", "builder-7: c", "lead"), thread("d", "Review", "c"), thread("e", "helper", "d")]);
  assert.deepEqual(chain.toDelete.map((s) => ids(s.order)), [["e", "d", "c"]]);
});

test("reap: frees only managed worktrees that no remaining thread uses, with every user listed", () => {
  const wt = (name: string) => ({ worktreePath: `${ROOT}/monorepo/${name}` });
  const result = plan(
    [
      thread("b", "builder-8: b", "lead", 10, wt("b")),
      thread("r", "Review", "b", 10, wt("b")),
      thread("r2", "Review 2", "b", 10, wt("r2")),
      thread("shared", "Review 3", "b", 10, wt("shared")),
      thread("nested", "Review 4", "b", 10, wt("parent")),
      thread("outside", "Review 5", "b", 10, { worktreePath: "/home/workspace/projects/tern-capital-wt/x" }),
      thread("root", "Review 6", "b", 10, { worktreePath: ROOT }),
      thread("other", "builder-9: kept", "lead", 1, wt("shared")),
      thread("inside", "Kept helper", "other", 1, { worktreePath: `${ROOT}/monorepo/parent/sub` }),
    ],
    {},
  );
  assert.deepEqual(result.toDelete.map((s) => s.root.thread.id), ["b"]);
  assert.deepEqual(
    result.worktrees.map((w) => [w.path, w.threadIds]),
    [
      [`${ROOT}/monorepo/b`, ["b", "r"]],
      [`${ROOT}/monorepo/r2`, ["r2"]],
    ],
  );
});

test("reap: a worktree two deleted subtrees share names both, so one failed deletion keeps it", () => {
  const worktreePath = `${ROOT}/monorepo/common`;
  const result = plan([thread("x", "builder-10: x", "lead", 20, { worktreePath }), thread("y", "builder-11: y", "lead", 9, { worktreePath })]);
  assert.deepEqual(result.worktrees, [{ path: worktreePath, threadIds: ["x", "y"] }]);
});

test("reap: a recent updatedAt alone is not activity (T3 bumps it on idle threads in bulk)", () => {
  const result = plan([thread("b", "builder-12: b", "lead", 20, { updatedAt: daysAgo(0) }), thread("r", "Review", "b", 20, { updatedAt: daysAgo(0) })]);
  assert.deepEqual(result.toDelete.map((s) => ids(s.order)), [["r", "b"]]);
});

test("reap: a worktree an archived thread still uses (not in the shell) is never freed", () => {
  const worktreePath = `${ROOT}/monorepo/agent-heron`;
  const result = planReap({
    entries: [thread("b", "builder-13: b", "lead", 20, { worktreePath })],
    now: NOW,
    minIdleDays: 7,
    keysOf: () => [],
    maxThreads: 100,
    worktreesRoot: ROOT,
    worktreesInUse: [worktreePath],
  });
  assert.deepEqual(result.toDelete.map((s) => s.root.thread.id), ["b"]);
  assert.deepEqual(result.worktrees, []);
});

test("reap: a worktree is in use when a live thread works in it, inside it, or in a folder containing it", () => {
  const wt = `${ROOT}/monorepo/t3-1`;
  assert.equal(worktreeInUse(wt, [`${ROOT}/monorepo/t3-2`]), false);
  assert.equal(worktreeInUse(wt, [`${wt}/`]), true, "same path, written differently");
  assert.equal(worktreeInUse(wt, [`${wt}/libs`]), true, "a thread inside it");
  assert.equal(worktreeInUse(wt, [`${ROOT}/monorepo`]), true, "a thread in a folder containing it");
});
