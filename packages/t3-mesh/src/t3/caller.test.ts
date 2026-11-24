import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import * as Schema from "effect/Schema";
import * as DateTime from "effect/DateTime";
import { OrchestrationV2ThreadShellJson, OrchestrationV2TurnItemJson, RunId, ThreadId, type OrchestrationV2TurnItem } from "@t3tools/contracts";
import { callerCandidateThreadIds, resolveCaller, type CallerLookup } from "./caller.ts";
import type { ShellEntry } from "./connection.ts";

// Real dynamic_tool items recorded from stock T3 .2676 (Claude first, Codex second), stored completed.
const recorded: ReadonlyArray<OrchestrationV2TurnItem> = Schema.decodeUnknownSync(
  Schema.Array(OrchestrationV2TurnItemJson),
)(JSON.parse(readFileSync(new URL("./fixtures/tool-items.json", import.meta.url), "utf8")));
const [claudeItem, codexItem] = recorded;
if (claudeItem === undefined || codexItem === undefined) throw new Error("fixtures missing");

const running = (item: OrchestrationV2TurnItem): OrchestrationV2TurnItem => ({ ...item, status: "running" });
const CLAUDE_CALL = "toolu_014rVCGDi3bP6CwUGg41MzRK";
const CODEX_CALL = "exec-b549e890-50b6-44ab-ae3b-f9dd9f803855";
const threadA = ThreadId.make("thread-a");
const threadB = ThreadId.make("thread-b");

const lookup = (threads: Record<string, ReadonlyArray<OrchestrationV2TurnItem>>): CallerLookup => ({
  candidateThreadIds: () => Object.keys(threads).map((id) => ThreadId.make(id)),
  projection: async (threadId) => ({ turnItems: threads[threadId] ?? [] }),
});
const noSleep = { sleep: async () => {}, timeoutMs: 0 };
const shell = Schema.decodeUnknownSync(OrchestrationV2ThreadShellJson)(
  JSON.parse(readFileSync(new URL("./fixtures/thread-shell.json", import.meta.url), "utf8")),
);
const staleEntry: ShellEntry = {
  location: "active",
  thread: { ...shell, id: threadB, status: "cancelled", updatedAt: DateTime.makeUnsafe(0) },
};

test("finds an older active run even when the latest shell run is cancelled and stale", async () => {
  const entry: ShellEntry = {
    ...staleEntry,
    thread: { ...staleEntry.thread, activeRunId: RunId.make("older-running-run") },
  };
  const result = await resolveCaller({
    candidateThreadIds: () => callerCandidateThreadIds([entry]),
    projection: async () => ({ turnItems: [running(codexItem)] }),
  }, CODEX_CALL, "mesh_join", noSleep);
  assert.deepEqual(result, { ok: true, threadId: threadB });
});

test("keeps waiting activity and recent idle threads in the fast candidates", () => {
  const now = 1_000_000;
  const waiting: ShellEntry = {
    ...staleEntry,
    thread: { ...staleEntry.thread, activityRunStatus: "waiting" },
  };
  const recent: ShellEntry = {
    ...staleEntry,
    thread: { ...staleEntry.thread, id: threadA, updatedAt: DateTime.makeUnsafe(now - 1_000) },
  };
  assert.deepEqual(callerCandidateThreadIds([waiting, recent], false, now), [threadB, threadA]);
});

test("fallback resolves Claude and Codex subscription tools from stale, settled shell entries", async () => {
  const entry: ShellEntry = {
    ...staleEntry,
    thread: { ...staleEntry.thread, settledAt: DateTime.makeUnsafe(0), settledOverride: "settled" },
  };
  for (const [item, callId, prefix] of [
    [claudeItem, CLAUDE_CALL, "mcp__t3-mesh__"],
    [codexItem, CODEX_CALL, "t3-mesh."],
  ] as const) {
    for (const tool of ["mesh_subscribe", "mesh_subscriptions", "mesh_unsubscribe"]) {
      const result = await resolveCaller({
        candidateThreadIds: () => callerCandidateThreadIds([entry]),
        fallbackThreadIds: () => callerCandidateThreadIds([entry], true),
        projection: async () => ({ turnItems: [{ ...running(item), toolName: `${prefix}${tool}` }] }),
      }, callId, tool, noSleep);
      assert.deepEqual(result, { ok: true, threadId: threadB, fallback: true });
    }
  }
});

test("neither candidate tier includes archived or deleted threads, even with an active run", () => {
  const live = { ...staleEntry.thread, activeRunId: RunId.make("run"), status: "running" as const };
  const excluded: ShellEntry[] = [
    { location: "archive", thread: live },
    { location: "active", thread: { ...live, archivedAt: DateTime.makeUnsafe(0) } },
    { location: "active", thread: { ...live, deletedAt: DateTime.makeUnsafe(0) } },
  ];
  assert.deepEqual(callerCandidateThreadIds(excluded), []);
  assert.deepEqual(callerCandidateThreadIds(excluded, true), []);
});

test("a fast match does not fetch fallback projections", async () => {
  const result = await resolveCaller({
    ...lookup({ [threadA]: [running(codexItem)] }),
    fallbackThreadIds: () => { throw new Error("unneeded fallback"); },
  }, CODEX_CALL, "mesh_join", noSleep);
  assert.deepEqual(result, { ok: true, threadId: threadA });
});

test("the fallback waits for the fast candidates' head start, then runs once", async (t) => {
  t.mock.timers.enable({ apis: ["Date"], now: 0 });
  const fetchedB: number[] = [];
  const result = await resolveCaller({
    candidateThreadIds: () => [threadA],
    fallbackThreadIds: () => [threadA, threadB],
    projection: async (id) => {
      if (id === threadB) fetchedB.push(Date.now());
      return { turnItems: id === threadB ? [running(codexItem)] : [] };
    },
  }, CODEX_CALL, "mesh_join", { timeoutMs: 10_000, sleep: async (ms) => { t.mock.timers.tick(ms); } });
  assert.deepEqual(result, { ok: true, threadId: threadB, fallback: true });
  assert.equal(fetchedB.length, 1);
  assert.ok((fetchedB[0] ?? 0) >= 1_500, `fallback started at ${fetchedB[0]} ms`);
});

test("an unresolvable call scans the fallback threads only once", async (t) => {
  t.mock.timers.enable({ apis: ["Date"], now: 0 });
  let fetchedB = 0;
  const result = await resolveCaller({
    candidateThreadIds: () => [threadA],
    fallbackThreadIds: () => [threadA, threadB],
    projection: async (id) => {
      if (id === threadB) fetchedB++;
      return { turnItems: [] };
    },
  }, CODEX_CALL, "mesh_join", { timeoutMs: 10_000, sleep: async (ms) => { t.mock.timers.tick(ms); } });
  assert.equal(result.ok ? "ok" : result.code, "caller_not_found");
  assert.equal(fetchedB, 1);
});

test("the fallback lists the most recently updated threads first", () => {
  const older: ShellEntry = { ...staleEntry, thread: { ...staleEntry.thread, id: threadA, updatedAt: DateTime.makeUnsafe(1_000) } };
  const newer: ShellEntry = { ...staleEntry, thread: { ...staleEntry.thread, id: threadB, updatedAt: DateTime.makeUnsafe(2_000) } };
  assert.deepEqual(callerCandidateThreadIds([older, newer], true, 10_000_000), [threadB, threadA]);
});

test("fallback scans every candidate with bounded concurrency and preserves ambiguity", async () => {
  const ids = Array.from({ length: 25 }, (_, index) => ThreadId.make(`fallback-${index}`));
  let inFlight = 0;
  let peak = 0;
  const calls: ThreadId[] = [];
  const result = await resolveCaller({
    candidateThreadIds: () => [],
    fallbackThreadIds: () => [...ids, ...ids],
    projection: async (id) => {
      calls.push(id);
      peak = Math.max(peak, ++inFlight);
      await new Promise<void>((resolve) => setImmediate(resolve));
      inFlight--;
      return { turnItems: id === ids[0] || id === ids.at(-1) ? [running(codexItem)] : [] };
    },
  }, CODEX_CALL, "mesh_join", noSleep);
  assert.equal(result.ok ? "ok" : result.code, "caller_ambiguous");
  assert.deepEqual(calls, ids);
  assert.ok(peak > 1 && peak <= 8, `concurrent projections: ${peak}`);
});

test("fallback projection failures are reported without discarding other candidates", async () => {
  const result = await resolveCaller({
    candidateThreadIds: () => [threadA],
    fallbackThreadIds: () => [threadB],
    projection: async (id) => {
      if (id === threadB) throw new Error("fallback projection failed");
      return { turnItems: [] };
    },
  }, CODEX_CALL, "mesh_join", noSleep);
  assert.equal(result.ok, false);
  if (result.ok) return;
  assert.equal(result.diagnostics.candidates, 2);
  assert.deepEqual(result.diagnostics.projectionErrors, ["thread-b: fallback projection failed"]);
});

test("resolves a Claude call by toolUseId", async () => {
  const result = await resolveCaller(
    lookup({ [threadA]: [running(codexItem)], [threadB]: [running(claudeItem)] }),
    CLAUDE_CALL,
    "mesh_join",
    noSleep,
  );
  assert.deepEqual(result, { ok: true, threadId: threadB });
});

test("resolves a Codex call by callId", async () => {
  const result = await resolveCaller(lookup({ [threadA]: [running(codexItem)] }), CODEX_CALL, "mesh_join", noSleep);
  assert.deepEqual(result, { ok: true, threadId: threadA });
});

test("ignores completed calls", async () => {
  const result = await resolveCaller(lookup({ [threadA]: [claudeItem] }), CLAUDE_CALL, "mesh_join", noSleep);
  assert.equal(result.ok, false);
});

test("ignores a matching ID on a different tool", async () => {
  const result = await resolveCaller(lookup({ [threadA]: [running(claudeItem)] }), CLAUDE_CALL, "mesh_send", noSleep);
  assert.equal(result.ok, false);
});

test("refuses an ID found in two threads", async () => {
  const result = await resolveCaller(
    lookup({ [threadA]: [running(claudeItem)], [threadB]: [running(claudeItem)] }),
    CLAUDE_CALL,
    "mesh_join",
    noSleep,
  );
  assert.equal(result.ok ? "ok" : result.code, "caller_ambiguous");
});

test("retries until the item appears", async () => {
  let calls = 0;
  const lazy: CallerLookup = {
    candidateThreadIds: () => [threadA],
    projection: async () => ({ turnItems: ++calls >= 3 ? [running(codexItem)] : [] }),
  };
  const result = await resolveCaller(lazy, CODEX_CALL, "mesh_join", { sleep: async () => {}, timeoutMs: 60_000 });
  assert.deepEqual(result, { ok: true, threadId: threadA });
  assert.equal(calls, 3);
});

test("reports what it saw when the caller cannot be resolved", async () => {
  const result = await resolveCaller(
    {
      candidateThreadIds: () => [threadA, threadB],
      projection: async (threadId) => {
        if (threadId === threadB) throw new Error("projection too large");
        return { turnItems: [claudeItem] };
      },
    },
    CLAUDE_CALL,
    "mesh_join",
    noSleep,
  );
  assert.equal(result.ok, false);
  if (result.ok) return;
  assert.equal(result.code, "caller_not_found");
  assert.deepEqual(result.diagnostics.seenAs, ["thread-a: mcp__t3-mesh__mesh_join completed"]);
  assert.deepEqual(result.diagnostics.projectionErrors, ["thread-b: projection too large"]);
});
