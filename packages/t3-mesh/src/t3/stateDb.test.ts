import { test } from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { T3StateDb, type QueuedRun } from "./stateDb.ts";

const THREAD = "bb2681a8";
const run = (n: number) => `run:thread:${THREAD}:ordinal:${n}`;

/** The columns of T3's tables (statev2.sqlite, migration 76) that the queries read. */
function fixture(): { db: DatabaseSync; state: T3StateDb } {
  const db = new DatabaseSync(":memory:");
  db.exec(`
    CREATE TABLE orchestration_v2_projection_runs (
      run_id TEXT PRIMARY KEY, thread_id TEXT NOT NULL, status TEXT NOT NULL, requested_at TEXT NOT NULL,
      payload_json TEXT NOT NULL);
    CREATE TABLE orchestration_v2_projection_turn_items (
      turn_item_id TEXT PRIMARY KEY, thread_id TEXT NOT NULL, run_id TEXT, updated_at TEXT NOT NULL);
    CREATE TABLE orchestration_v2_projection_messages (message_id TEXT PRIMARY KEY, payload_json TEXT NOT NULL);
    CREATE TABLE orchestration_events (
      sequence INTEGER PRIMARY KEY AUTOINCREMENT, aggregate_kind TEXT NOT NULL, stream_id TEXT NOT NULL,
      event_type TEXT NOT NULL, occurred_at TEXT NOT NULL, command_id TEXT, payload_json TEXT NOT NULL,
      application_event_version INTEGER NOT NULL DEFAULT 1);
    CREATE TABLE orchestration_command_receipts (
      command_id TEXT PRIMARY KEY, aggregate_kind TEXT NOT NULL, aggregate_id TEXT NOT NULL,
      accepted_at TEXT NOT NULL, command_type TEXT NOT NULL);
  `);
  return { db, state: new T3StateDb(db) };
}

function addRun(db: DatabaseSync, n: number, status: string, at: string, extra: Record<string, unknown> = {}): void {
  db.prepare("INSERT INTO orchestration_v2_projection_runs VALUES (?, ?, ?, ?, ?)").run(
    run(n),
    THREAD,
    status,
    at,
    JSON.stringify({ id: run(n), userMessageId: `message-${n}`, ...extra }),
  );
}

/** A `run.created`/`run.updated` event, plus its command receipt when typed. */
function event(
  db: DatabaseSync,
  type: "run.created" | "run.updated",
  n: number,
  at: string,
  payload: Record<string, unknown>,
  command: { id: string; type?: string } | null,
): void {
  db.prepare(
    "INSERT INTO orchestration_events (aggregate_kind, stream_id, event_type, occurred_at, command_id, payload_json, application_event_version) VALUES ('thread', ?, ?, ?, ?, ?, 2)",
  ).run(THREAD, type, at, command?.id ?? null, JSON.stringify({ id: run(n), ...payload }));
  if (command?.type !== undefined) receipt(db, command.id, command.type, at);
}

function receipt(db: DatabaseSync, id: string, type: string, at: string): void {
  db.prepare("INSERT OR IGNORE INTO orchestration_command_receipts VALUES (?, 'thread', ?, ?, ?)").run(id, THREAD, at, type);
}

const RECONCILE = { id: `command:runtime-reconcile:startup:${THREAD}:2026-11-02T03:50:38Z`, type: "provider-runtime.reconcile" };

function held(state: T3StateDb): QueuedRun {
  const oldest = state.queuedRunsByThread().get(THREAD)?.find((candidate) => candidate.held);
  assert.ok(oldest !== undefined);
  return oldest;
}

test("lists queued runs by thread, oldest first, with their hold", () => {
  const { db, state } = fixture();
  addRun(db, 3, "queued", "2026-11-02T03:00:00Z", { queueHeld: true });
  addRun(db, 2, "queued", "2026-11-02T02:00:00Z");
  addRun(db, 1, "completed", "2026-11-02T01:00:00Z", { startedAt: "2026-11-02T01:00:01Z" });
  assert.deepEqual(state.queuedRunsByThread().get(THREAD), [
    { runId: run(2), requestedAt: "2026-11-02T02:00:00Z", held: false, messageId: "message-2" },
    { runId: run(3), requestedAt: "2026-11-02T03:00:00Z", held: true, messageId: "message-3" },
  ]);
});

test("finds the active run and the run that last started", () => {
  const { db, state } = fixture();
  addRun(db, 1, "completed", "2026-11-02T01:00:00Z", { startedAt: "2026-11-02T01:00:01Z" });
  addRun(db, 2, "running", "2026-11-02T02:00:00Z", { startedAt: "2026-11-02T02:00:01Z" });
  addRun(db, 3, "queued", "2026-11-02T03:00:00Z");
  addRun(db, 4, "cancelled", "2026-11-02T03:30:00Z");
  db.prepare("INSERT INTO orchestration_v2_projection_turn_items VALUES ('i1', ?, ?, '2026-11-02T02:05:00Z')").run(THREAD, run(2));
  assert.deepEqual(state.activeRun(THREAD), {
    runId: run(2),
    status: "running",
    startedAt: "2026-11-02T02:00:01Z",
    lastItemAt: "2026-11-02T02:05:00Z",
  });
  assert.equal(state.lastStartedRunId(THREAD), run(2));
  assert.equal(state.activeRun("other"), null);
  assert.equal(state.lastStartedRunId("other"), null);
});

test("a restart's hold, held directly", () => {
  const { db, state } = fixture();
  addRun(db, 5, "queued", "2026-11-02T03:40:00Z", { queueHeld: true });
  event(db, "run.created", 5, "2026-11-02T03:40:00Z", { status: "queued" }, { id: "send-5", type: "message.dispatch" });
  event(db, "run.updated", 5, "2026-11-02T03:50:38Z", { status: "queued", queueHeld: true }, RECONCILE);
  assert.deepEqual(state.holdCause(THREAD, held(state)), {
    kind: "restart",
    at: "2026-11-02T03:50:38Z",
    commandId: RECONCILE.id,
  });
});

test("a restart's hold, inherited by runs queued after it", () => {
  const { db, state } = fixture();
  // The reconcile held run 5, which was later cancelled; run 6 was created held.
  event(db, "run.updated", 5, "2026-11-02T03:50:38Z", { status: "queued", queueHeld: true }, RECONCILE);
  event(db, "run.updated", 5, "2026-11-02T04:00:00Z", { status: "cancelled", queueHeld: true }, { id: "cancel-5", type: "queued-run.cancel" });
  addRun(db, 6, "queued", "2026-11-02T04:10:00Z", { queueHeld: true });
  event(db, "run.created", 6, "2026-11-02T04:10:00Z", { status: "queued", queueHeld: true }, { id: "pr-watch", type: "thread.pull-request-watch.sync" });
  assert.equal(state.holdCause(THREAD, held(state)).kind, "restart");
});

test("a Stop after a restart's hold makes it deliberate; the watchdog's own interrupt does not", () => {
  const { db, state } = fixture();
  addRun(db, 5, "queued", "2026-11-02T03:40:00Z", { queueHeld: true });
  event(db, "run.updated", 5, "2026-11-02T03:50:38Z", { status: "queued", queueHeld: true }, RECONCILE);
  receipt(db, "queue-watchdog:run.interrupt:x", "run.interrupt", "2026-11-02T04:00:00Z");
  assert.equal(state.holdCause(THREAD, held(state)).kind, "restart");
  receipt(db, "2ebf7348", "run.interrupt", "2026-11-02T04:46:44Z");
  assert.deepEqual(state.holdCause(THREAD, held(state)), { kind: "stop", at: "2026-11-02T04:46:44Z", commandId: "2ebf7348" });
});

test("a Stop's own hold", () => {
  const { db, state } = fixture();
  addRun(db, 3, "queued", "2026-10-18T20:38:02Z", { queueHeld: true });
  event(db, "run.updated", 3, "2026-10-18T20:38:05Z", { status: "queued", queueHeld: true }, { id: "5d4a570c", type: "run.interrupt" });
  assert.equal(state.holdCause(THREAD, held(state)).kind, "stop");
});

test("a server hold with no command, and no hold event at all", () => {
  const { db, state } = fixture();
  addRun(db, 7, "queued", "2026-11-02T05:00:00Z", { queueHeld: true });
  assert.deepEqual(state.holdCause(THREAD, held(state)), { kind: "unknown" });
  event(db, "run.updated", 7, "2026-11-02T05:01:00Z", { status: "queued", queueHeld: true }, null);
  assert.deepEqual(state.holdCause(THREAD, held(state)), {
    kind: "other",
    at: "2026-11-02T05:01:00Z",
    commandId: null,
    commandType: null,
  });
});

test("finds the queued runs a command cancelled, and message text", () => {
  const { db, state } = fixture();
  event(db, "run.updated", 13468, "2026-11-02T04:47:00Z", { status: "cancelled" }, { id: "queue-watchdog:i", type: "run.interrupt" });
  event(db, "run.updated", 13458, "2026-11-02T04:47:00Z", { status: "running" }, { id: "queue-watchdog:i" });
  assert.deepEqual(state.runsCancelledBy("queue-watchdog:i"), [run(13468)]);
  db.prepare("INSERT INTO orchestration_v2_projection_messages VALUES ('m', ?)").run(JSON.stringify({ text: "hello" }));
  assert.equal(state.messageText("m"), "hello");
  assert.equal(state.messageText("missing"), null);
});
