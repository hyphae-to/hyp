// Read-only queries on a T3 instance's own database (`<T3 home>/userdata/statev2.sqlite`) for what the
// shell subscription does not carry: queued runs, and why a queue is held. Opened read-only, never
// written: writes go through the running server. A T3 update that changes these tables makes the
// queries fail, which stops the queue watchdog before it acts.
import { DatabaseSync } from "node:sqlite";
import * as Schema from "effect/Schema";

/** Command IDs the queue watchdog dispatches start with this. */
export const WATCHDOG_COMMAND_PREFIX = "queue-watchdog:";

/** Run statuses that own the thread's provider turn, so a queued run waits behind them (T3's `isActiveRun`). */
const ACTIVE_RUN_STATUSES = ["preparing", "starting", "running", "waiting"] as const;
const ACTIVE_STATUS_LIST = ACTIVE_RUN_STATUSES.map((status) => `'${status}'`).join(", ");

/** How far before a held run to look for the command that held its queue. */
const HOLD_LOOKBACK_MS = 7 * 24 * 3_600_000;

export interface QueuedRun {
  readonly runId: string;
  readonly requestedAt: string;
  readonly held: boolean;
  readonly messageId: string;
}

export interface ActiveRun {
  readonly runId: string;
  readonly status: string;
  readonly startedAt: string | null;
  /** The last time one of the run's turn items changed. */
  readonly lastItemAt: string | null;
}

/** What held a thread's queue, from the command behind the `run.updated` event that held it. */
export type HoldCause =
  /** T3's startup or shutdown reconcile caught a turn in flight (a server restart). */
  | { readonly kind: "restart"; readonly at: string; readonly commandId: string }
  /** A Stop or interrupt from a user or agent, at or after the hold. */
  | { readonly kind: "stop"; readonly at: string; readonly commandId: string }
  /** Anything else, e.g. a provider failure or a missing worktree. */
  | { readonly kind: "other"; readonly at: string; readonly commandId: string | null; readonly commandType: string | null }
  /** No holding event within the lookback. */
  | { readonly kind: "unknown" };

const QueuedRunRow = Schema.Struct({
  run_id: Schema.String,
  thread_id: Schema.String,
  requested_at: Schema.String,
  held: Schema.NullOr(Schema.Number),
  message_id: Schema.String,
});
const ActiveRunRow = Schema.Struct({
  run_id: Schema.String,
  status: Schema.String,
  started_at: Schema.NullOr(Schema.String),
  last_item_at: Schema.NullOr(Schema.String),
});
const RunIdRow = Schema.Struct({ run_id: Schema.NullOr(Schema.String) });
const SequenceRow = Schema.Struct({ seq: Schema.NullOr(Schema.Number) });
const HoldRow = Schema.Struct({
  occurred_at: Schema.String,
  command_id: Schema.NullOr(Schema.String),
  command_type: Schema.NullOr(Schema.String),
});
const StopRow = Schema.Struct({ command_id: Schema.String, accepted_at: Schema.String });
const TextRow = Schema.Struct({ text: Schema.NullOr(Schema.String) });
const decodeQueuedRuns = Schema.decodeUnknownSync(Schema.Array(QueuedRunRow));
const decodeActiveRuns = Schema.decodeUnknownSync(Schema.Array(ActiveRunRow));
const decodeRunId = Schema.decodeUnknownSync(RunIdRow);
const decodeSequence = Schema.decodeUnknownSync(SequenceRow);
const decodeHold = Schema.decodeUnknownSync(Schema.UndefinedOr(HoldRow));
const decodeStop = Schema.decodeUnknownSync(Schema.UndefinedOr(StopRow));
const decodeRunIds = Schema.decodeUnknownSync(Schema.Array(Schema.Struct({ run_id: Schema.String })));
const decodeText = Schema.decodeUnknownSync(Schema.UndefinedOr(TextRow));

/** T3's v2 thread events (not `orchestration_v2_events`, which stays empty); a partial index on (stream_id, sequence) covers these. */
const THREAD_EVENTS = "application_event_version = 2 AND aggregate_kind = 'thread'";

export class T3StateDb {
  readonly #db: DatabaseSync;

  constructor(db: DatabaseSync) {
    this.#db = db;
  }

  static openReadOnly(path: string): T3StateDb {
    return new T3StateDb(new DatabaseSync(path, { readOnly: true }));
  }

  close(): void {
    this.#db.close();
  }

  /** Every queued run on the instance, by thread, oldest first. */
  queuedRunsByThread(): Map<string, QueuedRun[]> {
    const rows = decodeQueuedRuns(
      this.#db
        .prepare(
          `SELECT run_id, thread_id, requested_at, json_extract(payload_json, '$.queueHeld') AS held,
             json_extract(payload_json, '$.userMessageId') AS message_id
           FROM orchestration_v2_projection_runs WHERE status = 'queued'
           ORDER BY thread_id, requested_at, run_id`,
        )
        .all(),
    );
    const byThread = new Map<string, QueuedRun[]>();
    for (const row of rows) {
      const runs = byThread.get(row.thread_id) ?? [];
      runs.push({ runId: row.run_id, requestedAt: row.requested_at, held: row.held === 1, messageId: row.message_id });
      byThread.set(row.thread_id, runs);
    }
    return byThread;
  }

  /** The run that owns the thread's provider turn, if any. */
  activeRun(threadId: string): ActiveRun | null {
    const rows = decodeActiveRuns(
      this.#db
        .prepare(
          `SELECT r.run_id, r.status, json_extract(r.payload_json, '$.startedAt') AS started_at,
             (SELECT max(i.updated_at) FROM orchestration_v2_projection_turn_items i
               WHERE i.thread_id = r.thread_id AND i.run_id = r.run_id) AS last_item_at
           FROM orchestration_v2_projection_runs r
           WHERE r.thread_id = ? AND r.status IN (${ACTIVE_STATUS_LIST})
           ORDER BY r.requested_at DESC`,
        )
        .all(threadId),
    );
    const row = rows[0];
    return row === undefined
      ? null
      : { runId: row.run_id, status: row.status, startedAt: row.started_at, lastItemAt: row.last_item_at };
  }

  /** The run that most recently left the thread's queue and started. */
  lastStartedRunId(threadId: string): string | null {
    return decodeRunId(
      this.#db
        .prepare(
          `SELECT run_id FROM orchestration_v2_projection_runs
           WHERE thread_id = ? AND status <> 'queued' AND json_extract(payload_json, '$.startedAt') IS NOT NULL
           ORDER BY json_extract(payload_json, '$.startedAt') DESC LIMIT 1`,
        )
        .get(threadId) ?? { run_id: null },
    ).run_id;
  }

  /**
   * Why `heldRun` is held. A run created while the queue was held inherits the hold, so the cause is
   * the latest `run.updated` that held a queued run at or before `heldRun` became held. A Stop or
   * interrupt after that (other than the watchdog's own) makes it a deliberate hold.
   */
  holdCause(threadId: string, heldRun: QueuedRun): HoldCause {
    const becameHeld = decodeSequence(
      this.#db
        .prepare(
          `SELECT max(sequence) AS seq FROM orchestration_events
           WHERE ${THREAD_EVENTS} AND stream_id = ? AND event_type IN ('run.created', 'run.updated')
             AND occurred_at >= ? AND json_extract(payload_json, '$.id') = ?
             AND json_extract(payload_json, '$.queueHeld') = 1`,
        )
        .get(threadId, heldRun.requestedAt, heldRun.runId),
    ).seq;
    if (becameHeld === null) return { kind: "unknown" };
    const lookback = new Date(Date.parse(heldRun.requestedAt) - HOLD_LOOKBACK_MS).toISOString();
    const hold = decodeHold(
      this.#db
        .prepare(
          `SELECT e.occurred_at, e.command_id, r.command_type FROM orchestration_events e
           LEFT JOIN orchestration_command_receipts r ON r.command_id = e.command_id
           WHERE e.application_event_version = 2 AND e.aggregate_kind = 'thread' AND e.stream_id = ?
             AND e.event_type = 'run.updated' AND e.sequence <= ? AND e.occurred_at >= ?
             AND json_extract(e.payload_json, '$.status') = 'queued'
             AND json_extract(e.payload_json, '$.queueHeld') = 1
           ORDER BY e.sequence DESC LIMIT 1`,
        )
        .get(threadId, becameHeld, lookback),
    );
    if (hold === undefined) return { kind: "unknown" };
    const laterStop = decodeStop(
      this.#db
        .prepare(
          `SELECT command_id, accepted_at FROM orchestration_command_receipts
           WHERE aggregate_kind = 'thread' AND aggregate_id = ? AND command_type IN ('run.interrupt', 'thread.stop')
             AND accepted_at >= ? AND command_id NOT LIKE '${WATCHDOG_COMMAND_PREFIX}%'
           ORDER BY accepted_at DESC LIMIT 1`,
        )
        .get(threadId, hold.occurred_at),
    );
    if (laterStop !== undefined) return { kind: "stop", at: laterStop.accepted_at, commandId: laterStop.command_id };
    const commandId = hold.command_id;
    if (
      hold.command_type === "provider-runtime.reconcile" ||
      (hold.command_type === null && commandId?.startsWith("command:runtime-reconcile:") === true)
    ) {
      return { kind: "restart", at: hold.occurred_at, commandId: commandId ?? "" };
    }
    if (hold.command_type === "run.interrupt" || hold.command_type === "thread.stop") {
      return { kind: "stop", at: hold.occurred_at, commandId: commandId ?? "" };
    }
    return { kind: "other", at: hold.occurred_at, commandId, commandType: hold.command_type };
  }

  /** Queued runs that `commandId` cancelled. */
  runsCancelledBy(commandId: string): string[] {
    return decodeRunIds(
      this.#db
        .prepare(
          `SELECT DISTINCT json_extract(payload_json, '$.id') AS run_id FROM orchestration_events
           WHERE command_id = ? AND event_type = 'run.updated'
             AND json_extract(payload_json, '$.status') = 'cancelled'`,
        )
        .all(commandId),
    ).map((row) => row.run_id);
  }

  messageText(messageId: string): string | null {
    return (
      decodeText(
        this.#db
          .prepare(
            `SELECT json_extract(payload_json, '$.text') AS text FROM orchestration_v2_projection_messages
             WHERE message_id = ?`,
          )
          .get(messageId),
      )?.text ?? null
    );
  }
}
