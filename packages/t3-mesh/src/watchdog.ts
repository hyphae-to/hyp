// Queue watchdog decisions (scripts/queue-watchdog.ts, DEPLOY.md "Queue watchdog"). Each pass looks at
// every thread with queued runs; the only signal is whether its queue moved since the last pass:
// its oldest queued run, or the run that last left the queue, changed. A queue that has not moved
// for one pass gets the first action; for a second pass, a T3 restart. Each step also needs the
// queue to have been still for long enough, so passes run close together (by hand, or a timer
// catching up) do not escalate, and the run in front of the queue must have been silent (no turn
// item changed) for a while: healthy runs of 1-3 hours with messages queued behind them are common,
// and none went 15 minutes without a change; the stalls this exists for were silent for hours.
import * as Schema from "effect/Schema";
import type { ActiveRun, HoldCause } from "./t3/stateDb.ts";

/** Leave queues alone whose oldest message was already this old when first seen. */
export const MAX_FIRST_SEEN_AGE_MS = 24 * 3_600_000;
/** How long a queue must have been still for the first action; twice this for a restart. */
export const MIN_STILL_MS = 50 * 60_000;
/** How long the run in front of the queue must have been silent before it is interrupted or T3 restarted. */
export const DEFAULT_MIN_SILENT_MS = 60 * 60_000;
/** At most one T3 restart per instance in this window. */
export const RESTART_INTERVAL_MS = 6 * 3_600_000;

const Stage = Schema.Literals([
  /** Seen; acts if the queue has not moved at the next pass. */
  "watching",
  /** Interrupted the active run, or resumed the queue. */
  "acted",
  /** Restarted T3 for this queue. */
  "restarted",
  /** Nothing more the watchdog will do until the queue changes. */
  "left",
  /** Too old when first seen. */
  "ignored",
]);
export type Stage = typeof Stage.Type;

const ThreadRecord = Schema.Struct({
  oldestQueuedRunId: Schema.String,
  lastStartedRunId: Schema.NullOr(Schema.String),
  since: Schema.String,
  stage: Stage,
});
export type ThreadRecord = typeof ThreadRecord.Type;

export const WatchdogState = Schema.Struct({
  version: Schema.Literal(1),
  lastRestartAt: Schema.NullOr(Schema.String),
  threads: Schema.Record(Schema.String, ThreadRecord),
});
export type WatchdogState = typeof WatchdogState.Type;

export const EMPTY_STATE: WatchdogState = { version: 1, lastRestartAt: null, threads: {} };

export interface Observation {
  readonly threadId: string;
  readonly title: string;
  readonly oldestQueuedRunId: string;
  readonly oldestQueuedAt: string;
  readonly queued: number;
  readonly held: number;
  readonly activeRun: ActiveRun | null;
  readonly lastStartedRunId: string | null;
  /** Why the queue is held; null when no queued run is held. */
  readonly holdCause: HoldCause | null;
}

/** Whether this pass may restart T3, from the instance's platform, unit and last restart. */
export type RestartPermission =
  | { readonly kind: "allowed" }
  | { readonly kind: "refused"; readonly reason: string };

export type Step =
  | { readonly kind: "interrupt"; readonly runId: string }
  | { readonly kind: "resume" }
  | { readonly kind: "message"; readonly text: string }
  | { readonly kind: "restart" };

export interface Decision {
  readonly record: ThreadRecord;
  readonly steps: readonly Step[];
  /** What the watchdog concluded, for the journal. */
  readonly note: string;
  /** Sent to the operator as well as the journal. */
  readonly alert: string | null;
}

/**
 * Only a restart's hold is resumed: a Stop is deliberate, and its messages wait for the user. The
 * watchdog's own interrupt does not hold the queue.
 */
export const isResumable = (cause: HoldCause | null): boolean => cause?.kind === "restart";

export const describeHold = (cause: HoldCause | null): string => {
  if (cause === null) return "not held";
  switch (cause.kind) {
    case "restart":
      return `held by a T3 restart at ${cause.at}`;
    case "stop":
      return `held by a Stop at ${cause.at}`;
    case "other":
      return `held by ${cause.commandType ?? cause.commandId ?? "a server event"} at ${cause.at}`;
    case "unknown":
      return "held, cause unknown";
  }
};

/** The `ordinal:N` suffix of a run ID, for messages only; runs are always keyed by their full ID. */
export const shortRunId = (runId: string): string => runId.slice(runId.lastIndexOf(":ordinal:") + 1);

const hours = (ms: number): string => `${(ms / 3_600_000).toFixed(1)}h`;

export function decide(
  observation: Observation,
  previous: ThreadRecord | undefined,
  now: Date,
  restart: RestartPermission,
  minSilentMs: number = DEFAULT_MIN_SILENT_MS,
): Decision {
  const { activeRun } = observation;
  const sameOldest = previous?.oldestQueuedRunId === observation.oldestQueuedRunId;
  const moved = !sameOldest || previous.lastStartedRunId !== observation.lastStartedRunId;
  const record = (stage: Stage): ThreadRecord => ({
    oldestQueuedRunId: observation.oldestQueuedRunId,
    lastStartedRunId: observation.lastStartedRunId,
    since: moved || previous === undefined ? now.toISOString() : previous.since,
    stage,
  });
  const quiet = (stage: Stage, note: string): Decision => ({ record: record(stage), steps: [], note, alert: null });
  const queue = `${observation.queued} queued (${observation.held} held, ${describeHold(observation.holdCause)})`;

  if (!sameOldest) {
    const age = now.getTime() - Date.parse(observation.oldestQueuedAt);
    if (age > MAX_FIRST_SEEN_AGE_MS) {
      return {
        record: record("ignored"),
        steps: [],
        note: "oldest queued message too old when first seen, leaving it",
        alert: `${observation.title}: oldest queued message is ${hours(age)} old (${queue}); leaving it alone`,
      };
    }
    return quiet("watching", previous === undefined ? "new queue" : "queue moved");
  }
  // Movement behind an old message that is being left alone does not make it new.
  if (previous.stage === "ignored") return quiet("ignored", "too old when first seen");
  if (moved) return quiet("watching", "queue moved");

  const stillMs = now.getTime() - Date.parse(previous.since);
  const due = previous.stage === "watching" ? MIN_STILL_MS : previous.stage === "acted" ? 2 * MIN_STILL_MS : 0;
  if (stillMs < due) return quiet(previous.stage, `queue still for ${hours(stillMs)}, acting from ${hours(due)}`);
  if (activeRun !== null && (previous.stage === "watching" || previous.stage === "acted")) {
    const changes = [activeRun.lastItemAt, activeRun.startedAt].flatMap((time) => (time === null ? [] : [Date.parse(time)]));
    const silentMs = now.getTime() - Math.max(0, ...changes);
    if (silentMs < minSilentMs) {
      return quiet(
        previous.stage,
        `queue still for ${hours(stillMs)}, but run ${shortRunId(activeRun.runId)} changed ${Math.round(silentMs / 60_000)}m ago`,
      );
    }
  }
  const stuckFor = hours(stillMs);
  switch (previous.stage) {
    case "left":
      return quiet("left", "left alone");
    case "watching": {
      if (activeRun !== null) {
        const resume = observation.held > 0 && isResumable(observation.holdCause);
        return {
          record: record("acted"),
          steps: [
            { kind: "interrupt", runId: activeRun.runId },
            ...(resume ? [{ kind: "resume" } as const] : []),
            {
              kind: "message",
              text:
                `watchdog: resuming queue. Run ${shortRunId(activeRun.runId)} (${activeRun.status} since ` +
                `${activeRun.startedAt ?? "?"}) had not finished while ${observation.queued} queued message(s) ` +
                `waited behind it for over ${stuckFor}, so the watchdog interrupted it. If its last step was ` +
                "a tool call, check whether it completed.",
            },
          ],
          note: `queue stuck ${stuckFor}: interrupting ${activeRun.status} run ${shortRunId(activeRun.runId)}`,
          alert: null,
        };
      }
      if (observation.held === 0) {
        return {
          record: record("acted"),
          steps: [{ kind: "resume" }],
          note: `queue stuck ${stuckFor} with no active run and nothing held: resuming`,
          alert: null,
        };
      }
      if (isResumable(observation.holdCause)) {
        return {
          record: record("acted"),
          steps: [{ kind: "resume" }],
          note: `queue stuck ${stuckFor}: resuming`,
          alert: null,
        };
      }
      return quiet("left", `queue stuck ${stuckFor}: waits for the user`);
    }
    case "acted": {
      if (activeRun === null) {
        return {
          record: record("left"),
          steps: [],
          note: `queue still stuck ${stuckFor} after the watchdog acted`,
          alert: `${observation.title}: queue still not moving ${stuckFor} after the watchdog resumed it (${queue}); leaving it`,
        };
      }
      if (restart.kind === "refused") {
        return {
          record: record("left"),
          steps: [],
          note: `queue still stuck ${stuckFor} behind run ${shortRunId(activeRun.runId)}; no restart: ${restart.reason}`,
          alert:
            `${observation.title}: queue stuck ${stuckFor} behind ${activeRun.status} run ` +
            `${shortRunId(activeRun.runId)} after an interrupt; not restarting T3 (${restart.reason})`,
        };
      }
      return {
        record: record("restarted"),
        steps: [{ kind: "restart" }],
        note: `queue still stuck ${stuckFor} after an interrupt: restarting T3`,
        alert: null,
      };
    }
    case "restarted":
      return {
        record: record("left"),
        steps: [],
        note: `queue still stuck ${stuckFor} after a T3 restart`,
        alert: `${observation.title}: queue still stuck ${stuckFor} after the watchdog restarted T3 (${queue}); leaving it`,
      };
  }
}

/** Whether the instance may be restarted now, given the last restart. */
export function restartPermission(
  lastRestartAt: string | null,
  now: Date,
  platform: { readonly darwin: boolean; readonly unitPresent: boolean; readonly unit: string },
): RestartPermission {
  if (platform.darwin) return { kind: "refused", reason: "macOS: alert only" };
  if (!platform.unitPresent) return { kind: "refused", reason: `no systemd user unit ${platform.unit}` };
  if (lastRestartAt !== null && now.getTime() - Date.parse(lastRestartAt) < RESTART_INTERVAL_MS) {
    return { kind: "refused", reason: `already restarted at ${lastRestartAt}, at most one restart per 6h` };
  }
  return { kind: "allowed" };
}
