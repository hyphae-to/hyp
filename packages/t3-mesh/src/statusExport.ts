// Narrow execution status of this connector's T3 instance (docs/builder-subscriptions.md E4): the
// usage-tally input for whoever schedules new work (PM/Lead, slice D). Read-only: the connector itself
// admits or holds nothing on it. Built from the thread shell the connector already keeps (no full
// thread projections) and written atomically to a private file; consumers treat a missing file,
// `t3ObservedAt: null` or an old `generatedAt` as unknown, never as free capacity.
import { renameSync, writeFileSync } from "node:fs";
import type { ShellEntry } from "./t3/connection.ts";
import { classifyThread, type DeliveryState } from "./t3/threadState.ts";
import { ASSIGNMENT_KEY_PREFIX } from "./tidy.ts";

/**
 * The thread's latest run, finished or still stopping, had a stop or interrupt request; a new run (a
 * resume) clears it. T3 4399 records a user's thread Stop and a narrow run.interrupt alike.
 */
export const interruptRequested = (entry: ShellEntry): boolean => entry.thread.latestRunStopRequested === true;

export interface ExecutionStatus {
  readonly schema: 1;
  readonly connector: string;
  readonly generatedAt: string;
  /** Now while connected to T3 (loopback), null while disconnected. */
  readonly t3ObservedAt: string | null;
  readonly threads: ReadonlyArray<{
    readonly threadId: string;
    readonly parentThreadId: string | null;
    readonly state: DeliveryState;
    readonly status: string;
    /** The latest run, finished or still stopping, had a stop or interrupt request; a resume clears it. */
    readonly interruptRequested: boolean;
    readonly assignments: readonly string[];
    /** The run in progress, if any. */
    readonly activeRunId: string | null;
  }>;
  readonly counts: { readonly busy: number; readonly parked: number; readonly interrupted: number };
}

export interface StatusInput {
  readonly connector: string;
  readonly now: number;
  /** Null while the connector has no live T3 connection. */
  readonly shells: Iterable<ShellEntry> | null;
  readonly keysOf: (threadId: string) => readonly string[];
}

/**
 * Threads that are working, parked on an assignment, or interrupted and not settled (standing roles
 * included). Other idle and settled threads are left out: they use no slot and wait on no assignment.
 */
export function buildStatus({ connector, now, shells, keysOf }: StatusInput): ExecutionStatus {
  const threads: Array<ExecutionStatus["threads"][number]> = [];
  let busy = 0;
  let parked = 0;
  let interrupted = 0;
  for (const entry of shells ?? []) {
    const state = classifyThread(entry.thread, entry.location);
    if (state === "archived") continue;
    const assignments = keysOf(entry.thread.id).filter((key) => key.startsWith(ASSIGNMENT_KEY_PREFIX));
    // Every unsettled interrupted thread is listed, standing roles included (diagnostic for the tally).
    const interrupt = interruptRequested(entry) && state !== "settled";
    if (state !== "busy" && assignments.length === 0 && !interrupt) continue;
    if (interrupt) interrupted += 1;
    if (state === "busy") busy += 1;
    else if (assignments.length > 0 && !interrupt && state !== "settled") parked += 1;
    threads.push({
      threadId: entry.thread.id,
      parentThreadId: entry.thread.lineage.parentThreadId ?? null,
      state,
      status: entry.thread.status,
      interruptRequested: interrupt,
      assignments,
      activeRunId: entry.thread.activeRunId ?? null,
    });
  }
  const at = new Date(now).toISOString();
  return {
    schema: 1,
    connector,
    generatedAt: at,
    t3ObservedAt: shells === null ? null : at,
    threads,
    counts: { busy, parked, interrupted },
  };
}

/** How old `generatedAt` and `t3ObservedAt` may be before the status is unknown. */
export const STATUS_MAX_AGE_MS = 60_000;

/**
 * Why a written status must be treated as unknown, or null when it is usable: unreadable, from the
 * future, older than STATUS_MAX_AGE_MS, or written while not connected to T3 (`t3ObservedAt` null).
 */
export function statusProblem(text: string, now: number): string | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return "status is not readable JSON";
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return "status is not a status object";
  const time = (name: string): number => {
    const value: unknown = (parsed as Record<string, unknown>)[name];
    return typeof value === "string" ? Date.parse(value) : Number.NaN;
  };
  const fresh = (at: number) => Number.isFinite(at) && at <= now && now - at <= STATUS_MAX_AGE_MS;
  if (!fresh(time("generatedAt"))) return "status is stale";
  if (!fresh(time("t3ObservedAt"))) return "the connector was not connected to T3";
  return null;
}

/** Writes the status atomically (temp file, then rename), readable only by this user. */
export function writeStatus(path: string, status: ExecutionStatus): void {
  const temp = `${path}.${process.pid}.tmp`;
  writeFileSync(temp, `${JSON.stringify(status, null, 2)}\n`, { mode: 0o600 });
  renameSync(temp, path);
}
