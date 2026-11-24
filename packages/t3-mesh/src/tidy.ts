// What scripts/tidy-children.ts does to subagent child threads, as a pure decision so it can be tested
// with a fake clock. Children copy their parent's pin when created, so pinned ones are unpinned; idle
// ones are settled, which ends their event subscriptions (SPEC.md 12.3). A child parked on an open
// assignment (docs/builder-subscriptions.md E3) is not idle in that sense: it holds an `assignment:`
// subscription and waits for its own CI, review or dependency events, so it stays unsettled however
// long it waits. Standing role subscriptions also hold their threads. A user's own settlement is
// never undone here.
import { DateTime } from "effect";
import type { ShellEntry } from "./t3/connection.ts";
import { classifyThread } from "./t3/threadState.ts";

export const ASSIGNMENT_KEY_PREFIX = "assignment:";
export const ROLE_KEY_PREFIX = "role:";

/** Assignment waits and standing roles must survive T3's idle auto-settlement. */
export const optsOutOfAutoSettle = (key: string | undefined): boolean =>
  key?.startsWith(ASSIGNMENT_KEY_PREFIX) === true || key?.startsWith(ROLE_KEY_PREFIX) === true;

export interface TidyInput {
  readonly entries: Iterable<ShellEntry>;
  readonly now: number;
  readonly minIdleMinutes: number;
  /** Subscription keys a thread holds in the connector's state (mesh_subscribe keys). */
  readonly keysOf: (threadId: string) => readonly string[];
}

export interface TidyPlan {
  readonly toUnpin: readonly ShellEntry[];
  readonly toSettle: readonly ShellEntry[];
  /** Why children were left active, with counts. */
  readonly holds: ReadonlyMap<string, number>;
}

/** The last time the thread started, ran or was messaged. */
export function lastActivity({ thread }: ShellEntry): number {
  const times = [thread.createdAt, thread.latestRunStartedAt, thread.latestRunCompletedAt, thread.latestUserMessageAt];
  return Math.max(...times.flatMap((time) => (time == null ? [] : [DateTime.toEpochMillis(time)])));
}

/** Why the child must stay active, or null when it is safe to settle. */
export function holdReason(entry: ShellEntry, input: Pick<TidyInput, "now" | "minIdleMinutes" | "keysOf">): string | null {
  const { thread, location } = entry;
  const state = classifyThread(thread, location);
  if (state === "busy" || thread.activeRunId != null || thread.activityRunStatus != null) return "working";
  if (thread.pendingRuntimeRequest != null) return "pending request";
  if ((thread.pendingBackgroundTasks ?? []).length > 0) return "background tasks";
  const keys = input.keysOf(thread.id);
  if (keys.some(optsOutOfAutoSettle)) {
    return keys.some((key) => key.startsWith(ASSIGNMENT_KEY_PREFIX)) ? "parked on an assignment" : "holds a role subscription";
  }
  if (lastActivity(entry) >= input.now - input.minIdleMinutes * 60_000) return "recent";
  return null;
}

export function planTidy(input: TidyInput): TidyPlan {
  const toUnpin: ShellEntry[] = [];
  const toSettle: ShellEntry[] = [];
  const holds = new Map<string, number>();
  for (const entry of input.entries) {
    const state = classifyThread(entry.thread, entry.location);
    if (state === "archived" || entry.thread.lineage.relationshipToParent !== "subagent") continue;
    if (entry.thread.pinnedAt != null) toUnpin.push(entry);
    if (state === "settled") continue;
    const reason = holdReason(entry, input);
    if (reason === null) toSettle.push(entry);
    else holds.set(reason, (holds.get(reason) ?? 0) + 1);
  }
  return { toUnpin, toSettle, holds };
}
