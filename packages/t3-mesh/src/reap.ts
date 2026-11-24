// What scripts/reap-threads.ts deletes, as a pure decision so it can be tested with a fake clock.
// A group is a subagent thread whose parent is a top-level thread (or is not in T3's shell, e.g.
// archived), with every thread below it: a builder (`builder-<n>…`) and its reviews and helpers, a
// Lead's research task, a Release Manager's or Process Consultant's child. Top-level threads (the
// Lead, Release Manager, a person's own threads) are never deleted.
// A group goes only as a whole, and only when every thread in it is settled or archived, idle for
// the threshold, unpinned, with nothing running or pending and no mesh subscription (a parked builder
// holds an `assignment:` one). Deletion cannot be undone, so anything uncertain keeps the group.
//
// T3 does not delete child threads with their parent, so each group is listed children first and
// its root last: if a deletion fails partway, the root stays and the next run finds the rest.
//
// The plan also names the worktrees the deletions free: T3-managed ones (under the worktrees root)
// that no thread outside the deleted subtrees uses, archived ones included. The script removes one
// only after every thread using it is deleted, and only with a plain `git worktree remove`,
// which refuses a worktree with uncommitted or untracked files.
import { isAbsolute, relative, resolve } from "node:path";
import { DateTime } from "effect";
import type { ShellEntry } from "./t3/connection.ts";
import { classifyThread } from "./t3/threadState.ts";
import { holdReason, lastActivity } from "./tidy.ts";

export interface ReapInput {
  readonly entries: Iterable<ShellEntry>;
  readonly now: number;
  readonly minIdleDays: number;
  /** Subscription keys a thread holds in the connector's state (mesh_subscribe keys). */
  readonly keysOf: (threadId: string) => readonly string[];
  /** Most threads to delete in one run; whole subtrees only, oldest first. */
  readonly maxThreads: number;
  /** T3's managed worktrees directory (`~/.t3/worktrees`); worktrees elsewhere are never removed. */
  readonly worktreesRoot: string;
  /**
   * Worktrees of threads not in `entries` that still exist: T3's shell leaves archived threads
   * out, so the script reads theirs from T3's database. These are never removed.
   */
  readonly worktreesInUse?: readonly string[];
}

export interface ReapSubtree {
  readonly root: ShellEntry;
  /** The root's parent's title, when T3's shell has it (e.g. "Bayfold Lead Gen1"). */
  readonly parentTitle: string | null;
  /** Children before their parents; the root is last. */
  readonly order: readonly ShellEntry[];
  readonly lastActiveAt: number;
}

export interface ReapWorktree {
  readonly path: string;
  /** The threads being deleted that use it; it is removed only if every one of them was deleted. */
  readonly threadIds: readonly string[];
}

export interface ReapPlan {
  readonly toDelete: readonly ReapSubtree[];
  /** Groups kept, by the first reason found in them. */
  readonly holds: ReadonlyMap<string, number>;
  /** Eligible subtrees left for a later run by maxThreads. */
  readonly deferred: number;
  /** Managed worktrees used only by threads in toDelete. */
  readonly worktrees: readonly ReapWorktree[];
}

/** Why this thread keeps its group, or null when it may be deleted. */
export function keepReason(entry: ShellEntry, input: Pick<ReapInput, "now" | "minIdleDays" | "keysOf">): string | null {
  const { thread, location } = entry;
  const state = classifyThread(thread, location);
  // holdReason covers running, pending requests, background tasks and assignments; "recent" is
  // judged here in days, so it is asked with a zero threshold.
  const held = holdReason(entry, { now: input.now, minIdleMinutes: 0, keysOf: input.keysOf });
  if (held !== null && held !== "recent") return held;
  if (thread.pinnedAt != null) return "pinned";
  if (state !== "settled" && state !== "archived") return "not settled";
  if (input.keysOf(thread.id).length > 0) return "subscribed";
  if (activeAt(entry) >= input.now - input.minIdleDays * 86_400_000) return "recent";
  return null;
}

/**
 * Real activity: created, a run started or finished, a message, or someone opening the thread.
 * Not `updatedAt`: T3 bumps it on idle threads too (1,340 on solace in one hour on 2026-11-02),
 * which would keep every group "recent".
 */
function activeAt(entry: ShellEntry): number {
  const visited = entry.thread.lastVisitedAt;
  return Math.max(lastActivity(entry), visited == null ? 0 : DateTime.toEpochMillis(visited));
}

/** A path strictly inside root (not root itself), compared after resolving both. */
export function isInside(path: string, root: string): boolean {
  const rel = relative(resolve(root), resolve(path));
  return rel !== "" && !rel.startsWith("..") && !isAbsolute(rel);
}

/** A worktree is in use while a thread works in it, inside it, or in a folder containing it. */
export function worktreeInUse(path: string, inUse: Iterable<string>): boolean {
  const target = resolve(path);
  for (const other of inUse) {
    const resolved = resolve(other);
    if (resolved === target || isInside(resolved, target) || isInside(target, resolved)) return true;
  }
  return false;
}

export function planReap(input: ReapInput): ReapPlan {
  const byId = new Map<string, ShellEntry>();
  const children = new Map<string, ShellEntry[]>();
  for (const entry of input.entries) {
    if (entry.thread.deletedAt !== null) continue;
    byId.set(entry.thread.id, entry);
  }
  for (const entry of byId.values()) {
    const parent = entry.thread.lineage.parentThreadId;
    if (parent == null) continue;
    children.set(parent, [...(children.get(parent) ?? []), entry]);
  }

  const isSubagent = (entry: ShellEntry) => entry.thread.lineage.relationshipToParent === "subagent";
  const parentOf = (entry: ShellEntry): ShellEntry | undefined => {
    const parentId = entry.thread.lineage.parentThreadId;
    return parentId == null ? undefined : byId.get(parentId);
  };
  /**
   * A subagent whose parent is top-level or not in the shell. On a lineage cycle (which T3 should
   * never produce) every thread has a subagent parent, so none is a root and the cycle stays.
   */
  const isGroupRoot = (entry: ShellEntry): boolean => {
    if (!isSubagent(entry)) return false;
    const parent = parentOf(entry);
    return parent === undefined || !isSubagent(parent);
  };
  /** The subtree, children before parents; a lineage cycle is walked once. */
  const postOrder = (root: ShellEntry): ShellEntry[] => {
    const out: ShellEntry[] = [];
    const seen = new Set<string>();
    const visit = (entry: ShellEntry) => {
      if (seen.has(entry.thread.id)) return;
      seen.add(entry.thread.id);
      for (const child of children.get(entry.thread.id) ?? []) visit(child);
      out.push(entry);
    };
    visit(root);
    return out;
  };

  const eligible: ReapSubtree[] = [];
  const holds = new Map<string, number>();
  for (const root of byId.values()) {
    if (!isGroupRoot(root)) continue;
    const order = postOrder(root);
    const reason = order.map((entry) => keepReason(entry, input)).find((r) => r !== null) ?? null;
    if (reason !== null) {
      holds.set(reason, (holds.get(reason) ?? 0) + 1);
      continue;
    }
    eligible.push({ root, parentTitle: parentOf(root)?.thread.title ?? null, order, lastActiveAt: Math.max(...order.map(activeAt)) });
  }

  eligible.sort((a, b) => a.lastActiveAt - b.lastActiveAt);
  const toDelete: ReapSubtree[] = [];
  let budget = input.maxThreads;
  for (const subtree of eligible) {
    // A subtree larger than the whole budget still goes, alone, so it cannot block every later run.
    if (subtree.order.length > budget && toDelete.length > 0) break;
    toDelete.push(subtree);
    budget -= subtree.order.length;
  }

  // A worktree stays while any thread outside this run's deletions points at it.
  const deleting = new Set(toDelete.flatMap((subtree) => subtree.order.map((entry) => entry.thread.id)));
  const users = new Map<string, string[]>();
  const inUse = new Set<string>((input.worktreesInUse ?? []).map((path) => resolve(path)));
  for (const { thread } of byId.values()) {
    if (thread.worktreePath == null) continue;
    const path = resolve(thread.worktreePath);
    if (!deleting.has(thread.id)) inUse.add(path);
    else users.set(path, [...(users.get(path) ?? []), thread.id]);
  }
  // Kept as well when a remaining thread works inside it, or in a folder that contains it.
  const worktrees = [...users]
    .filter(([path]) => isInside(path, input.worktreesRoot) && !worktreeInUse(path, inUse))
    .map(([path, threadIds]) => ({ path, threadIds }));
  return { toDelete, holds, deferred: eligible.length - toDelete.length, worktrees };
}
