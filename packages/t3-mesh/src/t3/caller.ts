// Identify which T3 thread made an MCP tool call, from the provider's tool-call ID
// (SPEC.md section 3). Claude passes `_meta["claudecode/toolUseId"]`, Codex `_meta.callId`;
// T3 records the same ID as the running dynamic_tool item's nativeItemRef.nativeId.
import type { OrchestrationV2ThreadProjection, OrchestrationV2TurnItem, ThreadId } from "@t3tools/contracts";
import * as DateTime from "effect/DateTime";
import type { ShellEntry } from "./connection.ts";
import { isLiveStatus } from "./threadState.ts";

export const MCP_SERVER_NAME = "t3-mesh";
const RECENT_THREAD_MS = 2 * 60 * 1000;
const PROJECTION_CONCURRENCY = 8;
/** How long the fast candidates get before the one fallback scan of every eligible thread. */
const FALLBACK_AFTER_MS = 1_500;

/** Shell status describes the latest presented run, not necessarily the run executing the call. */
export function callerCandidateThreadIds(
  entries: Iterable<ShellEntry>,
  widen = false,
  now = Date.now(),
): readonly ThreadId[] {
  const eligible = [...entries]
    .filter(
      ({ thread, location }) =>
        location === "active" && thread.archivedAt === null && thread.deletedAt === null &&
        (widen || thread.activeRunId !== null ||
          (thread.activityRunStatus != null && isLiveStatus(thread.activityRunStatus)) ||
          isLiveStatus(thread.status) || DateTime.toEpochMillis(thread.updatedAt) >= now - RECENT_THREAD_MS),
    );
  // The fallback scans the most recently updated threads first.
  if (widen) eligible.sort((a, b) => DateTime.toEpochMillis(b.thread.updatedAt) - DateTime.toEpochMillis(a.thread.updatedAt));
  return eligible.map(({ thread }) => thread.id);
}

/** Tool names as T3 records them: Claude `mcp__<server>__<tool>`, Codex `<server>.<tool>`. */
export const recordedToolNames = (tool: string): ReadonlySet<string> =>
  new Set([`mcp__${MCP_SERVER_NAME}__${tool}`, `${MCP_SERVER_NAME}.${tool}`]);

export interface CallerLookup {
  /** Likely callers: active runs plus live/recent shell entries. */
  candidateThreadIds(): readonly ThreadId[];
  /** All eligible shell threads, independent of run status or freshness. */
  fallbackThreadIds?(): readonly ThreadId[];
  projection(threadId: ThreadId): Promise<Pick<OrchestrationV2ThreadProjection, "turnItems">>;
}

/** What the last lookup attempt saw; logged when a caller cannot be resolved. */
export interface CallerDiagnostics {
  readonly attempts: number;
  readonly candidates: number;
  readonly projectionErrors: readonly string[];
  /** The call ID was found, but not as an in-flight call of this tool. */
  readonly seenAs: readonly string[];
}

export type CallerResult =
  | { readonly ok: true; readonly threadId: ThreadId; readonly fallback?: true }
  | {
      readonly ok: false;
      readonly code: "caller_not_found" | "caller_ambiguous";
      readonly message: string;
      readonly diagnostics: CallerDiagnostics;
    };

export interface ResolveOptions {
  readonly timeoutMs?: number;
  readonly sleep?: (ms: number) => Promise<void>;
}

const IN_FLIGHT: ReadonlySet<OrchestrationV2TurnItem["status"]> = new Set(["pending", "running", "waiting"]);

export function matchesCall(item: OrchestrationV2TurnItem, callId: string, names: ReadonlySet<string>): boolean {
  return (
    item.type === "dynamic_tool" &&
    item.nativeItemRef?.nativeId === callId &&
    item.toolName !== null &&
    names.has(item.toolName) &&
    IN_FLIGHT.has(item.status)
  );
}

const defaultSleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

const errorText = (reason: unknown): string => (reason instanceof Error ? reason.message : String(reason)).slice(0, 200);

export async function resolveCaller(
  lookup: CallerLookup,
  callId: string,
  tool: string,
  options: ResolveOptions = {},
): Promise<CallerResult> {
  const names = recordedToolNames(tool);
  const sleep = options.sleep ?? defaultSleep;
  const started = Date.now();
  const deadline = started + (options.timeoutMs ?? 10_000);
  let delay = 50;
  let fallbackDone = false;
  for (let attempts = 1; ; attempts++) {
    const candidates = [...new Set(lookup.candidateThreadIds())];
    const matches: ThreadId[] = [];
    const projectionErrors: string[] = [];
    const seenAs: string[] = [];
    const scan = async (ids: readonly ThreadId[]) => {
      for (let offset = 0; offset < ids.length; offset += PROJECTION_CONCURRENCY) {
        const batch = ids.slice(offset, offset + PROJECTION_CONCURRENCY);
        const projections = await Promise.allSettled(batch.map((threadId) => lookup.projection(threadId)));
        projections.forEach((projection, index) => {
          const threadId = batch[index];
          if (threadId === undefined) return;
          if (projection.status === "rejected") {
            projectionErrors.push(`${threadId}: ${errorText(projection.reason)}`);
            return;
          }
          for (const item of projection.value.turnItems) {
            if (item.type !== "dynamic_tool" || item.nativeItemRef?.nativeId !== callId) continue;
            if (matchesCall(item, callId, names)) matches.push(threadId);
            else seenAs.push(`${threadId}: ${item.toolName ?? "?"} ${item.status}`);
          }
        });
      }
    };
    await scan(candidates);
    let fallback = false;
    let finalAttempt = Date.now() + delay > deadline;
    // A first miss is usually projection lag, which the fast candidates resolve on a retry. Only after
    // FALLBACK_AFTER_MS (or on the last attempt) scan every other eligible thread, and only once: a shell
    // can hold well over a thousand threads, each a full projection fetch.
    if (matches.length === 0 && !fallbackDone && (Date.now() - started >= FALLBACK_AFTER_MS || finalAttempt)) {
      fallbackDone = true;
      const primary = new Set(candidates);
      const extra = [...new Set(lookup.fallbackThreadIds?.() ?? [])].filter((id) => !primary.has(id));
      candidates.push(...extra);
      await scan(extra);
      fallback = true;
      finalAttempt ||= Date.now() + delay > deadline;
    }
    const diagnostics: CallerDiagnostics = { attempts, candidates: candidates.length, projectionErrors, seenAs };
    const [first, ...rest] = matches;
    if (first !== undefined && rest.length === 0) {
      return { ok: true, threadId: first, ...(fallback ? { fallback: true } : {}) };
    }
    if (rest.length > 0) {
      return {
        ok: false,
        code: "caller_ambiguous",
        message: `tool call ${callId} found in ${matches.length} threads`,
        diagnostics,
      };
    }
    if (finalAttempt) {
      return {
        ok: false,
        code: "caller_not_found",
        message: `no running ${tool} call ${callId} in ${candidates.length} candidate threads`,
        diagnostics,
      };
    }
    await sleep(delay);
    delay = Math.min(delay * 2, 800);
  }
}
