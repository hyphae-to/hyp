// Delivery state of a thread, derived from its shell entry, and the per-connector
// delivery policy (SPEC.md section 6).
import type { OrchestrationV2ThreadShell } from "@t3tools/contracts";

export const DELIVERY_STATES = ["busy", "idle", "stopped", "failed", "settled", "archived"] as const;
export type DeliveryState = (typeof DELIVERY_STATES)[number];

export type PolicyAction = "deliver" | "hold" | "reject";
export type DeliveryPolicy = Readonly<Record<DeliveryState, PolicyAction>>;

export const DEFAULT_POLICY: DeliveryPolicy = {
  busy: "deliver",
  idle: "deliver",
  stopped: "deliver",
  failed: "deliver",
  settled: "deliver",
  archived: "reject",
};

export type ShellLocation = "active" | "archive";

export type ThreadStateFields = Pick<
  OrchestrationV2ThreadShell,
  "status" | "archivedAt" | "deletedAt" | "settledAt" | "settledOverride"
>;

export function classifyThread(thread: ThreadStateFields, location: ShellLocation): DeliveryState {
  if (location === "archive" || thread.archivedAt !== null || thread.deletedAt !== null) return "archived";
  switch (thread.status) {
    case "preparing":
    case "queued":
    case "starting":
    case "running":
    case "waiting":
      return "busy";
    default:
      break;
  }
  const settled =
    thread.settledOverride === "settled" || (thread.settledAt !== null && thread.settledOverride !== "active");
  if (settled) return "settled";
  switch (thread.status) {
    case "interrupted":
      return "stopped";
    case "failed":
    case "cancelled":
      return "failed";
    default:
      return "idle";
  }
}

/** Statuses during which a thread can be making an MCP tool call. */
export const isLiveStatus = (status: OrchestrationV2ThreadShell["status"]): boolean =>
  status === "preparing" || status === "starting" || status === "running" || status === "waiting";
