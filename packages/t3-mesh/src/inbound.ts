// Idempotent T3 delivery shared by messages, router events, plugins and transfers.
import { CommandId, MessageId, ThreadId, type OrchestrationMessageContext } from "@t3tools/contracts";
import type { ConnectorConfig } from "./config.ts";
import { log } from "./log.ts";
import type { InboundEventBatch, InboundOutcome, InboxItem } from "./router/types.ts";
import type { SubscriptionMode } from "./store.ts";
import type { T3Connection } from "./t3/connection.ts";
import { classifyRefusal } from "./t3/refusal.ts";
import { classifyThread } from "./t3/threadState.ts";

export type DeliveryPrefix = "mesh" | "mesh-event" | `mesh-event-router:${string}` | "mesh-plugin" | "mesh-files" | "mesh-fork";

/** Extra links must never deliver messages or transfers, even if their router offers one. */
export function eventRouterDelivery(
  router: string,
  deliver: (batch: InboundEventBatch, prefix: DeliveryPrefix) => Promise<InboundOutcome>,
): (item: InboxItem) => Promise<InboundOutcome> {
  return async (item) => {
    if (item.kind !== "event") {
      log("warn", "router.event_only_rejected", { router, id: item.id, kind: item.kind });
      return { kind: "rejected", reason: "event_only_router" };
    }
    return deliver(item, `mesh-event-router:${router}`);
  };
}

export class InboundDelivery {
  readonly #policy: ConnectorConfig["policy"];
  readonly #delivery: ConnectorConfig["delivery"];
  /** A refused command ID cannot be reused; success retains it for lost-ack replay. */
  readonly #attempts = new Map<string, number>();
  readonly #queueOnly = new Set<string>();

  constructor(config: Pick<ConnectorConfig, "policy" | "delivery">) {
    this.#policy = config.policy;
    this.#delivery = config.delivery;
  }

  /** Applies the delivery policy to the thread, then dispatches `text` into it as `<prefix>:<id>:<attempt>`. */
  async dispatch(
    connection: Pick<T3Connection, "shellEntry" | "dispatch">,
    threadId: string,
    prefix: DeliveryPrefix,
    id: string,
    text: string,
    context: OrchestrationMessageContext | null,
    mode?: SubscriptionMode,
  ): Promise<InboundOutcome> {
    const entry = connection.shellEntry(threadId);
    if (entry === undefined) return { kind: "rejected", reason: "thread_gone" };

    const state = classifyThread(entry.thread, entry.location);
    const action = this.#policy[state];
    if (action === "hold") return { kind: "hold", reason: `policy:${state}` };
    if (action === "reject") return { kind: "rejected", reason: `policy:${state}` };

    if (mode === "interrupt" && entry.thread.pendingRuntimeRequest !== null) {
      return { kind: "hold", reason: "t3_pending_runtime_request" };
    }

    const attemptKey = `${prefix}:${id}`;
    const attempt = this.#attempts.get(attemptKey) ?? 1;
    const key = `${prefix}:${id}:${attempt}`;
    const deliveryIntent = mode === "interrupt"
      ? "restart" as const
      : mode === undefined && this.#delivery === "steer" && !this.#queueOnly.has(attemptKey)
        ? "auto" as const
        : undefined;
    const outcome = await connection.dispatch({
      type: "message.dispatch",
      commandId: CommandId.make(key),
      threadId: ThreadId.make(threadId),
      messageId: MessageId.make(key),
      // T3 rewrites createdBy to "user" for WebSocket clients; sent as "agent" for intent only.
      createdBy: "agent",
      creationSource: "server",
      text,
      ...(context === null ? {} : { context }),
      attachments: [],
      // T3 resolves auto and restart under its thread lock. Queue mode uses dispatchMode alone.
      ...(deliveryIntent === undefined ? {} : { deliveryIntent }),
      dispatchMode: { type: "queue_after_active" },
    });
    // Keep the attempt on success: if the router re-offers (lost ack), the same command ID replays its receipt.
    if (outcome.ok) return { kind: "delivered" };
    if (outcome.kind === "transport") return { kind: "hold", reason: `t3_transport: ${outcome.message}` };
    // T3 refused this command ID for good; the next try must use a new one.
    this.#attempts.set(attemptKey, attempt + 1);
    const refusal = classifyRefusal(outcome.message, attempt);
    if (mode === "interrupt" && (refusal.queueNext || /cannot satisfy a required interrupt-and-restart|interrupt_restart_steering/i.test(outcome.message))) {
      return { kind: "hold", reason: `t3_interrupt_unavailable: ${outcome.message}` };
    }
    if (refusal.queueNext) this.#queueOnly.add(attemptKey);
    return refusal.outcome;
  }
}
