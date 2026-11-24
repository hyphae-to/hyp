// The connector's view of the router (SPEC.md section 7), independent of transport.
import type { CloudEvent } from "./cloudevent.ts";
import type { SubscriptionSpec } from "./events.ts";

export type { SubscriptionSpec };

/**
 * The sending thread in its own T3 environment, as claimed by the sending connector. Display only:
 * receivers render it as a relative link for clients connected to both environments.
 */
export interface MessageOrigin {
  readonly environmentId: string;
  readonly threadId: string;
}

export interface InboundMessage {
  readonly id: string;
  readonly from: string;
  readonly to: string;
  readonly text: string;
  readonly sentAt: string;
  readonly origin: MessageOrigin | null;
}

/** A closed batch of events for one of the connector's subscriptions (SPEC.md section 12.5). */
export interface InboundEventBatch {
  readonly id: string;
  readonly subscriptionId: string;
  readonly topic: string;
  readonly events: readonly CloudEvent[];
  readonly sentAt: string;
}

/** A transfer waiting for this connector (SPEC.md section 15.2); the ciphertext is fetched separately. */
export interface InboundTransfer {
  readonly id: string;
  /** The sending connector ID. */
  readonly from: string;
  readonly type: "files" | "fork" | "fork.result";
  readonly size: number;
  /** The sender-signed header; checked by the recipient against the sender's key from the directory. */
  readonly header: { readonly payload: string; readonly sig: string };
  readonly sentAt: string;
}

/** What the router offers on a connector's inbox stream; acked by `id` either way. */
export type InboxItem =
  | ({ readonly kind: "message" } & InboundMessage)
  | ({ readonly kind: "event" } & InboundEventBatch)
  | ({ readonly kind: "transfer" } & InboundTransfer);

export interface OutboundMessage {
  readonly id: string;
  readonly fromHandle: string;
  readonly to: string;
  readonly text: string;
  readonly origin: MessageOrigin | null;
}

export type SendError =
  | "unknown_recipient"
  | "rate_limited"
  | "queue_full"
  | "too_large"
  | "id_conflict"
  | "invalid"
  | "not_granted"
  | "router_unavailable";

export type SendResult =
  | { readonly ok: true; readonly status: "stored" }
  | { readonly ok: false; readonly error: SendError; readonly message: string };

export type InboundOutcome =
  | { readonly kind: "delivered" }
  /** Dropped for good, e.g. the thread left or is archived. */
  | { readonly kind: "rejected"; readonly reason: string }
  /** Keep at the router and offer again later. */
  | { readonly kind: "hold"; readonly reason: string };

/** Wire/connector representation of an inbox ack (`POST /v1/messages/:id/ack`). */
export type WireOutcome =
  | { outcome: "delivered" }
  | { outcome: "hold" | "rejected"; reason: string };

/** Converts a wire/connector `{ outcome }` into a router-internal `{ kind }` `InboundOutcome`. */
export function toRouterOutcome(
  value: { readonly outcome: "delivered" } | { readonly outcome: "hold" | "rejected"; readonly reason: string },
): InboundOutcome {
  return value.outcome === "delivered"
    ? { kind: "delivered" }
    : { kind: value.outcome, reason: value.reason };
}

/** Converts a router-internal `{ kind }` `InboundOutcome` into a wire/connector `{ outcome }`. */
export function fromRouterOutcome(value: InboundOutcome): WireOutcome {
  return value.kind === "delivered"
    ? { outcome: "delivered" }
    : { outcome: value.kind, reason: value.reason };
}

export interface Peer {
  readonly address: string;
  readonly online: boolean;
}

export type SubscriptionSyncError =
  | "invalid"
  | "invalid_filter"
  | "too_many_subscriptions"
  | "id_conflict"
  | "not_granted"
  | "router_unavailable";

export type SubscriptionSync =
  | {
      readonly ok: true;
      /** Topics in the set that the router does not serve. */
      readonly unknownTopics: readonly string[];
    }
  | {
      readonly ok: false;
      readonly error: SubscriptionSyncError;
      readonly message: string;
      /** The offending subscription and, for invalid_filter, the path of the bad node. */
      readonly id?: string | undefined;
      readonly path?: string | undefined;
    };

export type TransferSendError =
  | "invalid"
  | "unauthorized"
  | "not_granted"
  | "unknown_recipient"
  | "too_large"
  | "queue_full"
  | "id_conflict"
  | "unsupported"
  | "router_unavailable";

export type TransferSendResult =
  | { readonly ok: true }
  | { readonly ok: false; readonly error: TransferSendError; readonly message: string };

/** The router's directory (SPEC.md section 14.5), unverified: the connector checks every item. */
export interface DirectoryResponse {
  readonly adminKey: string;
  readonly entries: readonly unknown[];
  readonly revocations: readonly unknown[];
}

export interface RouterLink {
  /** Replace this connector's enrolled handle set. */
  setHandles(handles: readonly string[]): Promise<void>;
  /**
   * Replace this connector's subscription set. The set is kept and sent again on every reconnect,
   * so a set that could not be sent now still reaches the router later.
   */
  setSubscriptions(subscriptions: readonly SubscriptionSpec[]): Promise<SubscriptionSync>;
  send(message: OutboundMessage): Promise<SendResult>;
  peers(): Promise<readonly Peer[]>;
  /** Delivery state of this connector's subscriptions over the router's retention window; null if unavailable. */
  subscriptionStatus(): Promise<readonly SubscriptionDelivery[] | null>;
  /**
   * Start receiving; `deliver` decides each inbound message's or event batch's outcome. While
   * receiving, the router shows this connector's handles as online. A no-op if already started.
   */
  start(deliver: (item: InboxItem) => Promise<InboundOutcome>): void;
  /** Stop receiving (handles show offline; items wait at the router). start() may be called again. */
  stop(): Promise<void>;
  /** The directory, or null where there is none (loopback, or a router without an admin key). */
  directory(): Promise<DirectoryResponse | null>;
  sendTransfer(header: { readonly payload: string; readonly sig: string }, ciphertext: Buffer): Promise<TransferSendResult>;
  /** A pending transfer's ciphertext; throws if the router does not have it. */
  fetchTransfer(id: string): Promise<Buffer>;
}

export const MAX_TEXT_BYTES = 16 * 1024;

/**
 * One subscription's delivery state at the router (docs/builder-subscriptions.md E5), over its
 * retention window (24 h). Delivered is not handled: follow-up is owned by the work records.
 */
export interface SubscriptionDelivery {
  readonly id: string;
  readonly pending: number;
  /** Opening time (RFC 3339) of the oldest pending batch. */
  readonly oldestPendingAt: string | null;
  /** The reason the connector gave for its latest hold of a pending batch, e.g. t3_unavailable. */
  readonly heldReason: string | null;
  readonly delivered: number;
  readonly lastDeliveredAt: string | null;
  readonly rejected: Readonly<Record<string, number>>;
  /**
   * Batches dropped unseen, by reason: expired (past retention) or queue_full. Batches of a removed
   * subscription, a changed topic or a revoked connector are deleted with it and not counted.
   */
  readonly dropped: Readonly<Record<string, number>>;
  readonly lastDroppedAt: string | null;
}
