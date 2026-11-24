// In-process router for a single connector: threads on one T3 instance message each other with
// the same rules as the real router (an in-memory RouterCore). For local testing and single-instance setups.
import { errorMessage } from "../log.ts";
import { RouterCore } from "./core.ts";
import type {
  InboundOutcome,
  InboxItem,
  OutboundMessage,
  Peer,
  DirectoryResponse,
  RouterLink,
  SendResult,
  SubscriptionDelivery,
  SubscriptionSpec,
  SubscriptionSync,
  TransferSendResult,
} from "./types.ts";

const TICK_MS = 1_000;

export class LoopbackRouter implements RouterLink {
  readonly #connectorId: string;
  readonly #core: RouterCore;
  #detach: (() => void) | null = null;
  #timer: NodeJS.Timeout | null = null;

  constructor(connectorId: string, core: RouterCore = new RouterCore({ dbPath: ":memory:" })) {
    this.#connectorId = connectorId;
    this.#core = core;
    core.ensureLocalConnector(connectorId);
  }

  async setHandles(handles: readonly string[]): Promise<void> {
    const result = this.#core.setHandles(this.#connectorId, handles);
    if (!result.ok) throw new Error(`invalid handles: ${result.invalid.join(", ")}`);
  }

  async setSubscriptions(subscriptions: readonly SubscriptionSpec[]): Promise<SubscriptionSync> {
    return this.#core.events.setSubscriptions(this.#connectorId, subscriptions);
  }

  async send(message: OutboundMessage): Promise<SendResult> {
    return this.#core.submit(this.#connectorId, message);
  }

  async subscriptionStatus(): Promise<readonly SubscriptionDelivery[] | null> {
    return this.#core.events.deliveryStatus(this.#connectorId);
  }

  async peers(): Promise<readonly Peer[]> {
    return this.#core.peers();
  }

  start(deliver: (item: InboxItem) => Promise<InboundOutcome>): void {
    if (this.#detach !== null) return;
    this.#detach = this.#core.attach(this.#connectorId, (item) => {
      void deliver(item)
        .catch((error: unknown): InboundOutcome => ({ kind: "hold", reason: errorMessage(error) }))
        .then((outcome) => this.#core.ack(this.#connectorId, item.id, outcome));
    });
    this.#timer = setInterval(() => this.#core.tick(), TICK_MS);
  }

  /** A single connector has no one to pair with or transfer to. */
  async directory(): Promise<DirectoryResponse | null> {
    return null;
  }

  async sendTransfer(): Promise<TransferSendResult> {
    return { ok: false, error: "unsupported", message: "a loopback router has no other connectors to transfer to" };
  }

  async fetchTransfer(id: string): Promise<Buffer> {
    throw new Error(`a loopback router has no transfers (asked for ${id})`);
  }

  async stop(): Promise<void> {
    this.#detach?.();
    this.#detach = null;
    if (this.#timer !== null) clearInterval(this.#timer);
    this.#timer = null;
  }
}
