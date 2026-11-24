// The connector's link to the HTTP router (SPEC.md section 7). Keeps an SSE inbox stream open,
// re-registers handles and subscriptions on every (re)connect, and acks each offered message or
// event batch.
import * as Schema from "effect/Schema";
import { errorMessage, log } from "../log.ts";
import { checkCloudEvent, type CloudEvent } from "./cloudevent.ts";
import type {
  DirectoryResponse,
  InboundOutcome,
  InboxItem,
  OutboundMessage,
  Peer,
  RouterLink,
  SendError,
  SendResult,
  SubscriptionDelivery,
  SubscriptionSpec,
  SubscriptionSync,
  SubscriptionSyncError,
  TransferSendResult,
} from "./types.ts";

const Counts = Schema.Record(Schema.String, Schema.Number);
const DeliveryBody = Schema.Struct({
  subscriptions: Schema.Array(
    Schema.Struct({
      id: Schema.String,
      pending: Schema.Number,
      oldestPendingAt: Schema.NullOr(Schema.String),
      heldReason: Schema.NullOr(Schema.String),
      delivered: Schema.Number,
      lastDeliveredAt: Schema.NullOr(Schema.String),
      rejected: Counts,
      dropped: Counts,
      lastDroppedAt: Schema.NullOr(Schema.String),
    }),
  ),
});
const decodeDeliveryBody = Schema.decodeUnknownOption(DeliveryBody);

const InboundMessageSchema = Schema.Struct({
  id: Schema.String,
  from: Schema.String,
  to: Schema.String,
  text: Schema.String,
  sentAt: Schema.String,
  origin: Schema.optionalKey(Schema.NullOr(Schema.Struct({ environmentId: Schema.String, threadId: Schema.String }))),
});
const InboundEventBatchSchema = Schema.Struct({
  kind: Schema.Literal("event"),
  id: Schema.String,
  subscriptionId: Schema.String,
  topic: Schema.String,
  events: Schema.Array(Schema.Unknown),
  sentAt: Schema.String,
});
const SubscriptionSyncErrorSchema = Schema.Literals([
  "invalid",
  "invalid_filter",
  "too_many_subscriptions",
  "id_conflict",
  "not_granted",
]);
const SubscriptionsOk = Schema.Struct({ unknownTopics: Schema.Array(Schema.String) });
const SubscriptionsError = Schema.Struct({
  error: Schema.String,
  message: Schema.String,
  id: Schema.optionalKey(Schema.String),
  path: Schema.optionalKey(Schema.String),
});
const SendErrorSchema = Schema.Literals([
  "unknown_recipient",
  "rate_limited",
  "queue_full",
  "too_large",
  "id_conflict",
  "invalid",
  "not_granted",
  "router_unavailable",
]);
const ErrorBody = Schema.Struct({ error: Schema.String, message: Schema.String });
const PeersBody = Schema.Struct({
  peers: Schema.Array(Schema.Struct({ address: Schema.String, online: Schema.Boolean })),
});
const decodeInbound = Schema.decodeUnknownSync(InboundMessageSchema);
const decodeEventBatch = Schema.decodeUnknownSync(InboundEventBatchSchema);
const decodeSubscriptionsOk = Schema.decodeUnknownOption(SubscriptionsOk);
const decodeSubscriptionsError = Schema.decodeUnknownOption(SubscriptionsError);
const isSubscriptionSyncError = Schema.is(SubscriptionSyncErrorSchema);
const decodeErrorBody = Schema.decodeUnknownOption(ErrorBody);
const isSendError = Schema.is(SendErrorSchema);
const decodePeers = Schema.decodeUnknownSync(PeersBody);

const InboundTransferSchema = Schema.Struct({
  kind: Schema.Literal("transfer"),
  id: Schema.String,
  from: Schema.String,
  type: Schema.Literals(["files", "fork", "fork.result"]),
  size: Schema.Number,
  header: Schema.Struct({ payload: Schema.String, sig: Schema.String }),
  sentAt: Schema.String,
});
const decodeTransfer = Schema.decodeUnknownSync(InboundTransferSchema);
const TransferErrorSchema = Schema.Literals([
  "invalid",
  "unauthorized",
  "not_granted",
  "unknown_recipient",
  "too_large",
  "queue_full",
  "id_conflict",
]);
const isTransferError = Schema.is(TransferErrorSchema);
const DirectoryBody = Schema.Struct({
  adminKey: Schema.String,
  entries: Schema.Array(Schema.Unknown),
  revocations: Schema.Array(Schema.Unknown),
});
/** Transfers are up to 256 MiB; at a few MB/s over the tailnet that takes well over the default timeout. */
const TRANSFER_TIMEOUT_MS = 30 * 60 * 1000;

/** An inbox item from its SSE data: `kind` "event" is a batch, "transfer" a transfer; anything else (or none) a message. */
export function decodeInboxItem(value: unknown): InboxItem {
  if (typeof value === "object" && value !== null && "kind" in value && value.kind === "transfer") return decodeTransfer(value);
  if (typeof value === "object" && value !== null && "kind" in value && value.kind === "event") {
    const batch = decodeEventBatch(value);
    // Events were checked by the router; anything that is not a CloudEvent now is dropped, not trusted.
    const events = batch.events.flatMap((event): CloudEvent[] => {
      const checked = checkCloudEvent(event);
      return checked.ok ? [checked.event] : [];
    });
    return { ...batch, events };
  }
  const message = decodeInbound(value);
  return { kind: "message", ...message, origin: message.origin ?? null };
}

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));
/** Every request but the inbox stream; a hung router must not stall tool calls or the reconnect behind them. */
const REQUEST_TIMEOUT_MS = 15_000;

interface InboxSession {
  stopped: boolean;
  abort: AbortController | null;
}

export class HttpRouterLink implements RouterLink {
  readonly #url: string;
  readonly #token: string;
  readonly #name: string;
  readonly #eventOnly: boolean;
  readonly #rejectRedirects: boolean;
  #subscriptionWrites: Promise<unknown> = Promise.resolve();
  #handles: readonly string[] = [];
  #subscriptions: readonly SubscriptionSpec[] = [];
  /** The running inbox stream; stop() ends it, start() opens a new one. */
  #session: InboxSession | null = null;

  readonly #requestTimeoutMs: number;

  constructor(url: string, token: string, options: { readonly requestTimeoutMs?: number; readonly name?: string; readonly eventOnly?: boolean; readonly rejectRedirects?: boolean } = {}) {
    this.#url = url.replace(/\/$/, "");
    this.#token = token;
    this.#name = options.name ?? "primary";
    this.#eventOnly = options.eventOnly ?? false;
    this.#rejectRedirects = this.#eventOnly || (options.rejectRedirects ?? false);
    this.#requestTimeoutMs = options.requestTimeoutMs ?? REQUEST_TIMEOUT_MS;
  }

  #request(method: string, path: string, body?: unknown, signal?: AbortSignal): Promise<Response> {
    return fetch(`${this.#url}${path}`, {
      method,
      headers: {
        authorization: `Bearer ${this.#token}`,
        ...(body === undefined ? {} : { "content-type": "application/json" }),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      ...(this.#rejectRedirects ? { redirect: "error" as const } : {}),
      signal: signal ?? AbortSignal.timeout(this.#requestTimeoutMs),
    });
  }

  async setHandles(handles: readonly string[]): Promise<void> {
    if (this.#eventOnly) return;
    this.#handles = [...handles];
    try {
      await this.#putHandles();
    } catch (error) {
      // The inbox loop re-sends handles when it reconnects.
      log("warn", "router.set_handles_failed", { error: errorMessage(error) });
    }
  }

  async #putHandles(): Promise<void> {
    const response = await this.#request("PUT", "/v1/handles", { handles: this.#handles });
    if (!response.ok) throw new Error(`PUT /v1/handles: HTTP ${response.status}`);
  }

  async setSubscriptions(subscriptions: readonly SubscriptionSpec[]): Promise<SubscriptionSync> {
    this.#subscriptions = [...subscriptions];
    return this.#queueSubscriptions();
  }

  /** Reconnect replays share the write queue; each write reads the latest desired set on starting. */
  #queueSubscriptions(): Promise<SubscriptionSync> {
    const result = this.#subscriptionWrites.then(() => this.#putSubscriptions());
    this.#subscriptionWrites = result.catch(() => undefined);
    return result;
  }

  async #putSubscriptions(): Promise<SubscriptionSync> {
    let response: Response;
    try {
      response = await this.#request("PUT", "/v1/subscriptions", { subscriptions: this.#subscriptions });
    } catch (error) {
      return { ok: false, error: "router_unavailable", message: errorMessage(error) };
    }
    const body: unknown = await response.json().catch(() => null);
    if (response.ok) {
      const ok = decodeSubscriptionsOk(body);
      return { ok: true, unknownTopics: ok._tag === "Some" ? ok.value.unknownTopics : [] };
    }
    const failed = decodeSubscriptionsError(body);
    if (response.status >= 500 || failed._tag === "None") {
      return { ok: false, error: "router_unavailable", message: `PUT /v1/subscriptions: HTTP ${response.status}` };
    }
    const error: SubscriptionSyncError = isSubscriptionSyncError(failed.value.error) ? failed.value.error : "invalid";
    return { ok: false, error, message: failed.value.message, id: failed.value.id, path: failed.value.path };
  }

  async send(message: OutboundMessage): Promise<SendResult> {
    let response: Response;
    try {
      response = await this.#request("POST", "/v1/messages", message);
    } catch (error) {
      return { ok: false, error: "router_unavailable", message: errorMessage(error) };
    }
    if (response.ok) return { ok: true, status: "stored" };
    const body = decodeErrorBody(await response.json().catch(() => null));
    if (body._tag === "Some") {
      const error: SendError = isSendError(body.value.error) ? body.value.error : "invalid";
      return { ok: false, error, message: body.value.message };
    }
    return { ok: false, error: "router_unavailable", message: `HTTP ${response.status}` };
  }

  async peers(): Promise<readonly Peer[]> {
    const response = await this.#request("GET", "/v1/peers");
    if (!response.ok) throw new Error(`GET /v1/peers: HTTP ${response.status}`);
    return decodePeers(await response.json()).peers;
  }

  async subscriptionStatus(): Promise<readonly SubscriptionDelivery[] | null> {
    try {
      const response = await this.#request("GET", "/v1/subscriptions/status");
      // 404: a router from before this endpoint; delivery state is unknown, not empty.
      if (!response.ok) return null;
      const body = decodeDeliveryBody(await response.json());
      return body._tag === "Some" ? body.value.subscriptions : null;
    } catch {
      return null;
    }
  }

  async directory(): Promise<DirectoryResponse | null> {
    const response = await this.#request("GET", "/v1/directory");
    // 503: the router has no admin key, so there is no directory.
    if (response.status === 503) return null;
    if (!response.ok) throw new Error(`GET /v1/directory: HTTP ${response.status}`);
    return Schema.decodeUnknownSync(DirectoryBody)(await response.json());
  }

  async sendTransfer(header: { readonly payload: string; readonly sig: string }, ciphertext: Buffer): Promise<TransferSendResult> {
    const id = Schema.decodeUnknownSync(Schema.fromJsonString(Schema.Struct({ id: Schema.String })))(header.payload).id;
    let response: Response;
    try {
      response = await fetch(`${this.#url}/v1/transfers/${encodeURIComponent(id)}`, {
        method: "PUT",
        headers: {
          authorization: `Bearer ${this.#token}`,
          "content-type": "application/octet-stream",
          "t3-mesh-transfer": Buffer.from(JSON.stringify(header), "utf8").toString("base64url"),
        },
        body: new Uint8Array(ciphertext),
        ...(this.#rejectRedirects ? { redirect: "error" as const } : {}),
        signal: AbortSignal.timeout(TRANSFER_TIMEOUT_MS),
      });
    } catch (error) {
      return { ok: false, error: "router_unavailable", message: errorMessage(error) };
    }
    if (response.ok) return { ok: true };
    const body = decodeErrorBody(await response.json().catch(() => null));
    if (body._tag === "Some" && isTransferError(body.value.error)) return { ok: false, error: body.value.error, message: body.value.message };
    return { ok: false, error: "router_unavailable", message: `PUT /v1/transfers: HTTP ${response.status}` };
  }

  async fetchTransfer(id: string): Promise<Buffer> {
    const response = await fetch(`${this.#url}/v1/transfers/${encodeURIComponent(id)}`, {
      headers: { authorization: `Bearer ${this.#token}` },
      ...(this.#rejectRedirects ? { redirect: "error" as const } : {}),
      signal: AbortSignal.timeout(TRANSFER_TIMEOUT_MS),
    });
    if (!response.ok) throw new Error(`GET /v1/transfers/${id}: HTTP ${response.status}`);
    return Buffer.from(await response.arrayBuffer());
  }

  start(deliver: (item: InboxItem) => Promise<InboundOutcome>): void {
    if (this.#session !== null) return;
    const session: InboxSession = { stopped: false, abort: null };
    this.#session = session;
    void this.#inboxLoop(session, deliver);
  }

  async stop(): Promise<void> {
    const session = this.#session;
    if (session === null) return;
    this.#session = null;
    session.stopped = true;
    session.abort?.abort();
  }

  async #inboxLoop(session: InboxSession, deliver: (item: InboxItem) => Promise<InboundOutcome>): Promise<void> {
    let backoff = 1000;
    while (!session.stopped) {
      const abort = new AbortController();
      session.abort = abort;
      try {
        if (!this.#eventOnly) await this.#putHandles();
        const synced = await this.#queueSubscriptions();
        if (!synced.ok && synced.error === "router_unavailable") throw new Error(synced.message);
        // A refused set is the connector's problem to fix; it must not keep messages from flowing.
        if (!synced.ok) log("error", "router.subscriptions_refused", { error: synced.error, message: synced.message });
        const response = await this.#request("GET", "/v1/inbox", undefined, abort.signal);
        if (!response.ok || response.body === null) throw new Error(`GET /v1/inbox: HTTP ${response.status}`);
        log("info", "router.connected", { router: this.#name, url: this.#url });
        backoff = 1000;
        await this.#readEvents(response.body, deliver);
        log("warn", "router.disconnected", { router: this.#name, reason: "stream ended" });
      } catch (error) {
        if (session.stopped) return;
        log("warn", "router.disconnected", { router: this.#name, error: errorMessage(error) });
      }
      if (session.stopped) return;
      await sleep(backoff);
      backoff = Math.min(backoff * 2, 30_000);
    }
  }

  async #readEvents(
    body: ReadableStream<Uint8Array>,
    deliver: (item: InboxItem) => Promise<InboundOutcome>,
  ): Promise<void> {
    const decoder = new TextDecoder();
    let buffer = "";
    for await (const chunk of body) {
      buffer += decoder.decode(chunk, { stream: true });
      let boundary = buffer.indexOf("\n\n");
      while (boundary >= 0) {
        const event = buffer.slice(0, boundary);
        buffer = buffer.slice(boundary + 2);
        boundary = buffer.indexOf("\n\n");
        const data = event
          .split("\n")
          .filter((line) => line.startsWith("data: "))
          .map((line) => line.slice(6))
          .join("\n");
        if (data.length === 0) continue;
        let value: unknown;
        let item: InboxItem;
        try {
          value = JSON.parse(data);
          item = decodeInboxItem(value);
        } catch (error) {
          // Rejected if it has an ID: unacked, it would be offered again forever and block its
          // recipient or subscription. Without one there is nothing to ack; the stream stays up.
          const id =
            typeof value === "object" && value !== null && "id" in value && typeof value.id === "string" ? value.id : null;
          log("error", "router.undecodable_item", { id, error: errorMessage(error) });
          if (id !== null) void this.#ack(id, { kind: "rejected", reason: "undecodable" });
          continue;
        }
        // Items are handled concurrently across recipients and subscriptions; the router sends one per each at a time.
        void this.#handle(item, deliver);
      }
    }
  }

  async #handle(message: InboxItem, deliver: (item: InboxItem) => Promise<InboundOutcome>): Promise<void> {
    let outcome: InboundOutcome;
    try {
      outcome = await deliver(message);
    } catch (error) {
      outcome = { kind: "hold", reason: errorMessage(error) };
    }
    await this.#ack(message.id, outcome);
  }

  async #ack(id: string, outcome: InboundOutcome): Promise<void> {
    const body = outcome.kind === "delivered" ? { outcome: "delivered" } : { outcome: outcome.kind, reason: outcome.reason };
    try {
      const response = await this.#request("POST", `/v1/messages/${encodeURIComponent(id)}/ack`, body);
      if (!response.ok) log("warn", "router.ack_failed", { id, status: response.status });
    } catch (error) {
      // Unacked messages are offered again after the router's ack timeout.
      log("warn", "router.ack_failed", { id, error: errorMessage(error) });
    }
  }
}
