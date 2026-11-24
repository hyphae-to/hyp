// The plugins' event store (SPEC.md section 13.4): a RouterCore on `<state dir>/local.db`, so plugin
// events get the router's storage, idempotency, coalescing, retention, pending cap and ack/hold
// semantics. Each (plugin, target) is one topic with one subscription; its publisher is
// `plugin:<name>`. Topic and subscription IDs are derived from the names, so they survive restarts.
import { createHash } from "node:crypto";
import type { PluginConfig } from "../config.ts";
import { errorMessage, log } from "../log.ts";
import { RouterCore } from "../router/core.ts";
import { DEFAULT_EVENT_LIMITS, type Publisher, type SubscriptionSpec } from "../router/events.ts";
import type { InboundEventBatch, InboundOutcome } from "../router/types.ts";
import type { NackError } from "./protocol.ts";

/** The connector ID the local store's subscriptions and batches belong to. */
const LOCAL_CONNECTOR = "local";
const TICK_MS = 1_000;

export const pluginPublisher = (plugin: string): string => `plugin:${plugin}`;

const digest = (plugin: string, target: string): string =>
  createHash("sha256").update(`t3-mesh plugin target\0${plugin}\0${target}`).digest("hex");
/** Plugin and target names may share characters with a separator, so the topic is a digest. */
const topicOf = (plugin: string, target: string): string => `plugin-${digest(plugin, target).slice(0, 32)}`;
const subscriptionIdOf = (plugin: string, target: string): string => {
  const hex = digest(plugin, target);
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
};

export interface TargetRef {
  readonly plugin: string;
  readonly target: string;
}

export type StoreOutcome =
  | { readonly ok: true; readonly status: "stored" | "duplicate" }
  | { readonly ok: false; readonly error: NackError; readonly message: string };

export interface TargetBacklog extends TargetRef {
  readonly pending: number;
  readonly oldestOpenedAt: number;
}

export interface LocalEventsOptions {
  readonly dbPath: string;
  readonly plugins: readonly PluginConfig[];
  readonly now?: () => number;
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

export class LocalEvents {
  readonly #core: RouterCore;
  readonly #topics = new Map<string, string>();
  readonly #routes = new Map<string, TargetRef>();
  #timer: NodeJS.Timeout | null = null;
  #detach: (() => void) | null = null;

  constructor(options: LocalEventsOptions) {
    const topics = new Map<string, string[]>();
    const specs: SubscriptionSpec[] = [];
    for (const plugin of options.plugins) {
      for (const target of plugin.targets) {
        const topic = topicOf(plugin.name, target.name);
        const id = subscriptionIdOf(plugin.name, target.name);
        topics.set(topic, [pluginPublisher(plugin.name)]);
        this.#topics.set(`${plugin.name}/${target.name}`, topic);
        this.#routes.set(id, { plugin: plugin.name, target: target.name });
        specs.push({
          id,
          topic,
          filters: [],
          coalesceSeconds: target.coalesceSeconds,
          maxBatchAgeMs: target.maxWaitSeconds * 1000,
          maxBatchesPerHour: target.wakesPerHour,
        });
      }
    }
    this.#core = new RouterCore({
      dbPath: options.dbPath,
      onDeferredError: (error) => log("error", "plugin.store_failed", { operation: "offer", error: errorMessage(error) }),
      topics,
      // Retention 24 h, 100 pending batches and 20 events per batch, as at the router (SPEC.md section 12.5).
      eventLimits: DEFAULT_EVENT_LIMITS,
      ...(options.now === undefined ? {} : { now: options.now }),
    });
    // Replaces the stored set: targets removed from config.json lose their batches.
    const synced = this.#core.events.setSubscriptions(LOCAL_CONNECTOR, specs);
    if (!synced.ok) throw new Error(`plugin targets: ${synced.message}`);
  }

  /** Stores one plugin event for a target; `publisher` is stamped, overwriting the plugin's value. */
  publish(plugin: string, to: string, value: unknown): StoreOutcome {
    const topic = this.#topics.get(`${plugin}/${to}`);
    if (topic === undefined) return { ok: false, error: "unknown_target", message: `plugin ${plugin} has no target ${JSON.stringify(to.slice(0, 64))}` };
    const publisher: Publisher = { id: pluginPublisher(plugin), topics: new Set([topic]) };
    const event = isRecord(value) ? { ...value, publisher: publisher.id } : value;
    try {
      const known =
        isRecord(event) &&
        typeof event["source"] === "string" &&
        typeof event["id"] === "string" &&
        this.#core.events.isKnownEvent(topic, publisher.id, event["source"], event["id"]);
      const result = this.#core.events.publish(publisher, topic, event);
      if (result.ok) return { ok: true, status: known ? "duplicate" : "stored" };
      switch (result.error) {
        case "invalid_event":
        case "too_large":
        case "id_conflict":
          return { ok: false, error: result.error, message: result.message };
        case "unknown_topic":
        case "not_granted":
          // Every target's topic is configured with its plugin as publisher.
          return { ok: false, error: "unavailable", message: `internal: ${result.error}` };
      }
    } catch (error) {
      return { ok: false, error: "unavailable", message: `the event store failed: ${errorMessage(error)}` };
    }
  }

  /** The (plugin, target) a batch's subscription stands for. */
  route(subscriptionId: string): TargetRef | undefined {
    return this.#routes.get(subscriptionId);
  }

  /** Targets with pending (closed, undelivered) batches. */
  backlog(): TargetBacklog[] {
    return this.#core.events.pendingSummary(LOCAL_CONNECTOR).flatMap((summary) => {
      const route = this.#routes.get(summary.subscriptionId);
      return route === undefined ? [] : [{ ...route, pending: summary.pending, oldestOpenedAt: summary.oldestOpenedAt }];
    });
  }

  /** Closes windows and expires batches every second, whether or not batches are being delivered. */
  start(): void {
    if (this.#timer !== null) return;
    this.#timer = setInterval(() => this.#guard("tick", () => this.tick()), TICK_MS);
  }

  /** Runs a store operation from a timer or callback: a SQLite error is logged and retried later, never thrown. */
  #guard(operation: string, body: () => void): void {
    try {
      body();
    } catch (error) {
      log("error", "plugin.store_failed", { operation, error: errorMessage(error) });
    }
  }

  tick(): void {
    this.#core.tick();
  }

  /** Starts offering due batches; each is acked with `deliver`'s outcome. A no-op if attached. */
  attach(deliver: (batch: InboundEventBatch) => Promise<InboundOutcome>): void {
    if (this.#detach !== null) return;
    this.#detach = this.#core.attach(LOCAL_CONNECTOR, (item) => {
      if (item.kind !== "event") return;
      void deliver(item)
        .catch((error: unknown): InboundOutcome => ({ kind: "hold", reason: errorMessage(error) }))
        .then((outcome) =>
          // Unrecorded, the batch stays pending and is offered again after the ack timeout.
          this.#guard("ack", () => this.#core.ack(LOCAL_CONNECTOR, item.id, outcome)),
        );
    });
  }

  /** Stops offering; batches wait. Answers to batches already offered are still recorded. */
  detach(): void {
    this.#detach?.();
    this.#detach = null;
  }

  get attached(): boolean {
    return this.#detach !== null;
  }

  close(): void {
    this.detach();
    if (this.#timer !== null) clearInterval(this.#timer);
    this.#timer = null;
    this.#core.close();
  }
}
