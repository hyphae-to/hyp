// The plugins' event store (SPEC.md section 13.4): an EventRouter directly on a shared SQLite
// connection (state.sqlite) or standalone dbPath, so plugin events get the router's storage,
// idempotency, coalescing, retention, pending cap and ack/hold semantics without creating unused
// router tables or a separate local.db file. Each (plugin, target) is one topic with one
// subscription; its publisher is `plugin:<name>`. Topic and subscription IDs are derived from
// the names, so they survive restarts.
import { createHash } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import type { PluginConfig } from "./types.ts";
import { errorMessage, log } from "../log.ts";
import { DEFAULT_EVENT_LIMITS, EventRouter, type Publisher, type SubscriptionSpec } from "../router/events.ts";
import type { InboundEventBatch, InboundOutcome } from "../router/types.ts";
import type { NackError } from "./protocol.ts";

/** The connector ID the local store's subscriptions and batches belong to. */
const LOCAL_CONNECTOR = "local";
const BUSY_TIMEOUT_MS = 2_000;
const DEFAULT_HOLD_RETRY_MS = 30_000;
const DEFAULT_ACK_TIMEOUT_MS = 60_000;
const MAX_TICK_SLEEP_MS = 60 * 60 * 1000;
const TICK_ERROR_RETRY_MS = 1_000;

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

export type LocalEventsOptions = (
  | {
      /** Caller-owned shared SQLite connection (e.g. `state.database()`); never closed by `LocalEvents.close()`. */
      readonly db: DatabaseSync;
      readonly dbPath?: undefined;
    }
  | {
      readonly db?: undefined;
      /** Standalone SQLite path (e.g. for direct unit tests); opened and closed by `LocalEvents`. */
      readonly dbPath: string;
    }
) & {
  readonly plugins: readonly PluginConfig[];
  readonly now?: () => number;
  readonly holdRetryMs?: number;
  readonly ackTimeoutMs?: number;
};

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

function enableWal(db: DatabaseSync): void {
  const deadline = Date.now() + BUSY_TIMEOUT_MS;
  for (;;) {
    try {
      const row = db.prepare("PRAGMA journal_mode").get() as { journal_mode?: unknown } | undefined;
      if (typeof row?.journal_mode === "string" && row.journal_mode.toLowerCase() === "wal") return;
      db.exec("PRAGMA journal_mode = WAL");
      return;
    } catch (error) {
      if (Date.now() >= deadline || !(error instanceof Error) || !/database is locked/.test(error.message)) throw error;
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 25);
    }
  }
}

export class LocalEvents {
  readonly #db: DatabaseSync;
  readonly #ownsDb: boolean;
  readonly #events: EventRouter;
  readonly #now: () => number;
  readonly #ackTimeoutMs: number;
  readonly #topics = new Map<string, string>();
  readonly #routes = new Map<string, TargetRef>();
  readonly #inFlight = new Map<string, number>();
  #deliver: ((batch: InboundEventBatch) => Promise<InboundOutcome>) | null = null;
  #timer: NodeJS.Timeout | null = null;
  #started = false;
  #ticking = false;
  #closed = false;

  constructor(options: LocalEventsOptions) {
    this.#now = options.now ?? Date.now;
    this.#ackTimeoutMs = options.ackTimeoutMs ?? DEFAULT_ACK_TIMEOUT_MS;

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

    if (options.db !== undefined) {
      this.#db = options.db;
      this.#ownsDb = false;
    } else if (options.dbPath !== undefined) {
      this.#db = new DatabaseSync(options.dbPath);
      this.#ownsDb = true;
      this.#db.exec(`PRAGMA busy_timeout = ${BUSY_TIMEOUT_MS};`);
      if (options.dbPath !== ":memory:") enableWal(this.#db);
    } else {
      throw new Error("LocalEvents requires either db or dbPath");
    }

    try {
      this.#db.exec("PRAGMA foreign_keys = ON;");
      this.#db.exec("BEGIN IMMEDIATE");
      try {
        EventRouter.migrate(this.#db);
        this.#db.exec("COMMIT");
      } catch (error) {
        this.#db.exec("ROLLBACK");
        throw error;
      }

      this.#events = new EventRouter(this.#db, {
        topics,
        // Retention 24 h, 100 pending batches and 20 events per batch, as at the router (SPEC.md section 12.5).
        limits: DEFAULT_EVENT_LIMITS,
        holdRetryMs: options.holdRetryMs ?? DEFAULT_HOLD_RETRY_MS,
        now: this.#now,
        audit: () => {},
        ready: () => this.#drain(),
        inFlight: (_connectorId, batchId) => this.#inFlight.has(batchId),
        onScheduleChange: () => this.#reschedule(),
      });
      // Replaces the stored set: targets removed from config.json lose their batches.
      const synced = this.#events.setSubscriptions(LOCAL_CONNECTOR, specs);
      if (!synced.ok) throw new Error(`plugin targets: ${synced.message}`);
    } catch (error) {
      if (this.#ownsDb) this.#db.close();
      throw error;
    }
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
        this.#events.isKnownEvent(topic, publisher.id, event["source"], event["id"]);
      const result = this.#events.publish(publisher, topic, event);
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
    return this.#events.pendingSummary(LOCAL_CONNECTOR).flatMap((summary) => {
      const route = this.#routes.get(summary.subscriptionId);
      return route === undefined ? [] : [{ ...route, pending: summary.pending, oldestOpenedAt: summary.oldestOpenedAt }];
    });
  }

  /** Earliest timestamp (ms) when a batch closes, expires, comes off hold/wake-cap, or times out in flight; null when idle. */
  nextDeadlineMs(): number | null {
    let earliest = this.#events.nextDeadlineMs();
    for (const offeredAt of this.#inFlight.values()) {
      const deadline = offeredAt + this.#ackTimeoutMs;
      earliest = earliest === null ? deadline : Math.min(earliest, deadline);
    }
    return earliest;
  }

  /** Arms exact deadline scheduling to close windows, expire batches, and retry timed-out deliveries. */
  start(): void {
    if (this.#started || this.#closed) return;
    this.#started = true;
    this.#reschedule();
  }

  /** Runs a store operation from a timer or callback: a SQLite error is logged and retried later, never thrown. */
  #guard(operation: string, body: () => void): void {
    try {
      body();
    } catch (error) {
      log("error", "plugin.store_failed", { operation, error: errorMessage(error) });
    }
  }

  #reschedule(): void {
    if (!this.#started || this.#closed || this.#ticking) return;
    if (this.#timer !== null) {
      clearTimeout(this.#timer);
      this.#timer = null;
    }
    let nextAt: number | null;
    try {
      nextAt = this.nextDeadlineMs();
    } catch (error) {
      log("error", "plugin.store_failed", { operation: "schedule", error: errorMessage(error) });
      this.#timer = setTimeout(() => {
        this.#timer = null;
        this.#runTick();
      }, TICK_ERROR_RETRY_MS);
      return;
    }
    if (nextAt === null) return;
    const delayMs = Math.min(MAX_TICK_SLEEP_MS, Math.max(1, nextAt - this.#now()));
    this.#timer = setTimeout(() => {
      this.#timer = null;
      this.#runTick();
    }, delayMs);
  }

  #runTick(): void {
    if (this.#closed) return;
    this.#ticking = true;
    let failed = false;
    try {
      this.tick();
    } catch (error) {
      failed = true;
      log("error", "plugin.store_failed", { operation: "tick", error: errorMessage(error) });
    } finally {
      this.#ticking = false;
    }
    if (this.#closed) return;
    if (failed) {
      this.#timer = setTimeout(() => {
        this.#timer = null;
        this.#runTick();
      }, TICK_ERROR_RETRY_MS);
    } else {
      this.#reschedule();
    }
  }

  tick(): void {
    this.#events.tick();
    const now = this.#now();
    for (const [id, offeredAt] of this.#inFlight) {
      if (now - offeredAt >= this.#ackTimeoutMs) this.#inFlight.delete(id);
    }
    this.#drain();
    this.#reschedule();
  }

  #drain(): void {
    const deliver = this.#deliver;
    if (deliver === null || this.#closed) return;
    const now = this.#now();
    let offered = false;
    for (const batch of this.#events.dueBatches(LOCAL_CONNECTOR, (id) => this.#inFlight.has(id))) {
      this.#inFlight.set(batch.id, now);
      offered = true;
      void deliver(batch)
        .catch((error: unknown): InboundOutcome => ({ kind: "hold", reason: errorMessage(error) }))
        .then((outcome) => {
          if (this.#closed) return;
          // Unrecorded (SQLite error), the batch stays pending and is offered again after the ack timeout.
          this.#guard("ack", () => {
            const settled = this.#events.ack(LOCAL_CONNECTOR, batch.id, outcome);
            this.#inFlight.delete(batch.id);
            if (settled) this.#drain();
            this.#reschedule();
          });
        });
    }
    if (offered) this.#reschedule();
  }

  /** Starts offering due batches; each is acked with `deliver`'s outcome. A no-op if attached. */
  attach(deliver: (batch: InboundEventBatch) => Promise<InboundOutcome>): void {
    if (this.#deliver !== null || this.#closed) return;
    this.#deliver = deliver;
    queueMicrotask(() => {
      if (this.#deliver !== deliver || this.#closed) return;
      this.#guard("offer", () => {
        this.#drain();
        this.#reschedule();
      });
    });
  }

  /** Stops offering; batches wait. Answers to batches already offered are still recorded. */
  detach(): void {
    this.#deliver = null;
    this.#inFlight.clear();
    this.#reschedule();
  }

  get attached(): boolean {
    return this.#deliver !== null;
  }

  close(): void {
    if (this.#closed) return;
    this.#closed = true;
    this.#deliver = null;
    this.#inFlight.clear();
    if (this.#timer !== null) clearTimeout(this.#timer);
    this.#timer = null;
    this.#started = false;
    if (this.#ownsDb) this.#db.close();
  }
}
