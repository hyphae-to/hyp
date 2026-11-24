// The connector's plugins (SPEC.md section 13): their processes, the local event store, delivery
// while T3 is connected, and backlog status lines to each plugin.
import type { DatabaseSync } from "node:sqlite";
import type { PluginConfig } from "./types.ts";
import { errorMessage, log } from "../log.ts";
import type { InboundEventBatch, InboundOutcome } from "../router/types.ts";
import { LocalEvents, type LocalEventsOptions, type TargetRef } from "./store.ts";
import { PluginProcess, type SupervisorOptions } from "./supervisor.ts";

/** A target's backlog is reported once its oldest pending batch is this old, and then at most this often. */
const STATUS_AFTER_MS = 60_000;
const STATUS_CHECK_MS = 5_000;

export interface PluginsOptions {
  /** Shared SQLite connection (e.g. `state.database()`); never closed by `Plugins.stop()`. */
  readonly db?: DatabaseSync;
  /** Standalone SQLite path (for unit tests); opened and closed by `LocalEvents`. */
  readonly dbPath?: string;
  readonly plugins: readonly PluginConfig[];
  readonly supervisor?: SupervisorOptions;
  readonly statusAfterMs?: number;
  readonly statusCheckMs?: number;
  readonly now?: () => number;
}

interface StatusState {
  readonly ref: TargetRef;
  lastSentAt: number;
  /** A backlog was reported and its clearing not yet. */
  reported: boolean;
}

export class Plugins {
  readonly #events: LocalEvents;
  readonly #processes: Map<string, PluginProcess>;
  readonly #statusAfterMs: number;
  readonly #statusCheckMs: number;
  readonly #now: () => number;
  readonly #status = new Map<string, StatusState>();
  #statusTimer: NodeJS.Timeout | null = null;

  constructor(options: PluginsOptions) {
    this.#now = options.now ?? Date.now;
    let storeOptions: LocalEventsOptions;
    if (options.db !== undefined) {
      storeOptions = { db: options.db, plugins: options.plugins, now: this.#now };
    } else if (options.dbPath !== undefined) {
      storeOptions = { dbPath: options.dbPath, plugins: options.plugins, now: this.#now };
    } else {
      throw new Error("Plugins requires either db or dbPath");
    }
    this.#events = new LocalEvents(storeOptions);
    this.#processes = new Map(
      options.plugins.map((plugin) => [
        plugin.name,
        new PluginProcess(plugin, (to, event) => this.#events.publish(plugin.name, to, event), options.supervisor),
      ]),
    );
    this.#statusAfterMs = options.statusAfterMs ?? STATUS_AFTER_MS;
    this.#statusCheckMs = options.statusCheckMs ?? STATUS_CHECK_MS;
  }

  start(): void {
    this.#events.start();
    for (const runner of this.#processes.values()) runner.start();
    this.#statusTimer = setInterval(() => {
      try {
        this.reportStatus();
      } catch (error) {
        log("error", "plugin.store_failed", { operation: "status", error: errorMessage(error) });
      }
    }, this.#statusCheckMs);
  }

  /** The (plugin, target) of a batch. */
  route(subscriptionId: string): TargetRef | undefined {
    return this.#events.route(subscriptionId);
  }

  /** Sends an outbound request (e.g. `post`) to a supervised plugin process over fd 3. */
  async request(
    pluginName: string,
    method: "post",
    target: string,
    params: Readonly<Record<string, unknown>>,
    timeoutMs = 15_000,
  ): Promise<{ ok: true; result: unknown } | { ok: false; error: string }> {
    const runner = this.#processes.get(pluginName);
    if (!runner) return { ok: false, error: `unknown_plugin:${pluginName}` };
    return runner.request(method, target, params, timeoutMs);
  }

  /** Tells the plugin that a stored batch for `ref` was dropped undelivered. */
  reportDeliveryFailed(ref: TargetRef, batch: InboundEventBatch, reason: string): void {
    this.#processes.get(ref.plugin)?.send({
      type: "delivery_failed",
      target: ref.target,
      events: batch.events.map((event) => ({ id: event.id, source: event.source })),
      reason,
    });
  }

  /** Delivers batches through `deliver` until detached (while connected to T3). */
  attach(deliver: (batch: InboundEventBatch) => Promise<InboundOutcome>): void {
    this.#events.attach(deliver);
  }

  detach(): void {
    this.#events.detach();
  }

  /**
   * Tells each plugin about a target whose oldest pending batch is older than a minute, at most once a
   * minute per target, and once more with `pending: 0` when the backlog has cleared.
   */
  reportStatus(): void {
    const now = this.#now();
    const t3Connected = this.#events.attached;
    const backlog = new Map(this.#events.backlog().map((entry) => [`${entry.plugin}/${entry.target}`, entry]));
    for (const [key, state] of this.#status) {
      if (!state.reported || backlog.has(key)) continue;
      const cleared = { type: "status", target: state.ref.target, pending: 0, oldestAgeSeconds: 0, t3Connected } as const;
      if (this.#processes.get(state.ref.plugin)?.send(cleared) === true) state.reported = false;
    }
    for (const [key, entry] of backlog) {
      const ageMs = now - entry.oldestOpenedAt;
      const state = this.#status.get(key) ?? { ref: entry, lastSentAt: Number.NEGATIVE_INFINITY, reported: false };
      this.#status.set(key, state);
      if (ageMs < this.#statusAfterMs || now - state.lastSentAt < this.#statusAfterMs) continue;
      const sent = this.#processes.get(entry.plugin)?.send({
        type: "status",
        target: entry.target,
        pending: entry.pending,
        oldestAgeSeconds: Math.floor(ageMs / 1000),
        t3Connected,
      });
      if (sent === true) {
        state.lastSentAt = now;
        state.reported = true;
      }
    }
  }

  /** Stops every plugin (SIGTERM, then SIGKILL) and closes the store. */
  async stop(): Promise<void> {
    if (this.#statusTimer !== null) clearInterval(this.#statusTimer);
    this.#statusTimer = null;
    await Promise.all([...this.#processes.values()].map((runner) => runner.stop()));
    this.#events.close();
  }
}
