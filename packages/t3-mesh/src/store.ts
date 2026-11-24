// Enrolled threads, event subscriptions and plugin target handoffs of this connector, persisted as
// JSON in the state dir.
import { readFileSync, renameSync, writeFileSync } from "node:fs";
import * as Schema from "effect/Schema";

const Enrollment = Schema.Struct({
  threadId: Schema.String,
  handle: Schema.String,
  joinedAt: Schema.String,
});
export type Enrollment = typeof Enrollment.Type;

export const SubscriptionMode = Schema.Literals(["queue", "interrupt"]);
export type SubscriptionMode = typeof SubscriptionMode.Type;

/** An event subscription of a thread (SPEC.md section 12.3). The router gets it without `threadId`. */
const Subscription = Schema.Struct({
  id: Schema.String,
  threadId: Schema.String,
  topic: Schema.String,
  /** Absent for the primary router, including state written before extra routers existed. */
  router: Schema.optionalKey(Schema.String),
  filters: Schema.Array(Schema.Unknown),
  coalesceSeconds: Schema.Number,
  /** Absent on legacy subscriptions, which keep the connector-wide delivery behavior. */
  mode: Schema.optionalKey(SubscriptionMode),
  createdAt: Schema.String,
  /**
   * The mesh_subscribe key, unique per thread (e.g. `assignment:owner/repo#123`), so a resumed builder
   * updates its subscription instead of adding another. Absent only on subscriptions stored before
   * keys were required.
   */
  key: Schema.optionalKey(Schema.String),
  updatedAt: Schema.optionalKey(Schema.String),
});
export type Subscription = typeof Subscription.Type;

/** A plugin target moved off its configured thread with mesh_plugin_handoff (SPEC.md section 13.5). */
const PluginTargetOverride = Schema.Struct({
  plugin: Schema.String,
  target: Schema.String,
  threadId: Schema.String,
  /** The target's threadId in config.json when the handoff was made; a record made under another is stale. */
  configuredThreadId: Schema.String,
  setAt: Schema.String,
  /** The thread that made the handoff. */
  setBy: Schema.String,
});
export type PluginTargetOverride = typeof PluginTargetOverride.Type;
/** As stored: records from before `configuredThreadId` are dropped on load. */
const StoredPluginTarget = Schema.Struct({ ...PluginTargetOverride.fields, configuredThreadId: Schema.optionalKey(Schema.String) });

const StateFile = Schema.Struct({
  version: Schema.Literal(1),
  enrollments: Schema.Array(Enrollment),
  // Absent in state files written before subscriptions existed.
  subscriptions: Schema.optionalKey(Schema.Array(Subscription)),
  // Kept outside the legacy array: old connectors ignore this key instead of routing it on primary.
  eventRouterSubscriptions: Schema.optionalKey(Schema.Array(Schema.Struct({ ...Subscription.fields, router: Schema.String }))),
  // Absent in state files written before plugins existed.
  pluginTargets: Schema.optionalKey(Schema.Array(StoredPluginTarget)),
});
const decodeState = Schema.decodeUnknownSync(StateFile);

export type JoinResult =
  | { readonly ok: true; readonly previousHandle: string | null }
  | { readonly ok: false; readonly code: "handle_taken" };

export class EnrollmentStore {
  readonly #path: string;
  readonly #byThread = new Map<string, Enrollment>();
  readonly #subscriptions = new Map<string, Subscription>();
  /** By `<plugin>/<target>` (neither name can contain "/"). */
  readonly #pluginTargets = new Map<string, PluginTargetOverride>();

  private constructor(
    path: string,
    enrollments: ReadonlyArray<Enrollment>,
    subscriptions: ReadonlyArray<Subscription>,
    pluginTargets: ReadonlyArray<PluginTargetOverride>,
  ) {
    this.#path = path;
    for (const enrollment of enrollments) this.#byThread.set(enrollment.threadId, enrollment);
    for (const subscription of subscriptions) this.#subscriptions.set(subscription.id, subscription);
    for (const override of pluginTargets) this.#pluginTargets.set(`${override.plugin}/${override.target}`, override);
  }

  static load(path: string): EnrollmentStore {
    let text: string;
    try {
      text = readFileSync(path, "utf8");
    } catch (error) {
      if (error instanceof Error && "code" in error && error.code === "ENOENT") return new EnrollmentStore(path, [], [], []);
      throw error;
    }
    const state = decodeState(JSON.parse(text));
    const pluginTargets = (state.pluginTargets ?? []).flatMap(({ configuredThreadId, ...rest }) =>
      configuredThreadId === undefined ? [] : [{ ...rest, configuredThreadId }],
    );
    return new EnrollmentStore(path, state.enrollments, [...(state.subscriptions ?? []), ...(state.eventRouterSubscriptions ?? [])], pluginTargets);
  }

  list(): Enrollment[] {
    return [...this.#byThread.values()];
  }

  handles(): string[] {
    return this.list().map((enrollment) => enrollment.handle);
  }

  byThread(threadId: string): Enrollment | undefined {
    return this.#byThread.get(threadId);
  }

  byHandle(handle: string): Enrollment | undefined {
    return this.list().find((enrollment) => enrollment.handle === handle);
  }

  join(threadId: string, handle: string): JoinResult {
    const holder = this.byHandle(handle);
    if (holder !== undefined && holder.threadId !== threadId) return { ok: false, code: "handle_taken" };
    const previous = this.#byThread.get(threadId);
    this.#byThread.set(threadId, { threadId, handle, joinedAt: previous?.joinedAt ?? new Date().toISOString() });
    this.#save();
    return { ok: true, previousHandle: previous !== undefined && previous.handle !== handle ? previous.handle : null };
  }

  leave(threadId: string): boolean {
    const removed = this.#byThread.delete(threadId);
    if (removed) this.#save();
    return removed;
  }

  /** Removes enrollments matching the predicate; returns the removed ones. */
  prune(shouldRemove: (enrollment: Enrollment) => boolean): Enrollment[] {
    const removed = this.list().filter(shouldRemove);
    for (const enrollment of removed) this.#byThread.delete(enrollment.threadId);
    if (removed.length > 0) this.#save();
    return removed;
  }

  // ---- subscriptions ----

  subscriptions(): Subscription[] {
    return [...this.#subscriptions.values()];
  }

  subscription(id: string): Subscription | undefined {
    return this.#subscriptions.get(id);
  }

  subscriptionsOf(threadId: string): Subscription[] {
    return this.subscriptions().filter((subscription) => subscription.threadId === threadId);
  }

  addSubscription(subscription: Subscription): void {
    this.#subscriptions.set(subscription.id, subscription);
    this.#save();
  }

  /** Removes a subscription only if it belongs to the thread. */
  removeSubscription(threadId: string, id: string): boolean {
    if (this.#subscriptions.get(id)?.threadId !== threadId) return false;
    this.#subscriptions.delete(id);
    this.#save();
    return true;
  }

  /** Removes subscriptions matching the predicate; returns the removed ones. */
  pruneSubscriptions(shouldRemove: (subscription: Subscription) => boolean): Subscription[] {
    const removed = this.subscriptions().filter(shouldRemove);
    for (const subscription of removed) this.#subscriptions.delete(subscription.id);
    if (removed.length > 0) this.#save();
    return removed;
  }

  // ---- plugin targets ----

  /** The handoff in force for a plugin target, if any. */
  pluginTarget(plugin: string, target: string): PluginTargetOverride | undefined {
    return this.#pluginTargets.get(`${plugin}/${target}`);
  }

  pluginTargets(): PluginTargetOverride[] {
    return [...this.#pluginTargets.values()];
  }

  setPluginTarget(override: PluginTargetOverride): void {
    this.#pluginTargets.set(`${override.plugin}/${override.target}`, override);
    this.#save();
  }

  removePluginTarget(plugin: string, target: string): boolean {
    const removed = this.#pluginTargets.delete(`${plugin}/${target}`);
    if (removed) this.#save();
    return removed;
  }

  #save(): void {
    const temp = `${this.#path}.tmp`;
    const subscriptions = this.subscriptions();
    const extra = subscriptions.filter((subscription) => (subscription.router ?? "primary") !== "primary");
    const state = {
      version: 1,
      enrollments: this.list(),
      subscriptions: subscriptions.filter((subscription) => (subscription.router ?? "primary") === "primary")
        .map(({ router: _router, ...subscription }) => subscription),
      ...(extra.length === 0 ? {} : { eventRouterSubscriptions: extra }),
      ...(this.#pluginTargets.size === 0 ? {} : { pluginTargets: [...this.#pluginTargets.values()] }),
    };
    writeFileSync(temp, JSON.stringify(state, null, 2) + "\n", { mode: 0o600 });
    renameSync(temp, this.#path);
  }
}
