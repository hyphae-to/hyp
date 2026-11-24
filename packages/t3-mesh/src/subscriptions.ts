// A connector's event subscriptions (SPEC.md sections 12.3-12.4): the agent tools' logic, kept in
// state.json and mirrored per router. Each link has its own queue, so an unavailable event router
// never blocks primary tools or another link's sync.
import { randomUUID } from "node:crypto";
import * as Schema from "effect/Schema";
import { toolError, type ToolResponse } from "./ipc.ts";
import { builderFilters, canonicalJson } from "./builderFilters.ts";
import { errorMessage, log } from "./log.ts";
import { isTopic } from "./router/cloudevent.ts";
import { checkFilters } from "./router/filter.ts";
import type { RouterLink, SubscriptionSpec, SubscriptionSync } from "./router/types.ts";
import type { EnrollmentStore, Subscription, SubscriptionMode } from "./store.ts";
import { optsOutOfAutoSettle } from "./tidy.ts";
import {
  DEFAULT_COALESCE_SECONDS,
  MAX_SUBSCRIPTIONS_PER_CONNECTOR,
  MAX_SUBSCRIPTIONS_PER_THREAD,
  SUBSCRIPTION_KEY,
  SubscribeArgs,
  UnsubscribeArgs,
} from "./tools.ts";

const decodeSubscribeArgs = Schema.decodeUnknownOption(SubscribeArgs);
const decodeUnsubscribeArgs = Schema.decodeUnknownOption(UnsubscribeArgs);
const MAX_COALESCE_SECONDS = 600;

/** Turns T3's auto-settle off or on for a thread; resolves to why it failed, or null. */
export type SetAutoSettle = (threadId: string, enabled: boolean, subscriptionId: string) => Promise<string | null>;

/** Router filters and batching are independent of local delivery mode. */
const routerView = (subscription: Subscription): SubscriptionSpec => ({
  id: subscription.id,
  topic: subscription.topic,
  filters: subscription.filters,
  coalesceSeconds: subscription.coalesceSeconds,
});

export class Subscriptions {
  readonly #store: EnrollmentStore;
  readonly #routers: ReadonlyMap<string, RouterLink>;
  readonly #changes = new Map<string, Promise<unknown>>();
  /** Reserve keys across queues while a new subscription is awaiting its router's acceptance. */
  readonly #pending = new Map<string, { router: string; count: number }>();
  /** Capacity reserved only by new subscriptions actively awaiting their router response. */
  readonly #creating = new Map<string, string>();
  /** The last PUT failed, so the router may hold another set than the stored one; see retrySync. */
  readonly #outOfSync = new Set<string>();

  constructor(store: EnrollmentStore, router: RouterLink, eventRouters: ReadonlyMap<string, RouterLink> = new Map()) {
    this.#store = store;
    this.#routers = new Map([["primary", router], ...eventRouters]);
  }

  /** A router can only deliver subscriptions belonging to its own link. */
  owns(subscriptionId: string, router: string): boolean {
    const subscription = this.#store.subscription(subscriptionId);
    return subscription !== undefined && (subscription.router ?? "primary") === router;
  }

  /** The thread a subscription delivers into. */
  threadOf(subscriptionId: string): string | undefined {
    return this.#store.subscription(subscriptionId)?.threadId;
  }

  modeOf(subscriptionId: string): SubscriptionMode | undefined {
    return this.#store.subscription(subscriptionId)?.mode;
  }

  /** The key of a subscription; undefined only for subscriptions made before keys were required. */
  keyOf(subscriptionId: string): string | undefined {
    return this.#store.subscription(subscriptionId)?.key;
  }

  /** Keys of a thread's subscriptions. */
  keysOf(threadId: string): string[] {
    return this.#store.subscriptionsOf(threadId).flatMap((subscription) => (subscription.key === undefined ? [] : [subscription.key]));
  }

  /** IDs of a thread's subscriptions that opt it out of auto-settlement. */
  protectedIdsOf(threadId: string): string[] {
    return this.#store
      .subscriptionsOf(threadId)
      .flatMap((subscription) => (optsOutOfAutoSettle(subscription.key) ? [subscription.id] : []));
  }

  count(): number {
    return this.#store.subscriptions().length;
  }

  /** Sends the stored set; the router link keeps it and sends it again on reconnect. */
  sync(router?: string): Promise<void> {
    return Promise.all((router === undefined ? [...this.#routers.keys()] : [router])
      .map((name) => this.#change(name, () => this.#sync(name)))).then(() => undefined);
  }

  /** Retry each failed link independently; the inbox reconnect also replays its desired set. */
  retrySync(): Promise<void> {
    return Promise.all([...this.#outOfSync].map((router) =>
      this.#change(router, () => this.#sync(router)),
    )).then(() => undefined);
  }

  async #sync(router: string): Promise<void> {
    const synced = await this.#put(router, null);
    if (!synced.ok) log("warn", "subscriptions.sync_failed", { router, error: synced.error, message: synced.message });
  }

  /**
   * PUTs the stored set, plus `candidate` if given. A stored subscription the router refuses by ID
   * (its filters or limits changed under it) is dropped and the set sent again, so one bad
   * subscription cannot block every later change.
   */
  async #put(router: string, candidate: Subscription | null): Promise<SubscriptionSync> {
    for (;;) {
      // A candidate with a stored ID replaces it (mesh_subscribe updating in place).
      const stored = this.#store.subscriptions().filter((subscription) =>
        (subscription.router ?? "primary") === router && subscription.id !== candidate?.id,
      );
      const set = [...stored, ...(candidate === null ? [] : [candidate])];
      const link = this.#routers.get(router);
      if (link === undefined) return { ok: false, error: "invalid", message: `unknown router ${router}` };
      const synced = await link.setSubscriptions(set.map(routerView)).catch((error): SubscriptionSync => ({
        ok: false, error: "router_unavailable", message: errorMessage(error),
      }));
      if (synced.ok) this.#outOfSync.delete(router);
      else this.#outOfSync.add(router);
      if (synced.ok || synced.id === undefined || synced.id === candidate?.id) return synced;
      const refusedId = synced.id;
      const dropped = this.#store.pruneSubscriptions((subscription) => (subscription.router ?? "primary") === router && subscription.id === refusedId);
      if (dropped.length === 0) return synced;
      log("warn", "subscriptions.refused_dropped", {
        router,
        subscriptions: dropped.map(({ id, threadId, topic }) => ({ id, threadId, topic })),
        error: synced.error,
        message: synced.message,
      });
    }
  }

  /** Drops subscriptions whose thread is gone, archived or deleted, then re-sends the set. */
  prune(isGone: (threadId: string) => boolean, router?: string): Promise<void> {
    const names = router === undefined
      ? new Set([...this.#routers.keys(), ...this.#store.subscriptions().map((sub) => sub.router ?? "primary")])
      : new Set([router]);
    return Promise.all([...names].map((name) => this.#change(name, async () => {
      const removed = this.#store.pruneSubscriptions((subscription) =>
        (subscription.router ?? "primary") === name && isGone(subscription.threadId),
      );
      if (removed.length === 0) return;
      log("info", "subscriptions.pruned", {
        router: name,
        subscriptions: removed.map((subscription) => ({ id: subscription.id, threadId: subscription.threadId })),
      });
      if (this.#routers.has(name)) await this.#sync(name);
    }))).then(() => undefined);
  }

  /**
   * Sends the set with `candidate` (new, or replacing the stored one with its ID). Null when the
   * router accepted it; otherwise the tool error, with the stored set restored at the router.
   */
  async #offer(threadId: string, candidate: Subscription): Promise<ToolResponse | null> {
    const router = candidate.router ?? "primary";
    const synced = await this.#put(router, candidate);
    let refused: ToolResponse | null = null;
    if (!synced.ok) {
      const code =
        synced.error === "invalid_filter" || synced.error === "too_many_subscriptions" || synced.error === "router_unavailable"
          ? synced.error
          : "invalid";
      refused = toolError(code, synced.path === undefined ? synced.message : `${synced.path}: ${synced.message}`);
    } else if (synced.unknownTopics.includes(candidate.topic)) {
      refused = toolError("unknown_topic", `the router has no topic ${candidate.topic}`);
    }
    if (refused === null) return null;
    if (synced.ok || synced.error !== "router_unavailable") this.#creating.delete(candidate.id);
    // Back to the stored set, at the router and in the link's copy that is re-sent on reconnect.
    await this.#sync(router);
    log("warn", "thread.subscribe_refused", { router, threadId, topic: candidate.topic, error: synced.ok ? "unknown_topic" : synced.error });
    return refused;
  }

  /**
   * `mesh_subscribe`: the calling thread's one subscription for `key`. Same topic, canonical
   * filters, coalescing, and mode: unchanged. Other changes keep the ID,
   * so the router keeps its pending batches (SPEC.md 12.5). Two calls never leave two subscriptions.
   */
  subscribe(threadId: string, args: unknown): Promise<ToolResponse> {
    return this.#subscribeWith(threadId, args, false);
  }

  /** `mesh_subscribe` also protects assignment waits and standing roles from T3's idle settlement. */
  async subscribeWithAutoSettle(threadId: string, args: unknown, setAutoSettle: SetAutoSettle): Promise<ToolResponse> {
    const subscribed = await this.subscribe(threadId, args);
    const id = subscribed.ok ? (subscribed.result as { id?: unknown }).id : undefined;
    if (typeof id === "string" && optsOutOfAutoSettle(this.keyOf(id))) {
      const failed = await setAutoSettle(threadId, false, id);
      if (failed !== null && subscribed.ok) {
        return { ok: true, result: { ...(subscribed.result as object), warning: `T3 auto-settle could not be turned off: ${failed}` } };
      }
    }
    return subscribed;
  }

  /**
   * For a fork's target: the thread's subscription for `key` is created only if the thread has none.
   * The check runs in the same queue as `mesh_subscribe`, so one the thread's agent made or changed
   * meanwhile is never overwritten; it is returned as it is, with `outcome: "kept"`. `onHeld` runs
   * inside that queue once the thread holds the key (created or kept), before any other change runs,
   * so a caller can record it durably together with the subscription.
   */
  subscribeIfMissing(threadId: string, args: unknown, onHeld?: () => void): Promise<ToolResponse> {
    return this.#subscribeWith(threadId, args, true, onHeld);
  }

  #subscribeWith(threadId: string, args: unknown, onlyIfMissing: boolean, onHeld?: () => void): Promise<ToolResponse> {
    const parsed = decodeSubscribeArgs(args);
    if (parsed._tag === "None") {
      return Promise.resolve(toolError("invalid", "mesh_subscribe needs {key, topic, filters | template, coalesceSeconds?, mode?}"));
    }
    const { key, topic, filters: rawFilters, template } = parsed.value;
    const router = parsed.value.router ?? "primary";
    if (!this.#routers.has(router)) {
      return Promise.resolve(toolError("unknown_router", `unknown router ${JSON.stringify(router)}; configured routers: ${[...this.#routers.keys()].join(", ")}`));
    }
    const coalesceSeconds = parsed.value.coalesceSeconds ?? DEFAULT_COALESCE_SECONDS;
    if (!SUBSCRIPTION_KEY.test(key)) return Promise.resolve(toolError("invalid", `key must look like assignment:owner/repo#123, got ${JSON.stringify(key)}`));
    if (!isTopic(topic)) return Promise.resolve(toolError("unknown_topic", `no topic ${topic}`));
    if (!Number.isInteger(coalesceSeconds) || coalesceSeconds < 0 || coalesceSeconds > MAX_COALESCE_SECONDS) {
      return Promise.resolve(toolError("invalid", `coalesceSeconds must be an integer from 0 to ${MAX_COALESCE_SECONDS}`));
    }
    if ((rawFilters === undefined) === (template === undefined)) {
      return Promise.resolve(toolError("invalid", "give exactly one of filters or template"));
    }
    let filters: readonly unknown[];
    if (template !== undefined) {
      const built = builderFilters(template);
      if (!built.ok) return Promise.resolve(toolError("invalid", `template: ${built.message}`));
      if (built.key !== key) {
        return Promise.resolve(toolError("invalid", `a builder template for this work is keyed ${built.key}, not ${key}`));
      }
      filters = built.filters;
    } else {
      const checked = checkFilters(rawFilters);
      if (!checked.ok) return Promise.resolve(toolError("invalid_filter", `${checked.path}: ${checked.message}`));
      filters = checked.filters;
    }
    const slot = `${threadId}\0${key}`;
    const pending = this.#pending.get(slot);
    const existing = this.#store.subscriptionsOf(threadId).find((subscription) => subscription.key === key);
    if ((existing !== undefined && (existing.router ?? "primary") !== router) || (pending !== undefined && pending.router !== router)) {
      return Promise.resolve(toolError("invalid", `unsubscribe ${key} first, then subscribe with the new router`));
    }
    this.#pending.set(slot, { router, count: (pending?.count ?? 0) + 1 });
    return this.#change(router, () => this.#subscribe(threadId, key, topic, router, filters, coalesceSeconds, parsed.value.mode, onlyIfMissing, onHeld))
      .finally(() => {
        const held = this.#pending.get(slot);
        if (held !== undefined && held.count > 1) held.count -= 1;
        else this.#pending.delete(slot);
      });
  }

  async #subscribe(
    threadId: string,
    key: string,
    topic: string,
    router: string,
    filters: readonly unknown[],
    coalesceSeconds: number,
    requestedMode: SubscriptionMode | undefined,
    onlyIfMissing: boolean,
    onHeld?: () => void,
  ): Promise<ToolResponse> {
    const existing = this.#store.subscriptionsOf(threadId).find((subscription) => subscription.key === key);
    if (existing !== undefined && (existing.router ?? "primary") !== router) {
      return toolError("invalid", `unsubscribe ${key} first, then subscribe with the new router`);
    }
    if (onlyIfMissing && existing !== undefined) {
      onHeld?.();
      return { ok: true, result: { id: existing.id, outcome: "kept", filters: existing.filters } };
    }
    // Changing the topic makes the router delete the subscription's pending batches (SPEC.md 12.5),
    // and a refusal could not bring them back. Refuse it before anything is sent.
    if (existing !== undefined && existing.topic !== topic) {
      return toolError("invalid", `${key} is subscribed to ${existing.topic}; unsubscribe it before subscribing it on ${topic}`);
    }
    const mode = requestedMode ?? (existing === undefined ? "queue" : existing.mode);
    if (
      existing !== undefined &&
      existing.coalesceSeconds === coalesceSeconds &&
      canonicalJson(existing.filters) === canonicalJson(filters)
    ) {
      if (mode === existing.mode) {
        return { ok: true, result: { id: existing.id, outcome: "unchanged", filters: existing.filters } };
      }
      this.#store.addSubscription({ ...existing, ...(mode === undefined ? {} : { mode }), updatedAt: new Date().toISOString() });
      return { ok: true, result: { id: existing.id, outcome: "updated", filters: existing.filters } };
    }
    if (existing === undefined) {
      const activeForThread = [...this.#creating.values()].filter((id) => id === threadId).length;
      if (this.#store.subscriptionsOf(threadId).length + activeForThread >= MAX_SUBSCRIPTIONS_PER_THREAD) {
        return toolError("too_many_subscriptions", `at most ${MAX_SUBSCRIPTIONS_PER_THREAD} subscriptions per thread`);
      }
      if (this.#store.subscriptions().length + this.#creating.size >= MAX_SUBSCRIPTIONS_PER_CONNECTOR) {
        return toolError("too_many_subscriptions", `at most ${MAX_SUBSCRIPTIONS_PER_CONNECTOR} subscriptions per connector`);
      }
    }
    const now = new Date().toISOString();
    const subscription: Subscription = {
      ...(existing ?? { id: randomUUID(), threadId, topic, createdAt: now, key, ...(router === "primary" ? {} : { router }) }),
      filters,
      coalesceSeconds,
      ...(mode === undefined ? {} : { mode }),
      ...(existing === undefined ? {} : { updatedAt: now }),
    };
    if (existing === undefined) this.#creating.set(subscription.id, threadId);
    try {
      const refused = await this.#offer(threadId, subscription);
      if (refused !== null) return refused;
      this.#store.addSubscription(subscription);
      onHeld?.();
      const outcome = existing === undefined ? "created" : "updated";
      log("info", "thread.subscribed", { threadId, subscription: subscription.id, key, topic, outcome });
      return { ok: true, result: { id: subscription.id, outcome, filters } };
    } finally {
      this.#creating.delete(subscription.id);
    }
  }

  /** `mesh_unsubscribe`: only the calling thread's subscriptions; any other ID gives `removed: false`. */
  unsubscribe(threadId: string, args: unknown): Promise<ToolResponse> {
    const parsed = decodeUnsubscribeArgs(args);
    if (parsed._tag === "None" || (parsed.value.id === undefined) === (parsed.value.key === undefined)) {
      return Promise.resolve(toolError("invalid", "mesh_unsubscribe needs {id} or {key}"));
    }
    const { id, key } = parsed.value;
    const current = this.#store.subscriptionsOf(threadId).find((sub) => id === undefined ? sub.key === key : sub.id === id);
    const pending = key === undefined ? undefined : this.#pending.get(`${threadId}\0${key}`);
    if (current === undefined && pending === undefined) return Promise.resolve({ ok: true, result: { removed: false } });
    const router = current === undefined ? pending?.router ?? "primary" : current.router ?? "primary";
    return this.#change(router, async () => {
      const row = this.#store.subscriptionsOf(threadId).find((sub) => id === undefined ? sub.key === key : sub.id === id);
      const target = row?.id;
      const removed = row !== undefined && (row.router ?? "primary") === router && this.#store.removeSubscription(threadId, row.id);
      if (removed) {
        log("info", "thread.unsubscribed", { threadId, subscription: target, ...(key === undefined ? {} : { key }) });
        // If the router is unreachable, the link sends the smaller set when it reconnects.
        await this.#sync(router);
      }
      return { ok: true, result: { removed } };
    });
  }

  /** Ordinary auto-settlement applies again only after the last protected subscription leaves. */
  async unsubscribeWithAutoSettle(threadId: string, args: unknown, setAutoSettle: SetAutoSettle): Promise<ToolResponse> {
    const before = this.protectedIdsOf(threadId);
    const removed = await this.unsubscribe(threadId, args);
    const after = new Set(this.protectedIdsOf(threadId));
    const gone = before.find((id) => !after.has(id));
    if (gone !== undefined && after.size === 0) await setAutoSettle(threadId, true, gone);
    return removed;
  }

  /**
   * Removes a thread's subscriptions, optionally for one router (a fork moves only primary). If one opted the
   * thread out of auto-settlement, ordinary auto-settlement applies again: one `{enabled: true}`, with
   * that subscription's ID. Returns how many were removed.
   */
  async pruneThreadWithAutoSettle(threadId: string, setAutoSettle: SetAutoSettle, router?: string): Promise<number> {
    const before = this.#store.subscriptionsOf(threadId).filter((sub) => router === undefined || (sub.router ?? "primary") === router);
    await this.prune((id) => id === threadId, router);
    const protectedSubscription = before.find((subscription) => optsOutOfAutoSettle(subscription.key));
    if (protectedSubscription !== undefined && this.protectedIdsOf(threadId).length === 0) await setAutoSettle(threadId, true, protectedSubscription.id);
    return before.length;
  }

  /** `mesh_subscriptions`: the calling thread's subscriptions, without the thread ID. */
  list(threadId: string): ToolResponse {
    return {
      ok: true,
      result: {
        subscriptions: this.#store.subscriptionsOf(threadId).map((subscription) => this.#view(subscription)),
      },
    };
  }

  /**
   * `mesh_subscriptions` with each subscription's `delivery` at the router (pending, held, delivered,
   * rejected, dropped over the retention window). `delivery` is null when the router cannot say, which
   * is unknown, not "nothing missed". Delivery is never acknowledgement that the work was handled.
   */
  async listWithDelivery(threadId: string): Promise<ToolResponse> {
    const stored = this.#store.subscriptionsOf(threadId);
    const names = new Set(stored.map((subscription) => subscription.router ?? "primary"));
    const statuses = await Promise.all([...names].map(async (router) => {
      const status = await this.#routers.get(router)?.subscriptionStatus().catch(() => null);
      return [router, new Map((status ?? []).map((entry) => [entry.id, entry]))] as const;
    }));
    const byRouter = new Map(statuses);
    return {
      ok: true,
      result: {
        subscriptions: stored.map((subscription) => {
          const router = subscription.router ?? "primary";
          const view = this.#view(subscription);
          const delivery = byRouter.get(router)?.get(subscription.id);
          if (delivery === undefined) return { ...view, delivery: null };
          const { id: _id, ...rest } = delivery;
          return { ...view, delivery: rest };
        }),
      },
    };
  }

  #view({ threadId: _threadId, router, ...subscription }: Subscription) {
    return {
      ...subscription,
      ...(this.#routers.size > 1 || (router !== undefined && router !== "primary") ? { router: router ?? "primary" } : {}),
    };
  }

  #change<A>(router: string, change: () => Promise<A>): Promise<A> {
    const result = (this.#changes.get(router) ?? Promise.resolve()).then(change, change);
    this.#changes.set(router, result.catch(() => undefined));
    return result;
  }
}
