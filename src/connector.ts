import { randomUUID } from "node:crypto";
import type { Config } from "./config.ts";
import { createDelivery, type Channel, type Delivery } from "./delivery.ts";
import { addressPattern, delivered, formatItem, handlePattern, hold, isMode, normalizeChannelName, object, reject, type InboxItem, type Mode, type Outcome } from "./protocol.ts";
import { RouterError, RouterLink } from "./router.ts";
import type { MailboxEntry, Session, State } from "./state.ts";

const SUBSCRIPTION_CHANGES = Symbol();
const MAX_SUBSCRIPTIONS = 20;
const MAX_TEXT_BYTES = 16_384;
const invalid = (message: string) => new RouterError("invalid", message);

export interface ConnectorHooks {
  readonly channel?: (sessionId: string) => Channel | undefined;
  readonly hasLiveTransport?: (sessionId: string) => boolean;
  readonly onMailboxItem?: (sessionId: string) => void;
  readonly listPluginTargets?: (sessionId: string) => unknown;
  readonly handoffPluginTarget?: (sessionId: string, args: Record<string, unknown>) => unknown;
}

export interface SessionStatus {
  id: string;
  backend: string;
  handle: string | null;
  address: string | null;
  subscriptions: number;
  pending: number;
  enrolled: boolean;
  hasLiveTransport: boolean;
  lastSeen: number;
}

export class Connector {
  readonly #config: Config;
  readonly #channel: (id: string) => Channel | undefined;
  readonly #hasLiveTransport: (id: string) => boolean;
  readonly #onMailboxItem: (id: string) => void;
  readonly #listPluginTargets?: (id: string) => unknown;
  readonly #handoffPluginTarget?: (id: string, args: Record<string, unknown>) => unknown;
  readonly #state: State;
  readonly #routers: Map<string, RouterLink>;
  readonly #mutations = new Map<string | symbol, Promise<unknown>>();
  readonly #dirty = new Set<string>();
  readonly #deliveryTails = new Map<string, Promise<unknown>>();

  constructor(
    config: Config,
    state: State,
    hooksOrChannel: ((id: string) => Channel | undefined) | ConnectorHooks = {},
  ) {
    this.#config = config;
    this.#state = state;
    if (typeof hooksOrChannel === "function") {
      this.#channel = hooksOrChannel;
      this.#hasLiveTransport = (id) => hooksOrChannel(id) !== undefined;
      this.#onMailboxItem = () => {};
    } else {
      this.#channel = hooksOrChannel.channel ?? (() => undefined);
      this.#hasLiveTransport = hooksOrChannel.hasLiveTransport ?? ((id) => this.#channel(id) !== undefined);
      this.#onMailboxItem = hooksOrChannel.onMailboxItem ?? (() => {});
      this.#listPluginTargets = hooksOrChannel.listPluginTargets;
      this.#handoffPluginTarget = hooksOrChannel.handoffPluginTarget;
    }
    this.#routers = new Map(config.routers.map((router) => [router.name, new RouterLink(router)]));
  }

  get connectorId(): string {
    return this.#config.connectorId;
  }

  get routerNames(): string[] {
    return [...this.#routers.keys()];
  }

  #delivery(session: Session): Delivery {
    return createDelivery(session.backend, () => this.#channel(session.id));
  }

  #usesDurableMailbox(session: Session): boolean {
    if (session.backend.kind === "antigravity") return true;
    if (session.backend.kind === "claude") return true;
    if (session.backend.kind === "codex" && session.backend.queue !== true) return true;
    return false;
  }

  async run(signal: AbortSignal): Promise<void> {
    const retry = setInterval(() => {
      for (const name of this.#dirty) void this.#sync(name).catch(() => {});
    }, 30_000).unref();
    try {
      await Promise.all([...this.#routers].map(([name, router]) => router.listen(
        signal, () => this.#sync(name), (item) => this.#receive(name, item),
      )));
    } finally {
      clearInterval(retry);
    }
  }

  #sync(name: string): Promise<void> {
    return this.#change(name, async () => {
      const router = this.#router(name);
      if (name === "primary") await router.handles(this.#state.handles());
      await router.subscriptions(this.#state.subscriptions().filter((subscription) => subscription.router === name));
      this.#dirty.delete(name);
    });
  }

  async drain(): Promise<void> {
    await Promise.all([...this.#deliveryTails.values(), ...this.#mutations.values()]);
  }

  #change<T>(router: string | symbol, run: () => Promise<T>): Promise<T> {
    const result = (this.#mutations.get(router) ?? Promise.resolve()).then(run);
    this.#mutations.set(router, result.catch(() => {}));
    return result;
  }

  async #receive(router: string, item: InboxItem): Promise<Outcome> {
    await this.#mutations.get(router);
    let session: Session | undefined;
    let mode: Mode = "queue";
    if (item.kind === "message") {
      const [connector, handle] = item.to.split("/");
      if (router !== "primary" || connector !== this.#config.connectorId) return reject("wrong_recipient");
      session = this.#state.byHandle(handle);
    } else {
      const subscription = this.#state.subscriptions().find(({ id }) => id === item.subscriptionId);
      if (subscription === undefined || subscription.router !== router || subscription.topic !== item.topic) {
        return reject("unknown_subscription");
      }
      if (item.events.length === 0) return reject("empty_event_batch");
      session = this.#state.session(subscription.sessionId);
      mode = subscription.mode;
    }
    if (!session) return reject("unknown_recipient");
    const target = session;
    const result = (this.#deliveryTails.get(target.id) ?? Promise.resolve()).then(() => this.#deliver(target, router, item, mode));
    const tail = result.catch(() => {});
    this.#deliveryTails.set(target.id, tail);
    try {
      return await result;
    } finally {
      if (this.#deliveryTails.get(target.id) === tail) this.#deliveryTails.delete(target.id);
    }
  }

  async #deliver(session: Session, router: string, item: InboxItem, mode: Mode): Promise<Outcome> {
    const text = formatItem(item);
    return this.#deliverPrepared(session, router, item.id, text, mode);
  }

  /** Serialized delivery for local connector plugin batches into any harness session. */
  async deliverPluginText(session: Session, plugin: string, batchId: string, text: string): Promise<Outcome> {
    const routerKey = `plugin:${plugin}`;
    const result = (this.#deliveryTails.get(session.id) ?? Promise.resolve()).then(() =>
      this.#deliverPrepared(session, routerKey, batchId, text, "queue"),
    );
    const tail = result.catch(() => {});
    this.#deliveryTails.set(session.id, tail);
    try {
      return await result;
    } finally {
      if (this.#deliveryTails.get(session.id) === tail) this.#deliveryTails.delete(session.id);
    }
  }

  async #deliverPrepared(session: Session, router: string, itemId: string, text: string, mode: Mode): Promise<Outcome> {
    const receipt = this.#state.receipt(router, itemId);
    if (receipt === "submitted") return delivered;
    if (receipt === "submitting") return reject("previous_submission_outcome_unknown");
    if (receipt !== undefined && receipt !== "interrupted") return reject(receipt);
    if (receipt === "interrupted") mode = "queue";
    if (Buffer.byteLength(text) > 100_000) return reject("event_prompt_too_large");

    if (this.#usesDurableMailbox(session)) {
      if (mode !== "queue") return hold("delivery_mode_unavailable");
      const stored = this.#state.putInInbox(session.id, router, itemId, text);
      if (!stored) return hold("local_inbox_full");
      this.#onMailboxItem(session.id);
      return delivered;
    }

    const delivery = this.#delivery(session);
    if (!delivery.modes.includes(mode)) return hold("delivery_mode_unavailable");
    return delivery.deliver(text, mode, async (attempt) => {
      this.#state.record(router, itemId, "submitting");
      const { interrupted, ...outcome } = await attempt().catch(() => ({ ...reject("submission_outcome_unknown"), interrupted: undefined }));
      if (outcome.outcome === "hold") {
        if (interrupted || receipt === "interrupted") this.#state.record(router, itemId, "interrupted");
        else this.#state.clear(router, itemId);
      } else {
        this.#state.record(router, itemId, outcome.outcome === "delivered" ? "submitted" : outcome.reason);
      }
      return outcome;
    });
  }

  drainMailbox(sessionId: string, limit = 10): MailboxEntry[] {
    this.#state.touch(sessionId);
    return this.#state.drainInbox(sessionId, limit);
  }

  peekMailbox(sessionId: string, limit = 5): MailboxEntry[] {
    return this.#state.peekInbox(sessionId, limit);
  }

  acknowledgeMailbox(sessionId: string, receipts: readonly string[]): void {
    this.#state.acknowledgeInbox(sessionId, receipts);
  }

  sessionStatus(sessionId: string): SessionStatus | undefined {
    const session = this.#state.session(sessionId);
    if (!session) return undefined;
    const subscriptions = this.#state.subscriptionsFor(sessionId).length;
    return {
      id: session.id,
      backend: session.backend.kind,
      handle: session.handle,
      address: this.#address(session.handle),
      subscriptions,
      pending: this.#state.pendingCount(sessionId),
      enrolled: session.handle !== null || subscriptions > 0,
      hasLiveTransport: this.#hasLiveTransport(sessionId),
      lastSeen: session.lastSeen,
    };
  }

  listSessions(): SessionStatus[] {
    return this.#state.sessions().map((session) => {
      const subscriptions = this.#state.subscriptionsFor(session.id).length;
      return {
        id: session.id,
        backend: session.backend.kind,
        handle: session.handle,
        address: this.#address(session.handle),
        subscriptions,
        pending: this.#state.pendingCount(session.id),
        enrolled: session.handle !== null || subscriptions > 0,
        hasLiveTransport: this.#hasLiveTransport(session.id),
        lastSeen: session.lastSeen,
      };
    });
  }

  async pruneStale(maxAgeMs: number, activeSessionIds: ReadonlySet<string> = new Set()): Promise<string[]> {
    const { pruned, routers } = this.#state.pruneSessions(Date.now() - maxAgeMs, activeSessionIds);
    if (pruned.length === 0) return [];
    for (const name of routers) {
      if (!this.#routers.has(name)) continue;
      await this.#sync(name).catch(() => this.#dirty.add(name));
    }
    return pruned;
  }

  #address(handle: string | null): string | null {
    return handle === null ? null : `${this.#config.connectorId}/${handle}`;
  }

  #router(name: string): RouterLink {
    const router = this.#routers.get(name);
    if (router === undefined) throw invalid(`Unknown router ${name}`);
    return router;
  }

  async call(sessionId: string, name: string, args: Record<string, unknown>): Promise<unknown> {
    const session = this.#state.session(sessionId);
    if (!session) throw new RouterError("unbound_session", "No registered client session");
    this.#state.touch(sessionId);
    switch (name) {
      case "mesh_capabilities":
        return {
          sessionId: session.id,
          backend: session.backend.kind,
          modes: this.#delivery(session).modes,
          routers: [...this.#routers.keys()],
          inbound: this.#inboundMode(session),
        };
      case "mesh_inbox": {
        const acknowledge = args.acknowledge ?? [];
        if (!Array.isArray(acknowledge) || acknowledge.length > 100 ||
            !acknowledge.every((id): id is string => typeof id === "string" && id.length <= 80)) {
          throw invalid("Expected at most 100 receipt IDs");
        }
        return { items: this.#state.inbox(session.id, acknowledge) };
      }
      case "mesh_join": {
        const { handle } = args;
        if (typeof handle !== "string" || !handlePattern.test(handle)) throw invalid("Invalid handle");
        return this.#change("primary", async () => {
          const owner = this.#state.byHandle(handle);
          if (owner && owner.id !== sessionId) throw new RouterError("handle_taken", "This handle belongs to another session");
          const previous = this.#state.session(sessionId)?.handle;
          const handles = this.#state.handles().filter((item) => item !== previous);
          try {
            await this.#router("primary").handles([...handles, handle]);
          } catch (error) {
            this.#dirty.add("primary");
            throw error;
          }
          this.#state.setHandle(sessionId, handle);
          return { address: this.#address(handle) };
        });
      }
      case "mesh_leave":
        return this.#change("primary", async () => {
          const left = this.#state.session(sessionId)?.handle != null;
          if (left) {
            this.#state.setHandle(sessionId, null);
            try {
              await this.#router("primary").handles(this.#state.handles());
            } catch {
              this.#dirty.add("primary");
              return { left, warning: "Router enrollment removal will be retried" };
            }
          }
          return { left };
        });
      case "mesh_peers": {
        const value = await this.#router("primary").query("/v1/peers");
        return { self: this.#address(session.handle), peers: object(value) ? value.peers : [] };
      }
      case "mesh_send": {
        const { to, text } = args;
        if (typeof to !== "string" || !addressPattern.test(to) || typeof text !== "string" || Buffer.byteLength(text) > MAX_TEXT_BYTES) {
          throw invalid("Expected a connector/handle address and text up to 16 KiB");
        }
        return this.#change("primary", async () => {
          const handle = this.#state.session(sessionId)?.handle ?? null;
          if (handle === null) throw new RouterError("not_enrolled", "Call mesh_join before sending");
          const messageId = randomUUID();
          await this.#router("primary").send(messageId, handle, to, text);
          return { messageId, status: "stored" };
        });
      }
      case "mesh_channel_join": {
        const rawChannel = args.channel;
        const channel = typeof rawChannel === "string" ? normalizeChannelName(rawChannel) : null;
        if (!channel) throw invalid("Expected channel name like '#incidents' or 'incidents'");
        return this.#change("primary", async () => {
          const handle = this.#state.session(sessionId)?.handle ?? null;
          if (handle === null) throw new RouterError("not_enrolled", "Call mesh_join before joining a channel");
          return this.#router("primary").joinChannel(handle, channel);
        });
      }
      case "mesh_channel_leave": {
        const rawChannel = args.channel;
        const channel = typeof rawChannel === "string" ? normalizeChannelName(rawChannel) : null;
        if (!channel) throw invalid("Expected channel name like '#incidents'");
        return this.#change("primary", async () => {
          const handle = this.#state.session(sessionId)?.handle ?? null;
          if (handle === null) throw new RouterError("not_enrolled", "Call mesh_join first");
          return this.#router("primary").leaveChannel(handle, channel);
        });
      }
      case "mesh_channel_post": {
        const { text } = args;
        const rawChannel = args.channel;
        const channel = typeof rawChannel === "string" ? normalizeChannelName(rawChannel) : null;
        if (!channel || typeof text !== "string" || text.length === 0 || Buffer.byteLength(text) > MAX_TEXT_BYTES - 128) {
          throw invalid("Expected channel name (e.g. '#incidents') and non-empty text up to 16 KiB");
        }
        return this.#change("primary", async () => {
          const handle = this.#state.session(sessionId)?.handle ?? null;
          if (handle === null) throw new RouterError("not_enrolled", "Call mesh_join before posting to a channel");
          const messageId = randomUUID();
          return this.#router("primary").postChannel(messageId, handle, channel, text);
        });
      }
      case "mesh_channels": {
        const rawChannel = args.channel;
        const channel = typeof rawChannel === "string" ? normalizeChannelName(rawChannel) ?? undefined : undefined;
        return this.#router("primary").channels(channel);
      }
      case "mesh_subscribe":
        return this.#subscribe(session, args);
      case "mesh_unsubscribe":
        return this.#unsubscribe(sessionId, args);
      case "mesh_subscriptions": {
        const subscriptions = this.#state.subscriptions().filter((entry) => entry.sessionId === sessionId);
        const statuses = new Map(await Promise.all([...new Set(subscriptions.map(({ router }) => router))].map(async (routerName) => {
          const value = await this.#router(routerName).query("/v1/subscriptions/status").catch(() => null);
          return [routerName, object(value) && Array.isArray(value.subscriptions) ? value.subscriptions.filter(object) : []] as const;
        })));
        return { subscriptions: subscriptions.map(({ sessionId: _session, ...item }) => ({
          ...item, delivery: statuses.get(item.router)?.find(({ id }) => id === item.id) ?? null,
        })) };
      }
      case "mesh_plugin_targets": {
        if (!this.#listPluginTargets) throw new RouterError("no_plugins", "This connector has no local plugins configured");
        return this.#listPluginTargets(sessionId);
      }
      case "mesh_plugin_handoff": {
        if (!this.#handoffPluginTarget) throw new RouterError("no_plugins", "This connector has no local plugins configured");
        return this.#handoffPluginTarget(sessionId, args);
      }
      default:
        throw new RouterError("unknown_tool", `Unknown tool ${name}`);
    }
  }

  #inboundMode(session: Session): string {
    if (session.backend.kind === "herdr") return "herdr";
    if (session.backend.kind === "codex" && session.backend.queue === true) return "codex-queue";
    if (this.#channel(session.id) !== undefined) return "claude-channel";
    if (this.#hasLiveTransport(session.id)) return "push-waiter";
    return "hooks-and-waiter";
  }

  #subscribe(session: Session, args: Record<string, unknown>): Promise<unknown> {
    const { key, topic, filters, mode } = args;
    const name = args.router ?? "primary";
    const coalesceSeconds = args.coalesceSeconds ?? 30;
    if (typeof key !== "string" || !/^[a-z][a-z0-9-]{0,31}:[A-Za-z0-9._/#:-]{1,120}$/.test(key) ||
        typeof topic !== "string" || !/^[a-z0-9][a-z0-9._-]{0,63}$/.test(topic) ||
        !Array.isArray(filters) || Buffer.byteLength(JSON.stringify(filters)) > 4096 ||
        typeof name !== "string" || typeof coalesceSeconds !== "number" || !Number.isInteger(coalesceSeconds) ||
        coalesceSeconds < 0 || coalesceSeconds > 600 || (mode !== undefined && !isMode(mode))) {
      throw invalid("Expected key, topic, filters and optional router, mode and coalesceSeconds");
    }
    const router = this.#router(name);
    // Serialize all subscription edits so the same key cannot be claimed on two links.
    return this.#change(SUBSCRIPTION_CHANGES, () => this.#change(name, async () => {
      const all = this.#state.subscriptions();
      const mine = all.filter((subscription) => subscription.sessionId === session.id);
      const existing = mine.find((subscription) => subscription.key === key);
      if (existing && (existing.router !== name || existing.topic !== topic)) throw invalid("Unsubscribe this key before changing its topic or router");
      if (!existing && (mine.length >= MAX_SUBSCRIPTIONS || all.length >= 200)) throw invalid("Subscription limit reached");
      const selected = mode ?? existing?.mode ?? "queue";
      const modes = this.#delivery(session).modes;
      if (!modes.includes(selected)) {
        throw new RouterError("unsupported_mode", `Supported modes: ${modes.join(", ")}`);
      }
      const subscription = { id: existing?.id ?? randomUUID(), sessionId: session.id, key, topic, router: name, filters, coalesceSeconds, mode: selected };
      const routerChanged = existing === undefined || existing.coalesceSeconds !== coalesceSeconds ||
        JSON.stringify(existing.filters) !== JSON.stringify(filters);
      if (routerChanged) {
        const previous = all.filter((entry) => entry.router === name);
        try {
          const unknown = await router.subscriptions([...previous.filter(({ id }) => id !== subscription.id), subscription]);
          if (unknown.includes(topic)) throw new RouterError("unknown_topic", `No topic ${topic} on router ${name}`);
        } catch (error) {
          await router.subscriptions(previous).catch(() => this.#dirty.add(name));
          throw error;
        }
      }
      const outcome = existing === undefined ? "created" : routerChanged || existing.mode !== selected ? "updated" : "unchanged";
      if (outcome !== "unchanged") this.#state.store(subscription);
      return { id: subscription.id, mode: selected, outcome, filters };
    }));
  }

  #unsubscribe(sessionId: string, { id, key }: Record<string, unknown>): Promise<unknown> {
    if ((typeof id === "string") === (typeof key === "string")) throw invalid("Give either id or key");
    return this.#change(SUBSCRIPTION_CHANGES, async () => {
      const item = this.#state.subscriptions().find((entry) => entry.sessionId === sessionId && (entry.id === id || entry.key === key));
      if (!item) return { removed: false };
      return this.#change(item.router, async () => {
        this.#state.remove(item.id);
        try {
          await this.#router(item.router).subscriptions(this.#state.subscriptions().filter(({ router }) => router === item.router));
        } catch {
          this.#dirty.add(item.router);
          return { removed: true, warning: "Router subscription removal will be retried" };
        }
        return { removed: true };
      });
    });
  }
}
