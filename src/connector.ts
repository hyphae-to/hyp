import { randomUUID } from "node:crypto";
import type { Config } from "./config.ts";
import { createDelivery, usesDurableMailbox, type Channel, type Delivery } from "./delivery.ts";
import {
  addressPattern, delivered, formatItem, formatUnreadDigest, handlePattern, hold, isDeliveryMode, isMode,
  normalizeChannelName, normalizeMutePattern, object, reject, type DeliveryMode, type InboxItem, type Mode, type Outcome,
} from "./protocol.ts";
import { RouterError, RouterLink } from "./router.ts";
import type { MailboxEntry, MuteRule, Session, State } from "./state.ts";

const SUBSCRIPTION_CHANGES = Symbol();
const MAX_SUBSCRIPTIONS = 20;
const MAX_TEXT_BYTES = 16_384;
const invalid = (message: string) => new RouterError("invalid", message);

function slimTopicEntry(entry: unknown): unknown {
  if (!object(entry)) return entry;
  const out: Record<string, unknown> = { topic: entry.topic };
  const meta = object(entry.metadata) ? entry.metadata : undefined;
  if (meta && typeof meta.kind === "string") out.kind = meta.kind;
  if (Array.isArray(entry.publishers)) out.publishers = entry.publishers;
  if (meta && object(meta.scope)) out.scope = meta.scope;
  if (meta && object(meta.schema) && Array.isArray(meta.schema.attributes)) {
    out.attributes = meta.schema.attributes;
  }
  if (object(entry.observed)) {
    const obs: Record<string, unknown> = {};
    if (typeof entry.observed.eventCount === "number") obs.eventCount = entry.observed.eventCount;
    if (Array.isArray(entry.observed.repos) && entry.observed.repos.length > 0) obs.repos = entry.observed.repos;
    if (entry.observed.lastEventAt) obs.lastEventAt = entry.observed.lastEventAt;
    if (Object.keys(obs).length > 0) out.observed = obs;
  }
  return out;
}

export interface ConnectorHooks {
  readonly channel?: (sessionId: string) => Channel | undefined;
  readonly hasLiveTransport?: (sessionId: string) => boolean;
  readonly onMailboxItem?: (sessionId: string) => void;
  readonly listPluginTargets?: (sessionId: string) => unknown;
  readonly handoffPluginTarget?: (sessionId: string, args: Record<string, unknown>) => unknown;
  readonly postPluginTarget?: (sessionId: string, args: Record<string, unknown>) => Promise<unknown>;
  readonly linkBridgeTarget?: (sessionId: string, args: Record<string, unknown>) => unknown;
  readonly unlinkBridgeTarget?: (sessionId: string, args: Record<string, unknown>) => unknown;
}

export interface SessionStatus {
  id: string;
  backend: string;
  handle: string | null;
  address: string | null;
  subscriptions: number;
  pending: number;
  unnotified: number;
  deliveryMode: DeliveryMode;
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
  readonly #postPluginTarget?: (id: string, args: Record<string, unknown>) => Promise<unknown>;
  readonly #linkBridgeTarget?: (id: string, args: Record<string, unknown>) => unknown;
  readonly #unlinkBridgeTarget?: (id: string, args: Record<string, unknown>) => unknown;
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
      this.#postPluginTarget = hooksOrChannel.postPluginTarget;
      this.#linkBridgeTarget = hooksOrChannel.linkBridgeTarget;
      this.#unlinkBridgeTarget = hooksOrChannel.unlinkBridgeTarget;
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
    return usesDurableMailbox(session.backend);
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
    const muteCandidates = this.#muteCandidates(item);
    if (this.#state.isMuted(session.id, muteCandidates)) {
      this.#state.record(router, item.id, "muted");
      return delivered;
    }
    const text = formatItem(item);
    const meta = item.kind === "message"
      ? { kind: "message" as const, source: this.#messageSource(item) }
      : { kind: "event" as const, source: item.topic };
    return this.#deliverPrepared(session, router, item.id, text, mode, meta);
  }

  #messageSource(item: Extract<InboxItem, { kind: "message" }>): string {
    const ch = /^\[(#[^\]\s]+)\]\s/.exec(item.text);
    return ch ? `${ch[1]} (${item.from})` : item.from;
  }

  #muteCandidates(item: InboxItem): string[] {
    if (item.kind === "message") {
      const from = item.from.toLowerCase();
      const connector = from.split("/")[0];
      const list = [from, `${connector}/*`];
      const ch = /^\[(#[^\]\s]+)\]\s/.exec(item.text);
      if (ch) list.push(ch[1].toLowerCase());
      return list;
    }
    return [`topic:${item.topic.toLowerCase()}`];
  }

  /** Serialized delivery for local connector plugin batches into any harness session. */
  async deliverPluginText(session: Session, plugin: string, batchId: string, text: string): Promise<Outcome> {
    const routerKey = `plugin:${plugin}`;
    if (this.#state.isMuted(session.id, [`plugin:${plugin.toLowerCase()}`])) {
      this.#state.record(routerKey, batchId, "muted");
      return delivered;
    }
    const result = (this.#deliveryTails.get(session.id) ?? Promise.resolve()).then(() =>
      this.#deliverPrepared(session, routerKey, batchId, text, "queue", { kind: "plugin", source: `plugin:${plugin}` }),
    );
    const tail = result.catch(() => {});
    this.#deliveryTails.set(session.id, tail);
    try {
      return await result;
    } finally {
      if (this.#deliveryTails.get(session.id) === tail) this.#deliveryTails.delete(session.id);
    }
  }

  async #deliverPrepared(
    session: Session,
    router: string,
    itemId: string,
    text: string,
    mode: Mode,
    meta: { kind?: "message" | "event" | "plugin"; source?: string } = {},
  ): Promise<Outcome> {
    const receipt = this.#state.receipt(router, itemId);
    if (receipt === "submitted" || receipt === "muted") return delivered;
    if (receipt === "submitting") return reject("previous_submission_outcome_unknown");
    if (receipt !== undefined && receipt !== "interrupted") return reject(receipt);
    if (receipt === "interrupted") mode = "queue";
    if (Buffer.byteLength(text) > 100_000) return reject("event_prompt_too_large");

    const current = this.#state.session(session.id) ?? session;
    const isNotifyMode = current.deliveryMode === "notify";

    if (isNotifyMode || this.#usesDurableMailbox(current)) {
      if (!isNotifyMode && mode !== "queue") return hold("delivery_mode_unavailable");
      const stored = this.#state.putInInbox(current.id, router, itemId, text, meta);
      if (!stored) return hold("local_inbox_full");

      if (isNotifyMode && !this.#usesDurableMailbox(current)) {
        const digest = this.#state.unreadDigest(current.id);
        const notice = formatUnreadDigest(digest);
        const delivery = this.#delivery(current);
        const outcome = await delivery.deliver(notice, "queue", (attempt) => attempt()).catch(() => hold("notify_push_failed"));
        if (outcome.outcome === "delivered") this.#state.markMailboxNotified(current.id);
        return delivered;
      }

      this.#onMailboxItem(current.id);
      return delivered;
    }

    const delivery = this.#delivery(current);
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

  drainForPush(sessionId: string, limit = 10): MailboxEntry[] {
    this.#state.touch(sessionId);
    const session = this.#state.session(sessionId);
    if (!session) return [];
    if (session.deliveryMode === "notify") {
      const digest = this.#state.unreadDigest(sessionId);
      if (digest.unnotified === 0) return [];
      this.#state.markMailboxNotified(sessionId);
      return [{
        receipt: `notice:${Date.now()}`,
        router: "hyphae",
        text: formatUnreadDigest(digest),
        received: Date.now(),
      }];
    }
    return this.#state.drainInbox(sessionId, limit);
  }

  peekForPush(sessionId: string, limit = 10): { notifyOnly: boolean; items: MailboxEntry[] } {
    const session = this.#state.session(sessionId);
    if (!session) return { notifyOnly: false, items: [] };
    if (session.deliveryMode === "notify") {
      const digest = this.#state.unreadDigest(sessionId);
      if (digest.unnotified === 0) return { notifyOnly: true, items: [] };
      return {
        notifyOnly: true,
        items: [{
          receipt: `notice:${Date.now()}`,
          router: "hyphae",
          text: formatUnreadDigest(digest),
          received: Date.now(),
        }],
      };
    }
    return { notifyOnly: false, items: this.#state.peekInbox(sessionId, limit) };
  }

  ackPush(sessionId: string, receipts: readonly string[], notifyOnly: boolean): void {
    if (notifyOnly) this.#state.markMailboxNotified(sessionId);
    else this.#state.acknowledgeInbox(sessionId, receipts);
  }

  drainMailbox(sessionId: string, limit = 10): MailboxEntry[] {
    return this.drainForPush(sessionId, limit);
  }

  peekMailbox(sessionId: string, limit = 5): MailboxEntry[] {
    return this.#state.peekInbox(sessionId, limit);
  }

  acknowledgeMailbox(sessionId: string, receipts: readonly string[]): void {
    this.#state.acknowledgeInbox(sessionId, receipts);
  }

  muteTarget(target: string, scope = "*", mutedBy = "cli"): MuteRule {
    const pattern = normalizeMutePattern(target);
    if (!pattern) {
      throw invalid("Invalid mute target. Use peer (<user@host/handle>), connector (<user@host/*>), #channel, topic:<name>, or plugin:<name>.");
    }
    return this.#state.addMute(pattern, scope, mutedBy);
  }

  unmuteTarget(target: string, scope = "*"): { pattern: string; removed: boolean } {
    const pattern = normalizeMutePattern(target);
    if (!pattern) throw invalid("Invalid mute target");
    return { pattern, removed: this.#state.removeMute(pattern, scope) };
  }

  listMutes(sessionId?: string): MuteRule[] {
    return this.#state.listMutes(sessionId);
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
      unnotified: this.#state.unnotifiedCount(sessionId),
      deliveryMode: session.deliveryMode,
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
        unnotified: this.#state.unnotifiedCount(session.id),
        deliveryMode: session.deliveryMode,
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
      case "hyp_session":
        return this.#sessionTool(session, args);
      case "hyp_channel":
        return this.#channelTool(sessionId, args);
      case "hyp_stream":
        return this.#streamTool(session, args);
      case "hyp_bridge":
        return this.#bridgeTool(sessionId, args);
      case "hyp_capabilities":
        return {
          sessionId: session.id,
          backend: session.backend.kind,
          modes: this.#delivery(session).modes,
          deliveryMode: session.deliveryMode,
          unread: this.#state.pendingCount(session.id),
          mutes: this.#state.listMutes(session.id).length,
          routers: [...this.#routers.keys()],
          inbound: this.#inboundMode(session),
        };
      case "hyp_mode": {
        const { mode } = args;
        if (!isDeliveryMode(mode)) throw invalid("Expected mode: 'full' or 'notify'");
        this.#state.setDeliveryMode(session.id, mode);
        if (mode === "full" && this.#state.pendingCount(session.id) > 0) {
          this.#onMailboxItem(session.id);
        }
        return {
          deliveryMode: mode,
          unread: this.#state.pendingCount(session.id),
        };
      }
      case "hyp_mute": {
        const { target, scope } = args;
        if (typeof target !== "string") throw invalid("Expected target (e.g. 'alice@laptop/codex', 'alice@laptop/*', '#deploys', 'topic:github', 'plugin:slack')");
        const resolvedScope = scope === "session" ? session.id : "*";
        const rule = this.muteTarget(target, resolvedScope, this.#address(session.handle) ?? session.id);
        return {
          muted: rule.pattern,
          scope: resolvedScope === "*" ? "connector" : "session",
        };
      }
      case "hyp_unmute": {
        const { target, scope } = args;
        if (typeof target !== "string") throw invalid("Expected target");
        const resolvedScope = scope === "session" ? session.id : "*";
        const res = this.unmuteTarget(target, resolvedScope);
        return {
          pattern: res.pattern,
          scope: resolvedScope === "*" ? "connector" : "session",
          removed: res.removed,
        };
      }
      case "hyp_mutes": {
        const rules = this.listMutes(session.id).map((rule) => ({
          pattern: rule.pattern,
          scope: rule.scope === "*" ? "connector" : "session",
          mutedAt: rule.mutedAt,
          mutedBy: rule.mutedBy,
        }));
        return { mutes: rules };
      }
      case "hyp_inbox": {
        const acknowledge = args.acknowledge ?? [];
        const acknowledgeAll = args.acknowledgeAll === true || (args.acknowledgeAll === undefined && args.ack === true);
        const summaryOnly = args.summaryOnly === true;
        const limit = typeof args.limit === "number" && Number.isInteger(args.limit) && args.limit > 0 && args.limit <= 50
          ? args.limit : 20;
        if (!Array.isArray(acknowledge) || acknowledge.length > 100 ||
            !acknowledge.every((id): id is string => typeof id === "string" && id.length <= 80)) {
          throw invalid("Expected at most 100 receipt IDs");
        }
        const rawItems = this.#state.inbox(session.id, acknowledge, { limit, acknowledgeAll });
        const items = summaryOnly
          ? rawItems.map((it) => ({
              receipt: it.receipt,
              kind: it.kind,
              source: it.source,
              received: it.received,
              preview: it.text.split("\n").find((l) => l.trim().length > 0 && !l.startsWith("External data"))?.slice(0, 140) ?? "",
            }))
          : rawItems;
        return {
          deliveryMode: session.deliveryMode,
          unread: this.#state.pendingCount(session.id),
          items,
        };
      }
      case "hyp_join": {
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
      case "hyp_leave":
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
      case "hyp_peers": {
        const value = await this.#router("primary").query("/v1/peers");
        return { self: this.#address(session.handle), peers: object(value) ? value.peers : [] };
      }
      case "hyp_send": {
        const { to, text } = args;
        if (typeof to !== "string" || typeof text !== "string") {
          throw invalid("Expected destination 'to' (<connector>/<handle>, #channel, or <plugin>:<target>) and text up to 16 KiB");
        }
        if (to.startsWith("#")) {
          return this.call(sessionId, "hyp_channel_post", { channel: to, text });
        }
        const bridgeMatch = /^([a-z0-9][a-z0-9._-]{0,31}):([a-z0-9][a-z0-9._-]{0,63})$/.exec(to);
        if (bridgeMatch && !to.includes("/")) {
          return this.call(sessionId, "hyp_plugin_post", {
            ...args,
            plugin: bridgeMatch[1],
            target: bridgeMatch[2],
            to: typeof args.replyTo === "string" ? undefined : undefined,
            text,
          });
        }
        if (!addressPattern.test(to) || Buffer.byteLength(text) > MAX_TEXT_BYTES) {
          throw invalid("Expected a connector/handle address and text up to 16 KiB");
        }
        return this.#change("primary", async () => {
          const handle = this.#state.session(sessionId)?.handle ?? null;
          if (handle === null) throw new RouterError("not_enrolled", "Call hyp_join before sending");
          const messageId = randomUUID();
          await this.#router("primary").send(messageId, handle, to, text);
          return { messageId, status: "stored" };
        });
      }
      case "hyp_channel_join": {
        const rawChannel = args.channel;
        const channel = typeof rawChannel === "string" ? normalizeChannelName(rawChannel) : null;
        if (!channel) throw invalid("Expected channel name like '#incidents' or 'incidents'");
        return this.#change("primary", async () => {
          const handle = this.#state.session(sessionId)?.handle ?? null;
          if (handle === null) throw new RouterError("not_enrolled", "Call hyp_join before joining a channel");
          return this.#router("primary").joinChannel(handle, channel);
        });
      }
      case "hyp_channel_leave": {
        const rawChannel = args.channel;
        const channel = typeof rawChannel === "string" ? normalizeChannelName(rawChannel) : null;
        if (!channel) throw invalid("Expected channel name like '#incidents'");
        return this.#change("primary", async () => {
          const handle = this.#state.session(sessionId)?.handle ?? null;
          if (handle === null) throw new RouterError("not_enrolled", "Call hyp_join first");
          return this.#router("primary").leaveChannel(handle, channel);
        });
      }
      case "hyp_channel_post": {
        const { text } = args;
        const rawChannel = args.channel;
        const channel = typeof rawChannel === "string" ? normalizeChannelName(rawChannel) : null;
        if (!channel || typeof text !== "string" || text.length === 0 || Buffer.byteLength(text) > MAX_TEXT_BYTES - 128) {
          throw invalid("Expected channel name (e.g. '#incidents') and non-empty text up to 16 KiB");
        }
        return this.#change("primary", async () => {
          const handle = this.#state.session(sessionId)?.handle ?? null;
          if (handle === null) throw new RouterError("not_enrolled", "Call hyp_join before posting to a channel");
          const messageId = randomUUID();
          return this.#router("primary").postChannel(messageId, handle, channel, text);
        });
      }
      case "hyp_channels": {
        const rawChannel = args.channel;
        const channel = typeof rawChannel === "string" ? normalizeChannelName(rawChannel) ?? undefined : undefined;
        return this.#router("primary").channels(channel);
      }
      case "hyp_subscribe":
        return this.#subscribe(session, args);
      case "hyp_unsubscribe":
        return this.#unsubscribe(sessionId, args);
      case "hyp_subscriptions": {
        const subscriptions = this.#state.subscriptions().filter((entry) => entry.sessionId === sessionId);
        const statuses = new Map(await Promise.all([...new Set(subscriptions.map(({ router }) => router))].map(async (routerName) => {
          const value = await this.#router(routerName).query("/v1/subscriptions/status").catch(() => null);
          return [routerName, object(value) && Array.isArray(value.subscriptions) ? value.subscriptions.filter(object) : []] as const;
        })));
        return { subscriptions: subscriptions.map(({ sessionId: _session, ...item }) => ({
          ...item, delivery: statuses.get(item.router)?.find(({ id }) => id === item.id) ?? null,
        })) };
      }
      case "hyp_topics": {
        const routerFilter = typeof args.router === "string" && args.router.length > 0 ? args.router : undefined;
        const slim = args.verbose === false;
        const names = routerFilter ? [routerFilter] : [...this.#routers.keys()];
        const routers = await Promise.all(names.map(async (routerName) => {
          const link = this.#router(routerName);
          try {
            const value = await link.query("/v1/topics");
            const rawTopics = object(value) && Array.isArray(value.topics) ? value.topics : [];
            const topics = slim ? rawTopics.map(slimTopicEntry) : rawTopics;
            return { router: routerName, supported: true, topics };
          } catch (error) {
            if (error instanceof RouterError && error.code === "not_found") {
              return { router: routerName, supported: false, topics: [] };
            }
            throw error;
          }
        }));
        return { routers };
      }
      case "hyp_plugin_targets": {
        if (!this.#listPluginTargets) throw new RouterError("no_plugins", "This connector has no local plugins configured");
        return this.#listPluginTargets(sessionId);
      }
      case "hyp_plugin_handoff": {
        if (!this.#handoffPluginTarget) throw new RouterError("no_plugins", "This connector has no local plugins configured");
        return this.#handoffPluginTarget(sessionId, args);
      }
      case "hyp_plugin_post": {
        if (!this.#postPluginTarget) throw new RouterError("no_plugins", "This connector has no local plugins configured");
        return this.#postPluginTarget(sessionId, args);
      }
      case "hyp_bridge_link": {
        if (!this.#linkBridgeTarget) throw new RouterError("no_plugins", "This connector has no local plugins configured");
        return this.#linkBridgeTarget(sessionId, args);
      }
      case "hyp_bridge_unlink": {
        if (!this.#unlinkBridgeTarget) throw new RouterError("no_plugins", "This connector has no local plugins configured");
        return this.#unlinkBridgeTarget(sessionId, args);
      }
      default:
        throw new RouterError("unknown_tool", `Unknown tool ${name}`);
    }
  }

  async #sessionTool(session: Session, args: Record<string, unknown>): Promise<unknown> {
    const action = args.action;
    switch (action) {
      case "status":
        return this.call(session.id, "hyp_capabilities", {});
      case "leave":
        return this.call(session.id, "hyp_leave", {});
      case "peers":
        return this.call(session.id, "hyp_peers", {});
      case "mode":
        return this.call(session.id, "hyp_mode", args);
      case "mute":
        return this.call(session.id, "hyp_mute", args);
      case "unmute":
        return this.call(session.id, "hyp_unmute", args);
      case "mutes":
        return this.call(session.id, "hyp_mutes", {});
      case "join": {
        const joined = (await this.call(session.id, "hyp_join", args)) as Record<string, unknown>;
        const out: Record<string, unknown> = {
          ...joined,
          deliveryMode: session.deliveryMode,
          unread: this.#state.pendingCount(session.id),
        };
        const include = Array.isArray(args.include) ? args.include.filter((x): x is string => typeof x === "string") : [];
        if (include.length > 0) {
          await Promise.all(include.map(async (part) => {
            if (part === "peers") {
              const p = (await this.call(session.id, "hyp_peers", {})) as Record<string, unknown>;
              out.peers = p.peers;
            } else if (part === "channels") {
              const c = (await this.call(session.id, "hyp_channels", {})) as Record<string, unknown>;
              out.channels = c.channels;
            } else if (part === "topics") {
              const t = (await this.call(session.id, "hyp_topics", { verbose: false })) as Record<string, unknown>;
              out.topics = t.routers;
            } else if (part === "subs") {
              const s = (await this.#streamTool(session, { action: "list" })) as Record<string, unknown>;
              out.subs = s.subscriptions;
            } else if (part === "mutes") {
              const m = (await this.call(session.id, "hyp_mutes", {})) as Record<string, unknown>;
              out.mutes = m.mutes;
            } else if (part === "bridges" && this.#listPluginTargets) {
              out.bridges = await this.#listPluginTargets(session.id);
            }
          }));
        }
        return out;
      }
      default:
        throw invalid("Expected action: join | leave | status | peers | mode | mute | unmute | mutes");
    }
  }

  async #channelTool(sessionId: string, args: Record<string, unknown>): Promise<unknown> {
    switch (args.action) {
      case "join":
        return this.call(sessionId, "hyp_channel_join", args);
      case "leave":
        return this.call(sessionId, "hyp_channel_leave", args);
      case "list":
        return this.call(sessionId, "hyp_channels", args);
      default:
        throw invalid("Expected action: join | leave | list");
    }
  }

  async #streamTool(session: Session, args: Record<string, unknown>): Promise<unknown> {
    switch (args.action) {
      case "topics":
        return this.call(session.id, "hyp_topics", { ...args, verbose: args.verbose === true });
      case "subscribe":
        return this.#subscribe(session, args);
      case "unsubscribe":
        return this.#unsubscribe(session.id, args);
      case "list": {
        const res = (await this.call(session.id, "hyp_subscriptions", {})) as { subscriptions: Array<Record<string, unknown>> };
        return {
          subscriptions: res.subscriptions.map((sub) => {
            if (!object(sub.delivery)) return sub;
            const d = sub.delivery;
            const trimmed: Record<string, unknown> = {};
            if (typeof d.pending === "number" && d.pending > 0) trimmed.pending = d.pending;
            if (typeof d.delivered === "number" && d.delivered > 0) trimmed.delivered = d.delivered;
            if (d.heldReason !== null && d.heldReason !== undefined) trimmed.heldReason = d.heldReason;
            if (d.oldestPendingAt !== null && d.oldestPendingAt !== undefined) trimmed.oldestPendingAt = d.oldestPendingAt;
            if (object(d.rejected) && Object.keys(d.rejected).length > 0) trimmed.rejected = d.rejected;
            if (object(d.dropped) && Object.keys(d.dropped).length > 0) trimmed.dropped = d.dropped;
            return { ...sub, delivery: Object.keys(trimmed).length > 0 ? trimmed : "ok" };
          }),
        };
      }
      default:
        throw invalid("Expected action: topics | subscribe | unsubscribe | list");
    }
  }

  async #bridgeTool(sessionId: string, args: Record<string, unknown>): Promise<unknown> {
    switch (args.action) {
      case "targets":
        return this.call(sessionId, "hyp_plugin_targets", args);
      case "link":
        return this.call(sessionId, "hyp_bridge_link", args);
      case "unlink":
        return this.call(sessionId, "hyp_bridge_unlink", args);
      case "handoff":
        return this.call(sessionId, "hyp_plugin_handoff", args);
      case "post":
        return this.call(sessionId, "hyp_plugin_post", args);
      default:
        throw invalid("Expected action: targets | link | unlink | handoff | post");
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
    const strict = args.strict === true;
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
      let diagnostics: unknown[] = [];
      if (routerChanged || strict) {
        const previous = all.filter((entry) => entry.router === name);
        try {
          const syncRes = await router.subscriptions([...previous.filter(({ id }) => id !== subscription.id), subscription]);
          if (syncRes.unknownTopics.includes(topic)) throw new RouterError("unknown_topic", `No topic ${topic} on router ${name}`);
          diagnostics = syncRes.diagnostics[subscription.id] ?? [];
          if (strict) {
            const firstError = diagnostics.find((d) => object(d) && d.severity === "error");
            if (object(firstError) && typeof firstError.message === "string") {
              throw new RouterError("unreachable_subscription", firstError.message);
            }
          }
        } catch (error) {
          await router.subscriptions(previous).catch(() => this.#dirty.add(name));
          throw error;
        }
      }
      const outcome = existing === undefined ? "created" : routerChanged || existing.mode !== selected ? "updated" : "unchanged";
      if (outcome !== "unchanged") this.#state.store(subscription);
      const reachable = !diagnostics.some((d) => object(d) && d.severity === "error");
      return {
        id: subscription.id,
        mode: selected,
        outcome,
        filters,
        reachable,
        ...(diagnostics.length > 0 ? { diagnostics } : {}),
      };
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
