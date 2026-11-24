// `t3-mesh daemon`: one per T3 instance. Holds the loopback T3 connection, verifies tool
// callers, delivers inbound messages into enrolled threads, and talks to the router.
import { randomUUID } from "node:crypto";
import { chmodSync, readFileSync, rmSync } from "node:fs";
import { createServer, type Server, type Socket } from "node:net";
import * as DateTime from "effect/DateTime";
import * as Schema from "effect/Schema";
import { CommandId, ThreadId } from "@t3tools/contracts";
import { formatAddress, isHandle, parseAddress } from "./address.ts";
import type { ConnectorConfig } from "./config.ts";
import { attestationLine, attestThreads, checkAttestInput, payloadFits } from "./attest.ts";
import type { KeyObject } from "node:crypto";
import { readKeys } from "./identity/pairClient.ts";
import { formatEventDelivery } from "./eventDelivery.ts";
import { buildStatus, writeStatus } from "./statusExport.ts";
import { formatDelivery } from "./header.ts";
import { decodeIpcRequest, toolError, type ToolRequest, type ToolResponse } from "./ipc.ts";
import { errorMessage, log } from "./log.ts";
import { formatPluginDelivery } from "./plugins/delivery.ts";
import { Plugins } from "./plugins/plugins.ts";
import { PluginTargets } from "./plugins/targets.ts";
import { HttpRouterLink } from "./router/client.ts";
import { LoopbackRouter } from "./router/loopback.ts";
import {
  MAX_TEXT_BYTES,
  type InboundEventBatch,
  type InboundMessage,
  type InboundOutcome,
  type InboxItem,
  type RouterLink,
} from "./router/types.ts";
import { EnrollmentStore } from "./store.ts";
import { eventRouterDelivery, InboundDelivery, type DeliveryPrefix } from "./inbound.ts";
import { Subscriptions } from "./subscriptions.ts";
import { Forks } from "./fork.ts";
import { Transfers } from "./transfers.ts";
import { callerCandidateThreadIds, resolveCaller } from "./t3/caller.ts";
import { findT3Bin, issueConnectorToken, needsRenewal, readStoredToken } from "./t3/credentials.ts";
import { IncompatibleServerError, T3Connection } from "./t3/connection.ts";
import { classifyThread } from "./t3/threadState.ts";
import { AttestArgs, JoinArgs, SendArgs, isToolName, type ToolName } from "./tools.ts";

const decodeJoinArgs = Schema.decodeUnknownOption(JoinArgs);
const decodeSendArgs = Schema.decodeUnknownOption(SendArgs);
const decodeAttestArgs = Schema.decodeUnknownOption(AttestArgs);

const PinFile = Schema.Struct({ npmVersion: Schema.String });

function pinnedT3Version(): string | null {
  try {
    const text = readFileSync(new URL("../t3-pin.json", import.meta.url), "utf8");
    return Schema.decodeUnknownSync(PinFile)(JSON.parse(text)).npmVersion;
  } catch {
    return null;
  }
}

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));
const RENEW_CHECK_MS = 6 * 60 * 60 * 1000;
/** How often the status export is rewritten (docs/builder-subscriptions.md E4); consumers allow 60 s. */
const STATUS_EXPORT_MS = 15_000;
/** How often a failed subscription PUT is retried, and subscriptions of settled, archived or deleted threads looked for. */
const SUBSCRIPTION_SWEEP_MS = 30_000;

/** The primary link refuses redirects only when event routers are configured; primary-only keeps the old behaviour. */
export function primaryLinkOptions(config: Pick<ConnectorConfig, "eventRouters">): { readonly rejectRedirects: boolean } {
  return { rejectRedirects: (config.eventRouters?.length ?? 0) > 0 };
}

export class Daemon {
  readonly #config: ConnectorConfig;
  readonly #store: EnrollmentStore;
  readonly #router: RouterLink;
  readonly #subscriptions: Subscriptions;
  readonly #pluginTargets: PluginTargets;
  /** Null unless config.json has plugins. */
  readonly #plugins: Plugins | null;
  /** Null until this connector has paired (SPEC.md section 14). */
  readonly #transfers: Transfers | null;
  readonly #forks: Forks | null;
  readonly #pinnedVersion = pinnedT3Version();
  readonly #delivery: InboundDelivery;
  readonly #eventRouters: ReadonlyMap<string, RouterLink>;
  #connection: T3Connection | null = null;

  constructor(config: ConnectorConfig) {
    this.#config = config;
    this.#delivery = new InboundDelivery(config);
    this.#store = EnrollmentStore.load(config.statePath);
    this.#router =
      config.router.mode === "http"
        ? new HttpRouterLink(config.router.url, config.router.token, primaryLinkOptions(config))
        : new LoopbackRouter(config.connectorId);
    this.#eventRouters = new Map((config.eventRouters ?? []).map(({ name, url, token }) =>
      [name, new HttpRouterLink(url, token, { name, eventOnly: true })],
    ));
    this.#subscriptions = new Subscriptions(this.#store, this.#router, this.#eventRouters);
    this.#pluginTargets = new PluginTargets(config.plugins, this.#store);
    this.#plugins =
      config.plugins.length === 0 ? null : new Plugins({ dbPath: config.localDbPath, plugins: config.plugins });
    this.#transfers = Transfers.open(config, this.#router);
    this.#forks =
      this.#transfers === null
        ? null
        : new Forks(
            {
              config,
              store: this.#store,
              subscriptions: this.#subscriptions,
              connection: () => this.#connection,
              syncHandles: () => this.#router.setHandles(this.#store.handles()),
              dispatch: async (threadId, prefix, id, text, context) => {
                const connection = this.#connection;
                if (connection === null) return { kind: "hold", reason: "t3_unavailable" };
                return this.#delivery.dispatch(connection, threadId, prefix, id, text, context);
              },
              setAutoSettle: (threadId, enabled, subscriptionId) => this.#setAutoSettle(threadId, enabled, subscriptionId),
            },
            this.#transfers,
          );
    if (this.#forks !== null) this.#transfers?.attachForks(this.#forks);
  }

  async run(): Promise<never> {
    this.#listen();
    const plugins = this.#plugins;
    if (plugins !== null) {
      plugins.start();
      // Plugins get SIGTERM, then SIGKILL after 10 s, before the daemon exits.
      const stop = (signal: NodeJS.Signals) => {
        log("info", "daemon.stopping", { signal });
        void plugins.stop().finally(() => process.exit(0));
      };
      process.once("SIGTERM", stop);
      process.once("SIGINT", stop);
    }
    await this.#renewTokenIfDue();
    setInterval(() => void this.#renewTokenIfDue(), RENEW_CHECK_MS);
    await this.#router.setHandles(this.#store.handles());
    await this.#subscriptions.sync("primary");
    for (const name of this.#eventRouters.keys()) void this.#subscriptions.sync(name);
    this.#transfers?.start();
    setInterval(() => {
      void this.#subscriptions.retrySync();
      const connection = this.#connection;
      if (connection === null) return;
      void this.#subscriptions.prune((threadId) => this.#subscriptionsEnd(connection, threadId));
      this.#pluginTargets.reconcile((threadId) => !this.#threadIsGone(connection, threadId), false);
    }, SUBSCRIPTION_SWEEP_MS);
    const statusPath = this.#config.statusPath;
    if (statusPath !== null) {
      const export_ = () => {
        try {
          const connection = this.#connection;
          writeStatus(
            statusPath,
            buildStatus({
              connector: this.#config.connectorId,
              now: Date.now(),
              shells: connection === null ? null : connection.shellEntries(),
              keysOf: (threadId) => this.#subscriptions.keysOf(threadId),
            }),
          );
        } catch (error) {
          log("warn", "status.export_failed", { message: error instanceof Error ? error.message : String(error) });
        }
      };
      export_();
      setInterval(export_, STATUS_EXPORT_MS);
    }
    log("info", "daemon.started", {
      connectorId: this.#config.connectorId,
      t3: this.#config.t3Url,
      router: this.#config.router.mode === "http" ? this.#config.router.url : "loopback",
      enrolled: this.#store.handles(),
      subscriptions: this.#subscriptions.count(),
      plugins: this.#config.plugins.map((plugin) => plugin.name),
    });
    return this.#connectLoop();
  }

  async #connectLoop(): Promise<never> {
    let backoff = 1000;
    for (let attempt = 1; ; attempt++) {
      log("info", "t3.connecting", { attempt });
      try {
        const connection = await T3Connection.open(this.#config.t3Url, readStoredToken(this.#config.t3TokenPath).token);
        backoff = 1000;
        const { serverVersion } = connection.descriptor;
        log(serverVersion === this.#pinnedVersion ? "info" : "warn", "t3.connected", {
          attempt,
          serverVersion,
          pinnedVersion: this.#pinnedVersion,
          environmentId: connection.descriptor.environmentId,
        });
        this.#connection = connection;
        await this.#reconcile(connection);
        // Receive from the router only while T3 is reachable, so peers see this connector as
        // offline (and items wait at the router) rather than online but unable to deliver.
        this.#router.start((item) => this.#deliverItem(item));
        for (const [name, link] of this.#eventRouters) {
          link.start(eventRouterDelivery(name, (batch, prefix) => this.#deliverEvents(batch, name, prefix)));
        }
        this.#plugins?.attach((batch) => this.#deliverPluginBatch(batch));
        const reason = await connection.closed;
        this.#connection = null;
        this.#plugins?.detach();
        await Promise.all([this.#router, ...this.#eventRouters.values()].map((link) => link.stop()));
        log("warn", "t3.disconnected", { reason });
        await connection.close();
      } catch (error) {
        this.#connection = null;
        this.#plugins?.detach();
        await Promise.all([this.#router, ...this.#eventRouters.values()].map((link) => link.stop()));
        log(error instanceof IncompatibleServerError ? "error" : "warn", "t3.connect_failed", {
          attempt,
          error: errorMessage(error),
        });
      }
      await sleep(backoff);
      backoff = Math.min(backoff * 2, 30_000);
    }
  }

  /** Renews the narrowed T3 token when it has less than a week left. Failures are logged and retried later. */
  async #renewTokenIfDue(): Promise<void> {
    try {
      if (!needsRenewal(readStoredToken(this.#config.t3TokenPath))) return;
      const { stored, revoked, cleanupError } = await issueConnectorToken(
        { bin: findT3Bin(this.#config.t3Home, this.#config.t3Bin), home: this.#config.t3Home },
        this.#config.t3Url,
        `t3-mesh ${this.#config.connectorId}`,
        this.#config.t3TokenPath,
      );
      log("info", "t3.token_renewed", { expiresAt: stored.expiresAt, revoked });
      if (cleanupError !== undefined) log("warn", "t3.token_cleanup_failed", { error: cleanupError });
      // The open connection keeps working; the next reconnect uses the new token.
    } catch (error) {
      log("error", "t3.token_renewal_failed", { error: errorMessage(error) });
    }
  }

  /** Drops enrollments whose thread is gone or archived, and subscriptions whose thread is also settled. */
  async #reconcile(connection: T3Connection): Promise<void> {
    await this.#subscriptions.prune((threadId) => this.#subscriptionsEnd(connection, threadId), "primary");
    for (const name of this.#eventRouters.keys()) {
      void this.#subscriptions.prune((threadId) => this.#subscriptionsEnd(connection, threadId), name);
    }
    // Plugin targets whose handoff thread is gone go back to their configured thread.
    this.#pluginTargets.reconcile((threadId) => !this.#threadIsGone(connection, threadId), true);
    const removed = this.#store.prune((enrollment) => this.#threadIsGone(connection, enrollment.threadId));
    if (removed.length === 0) return;
    log("info", "enrollments.pruned", { handles: removed.map((enrollment) => enrollment.handle) });
    await this.#router.setHandles(this.#store.handles());
  }

  #threadIsGone(connection: T3Connection, threadId: string): boolean {
    const entry = connection.shellEntry(threadId);
    return entry === undefined || classifyThread(entry.thread, entry.location) === "archived";
  }

  /**
   * Settling a thread ends its subscriptions too, so a filter the agent forgot cannot wake it
   * (SPEC.md section 12.3). Direct messages and plugin targets still reach a settled thread.
   */
  #subscriptionsEnd(connection: T3Connection, threadId: string): boolean {
    const entry = connection.shellEntry(threadId);
    if (entry === undefined) return true;
    const state = classifyThread(entry.thread, entry.location);
    return state === "archived" || state === "settled";
  }

  /**
   * `mesh_attest` (docs/builder-subscriptions.md E6): signs, with this connector's paired identity key,
   * that the verified calling thread, configured for `role`, asked to attest one request. Fails closed:
   * no configured threads for the role, an unpaired connector, or another thread get an error.
   */
  #attest(threadId: string, args: unknown): ToolResponse {
    const parsed = decodeAttestArgs(args);
    if (parsed._tag === "None") return toolError("invalid", "mesh_attest needs {role, recordId, envelopeSha256, work}");
    const input = {
      role: parsed.value.role,
      record_id: parsed.value.recordId,
      envelope_sha256: parsed.value.envelopeSha256,
      work: parsed.value.work,
    };
    const problem = checkAttestInput(input);
    if (problem !== null) return toolError("invalid", problem);
    const threads = attestThreads(this.#config.attestRoles, input.role);
    if (!threads.includes(threadId)) {
      log("warn", "attest.refused", { threadId, role: input.role, record: input.record_id });
      return toolError("not_configured", `this thread is not configured to attest ${input.role} decisions on this connector`);
    }
    const identity = this.#config.identity;
    if (identity === null) return toolError("not_paired", "attestations need a paired connector (t3-mesh pair)");
    // Before pairing there is no keys.json; any unreadable key is reported the same way, without its path.
    let signing: KeyObject;
    try {
      signing = readKeys(identity.keysPath).signing;
    } catch {
      log("warn", "attest.no_key", { threadId, role: input.role, record: input.record_id });
      return toolError("not_paired", "attestations need a paired connector with a readable identity key (t3-mesh pair)");
    }
    const payload = {
      v: 1 as const,
      kind: "bayfold-decision" as const,
      ...input,
      connector: this.#config.connectorId,
      threadId,
      issuedAt: new Date().toISOString(),
    };
    if (!payloadFits(payload)) return toolError("invalid", "this attestation would exceed the verifiers' payload limit");
    const line = attestationLine(payload, signing);
    log("info", "attest.signed", { threadId, role: input.role, record: input.record_id, work: input.work });
    return { ok: true, result: { line, payload } };
  }

  /**
   * Turns T3's automatic settlement off or on for a thread holding an assignment or role subscription
   * (docs/builder-subscriptions.md E3). The command ID is the protected subscription's, so repeating
   * a subscribe is one command (if the user turns auto-settle back on, a resume does not override
   * them), while a later subscription of the same thread gets its own. Failure is logged, not fatal:
   * tidy still holds the child, and PM reconciles.
   */
  async #setAutoSettle(threadId: string, enabled: boolean, subscriptionId: string): Promise<string | null> {
    const connection = this.#connection;
    if (connection === null) {
      log("warn", "assignment.auto_settle_skipped", { threadId, enabled, reason: "t3_unavailable" });
      return "T3 is not connected";
    }
    const outcome = await connection.dispatch({
      type: "thread.auto-settle.set",
      commandId: CommandId.make(`mesh-assignment:auto-settle-${enabled ? "on" : "off"}:${subscriptionId}`),
      threadId: ThreadId.make(threadId),
      enabled,
    });
    log(outcome.ok ? "info" : "warn", "assignment.auto_settle", {
      threadId,
      enabled,
      ...(outcome.ok ? {} : { error: outcome.kind, message: outcome.message }),
    });
    return outcome.ok ? null : outcome.message;
  }

  // ---- inbound ----

  async #deliverItem(item: InboxItem): Promise<InboundOutcome> {
    if (item.kind === "event") return this.#deliverEvents(item);
    if (item.kind === "message") return this.#deliver(item);
    const transfers = this.#transfers;
    if (transfers === null) return { kind: "rejected", reason: "not_paired" };
    return transfers.receive(
      item,
      (handle) => this.#store.byHandle(handle)?.threadId,
      async (threadId, prefix, id, text) => {
        const connection = this.#connection;
        if (connection === null) return { kind: "hold", reason: "t3_unavailable" };
        return this.#delivery.dispatch(connection, threadId, prefix, id, text, null);
      },
    );
  }

  async #deliver(message: InboundMessage): Promise<InboundOutcome> {
    const connection = this.#connection;
    if (connection === null) return { kind: "hold", reason: "t3_unavailable" };
    const address = parseAddress(message.to);
    if (address === null || address.connectorId !== this.#config.connectorId) {
      return { kind: "rejected", reason: "wrong_connector" };
    }
    const enrollment = this.#store.byHandle(address.handle);
    if (enrollment === undefined) return { kind: "rejected", reason: "not_enrolled" };
    const delivery = formatDelivery(message);
    return this.#delivery.dispatch(connection, enrollment.threadId, "mesh", message.id, delivery.text, delivery.context);
  }

  /** An event batch goes to the thread that owns the subscription (SPEC.md section 12.6). */
  async #deliverEvents(batch: InboundEventBatch, router = "primary", prefix: DeliveryPrefix = "mesh-event"): Promise<InboundOutcome> {
    // Every event failed the CloudEvent check on arrival; there is nothing to wake the thread for.
    if (batch.events.length === 0) return { kind: "rejected", reason: "no_valid_events" };
    const connection = this.#connection;
    if (connection === null) return { kind: "hold", reason: "t3_unavailable" };
    const threadId = this.#subscriptions.owns(batch.subscriptionId, router)
      ? this.#subscriptions.threadOf(batch.subscriptionId)
      : undefined;
    if (threadId === undefined) return { kind: "rejected", reason: "unknown_subscription" };
    // The thread settled (or went away) since the last sweep: drop its subscriptions now rather than wake it.
    if (this.#subscriptionsEnd(connection, threadId)) {
      await this.#subscriptions.prune((id) => id === threadId, router);
      for (const name of ["primary", ...this.#eventRouters.keys()]) {
        if (name !== router) void this.#subscriptions.prune((id) => id === threadId, name);
      }
      log("info", "events.delivery", {
        router,
        batch: batch.id,
        subscription: batch.subscriptionId,
        topic: batch.topic,
        events: batch.events.length,
        outcome: "rejected",
        reason: "subscription_ended",
      });
      return { kind: "rejected", reason: "subscription_ended" };
    }
    const outcome = await this.#delivery.dispatch(
      connection,
      threadId,
      prefix,
      batch.id,
      formatEventDelivery(batch),
      null,
      this.#subscriptions.modeOf(batch.subscriptionId),
    );
    log(outcome.kind === "delivered" ? "info" : "warn", "events.delivery", {
      router,
      batch: batch.id,
      subscription: batch.subscriptionId,
      topic: batch.topic,
      events: batch.events.length,
      outcome: outcome.kind,
      ...(outcome.kind === "delivered" ? {} : { reason: outcome.reason }),
    });
    return outcome;
  }

  /**
   * A plugin batch goes to its target's current thread (SPEC.md sections 13.4-13.5). If neither the
   * handoff thread nor the configured thread is live, the batch waits (up to retention) rather than
   * being dropped.
   */
  async #deliverPluginBatch(batch: InboundEventBatch): Promise<InboundOutcome> {
    const route = this.#plugins?.route(batch.subscriptionId);
    const connection = this.#connection;
    const resolved =
      route === undefined || connection === null
        ? undefined
        : this.#pluginTargets.resolve(route.plugin, route.target, (id) => !this.#threadIsGone(connection, id));
    const threadId = resolved?.threadId;
    let outcome: InboundOutcome;
    if (connection === null) outcome = { kind: "hold", reason: "t3_unavailable" };
    else if (route === undefined || resolved === undefined) outcome = { kind: "rejected", reason: "unknown_target" };
    else if (batch.events.length === 0) outcome = { kind: "rejected", reason: "no_valid_events" };
    else if (!resolved.ok) outcome = { kind: "hold", reason: "target_unavailable" };
    else {
      const text = formatPluginDelivery(route.plugin, batch);
      outcome = await this.#delivery.dispatch(connection, resolved.threadId, "mesh-plugin", batch.id, text, null);
    }
    const level =
      outcome.kind === "delivered" ? "info" : outcome.kind === "hold" && outcome.reason === "target_unavailable" ? "error" : "warn";
    if (outcome.kind === "rejected" && route !== undefined) this.#plugins?.reportDeliveryFailed(route, batch, outcome.reason);
    log(level, "plugin.delivery", {
      batch: batch.id,
      plugin: route?.plugin,
      target: route?.target,
      threadId,
      events: batch.events.length,
      outcome: outcome.kind,
      ...(outcome.kind === "delivered" ? {} : { reason: outcome.reason }),
    });
    return outcome;
  }

  // ---- tools ----

  async #handleTool(request: ToolRequest): Promise<ToolResponse> {
    if (!isToolName(request.tool)) return toolError("unknown_tool", `unknown tool ${request.tool}`);
    const connection = this.#connection;
    if (connection === null) return toolError("t3_unavailable", "the connector is not connected to T3");
    if (request.callId === null) {
      return toolError("caller_unverifiable", "the MCP client sent no tool-call ID; only Claude and Codex are supported");
    }
    const caller = await resolveCaller(
      {
        candidateThreadIds: () => callerCandidateThreadIds(connection.shellEntries()),
        fallbackThreadIds: () => callerCandidateThreadIds(connection.shellEntries(), true),
        projection: (threadId) => connection.threadProjection(threadId),
      },
      request.callId,
      request.tool,
    );
    const callerShell = (threadId: ThreadId) => {
      const entry = connection.shellEntry(threadId);
      return {
        threadId,
        status: entry?.thread.status ?? null,
        location: entry?.location ?? null,
        activeRunId: entry?.thread.activeRunId ?? null,
        activityRunStatus: entry?.thread.activityRunStatus ?? null,
        updatedAt: entry === undefined ? null : DateTime.formatIso(entry.thread.updatedAt),
      };
    };
    if (!caller.ok) {
      log("warn", "tool.caller_unresolved", {
        tool: request.tool,
        callId: request.callId,
        code: caller.code,
        ...caller.diagnostics,
        // The most recently updated eligible threads only: the full list can run past a thousand.
        recentShellEntries: callerCandidateThreadIds(connection.shellEntries(), true).slice(0, 20).map(callerShell),
      });
      return toolError(caller.code, caller.message);
    }
    if (caller.fallback) {
      log("info", "tool.caller_fallback", {
        tool: request.tool,
        callId: request.callId,
        ...callerShell(caller.threadId),
      });
    }
    return this.#runTool(request.tool, caller.threadId, request.arguments, connection.descriptor.environmentId);
  }

  async #runTool(tool: ToolName, threadId: string, args: unknown, environmentId: string): Promise<ToolResponse> {
    const self = (handle: string) => formatAddress({ connectorId: this.#config.connectorId, handle });
    switch (tool) {
      case "mesh_capabilities":
        return { ok: true, result: { backend: "t3", modes: ["queue", "interrupt"], routers: ["primary", ...this.#eventRouters.keys()] } };
      case "mesh_join": {
        const parsed = decodeJoinArgs(args);
        if (parsed._tag === "None" || !isHandle(parsed.value.handle)) {
          return toolError("invalid_handle", "handle must match [a-z0-9][a-z0-9._-]{0,63}");
        }
        const joined = this.#store.join(threadId, parsed.value.handle);
        if (!joined.ok) return toolError("handle_taken", `${parsed.value.handle} is used by another thread`);
        await this.#router.setHandles(this.#store.handles());
        log("info", "thread.joined", { threadId, handle: parsed.value.handle, previous: joined.previousHandle });
        return { ok: true, result: { address: self(parsed.value.handle) } };
      }
      case "mesh_leave": {
        const enrollment = this.#store.byThread(threadId);
        const left = this.#store.leave(threadId);
        if (left) {
          await this.#router.setHandles(this.#store.handles());
          log("info", "thread.left", { threadId, handle: enrollment?.handle });
        }
        return { ok: true, result: { left } };
      }
      case "mesh_send": {
        const enrollment = this.#store.byThread(threadId);
        if (enrollment === undefined) return toolError("not_enrolled", "call mesh_join before sending");
        const parsed = decodeSendArgs(args);
        if (parsed._tag === "None") return toolError("invalid", "mesh_send needs {to, text}");
        if (parseAddress(parsed.value.to) === null) {
          return toolError("invalid_address", "to must be <connector>/<handle>, see mesh_peers");
        }
        if (Buffer.byteLength(parsed.value.text, "utf8") > MAX_TEXT_BYTES) {
          return toolError("too_large", `text exceeds ${MAX_TEXT_BYTES} bytes`);
        }
        const messageId = randomUUID();
        const sent = await this.#router.send({
          id: messageId,
          fromHandle: enrollment.handle,
          to: parsed.value.to,
          text: parsed.value.text,
          origin: { environmentId, threadId },
        });
        log(sent.ok ? "info" : "warn", "message.sent", {
          id: messageId,
          from: self(enrollment.handle),
          to: parsed.value.to,
          bytes: Buffer.byteLength(parsed.value.text, "utf8"),
          ...(sent.ok ? {} : { error: sent.error }),
        });
        return sent.ok
          ? { ok: true, result: { messageId, status: sent.status } }
          : toolError(sent.error, sent.message);
      }
      case "mesh_peers": {
        const enrollment = this.#store.byThread(threadId);
        return {
          ok: true,
          result: {
            self: enrollment === undefined ? null : self(enrollment.handle),
            peers: await this.#router.peers(),
          },
        };
      }
      case "mesh_subscribe":
        return this.#subscriptions.subscribeWithAutoSettle(threadId, args, (id, enabled, subscriptionId) =>
          this.#setAutoSettle(id, enabled, subscriptionId),
        );
      case "mesh_unsubscribe":
        return this.#subscriptions.unsubscribeWithAutoSettle(threadId, args, (id, enabled, subscriptionId) =>
          this.#setAutoSettle(id, enabled, subscriptionId),
        );
      case "mesh_subscriptions":
        return this.#subscriptions.listWithDelivery(threadId);
      case "mesh_attest":
        return this.#attest(threadId, args);
      case "mesh_plugin_handoff":
        return this.#pluginTargets.handoff(threadId, args, (target) => {
          const connection = this.#connection;
          return connection !== null && !this.#threadIsGone(connection, target);
        });
      case "mesh_plugin_targets":
        return this.#pluginTargets.list(threadId);
      case "mesh_send_files": {
        const transfers = this.#transfers;
        if (transfers === null) return toolError("not_paired", "this connector has not paired with the router (t3-mesh init --pair)");
        const enrollment = this.#store.byThread(threadId);
        if (enrollment === undefined) return toolError("not_enrolled", "call mesh_join before sending files");
        const cwd = this.#threadCwd(threadId);
        if (cwd === undefined) return toolError("unknown_thread", "cannot find this thread's working directory");
        return transfers.sendFiles(enrollment.handle, cwd, args);
      }
      case "mesh_fork": {
        const forks = this.#forks;
        if (forks === null) return toolError("not_paired", "this connector has not paired with the router (t3-mesh init --pair)");
        return forks.start(threadId, args);
      }
    }
  }

  /** The thread's working directory: its worktree, else its project's root. */
  #threadCwd(threadId: string): string | undefined {
    const connection = this.#connection;
    const entry = connection?.shellEntry(threadId);
    if (connection === null || entry === undefined) return undefined;
    return entry.thread.worktreePath ?? connection.project(entry.thread.projectId)?.workspaceRoot;
  }

  // ---- IPC ----

  #listen(): Server {
    rmSync(this.#config.socketPath, { force: true });
    const server = createServer((socket) => this.#serve(socket));
    server.listen(this.#config.socketPath, () => chmodSync(this.#config.socketPath, 0o600));
    return server;
  }

  #serve(socket: Socket): void {
    let buffer = "";
    socket.setEncoding("utf8");
    socket.on("data", async (chunk: string) => {
      buffer += chunk;
      const newline = buffer.indexOf("\n");
      if (newline < 0) return;
      socket.removeAllListeners("data");
      let response: ToolResponse;
      try {
        const request = decodeIpcRequest(JSON.parse(buffer.slice(0, newline)));
        response = "type" in request
          ? { ok: true, result: { eventRouters: [...this.#eventRouters.keys()] } }
          : await this.#handleTool(request);
      } catch (error) {
        log("error", "tool.failed", { error: errorMessage(error) });
        response = toolError("internal", errorMessage(error));
      }
      socket.end(JSON.stringify(response) + "\n");
    });
    socket.on("error", () => socket.destroy());
  }
}
