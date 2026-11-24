import { join } from "node:path";
import type { AgentPluginConfig, AgentPluginTarget } from "./config.ts";
import { RouterError } from "./router.ts";
import type { Session, State } from "./state.ts";
import type { Outcome } from "./protocol.ts";
import { Plugins } from "./core/plugins/plugins.ts";
import { formatPluginDelivery } from "./core/plugins/delivery.ts";
import type { PluginConfig as T3PluginConfig } from "./core/plugins/types.ts";
import type { InboundEventBatch, InboundOutcome } from "./core/router/types.ts";

export interface PluginDeliverySink {
  deliverPluginText(session: Session, plugin: string, batchId: string, text: string): Promise<Outcome>;
}

/**
 * Universal local plugin host for `hyphae`: reuses `t3-mesh`'s battle-tested fd-3 process
 * supervisor, SQLite coalescing/retention store (`local.db`), and safe CloudEvent formatting,
 * while routing targets dynamically to ANY enrolled harness session (Antigravity, Claude, Codex, Herdr).
 */
export class PluginHost {
  readonly #configs: readonly AgentPluginConfig[];
  readonly #state: State;
  readonly #plugins: Plugins;

  constructor(stateDir: string, configs: readonly AgentPluginConfig[], state: State) {
    this.#configs = configs;
    this.#state = state;
    const t3Configs: T3PluginConfig[] = configs.map((plugin) => ({
      name: plugin.name,
      exec: plugin.exec,
      args: plugin.args,
      env: { ...plugin.env, AGENTS_MESH_FD: "3", AGENTS_MESH_PLUGIN: plugin.name, AGENTS_MESH_PROTOCOL: "1" },
      cwd: plugin.cwd,
      targets: plugin.targets.map((target) => ({
        name: target.name,
        threadId: target.sessionId ?? target.threadId ?? `handle:${target.handle}`,
        coalesceSeconds: target.coalesceSeconds,
        maxWaitSeconds: target.maxWaitSeconds,
        wakesPerHour: target.wakesPerHour,
      })),
    }));
    this.#plugins = new Plugins({ dbPath: join(stateDir, "local.db"), plugins: t3Configs });
  }

  get names(): string[] {
    return this.#configs.map((p) => p.name);
  }

  start(sink: PluginDeliverySink): void {
    this.#plugins.start();
    this.#plugins.attach((batch) => this.#deliver(batch, sink));
  }

  async stop(): Promise<void> {
    this.#plugins.detach();
    await this.#plugins.stop();
  }

  #findTarget(pluginName: string, targetName: string): AgentPluginTarget | undefined {
    return this.#configs.find((p) => p.name === pluginName)?.targets.find((t) => t.name === targetName);
  }

  #configuredSession(target: AgentPluginTarget): Session | undefined {
    if (target.sessionId) return this.#state.session(target.sessionId);
    if (target.handle) return this.#state.byHandle(target.handle);
    if (target.threadId) return this.#state.byThreadId(target.threadId);
    return undefined;
  }

  resolveTargetSession(pluginName: string, targetName: string): Session | undefined {
    const config = this.#findTarget(pluginName, targetName);
    if (!config) return undefined;
    const handoff = this.#state.pluginTarget(pluginName, targetName);
    if (handoff) {
      const targetSession = this.#state.session(handoff.sessionId);
      if (targetSession) return targetSession;
      this.#state.removePluginTarget(pluginName, targetName);
    }
    return this.#configuredSession(config);
  }

  #resolveRecipients(pluginName: string, targetName: string): Session[] {
    const recipients = new Map<string, Session>();
    const primary = this.resolveTargetSession(pluginName, targetName);
    if (primary) recipients.set(primary.id, primary);
    for (const link of this.#state.bridgeLinks(pluginName, targetName)) {
      const session = this.#state.session(link.sessionId);
      if (session) recipients.set(session.id, session);
      else this.#state.removeBridgeLink(pluginName, targetName, link.sessionId);
    }
    return [...recipients.values()];
  }

  #liveLinkedSessions(pluginName: string, targetName: string): Array<{ sessionId: string; handle: string | null }> {
    const linked: Array<{ sessionId: string; handle: string | null }> = [];
    for (const link of this.#state.bridgeLinks(pluginName, targetName)) {
      const session = this.#state.session(link.sessionId);
      if (session) linked.push({ sessionId: session.id, handle: session.handle });
      else this.#state.removeBridgeLink(pluginName, targetName, link.sessionId);
    }
    return linked;
  }

  #holderStatus(callerSessionId: string, pluginName: string, targetName: string, config: AgentPluginTarget): {
    current: Session | undefined;
    configured: Session | undefined;
    isPrimary: boolean;
    isLinked: boolean;
  } {
    const current = this.resolveTargetSession(pluginName, targetName);
    const configured = this.#configuredSession(config);
    const isPrimary = callerSessionId === current?.id || callerSessionId === configured?.id;
    const isLinked = this.#state.bridgeLinks(pluginName, targetName).some((link) => link.sessionId === callerSessionId);
    return { current, configured, isPrimary, isLinked };
  }

  #resolveDestination(args: Record<string, unknown>, fallbackSessionId?: string): Session {
    const { sessionId, handle, threadId } = args;
    let destination: Session | undefined;
    if (typeof sessionId === "string") destination = this.#state.session(sessionId);
    else if (typeof handle === "string") destination = this.#state.byHandle(handle);
    else if (typeof threadId === "string") destination = this.#state.byThreadId(threadId);
    else if (fallbackSessionId !== undefined) destination = this.#state.session(fallbackSessionId);
    else throw new RouterError("invalid", "Provide destination sessionId, handle, or threadId");
    if (!destination) throw new RouterError("unknown_session", "Destination session is not registered on this connector");
    return destination;
  }

  async #deliver(batch: InboundEventBatch, sink: PluginDeliverySink): Promise<InboundOutcome> {
    const route = this.#plugins.route(batch.subscriptionId);
    if (!route) return { kind: "rejected", reason: "unknown_target" };
    if (batch.events.length === 0) return { kind: "rejected", reason: "no_valid_events" };
    const recipients = this.#resolveRecipients(route.plugin, route.target);
    if (recipients.length === 0) return { kind: "hold", reason: "target_unavailable" };

    const text = formatPluginDelivery(route.plugin, batch);
    let deliveredCount = 0;
    let holdReason: string | undefined;
    let rejectedReason: string | undefined;

    for (const session of recipients) {
      const outcome = await sink.deliverPluginText(session, route.plugin, `${batch.id}:${session.id}`, text);
      if (outcome.outcome === "delivered") deliveredCount++;
      else if (outcome.outcome === "hold") holdReason ??= outcome.reason;
      else rejectedReason ??= outcome.reason;
    }

    if (holdReason !== undefined) return { kind: "hold", reason: holdReason };
    if (deliveredCount > 0) return { kind: "delivered" };
    const reason = rejectedReason ?? "delivery_rejected";
    this.#plugins.reportDeliveryFailed(route, batch, reason);
    return { kind: "rejected", reason };
  }

  listForSession(callerSessionId: string): {
    targets: Array<{
      plugin: string;
      target: string;
      sessionId: string | null;
      handle: string | null;
      linkedSessions: Array<{ sessionId: string; handle: string | null }>;
    }>;
  } {
    if (this.#configs.length === 0) {
      throw new RouterError("no_plugins", "This connector has no local plugins configured");
    }
    const results: Array<{
      plugin: string;
      target: string;
      sessionId: string | null;
      handle: string | null;
      linkedSessions: Array<{ sessionId: string; handle: string | null }>;
    }> = [];
    for (const plugin of this.#configs) {
      for (const target of plugin.targets) {
        const { current, isPrimary, isLinked } = this.#holderStatus(callerSessionId, plugin.name, target.name, target);
        if (isPrimary || isLinked) {
          results.push({
            plugin: plugin.name,
            target: target.name,
            sessionId: current?.id ?? null,
            handle: current?.handle ?? target.handle ?? null,
            linkedSessions: this.#liveLinkedSessions(plugin.name, target.name),
          });
        }
      }
    }
    return { targets: results };
  }

  handoff(callerSessionId: string, args: Record<string, unknown>): { plugin: string; target: string; sessionId: string } {
    if (this.#configs.length === 0) {
      throw new RouterError("no_plugins", "This connector has no local plugins configured");
    }
    const { plugin, target } = args;
    if (typeof plugin !== "string" || typeof target !== "string") {
      throw new RouterError("invalid", "hyp_plugin_handoff needs {plugin, target} plus one of {sessionId, handle, threadId}");
    }
    const config = this.#findTarget(plugin, target);
    if (!config) throw new RouterError("unknown_target", `No target ${target} of plugin ${plugin}`);

    const { isPrimary } = this.#holderStatus(callerSessionId, plugin, target, config);
    if (!isPrimary) {
      throw new RouterError("not_target_holder", `Only the session holding ${plugin}/${target} or its configured target can hand it off`);
    }

    const destination = this.#resolveDestination(args);
    this.#state.setPluginTarget({
      plugin,
      target,
      sessionId: destination.id,
      setAt: Date.now(),
      setBy: callerSessionId,
    });
    return { plugin, target, sessionId: destination.id };
  }

  linkBridge(callerSessionId: string, args: Record<string, unknown>): {
    plugin: string;
    target: string;
    sessionId: string;
    handle: string | null;
    linkedSessions: Array<{ sessionId: string; handle: string | null }>;
  } {
    if (this.#configs.length === 0) {
      throw new RouterError("no_plugins", "This connector has no local plugins configured");
    }
    const { plugin, target } = args;
    if (typeof plugin !== "string" || typeof target !== "string") {
      throw new RouterError("invalid", "hyp_bridge_link needs {plugin, target} and optional {sessionId, handle, threadId}");
    }
    const config = this.#findTarget(plugin, target);
    if (!config) throw new RouterError("unknown_target", `No target ${target} of plugin ${plugin}`);

    const destination = this.#resolveDestination(args, callerSessionId);
    const { current, configured, isPrimary } = this.#holderStatus(callerSessionId, plugin, target, config);
    const hasActiveHolder = current !== undefined || configured !== undefined;
    if (hasActiveHolder && !isPrimary) {
      throw new RouterError(
        "not_target_holder",
        `Only the primary holder of ${plugin}/${target} can link additional sessions to this bridge`,
      );
    }

    this.#state.addBridgeLink({
      plugin,
      target,
      sessionId: destination.id,
      linkedAt: Date.now(),
      linkedBy: callerSessionId,
    });
    return {
      plugin,
      target,
      sessionId: destination.id,
      handle: destination.handle,
      linkedSessions: this.#liveLinkedSessions(plugin, target),
    };
  }

  unlinkBridge(callerSessionId: string, args: Record<string, unknown>): {
    plugin: string;
    target: string;
    sessionId?: string;
    removed: boolean;
    removedCount: number;
    linkedSessions: Array<{ sessionId: string; handle: string | null }>;
  } {
    if (this.#configs.length === 0) {
      throw new RouterError("no_plugins", "This connector has no local plugins configured");
    }
    const { plugin, target, all } = args;
    if (typeof plugin !== "string" || typeof target !== "string") {
      throw new RouterError("invalid", "hyp_bridge_unlink needs {plugin, target} and optional {sessionId, handle, threadId, all}");
    }
    const config = this.#findTarget(plugin, target);
    if (!config) throw new RouterError("unknown_target", `No target ${target} of plugin ${plugin}`);

    const { isPrimary } = this.#holderStatus(callerSessionId, plugin, target, config);
    if (all === true) {
      if (!isPrimary) {
        throw new RouterError("not_target_holder", `Only the primary holder of ${plugin}/${target} can unlink all sessions`);
      }
      const removedCount = this.#state.removeBridgeLink(plugin, target);
      return { plugin, target, removed: removedCount > 0, removedCount, linkedSessions: [] };
    }

    const destination = this.#resolveDestination(args, callerSessionId);
    if (!isPrimary && destination.id !== callerSessionId) {
      throw new RouterError("not_target_holder", `Only the primary holder of ${plugin}/${target} can unlink another session`);
    }
    const removedCount = this.#state.removeBridgeLink(plugin, target, destination.id);
    return {
      plugin,
      target,
      sessionId: destination.id,
      removed: removedCount > 0,
      removedCount,
      linkedSessions: this.#liveLinkedSessions(plugin, target),
    };
  }

  async postToPlugin(callerSessionId: string, args: Record<string, unknown>): Promise<{
    plugin: string;
    target: string;
    result: unknown;
  }> {
    if (this.#configs.length === 0) {
      throw new RouterError("no_plugins", "This connector has no local plugins configured");
    }
    const { plugin, target, text } = args;
    if (typeof plugin !== "string" || typeof target !== "string" || typeof text !== "string" || text.trim().length === 0) {
      throw new RouterError("invalid", "hyp_plugin_post needs {plugin, target, text}");
    }
    if (Buffer.byteLength(text, "utf8") > 16_384) {
      throw new RouterError("invalid", "hyp_plugin_post text exceeds 16 KiB");
    }
    const config = this.#findTarget(plugin, target);
    if (!config) throw new RouterError("unknown_target", `No target ${target} of plugin ${plugin}`);

    const { isPrimary, isLinked } = this.#holderStatus(callerSessionId, plugin, target, config);
    if (!isPrimary && !isLinked) {
      throw new RouterError(
        "not_target_holder",
        `Session is not the holder or a linked member of ${plugin}/${target}`,
      );
    }

    const params: Record<string, unknown> = { text };
    for (const key of ["channel", "threadTs", "replyTo", "to"] as const) {
      const value = args[key];
      if (value === undefined) continue;
      if (typeof value !== "string" || value.length === 0 || value.length > 256) {
        throw new RouterError("invalid", `${key} must be a non-empty string up to 256 characters`);
      }
      params[key] = value;
    }
    if (args.chatId !== undefined) {
      if (typeof args.chatId === "number" && Number.isSafeInteger(args.chatId)) {
        params.chatId = String(args.chatId);
      } else if (typeof args.chatId === "string" && args.chatId.length > 0 && args.chatId.length <= 256) {
        params.chatId = args.chatId;
      } else {
        throw new RouterError("invalid", "chatId must be a string or safe integer");
      }
    }

    const response = await this.#plugins.request(plugin, "post", target, params);
    if (!response.ok) {
      throw new RouterError("plugin_post_failed", response.error);
    }
    return { plugin, target, result: response.result };
  }
}
