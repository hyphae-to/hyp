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

  async #deliver(batch: InboundEventBatch, sink: PluginDeliverySink): Promise<InboundOutcome> {
    const route = this.#plugins.route(batch.subscriptionId);
    if (!route) return { kind: "rejected", reason: "unknown_target" };
    if (batch.events.length === 0) return { kind: "rejected", reason: "no_valid_events" };
    const session = this.resolveTargetSession(route.plugin, route.target);
    if (!session) return { kind: "hold", reason: "target_unavailable" };

    const text = formatPluginDelivery(route.plugin, batch);
    const outcome = await sink.deliverPluginText(session, route.plugin, batch.id, text);
    if (outcome.outcome === "delivered") return { kind: "delivered" };
    if (outcome.outcome === "hold") return { kind: "hold", reason: outcome.reason };
    this.#plugins.reportDeliveryFailed(route, batch, outcome.reason);
    return { kind: "rejected", reason: outcome.reason };
  }

  listForSession(callerSessionId: string): { targets: Array<{ plugin: string; target: string; sessionId: string | null; handle: string | null }> } {
    if (this.#configs.length === 0) {
      throw new RouterError("no_plugins", "This connector has no local plugins configured");
    }
    const results: Array<{ plugin: string; target: string; sessionId: string | null; handle: string | null }> = [];
    for (const plugin of this.#configs) {
      for (const target of plugin.targets) {
        const current = this.resolveTargetSession(plugin.name, target.name);
        const configured = this.#configuredSession(target);
        if (current?.id === callerSessionId || configured?.id === callerSessionId) {
          results.push({
            plugin: plugin.name,
            target: target.name,
            sessionId: current?.id ?? null,
            handle: current?.handle ?? target.handle ?? null,
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
    const { plugin, target, sessionId, handle, threadId } = args;
    if (typeof plugin !== "string" || typeof target !== "string") {
      throw new RouterError("invalid", "hyp_plugin_handoff needs {plugin, target} plus one of {sessionId, handle, threadId}");
    }
    const config = this.#findTarget(plugin, target);
    if (!config) throw new RouterError("unknown_target", `No target ${target} of plugin ${plugin}`);

    const current = this.resolveTargetSession(plugin, target);
    const configured = this.#configuredSession(config);
    if (callerSessionId !== current?.id && callerSessionId !== configured?.id) {
      throw new RouterError("not_target_holder", `Only the session holding ${plugin}/${target} or its configured target can hand it off`);
    }

    let destination: Session | undefined;
    if (typeof sessionId === "string") destination = this.#state.session(sessionId);
    else if (typeof handle === "string") destination = this.#state.byHandle(handle);
    else if (typeof threadId === "string") destination = this.#state.byThreadId(threadId);
    else throw new RouterError("invalid", "Provide destination sessionId, handle, or threadId");

    if (!destination) throw new RouterError("unknown_session", "Destination session is not registered on this connector");

    this.#state.setPluginTarget({
      plugin,
      target,
      sessionId: destination.id,
      setAt: Date.now(),
      setBy: callerSessionId,
    });
    return { plugin, target, sessionId: destination.id };
  }
}
