// Which thread each plugin target delivers into (SPEC.md section 13.5): the configured ("bootstrap")
// thread, unless mesh_plugin_handoff moved it. Only the thread holding a target, or its configured
// thread, may move it, so the configured thread can always take it back. A handoff whose thread is
// gone reverts to the configured thread; one made under another config is dropped.
import * as Schema from "effect/Schema";
import type { PluginConfig, PluginTarget } from "../config.ts";
import { toolError, type ToolResponse } from "../ipc.ts";
import { log } from "../log.ts";
import type { EnrollmentStore, PluginTargetOverride } from "../store.ts";
import { PluginHandoffArgs } from "../tools.ts";

const decodeHandoffArgs = Schema.decodeUnknownOption(PluginHandoffArgs);

const NO_PLUGINS = toolError("no_plugins", "this connector has no plugins configured");

/** Whether a thread is in this instance's shell cache and not archived or deleted. */
export type IsLiveThread = (threadId: string) => boolean;

export type TargetThread =
  | { readonly ok: true; readonly threadId: string }
  /** Neither the handoff thread nor the configured thread is live. */
  | { readonly ok: false; readonly threadId: string };

export class PluginTargets {
  readonly #plugins: readonly PluginConfig[];
  readonly #store: EnrollmentStore;

  constructor(plugins: readonly PluginConfig[], store: EnrollmentStore) {
    this.#plugins = plugins;
    this.#store = store;
    for (const override of store.pluginTargets()) this.#override(override.plugin, override.target);
  }

  #target(plugin: string, target: string): PluginTarget | undefined {
    return this.#plugins.find((config) => config.name === plugin)?.targets.find((config) => config.name === target);
  }

  /**
   * The handoff in force for a target. A record for a target no longer configured, or made while the
   * target had another configured thread, is deleted instead.
   */
  #override(plugin: string, target: string): PluginTargetOverride | undefined {
    const override = this.#store.pluginTarget(plugin, target);
    if (override === undefined) return undefined;
    const config = this.#target(plugin, target);
    if (config !== undefined && config.threadId === override.configuredThreadId) return override;
    this.#store.removePluginTarget(plugin, target);
    log("info", "plugin.target_handoff_dropped", {
      plugin,
      target,
      threadId: override.threadId,
      reason: config === undefined ? "not_configured" : "configuration_changed",
    });
    return undefined;
  }

  /** The thread a target currently delivers into, without checking that it is live. */
  threadOf(plugin: string, target: string): string | undefined {
    const config = this.#target(plugin, target);
    if (config === undefined) return undefined;
    return this.#override(plugin, target)?.threadId ?? config.threadId;
  }

  /**
   * The live thread to deliver a target's batch into. A handoff thread that is gone reverts the target
   * to its configured thread; if that is gone too, the batch has to wait. Undefined for unknown targets.
   */
  resolve(plugin: string, target: string, isLive: IsLiveThread): TargetThread | undefined {
    const config = this.#target(plugin, target);
    if (config === undefined) return undefined;
    const override = this.#override(plugin, target);
    if (override !== undefined) {
      if (isLive(override.threadId)) return { ok: true, threadId: override.threadId };
      this.#revert(override);
    }
    return { ok: isLive(config.threadId), threadId: config.threadId };
  }

  /**
   * Reverts handoffs whose thread is gone (on connecting to T3 and in the daemon's sweep). With
   * `warnMissing`, also warns about configured threads that are not live.
   */
  reconcile(isLive: IsLiveThread, warnMissing: boolean): void {
    for (const plugin of this.#plugins) {
      for (const target of plugin.targets) {
        const override = this.#override(plugin.name, target.name);
        if (override !== undefined && !isLive(override.threadId)) this.#revert(override);
        if (warnMissing && !isLive(target.threadId)) {
          log("warn", "plugin.target_thread_missing", { plugin: plugin.name, target: target.name, threadId: target.threadId });
        }
      }
    }
  }

  #revert(override: PluginTargetOverride): void {
    this.#store.removePluginTarget(override.plugin, override.target);
    log("warn", "plugin.target_reverted", {
      plugin: override.plugin,
      target: override.target,
      from: override.threadId,
      to: override.configuredThreadId,
    });
  }

  /**
   * `mesh_plugin_handoff`: moves a target to `threadId`, which must be a live, non-archived thread on
   * this instance. Pending batches follow, since delivery looks the thread up for every batch.
   */
  handoff(callerThreadId: string, args: unknown, isLive: IsLiveThread): ToolResponse {
    if (this.#plugins.length === 0) return NO_PLUGINS;
    const parsed = decodeHandoffArgs(args);
    if (parsed._tag === "None") return toolError("invalid", "mesh_plugin_handoff needs {plugin, target, threadId}");
    const { plugin, target, threadId } = parsed.value;
    const config = this.#target(plugin, target);
    if (config === undefined) return toolError("unknown_target", `no target ${target} of plugin ${plugin}`);
    const current = this.threadOf(plugin, target) ?? config.threadId;
    if (callerThreadId !== current && callerThreadId !== config.threadId) {
      return toolError("not_target_holder", `only the thread holding ${plugin}/${target}, or its configured thread, can hand it off`);
    }
    if (!isLive(threadId)) return toolError("unknown_thread", `no live, unarchived thread ${threadId} on this instance`);
    this.#store.setPluginTarget({
      plugin,
      target,
      threadId,
      configuredThreadId: config.threadId,
      setAt: new Date().toISOString(),
      setBy: callerThreadId,
    });
    log("info", "plugin.target_handoff", { plugin, target, from: current, to: threadId, by: callerThreadId });
    return { ok: true, result: { plugin, target, threadId } };
  }

  /** `mesh_plugin_targets`: the targets the caller holds or is the configured thread of. */
  list(callerThreadId: string): ToolResponse {
    if (this.#plugins.length === 0) return NO_PLUGINS;
    const targets = this.#plugins.flatMap((plugin) =>
      plugin.targets.flatMap((target) => {
        const threadId = this.threadOf(plugin.name, target.name) ?? target.threadId;
        return threadId === callerThreadId || target.threadId === callerThreadId
          ? [{ plugin: plugin.name, target: target.name, threadId }]
          : [];
      }),
    );
    return { ok: true, result: { targets } };
  }
}
