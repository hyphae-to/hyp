/** A thread a plugin may deliver into (SPEC.md section 13.2). */
export interface PluginTarget {
  readonly name: string;
  /** The configured ("bootstrap") thread; mesh_plugin_handoff can move delivery elsewhere. */
  readonly threadId: string;
  readonly coalesceSeconds: number;
  readonly maxWaitSeconds: number;
  readonly wakesPerHour: number;
}

export interface PluginConfig {
  readonly name: string;
  readonly exec: string;
  readonly args: readonly string[];
  readonly env: Readonly<Record<string, string>>;
  readonly cwd: string;
  readonly targets: readonly PluginTarget[];
}
