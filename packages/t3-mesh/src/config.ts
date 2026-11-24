// Connector configuration: `<state dir>/config.json` (SPEC.md section 9).
import { readFileSync, statSync } from "node:fs";
import { dirname, isAbsolute, resolve } from "node:path";
import * as Schema from "effect/Schema";
import { isConnectorId } from "./address.ts";
import { isRawKey } from "./identity/keys.ts";
import { readPrivateFile } from "./privateFile.ts";
import { DEFAULT_POLICY, type DeliveryPolicy } from "./t3/threadState.ts";

const PolicyAction = Schema.Literals(["deliver", "hold", "reject"]);

const PluginTargetFile = Schema.Struct({
  name: Schema.String,
  threadId: Schema.String,
  coalesceSeconds: Schema.optionalKey(Schema.Number),
  maxWaitSeconds: Schema.optionalKey(Schema.Number),
  wakesPerHour: Schema.optionalKey(Schema.Number),
});
const PluginFile = Schema.Struct({
  name: Schema.String,
  exec: Schema.String,
  args: Schema.optionalKey(Schema.Array(Schema.String)),
  env: Schema.optionalKey(Schema.Record(Schema.String, Schema.String)),
  cwd: Schema.optionalKey(Schema.String),
  targets: Schema.Array(PluginTargetFile),
});
type PluginFile = typeof PluginFile.Type;

const EventRouterFile = Schema.Struct({ name: Schema.String, url: Schema.String, tokenFile: Schema.String });
const EventRoutersFile = Schema.Struct({ eventRouters: Schema.optionalKey(Schema.Array(EventRouterFile)) });

/** Extra links receive events only; messages and transfers always use the primary router. */
export interface EventRouterConfig {
  readonly name: string;
  readonly url: string;
  readonly token: string;
}

const EVENT_ROUTER_NAME = /^[a-z0-9][a-z0-9-]{0,31}$/;

function checkEventRouterNames(routers: readonly { readonly name: string }[]): void {
  const names = new Set<string>();
  for (const { name } of routers) {
    if (!EVENT_ROUTER_NAME.test(name)) throw new Error(`event router name ${JSON.stringify(name)} must match ${EVENT_ROUTER_NAME.source}`);
    if (name === "primary") throw new Error('event router name "primary" is reserved');
    if (names.has(name)) throw new Error(`event router ${name} is configured twice`);
    names.add(name);
  }
}

const ConfigFile = Schema.Struct({
  ...EventRoutersFile.fields,
  connectorId: Schema.String,
  t3: Schema.Struct({
    url: Schema.String,
    /** T3CODE_HOME of the instance; used with the t3 CLI to renew the connector token. */
    home: Schema.String,
    bin: Schema.optionalKey(Schema.String),
  }),
  router: Schema.Union([
    Schema.Struct({ mode: Schema.Literal("loopback") }),
    Schema.Struct({ mode: Schema.Literal("http"), url: Schema.String, tokenFile: Schema.String }),
  ]),
  /** "steer" (default): into the active run when the provider can steer; "queue": always after it. */
  delivery: Schema.optionalKey(Schema.Literals(["steer", "queue"])),
  policy: Schema.optionalKey(
    Schema.Struct({
      busy: Schema.optionalKey(PolicyAction),
      idle: Schema.optionalKey(PolicyAction),
      stopped: Schema.optionalKey(PolicyAction),
      failed: Schema.optionalKey(PolicyAction),
      settled: Schema.optionalKey(PolicyAction),
      archived: Schema.optionalKey(PolicyAction),
    }),
  ),
  /** Local processes delivering events into threads of this instance (SPEC.md section 13). */
  plugins: Schema.optionalKey(Schema.Array(PluginFile)),
  /** Set by pairing (SPEC.md section 14): the mesh admin's public key; keys are in keys.json. */
  identity: Schema.optionalKey(Schema.Struct({ adminKey: Schema.String })),
  /**
   * Threads allowed to attest role decisions with mesh_attest (docs/builder-subscriptions.md E6), by
   * role. Absent or empty: nothing is attested. Needs a paired connector (its signing key).
   */
  attest: Schema.optionalKey(Schema.Struct({ roles: Schema.Record(Schema.String, Schema.Array(Schema.String)) })),
  /** Narrow execution status, the usage-tally input (docs/builder-subscriptions.md E4); off unless enabled. */
  statusExport: Schema.optionalKey(Schema.Struct({ enabled: Schema.Boolean, path: Schema.optionalKey(Schema.String) })),
  /** Narrows what this connector accepts (SPEC.md sections 15.4 and 16): connector IDs per kind. */
  accept: Schema.optionalKey(
    Schema.Struct({ files: Schema.optionalKey(Schema.Array(Schema.String)), forks: Schema.optionalKey(Schema.Array(Schema.String)) }),
  ),
});
const decodeConfigFile = Schema.decodeUnknownSync(ConfigFile);

export type { PluginConfig, PluginTarget } from "./plugins/types.ts";
import type { PluginConfig, PluginTarget } from "./plugins/types.ts";

/** Plugin and target names: what a plugin addresses and what logs and headers show. */
export const PLUGIN_NAME = /^[a-z0-9][a-z0-9._-]{0,31}$/;
const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;

const integerIn = (label: string, value: number, min: number, max: number): number => {
  if (!Number.isInteger(value) || value < min || value > max) throw new Error(`${label} must be an integer from ${min} to ${max}`);
  return value;
};

/** Checks the `plugins` section; `cwd` defaults to the state dir. Throws on the first problem. */
export function checkPlugins(plugins: readonly PluginFile[], stateDir: string): PluginConfig[] {
  const names = new Set<string>();
  return plugins.map((plugin) => {
    const at = `plugins.${plugin.name}`;
    if (!PLUGIN_NAME.test(plugin.name)) throw new Error(`plugin name ${JSON.stringify(plugin.name)} must match ${PLUGIN_NAME.source}`);
    if (names.has(plugin.name)) throw new Error(`plugin ${plugin.name} is configured twice`);
    names.add(plugin.name);
    if (!isAbsolute(plugin.exec)) throw new Error(`${at}.exec must be an absolute path`);
    if (plugin.cwd !== undefined && !isAbsolute(plugin.cwd)) throw new Error(`${at}.cwd must be an absolute path`);
    for (const key of Object.keys(plugin.env ?? {})) {
      if (!ENV_NAME.test(key)) throw new Error(`${at}.env has an invalid variable name ${JSON.stringify(key)}`);
    }
    if (plugin.targets.length === 0) throw new Error(`${at} needs at least one target`);
    const targetNames = new Set<string>();
    const targets = plugin.targets.map((target): PluginTarget => {
      const where = `${at}.targets.${target.name}`;
      if (!PLUGIN_NAME.test(target.name)) {
        throw new Error(`${at}: target name ${JSON.stringify(target.name)} must match ${PLUGIN_NAME.source}`);
      }
      if (targetNames.has(target.name)) throw new Error(`${at}: target ${target.name} is configured twice`);
      targetNames.add(target.name);
      if (target.threadId.length === 0) throw new Error(`${where}.threadId is empty`);
      return {
        name: target.name,
        threadId: target.threadId,
        coalesceSeconds: integerIn(`${where}.coalesceSeconds`, target.coalesceSeconds ?? 5, 0, 600),
        maxWaitSeconds: integerIn(`${where}.maxWaitSeconds`, target.maxWaitSeconds ?? 30, 1, 3600),
        wakesPerHour: integerIn(`${where}.wakesPerHour`, target.wakesPerHour ?? 120, 1, 3600),
      };
    });
    return {
      name: plugin.name,
      exec: plugin.exec,
      args: plugin.args ?? [],
      env: plugin.env ?? {},
      cwd: plugin.cwd ?? stateDir,
      targets,
    };
  });
}

/** Decodes and checks a `plugins` value as it appears in config.json. */
export const decodePlugins = (value: unknown, stateDir: string): PluginConfig[] =>
  checkPlugins(Schema.decodeUnknownSync(Schema.Array(PluginFile))(value), stateDir);

export interface ConnectorConfig {
  readonly stateDir: string;
  readonly connectorId: string;
  readonly t3Url: string;
  readonly t3Home: string;
  readonly t3Bin: string | undefined;
  /** JSON {token, expiresAt}, written by `init` and renewed by the daemon. */
  readonly t3TokenPath: string;
  readonly router:
    | { readonly mode: "loopback" }
    | { readonly mode: "http"; readonly url: string; readonly token: string };
  readonly eventRouters?: readonly EventRouterConfig[];
  readonly delivery: "steer" | "queue";
  readonly policy: DeliveryPolicy;
  readonly socketPath: string;
  readonly statePath: string;
  /** Empty unless configured. */
  readonly plugins: readonly PluginConfig[];
  /** The plugins' event store (SPEC.md section 13.4). */
  readonly localDbPath: string;
  /** Present once the connector has paired (SPEC.md section 14). */
  readonly identity: { readonly adminKey: string; readonly keysPath: string } | null;
  /** Connector IDs this connector accepts files / forks from; null means any the scopes allow. */
  readonly accept: { readonly files: readonly string[] | null; readonly forks: readonly string[] | null };
  /** Role -> T3 thread IDs that may attest its decisions; empty when not configured. */
  readonly attestRoles: Readonly<Record<string, readonly string[]>>;
  /** Null when the status export is off. */
  readonly statusPath: string | null;
}

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "[::1]"]);

export function loadConfig(configPath: string): ConnectorConfig {
  const path = resolve(configPath);
  const stateDir = dirname(path);
  const dirMode = statSync(stateDir).mode & 0o777;
  if ((dirMode & 0o077) !== 0) {
    throw new Error(`${stateDir} is mode ${dirMode.toString(8)}; it must be private (chmod 700)`);
  }
  const file = decodeConfigFile(JSON.parse(readFileSync(path, "utf8")));
  checkEventRouterNames(file.eventRouters ?? []);
  const origins = new Set(file.router.mode === "http" ? [new URL(file.router.url).origin] : []);
  for (const { name, url } of file.eventRouters ?? []) {
    const parsed = new URL(url);
    const loopback = parsed.hostname === "localhost" || parsed.hostname === "[::1]" || /^127\.\d+\.\d+\.\d+$/.test(parsed.hostname);
    if (parsed.protocol !== "https:" && !(parsed.protocol === "http:" && loopback)) {
      throw new Error(`event router ${name} requires https outside loopback`);
    }
    const origin = parsed.origin;
    if (origins.has(origin)) throw new Error(`event router ${name} shares origin ${origin} with another router`);
    origins.add(origin);
  }
  if (!isConnectorId(file.connectorId)) throw new Error(`invalid connectorId: ${file.connectorId}`);
  if (file.identity !== undefined && !isRawKey(file.identity.adminKey)) throw new Error("identity.adminKey is not a raw public key");
  const t3Url = new URL(file.t3.url);
  if (!LOOPBACK_HOSTS.has(t3Url.hostname)) {
    throw new Error(`t3.url must be a loopback address; the T3 token never leaves this host (got ${t3Url.hostname})`);
  }
  const tokenPaths = new Set<string>();
  const tokens = new Set<string>();
  const routerToken = (name: string, tokenFile: string): string => {
    const path = resolve(stateDir, tokenFile);
    if (tokenPaths.has(path)) throw new Error(`router ${name} shares a tokenFile path with another link`);
    const token = readPrivateFile(path);
    if (tokens.has(token)) throw new Error(`router ${name} shares token contents with another link`);
    tokenPaths.add(path);
    tokens.add(token);
    return token;
  };
  const router = file.router.mode === "http"
    ? { mode: "http" as const, url: new URL(file.router.url).origin, token: routerToken("primary", file.router.tokenFile) }
    : file.router;
  const eventRouters = (file.eventRouters ?? []).map(({ name, url, tokenFile }) => ({
    name, url: new URL(url).origin, token: routerToken(name, tokenFile),
  }));
  return {
    stateDir,
    connectorId: file.connectorId,
    t3Url: t3Url.origin,
    t3Home: resolve(stateDir, file.t3.home),
    t3Bin: file.t3.bin,
    t3TokenPath: resolve(stateDir, "t3-token.json"),
    router,
    eventRouters,
    delivery: file.delivery ?? "steer",
    policy: { ...DEFAULT_POLICY, ...file.policy },
    socketPath: resolve(stateDir, "daemon.sock"),
    statePath: resolve(stateDir, "state.json"),
    plugins: checkPlugins(file.plugins ?? [], stateDir),
    localDbPath: resolve(stateDir, "local.db"),
    identity:
      file.identity === undefined ? null : { adminKey: file.identity.adminKey, keysPath: resolve(stateDir, "keys.json") },
    accept: { files: file.accept?.files ?? null, forks: file.accept?.forks ?? null },
    attestRoles: file.attest?.roles ?? {},
    statusPath: file.statusExport?.enabled === true ? resolve(stateDir, file.statusExport.path ?? "status.json") : null,
  };
}
