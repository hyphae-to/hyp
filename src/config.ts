import { existsSync, lstatSync, readFileSync } from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Backend } from "./delivery.ts";
import { connectorPattern, handlePattern, object, sessionIdPattern } from "./protocol.ts";
import type { RouterConfig } from "./router.ts";
import { resolveEnvWithSecrets } from "./secrets.ts";
import { isTopic } from "./core/router/cloudevent.ts";

export type BuiltinStreamName = "github-webhook" | "webhook-stream" | "prometheus-webhook";

export interface RouterStreamScope {
  readonly repos?: readonly string[];
  readonly orgs?: readonly string[];
  readonly subjects?: readonly string[];
}

export interface RouterStreamConfig {
  readonly name: string;
  readonly topic: string;
  readonly builtin?: BuiltinStreamName;
  readonly exec?: string;
  readonly args: readonly string[];
  readonly env: Readonly<Record<string, string>>;
  readonly cwd: string;
  readonly scope?: RouterStreamScope;
}

export interface LocalRouterConfig {
  host: string;
  port: number;
  dbPath: string;
  auditPath?: string;
  exposure?: "private" | "public";
  streams?: readonly RouterStreamConfig[];
}

export type BuiltinPluginName = "slack" | "telegram" | "whatsapp" | "webhook";

export interface AgentPluginTarget {
  readonly name: string;
  readonly sessionId?: string;
  readonly handle?: string;
  readonly threadId?: string;
  readonly coalesceSeconds: number;
  readonly maxWaitSeconds: number;
  readonly wakesPerHour: number;
}

export interface AgentPluginConfig {
  readonly name: string;
  readonly builtin?: BuiltinPluginName;
  readonly exec: string;
  readonly args: readonly string[];
  readonly env: Readonly<Record<string, string>>;
  readonly cwd: string;
  readonly targets: readonly AgentPluginTarget[];
}

export interface Config {
  connectorId: string;
  directory: string;
  routers: RouterConfig[];
  localRouter?: LocalRouterConfig;
  plugins?: readonly AgentPluginConfig[];
}

const PLUGIN_NAME = /^[a-z0-9][a-z0-9._-]{0,31}$/;
const BUILTIN_PLUGINS = new Set<BuiltinPluginName>(["slack", "telegram", "whatsapp", "webhook"]);
const BUILTIN_STREAMS = new Set<BuiltinStreamName>(["github-webhook", "webhook-stream", "prometheus-webhook"]);

function parseStreams(raw: unknown, configDir: string, stateDir: string): RouterStreamConfig[] {
  if (raw === undefined) return [];
  if (!Array.isArray(raw)) throw new Error("localRouter.streams must be an array");
  const seenNames = new Set<string>();
  return raw.map((entry): RouterStreamConfig => {
    if (!object(entry) || typeof entry.name !== "string" || !PLUGIN_NAME.test(entry.name)) {
      throw new Error("Each router stream needs a valid lowercase name");
    }
    if (seenNames.has(entry.name)) throw new Error(`Duplicate stream name '${entry.name}'`);
    seenNames.add(entry.name);
    if (typeof entry.topic !== "string" || !isTopic(entry.topic)) {
      throw new Error(`Stream '${entry.name}' needs a valid topic name`);
    }

    let builtin: BuiltinStreamName | undefined;
    let exec: string | undefined;
    let args: string[] = [];

    if (entry.builtin !== undefined) {
      if (typeof entry.builtin !== "string" || !BUILTIN_STREAMS.has(entry.builtin as BuiltinStreamName)) {
        throw new Error(`Stream '${entry.name}' has unknown builtin '${String(entry.builtin)}' (expected github-webhook, webhook-stream, or prometheus-webhook)`);
      }
      if (entry.exec !== undefined) throw new Error(`Stream '${entry.name}' cannot specify both builtin and exec`);
      builtin = entry.builtin as BuiltinStreamName;
      if (builtin === "webhook-stream" || builtin === "prometheus-webhook") {
        exec = process.execPath;
        const extraArgs = entry.args === undefined ? [] : (Array.isArray(entry.args) && entry.args.every((a) => typeof a === "string") ? entry.args : null);
        if (!extraArgs) throw new Error(`Stream '${entry.name}' args must be an array of strings`);
        args = [resolveBuiltinPluginScript(builtin === "prometheus-webhook" ? "prometheus" : "webhook"), ...extraArgs];
      }
    } else {
      if (typeof entry.exec !== "string" || !isAbsolute(entry.exec)) {
        throw new Error(`Stream '${entry.name}' needs an absolute exec path (or builtin: "github-webhook"|"webhook-stream"|"prometheus-webhook")`);
      }
      exec = entry.exec;
      if (entry.args !== undefined && (!Array.isArray(entry.args) || !entry.args.every((a) => typeof a === "string"))) {
        throw new Error(`Stream '${entry.name}' args must be an array of strings`);
      }
      args = (entry.args as string[] | undefined) ?? [];
    }

    const cwd = entry.cwd === undefined ? stateDir : entry.cwd;
    if (typeof cwd !== "string" || !isAbsolute(cwd)) throw new Error(`Stream '${entry.name}' cwd must be an absolute path`);
    const { env } = resolveEnvWithSecrets(entry.env, configDir, `Stream '${entry.name}'`);
    const parseCsv = (rawCsv: string | undefined): string[] =>
      rawCsv ? rawCsv.split(",").map((s) => s.trim()).filter(Boolean) : [];
    const stringArray = (v: unknown, label: string): string[] | undefined => {
      if (v === undefined) return undefined;
      if (!Array.isArray(v) || !v.every((x) => typeof x === "string")) {
        throw new Error(`Stream '${entry.name}' ${label} must be an array of strings`);
      }
      return v.map((s) => s.trim()).filter(Boolean);
    };
    let scope: RouterStreamScope | undefined;
    const rawScope = object(entry.scope) ? entry.scope : undefined;
    const scopeRepos = [
      ...(stringArray(rawScope?.repos, "scope.repos") ?? []),
      ...parseCsv(env.GITHUB_REPOS ?? env.GITHUB_ALLOWED_REPOS),
    ];
    const scopeOrgs = [
      ...(stringArray(rawScope?.orgs, "scope.orgs") ?? []),
      ...parseCsv(env.GITHUB_ORGS ?? env.GITHUB_ALLOWED_ORGS),
    ];
    const scopeSubjects = stringArray(rawScope?.subjects, "scope.subjects") ?? [];
    if (scopeRepos.length > 0 || scopeOrgs.length > 0 || scopeSubjects.length > 0) {
      scope = {
        ...(scopeRepos.length > 0 ? { repos: [...new Set(scopeRepos)] } : {}),
        ...(scopeOrgs.length > 0 ? { orgs: [...new Set(scopeOrgs)] } : {}),
        ...(scopeSubjects.length > 0 ? { subjects: [...new Set(scopeSubjects)] } : {}),
      };
    }
    return {
      name: entry.name,
      topic: entry.topic,
      ...(builtin ? { builtin } : {}),
      ...(exec ? { exec } : {}),
      args,
      env,
      cwd,
      ...(scope ? { scope } : {}),
    };
  });
}

export function resolveBuiltinPluginScript(builtin: BuiltinPluginName | "prometheus"): string {
  const here = dirname(fileURLToPath(import.meta.url));
  const pkgRoot = here.endsWith(join("dist", "src")) ? resolve(here, "..", "..") : resolve(here, "..");
  const script = join(pkgRoot, "plugins", builtin, "index.mjs");
  if (!existsSync(script)) throw new Error(`Built-in plugin '${builtin}' script not found at ${script}`);
  return script;
}

function intInRange(label: string, value: unknown, fallback: number, min: number, max: number): number {
  const resolved = value === undefined ? fallback : value;
  if (typeof resolved !== "number" || !Number.isInteger(resolved) || resolved < min || resolved > max) {
    throw new Error(`${label} must be an integer between ${min} and ${max}`);
  }
  return resolved;
}

function parsePlugins(raw: unknown, configDir: string, stateDir: string): AgentPluginConfig[] {
  if (raw === undefined) return [];
  if (!Array.isArray(raw)) throw new Error("plugins must be an array");
  const seenNames = new Set<string>();
  return raw.map((entry): AgentPluginConfig => {
    if (!object(entry) || typeof entry.name !== "string" || !PLUGIN_NAME.test(entry.name)) {
      throw new Error("Each plugin needs a valid lowercase name");
    }
    if (seenNames.has(entry.name)) throw new Error(`Duplicate plugin name '${entry.name}'`);
    seenNames.add(entry.name);

    let exec: string;
    let args: string[];
    let builtin: BuiltinPluginName | undefined;
    if (entry.builtin !== undefined) {
      if (typeof entry.builtin !== "string" || !BUILTIN_PLUGINS.has(entry.builtin as BuiltinPluginName)) {
        throw new Error(`Plugin '${entry.name}' has unknown builtin '${String(entry.builtin)}' (expected slack, telegram, whatsapp, or webhook)`);
      }
      if (entry.exec !== undefined) throw new Error(`Plugin '${entry.name}' cannot specify both builtin and exec`);
      builtin = entry.builtin as BuiltinPluginName;
      exec = process.execPath;
      const extraArgs = entry.args === undefined ? [] : (Array.isArray(entry.args) && entry.args.every((a) => typeof a === "string") ? entry.args : null);
      if (!extraArgs) throw new Error(`Plugin '${entry.name}' args must be an array of strings`);
      args = [resolveBuiltinPluginScript(builtin), ...extraArgs];
    } else {
      if (typeof entry.exec !== "string" || !isAbsolute(entry.exec)) {
        throw new Error(`Plugin '${entry.name}' needs an absolute exec path (or builtin: "slack"|"telegram"|"whatsapp"|"webhook")`);
      }
      exec = entry.exec;
      if (entry.args !== undefined && (!Array.isArray(entry.args) || !entry.args.every((a) => typeof a === "string"))) {
        throw new Error(`Plugin '${entry.name}' args must be an array of strings`);
      }
      args = (entry.args as string[] | undefined) ?? [];
    }

    const cwd = entry.cwd === undefined ? stateDir : entry.cwd;
    if (typeof cwd !== "string" || !isAbsolute(cwd)) throw new Error(`Plugin '${entry.name}' cwd must be an absolute path`);

    const { env } = resolveEnvWithSecrets(entry.env, configDir, `Plugin '${entry.name}'`);

    if (!Array.isArray(entry.targets) || entry.targets.length === 0) {
      throw new Error(`Plugin '${entry.name}' must define at least one target`);
    }
    const seenTargets = new Set<string>();
    const targets = entry.targets.map((t): AgentPluginTarget => {
      if (!object(t) || typeof t.name !== "string" || !PLUGIN_NAME.test(t.name)) {
        throw new Error(`Invalid target name in plugin '${entry.name}'`);
      }
      if (seenTargets.has(t.name)) throw new Error(`Duplicate target '${t.name}' in plugin '${entry.name}'`);
      seenTargets.add(t.name);

      const sessionId = typeof t.sessionId === "string" && sessionIdPattern.test(t.sessionId) ? t.sessionId : undefined;
      const handle = typeof t.handle === "string" && handlePattern.test(t.handle) ? t.handle : undefined;
      const threadId = typeof t.threadId === "string" && t.threadId.length > 0 && t.threadId.length <= 200 ? t.threadId : undefined;
      if (!sessionId && !handle && !threadId) {
        throw new Error(`Target '${t.name}' in plugin '${entry.name}' needs sessionId, handle, or threadId`);
      }
      return {
        name: t.name,
        ...(sessionId ? { sessionId } : {}),
        ...(handle ? { handle } : {}),
        ...(threadId ? { threadId } : {}),
        coalesceSeconds: intInRange(`${entry.name}/${t.name} coalesceSeconds`, t.coalesceSeconds, 5, 0, 600),
        maxWaitSeconds: intInRange(`${entry.name}/${t.name} maxWaitSeconds`, t.maxWaitSeconds, 30, 1, 3600),
        wakesPerHour: intInRange(`${entry.name}/${t.name} wakesPerHour`, t.wakesPerHour, 120, 1, 3600),
      };
    });

    return { name: entry.name, ...(builtin ? { builtin } : {}), exec, args, env, cwd, targets };
  });
}

export function loadConfig(path: string): Config {
  const raw: unknown = JSON.parse(readFileSync(path, "utf8"));
  const base = dirname(resolve(path));
  if (!object(raw) || typeof raw.connectorId !== "string" || !connectorPattern.test(raw.connectorId) ||
      typeof raw.stateDir !== "string" || raw.stateDir.length === 0 || !Array.isArray(raw.routers)) {
    throw new Error("Expected connectorId, stateDir and routers");
  }
  const routers = raw.routers.map((link: unknown): RouterConfig => {
    if (!object(link) || typeof link.name !== "string" || !/^[a-z][a-z0-9-]{0,31}$/.test(link.name) ||
        typeof link.url !== "string" || typeof link.tokenFile !== "string") {
      throw new Error("Each router needs name, url and tokenFile");
    }
    const url = new URL(link.url);
    const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
    if (!(url.protocol === "https:" || (url.protocol === "http:" && loopback)) ||
        url.username || url.password || url.pathname !== "/" || url.search || url.hash) {
      throw new Error(`Router ${link.name} must be an HTTPS origin or loopback HTTP origin`);
    }
    const file = resolve(base, link.tokenFile);
    const stat = lstatSync(file);
    if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0 ||
        (process.getuid !== undefined && stat.uid !== process.getuid())) {
      throw new Error(`Token file for ${link.name} must be a private regular file owned by the current user (chmod 600)`);
    }
    const token = readFileSync(file, "utf8").trim();
    if (token.length === 0 || !/^[!-~]+$/.test(token)) throw new Error(`Invalid token file for ${link.name}`);
    return { name: link.name, url: url.origin, token };
  });
  if (!routers.some(({ name }) => name === "primary") ||
      new Set(routers.map(({ name }) => name)).size !== routers.length ||
      new Set(routers.map(({ url }) => url)).size !== routers.length ||
      new Set(routers.map(({ token }) => token)).size !== routers.length) {
    throw new Error("Set a primary router and use unique names, origins and credentials");
  }
  const directory = resolve(base, raw.stateDir);
  let localRouter: LocalRouterConfig | undefined;
  if (raw.localRouter !== undefined) {
    if (!object(raw.localRouter)) throw new Error("localRouter must be an object");
    const host = raw.localRouter.host ?? "127.0.0.1";
    const port = raw.localRouter.port ?? 8790;
    const db = raw.localRouter.db ?? "router/router.sqlite";
    const audit = raw.localRouter.audit;
    const exposure = raw.localRouter.exposure;
    if (typeof host !== "string" || !["127.0.0.1", "::1", "localhost"].includes(host)) {
      throw new Error("localRouter.host must be loopback (127.0.0.1, ::1, or localhost)");
    }
    if (typeof port !== "number" || !Number.isInteger(port) || port < 0 || port > 65535) {
      throw new Error("localRouter.port must be an integer between 0 and 65535");
    }
    if (typeof db !== "string" || db.length === 0) {
      throw new Error("localRouter.db must be a non-empty path");
    }
    if (audit !== undefined && (typeof audit !== "string" || audit.length === 0)) {
      throw new Error("localRouter.audit must be a non-empty path");
    }
    if (exposure !== undefined && exposure !== "private" && exposure !== "public") {
      throw new Error("localRouter.exposure must be 'private' or 'public'");
    }
    const streams = parseStreams(raw.localRouter.streams, base, directory);
    localRouter = {
      host,
      port,
      dbPath: resolve(base, db),
      ...(audit ? { auditPath: resolve(base, audit) } : {}),
      ...(exposure ? { exposure } : {}),
      ...(streams.length > 0 ? { streams } : {}),
    };
  }
  const plugins = parsePlugins(raw.plugins, base, directory);
  return {
    connectorId: raw.connectorId,
    directory,
    routers,
    ...(localRouter ? { localRouter } : {}),
    ...(plugins.length > 0 ? { plugins } : {}),
  };
}

const codexRemotePattern = /^(?:wss?:\/\/[^\s]+|unix:\/\/[^\s]*)$/;

export function parseBackend(raw: Record<string, unknown>): Backend {
  if (raw.kind === "antigravity") return { kind: "antigravity" };
  if (raw.kind === "cursor") return { kind: "cursor" };
  if (raw.kind === "opencode") return { kind: "opencode" };
  if (raw.kind === "gemini") return { kind: "gemini" };
  if (raw.kind === "openclaw") return { kind: "openclaw" };
  if (raw.kind === "claude") return { kind: "claude", ...(raw.channel === true ? { channel: true } : {}) };
  if (raw.bin !== undefined && (typeof raw.bin !== "string" || !isAbsolute(raw.bin))) {
    throw new Error("Backend bin must be an absolute path");
  }
  if (raw.kind === "codex") {
    const threadId = raw.threadId;
    if (threadId !== undefined && (typeof threadId !== "string" || threadId.length === 0 || threadId.length > 128)) {
      throw new Error("Invalid Codex thread ID");
    }
    const codexHome = raw.codexHome;
    if (codexHome !== undefined && (typeof codexHome !== "string" || codexHome.length === 0 || codexHome.includes("\0"))) {
      throw new Error("Invalid Codex home directory");
    }
    const remote = raw.remote;
    if (remote !== undefined && (typeof remote !== "string" || !codexRemotePattern.test(remote))) {
      throw new Error("Codex remote must be ws://, wss://, or unix://");
    }
    if (raw.resume !== undefined && typeof raw.resume !== "boolean") {
      throw new Error("Invalid Codex resume option");
    }
    if (raw.queue !== undefined && typeof raw.queue !== "boolean") {
      throw new Error("Invalid Codex queue option");
    }
    return {
      kind: "codex",
      ...(threadId ? { threadId } : {}),
      ...(codexHome ? { codexHome } : {}),
      bin: raw.bin ?? "codex",
      resume: raw.resume === true,
      ...(remote ? { remote } : {}),
      ...(raw.queue !== undefined ? { queue: raw.queue } : {}),
    };
  }
  if (raw.kind === "herdr" && typeof raw.terminalId === "string" && /^t[a-z0-9]+$/.test(raw.terminalId) &&
      typeof raw.createdMs === "number" && Number.isSafeInteger(raw.createdMs) && raw.createdMs > 0 &&
      typeof raw.pid === "number" && Number.isSafeInteger(raw.pid) && raw.pid > 0 &&
      typeof raw.app === "string" && raw.app.length > 0) {
    return { kind: "herdr", terminalId: raw.terminalId, createdMs: raw.createdMs, pid: raw.pid, app: raw.app, bin: raw.bin ?? "hc" };
  }
  throw new Error("Invalid backend configuration");
}
