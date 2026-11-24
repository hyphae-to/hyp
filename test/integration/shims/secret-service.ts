import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { delimiter, join, resolve } from "node:path";

export type SecretToolFailMode = null | "store" | "lookup" | "clear" | "all";

export interface SecretToolInvocation {
  readonly timestamp: number;
  readonly subcommand: string;
  readonly args: readonly string[];
  readonly argvJoined: string;
  readonly label: string | null;
  readonly attributes: Readonly<Record<string, string>>;
  readonly stdin: string;
  readonly stdinLen: number;
}

export interface VirtualSecretEntry {
  readonly service: string;
  readonly account: string;
  readonly label: string;
  readonly value: string;
  readonly updatedAt: number;
}

export interface VirtualSecretStore {
  get(service: string, account: string): VirtualSecretEntry | undefined;
  has(service: string, account: string): boolean;
  set(service: string, account: string, value: string, label?: string): void;
  delete(service: string, account: string): boolean;
  entries(): VirtualSecretEntry[];
  clear(): void;
  readonly size: number;
}

export interface VirtualSecretService {
  readonly binDir: string;
  readonly stateDir: string;
  /** Returns a shallow copy of `baseEnv` with `binDir` prepended to `PATH`. */
  envWithPath(baseEnv?: NodeJS.ProcessEnv): NodeJS.ProcessEnv;
  /** Live file-backed view of entries stored by the virtual `secret-tool`. */
  readonly store: VirtualSecretStore;
  /** Live chronological log of every `secret-tool` invocation across sync and child processes. */
  readonly invocations: SecretToolInvocation[];
  /** Clears recorded invocation log entries. */
  clearInvocations(): void;
  /** Injects deterministic failures into `secret-tool` subcommands (or clears with `null`). */
  setFailMode(mode: SecretToolFailMode, exitCode?: number, stderr?: string): void;
  /** Removes the virtual Secret Service directory and scripts. */
  close(): void;
}

type RawStoreMap = Record<string, VirtualSecretEntry>;

interface FaultConfig {
  readonly mode: Exclude<SecretToolFailMode, null>;
  readonly exitCode: number;
  readonly stderr: string;
}

function storeKey(service: string, account: string): string {
  return `${service}\u0000${account}`;
}

function shellQuote(value: string): string {
  return `'${value.replace(/'/g, "'\\''")}'`;
}

function atomicWriteJson(filePath: string, data: unknown): void {
  const tmpPath = `${filePath}.${process.pid}.${Date.now()}.${Math.random().toString(16).slice(2)}.tmp`;
  writeFileSync(tmpPath, JSON.stringify(data, null, 2) + "\n", { mode: 0o600 });
  chmodSync(tmpPath, 0o600);
  renameSync(tmpPath, filePath);
}

function buildSecretToolScript(stateDir: string): string {
  return `import { appendFileSync, chmodSync, existsSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const stateDir = ${JSON.stringify(stateDir)};
const storePath = join(stateDir, "store.json");
const invocationsPath = join(stateDir, "invocations.ndjson");
const faultPath = join(stateDir, "fault.json");

function readJsonFile(path, fallback) {
  if (!existsSync(path)) return fallback;
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch {
    return fallback;
  }
}

function writeJsonAtomic(path, data) {
  const tmp = \`\${path}.\${process.pid}.\${Date.now()}.\${Math.random().toString(16).slice(2)}.tmp\`;
  writeFileSync(tmp, JSON.stringify(data, null, 2) + "\\n", { mode: 0o600 });
  chmodSync(tmp, 0o600);
  renameSync(tmp, path);
}

async function readAllStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk)));
  }
  return Buffer.concat(chunks).toString("utf8");
}

function parseArgs(rawArgs) {
  const subcommand = rawArgs[0] ?? "";
  let label = null;
  const positional = [];
  for (let i = 1; i < rawArgs.length; i++) {
    const arg = rawArgs[i];
    if (arg.startsWith("--label=")) {
      label = arg.slice("--label=".length);
    } else if (arg === "--label" && i + 1 < rawArgs.length) {
      label = rawArgs[++i];
    } else if (arg.startsWith("--")) {
      continue;
    } else {
      positional.push(arg);
    }
  }
  const attributes = {};
  for (let i = 0; i + 1 < positional.length; i += 2) {
    attributes[positional[i]] = positional[i + 1];
  }
  return { subcommand, label, attributes };
}

const rawArgs = process.argv.slice(2);
const { subcommand, label, attributes } = parseArgs(rawArgs);
const stdin = subcommand === "store" ? await readAllStdin() : "";

const record = {
  timestamp: Date.now(),
  subcommand,
  args: rawArgs,
  argvJoined: rawArgs.join(" "),
  label,
  attributes,
  stdin,
  stdinLen: Buffer.byteLength(stdin, "utf8"),
};
appendFileSync(invocationsPath, JSON.stringify(record) + "\\n", { mode: 0o600 });

const fault = readJsonFile(faultPath, null);
if (fault && (fault.mode === "all" || fault.mode === subcommand)) {
  const msg = typeof fault.stderr === "string" && fault.stderr.length > 0
    ? fault.stderr
    : \`secret-tool: simulated \${subcommand || "command"} failure\`;
  process.stderr.write(msg.endsWith("\\n") ? msg : msg + "\\n");
  process.exit(typeof fault.exitCode === "number" ? fault.exitCode : 1);
}

const service = attributes.service ?? "";
const account = attributes.account ?? "";
const key = \`\${service}\\u0000\${account}\`;

if (subcommand === "store") {
  if (!service || !account) {
    process.stderr.write("secret-tool: store requires service and account attributes\\n");
    process.exit(2);
  }
  const store = readJsonFile(storePath, {});
  store[key] = {
    service,
    account,
    label: label ?? "",
    value: stdin,
    updatedAt: Date.now(),
  };
  writeJsonAtomic(storePath, store);
  process.exit(0);
}

if (subcommand === "lookup") {
  if (!service || !account) {
    process.stderr.write("secret-tool: lookup requires service and account attributes\\n");
    process.exit(2);
  }
  const store = readJsonFile(storePath, {});
  const entry = store[key];
  if (!entry || typeof entry.value !== "string") {
    process.exit(1);
  }
  process.stdout.write(entry.value);
  process.exit(0);
}

if (subcommand === "clear") {
  if (!service || !account) {
    process.stderr.write("secret-tool: clear requires service and account attributes\\n");
    process.exit(2);
  }
  const store = readJsonFile(storePath, {});
  if (Object.prototype.hasOwnProperty.call(store, key)) {
    delete store[key];
    writeJsonAtomic(storePath, store);
  }
  process.exit(0);
}

process.stderr.write(\`secret-tool: unknown subcommand '\${subcommand}'\\n\`);
process.exit(2);
`;
}

/**
 * Creates a cross-platform virtual Freedesktop Secret Service (`secret-tool`) shim backed by
 * atomic JSON/NDJSON files on disk inside `baseDir`.
 *
 * Backing the shim on disk (rather than an in-process HTTP server) ensures both in-process
 * synchronous `spawnSync("secret-tool", ...)` calls and child `hyp` CLI / daemon processes work
 * seamlessly on macOS and Linux with zero event-loop deadlocks.
 */
export function startVirtualSecretService(baseDir: string): VirtualSecretService {
  const rootDir = join(resolve(baseDir), "vss");
  const binDir = join(rootDir, "bin");
  const stateDir = join(rootDir, "state");
  mkdirSync(binDir, { recursive: true, mode: 0o700 });
  mkdirSync(stateDir, { recursive: true, mode: 0o700 });

  const storePath = join(stateDir, "store.json");
  const invocationsPath = join(stateDir, "invocations.ndjson");
  const faultPath = join(stateDir, "fault.json");
  const scriptPath = join(stateDir, "secret-tool.mjs");
  const wrapperPath = join(binDir, "secret-tool");

  atomicWriteJson(storePath, {});
  writeFileSync(invocationsPath, "", { mode: 0o600 });
  chmodSync(invocationsPath, 0o600);

  writeFileSync(scriptPath, buildSecretToolScript(stateDir), { mode: 0o700 });
  chmodSync(scriptPath, 0o700);

  const wrapper = `#!/bin/sh\nexec ${shellQuote(process.execPath)} ${shellQuote(scriptPath)} "$@"\n`;
  writeFileSync(wrapperPath, wrapper, { mode: 0o755 });
  chmodSync(wrapperPath, 0o755);

  const readStoreMap = (): RawStoreMap => {
    if (!existsSync(storePath)) return {};
    try {
      return JSON.parse(readFileSync(storePath, "utf8")) as RawStoreMap;
    } catch {
      return {};
    }
  };

  const writeStoreMap = (map: RawStoreMap): void => {
    atomicWriteJson(storePath, map);
  };

  const store: VirtualSecretStore = {
    get(service: string, account: string): VirtualSecretEntry | undefined {
      return readStoreMap()[storeKey(service, account)];
    },
    has(service: string, account: string): boolean {
      return readStoreMap()[storeKey(service, account)] !== undefined;
    },
    set(service: string, account: string, value: string, label = `Hyphae: ${account}`): void {
      const map = readStoreMap();
      map[storeKey(service, account)] = {
        service,
        account,
        label,
        value,
        updatedAt: Date.now(),
      };
      writeStoreMap(map);
    },
    delete(service: string, account: string): boolean {
      const map = readStoreMap();
      const key = storeKey(service, account);
      if (!(key in map)) return false;
      delete map[key];
      writeStoreMap(map);
      return true;
    },
    entries(): VirtualSecretEntry[] {
      return Object.values(readStoreMap());
    },
    clear(): void {
      writeStoreMap({});
    },
    get size(): number {
      return Object.keys(readStoreMap()).length;
    },
  };

  const readInvocations = (): SecretToolInvocation[] => {
    if (!existsSync(invocationsPath)) return [];
    const raw = readFileSync(invocationsPath, "utf8");
    const out: SecretToolInvocation[] = [];
    for (const line of raw.split(/\r?\n/)) {
      if (!line.trim()) continue;
      try {
        out.push(JSON.parse(line) as SecretToolInvocation);
      } catch {}
    }
    return out;
  };

  return {
    binDir,
    stateDir,
    envWithPath(baseEnv: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
      const currentPath = baseEnv.PATH ?? process.env.PATH ?? "";
      return {
        ...baseEnv,
        PATH: currentPath ? `${binDir}${delimiter}${currentPath}` : binDir,
      };
    },
    store,
    get invocations(): SecretToolInvocation[] {
      return readInvocations();
    },
    clearInvocations(): void {
      writeFileSync(invocationsPath, "", { mode: 0o600 });
      chmodSync(invocationsPath, 0o600);
    },
    setFailMode(mode: SecretToolFailMode, exitCode = 1, stderr = ""): void {
      if (mode === null) {
        rmSync(faultPath, { force: true });
        return;
      }
      const cfg: FaultConfig = { mode, exitCode, stderr };
      atomicWriteJson(faultPath, cfg);
    },
    close(): void {
      rmSync(rootDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
    },
  };
}
