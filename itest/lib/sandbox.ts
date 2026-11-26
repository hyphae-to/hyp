/**
 * Hermetic per-test sandbox, strict env scrubbing, POSIX process-group reaper,
 * host-config canary, and failure forensics bundler.
 *
 * Security & hermeticity invariants:
 * - Never touches host `~/.config/hyphae`, `~/.openclaw`, `~/.claude`, `~/.codex`, or OS Keychain.
 * - Uses an allowlist-only scrubbed environment stripping all ambient harness & LLM vars (B5).
 * - Uses short `/tmp/hyp-it-XXXXXX/` paths so Unix socket paths stay well below macOS 104-byte SUN_LEN.
 * - Guarantees `-pgid` process-group termination on teardown, timeout, or process exit.
 */

import { spawn } from "node:child_process";
import type { ChildProcess, SpawnOptions } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const REPO_ROOT = path.resolve(__dirname, "..", "..");
export const FORENSICS_ROOT = path.join(REPO_ROOT, "itest-forensics");

/** Real host home captured once at module load, BEFORE any sandbox env manipulation. */
export const REAL_HOST_HOME = os.homedir();

export interface SandboxPaths {
  rootDir: string;
  homeDir: string;
  xdgConfigDir: string;
  xdgStateDir: string;
  xdgDataDir: string;
  xdgRunDir: string;
  hyphaeConfigDir: string;
  hyphaeStateDir: string;
  socketPath: string;
  workspaceDir: string;
  binDir: string;
  logsDir: string;
  tmpDir: string;
}

export interface SandboxOptions {
  /** Base environment to scrub (defaults to `process.env`; override to test poisoned env). */
  sourceEnv?: Record<string, string | undefined>;
  /** Additional directories to prepend to scrubbed `PATH` (e.g., harness binary dirs). */
  extraPathDirs?: string[];
  /** Additional explicit env overrides applied AFTER scrubbing. */
  extraEnv?: Record<string, string>;
  /** Set `HTTP_PROXY`/`HTTPS_PROXY` to `http://127.0.0.1:1` with `NO_PROXY=127.0.0.1,localhost,::1`. Default: true. */
  egressBlackhole?: boolean;
  /** Extra host file paths to monitor in `HostCanary`. */
  extraCanaryPaths?: string[];
}

export interface FileStatSnapshot {
  path: string;
  exists: boolean;
  ino?: number;
  size?: number;
  mtimeMs?: number;
  ctimeMs?: number;
}

export interface TrackedProcess {
  id: number;
  label: string;
  pid: number;
  pgid: number;
  child: ChildProcess;
  logPath: string;
  stdout: string;
  stderr: string;
  exited: boolean;
  exitCode: number | null;
  signal: NodeJS.Signals | null;
  exitPromise: Promise<{ code: number | null; signal: NodeJS.Signals | null }>;
}

const DEFAULT_HOST_CANARY_RELPATHS = [
  ".config/hyphae/node.json",
  ".openclaw/openclaw.json",
  ".claude/settings.json",
  ".claude.json",
  ".codex/config.toml",
  ".codex/hooks.json",
  ".config/opencode/opencode.json",
  ".config/herdr-core/config.toml",
  ".config/herdr-app/keys.json",
  ".gemini/settings.json",
];

/** Exact safe system environment keys allowed through the allowlist scrubber. */
const ALLOWED_BASE_ENV_KEYS = new Set(["USER", "LOGNAME", "SHELL", "TZ"]);

/**
 * Prefixes/keys that MUST NEVER survive scrubbing (documented explicitly for B5 audit clarity;
 * enforced structurally because `buildScrubbedEnv` starts from an empty allowlist map!).
 */
export const FORBIDDEN_AMBIENT_PREFIXES = [
  "CLAUDE",
  "HC_",
  "HERDR_",
  "CODEX_",
  "OPENCLAW_",
  "OPENCODE_",
  "T3CODE_",
  "T3_",
  "GEMINI_",
  "HYPHAE_",
  "AGENTS_MESH_",
  "ANTHROPIC_",
  "OPENAI_",
  "GOOGLE_",
  "TAILSCALE_",
] as const;

export const FORBIDDEN_AMBIENT_KEYS = [
  "SSH_AUTH_SOCK",
  "DBUS_SESSION_BUS_ADDRESS",
  "CLAUDECODE",
  "CLAUDE_ENV_FILE",
  "CLAUDE_CONFIG_DIR",
  "HYPHAE_SESSION_ID",
  "HYPHAE_SESSION_TOKEN",
  "HC_TERMINAL_ID",
  "OPENCLAW_STATE_DIR",
  "OPENCLAW_CONFIG_PATH",
  "OPENCLAW_HOME",
] as const;

function buildSafePath(sandboxBinDir: string, extraDirs: string[] = []): string {
  const nodeBinDir = path.dirname(process.execPath);
  const ordered = [
    sandboxBinDir,
    nodeBinDir,
    ...extraDirs.filter(Boolean),
    "/opt/homebrew/bin",
    "/usr/local/bin",
    "/usr/bin",
    "/bin",
    "/usr/sbin",
    "/sbin",
  ];
  const seen = new Set<string>();
  const out: string[] = [];
  for (const dir of ordered) {
    if (!dir || seen.has(dir)) continue;
    seen.add(dir);
    out.push(dir);
  }
  return out.join(path.delimiter);
}

/**
 * Builds a strictly hermetic, allowlist-only environment for child processes.
 * All ambient `CLAUDE*`, `HC_*`, `HERDR_*`, `CODEX_*`, `OPENCLAW_*`, `HYPHAE_*`,
 * `ANTHROPIC_*`, `OPENAI_*`, `GEMINI_*` variables in `sourceEnv` are guaranteed stripped.
 */
export function buildScrubbedEnv(
  sourceEnv: Record<string, string | undefined>,
  paths: SandboxPaths,
  options: {
    extraPathDirs?: string[];
    extraEnv?: Record<string, string>;
    egressBlackhole?: boolean;
  } = {},
): Record<string, string> {
  const env: Record<string, string> = {};

  for (const key of ALLOWED_BASE_ENV_KEYS) {
    const val = sourceEnv[key];
    if (typeof val === "string" && val.length > 0) {
      env[key] = val;
    }
  }

  env.PATH = buildSafePath(paths.binDir, options.extraPathDirs);
  env.HOME = paths.homeDir;
  env.TMPDIR = paths.tmpDir;
  env.XDG_CONFIG_HOME = paths.xdgConfigDir;
  env.XDG_STATE_HOME = paths.xdgStateDir;
  env.XDG_DATA_HOME = paths.xdgDataDir;
  env.XDG_RUNTIME_DIR = paths.xdgRunDir;
  env.HYPHAE_CONFIG_DIR = paths.hyphaeConfigDir;
  env.HYPHAE_STATE_DIR = paths.hyphaeStateDir;
  env.HYPHAE_SOCKET = paths.socketPath;
  env.HYPHAE_SECRET_BACKEND = "file";
  env.HYPHAE_TAILSCALE_BIN = "none";
  env.TAILSCALE_BIN = "none";
  env.HYPHAE_NO_OPEN = "1";
  env.HYPHAE_NO_SERVICE = "1";
  env.HYPHAE_WIZARD_NO_ANIM = "1";
  env.CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC = "1";
  env.TERM = "dumb";
  env.LANG = "C.UTF-8";
  env.LC_ALL = "C.UTF-8";
  env.NO_PROXY = "127.0.0.1,localhost,::1";
  env.no_proxy = "127.0.0.1,localhost,::1";

  if (options.egressBlackhole !== false) {
    env.HTTP_PROXY = "http://127.0.0.1:1";
    env.HTTPS_PROXY = "http://127.0.0.1:1";
    env.http_proxy = "http://127.0.0.1:1";
    env.https_proxy = "http://127.0.0.1:1";
  }

  if (options.extraEnv) {
    for (const [k, v] of Object.entries(options.extraEnv)) {
      env[k] = v;
    }
  }

  return env;
}

function statSnapshot(targetPath: string): FileStatSnapshot {
  try {
    const st = fs.lstatSync(targetPath);
    return {
      path: targetPath,
      exists: true,
      ino: st.ino,
      size: st.size,
      mtimeMs: st.mtimeMs,
      ctimeMs: st.ctimeMs,
    };
  } catch {
    return { path: targetPath, exists: false };
  }
}

/**
 * Monitors host configuration files before and after a test run, failing loudly if
 * any host file was created, deleted, or modified during the test.
 */
export class HostCanary {
  readonly snapshots: FileStatSnapshot[];

  private constructor(snapshots: FileStatSnapshot[]) {
    this.snapshots = snapshots;
  }

  static capture(extraPaths: string[] = [], hostHome: string = REAL_HOST_HOME): HostCanary {
    const watched = [
      ...DEFAULT_HOST_CANARY_RELPATHS.map((rel) => path.join(hostHome, rel)),
      ...extraPaths,
    ];
    const unique = [...new Set(watched)];
    return new HostCanary(unique.map(statSnapshot));
  }

  diff(): Array<{ path: string; before: FileStatSnapshot; after: FileStatSnapshot }> {
    const diffs: Array<{ path: string; before: FileStatSnapshot; after: FileStatSnapshot }> = [];
    for (const before of this.snapshots) {
      const after = statSnapshot(before.path);
      const changed =
        before.exists !== after.exists ||
        before.ino !== after.ino ||
        before.size !== after.size ||
        before.mtimeMs !== after.mtimeMs;
      if (changed) {
        diffs.push({ path: before.path, before, after });
      }
    }
    return diffs;
  }

  assertUntouched(): void {
    const diffs = this.diff();
    if (diffs.length > 0) {
      const detail = diffs
        .map(
          (d) =>
            `  - ${d.path}: before=${JSON.stringify(d.before)} after=${JSON.stringify(d.after)}`,
        )
        .join("\n");
      throw new Error(`HostCanary VIOLATION — test mutated host config files!\n${detail}`);
    }
  }
}

const GLOBAL_ACTIVE_REAPERS = new Set<ProcessReaper>();
let globalSignalsInstalled = false;

function killProcessGroupSync(pid: number, signal: NodeJS.Signals): void {
  if (!pid || pid <= 0) return;
  if (process.platform !== "win32") {
    try {
      process.kill(-pid, signal);
      return;
    } catch {
      // Fallback to single PID below.
    }
  }
  try {
    process.kill(pid, signal);
  } catch {
    // Already exited.
  }
}

function installGlobalReaperHooks(): void {
  if (globalSignalsInstalled) return;
  globalSignalsInstalled = true;

  const emergencyReapSync = () => {
    for (const reaper of GLOBAL_ACTIVE_REAPERS) {
      reaper.forceKillAllSync();
    }
  };

  process.on("exit", emergencyReapSync);
  for (const sig of ["SIGINT", "SIGTERM"] as const) {
    process.on(sig, () => {
      emergencyReapSync();
      process.exit(sig === "SIGINT" ? 130 : 143);
    });
  }
}

/**
 * Spawns child processes in dedicated POSIX process groups (`detached: true`) and
 * guarantees `-pgid` `SIGTERM` -> `SIGKILL` cleanup with zero zombie survivors.
 */
export class ProcessReaper {
  private readonly logsDir: string;
  private readonly processes = new Map<number, TrackedProcess>();
  private nextId = 1;

  constructor(logsDir: string) {
    this.logsDir = logsDir;
    fs.mkdirSync(logsDir, { recursive: true });
    installGlobalReaperHooks();
    GLOBAL_ACTIVE_REAPERS.add(this);
  }

  spawn(
    label: string,
    command: string,
    args: string[],
    options: SpawnOptions & { logFileName?: string } = {},
  ): TrackedProcess {
    const id = this.nextId++;
    const safeLabel = label.replace(/[^a-zA-Z0-9._-]/g, "_");
    const logPath = path.join(this.logsDir, options.logFileName || `${safeLabel}-${id}.log`);
    const logStream = fs.createWriteStream(logPath, { flags: "a" });

    const { logFileName: _unused, ...spawnOpts } = options;
    const child = spawn(command, args, {
      ...spawnOpts,
      detached: process.platform !== "win32",
      stdio: spawnOpts.stdio ?? ["ignore", "pipe", "pipe"],
    });

    const pid = child.pid ?? 0;
    let resolveExit!: (v: { code: number | null; signal: NodeJS.Signals | null }) => void;
    const exitPromise = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>(
      (resolve) => {
        resolveExit = resolve;
      },
    );

    const tracked: TrackedProcess = {
      id,
      label,
      pid,
      pgid: pid,
      child,
      logPath,
      stdout: "",
      stderr: "",
      exited: false,
      exitCode: null,
      signal: null,
      exitPromise,
    };

    const MAX_MEM_LOG = 512 * 1024;
    const appendMem = (current: string, chunk: string) => {
      const next = current + chunk;
      return next.length > MAX_MEM_LOG ? next.slice(next.length - MAX_MEM_LOG) : next;
    };

    child.stdout?.on("data", (buf: Buffer) => {
      const text = buf.toString("utf8");
      tracked.stdout = appendMem(tracked.stdout, text);
      try {
        logStream.write(text);
      } catch {
        // stream closed
      }
    });
    child.stderr?.on("data", (buf: Buffer) => {
      const text = buf.toString("utf8");
      tracked.stderr = appendMem(tracked.stderr, text);
      try {
        logStream.write(text);
      } catch {
        // stream closed
      }
    });

    const finalize = (code: number | null, signal: NodeJS.Signals | null) => {
      if (tracked.exited) return;
      tracked.exited = true;
      tracked.exitCode = code;
      tracked.signal = signal;
      try {
        logStream.end();
      } catch {
        // ignore
      }
      resolveExit({ code, signal });
    };

    child.once("exit", finalize);
    child.once("error", (err) => {
      tracked.stderr = appendMem(tracked.stderr, `\n[spawn error] ${err.message}\n`);
      finalize(-1, null);
    });

    this.processes.set(id, tracked);
    return tracked;
  }

  list(): TrackedProcess[] {
    return [...this.processes.values()];
  }

  async kill(tracked: TrackedProcess, graceMs = 2_000): Promise<void> {
    if (tracked.exited || tracked.pid <= 0) return;
    killProcessGroupSync(tracked.pgid, "SIGTERM");
    await Promise.race([
      tracked.exitPromise,
      new Promise<void>((resolve) => setTimeout(resolve, graceMs)),
    ]);
    if (!tracked.exited) {
      killProcessGroupSync(tracked.pgid, "SIGKILL");
      await Promise.race([
        tracked.exitPromise,
        new Promise<void>((resolve) => setTimeout(resolve, 1_000)),
      ]);
    }
  }

  async reapAll(graceMs = 2_000): Promise<void> {
    const active = [...this.processes.values()].filter((p) => !p.exited && p.pid > 0);
    await Promise.all(active.map((p) => this.kill(p, graceMs)));
    GLOBAL_ACTIVE_REAPERS.delete(this);
  }

  forceKillAllSync(): void {
    for (const p of this.processes.values()) {
      if (!p.exited && p.pid > 0) {
        killProcessGroupSync(p.pgid, "SIGKILL");
      }
    }
  }
}

export type ForensicsProvider = () => Promise<string | object | null> | string | object | null;

/**
 * Full per-test hermetic sandbox owning TempDir layout, scrubbed env, ProcessReaper,
 * HostCanary, secret registry, and automatic Failure Forensics bundling.
 */
export class Sandbox {
  readonly testName: string;
  readonly paths: SandboxPaths;
  readonly env: Record<string, string>;
  readonly reaper: ProcessReaper;
  readonly hostCanary: HostCanary;
  readonly createdAtMs: number;

  private readonly secrets = new Map<string, string>();
  private readonly secretListeners: Array<(name: string, value: string) => void> = [];
  private readonly forensicsProviders = new Map<string, ForensicsProvider>();
  private readonly teardownHooks: Array<() => Promise<void> | void> = [];
  private cleanedUp = false;

  private constructor(
    testName: string,
    paths: SandboxPaths,
    env: Record<string, string>,
    hostCanary: HostCanary,
  ) {
    this.testName = testName;
    this.paths = paths;
    this.env = env;
    this.reaper = new ProcessReaper(paths.logsDir);
    this.hostCanary = hostCanary;
    this.createdAtMs = Date.now();
  }

  static create(testName: string, options: SandboxOptions = {}): Sandbox {
    const hostCanary = HostCanary.capture(options.extraCanaryPaths);
    // Keep root path short under /tmp so macOS SUN_LEN (104 bytes) is never exceeded for connector.sock.
    const baseTmp = process.platform === "win32" ? os.tmpdir() : "/tmp";
    const rawRoot = fs.mkdtempSync(path.join(baseTmp, "hyp-it-"));
    const rootDir = fs.realpathSync(rawRoot);

    const paths: SandboxPaths = {
      rootDir,
      homeDir: path.join(rootDir, "home"),
      xdgConfigDir: path.join(rootDir, "xdg", "config"),
      xdgStateDir: path.join(rootDir, "xdg", "state"),
      xdgDataDir: path.join(rootDir, "xdg", "data"),
      xdgRunDir: path.join(rootDir, "xdg", "run"),
      hyphaeConfigDir: path.join(rootDir, "h"),
      hyphaeStateDir: path.join(rootDir, "h"),
      socketPath: path.join(rootDir, "h", "connector.sock"),
      workspaceDir: path.join(rootDir, "ws"),
      binDir: path.join(rootDir, "bin"),
      logsDir: path.join(rootDir, "logs"),
      tmpDir: path.join(rootDir, "tmp"),
    };

    for (const dir of [
      paths.homeDir,
      paths.xdgConfigDir,
      paths.xdgStateDir,
      paths.xdgDataDir,
      paths.xdgRunDir,
      paths.hyphaeConfigDir,
      paths.workspaceDir,
      paths.binDir,
      paths.logsDir,
      paths.tmpDir,
    ]) {
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    }

    const env = buildScrubbedEnv(options.sourceEnv ?? process.env, paths, {
      extraPathDirs: options.extraPathDirs,
      extraEnv: options.extraEnv,
      egressBlackhole: options.egressBlackhole,
    });

    return new Sandbox(testName, paths, env, hostCanary);
  }

  /** Returns a copy of the scrubbed env with per-command additions. */
  envWith(overrides: Record<string, string>): Record<string, string> {
    return { ...this.env, ...overrides };
  }

  /** Registers a sandbox secret so attached `llm-shim` auditors can scan for leaks. */
  registerSecret(name: string, value: string): void {
    if (!value) return;
    this.secrets.set(name, value);
    for (const listener of this.secretListeners) {
      listener(name, value);
    }
  }

  onSecretRegistered(listener: (name: string, value: string) => void): void {
    this.secretListeners.push(listener);
    for (const [name, val] of this.secrets.entries()) {
      listener(name, val);
    }
  }

  getRegisteredSecrets(): ReadonlyMap<string, string> {
    return this.secrets;
  }

  addForensicsProvider(filename: string, provider: ForensicsProvider): void {
    this.forensicsProviders.set(filename, provider);
  }

  onTeardown(fn: () => Promise<void> | void): void {
    this.teardownHooks.push(fn);
  }

  /** Writes failure forensics bundle to `itest-forensics/<test-name>/`. */
  async writeForensics(reason?: unknown): Promise<string> {
    const slug = this.testName
      .toLowerCase()
      .replace(/[^a-z0-9._-]+/g, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, 64);
    const outDir = path.join(FORENSICS_ROOT, `${slug || "test"}-${Date.now()}`);
    fs.mkdirSync(outDir, { recursive: true });

    const errorMessage =
      reason instanceof Error
        ? `${reason.message}\n${reason.stack || ""}`
        : reason !== undefined
          ? String(reason)
          : null;

    fs.writeFileSync(
      path.join(outDir, "summary.json"),
      JSON.stringify(
        {
          testName: this.testName,
          elapsedMs: Date.now() - this.createdAtMs,
          rootDir: this.paths.rootDir,
          socketPath: this.paths.socketPath,
          error: errorMessage,
          processes: this.reaper.list().map((p) => ({
            id: p.id,
            label: p.label,
            pid: p.pid,
            exited: p.exited,
            exitCode: p.exitCode,
            signal: p.signal,
            logPath: p.logPath,
          })),
        },
        null,
        2,
      ) + "\n",
    );

    // Collect provider artifacts (`llm-shim-requests.json`, `hyp-inspect.json`, etc.).
    for (const [filename, provider] of this.forensicsProviders.entries()) {
      try {
        const data = await provider();
        if (data === null || data === undefined) continue;
        const text = typeof data === "string" ? data : JSON.stringify(data, null, 2) + "\n";
        fs.writeFileSync(path.join(outDir, filename), text);
      } catch (err) {
        fs.writeFileSync(
          path.join(outDir, `${filename}.err.txt`),
          `Forensics provider failed: ${err instanceof Error ? err.message : String(err)}\n`,
        );
      }
    }

    // Consolidate process logs (`daemon.log`, `gateway.log`, `harness-stdout.log`).
    const harnessChunks: string[] = [];
    for (const proc of this.reaper.list()) {
      let body = "";
      try {
        if (fs.existsSync(proc.logPath)) {
          body = fs.readFileSync(proc.logPath, "utf8");
        }
      } catch {
        body = `${proc.stdout}\n${proc.stderr}`;
      }
      if (proc.label === "daemon" || proc.label.startsWith("daemon")) {
        fs.appendFileSync(path.join(outDir, "daemon.log"), `\n=== ${proc.label} (pid ${proc.pid}) ===\n${body}`);
      } else if (proc.label.includes("gateway")) {
        fs.appendFileSync(path.join(outDir, "gateway.log"), `\n=== ${proc.label} (pid ${proc.pid}) ===\n${body}`);
      } else {
        harnessChunks.push(`=== ${proc.label} (pid ${proc.pid}, code=${proc.exitCode}) ===\n${body}`);
      }
    }
    if (harnessChunks.length > 0) {
      fs.writeFileSync(path.join(outDir, "harness-stdout.log"), harnessChunks.join("\n\n"));
    }

    return outDir;
  }

  /**
   * Full deterministic teardown:
   * 1. Captures forensics bundle on failure (or `HYPHAE_ITEST_KEEP_LOGS=1`) BEFORE killing daemon.
   * 2. Kills all spawned process groups (`SIGTERM` -> `SIGKILL` to `-pgid`).
   * 3. Runs teardown hooks (closing loopback HTTP servers, etc.).
   * 4. Removes TempDir.
   * 5. Verifies `HostCanary.assertUntouched()`.
   */
  async cleanup(options: { failed?: boolean; error?: unknown } = {}): Promise<void> {
    if (this.cleanedUp) return;
    this.cleanedUp = true;

    const keepLogs =
      process.env.HYPHAE_ITEST_KEEP_LOGS === "1" || process.env.HYPHAE_ITEST_KEEP_LOGS === "true";

    if (options.failed || keepLogs) {
      try {
        const forensicsDir = await this.writeForensics(options.error);
        if (options.failed) {
          console.error(`[hyphae-itest] Failure forensics saved to: ${forensicsDir}`);
        }
      } catch (err) {
        console.error(`[hyphae-itest] Failed writing forensics: ${err}`);
      }
    }

    await this.reaper.reapAll();

    for (const hook of this.teardownHooks.reverse()) {
      try {
        await hook();
      } catch {
        // best-effort teardown
      }
    }

    try {
      fs.rmSync(this.paths.rootDir, { recursive: true, force: true });
    } catch {
      // ignore cleanup races
    }

    this.hostCanary.assertUntouched();
  }
}

/**
 * Convenience wrapper guaranteeing `sandbox.cleanup()` + Failure Forensics + `HostCanary`
 * on every test run.
 */
export async function withSandbox<T>(
  testName: string,
  optionsOrFn: SandboxOptions | ((sandbox: Sandbox) => Promise<T>),
  maybeFn?: (sandbox: Sandbox) => Promise<T>,
): Promise<T> {
  const options = typeof optionsOrFn === "function" ? {} : optionsOrFn;
  const fn = typeof optionsOrFn === "function" ? optionsOrFn : maybeFn!;
  const sandbox = Sandbox.create(testName, options);
  let failed = false;
  let caught: unknown;
  try {
    return await fn(sandbox);
  } catch (err) {
    failed = true;
    caught = err;
    throw err;
  } finally {
    await sandbox.cleanup({ failed, error: caught });
  }
}
