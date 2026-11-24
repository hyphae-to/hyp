import { execFileSync, spawn } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { setupAntigravity, setupClaude, setupCodex, setupCursor, setupOpenCode } from "../../../src/setup.ts";
import {
  startScriptedAnthropicServer,
  startScriptedGeminiServer,
  startScriptedOpenAIResponsesServer,
  type RunningScriptedServer,
  type TurnHandler,
} from "../shims/llm.ts";

export interface DetectedBinaries {
  readonly claude: string | null;
  readonly codex: string | null;
  readonly opencode: string | null;
  readonly agy: string | null;
  readonly cursorAgent: string | null;
  readonly hc: string | null;
  readonly t3: string | null;
}

export function findBinary(name: string): string | null {
  try {
    return execFileSync("which", [name], { encoding: "utf8" }).trim() || null;
  } catch {
    return null;
  }
}

export const BINARIES: DetectedBinaries = {
  claude: findBinary("claude"),
  codex: findBinary("codex"),
  opencode: findBinary("opencode"),
  agy: findBinary("agy"),
  cursorAgent: findBinary("cursor-agent"),
  hc: findBinary("hc"),
  t3: findBinary("t3"),
};

export interface ProcessResult {
  readonly code: number | null;
  readonly stdout: string;
  readonly stderr: string;
}

export function runProcess(
  bin: string,
  args: string[],
  options: { readonly cwd: string; readonly env: NodeJS.ProcessEnv; readonly timeoutMs?: number },
): Promise<ProcessResult> {
  return new Promise((resolve) => {
    const proc = spawn(bin, args, { cwd: options.cwd, env: options.env, stdio: ["ignore", "pipe", "pipe"] });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    proc.stdout.on("data", (d: Buffer) => out.push(d));
    proc.stderr.on("data", (d: Buffer) => err.push(d));
    const timer = setTimeout(() => { proc.kill("SIGKILL"); }, options.timeoutMs ?? 45_000).unref();
    proc.once("exit", (code) => {
      clearTimeout(timer);
      resolve({
        code,
        stdout: Buffer.concat(out).toString("utf8"),
        stderr: Buffer.concat(err).toString("utf8"),
      });
    });
  });
}

export function initTempWorkspace(rootDir: string, name = "workspace"): string {
  const workspace = join(rootDir, name);
  mkdirSync(workspace, { recursive: true });
  execFileSync("git", ["init", "-q"], { cwd: workspace });
  return workspace;
}

export function devRuntime(): { readonly nodeBin: string; readonly cliScript: string } {
  return { nodeBin: process.execPath, cliScript: join(process.cwd(), "src", "cli.ts") };
}

/** Build a clean env inheriting PATH but isolating XDG/HOME and removing live Herdr terminal bindings. */
export function isolatedEnv(baseDir: string, extra: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  const home = join(baseDir, "home");
  mkdirSync(home, { recursive: true });
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    HOME: home,
    XDG_CONFIG_HOME: join(home, ".config"),
    XDG_DATA_HOME: join(baseDir, "xdg-data"),
    XDG_CACHE_HOME: join(baseDir, "xdg-cache"),
    XDG_STATE_HOME: join(baseDir, "xdg-state"),
    ...extra,
  };
  delete env.HC_TERMINAL_ID;
  delete env.ANTIGRAVITY_SOURCE_METADATA;
  delete env.CLAUDE_SESSION_ID;
  delete env.CODEX_THREAD_ID;
  return env;
}

export interface RealClaudeRunOptions {
  readonly baseDir: string;
  readonly socketPath: string;
  readonly prompt: string;
  readonly handler: TurnHandler;
  readonly model?: string;
  readonly timeoutMs?: number;
}

export interface RealHarnessRunResult {
  readonly result: ProcessResult;
  readonly server: RunningScriptedServer;
  readonly workspace: string;
}

/**
 * Sets up a real isolated project for Claude Code (`setupClaude`) and runs the real `claude` CLI
 * against a local loopback Anthropic Messages API shim (zero cloud calls, zero user-dir writes).
 */
export async function runRealClaude(opts: RealClaudeRunOptions): Promise<RealHarnessRunResult> {
  if (!BINARIES.claude) throw new Error("claude CLI binary not installed");
  const workspace = initTempWorkspace(opts.baseDir, "claude-workspace");
  setupClaude({ scope: "project", projectDir: workspace, socketPath: opts.socketPath, runtime: devRuntime() });

  const server = await startScriptedAnthropicServer(opts.handler);
  try {
    // Keep Claude's own home isolated so it never modifies ~/.claude or ~/.claude.json.
    const env = isolatedEnv(opts.baseDir, {
      ANTHROPIC_BASE_URL: server.url,
      ANTHROPIC_API_KEY: "sk-ant-dummy-local-integration",
      CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1",
      DISABLE_TELEMETRY: "1",
    });

    const result = await runProcess(
      BINARIES.claude,
      [
        "-p", opts.prompt,
        "--mcp-config", join(workspace, ".mcp.json"),
        "--strict-mcp-config",
        "--settings", join(workspace, ".claude", "settings.json"),
        "--dangerously-skip-permissions",
        "--no-session-persistence",
        "--model", opts.model ?? "claude-sonnet-4-5",
      ],
      { cwd: workspace, env, timeoutMs: opts.timeoutMs ?? 45_000 },
    );
    return { result, server, workspace };
  } finally {
    await server.close();
  }
}

export interface RealCodexEnv {
  readonly workspace: string;
  readonly codexHome: string;
  readonly server: RunningScriptedServer;
  exec(prompt: string, timeoutMs?: number): Promise<ProcessResult>;
  readQueueRows(): Array<{ table: string; rows: unknown[] }>;
  close(): Promise<void>;
}

/**
 * Sets up a real isolated Codex environment (`setupCodex` into an ephemeral `CODEX_HOME`)
 * wired to a local loopback OpenAI Responses API shim. Supports multiple `exec(...)` invocations
 * against the same `CODEX_HOME` to test multi-thread multiplexing.
 */
export async function createRealCodexRunner(opts: {
  readonly baseDir: string;
  readonly socketPath: string;
  readonly handler: TurnHandler;
  readonly model?: string;
}): Promise<RealCodexEnv> {
  if (!BINARIES.codex) throw new Error("codex CLI binary not installed");
  const workspace = initTempWorkspace(opts.baseDir, "codex-workspace");
  setupCodex({ scope: "project", projectDir: opts.baseDir, socketPath: opts.socketPath, runtime: devRuntime() });
  const codexHome = join(opts.baseDir, ".codex");
  const server = await startScriptedOpenAIResponsesServer(opts.handler);
  const model = opts.model ?? "gpt-5";

  const env = isolatedEnv(opts.baseDir, {
    CODEX_HOME: codexHome,
    OPENAI_API_KEY: "sk-dummy-local-codex",
  });

  const commonArgs = [
    "--skip-git-repo-check",
    "--dangerously-bypass-approvals-and-sandbox",
    "-m", model,
    "-c", 'model_provider="dummy"',
    "-c", 'model_providers.dummy.name="dummy"',
    "-c", `model_providers.dummy.base_url="${server.url}/v1"`,
    "-c", 'model_providers.dummy.wire_api="responses"',
    "-c", 'model_providers.dummy.env_key="OPENAI_API_KEY"',
  ];

  return {
    workspace,
    codexHome,
    server,
    exec: (prompt, timeoutMs = 45_000) =>
      runProcess(BINARIES.codex!, ["exec", ...commonArgs, prompt], { cwd: workspace, env, timeoutMs }),
    readQueueRows() {
      const dbPath = join(codexHome, "queue_1.sqlite");
      if (!existsSync(dbPath)) return [];
      const out = execFileSync(
        process.execPath,
        [
          "-e",
          `import { DatabaseSync } from "node:sqlite"; const db = new DatabaseSync(${JSON.stringify(dbPath)}); const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all(); console.log(JSON.stringify(tables.map(t => ({ table: t.name, rows: db.prepare('SELECT * FROM "' + t.name + '"').all() }))));`,
        ],
        { encoding: "utf8" },
      );
      return JSON.parse(out) as Array<{ table: string; rows: unknown[] }>;
    },
    close: () => server.close(),
  };
}

export interface RealOpenCodeRunOptions {
  readonly baseDir: string;
  readonly socketPath: string;
  readonly prompt: string;
  readonly handler: TurnHandler;
  readonly model?: string;
  readonly timeoutMs?: number;
}

/**
 * Sets up a real isolated OpenCode v2 environment (`setupOpenCode` into an ephemeral `XDG_CONFIG_HOME`)
 * and runs `opencode run --standalone --auto` against a local loopback OpenAI Responses API shim.
 */
export async function runRealOpenCode(opts: RealOpenCodeRunOptions): Promise<RealHarnessRunResult> {
  if (!BINARIES.opencode) throw new Error("opencode CLI binary not installed");
  const workspace = initTempWorkspace(opts.baseDir, "opencode-workspace");
  const env = isolatedEnv(opts.baseDir, {
    PWD: workspace,
    OPENCODE_DISABLE_MODELS_FETCH: "1",
    OPENAI_API_KEY: "sk-dummy-local-opencode",
  });
  const fakeHome = env.HOME!;

  setupOpenCode({ scope: "user", homeDir: fakeHome, socketPath: opts.socketPath, runtime: devRuntime() });
  const server = await startScriptedOpenAIResponsesServer(opts.handler);
  try {
    const cfgFile = join(fakeHome, ".config", "opencode", "opencode.json");
    const ocJson = JSON.parse(readFileSync(cfgFile, "utf8")) as Record<string, unknown>;
    ocJson.providers = {
      openai: {
        settings: { baseURL: `${server.url}/v1`, apiKey: "sk-dummy-local-opencode" },
      },
    };
    writeFileSync(cfgFile, JSON.stringify(ocJson, null, 2) + "\n", "utf8");

    const result = await runProcess(
      BINARIES.opencode,
      [
        "run",
        "--standalone",
        "--auto",
        "--model", opts.model ?? "openai/gpt-4.1",
        opts.prompt,
      ],
      { cwd: workspace, env, timeoutMs: opts.timeoutMs ?? 45_000 },
    );
    return { result, server, workspace };
  } finally {
    await server.close();
  }
}

/** Runs `setupAntigravity` into an isolated fake HOME and verifies `agy plugin list` discovers it. */
export async function runRealAgyPluginCheck(baseDir: string, socketPath: string): Promise<ProcessResult> {
  if (!BINARIES.agy) throw new Error("agy CLI binary not installed");
  const env = isolatedEnv(baseDir);
  setupAntigravity({ scope: "user", homeDir: env.HOME!, socketPath, noSidecar: true, runtime: devRuntime() });
  return runProcess(BINARIES.agy, ["plugin", "list"], { cwd: baseDir, env, timeoutMs: 20_000 });
}

export interface RealAgyRunOptions {
  readonly baseDir: string;
  readonly socketPath: string;
  readonly prompt: string;
  readonly handler: TurnHandler;
  readonly timeoutMs?: number;
}

/**
 * Sets up a real isolated Antigravity plugin (`setupAntigravity` into an ephemeral `HOME`)
 * and runs the real `agy` CLI against a local loopback Gemini SSE API shim
 * (`GOOGLE_GEMINI_BASE_URL` + `GEMINI_API_KEY` + `--settings '{"modelProvider":"gemini"}'`).
 */
export async function runRealAgy(opts: RealAgyRunOptions): Promise<RealHarnessRunResult> {
  if (!BINARIES.agy) throw new Error("agy CLI binary not installed");
  const workspace = initTempWorkspace(opts.baseDir, "agy-workspace");
  const env = isolatedEnv(opts.baseDir, {
    GEMINI_API_KEY: "dummy-local-gemini-key",
    HTTPS_PROXY: "http://127.0.0.1:1",
    NO_PROXY: "127.0.0.1,localhost",
    no_proxy: "127.0.0.1,localhost",
  });
  setupAntigravity({
    scope: "user",
    homeDir: env.HOME!,
    socketPath: opts.socketPath,
    noSidecar: true,
    runtime: devRuntime(),
  });

  const server = await startScriptedGeminiServer(opts.handler);
  try {
    env.GOOGLE_GEMINI_BASE_URL = server.url;
    const result = await runProcess(
      BINARIES.agy,
      [
        "-p", opts.prompt,
        "--dangerously-skip-permissions",
        "--settings", JSON.stringify({ modelProvider: "gemini" }),
      ],
      { cwd: workspace, env, timeoutMs: opts.timeoutMs ?? 45_000 },
    );
    return { result, server, workspace };
  } finally {
    await server.close();
  }
}

/** Runs `setupCursor` into an isolated project + HOME and returns generated files and cursor-agent version check. */
export async function runRealCursorSetupCheck(baseDir: string, socketPath: string): Promise<{
  readonly files: string[];
  readonly versionResult: ProcessResult | null;
}> {
  const workspace = initTempWorkspace(baseDir, "cursor-workspace");
  const env = isolatedEnv(baseDir);
  const setup = setupCursor({ scope: "project", projectDir: workspace, socketPath, runtime: devRuntime() });
  const versionResult = BINARIES.cursorAgent
    ? await runProcess(BINARIES.cursorAgent, ["--version"], { cwd: workspace, env, timeoutMs: 15_000 })
    : null;
  return { files: setup.files, versionResult };
}
