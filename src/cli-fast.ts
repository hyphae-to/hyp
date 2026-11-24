// Minimal-import fast-path CLI entrypoint for hot-path protocol subcommands (`hook`, `mcp`, `wait`, `watch`).
// Avoids eagerly loading daemon, setup, RouterCore, interactive prompts, or CLI UI formatters so
// hooks execute in ~30ms and stateless MCP/wait shims stay ~45 MB RSS instead of ~130 MB RSS.
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { isHarness } from "./protocol.ts";

const VALID_HOOK_EVENTS = new Set(["pre-tool-use", "post-tool-use", "pre-invocation", "stop"]);

function defaultSocketPath(): string {
  const envSock = process.env.HYPHAE_SOCKET ?? process.env.AGENTS_MESH_SOCKET;
  if (envSock) return envSock;
  const base = process.env.XDG_CONFIG_HOME ?? join(homedir(), ".config");
  const primary = join(base, "hyphae");
  const legacy = join(base, "agents-mesh");
  const dir = !existsSync(join(primary, "connector.json")) && existsSync(join(legacy, "connector.json")) ? legacy : primary;
  return join(dir, "state", "connector.sock");
}

function resolveFastRuntimePaths(): { nodeBin: string; cliScript: string } {
  const here = dirname(fileURLToPath(import.meta.url));
  const pkgRoot = here.endsWith(join("dist", "src")) ? resolve(here, "..", "..") : resolve(here, "..");
  const builtBin = join(pkgRoot, "bin", "hyphae.mjs");
  const devCli = join(pkgRoot, "src", "cli.ts");
  const distCli = join(pkgRoot, "dist", "src", "cli.js");
  const cliScript = existsSync(distCli) && existsSync(builtBin) ? builtBin : devCli;
  return { nodeBin: process.execPath, cliScript };
}

function usageError(message: string, usage: string): never {
  process.stderr.write(`error: ${message}\nusage: ${usage}\n`);
  process.exit(2);
}

export async function runFastCli(argv: readonly string[]): Promise<void> {
  const [action, ...args] = argv;

  if (action === "mcp") {
    let parsed: ReturnType<typeof parseArgs>;
    try {
      parsed = parseArgs({
        args: [...args],
        allowPositionals: true,
        options: {
          backend: { type: "string" },
          thread: { type: "string" },
          resume: { type: "boolean" },
          remote: { type: "string" },
          "t3-url": { type: "string" },
          "t3-base-dir": { type: "string" },
          "claude-channel": { type: "boolean" },
          "legacy-tools": { type: "boolean" },
          ephemeral: { type: "boolean" },
        },
      });
    } catch (err) {
      usageError(
        err instanceof Error ? err.message : "Invalid mcp arguments",
        "hyp mcp [socket] [--claude-channel] [--backend <harness>] [--thread <uuid>] [--resume] [--remote <addr>] [--t3-url <url>] [--t3-base-dir <dir>] [--legacy-tools] [--ephemeral]",
      );
    }
    const { values, positionals } = parsed;
    const backend = typeof values.backend === "string" ? values.backend : undefined;
    if (positionals.length > 1 || (backend !== undefined && !isHarness(backend))) {
      usageError(
        "Invalid mcp arguments",
        "hyp mcp [socket] [--claude-channel] [--backend <harness>] [--thread <uuid>] [--resume] [--remote <addr>] [--t3-url <url>] [--t3-base-dir <dir>] [--legacy-tools] [--ephemeral]",
      );
    }
    const { runMcp } = await import("./mcp.ts");
    runMcp(positionals[0] ?? defaultSocketPath(), {
      ...(backend ? { backend } : {}),
      channel: values["claude-channel"] === true,
      threadId: typeof values.thread === "string" ? values.thread : undefined,
      resume: values.resume === true,
      remote: typeof values.remote === "string" ? values.remote : undefined,
      ...(typeof values["t3-url"] === "string" ? { t3Url: values["t3-url"] } : {}),
      ...(typeof values["t3-base-dir"] === "string" ? { t3BaseDir: values["t3-base-dir"] } : {}),
      legacyTools: values["legacy-tools"] === true,
      ephemeral: values.ephemeral === true,
    });
    return;
  }

  if (action === "hook") {
    let parsed: ReturnType<typeof parseArgs>;
    try {
      parsed = parseArgs({
        args: [...args],
        allowPositionals: true,
        options: { socket: { type: "string" } },
      });
    } catch (err) {
      usageError(
        err instanceof Error ? err.message : "Invalid hook arguments",
        "hyp hook <antigravity|claude|codex|cursor|opencode|gemini|openclaw> <pre-tool-use|post-tool-use|pre-invocation|stop> [--socket <path>]",
      );
    }
    const { values, positionals } = parsed;
    const [harness, event] = positionals;
    if (positionals.length !== 2 || !isHarness(harness) || harness === "herdr" || !VALID_HOOK_EVENTS.has(event ?? "")) {
      usageError(
        "Invalid hook harness or event",
        "hyp hook <antigravity|claude|codex|cursor|opencode|gemini|openclaw> <pre-tool-use|post-tool-use|pre-invocation|stop> [--socket <path>]",
      );
    }
    const runtime = resolveFastRuntimePaths();
    const quote = (v: string) => (/^[A-Za-z0-9_./:@=-]+$/.test(v) ? v : `'${v.replace(/'/g, `'\\''`)}'`);
    const socket = typeof values.socket === "string" ? values.socket : undefined;
    const { runHook } = await import("./hooks.ts");
    await runHook({
      harness,
      event: event as "pre-tool-use" | "post-tool-use" | "pre-invocation" | "stop",
      socketPath: socket ?? defaultSocketPath(),
      explicitSocket: socket,
      cliPath: `${quote(runtime.nodeBin)} ${quote(runtime.cliScript)}`,
    });
    return;
  }

  if (action === "wait" || action === "watch") {
    let parsed: ReturnType<typeof parseArgs>;
    try {
      parsed = parseArgs({
        args: [...args],
        allowPositionals: false,
        options: {
          session: { type: "string" },
          handle: { type: "string" },
          socket: { type: "string" },
          timeout: { type: "string" },
          stream: { type: "boolean" },
        },
      });
    } catch (err) {
      usageError(
        err instanceof Error ? err.message : "Invalid wait arguments",
        "hyp wait [--stream] [--session <id> | --handle <handle>] [--timeout <sec>]",
      );
    }
    const { values } = parsed;
    const timeoutSeconds = typeof values.timeout === "string" ? Number(values.timeout) : undefined;
    if (timeoutSeconds !== undefined && (!Number.isFinite(timeoutSeconds) || timeoutSeconds < 0)) {
      usageError(
        "Expected non-negative --timeout seconds",
        "hyp wait [--stream] [--session <id> | --handle <handle>] [--timeout <sec>]",
      );
    }
    const { runWait } = await import("./wait.ts");
    process.exitCode = await runWait({
      socketPath: typeof values.socket === "string" ? values.socket : defaultSocketPath(),
      mode: action === "watch" || values.stream === true ? "stream" : "once",
      sessionId: typeof values.session === "string" ? values.session : undefined,
      handle: typeof values.handle === "string" ? values.handle : undefined,
      timeoutSeconds,
    });
    return;
  }
}
