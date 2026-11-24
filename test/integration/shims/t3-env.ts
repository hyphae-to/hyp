import { spawn, type ChildProcess } from "node:child_process";
import { chmodSync, mkdirSync, writeFileSync } from "node:fs";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { join } from "node:path";
import { object } from "../../../src/protocol.ts";
import { BINARIES } from "../harness/drivers.ts";
import { freePort, waitFor } from "../harness/topology.ts";

function shellQuote(value: string): string {
  return `'${value.replace(/'/g, "'\\''")}'`;
}

function readJsonBody(req: IncomingMessage): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => {
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")));
      } catch (error) {
        reject(error);
      }
    });
    req.on("error", reject);
  });
}

// ---------------------------------------------------------------------------
// 1. Real `t3 serve` isolated subprocess launcher
// ---------------------------------------------------------------------------

export interface RealT3ServerHandle {
  readonly url: string;
  readonly port: number;
  readonly baseDir: string;
  readonly homeDir: string;
  readonly cwd: string;
  readonly initialHttpStatus: number;
  readonly proc: ChildProcess;
  readonly stdout: string[];
  readonly stderr: string[];
  stop(): Promise<void>;
}

export interface StartRealT3ServerOptions {
  readonly startupTimeoutMs?: number;
  readonly extraEnv?: NodeJS.ProcessEnv;
}

/**
 * Launches the real `t3 serve` binary into a completely isolated `--base-dir` + `HOME` + `T3CODE_HOME`
 * on a free loopback port (`127.0.0.1:<freePort>`), never touching `~/.t3` or `~/.t3-mesh`.
 * Guarantees SIGTERM -> SIGKILL cleanup in `stop()`.
 */
export async function startRealT3Server(
  rootDir: string,
  options: StartRealT3ServerOptions = {},
): Promise<RealT3ServerHandle> {
  if (!BINARIES.t3) {
    throw new Error("Real `t3` binary is not installed on PATH");
  }

  const baseDir = join(rootDir, "t3-base");
  const homeDir = join(rootDir, "t3-home");
  const cwd = join(rootDir, "t3-cwd");
  mkdirSync(baseDir, { recursive: true, mode: 0o700 });
  mkdirSync(join(homeDir, ".config"), { recursive: true, mode: 0o700 });
  mkdirSync(cwd, { recursive: true, mode: 0o700 });

  const port = await freePort();
  const url = `http://127.0.0.1:${port}`;

  const env: NodeJS.ProcessEnv = {
    ...process.env,
    HOME: homeDir,
    T3CODE_HOME: baseDir,
    XDG_CONFIG_HOME: join(homeDir, ".config"),
    XDG_DATA_HOME: join(homeDir, ".local", "share"),
    XDG_CACHE_HOME: join(homeDir, ".cache"),
    XDG_STATE_HOME: join(homeDir, ".local", "state"),
    ...options.extraEnv,
  };
  delete env.HC_TERMINAL_ID;
  delete env.ANTIGRAVITY_SOURCE_METADATA;
  delete env.CLAUDE_SESSION_ID;
  delete env.CODEX_THREAD_ID;
  delete env.HYPHAE_SOCKET;
  delete env.AGENTS_MESH_SOCKET;
  delete env.T3CODE_PORT;
  delete env.T3CODE_HOST;
  delete env.T3CODE_MODE;

  const proc = spawn(
    BINARIES.t3,
    [
      "serve",
      "--mode", "desktop",
      "--host", "127.0.0.1",
      "--port", String(port),
      "--base-dir", baseDir,
      "--no-browser",
      cwd,
    ],
    {
      cwd,
      env,
      stdio: ["ignore", "pipe", "pipe"],
    },
  );

  const stdout: string[] = [];
  const stderr: string[] = [];
  proc.stdout.on("data", (d: Buffer) => stdout.push(d.toString("utf8")));
  proc.stderr.on("data", (d: Buffer) => stderr.push(d.toString("utf8")));

  const emergencyKill = () => {
    if (proc.exitCode === null && proc.signalCode === null) {
      try { proc.kill("SIGKILL"); } catch {}
    }
  };
  process.once("exit", emergencyKill);

  let stopped = false;
  const stop = async (): Promise<void> => {
    if (stopped) return;
    stopped = true;
    process.off("exit", emergencyKill);
    if (proc.exitCode !== null || proc.signalCode !== null) return;
    await new Promise<void>((resolveExit) => {
      const killTimer = setTimeout(() => {
        if (proc.exitCode === null && proc.signalCode === null) {
          try { proc.kill("SIGKILL"); } catch {}
        }
      }, 2_500).unref();
      const hardTimer = setTimeout(() => {
        clearTimeout(killTimer);
        resolveExit();
      }, 4_500).unref();
      proc.once("exit", () => {
        clearTimeout(killTimer);
        clearTimeout(hardTimer);
        resolveExit();
      });
      try {
        proc.kill("SIGTERM");
      } catch {
        clearTimeout(killTimer);
        clearTimeout(hardTimer);
        resolveExit();
      }
    });
  };

  let initialHttpStatus = 0;
  try {
    initialHttpStatus = await waitFor(
      async () => {
        if (proc.exitCode !== null || proc.signalCode !== null) {
          throw new Error(
            `t3 serve exited early (code=${proc.exitCode}, signal=${proc.signalCode}):\nSTDOUT:\n${stdout.join("")}\nSTDERR:\n${stderr.join("")}`,
          );
        }
        try {
          const res = await fetch(`${url}/`, { signal: AbortSignal.timeout(1_000) });
          await res.arrayBuffer().catch(() => {});
          return res.status;
        } catch {
          return false;
        }
      },
      {
        timeoutMs: options.startupTimeoutMs ?? 20_000,
        intervalMs: 100,
        label: `real t3 serve HTTP on ${url}`,
      },
    );
  } catch (error) {
    await stop();
    throw error;
  }

  return {
    url,
    port,
    baseDir,
    homeDir,
    cwd,
    initialHttpStatus,
    proc,
    stdout,
    stderr,
    stop,
  };
}

// ---------------------------------------------------------------------------
// 2. Virtual ~/.t3 + ~/.t3-mesh Home Seeder
// ---------------------------------------------------------------------------

export interface SeedVirtualT3MeshOptions {
  readonly connectorId?: string;
  readonly routerUrl?: string;
  readonly plugins?: readonly string[];
  readonly secretToken?: string;
  /** Skip creating `~/.t3-mesh/config.json` (simulates T3 Code installed without t3-mesh). */
  readonly omitMeshConfig?: boolean;
  /** Write raw string contents directly into `~/.t3-mesh/config.json` (for malformed JSON perturbation). */
  readonly rawMeshConfig?: string;
}

export interface SeededVirtualT3MeshHome {
  readonly homeDir: string;
  readonly t3Dir: string;
  readonly t3MeshDir: string;
  readonly configPath: string;
  readonly tokenFile: string;
  readonly secretToken: string;
}

/**
 * Seeds an isolated fake HOME containing `~/.t3` and `~/.t3-mesh/config.json` plus a private
 * `0600` token file (and decoy secret fields) to test that `detectLocalEnvironment` and
 * `runDoctor` extract metadata accurately and NEVER read or leak secrets.
 */
export function seedVirtualT3MeshHome(
  homeDir: string,
  opts: SeedVirtualT3MeshOptions = {},
): SeededVirtualT3MeshHome {
  const secretToken = opts.secretToken ?? "SUPER_SECRET_T3_TOKEN";
  const t3Dir = join(homeDir, ".t3");
  const t3MeshDir = join(homeDir, ".t3-mesh");
  mkdirSync(join(t3Dir, "userdata"), { recursive: true, mode: 0o700 });
  mkdirSync(t3MeshDir, { recursive: true, mode: 0o700 });

  const tokenFile = join(t3MeshDir, "router.token");
  writeFileSync(tokenFile, `${secretToken}\n`, { mode: 0o600 });
  chmodSync(tokenFile, 0o600);

  const keyFile = join(t3MeshDir, "identity.key");
  writeFileSync(keyFile, `${secretToken}-PRIVATE-KEY\n`, { mode: 0o600 });
  chmodSync(keyFile, 0o600);

  const configPath = join(t3MeshDir, "config.json");
  if (!opts.omitMeshConfig) {
    if (opts.rawMeshConfig !== undefined) {
      writeFileSync(configPath, opts.rawMeshConfig, { mode: 0o600 });
    } else {
      const cfg = {
        connectorId: opts.connectorId ?? "t3@desktop",
        router: {
          url: opts.routerUrl ?? "http://127.0.0.1:8790",
          tokenFile,
          // Decoy inline secret field to assert `detectLocalEnvironment` never copies unknown fields
          token: secretToken,
        },
        plugins: (opts.plugins ?? []).map((name) => ({
          name,
          exec: "/usr/bin/true",
          env: { API_SECRET: secretToken },
          targets: [],
        })),
      };
      writeFileSync(configPath, JSON.stringify(cfg, null, 2) + "\n", { mode: 0o600 });
    }
    chmodSync(configPath, 0o600);
  }

  return {
    homeDir,
    t3Dir,
    t3MeshDir,
    configPath,
    tokenFile,
    secretToken,
  };
}

// ---------------------------------------------------------------------------
// 3. Stateful Loopback Virtual `codex` CLI (`codex queue ...`)
// ---------------------------------------------------------------------------

export type VirtualCodexMode =
  | { readonly kind: "ok"; readonly stdout?: string }
  | { readonly kind: "offline"; readonly code?: number; readonly stderr?: string }
  | { readonly kind: "error"; readonly code?: number; readonly stderr?: string };

export interface VirtualCodexInvocation {
  readonly args: readonly string[];
  readonly subcommand: string;
  readonly threadId?: string;
  readonly message?: string;
  readonly resume: boolean;
  readonly remote?: string;
  readonly codexHome: string | null;
  readonly exitCode: number;
  readonly stdout: string;
  readonly stderr: string;
  readonly timestamp: number;
}

export interface VirtualCodexQueueMessage {
  readonly threadId: string;
  readonly message: string;
  readonly resume: boolean;
  readonly remote?: string;
  readonly codexHome: string | null;
  readonly args: readonly string[];
  readonly timestamp: number;
}

export interface VirtualCodexCli {
  readonly url: string;
  readonly port: number;
  readonly binDir: string;
  readonly codexPath: string;
  readonly invocations: readonly VirtualCodexInvocation[];
  readonly queuedMessages: readonly VirtualCodexQueueMessage[];
  setMode(mode: VirtualCodexMode): void;
  queueMode(...modes: VirtualCodexMode[]): void;
  waitForQueueMessage(
    predicate?: (msg: VirtualCodexQueueMessage) => boolean,
    timeoutMs?: number,
  ): Promise<VirtualCodexQueueMessage>;
  waitForInvocation(
    predicate: (inv: VirtualCodexInvocation) => boolean,
    timeoutMs?: number,
  ): Promise<VirtualCodexInvocation>;
  envWithVirtualCodex(extraEnv?: NodeJS.ProcessEnv): NodeJS.ProcessEnv;
  close(): Promise<void>;
}

function parseCodexQueueArgs(args: readonly string[]): {
  threadId?: string;
  message?: string;
  resume: boolean;
  remote?: string;
} {
  let threadId: string | undefined;
  let message: string | undefined;
  let resume = false;
  let remote: string | undefined;

  for (let i = 1; i < args.length; i++) {
    const token = args[i]!;
    if (token === "--thread") {
      threadId = args[++i];
    } else if (token.startsWith("--thread=")) {
      threadId = token.slice("--thread=".length);
    } else if (token === "--message") {
      message = args[++i];
    } else if (token.startsWith("--message=")) {
      message = token.slice("--message=".length);
    } else if (token === "--resume") {
      resume = true;
    } else if (token === "--remote") {
      remote = args[++i];
    } else if (token.startsWith("--remote=")) {
      remote = token.slice("--remote=".length);
    }
  }
  return { threadId, message, resume, remote };
}

/**
 * Starts a loopback HTTP controller + executable `<rootDir>/codex-bin/codex` wrapper capturing
 * `codex queue --thread <uuid> --message <text> [--resume] [--remote <url>]`, supporting
 * controllable online/offline/hard-error modes and recording every invocation + `CODEX_HOME`.
 */
export async function startVirtualCodexCli(rootDir: string): Promise<VirtualCodexCli> {
  mkdirSync(rootDir, { recursive: true, mode: 0o700 });
  const binDir = join(rootDir, "codex-bin");
  mkdirSync(binDir, { recursive: true, mode: 0o700 });

  let defaultMode: VirtualCodexMode = { kind: "ok" };
  const queuedModes: VirtualCodexMode[] = [];
  const invocations: VirtualCodexInvocation[] = [];
  const queuedMessages: VirtualCodexQueueMessage[] = [];
  const invocationWaiters = new Set<(inv: VirtualCodexInvocation) => void>();
  const messageWaiters = new Set<(msg: VirtualCodexQueueMessage) => void>();

  const nextMode = (): VirtualCodexMode => queuedModes.shift() ?? defaultMode;

  const handleCodex = (
    args: readonly string[],
    codexHome: string | null,
  ): {
    code: number;
    stdout: string;
    stderr: string;
    parsed: ReturnType<typeof parseCodexQueueArgs>;
    delivered?: VirtualCodexQueueMessage;
  } => {
    const cmd = args[0] ?? "";
    if (cmd === "--version" || cmd === "-V") {
      return { code: 0, stdout: "codex-cli 0.99.0-virtual\n", stderr: "", parsed: { resume: false } };
    }
    if (cmd !== "queue") {
      return {
        code: 2,
        stdout: "",
        stderr: `unsupported virtual codex command: ${args.join(" ")}\n`,
        parsed: { resume: false },
      };
    }

    const parsed = parseCodexQueueArgs(args);
    const mode = nextMode();
    if (mode.kind === "offline") {
      return {
        code: mode.code ?? 1,
        stdout: "",
        stderr: mode.stderr ?? "daemon refused connection\n",
        parsed,
      };
    }
    if (mode.kind === "error") {
      return {
        code: mode.code ?? 2,
        stdout: "",
        stderr: mode.stderr ?? "fatal codex queue error\n",
        parsed,
      };
    }

    if (!parsed.threadId || parsed.message === undefined) {
      return {
        code: 2,
        stdout: "",
        stderr: "missing --thread or --message\n",
        parsed,
      };
    }

    const delivered: VirtualCodexQueueMessage = {
      threadId: parsed.threadId,
      message: parsed.message,
      resume: parsed.resume,
      ...(parsed.remote !== undefined ? { remote: parsed.remote } : {}),
      codexHome,
      args: [...args],
      timestamp: Date.now(),
    };
    queuedMessages.push(delivered);
    return {
      code: 0,
      stdout: mode.stdout ?? JSON.stringify({ queued: true, threadId: parsed.threadId }) + "\n",
      stderr: "",
      parsed,
      delivered,
    };
  };

  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    if (req.method !== "POST" || req.url !== "/codex") {
      res.writeHead(404, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "not_found" }));
      return;
    }
    void readJsonBody(req)
      .then((body) => {
        const args = object(body) && Array.isArray(body.args) ? body.args.map((a) => String(a)) : [];
        const codexHome = object(body) && object(body.env) && typeof body.env.CODEX_HOME === "string"
          ? body.env.CODEX_HOME
          : null;
        const result = handleCodex(args, codexHome);
        const inv: VirtualCodexInvocation = {
          args: [...args],
          subcommand: args[0] ?? "",
          ...(result.parsed.threadId !== undefined ? { threadId: result.parsed.threadId } : {}),
          ...(result.parsed.message !== undefined ? { message: result.parsed.message } : {}),
          resume: result.parsed.resume,
          ...(result.parsed.remote !== undefined ? { remote: result.parsed.remote } : {}),
          codexHome,
          exitCode: result.code,
          stdout: result.stdout,
          stderr: result.stderr,
          timestamp: Date.now(),
        };
        invocations.push(inv);
        for (const listener of [...invocationWaiters]) listener(inv);
        if (result.delivered) {
          for (const listener of [...messageWaiters]) listener(result.delivered);
        }
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ code: result.code, stdout: result.stdout, stderr: result.stderr }));
      })
      .catch((error: unknown) => {
        res.writeHead(400, { "content-type": "application/json" });
        res.end(JSON.stringify({ code: 1, stdout: "", stderr: error instanceof Error ? error.message : String(error) }));
      });
  });

  await new Promise<void>((resolveListen, rejectListen) => {
    server.once("error", rejectListen);
    server.listen(0, "127.0.0.1", () => resolveListen());
  });

  const addr = server.address();
  if (!addr || typeof addr === "string") {
    server.close();
    throw new Error("Virtual codex controller failed to bind loopback TCP port");
  }
  const port = addr.port;
  const url = `http://127.0.0.1:${port}`;

  // Place client script outside codex-bin so codex-bin exposes only the executable `codex` shim.
  const clientScriptPath = join(rootDir, "codex-client.mjs");
  const clientScript = `import { request } from "node:http";
const payload = JSON.stringify({
  args: process.argv.slice(2),
  env: { CODEX_HOME: process.env.CODEX_HOME ?? null },
});
const req = request(
  {
    hostname: "127.0.0.1",
    port: ${port},
    path: "/codex",
    method: "POST",
    headers: {
      "content-type": "application/json",
      "content-length": Buffer.byteLength(payload),
    },
  },
  (res) => {
    const chunks = [];
    res.on("data", (chunk) => chunks.push(chunk));
    res.on("end", () => {
      try {
        const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
        if (body.stdout) process.stdout.write(body.stdout);
        if (body.stderr) process.stderr.write(body.stderr);
        process.exitCode = typeof body.code === "number" ? body.code : 1;
      } catch (err) {
        process.stderr.write("virtual codex parse error: " + String(err) + "\\n");
        process.exitCode = 1;
      }
    });
  },
);
req.on("error", (err) => {
  process.stderr.write("virtual codex controller error: " + err.message + "\\n");
  process.exitCode = 1;
});
req.end(payload);
`;
  writeFileSync(clientScriptPath, clientScript, { mode: 0o644 });

  const codexPath = join(binDir, "codex");
  writeFileSync(
    codexPath,
    `#!/bin/sh\nexec ${shellQuote(process.execPath)} ${shellQuote(clientScriptPath)} "$@"\n`,
    { mode: 0o755 },
  );
  chmodSync(codexPath, 0o755);

  let closed = false;
  return {
    url,
    port,
    binDir,
    codexPath,
    get invocations() {
      return invocations;
    },
    get queuedMessages() {
      return queuedMessages;
    },
    setMode(mode) {
      defaultMode = mode;
    },
    queueMode(...modes) {
      queuedModes.push(...modes);
    },
    waitForQueueMessage(predicate, timeoutMs = 8_000) {
      const matches = (msg: VirtualCodexQueueMessage) => !predicate || predicate(msg);
      const existing = queuedMessages.find(matches);
      if (existing) return Promise.resolve(existing);
      return new Promise<VirtualCodexQueueMessage>((resolvePromise, rejectPromise) => {
        const timer = setTimeout(() => {
          messageWaiters.delete(onMsg);
          const seen = queuedMessages.map((m) => m.message.slice(0, 80)).join(" | ");
          rejectPromise(
            new Error(`Timed out after ${timeoutMs}ms waiting for codex queue message (saw ${queuedMessages.length}: ${seen || "none"})`),
          );
        }, timeoutMs).unref();
        const onMsg = (msg: VirtualCodexQueueMessage) => {
          if (matches(msg)) {
            clearTimeout(timer);
            messageWaiters.delete(onMsg);
            resolvePromise(msg);
          }
        };
        messageWaiters.add(onMsg);
      });
    },
    waitForInvocation(predicate, timeoutMs = 8_000) {
      const existing = invocations.find(predicate);
      if (existing) return Promise.resolve(existing);
      return new Promise<VirtualCodexInvocation>((resolvePromise, rejectPromise) => {
        const timer = setTimeout(() => {
          invocationWaiters.delete(onInv);
          const recent = invocations.slice(-8).map((i) => `${i.args.join(" ")} -> ${i.exitCode}`).join(" | ");
          rejectPromise(
            new Error(`Timed out after ${timeoutMs}ms waiting for codex invocation (recent: ${recent || "none"})`),
          );
        }, timeoutMs).unref();
        const onInv = (inv: VirtualCodexInvocation) => {
          if (predicate(inv)) {
            clearTimeout(timer);
            invocationWaiters.delete(onInv);
            resolvePromise(inv);
          }
        };
        invocationWaiters.add(onInv);
      });
    },
    envWithVirtualCodex(extraEnv: NodeJS.ProcessEnv = {}) {
      const basePath = extraEnv.PATH ?? process.env.PATH ?? "/usr/bin:/bin";
      const env: NodeJS.ProcessEnv = {
        ...process.env,
        PATH: `${binDir}:${basePath}`,
      };
      delete env.HC_TERMINAL_ID;
      delete env.ANTIGRAVITY_SOURCE_METADATA;
      delete env.CLAUDE_SESSION_ID;
      delete env.CODEX_THREAD_ID;
      delete env.CODEX_HOME;
      delete env.HYPHAE_SOCKET;
      delete env.AGENTS_MESH_SOCKET;
      return { ...env, ...extraEnv, PATH: `${binDir}:${basePath}` };
    },
    async close() {
      if (closed) return;
      closed = true;
      invocationWaiters.clear();
      messageWaiters.clear();
      server.closeAllConnections();
      await new Promise<void>((resolveClose) => server.close(() => resolveClose()));
    },
  };
}

// ---------------------------------------------------------------------------
// 4. Lightweight `t3-mesh` Router Inbox SSE Stream Client (for simulated T3 nodes)
// ---------------------------------------------------------------------------

export interface SseInboxEvent {
  readonly event: string;
  readonly data: Record<string, unknown>;
}

export interface RouterSseInboxHandle {
  readonly events: readonly SseInboxEvent[];
  waitForEvent(predicate: (ev: SseInboxEvent) => boolean, timeoutMs?: number): Promise<SseInboxEvent>;
  close(): Promise<void>;
}

/**
 * Connects to a router's `GET /v1/inbox` SSE stream with a connector's bearer token (simulating a
 * native `t3-mesh` node receiving messages, event batches, and `transfer` offers over the wire).
 */
export async function openRouterInboxSse(routerUrl: string, token: string): Promise<RouterSseInboxHandle> {
  const abort = new AbortController();
  const response = await fetch(`${routerUrl}/v1/inbox`, {
    headers: { authorization: `Bearer ${token}` },
    signal: abort.signal,
  });
  if (!response.ok || !response.body) {
    abort.abort();
    throw new Error(`GET /v1/inbox failed with HTTP ${response.status}`);
  }

  const events: SseInboxEvent[] = [];
  const waiters = new Set<(ev: SseInboxEvent) => void>();

  const readerLoop = (async () => {
    const decoder = new TextDecoder();
    let buffer = "";
    try {
      for await (const chunk of response.body!) {
        buffer += decoder.decode(chunk, { stream: true });
        let sep = buffer.indexOf("\n\n");
        while (sep !== -1) {
          const frame = buffer.slice(0, sep);
          buffer = buffer.slice(sep + 2);
          sep = buffer.indexOf("\n\n");
          let eventName = "message";
          const dataLines: string[] = [];
          for (const line of frame.split("\n")) {
            if (line.startsWith("event: ")) eventName = line.slice(7).trim();
            else if (line.startsWith("data: ")) dataLines.push(line.slice(6));
          }
          if (dataLines.length === 0) continue;
          try {
            const parsed: unknown = JSON.parse(dataLines.join("\n"));
            if (!object(parsed)) continue;
            const ev: SseInboxEvent = { event: eventName, data: parsed };
            events.push(ev);
            for (const listener of [...waiters]) listener(ev);
          } catch {}
        }
      }
    } catch {
      // Expected on abort/close
    }
  })();

  let closed = false;
  return {
    get events() {
      return events;
    },
    waitForEvent(predicate, timeoutMs = 8_000) {
      const existing = events.find(predicate);
      if (existing) return Promise.resolve(existing);
      return new Promise<SseInboxEvent>((resolvePromise, rejectPromise) => {
        const timer = setTimeout(() => {
          waiters.delete(onEvent);
          rejectPromise(
            new Error(`Timed out after ${timeoutMs}ms waiting for SSE inbox event (saw ${events.length} event(s))`),
          );
        }, timeoutMs).unref();
        const onEvent = (ev: SseInboxEvent) => {
          if (predicate(ev)) {
            clearTimeout(timer);
            waiters.delete(onEvent);
            resolvePromise(ev);
          }
        };
        waiters.add(onEvent);
      });
    },
    async close() {
      if (closed) return;
      closed = true;
      waiters.clear();
      abort.abort();
      await readerLoop.catch(() => {});
    },
  };
}
