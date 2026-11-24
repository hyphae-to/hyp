import assert from "node:assert/strict";
import { execFile, spawn, type ChildProcess } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { test } from "node:test";
import { daemonRpc } from "../../src/hooks.ts";
import { CORE_MCP_TOOLS, object } from "../../src/protocol.ts";
import {
  setupAntigravity,
  setupClaude,
  setupCodex,
  setupCursor,
  setupOpenClaw,
  setupOpenCode,
} from "../../src/setup.ts";
import { BINARIES, devRuntime, initTempWorkspace, isolatedEnv } from "./harness/drivers.ts";
import { freePort, MeshTopology, waitFor } from "./harness/topology.ts";
import { startIsolatedDaemonSubprocess, type IsolatedDaemonHandle } from "./shims/herdr-env.ts";
import { startScriptedOpenAIResponsesServer } from "./shims/llm.ts";

function execFileAsync(
  bin: string,
  args: readonly string[],
  options: { readonly cwd?: string; readonly env?: NodeJS.ProcessEnv; readonly timeoutMs?: number } = {},
): Promise<{ readonly stdout: string; readonly stderr: string }> {
  return new Promise((resolve, reject) => {
    execFile(
      bin,
      [...args],
      {
        encoding: "utf8",
        cwd: options.cwd,
        env: options.env,
        timeout: options.timeoutMs ?? 15_000,
        maxBuffer: 1024 * 1024,
      },
      (error, stdout, stderr) => {
        if (error) {
          reject(new Error(`${bin} ${args.join(" ")} failed: ${error.message}\nstdout: ${stdout}\nstderr: ${stderr}`));
          return;
        }
        resolve({ stdout, stderr });
      },
    );
  });
}

async function stopChildProcess(proc: ChildProcess | undefined, graceMs = 3_000): Promise<void> {
  if (!proc || proc.exitCode !== null) return;
  await new Promise<void>((resolve) => {
    const timer = setTimeout(() => {
      if (proc.exitCode === null) {
        try { proc.kill("SIGKILL"); } catch {}
      }
      resolve();
    }, graceMs).unref();
    proc.once("exit", () => {
      clearTimeout(timer);
      resolve();
    });
    try {
      proc.kill("SIGTERM");
    } catch {
      clearTimeout(timer);
      resolve();
    }
  });
}

interface JsonRpcNotification {
  readonly method: string;
  readonly params?: Record<string, unknown>;
}

/** Minimal Node 24 native WebSocket JSON-RPC client for driving `codex app-server --listen ws://...`. */
class CodexAppServerClient {
  readonly #ws: WebSocket;
  readonly #pending = new Map<number, { resolve: (result: unknown) => void; reject: (err: Error) => void }>();
  readonly #notificationWaiters = new Set<() => void>();
  readonly notifications: JsonRpcNotification[] = [];
  #nextId = 0;

  private constructor(ws: WebSocket) {
    this.#ws = ws;
    ws.addEventListener("message", (event) => {
      const raw = typeof event.data === "string" ? event.data : String(event.data);
      let msg: unknown;
      try { msg = JSON.parse(raw); } catch { return; }
      if (!object(msg)) return;

      if (typeof msg.id === "number" && typeof msg.method !== "string") {
        const waiter = this.#pending.get(msg.id);
        if (!waiter) return;
        this.#pending.delete(msg.id);
        if (object(msg.error)) {
          waiter.reject(new Error(`RPC error (${String(msg.error.code)}): ${String(msg.error.message ?? JSON.stringify(msg.error))}`));
        } else {
          waiter.resolve(msg.result);
        }
        return;
      }

      if (typeof msg.method === "string" && msg.id === undefined) {
        this.notifications.push({
          method: msg.method,
          ...(object(msg.params) ? { params: msg.params } : {}),
        });
        for (const wake of [...this.#notificationWaiters]) wake();
      }
    });
    ws.addEventListener("close", () => {
      for (const waiter of this.#pending.values()) {
        waiter.reject(new Error("codex app-server WebSocket closed"));
      }
      this.#pending.clear();
    });
  }

  static connect(url: string, timeoutMs = 8_000): Promise<CodexAppServerClient> {
    return new Promise((resolve, reject) => {
      const ws = new WebSocket(url);
      const timer = setTimeout(() => {
        try { ws.close(); } catch {}
        reject(new Error(`Timed out connecting WebSocket to ${url}`));
      }, timeoutMs).unref();
      ws.addEventListener("open", () => {
        clearTimeout(timer);
        resolve(new CodexAppServerClient(ws));
      }, { once: true });
      ws.addEventListener("error", () => {
        clearTimeout(timer);
        reject(new Error(`WebSocket connection error to ${url}`));
      }, { once: true });
    });
  }

  request<T = Record<string, unknown>>(method: string, params: Record<string, unknown> = {}, timeoutMs = 15_000): Promise<T> {
    const id = ++this.#nextId;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.#pending.delete(id);
        reject(new Error(`codex app-server request '${method}' timed out after ${timeoutMs}ms`));
      }, timeoutMs).unref();
      this.#pending.set(id, {
        resolve: (result) => {
          clearTimeout(timer);
          resolve(result as T);
        },
        reject: (error) => {
          clearTimeout(timer);
          reject(error);
        },
      });
      this.#ws.send(JSON.stringify({ jsonrpc: "2.0", id, method, params }));
    });
  }

  notify(method: string, params?: Record<string, unknown>): void {
    this.#ws.send(JSON.stringify({ jsonrpc: "2.0", method, ...(params ? { params } : {}) }));
  }

  waitForNotification(
    predicate: (n: JsonRpcNotification) => boolean,
    fromIndex = 0,
    timeoutMs = 20_000,
    label = "notification",
  ): Promise<JsonRpcNotification> {
    for (let i = fromIndex; i < this.notifications.length; i += 1) {
      if (predicate(this.notifications[i]!)) return Promise.resolve(this.notifications[i]!);
    }
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.#notificationWaiters.delete(check);
        const recent = this.notifications.slice(-10).map((n) => n.method).join(", ");
        reject(new Error(`Timed out after ${timeoutMs}ms waiting for ${label} (recent: ${recent || "none"})`));
      }, timeoutMs).unref();
      const check = () => {
        for (let i = fromIndex; i < this.notifications.length; i += 1) {
          const item = this.notifications[i]!;
          if (predicate(item)) {
            clearTimeout(timer);
            this.#notificationWaiters.delete(check);
            resolve(item);
            return;
          }
        }
      };
      this.#notificationWaiters.add(check);
    });
  }

  async close(): Promise<void> {
    if (this.#ws.readyState === WebSocket.CLOSED) return;
    await new Promise<void>((resolve) => {
      const timer = setTimeout(resolve, 1_500).unref();
      this.#ws.addEventListener("close", () => {
        clearTimeout(timer);
        resolve();
      }, { once: true });
      try { this.#ws.close(); } catch { clearTimeout(timer); resolve(); }
    });
  }
}

function parseCodexTomlMcpCommand(tomlContent: string): { readonly command: string; readonly args: string[] } {
  const headerIdx = tomlContent.indexOf("[mcp_servers.hyphae]");
  assert.notEqual(headerIdx, -1, `Missing [mcp_servers.hyphae] block in config.toml:\n${tomlContent}`);
  const rest = tomlContent.slice(headerIdx + "[mcp_servers.hyphae]".length);
  const nextSection = rest.search(/\n\[/);
  const block = nextSection >= 0 ? rest.slice(0, nextSection) : rest;

  const cmdMatch = /^\s*command\s*=\s*(".*")\s*$/m.exec(block);
  const argsMatch = /^\s*args\s*=\s*(\[.*\])\s*$/m.exec(block);
  assert.ok(cmdMatch, `Could not parse command in [mcp_servers.hyphae]:\n${block}`);
  assert.ok(argsMatch, `Could not parse args in [mcp_servers.hyphae]:\n${block}`);

  const command = JSON.parse(cmdMatch[1]!) as unknown;
  const args = JSON.parse(argsMatch[1]!) as unknown;
  assert.ok(typeof command === "string", `Expected string command in [mcp_servers.hyphae]: ${String(command)}`);
  assert.ok(Array.isArray(args) && args.every((a): a is string => typeof a === "string"));
  return { command, args };
}

async function probeMcpToolsUnderEnv(
  command: string,
  args: readonly string[],
  env: NodeJS.ProcessEnv,
): Promise<string[]> {
  const proc = spawn(command, [...args], { env, stdio: ["pipe", "pipe", "pipe"] });
  const stderr: string[] = [];
  proc.stderr.on("data", (d: Buffer) => stderr.push(d.toString("utf8")));

  const pending = new Map<number, { resolve: (msg: Record<string, unknown>) => void; reject: (err: Error) => void }>();
  let nextId = 0;

  const spawnError = new Promise<never>((_resolve, reject) => {
    proc.once("error", (err) => reject(new Error(`Failed to spawn ${command}: ${err.message}`)));
  });

  createInterface({ input: proc.stdout }).on("line", (line) => {
    if (!line.trim()) return;
    let parsed: unknown;
    try { parsed = JSON.parse(line); } catch { return; }
    if (!object(parsed) || typeof parsed.id !== "number") return;
    const waiter = pending.get(parsed.id);
    if (!waiter) return;
    pending.delete(parsed.id);
    waiter.resolve(parsed);
  });

  const rpc = (method: string, params: Record<string, unknown> = {}, timeoutMs = 8_000): Promise<Record<string, unknown>> => {
    const id = ++nextId;
    return Promise.race([
      spawnError,
      new Promise<Record<string, unknown>>((resolve, reject) => {
        const timer = setTimeout(() => {
          pending.delete(id);
          reject(new Error(`MCP ${method} timed out for ${command} ${args.join(" ")}\nstderr:\n${stderr.join("")}`));
        }, timeoutMs).unref();
        pending.set(id, {
          resolve: (msg) => { clearTimeout(timer); resolve(msg); },
          reject: (err) => { clearTimeout(timer); reject(err); },
        });
        proc.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
      }),
    ]);
  };

  try {
    const initRes = await rpc("initialize", {
      protocolVersion: "2025-06-18",
      capabilities: {},
      clientInfo: { name: "electron-path-test", version: "0.1.0" },
    });
    assert.ok(object(initRes.result), `Expected MCP initialize result, got: ${JSON.stringify(initRes)}\nstderr:\n${stderr.join("")}`);
    proc.stdin.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n");

    const listRes = await rpc("tools/list", {});
    assert.ok(object(listRes.result) && Array.isArray(listRes.result.tools), `Expected tools array: ${JSON.stringify(listRes)}`);
    return listRes.result.tools
      .filter(object)
      .map((t) => String(t.name ?? ""));
  } finally {
    try { proc.stdin.end(); } catch {}
    await stopChildProcess(proc, 1_500);
  }
}

function runShellHookUnderEnv(
  cmd: string,
  stdinPayload: Record<string, unknown>,
  env: NodeJS.ProcessEnv,
  timeoutMs = 10_000,
): Promise<{ readonly code: number | null; readonly stdout: string; readonly stderr: string }> {
  return new Promise((resolve) => {
    const proc = spawn("/bin/sh", ["-c", cmd], { env, stdio: ["pipe", "pipe", "pipe"] });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    proc.stdout.on("data", (d: Buffer) => out.push(d));
    proc.stderr.on("data", (d: Buffer) => err.push(d));
    const timer = setTimeout(() => {
      try { proc.kill("SIGKILL"); } catch {}
    }, timeoutMs).unref();
    proc.once("exit", (code) => {
      clearTimeout(timer);
      resolve({
        code,
        stdout: Buffer.concat(out).toString("utf8"),
        stderr: Buffer.concat(err).toString("utf8"),
      });
    });
    proc.stdin.end(JSON.stringify(stdinPayload));
  });
}

test(
  "Test 1 — REAL codex app-server WebSocket (Codex Desktop headless engine): multi-thread rollout identity + real codex queue --remote parked-thread push wakeup",
  { skip: BINARIES.codex === null ? "codex CLI not installed locally" : false, timeout: 60_000 },
  async () => {
    const codexBin = BINARIES.codex;
    assert.ok(codexBin);

    const topo = new MeshTopology("hi-cd-");
    let appServer: ChildProcess | undefined;
    let wsClient: CodexAppServerClient | undefined;
    let api: Awaited<ReturnType<typeof startScriptedOpenAIResponsesServer>> | undefined;
    const appStderr: string[] = [];

    try {
      const router = await topo.addRouter({ name: "team" });
      const alex = await topo.addConnector({ connectorId: "alex@desktop", links: [{ name: "primary", router }] });

      alex.daemon.state.register("antigravity:peer-ops", { kind: "antigravity" });
      await alex.daemon.connector.call("antigravity:peer-ops", "hyp_join", { handle: "peer-ops" });

      const wsPort = await freePort();
      const remoteUrl = `ws://127.0.0.1:${wsPort}`;
      const baseDir = topo.subDir("cd");
      const wsDir = realpathSync(initTempWorkspace(baseDir, "ws"));

      setupCodex({
        scope: "project",
        projectDir: baseDir,
        socketPath: alex.socketPath,
        codexRemote: remoteUrl,
        runtime: devRuntime(),
      });
      const codexHome = join(baseDir, ".codex");

      let joinedA = false;
      let joinedB = false;
      let sawRemotePush = false;
      let sentAck = false;

      api = await startScriptedOpenAIResponsesServer((ctx) => {
        if (ctx.hasText("REMOTE_PUSH_TO_DESKTOP")) {
          sawRemotePush = true;
          if (!sentAck) {
            sentAck = true;
            return ctx.callTool("hyp_send", {
              to: "alex@desktop/peer-ops",
              text: "DESKTOP_ACK_PUSH",
            });
          }
          return ctx.reply("Acked remote push.");
        }
        if (ctx.hasText("desktop-a")) {
          if (!joinedA) {
            joinedA = true;
            return ctx.callTool("hyp_session", { action: "join", handle: "desktop-a" });
          }
          return ctx.reply("Joined as desktop-a.");
        }
        if (ctx.hasText("desktop-b")) {
          if (!joinedB) {
            joinedB = true;
            return ctx.callTool("hyp_session", { action: "join", handle: "desktop-b" });
          }
          return ctx.reply("Joined as desktop-b.");
        }
        return ctx.reply("OK");
      });

      const serverEnv = isolatedEnv(baseDir, {
        CODEX_HOME: codexHome,
        OPENAI_API_KEY: "sk-dummy",
      });

      appServer = spawn(
        codexBin,
        [
          "app-server",
          "--listen", remoteUrl,
          "-c", 'model_provider="dummy"',
          "-c", 'model_providers.dummy.name="dummy"',
          "-c", `model_providers.dummy.base_url="${api.url}/v1"`,
          "-c", 'model_providers.dummy.wire_api="responses"',
          "-c", 'model_providers.dummy.env_key="OPENAI_API_KEY"',
        ],
        { cwd: wsDir, env: serverEnv, stdio: ["ignore", "pipe", "pipe"] },
      );
      appServer.stderr?.on("data", (d: Buffer) => appStderr.push(d.toString("utf8")));

      // Wait for `http://127.0.0.1:${wsPort}/readyz` to return 200 (or WS listener ready)
      await waitFor(
        async () => {
          if (appServer!.exitCode !== null) {
            throw new Error(`codex app-server exited early with code ${appServer!.exitCode}:\n${appStderr.join("")}`);
          }
          try {
            const res = await fetch(`http://127.0.0.1:${wsPort}/readyz`);
            return res.status === 200;
          } catch {
            return false;
          }
        },
        { timeoutMs: 15_000, intervalMs: 100, label: `codex app-server readyz on ${wsPort}` },
      );

      wsClient = await CodexAppServerClient.connect(remoteUrl);
      await wsClient.request("initialize", {
        clientInfo: { name: "hyphae-desktop-test", version: "0.1.0" },
      });
      wsClient.notify("initialized");

      // Thread A: start + enroll as desktop-a
      const startedA = await wsClient.request<{ thread: { id: string } }>("thread/start", {
        cwd: wsDir,
        model: "gpt-5",
        approvalPolicy: "never",
        sandbox: "danger-full-access",
      });
      const threadA = startedA.thread.id;
      assert.ok(threadA, `Expected threadA id, got: ${JSON.stringify(startedA)}`);

      const markA = wsClient.notifications.length;
      await wsClient.request("turn/start", {
        threadId: threadA,
        input: [{ type: "text", text: "Join hyphae as desktop-a" }],
      });
      await wsClient.waitForNotification(
        (n) => n.method === "turn/completed" && n.params?.threadId === threadA,
        markA,
        20_000,
        "threadA turn/completed",
      );

      // Thread B on the EXACT SAME codex app-server: start + enroll as desktop-b
      const startedB = await wsClient.request<{ thread: { id: string } }>("thread/start", {
        cwd: wsDir,
        model: "gpt-5",
        approvalPolicy: "never",
        sandbox: "danger-full-access",
      });
      const threadB = startedB.thread.id;
      assert.ok(threadB, `Expected threadB id, got: ${JSON.stringify(startedB)}`);
      assert.notEqual(threadA, threadB, "Thread A and Thread B must have distinct rollout IDs");

      const markB = wsClient.notifications.length;
      await wsClient.request("turn/start", {
        threadId: threadB,
        input: [{ type: "text", text: "Join hyphae as desktop-b" }],
      });
      await wsClient.waitForNotification(
        (n) => n.method === "turn/completed" && n.params?.threadId === threadB,
        markB,
        20_000,
        "threadB turn/completed",
      );

      // Verify BOTH sessions enrolled distinctly via rollout verification with backend.remote === remoteUrl
      const sessionA = alex.daemon.state.byHandle("desktop-a");
      const sessionB = alex.daemon.state.byHandle("desktop-b");
      assert.ok(sessionA, `Expected desktop-a enrolled; sessions=${JSON.stringify(alex.daemon.connector.listSessions())}`);
      assert.ok(sessionB, `Expected desktop-b enrolled; sessions=${JSON.stringify(alex.daemon.connector.listSessions())}`);
      assert.equal(sessionA.id, `codex:${threadA}`);
      assert.equal(sessionB.id, `codex:${threadB}`);
      assert.equal(sessionA.backend.kind, "codex");
      assert.equal(sessionA.backend.remote, remoteUrl);
      assert.equal(sessionB.backend.kind, "codex");
      assert.equal(sessionB.backend.remote, remoteUrl);

      // Push message to parked Thread A -> daemon runs real `codex queue --thread <threadA> --remote ws://127.0.0.1:<wsPort>`
      await alex.daemon.connector.call("antigravity:peer-ops", "hyp_send", {
        to: "alex@desktop/desktop-a",
        text: "REMOTE_PUSH_TO_DESKTOP",
      });

      const ackItems = await waitFor(
        () => {
          const items = alex.daemon.connector.drainMailbox("antigravity:peer-ops", 5);
          return items.length > 0 ? items : null;
        },
        { timeoutMs: 20_000, intervalMs: 100, label: "peer-ops receiving DESKTOP_ACK_PUSH from woken Thread A" },
      );

      assert.equal(sawRemotePush, true, "Parked Codex Desktop thread must wake up on real codex queue --remote push");
      assert.match(ackItems[0]!.text, /hyphae from alex@desktop\/desktop-a/);
      assert.match(ackItems[0]!.text, /DESKTOP_ACK_PUSH/);
    } finally {
      await wsClient?.close().catch(() => {});
      await stopChildProcess(appServer);
      await api?.close().catch(() => {});
      await topo.cleanup();
    }
  },
);

test(
  "Test 2 — REAL isolated hc (Herdr Core) + REAL interactive codex TUI: live hc get caller verification + live hc send actuation across connectors",
  {
    skip: BINARIES.hc === null || BINARIES.codex === null ? "requires both hc (Herdr Core) and codex CLIs installed locally" : false,
    timeout: 75_000,
  },
  async () => {
    const hcBin = BINARIES.hc;
    const codexBin = BINARIES.codex;
    assert.ok(hcBin && codexBin);

    // Short /tmp/hc-XXXXXX root to stay strictly under macOS's 103-byte Unix socket path limit.
    const hcRoot = mkdtempSync("/tmp/hc-");
    for (const sub of ["h", "r", "c", "d", "s", "w", "x"]) {
      mkdirSync(join(hcRoot, sub), { recursive: true, mode: 0o700 });
    }
    const wsReal = realpathSync(join(hcRoot, "w"));
    await execFileAsync("git", ["init", "-q"], { cwd: wsReal });

    const hcEnv: NodeJS.ProcessEnv = {
      ...process.env,
      HOME: join(hcRoot, "h"),
      XDG_RUNTIME_DIR: join(hcRoot, "r"),
      XDG_CONFIG_HOME: join(hcRoot, "c"),
      XDG_DATA_HOME: join(hcRoot, "d"),
      XDG_STATE_HOME: join(hcRoot, "s"),
      HC_SESSION: "t",
      CODEX_HOME: join(hcRoot, "x"),
      OPENAI_API_KEY: "sk-dummy",
      TERM: "xterm-256color",
      PATH: process.env.PATH ?? "/usr/bin:/bin",
    };
    delete hcEnv.HC_TERMINAL_ID;
    delete hcEnv.ANTIGRAVITY_SOURCE_METADATA;
    delete hcEnv.CLAUDE_SESSION_ID;
    delete hcEnv.CODEX_THREAD_ID;
    delete hcEnv.HYPHAE_SOCKET;
    delete hcEnv.AGENTS_MESH_SOCKET;

    const topo = new MeshTopology("hi-hr-");
    let alexDaemon: IsolatedDaemonHandle | undefined;
    let api: Awaited<ReturnType<typeof startScriptedOpenAIResponsesServer>> | undefined;
    let tid: string | undefined;

    try {
      const router = await topo.addRouter({ name: "team" });
      const alexToken = router.addConnector("alex@herdr");

      await execFileAsync(hcBin, ["server", "start", "--json"], { env: hcEnv });

      alexDaemon = await startIsolatedDaemonSubprocess({
        rootDir: topo.rootDir,
        name: "d0",
        connectorId: "alex@herdr",
        routerUrl: router.url,
        token: alexToken,
        env: hcEnv,
      });

      const alice = await topo.addConnector({
        connectorId: "alice@remote",
        links: [{ name: "primary", router }],
      });
      alice.daemon.state.register("antigravity:alice-1", { kind: "antigravity" });
      await alice.daemon.connector.call("antigravity:alice-1", "hyp_join", { handle: "alice-ops" });

      let joinedHerdr = false;
      let sawRealHerdrActuation = false;
      let repliedAlice = false;

      api = await startScriptedOpenAIResponsesServer((ctx) => {
        if (ctx.hasText("WAKE_REAL_HERDR_CODEX")) {
          sawRealHerdrActuation = true;
          if (!repliedAlice) {
            repliedAlice = true;
            return ctx.callTool("hyp_send", {
              to: "alice@remote/alice-ops",
              text: "HERDR_REAL_ACTUATION_ACK",
            });
          }
          return ctx.reply("Replied to alice-ops.");
        }
        if (ctx.hasText("JOIN_MESH_AS_HERDR_CODEX")) {
          if (!joinedHerdr) {
            joinedHerdr = true;
            return ctx.callTool("hyp_session", { action: "join", handle: "herdr-codex" });
          }
          return ctx.reply("Joined as herdr-codex.");
        }
        if (ctx.hasText("WARMUP_HERDR_TUI")) {
          return ctx.reply("HERDR_TUI_WARMED_UP");
        }
        return ctx.reply("Ready.");
      });

      const cliScript = devRuntime().cliScript;
      const codexConfig = [
        'model = "gpt-5"',
        'model_provider = "dummy"',
        'approval_policy = "never"',
        'sandbox_mode = "danger-full-access"',
        "",
        "[model_providers.dummy]",
        'name = "dummy"',
        `base_url = ${JSON.stringify(`${api.url}/v1`)}`,
        'wire_api = "responses"',
        'env_key = "OPENAI_API_KEY"',
        "",
        `[projects.${JSON.stringify(wsReal)}]`,
        'trust_level = "trusted"',
        "",
        "[mcp_servers.hyphae]",
        `command = ${JSON.stringify(process.execPath)}`,
        `args = [${JSON.stringify(cliScript)}, "mcp", ${JSON.stringify(alexDaemon.socketPath)}, "--backend", "herdr"]`,
        'env_vars = ["HC_TERMINAL_ID", "HOME", "XDG_RUNTIME_DIR", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "HC_SESSION", "PATH", "HYPHAE_SOCKET"]',
        "",
      ].join("\n");
      writeFileSync(join(hcRoot, "x", "config.toml"), codexConfig, "utf8");

      // Launch real interactive Codex TUI inside isolated Herdr Core
      const launched = await execFileAsync(
        hcBin,
        ["run", "--bg", "--json", "--cwd", wsReal, "--", codexBin, "--dangerously-bypass-approvals-and-sandbox"],
        { env: hcEnv },
      );
      const launchInfo = JSON.parse(launched.stdout) as { address?: string };
      assert.ok(launchInfo.address && /^t[a-z0-9]+$/.test(launchInfo.address), `Unexpected hc run output: ${launched.stdout}`);
      tid = launchInfo.address;

      // Wait until Codex TUI renders its input prompt
      await waitFor(
        async () => {
          const getRes = await execFileAsync(hcBin, ["get", "--json", tid!], { env: hcEnv });
          const term = JSON.parse(getRes.stdout) as { state?: string };
          if (term.state !== "live") {
            const screen = await execFileAsync(hcBin, ["read", tid!], { env: hcEnv }).catch(() => ({ stdout: "" }));
            throw new Error(`Herdr terminal ${tid} exited early (state=${String(term.state)}):\n${screen.stdout}`);
          }
          const readRes = await execFileAsync(hcBin, ["read", tid!], { env: hcEnv });
          return readRes.stdout.includes("Ask Codex") || readRes.stdout.includes("›");
        },
        { timeoutMs: 15_000, intervalMs: 250, label: "Codex TUI prompt inside isolated hc" },
      );

      // Turn 1 warmup so Herdr Core reports OSC 7501 status { app: "codex", state: "done" | "idle" }
      await execFileAsync(hcBin, ["send", "--json", tid, "WARMUP_HERDR_TUI"], { env: hcEnv });

      const warmedTerm = await waitFor(
        async () => {
          const getRes = await execFileAsync(hcBin, ["get", "--json", tid!], { env: hcEnv });
          const term = JSON.parse(getRes.stdout) as {
            address?: string;
            state?: string;
            created_ms?: number;
            pid?: number;
            status?: { app?: string; state?: string } | null;
          };
          if (term.state !== "live") {
            throw new Error(`Herdr terminal ${tid} died during warmup: ${getRes.stdout}`);
          }
          if (term.status?.app === "codex" && (term.status.state === "done" || term.status.state === "idle")) {
            return term;
          }
          return null;
        },
        { timeoutMs: 20_000, intervalMs: 250, label: "hc get reporting codex done/idle after warmup" },
      );
      assert.equal(typeof warmedTerm.created_ms, "number");

      // Turn 2: instruct Codex TUI to enroll via hyp_join (verified via live `hc get`)
      await execFileAsync(hcBin, ["send", "--json", tid, "JOIN_MESH_AS_HERDR_CODEX"], { env: hcEnv });

      const enrolledSession = await waitFor(
        async () => {
          const rpc = await daemonRpc(alexDaemon!.socketPath, { type: "daemon.status" });
          if (!rpc.ok || !Array.isArray(rpc.result?.sessions)) return null;
          const sessions = rpc.result.sessions as Array<{ id?: string; handle?: string | null; backend?: string }>;
          return sessions.find(
            (s) =>
              s.handle === "herdr-codex" &&
              s.backend === "herdr" &&
              typeof s.id === "string" &&
              s.id.startsWith(`herdr:${tid}:${warmedTerm.created_ms}`),
          ) ?? null;
        },
        { timeoutMs: 20_000, intervalMs: 250, label: `herdr:${tid}:${warmedTerm.created_ms} enrolled as herdr-codex` },
      );
      assert.ok(enrolledSession);

      // Wait for Turn 2 to finish so Herdr terminal is back in "done" or "idle"
      await waitFor(
        async () => {
          const getRes = await execFileAsync(hcBin, ["get", "--json", tid!], { env: hcEnv });
          const term = JSON.parse(getRes.stdout) as { status?: { app?: string; state?: string } | null };
          return term.status?.app === "codex" && (term.status.state === "done" || term.status.state === "idle");
        },
        { timeoutMs: 15_000, intervalMs: 250, label: "hc get returning done/idle before remote wake" },
      );

      // Remote peer on alice@remote sends a cross-connector message -> alex@herdr actuates live Codex TUI via real `hc get` + `hc send`!
      await alice.daemon.connector.call("antigravity:alice-1", "hyp_send", {
        to: "alex@herdr/herdr-codex",
        text: "WAKE_REAL_HERDR_CODEX",
      });

      const aliceItems = await waitFor(
        () => {
          const items = alice.daemon.connector.drainMailbox("antigravity:alice-1", 5);
          return items.length > 0 ? items : null;
        },
        { timeoutMs: 25_000, intervalMs: 150, label: "alice-ops receiving HERDR_REAL_ACTUATION_ACK across Team Router" },
      );

      assert.equal(sawRealHerdrActuation, true, "Real Codex TUI inside isolated hc must be actuated via live hc send");
      assert.match(aliceItems[0]!.text, /hyphae from alex@herdr\/herdr-codex/);
      assert.match(aliceItems[0]!.text, /HERDR_REAL_ACTUATION_ACK/);
    } finally {
      if (tid) {
        await execFileAsync(hcBin, ["kill", tid], { env: hcEnv }).catch(() => {});
        await execFileAsync(hcBin, ["rm", tid], { env: hcEnv }).catch(() => {});
      }
      await execFileAsync(hcBin, ["server", "stop"], { env: hcEnv }).catch(() => {});
      await execFileAsync(codexBin, ["app-server", "daemon", "stop"], { env: hcEnv }).catch(() => {});
      await execFileAsync("pkill", ["-f", join(hcRoot, "x")]).catch(() => {});
      await alexDaemon?.stop().catch(() => {});
      await api?.close().catch(() => {});
      await topo.cleanup();
      rmSync(hcRoot, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
    }
  },
);

test(
  "Test 3 — Desktop Electron stripped-PATH (/usr/bin:/bin:/usr/sbin:/sbin) execution test for all generated MCP servers and shell hooks",
  { timeout: 30_000 },
  async () => {
    const topo = new MeshTopology("hi-el-");
    try {
      const router = await topo.addRouter({ name: "local" });
      const alex = await topo.addConnector({
        connectorId: "alex@electron",
        links: [{ name: "primary", router }],
      });

      const fakeHome = topo.subDir("home");
      const runtime = devRuntime();

      setupClaude({ scope: "user", homeDir: fakeHome, socketPath: alex.socketPath, runtime });
      setupCodex({ scope: "user", homeDir: fakeHome, socketPath: alex.socketPath, runtime });
      setupAntigravity({ scope: "user", homeDir: fakeHome, socketPath: alex.socketPath, noSidecar: true, runtime });
      setupCursor({ scope: "user", homeDir: fakeHome, socketPath: alex.socketPath, runtime });
      setupOpenCode({ scope: "user", homeDir: fakeHome, socketPath: alex.socketPath, runtime });
      setupOpenClaw({ scope: "user", homeDir: fakeHome, socketPath: alex.socketPath, runtime });

      const strippedEnv: NodeJS.ProcessEnv = {
        HOME: fakeHome,
        PATH: "/usr/bin:/bin:/usr/sbin:/sbin",
        USER: "test",
      };

      // Extract exact generated MCP command + args from every harness config file
      const claudeDoc = JSON.parse(readFileSync(join(fakeHome, ".claude.json"), "utf8")) as {
        mcpServers: { hyphae: { command: string; args: string[] } };
      };
      const codexParsed = parseCodexTomlMcpCommand(readFileSync(join(fakeHome, ".codex", "config.toml"), "utf8"));
      const agyDoc = JSON.parse(
        readFileSync(join(fakeHome, ".gemini", "config", "plugins", "hyphae", "mcp_config.json"), "utf8"),
      ) as { mcpServers: { hyphae: { command: string; args: string[] } } };
      const cursorDoc = JSON.parse(readFileSync(join(fakeHome, ".cursor", "mcp.json"), "utf8")) as {
        mcpServers: { hyphae: { command: string; args: string[] } };
      };
      const opencodeDoc = JSON.parse(
        readFileSync(join(fakeHome, ".config", "opencode", "opencode.json"), "utf8"),
      ) as { mcp: { hyphae: { command: string[] } } };
      const openclawDoc = JSON.parse(
        readFileSync(join(fakeHome, ".openclaw", "openclaw.json"), "utf8"),
      ) as { mcp: { servers: { hyphae: { command: string; args: string[] } } } };

      const mcpEntries: Array<{ readonly harness: string; readonly command: string; readonly args: string[] }> = [
        { harness: "claude", command: claudeDoc.mcpServers.hyphae.command, args: claudeDoc.mcpServers.hyphae.args },
        { harness: "codex", command: codexParsed.command, args: codexParsed.args },
        { harness: "antigravity", command: agyDoc.mcpServers.hyphae.command, args: agyDoc.mcpServers.hyphae.args },
        { harness: "cursor", command: cursorDoc.mcpServers.hyphae.command, args: cursorDoc.mcpServers.hyphae.args },
        {
          harness: "opencode",
          command: opencodeDoc.mcp.hyphae.command[0]!,
          args: opencodeDoc.mcp.hyphae.command.slice(1),
        },
        {
          harness: "openclaw",
          command: openclawDoc.mcp.servers.hyphae.command,
          args: openclawDoc.mcp.servers.hyphae.args,
        },
      ];

      // Spawn every generated MCP entry concurrently under stripped Electron PATH and verify consolidated CORE_MCP_TOOLS
      const mcpResults = await Promise.all(
        mcpEntries.map(async (entry) => ({
          harness: entry.harness,
          tools: await probeMcpToolsUnderEnv(entry.command, entry.args, strippedEnv),
        })),
      );

      const coreToolSet = new Set<string>(CORE_MCP_TOOLS);
      for (const { harness, tools } of mcpResults) {
        assert.equal(
          tools.length,
          CORE_MCP_TOOLS.length,
          `Expected ${CORE_MCP_TOOLS.length} core tools for ${harness} under stripped PATH, got ${tools.length}: ${tools.join(", ")}`,
        );
        for (const name of tools) {
          assert.ok(coreToolSet.has(name), `Unexpected tool '${name}' from ${harness}`);
        }
      }

      // Execute generated Claude, Antigravity, and Codex hook commands via `/bin/sh -c` under exact same stripped PATH
      const claudeSettings = JSON.parse(readFileSync(join(fakeHome, ".claude", "settings.json"), "utf8")) as {
        hooks: {
          PreToolUse: Array<{ hooks: Array<{ command: string }> }>;
          PostToolUse: Array<{ hooks: Array<{ command: string }> }>;
          Stop: Array<{ hooks: Array<{ command: string }> }>;
        };
      };
      const agyHooks = JSON.parse(
        readFileSync(join(fakeHome, ".gemini", "config", "plugins", "hyphae", "hooks.json"), "utf8"),
      ) as {
        hyphae: {
          PreToolUse: Array<{ hooks: Array<{ command: string }> }>;
          PostToolUse: Array<{ hooks: Array<{ command: string }> }>;
          PreInvocation: Array<{ command: string }>;
          Stop: Array<{ command: string }>;
        };
      };
      const codexHooks = JSON.parse(readFileSync(join(fakeHome, ".codex", "hooks.json"), "utf8")) as {
        hooks: {
          PreToolUse: Array<{ hooks: Array<{ command: string }> }>;
          PostToolUse: Array<{ hooks: Array<{ command: string }> }>;
          Stop: Array<{ hooks: Array<{ command: string }> }>;
        };
      };

      const hookChecks: Array<{
        readonly label: string;
        readonly cmd: string;
        readonly payload: Record<string, unknown>;
        readonly assertOutput?: (parsed: Record<string, unknown>) => void;
      }> = [
        {
          label: "claude PreToolUse",
          cmd: claudeSettings.hooks.PreToolUse[0]!.hooks[0]!.command,
          payload: { session_id: "claude-el-1", tool_name: "mcp__hyphae__hyp_capabilities", tool_use_id: "toolu_el_1" },
        },
        {
          label: "claude PostToolUse",
          cmd: claudeSettings.hooks.PostToolUse[0]!.hooks[0]!.command,
          payload: { session_id: "claude-el-1", tool_name: "mcp__hyphae__hyp_capabilities", tool_use_id: "toolu_el_1" },
        },
        {
          label: "claude Stop",
          cmd: claudeSettings.hooks.Stop[0]!.hooks[0]!.command,
          payload: { session_id: "claude-el-1" },
        },
        {
          label: "antigravity PreToolUse",
          cmd: agyHooks.hyphae.PreToolUse[0]!.hooks[0]!.command,
          payload: {
            conversationId: "agy-el-1",
            toolCall: {
              id: "tc_el_1",
              name: "call_mcp_tool",
              args: { ServerName: "hyphae", ToolName: "hyp_capabilities", Arguments: {} },
            },
          },
          assertOutput: (parsed) => {
            assert.equal(parsed.decision, "allow");
            assert.ok(
              object(parsed.overwrite) &&
              object(parsed.overwrite.Arguments) &&
              typeof parsed.overwrite.Arguments._meshCall === "string" &&
              parsed.overwrite.Arguments._meshCall.length > 0,
              `Expected live _meshCall token from daemon under stripped PATH, got: ${JSON.stringify(parsed)}`,
            );
          },
        },
        {
          label: "antigravity PostToolUse",
          cmd: agyHooks.hyphae.PostToolUse[0]!.hooks[0]!.command,
          payload: { conversationId: "agy-el-1", toolCall: { id: "tc_el_1", name: "call_mcp_tool" } },
        },
        {
          label: "antigravity PreInvocation",
          cmd: agyHooks.hyphae.PreInvocation[0]!.command,
          payload: { conversationId: "agy-el-1" },
        },
        {
          label: "antigravity Stop",
          cmd: agyHooks.hyphae.Stop[0]!.command,
          payload: { conversationId: "agy-el-1", terminationReason: "NO_TOOL_CALL" },
        },
        {
          label: "codex PreToolUse",
          cmd: codexHooks.hooks.PreToolUse[0]!.hooks[0]!.command,
          payload: { thread_id: "codex-el-1", tool_name: "mcp__hyphae__hyp_capabilities", call_id: "call_el_1" },
        },
        {
          label: "codex PostToolUse",
          cmd: codexHooks.hooks.PostToolUse[0]!.hooks[0]!.command,
          payload: { thread_id: "codex-el-1", tool_name: "mcp__hyphae__hyp_capabilities", call_id: "call_el_1" },
        },
        {
          label: "codex Stop",
          cmd: codexHooks.hooks.Stop[0]!.hooks[0]!.command,
          payload: { thread_id: "codex-el-1" },
        },
      ];

      for (const check of hookChecks) {
        const res = await runShellHookUnderEnv(check.cmd, check.payload, strippedEnv);
        assert.equal(
          res.code,
          0,
          `${check.label} failed under stripped PATH (exit ${res.code})\ncmd: ${check.cmd}\nstdout: ${res.stdout}\nstderr: ${res.stderr}`,
        );
        const parsed: unknown = JSON.parse(res.stdout.trim());
        assert.ok(object(parsed), `${check.label} expected JSON object stdout, got: ${res.stdout}`);
        check.assertOutput?.(parsed);
      }

      // Verify native T3 `~/.local/bin/t3` fallback resolution works under stripped Electron PATH
      // (even when `t3` is absent from `/usr/bin:/bin:/usr/sbin:/sbin`).
      const fakeT3Dir = join(fakeHome, ".local", "bin");
      mkdirSync(fakeT3Dir, { recursive: true, mode: 0o700 });
      const fakeT3Bin = join(fakeT3Dir, "t3");
      writeFileSync(fakeT3Bin, "#!/bin/sh\necho 't3_bare_path_token_ok'\n", { mode: 0o755 });
      chmodSync(fakeT3Bin, 0o755);

      const t3ModulePath = join(process.cwd(), "src", "t3.ts");
      const t3Probe = await execFileAsync(
        process.execPath,
        [
          "--input-type=module",
          "-e",
          `import { resolveT3Binary, issueT3BearerToken } from ${JSON.stringify(t3ModulePath)};` +
          `const bin = resolveT3Binary(${JSON.stringify(fakeHome)});` +
          `const tok = issueT3BearerToken(${JSON.stringify(join(fakeHome, ".t3"))}, undefined, ${JSON.stringify(fakeHome)});` +
          `console.log(JSON.stringify({ bin, tok }));`,
        ],
        { env: strippedEnv },
      );
      const t3Out = JSON.parse(t3Probe.stdout.trim()) as { bin: string | null; tok: string };
      assert.equal(t3Out.bin, fakeT3Bin, `Expected ~/.local/bin/t3 fallback under stripped PATH, got: ${t3Out.bin}`);
      assert.equal(t3Out.tok, "t3_bare_path_token_ok");
    } finally {
      await topo.cleanup();
    }
  },
);
