import assert from "node:assert/strict";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { test } from "node:test";
import { startDaemon } from "./daemon.ts";
import { handleHookPayload } from "./hooks.ts";
import { object } from "./protocol.ts";
import { runDoctor, runOnboard, setupAntigravity, setupClaude, setupCodex, setupCursor, setupGemini, setupOpenCode, setupService } from "./setup.ts";
import { serveRouter } from "./core/router/server.ts";
import { RouterCore } from "./core/router/core.ts";

class McpClient {
  readonly #proc: ChildProcessWithoutNullStreams;
  readonly #pending = new Map<number, (msg: Record<string, unknown>) => void>();
  readonly notifications: Record<string, unknown>[] = [];
  #nextId = 0;

  constructor(socketPath: string, extraArgs: string[] = []) {
    this.#proc = spawn(process.execPath, [join(process.cwd(), "src", "cli.ts"), "mcp", socketPath, ...extraArgs], {
      stdio: ["pipe", "pipe", "pipe"],
    });
    createInterface({ input: this.#proc.stdout }).on("line", (line) => {
      const msg: unknown = JSON.parse(line);
      if (!object(msg)) return;
      if (typeof msg.id === "number") {
        const resolve = this.#pending.get(msg.id);
        if (resolve) {
          this.#pending.delete(msg.id);
          resolve(msg);
        }
      } else {
        this.notifications.push(msg);
      }
    });
  }

  async initialize(): Promise<Record<string, unknown>> {
    const res = await this.request("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "test", version: "1" } });
    this.#proc.stdin.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n");
    return res;
  }

  request(method: string, params: Record<string, unknown> = {}): Promise<Record<string, unknown>> {
    const id = ++this.#nextId;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`MCP request ${method} timed out`)), 5_000).unref();
      this.#pending.set(id, (msg) => {
        clearTimeout(timer);
        resolve(msg);
      });
      this.#proc.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
    });
  }

  async callTool(name: string, args: Record<string, unknown>, meta?: Record<string, unknown>): Promise<{ text: string; isError: boolean }> {
    const res = await this.request("tools/call", {
      name,
      arguments: args,
      ...(meta ? { _meta: meta } : {}),
    });
    const result = object(res.result) ? res.result : {};
    const content = Array.isArray(result.content) && object(result.content[0]) ? result.content[0] : {};
    return { text: String(content.text ?? ""), isError: result.isError === true };
  }

  close(): Promise<void> {
    return new Promise((resolve) => {
      if (this.#proc.exitCode !== null) { resolve(); return; }
      this.#proc.once("exit", () => resolve());
      this.#proc.stdin.end();
      setTimeout(() => { if (this.#proc.exitCode === null) this.#proc.kill("SIGKILL"); }, 1000).unref();
    });
  }
}

test("ONE shared MCP subprocess multiplexes Antigravity, Claude, and Codex threads with zero-polling push wakeup over real t3-mesh router", { timeout: 15_000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "hyphae-e2e-"));
  const routerStore = new RouterCore({ dbPath: join(dir, "router.sqlite") });
  const token = routerStore.addConnector("bogdan@local");
  const router = await serveRouter({ core: routerStore, host: "127.0.0.1", port: 0 });
  const tokenFile = join(dir, "connector.token");
  writeFileSync(tokenFile, token + "\n", { mode: 0o600 });
  chmodSync(tokenFile, 0o600);

  const daemon = await startDaemon({
    connectorId: "bogdan@local",
    directory: join(dir, "state"),
    routers: [{ name: "primary", url: router.url, token }],
  }, { quiet: true });

  // ONE shared MCP process serving ALL 3 harnesses simultaneously!
  const sharedMcp = new McpClient(daemon.socketPath);
  await sharedMcp.initialize();

  try {
    // 0. Calling a tool without PreToolUse hook verification fails closed!
    const unverified = await sharedMcp.callTool("mesh_join", { handle: "spoof" });
    assert.equal(unverified.isError, true);
    assert.match(unverified.text, /caller_unverifiable/);

    // 1. Antigravity conversation joins via PreToolUse `overwrite` token on the shared MCP process
    const agPre = await handleHookPayload(
      { conversationId: "ag-conv-1", toolCall: { id: "ag-call-1", name: "mesh_join", args: { handle: "ag-peer" } } },
      { harness: "antigravity", event: "pre-tool-use", socketPath: daemon.socketPath },
    );
    const agJoin = await sharedMcp.callTool("mesh_join", { handle: "ag-peer", ...(object(agPre.overwrite) ? agPre.overwrite : {}) });
    assert.equal(agJoin.isError, false);
    assert.deepEqual(JSON.parse(agJoin.text), { address: "bogdan@local/ag-peer" });

    // 2. Claude session joins via PreToolUse + `_meta["claudecode/toolUseId"]` on the SAME shared MCP process
    await handleHookPayload(
      { session_id: "claude-sess-2", tool_use_id: "toolu_join_2", tool_name: "mcp__hyphae__mesh_join" },
      { harness: "claude", event: "pre-tool-use", socketPath: daemon.socketPath },
    );
    const claudeJoin = await sharedMcp.callTool("mesh_join", { handle: "claude-peer" }, { "claudecode/toolUseId": "toolu_join_2" });
    assert.equal(claudeJoin.isError, false);
    assert.deepEqual(JSON.parse(claudeJoin.text), { address: "bogdan@local/claude-peer" });

    // 3. Codex thread joins via PreToolUse + `_meta.callId` on the SAME shared MCP process
    await handleHookPayload(
      { session_id: "codex-thr-3", tool_use_id: "call_join_3", tool_name: "hyphae.mesh_join" },
      { harness: "codex", event: "pre-tool-use", socketPath: daemon.socketPath },
    );
    const codexJoin = await sharedMcp.callTool("mesh_join", { handle: "codex-peer" }, { callId: "call_join_3" });
    assert.equal(codexJoin.isError, false);
    assert.deepEqual(JSON.parse(codexJoin.text), { address: "bogdan@local/codex-peer" });

    // Verify all 3 sessions registered under their distinct real host IDs
    const sessions = daemon.connector.listSessions();
    assert.equal(sessions.length, 3);
    assert.deepEqual(
      sessions.map((s) => `${s.id}=${s.handle}`).sort(),
      ["antigravity:ag-conv-1=ag-peer", "claude:claude-sess-2=claude-peer", "codex:codex-thr-3=codex-peer"],
    );

    // 4. Antigravity arms blocking `hyp wait` (inferring session from ANTIGRAVITY_SOURCE_METADATA!)
    const agWaitProc = spawn(process.execPath, [join(process.cwd(), "src", "cli.ts"), "wait", "--socket", daemon.socketPath], {
      env: { ...process.env, ANTIGRAVITY_SOURCE_METADATA: JSON.stringify({ tool: { conversationId: "ag-conv-1" } }) },
      stdio: ["ignore", "pipe", "pipe"],
    });
    const agWaitOut = new Promise<string>((resolve, reject) => {
      const chunks: Buffer[] = [];
      agWaitProc.stdout.on("data", (chunk: Buffer) => chunks.push(chunk));
      agWaitProc.once("exit", (code) => {
        if (code === 0) resolve(Buffer.concat(chunks).toString("utf8"));
        else reject(new Error(`wait exited with ${code}`));
      });
    });

    // Wait briefly for waiter to attach, then verify Stop hook allows Antigravity to stay idle!
    for (let i = 0; i < 40; i++) {
      const st = await handleHookPayload(
        { conversationId: "ag-conv-1", continuationActive: false, terminationReason: "NO_TOOL_CALL" },
        { harness: "antigravity", event: "stop", socketPath: daemon.socketPath },
      );
      if (Object.keys(st).length === 0) break;
      await new Promise((r) => setTimeout(r, 50));
    }
    const agStopWhileArmed = await handleHookPayload(
      { conversationId: "ag-conv-1", continuationActive: false, terminationReason: "NO_TOOL_CALL" },
      { harness: "antigravity", event: "stop", socketPath: daemon.socketPath },
    );
    assert.deepEqual(agStopWhileArmed, {});

    // 5. Claude sends a real mesh message to Antigravity through the real t3-mesh router!
    await handleHookPayload(
      { session_id: "claude-sess-2", tool_use_id: "toolu_send_1", tool_name: "mcp__hyphae__mesh_send" },
      { harness: "claude", event: "pre-tool-use", socketPath: daemon.socketPath },
    );
    const sendToAg = await sharedMcp.callTool(
      "mesh_send",
      { to: "bogdan@local/ag-peer", text: "wake up antigravity!" },
      { "claudecode/toolUseId": "toolu_send_1" },
    );
    assert.equal(sendToAg.isError, false);

    // Antigravity's blocking `wait` exits 0 immediately with the payload (zero polling!)
    const agReceived = await agWaitOut;
    assert.match(agReceived, /mesh from bogdan@local\/claude-peer/);
    assert.match(agReceived, /wake up antigravity!/);

    // 6. Claude starts streaming `hyp watch` (Monitor mode) and receives Antigravity's reply!
    const claudeWatchProc = spawn(
      process.execPath,
      [join(process.cwd(), "src", "cli.ts"), "watch", "--session", "claude:claude-sess-2", "--socket", daemon.socketPath],
      { stdio: ["ignore", "pipe", "pipe"] },
    );
    const firstWatchLine = new Promise<string>((resolve) => {
      createInterface({ input: claudeWatchProc.stdout }).once("line", resolve);
    });
    await new Promise((r) => setTimeout(r, 150));

    const agSendPre = await handleHookPayload(
      { conversationId: "ag-conv-1", toolCall: { id: "ag-call-2", name: "mesh_send", args: {} } },
      { harness: "antigravity", event: "pre-tool-use", socketPath: daemon.socketPath },
    );
    const replyToClaude = await sharedMcp.callTool("mesh_send", {
      to: "bogdan@local/claude-peer",
      text: "pong from antigravity!",
      ...(object(agSendPre.overwrite) ? agSendPre.overwrite : {}),
    });
    assert.equal(replyToClaude.isError, false);

    const watchEvent = JSON.parse(await firstWatchLine) as { text: string };
    assert.match(watchEvent.text, /mesh from bogdan@local\/ag-peer/);
    assert.match(watchEvent.text, /pong from antigravity!/);
    claudeWatchProc.kill("SIGTERM");

    // 7. Codex receives a message while mid-turn and drains it immediately on Stop hook (zero polling!)
    const agSendCodexPre = await handleHookPayload(
      { conversationId: "ag-conv-1", toolCall: { id: "ag-call-3", name: "mesh_send", args: {} } },
      { harness: "antigravity", event: "pre-tool-use", socketPath: daemon.socketPath },
    );
    await sharedMcp.callTool("mesh_send", {
      to: "bogdan@local/codex-peer",
      text: "hey codex desktop!",
      ...(object(agSendCodexPre.overwrite) ? agSendCodexPre.overwrite : {}),
    });
    await new Promise((r) => setTimeout(r, 150));

    const codexStop = await handleHookPayload(
      { session_id: "codex-thr-3", stop_hook_active: false },
      { harness: "codex", event: "stop", socketPath: daemon.socketPath },
    );
    assert.equal(codexStop.decision, "block");
    assert.match(String(codexStop.reason), /hey codex desktop!/);

    // 8. Prune stale sessions (simulate old session) — active sessions stay, stale ones drop!
    daemon.state.touch("codex:codex-thr-3", Date.now() - 10 * 86_400_000);
    const pruned = await daemon.connector.pruneStale(7 * 86_400_000);
    assert.deepEqual(pruned, ["codex:codex-thr-3"]);
    assert.equal(daemon.state.byHandle("codex-peer"), undefined);
  } finally {
    await sharedMcp.close();
    await daemon.stop();
    await router.close();
    routerStore.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("setup commands generate valid, idempotent configs for Antigravity, Claude, Codex, and OS service without clobbering existing entries", async () => {
  const dir = mkdtempSync(join(tmpdir(), "hyphae-setup-"));
  const home = join(dir, "home");
  const project = join(dir, "proj");
  const runtime = { nodeBin: "/opt/node24/bin/node", cliScript: "/opt/hyphae/bin/hyphae.mjs" };

  try {
    // Pre-populate existing Claude & Codex configs to prove non-destructive merging
    const claudeMcpPath = join(home, ".claude.json");
    const claudeSettingsPath = join(home, ".claude", "settings.json");
    const codexTomlPath = join(home, ".codex", "config.toml");
    const codexHooksPath = join(home, ".codex", "hooks.json");

    const preExisting = { mcpServers: { other: { command: "other-mcp", args: [] } } };
    const preSettings = { theme: "dark", hooks: { Stop: [{ hooks: [{ type: "command", command: "echo custom" }] }] } };
    const fs = await import("node:fs");
    fs.mkdirSync(join(home, ".claude"), { recursive: true });
    fs.mkdirSync(join(home, ".codex"), { recursive: true });
    writeFileSync(claudeMcpPath, JSON.stringify(preExisting));
    writeFileSync(claudeSettingsPath, JSON.stringify(preSettings));
    writeFileSync(codexTomlPath, 'model = "gpt-5"\n');
    writeFileSync(codexHooksPath, JSON.stringify({ hooks: { Stop: [{ hooks: [{ type: "command", command: "echo keep" }] }] } }));

    // Run setup twice to verify idempotency across all 6 harnesses
    for (let i = 0; i < 2; i++) {
      setupAntigravity({ scope: "user", homeDir: home, runtime });
      setupClaude({ scope: "user", homeDir: home, runtime });
      setupCodex({ scope: "user", homeDir: home, runtime });
      setupCursor({ scope: "user", homeDir: home, runtime });
      setupOpenCode({ scope: "user", homeDir: home, runtime });
      setupGemini({ scope: "user", homeDir: home, runtime });
    }

    // Verify Antigravity plugin
    const agPluginDir = join(home, ".gemini", "config", "plugins", "hyphae");
    assert.ok(existsSync(join(agPluginDir, "plugin.json")));
    assert.ok(existsSync(join(agPluginDir, "mcp_config.json")));
    assert.ok(existsSync(join(agPluginDir, "hooks.json")));
    assert.ok(existsSync(join(agPluginDir, "sidecars", "daemon", "sidecar.json")));
    assert.ok(existsSync(join(agPluginDir, "rules", "AGENTS.md")));
    assert.ok(existsSync(join(agPluginDir, "skills", "hyphae", "SKILL.md")));

    // Verify Claude preserved existing MCP server & hooks and did not duplicate hyphae
    const claudeMcp = JSON.parse(readFileSync(claudeMcpPath, "utf8")) as { mcpServers: Record<string, unknown> };
    assert.ok(claudeMcp.mcpServers.other);
    assert.ok(claudeMcp.mcpServers["hyphae"]);
    const claudeSettings = JSON.parse(readFileSync(claudeSettingsPath, "utf8")) as { theme: string; hooks: { Stop: unknown[] } };
    assert.equal(claudeSettings.theme, "dark");
    assert.equal(claudeSettings.hooks.Stop.length, 2);

    // Verify Codex preserved existing TOML & hooks and did not duplicate block
    const codexToml = readFileSync(codexTomlPath, "utf8");
    assert.match(codexToml, /model = "gpt-5"/);
    assert.equal(codexToml.match(/\[mcp_servers\.hyphae\]/g)?.length, 1);
    const codexHooks = JSON.parse(readFileSync(codexHooksPath, "utf8")) as { hooks: { Stop: unknown[] } };
    assert.equal(codexHooks.hooks.Stop.length, 2);

    // Verify Cursor, OpenCode, and Gemini CLI configs (idempotent & non-colliding with Antigravity)
    const cursorMcp = JSON.parse(readFileSync(join(home, ".cursor", "mcp.json"), "utf8")) as { mcpServers: Record<string, unknown> };
    assert.ok(cursorMcp.mcpServers["hyphae"]);
    const cursorHooks = JSON.parse(readFileSync(join(home, ".cursor", "hooks.json"), "utf8")) as { version: number; hooks: { beforeMCPExecution: unknown[]; stop: unknown[] } };
    assert.equal(cursorHooks.version, 1);
    assert.equal(cursorHooks.hooks.beforeMCPExecution.length, 1);
    assert.equal(cursorHooks.hooks.stop.length, 1);

    const openCodeCfg = JSON.parse(readFileSync(join(home, ".config", "opencode", "opencode.json"), "utf8")) as { mcp: Record<string, { type: string; command: string[] }> };
    assert.equal(openCodeCfg.mcp["hyphae"].type, "local");
    assert.equal(openCodeCfg.mcp["hyphae"].command[0], "/opt/node24/bin/node");
    assert.ok(existsSync(join(home, ".config", "opencode", "plugins", "hyphae.ts")));

    const geminiSettings = JSON.parse(readFileSync(join(home, ".gemini", "settings.json"), "utf8")) as {
      mcpServers: Record<string, unknown>;
      tools: { enableHooks: boolean };
      hooks: { BeforeTool: unknown[]; AfterAgent: unknown[] };
    };
    assert.ok(geminiSettings.mcpServers["hyphae"]);
    assert.equal(geminiSettings.tools.enableHooks, true);
    assert.equal(geminiSettings.hooks.BeforeTool.length, 1);
    assert.equal(geminiSettings.hooks.AfterAgent.length, 1);

    // Verify macOS launchd plist & Linux systemd service generation
    const macSvc = setupService({ install: true, configPath: join(dir, "connector.json"), homeDir: home, platform: "darwin", runtime });
    assert.ok(existsSync(macSvc.path));
    assert.match(readFileSync(macSvc.path, "utf8"), /\/opt\/node24\/bin\/node/);

    const linuxSvc = setupService({ install: true, configPath: join(dir, "connector.json"), homeDir: home, platform: "linux", runtime });
    assert.ok(existsSync(linuxSvc.path));
    assert.match(readFileSync(linuxSvc.path, "utf8"), /ExecStart=\/opt\/node24\/bin\/node/);

    // Verify doctor reports installed harness configs
    const checks = await runDoctor(join(dir, "missing.json"), join(dir, "missing.sock"), home);
    assert.equal(checks.find((c) => c.name === "antigravity")?.ok, true);
    assert.equal(checks.find((c) => c.name === "claude")?.ok, true);
    assert.equal(checks.find((c) => c.name === "codex")?.ok, true);
    assert.equal(checks.find((c) => c.name === "cursor")?.ok, true);
    assert.equal(checks.find((c) => c.name === "opencode")?.ok, true);
    assert.equal(checks.find((c) => c.name === "gemini")?.ok, true);

    // Project scope setup check
    const projAg = setupAntigravity({ scope: "project", projectDir: project, runtime });
    assert.ok(projAg.files.some((f) => f.includes(".agents/plugins/hyphae/hooks.json")));
    assert.ok(!projAg.files.some((f) => f.includes("sidecar.json")));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// Sanity test that stale socket file is safely cleaned up on daemon restart
test("daemon cleans up stale connector.sock and refuses duplicate live daemon", async () => {
  const dir = mkdtempSync(join(tmpdir(), "hyphae-sock-"));
  const server = createServer((_req, res) => { res.writeHead(200); res.end('{"unknownTopics":[]}'); });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");

  try {
    const stateDir = join(dir, "state");
    const cfg = {
      connectorId: "user@host",
      directory: stateDir,
      routers: [{ name: "primary", url: `http://127.0.0.1:${addr.port}`, token: "tok" }],
    };
    const d1 = await startDaemon(cfg, { quiet: true });
    // Starting a second live daemon on the same socket fails cleanly
    await assert.rejects(startDaemon(cfg, { quiet: true }), /already running/);
    await d1.stop();

    // Create a leftover stale socket file and verify daemon recovers cleanly
    const staleSock = join(stateDir, "connector.sock");
    writeFileSync(staleSock, "");
    const d2 = await startDaemon(cfg, { quiet: true });
    await d2.stop();
  } finally {
    server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("MCP shim stays alive and returns a clean error when daemon socket is missing", async () => {
  const dir = mkdtempSync(join(tmpdir(), "hyphae-nosock-"));
  const client = new McpClient(join(dir, "missing.sock"));
  try {
    await client.initialize();
    const res = await client.callTool("mesh_capabilities", {});
    assert.equal(res.isError, true);
    assert.match(res.text, /daemon is not running/i);
    // Process must still be alive for subsequent ping
    const ping = await client.request("ping");
    assert.deepEqual(ping.result, {});
  } finally {
    await client.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("onboard creates embedded local router config, configures harnesses, and daemon starts both router + connector in one process", async () => {
  const dir = mkdtempSync(join(tmpdir(), "hyphae-onboard-"));
  const home = join(dir, "home");
  const configPath = join(dir, "config", "connector.json");
  const runtime = { nodeBin: process.execPath, cliScript: join(process.cwd(), "src", "cli.ts") };

  try {
    const res = await runOnboard({
      configPath,
      connectorId: "dev@local",
      port: 0,
      homeDir: home,
      harnesses: ["antigravity", "claude", "codex"],
      startDaemon: false,
      runtime,
    });
    assert.equal(res.configCreated, true);
    assert.equal(res.localRouter, true);
    assert.equal(res.configuredHarnesses.length, 3);

    const { loadConfig } = await import("./config.ts");
    const loaded = loadConfig(configPath);
    const daemon = await startDaemon(loaded, { quiet: true });
    try {
      assert.ok(daemon.localRouterUrl?.startsWith("http://127.0.0.1:"));
      daemon.state.register("antigravity:test-1", { kind: "antigravity" });
      const joined = await daemon.connector.call("antigravity:test-1", "mesh_join", { handle: "solo" });
      assert.deepEqual(joined, { address: "dev@local/solo" });
    } finally {
      await daemon.stop();
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
