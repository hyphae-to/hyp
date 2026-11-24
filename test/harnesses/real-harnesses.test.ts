import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { startDaemon } from "../../src/daemon.ts";
import { setupAntigravity, setupClaude, setupCodex } from "../../src/setup.ts";
import { RouterCore } from "../../src/core/router/core.ts";
import { serveRouter } from "../../src/core/router/server.ts";
import { startDummyAnthropicServer, startDummyOpenAIServer } from "./dummy-apis.ts";

function findBinary(name: string): string | null {
  try {
    return execFileSync("which", [name], { encoding: "utf8" }).trim() || null;
  } catch {
    return null;
  }
}

function runProcess(
  bin: string,
  args: string[],
  options: { cwd: string; env: NodeJS.ProcessEnv; timeoutMs?: number },
): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const proc = spawn(bin, args, { cwd: options.cwd, env: options.env, stdio: ["ignore", "pipe", "pipe"] });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    proc.stdout.on("data", (d: Buffer) => out.push(d));
    proc.stderr.on("data", (d: Buffer) => err.push(d));
    const timer = setTimeout(() => { proc.kill("SIGKILL"); }, options.timeoutMs ?? 45_000).unref();
    proc.once("exit", (code) => {
      clearTimeout(timer);
      resolve({ code, stdout: Buffer.concat(out).toString("utf8"), stderr: Buffer.concat(err).toString("utf8") });
    });
  });
}

const claudeBin = findBinary("claude");
const codexBin = findBinary("codex");
const agyBin = findBinary("agy");
const hcBin = findBinary("hc");

test(
  "REAL Claude Code binary + dummy Anthropic API: per-call PreToolUse identity + zero-polling Stop hook push + hyp_send reply",
  { skip: claudeBin === null ? "claude CLI not installed locally" : false, timeout: 60_000 },
  async () => {
    assert.ok(claudeBin);
    const dir = mkdtempSync(join(tmpdir(), "hyphae-real-claude-"));
    const workspace = join(dir, "workspace");
    mkdirSync(workspace, { recursive: true });
    execFileSync("git", ["init", "-q"], { cwd: workspace });

    const routerStore = new RouterCore({ dbPath: join(dir, "router.sqlite") });
    const token = routerStore.addConnector("bogdan@local");
    const router = await serveRouter({ core: routerStore, host: "127.0.0.1", port: 0 });
    const daemon = await startDaemon({
      connectorId: "bogdan@local",
      directory: join(dir, "state"),
      routers: [{ name: "primary", url: router.url, token }],
    }, { quiet: true });

    // Enroll a virtual peer on the same daemon so real Claude can exchange messages with it!
    daemon.state.register("antigravity:peer-conv", { kind: "antigravity" });
    await daemon.connector.call("antigravity:peer-conv", "hyp_join", { handle: "peer-bot" });

    // Generate real project setup via `setupClaude`!
    const runtime = { nodeBin: process.execPath, cliScript: join(process.cwd(), "src", "cli.ts") };
    setupClaude({ scope: "project", projectDir: workspace, socketPath: daemon.socketPath, runtime });

    let sawPushedMessage = false;
    let pushedToClaude = false;
    let didJoin = false;
    let didSearch = false;

    const dummyApi = await startDummyAnthropicServer(async (req) => {
      const joinTool = req.tools.find((t) => t.name.endsWith("hyp_join"))?.name;
      const sendTool = req.tools.find((t) => t.name.endsWith("hyp_send"))?.name;
      const toolSearch = req.tools.find((t) => t.name === "ToolSearch")?.name;
      const allText = JSON.stringify(req.messages);

      // Claude Code defers MCP tools behind ToolSearch by default: load them first!
      if (!joinTool && toolSearch && !didSearch) {
        didSearch = true;
        return {
          type: "tool_use",
          id: "toolu_search_0",
          name: toolSearch,
          input: { query: "select:mcp__hyphae__hyp_join,mcp__hyphae__hyp_send" },
        };
      }

      if (!didJoin) {
        didJoin = true;
        assert.ok(joinTool, `Expected Claude to advertise hyp_join; got: ${req.tools.map((t) => t.name).join(", ")}`);
        return { type: "tool_use", id: "toolu_real_join_1", name: joinTool, input: { handle: "claude-real" } };
      }

      if (!pushedToClaude) {
        assert.match(allText, /bogdan@local\/claude-real/, `Expected hyp_join result in messages, got: ${allText}`);
        pushedToClaude = true;
        await daemon.connector.call("antigravity:peer-conv", "hyp_send", {
          to: "bogdan@local/claude-real",
          text: "push-hello-to-real-claude",
        });
        // Let SSE deliver into SQLite mailbox before Claude finishes turn and fires Stop hook!
        await new Promise((r) => setTimeout(r, 200));
        return { type: "text", text: "Joined as claude-real." };
      }

      if (allText.includes("push-hello-to-real-claude") && !sawPushedMessage) {
        sawPushedMessage = true;
        assert.ok(sendTool, "Expected hyp_send tool");
        return {
          type: "tool_use",
          id: "toolu_real_send_2",
          name: sendTool,
          input: { to: "bogdan@local/peer-bot", text: "ack-from-real-claude-without-polling" },
        };
      }

      return { type: "text", text: "All done!" };
    });

    try {
      const env: NodeJS.ProcessEnv = {
        ...process.env,
        ANTHROPIC_BASE_URL: dummyApi.url,
        ANTHROPIC_API_KEY: "sk-ant-dummy-local-test",
        CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1",
        DISABLE_TELEMETRY: "1",
      };
      delete env.HC_TERMINAL_ID;

      const res = await runProcess(
        claudeBin,
        [
          "-p", "Join the mesh as claude-real and respond to any peer message.",
          "--mcp-config", join(workspace, ".mcp.json"),
          "--strict-mcp-config",
          "--settings", join(workspace, ".claude", "settings.json"),
          "--dangerously-skip-permissions",
          "--no-session-persistence",
          "--model", "claude-sonnet-4-5",
        ],
        { cwd: workspace, env },
      );

      assert.equal(res.code, 0, `claude exited ${res.code}\nstdout:\n${res.stdout}\nstderr:\n${res.stderr}`);
      assert.equal(sawPushedMessage, true, "Real Claude should have received peer message via Stop/PostToolUse hook without polling hyp_inbox");

      // Verify identity was bound to real `claude:<session_id>`, NOT a random MCP UUID
      const claudeSession = daemon.state.byHandle("claude-real");
      assert.ok(claudeSession, "Expected claude-real handle to be enrolled");
      assert.match(claudeSession.id, /^claude:.+/);

      // Verify peer-bot received Claude's reply through the real router!
      await new Promise((r) => setTimeout(r, 250));
      const peerInbox = daemon.connector.drainMailbox("antigravity:peer-conv", 5);
      assert.equal(peerInbox.length, 1, `Expected 1 reply in peer-bot mailbox, got ${peerInbox.length}`);
      assert.match(peerInbox[0].text, /hyphae from bogdan@local\/claude-real/);
      assert.match(peerInbox[0].text, /ack-from-real-claude-without-polling/);
    } finally {
      await dummyApi.close();
      await daemon.stop();
      await router.close();
      routerStore.close();
      rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
    }
  },
);

test(
  "REAL Codex binary + dummy OpenAI Responses API: per-call rollout identity (no --thread!) + native codex queue push",
  { skip: codexBin === null ? "codex CLI not installed locally" : false, timeout: 60_000 },
  async () => {
    assert.ok(codexBin);
    const dir = mkdtempSync(join(tmpdir(), "hyphae-real-codex-"));
    const workspace = join(dir, "workspace");
    mkdirSync(workspace, { recursive: true });
    execFileSync("git", ["init", "-q"], { cwd: workspace });

    const routerStore = new RouterCore({ dbPath: join(dir, "router.sqlite") });
    const token = routerStore.addConnector("bogdan@local");
    const router = await serveRouter({ core: routerStore, host: "127.0.0.1", port: 0 });
    const daemon = await startDaemon({
      connectorId: "bogdan@local",
      directory: join(dir, "state"),
      routers: [{ name: "primary", url: router.url, token }],
    }, { quiet: true });

    daemon.state.register("antigravity:peer-conv", { kind: "antigravity" });
    await daemon.connector.call("antigravity:peer-conv", "hyp_join", { handle: "peer-bot" });

    // Generate real Codex config + hooks via `setupCodex` into isolated CODEX_HOME!
    const runtime = { nodeBin: process.execPath, cliScript: join(process.cwd(), "src", "cli.ts") };
    setupCodex({ scope: "project", projectDir: dir, socketPath: daemon.socketPath, runtime });
    const generatedCodexHome = join(dir, ".codex");

    let didJoin = false;
    let didReply = false;

    const dummyApi = await startDummyOpenAIServer(async (req) => {
      const joinTool = req.tools.find((t) => t.name.endsWith("hyp_join"));
      const sendTool = req.tools.find((t) => t.name.endsWith("hyp_send"));
      const allText = JSON.stringify(req.input);

      if (!didJoin) {
        didJoin = true;
        assert.ok(joinTool, `Expected Codex to advertise hyp_join; got: ${JSON.stringify(req.tools)}`);
        return {
          type: "function_call",
          callId: "call_real_codex_join_1",
          name: joinTool.name,
          ...(joinTool.namespace ? { namespace: joinTool.namespace } : {}),
          arguments: { handle: "codex-real" },
        };
      }

      if (allText.includes("push-hello-to-real-codex") && !didReply) {
        didReply = true;
        assert.ok(sendTool, "Expected hyp_send tool");
        return {
          type: "function_call",
          callId: "call_real_codex_send_2",
          name: sendTool.name,
          ...(sendTool.namespace ? { namespace: sendTool.namespace } : {}),
          arguments: { to: "bogdan@local/peer-bot", text: "ack-from-real-codex-via-queue" },
        };
      }

      return { type: "text", text: "Done!" };
    });

    try {
      const env: NodeJS.ProcessEnv = {
        ...process.env,
        CODEX_HOME: generatedCodexHome,
        OPENAI_API_KEY: "sk-dummy-local-codex",
      };
      delete env.HC_TERMINAL_ID;

      const commonArgs = [
        "--skip-git-repo-check",
        "--dangerously-bypass-approvals-and-sandbox",
        "-m", "gpt-5",
        "-c", 'model_provider="dummy"',
        "-c", 'model_providers.dummy.name="dummy"',
        "-c", `model_providers.dummy.base_url="${dummyApi.url}/v1"`,
        "-c", 'model_providers.dummy.wire_api="responses"',
        "-c", 'model_providers.dummy.env_key="OPENAI_API_KEY"',
      ];

      // Step 1: Real Codex joins via MCP — caller verified directly from rollout JSONL (NO --thread flag!)
      const res1 = await runProcess(
        codexBin,
        ["exec", ...commonArgs, "Join the mesh as codex-real."],
        { cwd: workspace, env },
      );
      assert.equal(res1.code, 0, `codex exec exited ${res1.code}\nstdout:\n${res1.stdout}\nstderr:\n${res1.stderr}`);

      const codexSession = daemon.state.byHandle("codex-real");
      assert.ok(codexSession, `Expected codex-real handle to be enrolled via rollout verification.\nstderr:\n${res1.stderr}\nrequests:\n${JSON.stringify(dummyApi.requests.map((r) => r.input), null, 2)}`);
      assert.match(codexSession.id, /^codex:[0-9a-f-]+$/i);
      const threadId = codexSession.id.slice("codex:".length);

      // Step 2: Peer sends a real mesh message → daemon pushes it natively via `codex queue --thread <id>`!
      await daemon.connector.call("antigravity:peer-conv", "hyp_send", {
        to: "bogdan@local/codex-real",
        text: "push-hello-to-real-codex",
      });
      // Wait for SSE → daemon → `codex queue` submission
      const deadline = Date.now() + 8_000;
      let deliveredToQueue = false;
      while (Date.now() < deadline) {
        const queued = execFileSync(
          process.execPath,
          [
            "-e",
            `import { DatabaseSync } from "node:sqlite"; const db = new DatabaseSync(${JSON.stringify(join(generatedCodexHome, "queue_1.sqlite"))}); const rows = db.prepare("SELECT * FROM sqlite_master WHERE type='table'").all(); console.log(JSON.stringify(rows.map(r => ({ name: r.name, rows: db.prepare('SELECT * FROM "' + r.name + '"').all() }))));`,
          ],
          { encoding: "utf8" },
        );
        if (queued.includes("push-hello-to-real-codex") && queued.includes(threadId)) {
          deliveredToQueue = true;
          break;
        }
        await new Promise((r) => setTimeout(r, 150));
      }
      assert.equal(deliveredToQueue, true, "Expected daemon to push peer message directly into Codex native queue_1.sqlite without polling");

      // Step 3: Spin up a SECOND real Codex thread against the EXACT SAME config & daemon —
      // proves 1 connector : N threads with zero per-thread config or handle collision!
      didJoin = false;
      const res2 = await runProcess(
        codexBin,
        ["exec", ...commonArgs, "Join the mesh as codex-second."],
        { cwd: workspace, env },
      );
      assert.equal(res2.code, 0, `second codex exec exited ${res2.code}\nstderr:\n${res2.stderr}`);
      // Second thread trying to claim `codex-real` is blocked by handle ownership on distinct thread ID
      const sessions = daemon.connector.listSessions().filter((s) => s.id.startsWith("codex:"));
      assert.equal(sessions.length, 2, `Expected 2 distinct codex:<uuid> sessions, got: ${JSON.stringify(sessions)}`);
      assert.notEqual(sessions[0].id, sessions[1].id);
    } finally {
      await dummyApi.close();
      await daemon.stop();
      await router.close();
      routerStore.close();
      rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
    }
  },
);

test(
  "REAL Antigravity CLI discovers generated user plugin cleanly",
  { skip: agyBin === null ? "agy CLI not installed locally" : false, timeout: 30_000 },
  async () => {
    assert.ok(agyBin);
    const dir = mkdtempSync(join(tmpdir(), "hyphae-real-agy-"));
    const fakeHome = join(dir, "home");
    mkdirSync(fakeHome, { recursive: true });
    const runtime = { nodeBin: process.execPath, cliScript: join(process.cwd(), "src", "cli.ts") };
    setupAntigravity({ scope: "user", homeDir: fakeHome, socketPath: join(dir, "connector.sock"), runtime });

    try {
      const res = await runProcess(agyBin, ["plugin", "list"], {
        cwd: dir,
        env: { ...process.env, HOME: fakeHome },
      });
      assert.equal(res.code, 0, `agy plugin list exited ${res.code}\nstdout:\n${res.stdout}\nstderr:\n${res.stderr}`);
      assert.match(res.stdout, /hyphae/, `Expected agy plugin list to discover hyp plugin.\nstdout:\n${res.stdout}`);
    } finally {
      rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
    }
  },
);

test(
  "REAL Herdr Core connector: fails closed on bare shell terminal and verifies live agent HC_TERMINAL_ID via hc get",
  { skip: hcBin === null ? "hc (Herdr Core) not installed locally" : false, timeout: 30_000 },
  async () => {
    assert.ok(hcBin);
    const dir = mkdtempSync(join(tmpdir(), "am-herdr-"));
    const routerCore = new RouterCore({ dbPath: join(dir, "router.sqlite") });
    const token = routerCore.addConnector("bogdan@herdr");
    const router = await serveRouter({ core: routerCore, host: "127.0.0.1", port: 0 });
    const daemon = await startDaemon({
      connectorId: "bogdan@herdr",
      directory: join(dir, "state"),
      routers: [{ name: "primary", url: router.url, token }],
    }, { quiet: true });

    const callHerdrMcp = async (terminalId: string, calls: Array<{ name: string; arguments: Record<string, unknown> }>) => {
      const mcp = spawn(
        process.execPath,
        [join(process.cwd(), "src", "cli.ts"), "mcp", daemon.socketPath, "--backend", "herdr"],
        { env: { ...process.env, HC_TERMINAL_ID: terminalId }, stdio: ["pipe", "pipe", "pipe"] },
      );
      const sendRpc = (id: number, method: string, params: Record<string, unknown>) =>
        new Promise<Record<string, unknown>>((resolve, reject) => {
          const timer = setTimeout(() => reject(new Error(`Herdr MCP ${method} timed out`)), 5_000).unref();
          const onData = (chunk: Buffer) => {
            for (const line of chunk.toString("utf8").split("\n")) {
              if (!line.trim()) continue;
              const msg = JSON.parse(line) as Record<string, unknown>;
              if (msg.id === id) {
                clearTimeout(timer);
                mcp.stdout.off("data", onData);
                resolve(msg);
              }
            }
          };
          mcp.stdout.on("data", onData);
          mcp.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
        });
      try {
        await sendRpc(1, "initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "herdr-test", version: "1" } });
        const results: Array<Record<string, unknown>> = [];
        let id = 2;
        for (const call of calls) {
          results.push(await sendRpc(id++, "tools/call", call));
        }
        return results;
      } finally {
        mcp.stdin.end();
        mcp.kill("SIGTERM");
      }
    };

    let termId: string | undefined;
    try {
      // 1. Spawn a real disposable Herdr terminal running a bare shell (status: null)
      const started = execFileSync(hcBin, ["run", "--bg", "--json", "sh"], { encoding: "utf8" });
      const parsed = JSON.parse(started) as { address?: string };
      assert.ok(parsed.address && /^t[a-z0-9]+$/.test(parsed.address), `Unexpected hc run output: ${started}`);
      termId = parsed.address;

      const info = JSON.parse(execFileSync(hcBin, ["get", "--json", termId], { encoding: "utf8" })) as {
        address: string; state: string; pid: number; created_ms: number; status: { app?: string } | null;
      };
      assert.equal(info.address, termId);
      assert.equal(info.state, "live");
      assert.equal(info.status, null);

      // Must fail closed on a non-agent shell terminal (prevents injecting mesh text into a raw shell)
      const [denied] = await callHerdrMcp(termId, [{ name: "hyp_capabilities", arguments: {} }]);
      assert.equal((denied.result as { isError?: boolean }).isError, true);
      const deniedText = ((denied.result as { content: Array<{ text: string }> }).content[0]).text;
      assert.match(deniedText, /caller_unverifiable|Could not verify/i);

      // 2. If running inside a real live Herdr agent terminal (status.app present), verify live identity + enrollment
      // on this isolated test daemon/router (strictly read-only against hc get; never sends hc send to parent terminal).
      const liveAgentTerm = process.env.HC_TERMINAL_ID;
      if (liveAgentTerm && /^t[a-z0-9]+$/.test(liveAgentTerm)) {
        const liveInfo = JSON.parse(execFileSync(hcBin, ["get", "--json", liveAgentTerm], { encoding: "utf8" })) as {
          state?: string; status?: { app?: string } | null;
        };
        if (liveInfo.state === "live" && liveInfo.status?.app) {
          const [capRes, joinRes] = await callHerdrMcp(liveAgentTerm, [
            { name: "hyp_capabilities", arguments: {} },
            { name: "hyp_join", arguments: { handle: "hc-agent" } },
          ]);
          const caps = JSON.parse(((capRes.result as { content: Array<{ text: string }> }).content[0]).text) as {
            sessionId: string; backend: string; modes: string[];
          };
          assert.equal(caps.backend, "herdr");
          assert.deepEqual(caps.modes, ["queue", "interrupt"]);
          assert.ok(caps.sessionId.startsWith(`herdr:${liveAgentTerm}:`), `Unexpected sessionId: ${caps.sessionId}`);
          const joined = JSON.parse(((joinRes.result as { content: Array<{ text: string }> }).content[0]).text) as {
            address: string;
          };
          assert.equal(joined.address, "bogdan@herdr/hc-agent");
        }
      }
    } finally {
      if (termId) {
        try { execFileSync(hcBin, ["kill", termId], { stdio: "ignore" }); } catch {}
        try { execFileSync(hcBin, ["rm", termId], { stdio: "ignore" }); } catch {}
      }
      await daemon.stop();
      await router.close();
      routerCore.close();
      rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
    }
  },
);
