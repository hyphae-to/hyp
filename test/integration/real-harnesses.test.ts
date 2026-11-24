import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { test } from "node:test";
import { handleHookPayload } from "../../src/hooks.ts";
import { object } from "../../src/protocol.ts";
import {
  BINARIES,
  createRealCodexRunner,
  runRealAgy,
  runRealAgyPluginCheck,
  runRealClaude,
  runRealCursorSetupCheck,
  runRealOpenCode,
} from "./harness/drivers.ts";
import { MeshTopology, waitFor } from "./harness/topology.ts";

test(
  "REAL Claude binary + scripted Anthropic API: ToolSearch -> hyp_join -> #deploys -> notify mode Stop push -> hyp_inbox -> hyp_mute -> hyp_send",
  { skip: BINARIES.claude === null ? "claude CLI not installed locally" : false, timeout: 60_000 },
  async () => {
    const topo = new MeshTopology("hyphae-real-claude-int-");
    try {
      const router = await topo.addRouter({ name: "team" });
      const alex = await topo.addConnector({ connectorId: "alex@laptop", links: [{ name: "primary", router }] });
      const alice = await topo.addConnector({ connectorId: "alice@laptop", links: [{ name: "primary", router }] });

      // Peer on a separate connector across the Team Router
      alice.daemon.state.register("antigravity:alice-1", { kind: "antigravity" });
      await alice.daemon.connector.call("antigravity:alice-1", "hyp_join", { handle: "ops" });
      await alice.daemon.connector.call("antigravity:alice-1", "hyp_channel_join", { channel: "#deploys" });

      let stage = 0;
      let sawNotifyBanner = false;
      let sawFullPayloadInInbox = false;

      const { result, server } = await runRealClaude({
        baseDir: topo.subDir("claude"),
        socketPath: alex.socketPath,
        prompt: "Join hyphae as claude-dev, join #deploys, switch to notify mode, read inbox on notice, and reply to alice@laptop/ops.",
        handler: async (ctx) => {
          // Stage 0: Load deferred MCP tools via Claude's ToolSearch if needed
          if (!ctx.findTool("hyp_join") && ctx.findTool("ToolSearch") && stage === 0) {
            return ctx.selectClaudeTools([
              "hyp_join",
              "hyp_channel_join",
              "hyp_mode",
              "hyp_inbox",
              "hyp_mute",
              "hyp_send",
            ]);
          }

          if (stage === 0) {
            stage = 1;
            return ctx.callTool("hyp_join", { handle: "claude-dev" });
          }

          if (stage === 1) {
            assert.ok(ctx.hasText("alex@laptop/claude-dev"), `Expected hyp_join result in context: ${ctx.allText()}`);
            stage = 2;
            return ctx.callTool("hyp_channel_join", { channel: "#deploys" });
          }

          if (stage === 2) {
            stage = 3;
            return ctx.callTool("hyp_mode", { mode: "notify" });
          }

          if (stage === 3) {
            stage = 4;
            // Remote peer posts to #deploys AND sends a direct message while Claude finishes its turn!
            await alice.daemon.connector.call("antigravity:alice-1", "hyp_channel_post", {
              channel: "#deploys",
              text: "release-v4-canary-started",
            });
            await alice.daemon.connector.call("antigravity:alice-1", "hyp_send", {
              to: "alex@laptop/claude-dev",
              text: "SECRET_DIRECT_NOTE_FOR_CLAUDE",
            });
            await waitFor(
              () => {
                const s = alex.daemon.state.byHandle("claude-dev");
                return s && alex.daemon.state.pendingCount(s.id) >= 2;
              },
              { label: "2 messages queued in claude-dev mailbox" },
            );
            // End turn so Stop hook triggers and injects ONLY the slim unread-count digest!
            return ctx.reply("Standing by in notify mode.");
          }

          if (stage === 4 && ctx.hasText("hyphae notice")) {
            sawNotifyBanner = true;
            // Verify notify mode did NOT leak the full payload before hyp_inbox was called
            assert.equal(ctx.hasText("SECRET_DIRECT_NOTE_FOR_CLAUDE"), false, "Notify mode must not push full body before hyp_inbox");
            stage = 5;
            return ctx.callTool("hyp_inbox", { acknowledgeAll: true });
          }

          if (stage === 5 && ctx.hasText("SECRET_DIRECT_NOTE_FOR_CLAUDE")) {
            sawFullPayloadInInbox = true;
            stage = 6;
            return ctx.callTool("hyp_mute", { target: "noisy@prod/*" });
          }

          if (stage === 6) {
            stage = 7;
            return ctx.callTool("hyp_send", {
              to: "alice@laptop/ops",
              text: "claude-read-inbox-and-acked",
            });
          }

          return ctx.reply("Completed workflow.");
        },
      });

      assert.equal(
        result.code,
        0,
        `claude exited ${result.code}\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}\ntranscript:\n${JSON.stringify(server.transcript, null, 2)}`,
      );
      assert.equal(sawNotifyBanner, true, "Real Claude should receive slim notify digest via Stop hook");
      assert.equal(sawFullPayloadInInbox, true, "Real Claude should read full payload via hyp_inbox");

      const claudeSession = alex.daemon.state.byHandle("claude-dev");
      assert.ok(claudeSession);
      assert.match(claudeSession.id, /^claude:.+/);
      assert.ok(alex.daemon.connector.listMutes().some((m) => m.pattern === "noisy@prod/*"));

      const aliceItems = await waitFor(() => {
        const items = alice.daemon.connector.drainMailbox("antigravity:alice-1", 5);
        return items.length > 0 ? items : null;
      }, { label: "Alice receiving Claude's reply across Team Router" });
      assert.match(aliceItems[0].text, /hyphae from alex@laptop\/claude-dev/);
      assert.match(aliceItems[0].text, /claude-read-inbox-and-acked/);
    } finally {
      await topo.cleanup();
    }
  },
);

test(
  "REAL Codex binary + scripted OpenAI Responses API: rollout caller identity, native codex queue push, and 1:N multi-thread isolation",
  { skip: BINARIES.codex === null ? "codex CLI not installed locally" : false, timeout: 60_000 },
  async () => {
    const topo = new MeshTopology("hyphae-real-codex-int-");
    try {
      const router = await topo.addRouter({ name: "team" });
      const alex = await topo.addConnector({ connectorId: "alex@laptop", links: [{ name: "primary", router }] });
      const jack = await topo.addConnector({ connectorId: "jack@prod", links: [{ name: "primary", router }] });

      jack.daemon.state.register("antigravity:jack-1", { kind: "antigravity" });
      await jack.daemon.connector.call("antigravity:jack-1", "hyp_join", { handle: "prod-bot" });

      let desiredHandle = "codex-primary";
      let shouldSend = true;

      const codex = await createRealCodexRunner({
        baseDir: topo.subDir("codex"),
        socketPath: alex.socketPath,
        handler: async (ctx) => {
          if (ctx.turnIndex === 0) {
            return ctx.callTool("hyp_join", { handle: desiredHandle });
          }
          if (ctx.turnIndex === 1 && shouldSend) {
            return ctx.callTool("hyp_send", {
              to: "jack@prod/prod-bot",
              text: `hello-from-${desiredHandle}`,
            });
          }
          return ctx.reply(`Finished as ${desiredHandle}`);
        },
      });
      topo.track(() => codex.close());

      // Thread 1 joins as `codex-primary` and messages Jack across the Team Router
      const res1 = await codex.exec("Join as codex-primary and greet jack@prod/prod-bot.");
      assert.equal(res1.code, 0, `codex #1 exited ${res1.code}\nstderr:\n${res1.stderr}`);

      const session1 = alex.daemon.state.byHandle("codex-primary");
      assert.ok(session1, "Expected codex-primary enrolled via rollout JSONL verification");
      assert.match(session1.id, /^codex:[0-9a-f-]+$/i);
      const threadId1 = session1.id.slice("codex:".length);

      const jackGot = await waitFor(() => {
        const items = jack.daemon.connector.drainMailbox("antigravity:jack-1", 5);
        return items.length > 0 ? items : null;
      }, { label: "Jack receiving Codex message" });
      assert.match(jackGot[0].text, /hello-from-codex-primary/);

      // Jack replies -> daemon natively pushes into Codex's `queue_1.sqlite` for `threadId1`
      await jack.daemon.connector.call("antigravity:jack-1", "hyp_send", {
        to: "alex@laptop/codex-primary",
        text: "native-queue-push-to-codex",
      });
      await waitFor(
        () => {
          const dump = JSON.stringify(codex.readQueueRows());
          return dump.includes("native-queue-push-to-codex") && dump.includes(threadId1);
        },
        { timeoutMs: 8_000, intervalMs: 150, label: "native codex queue_1.sqlite delivery" },
      );

      // Thread 2 runs against the EXACT SAME CODEX_HOME & daemon:
      // trying to claim `codex-primary` is blocked by handle ownership, while claiming `codex-secondary` succeeds!
      desiredHandle = "codex-secondary";
      shouldSend = false;
      codex.server.resetTurns();
      const res2 = await codex.exec("Join as codex-secondary.");
      assert.equal(res2.code, 0, `codex #2 exited ${res2.code}\nstderr:\n${res2.stderr}`);

      const codexSessions = alex.daemon.connector.listSessions().filter((s) => s.id.startsWith("codex:"));
      assert.equal(codexSessions.length, 2);
      assert.notEqual(codexSessions[0].id, codexSessions[1].id);
      assert.deepEqual(
        codexSessions.map((s) => s.handle).sort(),
        ["codex-primary", "codex-secondary"],
      );
    } finally {
      await topo.cleanup();
    }
  },
);

test(
  "REAL OpenCode v2 binary + scripted OpenAI Responses API: v2 plugin _meshCall verification + execute.after push wakeup + hyp_send reply",
  { skip: BINARIES.opencode === null ? "opencode CLI not installed locally" : false, timeout: 60_000 },
  async () => {
    const topo = new MeshTopology("hyphae-real-opencode-int-");
    try {
      const router = await topo.addRouter({ name: "team" });
      const alice = await topo.addConnector({ connectorId: "alice@laptop", links: [{ name: "primary", router }] });
      const jack = await topo.addConnector({ connectorId: "jack@prod", links: [{ name: "primary", router }] });

      jack.daemon.state.register("antigravity:jack-1", { kind: "antigravity" });
      await jack.daemon.connector.call("antigravity:jack-1", "hyp_join", { handle: "jack-ops" });

      let sawPushedPeerMessage = false;

      const { result, server } = await runRealOpenCode({
        baseDir: topo.subDir("opencode"),
        socketPath: alice.socketPath,
        prompt: "Enroll in hyphae as oc-dev, check peers, and respond to any incoming message from jack@prod/jack-ops.",
        handler: async (ctx) => {
          if (ctx.turnIndex === 0) {
            return ctx.callOpenCodeTool("hyp_join", { handle: "oc-dev" });
          }
          if (ctx.turnIndex === 1) {
            assert.ok(ctx.hasText("alice@laptop/oc-dev"), `Expected oc-dev address in turn 1: ${ctx.allText()}`);
            // Remote peer sends a message BEFORE OpenCode runs its next tool call ->
            // OpenCode's v2 `execute.after` plugin hook drains & injects it into the model's context automatically!
            await jack.daemon.connector.call("antigravity:jack-1", "hyp_send", {
              to: "alice@laptop/oc-dev",
              text: "incident-handoff-to-real-opencode",
            });
            await waitFor(
              () => {
                const s = alice.daemon.state.byHandle("oc-dev");
                return s && alice.daemon.state.pendingCount(s.id) >= 1;
              },
              { label: "message queued for oc-dev" },
            );
            return ctx.callOpenCodeTool("hyp_peers", {});
          }
          if (ctx.turnIndex === 2) {
            if (ctx.hasText("incident-handoff-to-real-opencode")) {
              sawPushedPeerMessage = true;
            }
            return ctx.callOpenCodeTool("hyp_send", {
              to: "jack@prod/jack-ops",
              text: "ack-from-real-opencode-v2",
            });
          }
          return ctx.reply("Handled message from jack.");
        },
      });

      assert.equal(
        result.code,
        0,
        `opencode exited ${result.code}\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}\ntranscript:\n${JSON.stringify(server.transcript, null, 2)}`,
      );
      assert.equal(sawPushedPeerMessage, true, "Real OpenCode v2 should receive pushed peer message via execute.after without polling");

      const ocSession = alice.daemon.state.byHandle("oc-dev");
      assert.ok(ocSession);
      assert.match(ocSession.id, /^opencode:ses_.+/);

      const jackReply = await waitFor(() => {
        const items = jack.daemon.connector.drainMailbox("antigravity:jack-1", 5);
        return items.length > 0 ? items : null;
      }, { label: "Jack receiving OpenCode's reply" });
      assert.match(jackReply[0].text, /hyphae from alice@laptop\/oc-dev/);
      assert.match(jackReply[0].text, /ack-from-real-opencode-v2/);
    } finally {
      await topo.cleanup();
    }
  },
);

test(
  "LIVE cross-harness real-binary conversation: real Claude (alex@laptop) <-> real OpenCode (alice@laptop) over Team Router",
  {
    skip:
      BINARIES.claude === null || BINARIES.opencode === null
        ? "requires both claude and opencode CLIs installed locally"
        : false,
    timeout: 75_000,
  },
  async () => {
    const topo = new MeshTopology("hyphae-claude-x-opencode-");
    try {
      const teamRouter = await topo.addRouter({ name: "team" });
      const alex = await topo.addConnector({ connectorId: "alex@laptop", links: [{ name: "primary", router: teamRouter }] });
      const alice = await topo.addConnector({ connectorId: "alice@laptop", links: [{ name: "primary", router: teamRouter }] });

      let claudeReceivedReply = false;
      let opencodeReceivedPing = false;

      // Launch BOTH real binaries concurrently and coordinate their live turn-by-turn mesh exchange!
      const claudePromise = runRealClaude({
        baseDir: topo.subDir("claude-live"),
        socketPath: alex.socketPath,
        prompt: "Join as claude-lead, ping alice@laptop/oc-worker, and confirm receipt of reply.",
        handler: async (ctx) => {
          if (!ctx.findTool("hyp_join") && ctx.findTool("ToolSearch")) {
            return ctx.selectClaudeTools(["hyp_join", "hyp_send"]);
          }
          if (!alex.daemon.state.byHandle("claude-lead")) {
            return ctx.callTool("hyp_join", { handle: "claude-lead" });
          }
          if (!ctx.hasText("pong-from-real-opencode") && !ctx.hasText("messageId")) {
            // Wait until real OpenCode has enrolled on alice@laptop before sending!
            await waitFor(() => Boolean(alice.daemon.state.byHandle("oc-worker")), {
              timeoutMs: 20_000,
              label: "real OpenCode enrolling as oc-worker",
            });
            return ctx.callTool("hyp_send", {
              to: "alice@laptop/oc-worker",
              text: "ping-from-real-claude",
            });
          }
          if (ctx.hasText("pong-from-real-opencode")) {
            claudeReceivedReply = true;
            return ctx.reply("Received live reply from OpenCode.");
          }
          // Wait until OpenCode's reply arrives in Claude's mailbox, then end turn so Stop hook injects it!
          await waitFor(() => {
            const s = alex.daemon.state.byHandle("claude-lead");
            return s && alex.daemon.state.pendingCount(s.id) >= 1;
          }, { timeoutMs: 20_000, label: "OpenCode reply landing in Claude mailbox" });
          return ctx.reply("Waiting for OpenCode reply.");
        },
      });

      const opencodePromise = runRealOpenCode({
        baseDir: topo.subDir("opencode-live"),
        socketPath: alice.socketPath,
        prompt: "Join as oc-worker, receive ping from alex@laptop/claude-lead, and reply.",
        handler: async (ctx) => {
          if (ctx.turnIndex === 0) {
            return ctx.callOpenCodeTool("hyp_join", { handle: "oc-worker" });
          }
          if (ctx.turnIndex === 1) {
            // Wait for real Claude's ping to arrive in OpenCode's mailbox before running hyp_peers -> execute.after injects it!
            await waitFor(() => {
              const s = alice.daemon.state.byHandle("oc-worker");
              return s && alice.daemon.state.pendingCount(s.id) >= 1;
            }, { timeoutMs: 20_000, label: "Claude ping landing in OpenCode mailbox" });
            return ctx.callOpenCodeTool("hyp_peers", {});
          }
          if (ctx.turnIndex === 2) {
            if (ctx.hasText("ping-from-real-claude")) opencodeReceivedPing = true;
            return ctx.callOpenCodeTool("hyp_send", {
              to: "alex@laptop/claude-lead",
              text: "pong-from-real-opencode",
            });
          }
          return ctx.reply("Replied to Claude.");
        },
      });

      const [claudeRun, opencodeRun] = await Promise.all([claudePromise, opencodePromise]);
      assert.equal(claudeRun.result.code, 0, `claude failed: ${claudeRun.result.stderr}`);
      assert.equal(opencodeRun.result.code, 0, `opencode failed: ${opencodeRun.result.stderr}`);
      assert.equal(opencodeReceivedPing, true, "Real OpenCode should receive real Claude's message");
      assert.equal(claudeReceivedReply, true, "Real Claude should receive real OpenCode's reply");
    } finally {
      await topo.cleanup();
    }
  },
);

test(
  "REAL Antigravity (agy) binary + scripted Gemini API: lazy call_mcp_tool + PreToolUse _meshCall overwrite + Stop hook push + hyp_send reply",
  { skip: BINARIES.agy === null ? "agy CLI not installed locally" : false, timeout: 60_000 },
  async () => {
    const topo = new MeshTopology("hi-agy-");
    try {
      const router = await topo.addRouter({ name: "team" });
      const alex = await topo.addConnector({ connectorId: "alex@laptop", links: [{ name: "primary", router }] });
      const jack = await topo.addConnector({ connectorId: "jack@prod", links: [{ name: "primary", router }] });

      jack.daemon.state.register("claude:jack-1", { kind: "claude" });
      await jack.daemon.connector.call("claude:jack-1", "hyp_join", { handle: "prod-ops" });
      await jack.daemon.connector.call("claude:jack-1", "hyp_channel_join", { channel: "#deploys" });

      let stage = 0;
      let sawPushedStopMessage = false;

      const { result, server } = await runRealAgy({
        baseDir: topo.subDir("agy"),
        socketPath: alex.socketPath,
        prompt: "Join hyphae as agy-real, join #deploys, and respond to any incoming message from jack@prod/prod-ops.",
        handler: async (ctx) => {
          if (stage === 0) {
            stage = 1;
            return ctx.callAgyMcpTool("hyp_join", { handle: "agy-real" });
          }
          if (stage === 1) {
            assert.ok(ctx.hasText("alex@laptop/agy-real"), `Expected hyp_join result in agy context: ${ctx.allText()}`);
            stage = 2;
            return ctx.callAgyMcpTool("hyp_channel_join", { channel: "#deploys" });
          }
          if (stage === 2) {
            stage = 3;
            // Remote peer posts to #deploys -> Antigravity Stop hook drains & continues turn with zero polling!
            await jack.daemon.connector.call("claude:jack-1", "hyp_channel_post", {
              channel: "#deploys",
              text: "push-deploy-ping-to-real-agy",
            });
            await waitFor(
              () => {
                const s = alex.daemon.state.byHandle("agy-real");
                return s && alex.daemon.state.pendingCount(s.id) >= 1;
              },
              { label: "#deploys post queued for agy-real" },
            );
            return ctx.reply("Joined #deploys.");
          }
          if (stage === 3 && ctx.hasText("push-deploy-ping-to-real-agy")) {
            sawPushedStopMessage = true;
            stage = 4;
            return ctx.callAgyMcpTool("hyp_send", {
              to: "jack@prod/prod-ops",
              text: "ack-from-real-agy-via-stop-hook",
            });
          }
          return ctx.reply("All done.");
        },
      });

      assert.equal(
        result.code,
        0,
        `agy exited ${result.code}\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}\ntranscript:\n${JSON.stringify(server.transcript, null, 2)}`,
      );
      assert.equal(sawPushedStopMessage, true, "Real agy should receive pushed #deploys message via Stop hook without polling");

      const agySession = alex.daemon.state.byHandle("agy-real");
      assert.ok(agySession);
      assert.match(agySession.id, /^antigravity:[0-9a-f-]+$/i);

      const jackReply = await waitFor(() => {
        const items = jack.daemon.connector.drainMailbox("claude:jack-1", 5);
        return items.length > 0 ? items : null;
      }, { label: "Jack receiving real agy reply across Team Router" });
      assert.match(jackReply[0].text, /hyphae from alex@laptop\/agy-real/);
      assert.match(jackReply[0].text, /ack-from-real-agy-via-stop-hook/);
    } finally {
      await topo.cleanup();
    }
  },
);

test(
  "REAL agy + cursor-agent + hc verification (setup discovery, hook/MCP protocols, and Herdr fail-closed isolation)",
  { timeout: 30_000 },
  async () => {
    const topo = new MeshTopology("hyphae-other-harnesses-");
    try {
      const router = await topo.addRouter({ name: "team" });
      const conn = await topo.addConnector({ connectorId: "dev@laptop", links: [{ name: "primary", router }] });

      // 1. Real `agy` CLI plugin discovery (if installed)
      if (BINARIES.agy) {
        const agyRes = await runRealAgyPluginCheck(topo.subDir("agy"), conn.socketPath);
        assert.equal(agyRes.code, 0, `agy plugin list failed: ${agyRes.stderr}`);
        assert.match(agyRes.stdout, /hyphae/);
      }

      // 2. Real `cursor-agent` binary + `setupCursor` + full Cursor hook/MCP protocol
      const cursorCheck = await runRealCursorSetupCheck(topo.subDir("cursor"), conn.socketPath);
      assert.ok(cursorCheck.files.every((f) => existsSync(f)));
      if (cursorCheck.versionResult) {
        assert.equal(cursorCheck.versionResult.code, 0);
      }

      // Exercise Cursor's exact hook contract (`beforeMCPExecution`, `afterMCPExecution`, `stop` -> `followup_message`)
      const mcp = await conn.openMcp();
      const preCursor = await handleHookPayload(
        { conversation_id: "cur-conv-9", tool_name: "hyp_join", tool_use_id: "cur_call_1" },
        { harness: "cursor", event: "pre-tool-use", socketPath: conn.socketPath },
      );
      assert.deepEqual(preCursor, { permission: "allow" });
      const curJoin = await mcp.callTool("hyp_join", { handle: "cursor-dev" }, { toolUseId: "cur_call_1" });
      assert.equal(curJoin.isError, false);
      assert.deepEqual(curJoin.json(), { address: "dev@laptop/cursor-dev" });

      // Antigravity `call_mcp_tool` wrapper PreToolUse overwrite + PreInvocation injectSteps
      const preAg = await handleHookPayload(
        {
          conversationId: "ag-conv-9",
          toolCall: { id: "ag_call_1", name: "call_mcp_tool", args: { ServerName: "hyphae", ToolName: "hyp_join", Arguments: { handle: "agy-dev" } } },
        },
        { harness: "antigravity", event: "pre-tool-use", socketPath: conn.socketPath },
      );
      assert.equal(preAg.decision, "allow");
      const overwriteArgs = object(preAg.overwrite) && object(preAg.overwrite.Arguments) ? preAg.overwrite.Arguments : {};
      const agJoin = await mcp.callTool("hyp_join", overwriteArgs);
      assert.equal(agJoin.isError, false);
      assert.deepEqual(agJoin.json(), { address: "dev@laptop/agy-dev" });

      // Antigravity sends a message to Cursor -> Cursor `stop` hook returns `followup_message`!
      const preAgSend = await handleHookPayload(
        { conversationId: "ag-conv-9", toolCall: { id: "ag_call_2", name: "hyp_send", args: {} } },
        { harness: "antigravity", event: "pre-tool-use", socketPath: conn.socketPath },
      );
      const sendRes = await mcp.callTool("hyp_send", {
        to: "dev@laptop/cursor-dev",
        text: "hello-cursor-followup",
        ...(object(preAgSend.overwrite) ? preAgSend.overwrite : {}),
      });
      assert.equal(sendRes.isError, false);

      await waitFor(() => conn.daemon.state.pendingCount("cursor:cur-conv-9") >= 1, { label: "Cursor mailbox item" });
      const curStop = await handleHookPayload(
        { conversation_id: "cur-conv-9", loop_count: 0 },
        { harness: "cursor", event: "stop", socketPath: conn.socketPath },
      );
      assert.match(String(curStop.followup_message), /hello-cursor-followup/);

      // 3. Real `hc` (Herdr Core) fail-closed check on an ephemeral bare shell terminal
      if (BINARIES.hc) {
        let termId: string | undefined;
        try {
          const started = execFileSync(BINARIES.hc, ["run", "--bg", "--json", "sh"], { encoding: "utf8" });
          const parsed = JSON.parse(started) as { address?: string };
          assert.ok(parsed.address && /^t[a-z0-9]+$/.test(parsed.address));
          termId = parsed.address;

          const herdrMcp = await conn.openMcp(["--backend", "herdr"], { ...process.env, HC_TERMINAL_ID: termId });
          const denied = await herdrMcp.callTool("hyp_capabilities", {});
          assert.equal(denied.isError, true);
          assert.match(denied.text, /caller_unverifiable|Could not verify/i);
        } finally {
          if (termId) {
            try { execFileSync(BINARIES.hc, ["kill", termId], { stdio: "ignore" }); } catch {}
            try { execFileSync(BINARIES.hc, ["rm", termId], { stdio: "ignore" }); } catch {}
          }
        }
      }
    } finally {
      await topo.cleanup();
    }
  },
);
