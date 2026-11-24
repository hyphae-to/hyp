import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { join } from "node:path";
import { test } from "node:test";
import { loadConfig } from "../../src/config.ts";
import { startDaemon } from "../../src/daemon.ts";
import { handleHookPayload } from "../../src/hooks.ts";
import { object } from "../../src/protocol.ts";
import { BINARIES, runRealAgy } from "./harness/drivers.ts";
import { freePort, McpClient, MeshTopology, waitFor } from "./harness/topology.ts";
import { deliverSignedWebhook } from "./shims/services.ts";

const CLI_SCRIPT = join(process.cwd(), "src", "cli.ts");

function runCli(
  args: readonly string[],
  timeoutMs = 15_000,
): Promise<{ readonly code: number | null; readonly stdout: string; readonly stderr: string }> {
  return new Promise((resolve) => {
    const proc = spawn(process.execPath, [CLI_SCRIPT, ...args], {
      stdio: ["ignore", "pipe", "pipe"],
    });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    proc.stdout.on("data", (d: Buffer) => out.push(d));
    proc.stderr.on("data", (d: Buffer) => err.push(d));
    const timer = setTimeout(() => { proc.kill("SIGKILL"); }, timeoutMs).unref();
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

async function publishTopicEvent(
  routerUrl: string,
  token: string,
  topic: string,
  event: Record<string, unknown>,
): Promise<void> {
  const res = await fetch(`${routerUrl}/v1/events?topic=${encodeURIComponent(topic)}`, {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    body: JSON.stringify(event),
  });
  assert.equal(res.status, 202, `Expected 202 publishing event to topic '${topic}', got ${res.status}`);
}

type HookHarness = "antigravity" | "claude" | "codex" | "cursor" | "opencode" | "gemini";

async function callMcpAs(
  mcp: McpClient,
  socketPath: string,
  harness: HookHarness,
  rawId: string,
  tool: string,
  args: Record<string, unknown>,
  seq: string,
): Promise<{ text: string; isError: boolean; json(): unknown }> {
  const callId = `${harness}_${rawId}_${seq}`;
  let callArgs: Record<string, unknown> = { ...args };
  let meta: Record<string, unknown> | undefined;

  if (harness === "antigravity") {
    const pre = await handleHookPayload(
      { conversationId: rawId, toolCall: { id: callId, name: tool, args } },
      { harness: "antigravity", event: "pre-tool-use", socketPath },
    );
    if (object(pre.overwrite)) callArgs = { ...callArgs, ...pre.overwrite };
  } else if (harness === "claude") {
    await handleHookPayload(
      { session_id: rawId, tool_use_id: callId, tool_name: `mcp__hyphae__${tool}` },
      { harness: "claude", event: "pre-tool-use", socketPath },
    );
    meta = { "claudecode/toolUseId": callId };
  } else if (harness === "codex") {
    await handleHookPayload(
      { session_id: rawId, tool_use_id: callId, tool_name: `hyphae.${tool}` },
      { harness: "codex", event: "pre-tool-use", socketPath },
    );
    meta = { callId };
  } else if (harness === "cursor") {
    await handleHookPayload(
      { conversation_id: rawId, tool_use_id: callId, tool_name: `hyphae_${tool}` },
      { harness: "cursor", event: "pre-tool-use", socketPath },
    );
    meta = { toolUseId: callId };
  } else if (harness === "opencode") {
    const pre = await handleHookPayload(
      { session_id: rawId, call_id: callId, tool_name: `hyphae_${tool}` },
      { harness: "opencode", event: "pre-tool-use", socketPath },
    );
    if (typeof pre.callToken === "string") callArgs._meshCall = pre.callToken;
  } else if (harness === "gemini") {
    const pre = await handleHookPayload(
      { session_id: rawId, tool_name: `mcp_hyphae_${tool}`, tool_input: args },
      { harness: "gemini", event: "pre-tool-use", socketPath },
    );
    const out = object(pre.hookSpecificOutput) && object(pre.hookSpecificOutput.tool_input)
      ? pre.hookSpecificOutput.tool_input
      : {};
    callArgs = { ...callArgs, ...out };
  }

  return mcp.callTool(tool, callArgs, meta);
}

test(
  "complete muting matrix: CLI + MCP actuation, all 5 target classes, normalization, invalid inputs, daemon restart persistence, and prune session-mute cleanup",
  { timeout: 35_000 },
  async () => {
    const topo = new MeshTopology("hi-m1-");
    try {
      const hookPort = await freePort();
      const hookSecret = "local-hook-hmac-secret-91";

      const router = await topo.addRouter({
        name: "team",
        topics: new Map([["builds", ["ci-bot"]]]),
      });
      const ciToken = router.core.events.addPublisher("ci-bot", ["builds"]);

      // Receiver connector with built-in `webhook` plugin named `local-hook` targeting `main`
      const receiver = await topo.addConnector({
        connectorId: "alex@laptop",
        links: [{ name: "primary", router }],
        secrets: { "hook-secret": hookSecret },
        rawPlugins: [
          {
            name: "local-hook",
            builtin: "webhook",
            env: {
              WEBHOOK_HOST: "127.0.0.1",
              WEBHOOK_PORT: String(hookPort),
              WEBHOOK_PATH: "/hook",
              WEBHOOK_TARGET: "ops",
              WEBHOOK_SOURCE: "local-hook/ci",
              WEBHOOK_SECRET: { secret: "hook-secret" },
            },
            targets: [
              { name: "ops", handle: "main", coalesceSeconds: 0, maxWaitSeconds: 5, wakesPerHour: 120 },
            ],
          },
        ],
      });

      const alice = await topo.addConnector({
        connectorId: "alice@laptop",
        links: [{ name: "primary", router }],
      });
      const jack = await topo.addConnector({
        connectorId: "jack@prod",
        links: [{ name: "primary", router }],
      });

      // Enroll remote senders on alice@laptop and jack@prod
      alice.daemon.state.register("claude:noisy", { kind: "claude" });
      alice.daemon.state.register("antigravity:quiet", { kind: "antigravity" });
      await alice.daemon.connector.call("claude:noisy", "hyp_join", { handle: "noisy" });
      await alice.daemon.connector.call("antigravity:quiet", "hyp_join", { handle: "quiet" });
      await alice.daemon.connector.call("antigravity:quiet", "hyp_channel_join", { channel: "#noisy-room" });

      jack.daemon.state.register("codex:bot1", { kind: "codex" });
      jack.daemon.state.register("codex:bot2", { kind: "codex" });
      await jack.daemon.connector.call("codex:bot1", "hyp_join", { handle: "bot1" });
      await jack.daemon.connector.call("codex:bot2", "hyp_join", { handle: "bot2" });

      // Enroll 3 local sessions on alex@laptop via real hook-verified MCP:
      // - claude:main (receives local-hook plugin + #noisy-room + topic:builds)
      // - antigravity:side (separate session on same connector to verify connector vs session scope)
      // - codex:stale-worker (will add a session mute, survive daemon restart, then get pruned by CLI)
      const mcp1 = await receiver.openMcp();
      const joinMain = await callMcpAs(mcp1, receiver.socketPath, "claude", "main", "hyp_join", { handle: "main" }, "j1");
      assert.equal(joinMain.isError, false, joinMain.text);
      const joinSide = await callMcpAs(mcp1, receiver.socketPath, "antigravity", "side", "hyp_join", { handle: "side" }, "j2");
      assert.equal(joinSide.isError, false, joinSide.text);
      const joinStale = await callMcpAs(mcp1, receiver.socketPath, "codex", "stale-worker", "hyp_join", { handle: "stale" }, "j3");
      assert.equal(joinStale.isError, false, joinStale.text);

      for (const [h, rawId] of [
        ["claude", "main"],
        ["antigravity", "side"],
      ] as const) {
        const ch = await callMcpAs(mcp1, receiver.socketPath, h, rawId, "hyp_channel_join", { channel: "#noisy-room" }, "ch1");
        assert.equal(ch.isError, false, ch.text);
        const sub = await callMcpAs(
          mcp1,
          receiver.socketPath,
          h,
          rawId,
          "hyp_subscribe",
          {
            key: "ci:builds",
            topic: "builds",
            filters: [{ exact: { type: "com.ci.build" } }],
            coalesceSeconds: 0,
          },
          "sub1",
        );
        assert.equal(sub.isError, false, sub.text);
      }

      // ---- 1. Invalid mute patterns rejected cleanly via BOTH MCP and CLI ----
      const invalidPatterns = ["", "bad pattern", "foo/bar/baz", "topic:"];
      for (let i = 0; i < invalidPatterns.length; i++) {
        const bad = invalidPatterns[i];
        const mcpErr = await callMcpAs(mcp1, receiver.socketPath, "claude", "main", "hyp_mute", { target: bad }, `bad_${i}`);
        assert.equal(mcpErr.isError, true, `MCP hyp_mute should reject invalid pattern ${JSON.stringify(bad)}`);
        assert.match(mcpErr.text, /invalid/i);

        const cliErr = await runCli(["mute", bad, "--socket", receiver.socketPath]);
        assert.notEqual(cliErr.code, 0, `CLI hyp mute should reject invalid pattern ${JSON.stringify(bad)} (stdout: ${cliErr.stdout})`);
      }

      // ---- 2. Actuate all 5 mute target classes via CLI + MCP with uppercase normalization ----
      // Class 1 (exact peer via CLI, uppercase -> lowercase)
      const cliMutePeer = await runCli(["mute", "ALICE@LAPTOP/NOISY", "--socket", receiver.socketPath]);
      assert.equal(cliMutePeer.code, 0, `CLI mute peer failed: ${cliMutePeer.stderr}`);
      const peerRule = JSON.parse(cliMutePeer.stdout) as { rule: { pattern: string; scope: string; mutedBy: string } };
      assert.equal(peerRule.rule.pattern, "alice@laptop/noisy");
      assert.equal(peerRule.rule.scope, "*");
      assert.equal(peerRule.rule.mutedBy, "cli");

      // Class 2 (connector wildcard via CLI, uppercase -> lowercase)
      const cliMuteWild = await runCli(["mute", "JACK@PROD/*", "--socket", receiver.socketPath]);
      assert.equal(cliMuteWild.code, 0, `CLI mute wildcard failed: ${cliMuteWild.stderr}`);
      assert.equal((JSON.parse(cliMuteWild.stdout) as { rule: { pattern: string } }).rule.pattern, "jack@prod/*");

      // Class 3 (#channel via CLI, uppercase -> lowercase)
      const cliMuteChan = await runCli(["mute", "#NOISY-ROOM", "--socket", receiver.socketPath]);
      assert.equal(cliMuteChan.code, 0, `CLI mute #channel failed: ${cliMuteChan.stderr}`);
      assert.equal((JSON.parse(cliMuteChan.stdout) as { rule: { pattern: string } }).rule.pattern, "#noisy-room");

      // Class 4 (topic:<name> via MCP, scope: "connector", uppercase -> lowercase)
      const mcpMuteTopic = await callMcpAs(
        mcp1,
        receiver.socketPath,
        "claude",
        "main",
        "hyp_mute",
        { target: "TOPIC:BUILDS", scope: "connector" },
        "m_topic",
      );
      assert.equal(mcpMuteTopic.isError, false, mcpMuteTopic.text);
      assert.deepEqual(mcpMuteTopic.json(), { muted: "topic:builds", scope: "connector" });

      // Class 5 (plugin:<name> via MCP, scope: "session" on claude:main, uppercase -> lowercase)
      const mcpMutePlugin = await callMcpAs(
        mcp1,
        receiver.socketPath,
        "claude",
        "main",
        "hyp_mute",
        { target: "PLUGIN:LOCAL-HOOK", scope: "session" },
        "m_plugin",
      );
      assert.equal(mcpMutePlugin.isError, false, mcpMutePlugin.text);
      assert.deepEqual(mcpMutePlugin.json(), { muted: "plugin:local-hook", scope: "session" });

      // Session-scoped mute on codex:stale-worker (to verify restart persistence AND prune cleanup!)
      const mcpMuteStale = await callMcpAs(
        mcp1,
        receiver.socketPath,
        "codex",
        "stale-worker",
        "hyp_mute",
        { target: "ALICE@LAPTOP/QUIET", scope: "session" },
        "m_stale",
      );
      assert.equal(mcpMuteStale.isError, false, mcpMuteStale.text);
      assert.deepEqual(mcpMuteStale.json(), { muted: "alice@laptop/quiet", scope: "session" });

      // Verify CLI `hyp mutes` lists ONLY the 4 connector-level mutes
      const cliMutes = await runCli(["mutes", "--socket", receiver.socketPath]);
      assert.equal(cliMutes.code, 0, cliMutes.stderr);
      assert.match(cliMutes.stdout, /alice@laptop\/noisy/);
      assert.match(cliMutes.stdout, /jack@prod\/\*/);
      assert.match(cliMutes.stdout, /#noisy-room/);
      assert.match(cliMutes.stdout, /topic:builds/);
      assert.doesNotMatch(cliMutes.stdout, /plugin:local-hook/);
      assert.doesNotMatch(cliMutes.stdout, /alice@laptop\/quiet/);

      // Verify MCP `hyp_mutes` and `hyp_capabilities` live `mutes` count for every session
      const mainMutes = (await callMcpAs(mcp1, receiver.socketPath, "claude", "main", "hyp_mutes", {}, "lm1")).json() as {
        mutes: Array<{ pattern: string; scope: string }>;
      };
      const sideMutes = (await callMcpAs(mcp1, receiver.socketPath, "antigravity", "side", "hyp_mutes", {}, "lm2")).json() as {
        mutes: Array<{ pattern: string; scope: string }>;
      };
      const staleMutes = (await callMcpAs(mcp1, receiver.socketPath, "codex", "stale-worker", "hyp_mutes", {}, "lm3")).json() as {
        mutes: Array<{ pattern: string; scope: string }>;
      };
      assert.equal(mainMutes.mutes.length, 5);
      assert.equal(sideMutes.mutes.length, 4);
      assert.equal(staleMutes.mutes.length, 5);
      assert.ok(mainMutes.mutes.some((m) => m.pattern === "plugin:local-hook" && m.scope === "session"));
      assert.ok(!sideMutes.mutes.some((m) => m.pattern === "plugin:local-hook"));
      assert.ok(staleMutes.mutes.some((m) => m.pattern === "alice@laptop/quiet" && m.scope === "session"));

      const capsMain = (await callMcpAs(mcp1, receiver.socketPath, "claude", "main", "hyp_capabilities", {}, "c1")).json() as { mutes: number };
      const capsSide = (await callMcpAs(mcp1, receiver.socketPath, "antigravity", "side", "hyp_capabilities", {}, "c2")).json() as { mutes: number };
      const capsStale = (await callMcpAs(mcp1, receiver.socketPath, "codex", "stale-worker", "hyp_capabilities", {}, "c3")).json() as { mutes: number };
      assert.equal(capsMain.mutes, 5);
      assert.equal(capsSide.mutes, 4);
      assert.equal(capsStale.mutes, 5);

      // ---- 3. Fire traffic from ALL 5 muted classes + unmuted sentinel BEFORE restart ----
      const fireAllTraffic = async (
        daemonState: typeof receiver.daemon.state,
        daemonConnector: typeof receiver.daemon.connector,
        tag: string,
        checkStaleSession: boolean,
      ) => {
        // 1. Exact peer muted: alice@laptop/noisy -> main
        const mNoisy = (await alice.daemon.connector.call("claude:noisy", "hyp_send", {
          to: "alex@laptop/main",
          text: `MUTED_EXACT_PEER_${tag}`,
        })) as { messageId: string };
        // 2. Connector wildcard muted: jack@prod/bot1 -> main, jack@prod/bot2 -> side
        const mWild1 = (await jack.daemon.connector.call("codex:bot1", "hyp_send", {
          to: "alex@laptop/main",
          text: `MUTED_WILDCARD_1_${tag}`,
        })) as { messageId: string };
        const mWild2 = (await jack.daemon.connector.call("codex:bot2", "hyp_send", {
          to: "alex@laptop/side",
          text: `MUTED_WILDCARD_2_${tag}`,
        })) as { messageId: string };
        // 3. #channel muted even though sender (alice@laptop/quiet) is UNMUTED!
        await alice.daemon.connector.call("antigravity:quiet", "hyp_channel_post", {
          channel: "#noisy-room",
          text: `MUTED_CHANNEL_FROM_UNMUTED_PEER_${tag}`,
        });
        // 4. topic:builds muted
        await publishTopicEvent(router.url, ciToken, "builds", {
          specversion: "1.0",
          id: `build-muted-${tag}`,
          source: "ci/team",
          type: "com.ci.build",
          datacontenttype: "application/json",
          data: { build: `MUTED_TOPIC_${tag}` },
        });
        // 5. plugin:local-hook muted (session-scoped on claude:main)
        const hookRes = await deliverSignedWebhook({
          url: `http://127.0.0.1:${hookPort}/hook`,
          secret: hookSecret,
          deliveryId: `hook-muted-${tag}`,
          payload: {
            type: "com.local.hook",
            data: { note: `MUTED_PLUGIN_${tag}` },
          },
        });
        assert.equal(hookRes.status, 202);

        // Session-muted direct peer on stale-worker (if still present)
        let mStaleMutedId: string | undefined;
        if (checkStaleSession) {
          const mStale = (await alice.daemon.connector.call("antigravity:quiet", "hyp_send", {
            to: "alex@laptop/stale",
            text: `MUTED_SESSION_STALE_${tag}`,
          })) as { messageId: string };
          mStaleMutedId = mStale.messageId;
        }

        // Unmuted direct sentinel from alice@laptop/quiet -> main and side
        await alice.daemon.connector.call("antigravity:quiet", "hyp_send", {
          to: "alex@laptop/main",
          text: `ALLOWED_SENTINEL_MAIN_${tag}`,
        });
        await alice.daemon.connector.call("antigravity:quiet", "hyp_send", {
          to: "alex@laptop/side",
          text: `ALLOWED_SENTINEL_SIDE_${tag}`,
        });

        // Wait until muted receipts are recorded AND both unmuted sentinels land
        await waitFor(
          () =>
            daemonState.receipt("primary", mNoisy.messageId) === "muted" &&
            daemonState.receipt("primary", mWild1.messageId) === "muted" &&
            daemonState.receipt("primary", mWild2.messageId) === "muted" &&
            (!mStaleMutedId || daemonState.receipt("primary", mStaleMutedId) === "muted") &&
            daemonState.pendingCount("claude:main") >= 1 &&
            daemonState.pendingCount("antigravity:side") >= 1,
          { timeoutMs: 8_000, label: `muted receipts + sentinels (${tag})` },
        );
        // Allow any in-flight event/plugin/channel deliveries to settle cleanly
        await new Promise((r) => setTimeout(r, 300));

        const mainItems = daemonConnector.drainMailbox("claude:main", 20);
        const sideItems = daemonConnector.drainMailbox("antigravity:side", 20);
        assert.equal(mainItems.length, 1, `Expected ONLY sentinel for main (${tag}), got: ${JSON.stringify(mainItems)}`);
        assert.match(mainItems[0].text, new RegExp(`ALLOWED_SENTINEL_MAIN_${tag}`));
        assert.equal(sideItems.length, 1, `Expected ONLY sentinel for side (${tag}), got: ${JSON.stringify(sideItems)}`);
        assert.match(sideItems[0].text, new RegExp(`ALLOWED_SENTINEL_SIDE_${tag}`));
        if (checkStaleSession) {
          assert.equal(daemonState.pendingCount("codex:stale-worker"), 0);
        }
      };

      await fireAllTraffic(receiver.daemon.state, receiver.daemon.connector, "before_restart", true);

      // ---- 4. Persistence across daemon restart on the exact same stateDir ----
      await mcp1.close();
      await receiver.stop();

      const restarted = await startDaemon(loadConfig(receiver.configPath), { quiet: true });
      topo.track(() => restarted.stop());

      // Wait until restarted daemon reconnects to router and re-syncs handles & subscriptions
      await waitFor(async () => {
        try {
          const peers = (await alice.daemon.connector.call("antigravity:quiet", "hyp_peers", {})) as {
            peers: Array<{ address: string; online: boolean }>;
          };
          return peers.peers.some((p) => p.address === "alex@laptop/main" && p.online);
        } catch {
          return false;
        }
      }, { timeoutMs: 10_000, intervalMs: 100, label: "restarted daemon reconnecting to router" });

      const mcp2 = new McpClient(restarted.socketPath);
      topo.track(() => mcp2.close());
      await mcp2.initialize();

      // Confirm BOTH connector-level AND session-level mutes survived restart in state.sqlite
      const cliMutesAfter = await runCli(["mutes", "--socket", restarted.socketPath]);
      assert.equal(cliMutesAfter.code, 0, cliMutesAfter.stderr);
      assert.match(cliMutesAfter.stdout, /alice@laptop\/noisy/);
      assert.match(cliMutesAfter.stdout, /jack@prod\/\*/);
      assert.match(cliMutesAfter.stdout, /#noisy-room/);
      assert.match(cliMutesAfter.stdout, /topic:builds/);

      const capsMainAfter = (await callMcpAs(mcp2, restarted.socketPath, "claude", "main", "hyp_capabilities", {}, "cr1")).json() as { mutes: number };
      const capsSideAfter = (await callMcpAs(mcp2, restarted.socketPath, "antigravity", "side", "hyp_capabilities", {}, "cr2")).json() as { mutes: number };
      const capsStaleAfter = (await callMcpAs(mcp2, restarted.socketPath, "codex", "stale-worker", "hyp_capabilities", {}, "cr3")).json() as { mutes: number };
      assert.equal(capsMainAfter.mutes, 5);
      assert.equal(capsSideAfter.mutes, 4);
      assert.equal(capsStaleAfter.mutes, 5);

      // Re-fire all 5 muted classes after restart -> ALL still dropped!
      await fireAllTraffic(restarted.state, restarted.connector, "after_restart", true);

      // ---- 5. Prune stale session via real CLI -> deletes stale session's mutes while preserving connector mutes ----
      restarted.state.touch("codex:stale-worker", Date.now() - 2 * 3_600_000);
      restarted.state.touch("claude:main", Date.now());
      restarted.state.touch("antigravity:side", Date.now());

      const pruneRes = await runCli(["prune", "--older-than-hours", "1", "--socket", restarted.socketPath]);
      assert.equal(pruneRes.code, 0, `CLI prune failed: ${pruneRes.stderr}`);
      const pruneJson = JSON.parse(pruneRes.stdout) as { pruned: string[] };
      assert.deepEqual(pruneJson.pruned, ["codex:stale-worker"]);

      // Verify stale session & its session-scoped mute were deleted, while connector mutes + main's session mute survived
      assert.equal(restarted.state.session("codex:stale-worker"), undefined);
      const staleRemaining = restarted.state.listMutes("codex:stale-worker");
      assert.equal(staleRemaining.length, 4, "Only the 4 connector-level mutes should remain for pruned session lookup");
      assert.ok(staleRemaining.every((r) => r.scope === "*"));
      assert.ok(!staleRemaining.some((r) => r.pattern === "alice@laptop/quiet"));

      const capsMainPostPrune = (await callMcpAs(mcp2, restarted.socketPath, "claude", "main", "hyp_capabilities", {}, "cp1")).json() as { mutes: number };
      const capsSidePostPrune = (await callMcpAs(mcp2, restarted.socketPath, "antigravity", "side", "hyp_capabilities", {}, "cp2")).json() as { mutes: number };
      assert.equal(capsMainPostPrune.mutes, 5);
      assert.equal(capsSidePostPrune.mutes, 4);

      // ---- 6. Unmute all 5 classes via CLI + MCP, verify hyp_capabilities=0 & delivery resumes ----
      for (const target of ["ALICE@LAPTOP/NOISY", "jack@prod/*", "#noisy-room"]) {
        const res = await runCli(["unmute", target, "--socket", restarted.socketPath]);
        assert.equal(res.code, 0, `CLI unmute '${target}' failed: ${res.stderr}`);
        assert.equal((JSON.parse(res.stdout) as { removed: boolean }).removed, true);
      }
      const unmuteTopic = await callMcpAs(mcp2, restarted.socketPath, "claude", "main", "hyp_unmute", {
        target: "topic:builds",
        scope: "connector",
      }, "u1");
      assert.equal(unmuteTopic.isError, false, unmuteTopic.text);
      assert.equal((unmuteTopic.json() as { removed: boolean }).removed, true);

      const unmutePlugin = await callMcpAs(mcp2, restarted.socketPath, "claude", "main", "hyp_unmute", {
        target: "plugin:local-hook",
        scope: "session",
      }, "u2");
      assert.equal(unmutePlugin.isError, false, unmutePlugin.text);
      assert.equal((unmutePlugin.json() as { removed: boolean }).removed, true);

      const cliMutesEmpty = await runCli(["mutes", "--socket", restarted.socketPath]);
      assert.equal(cliMutesEmpty.code, 0, cliMutesEmpty.stderr);
      assert.match(cliMutesEmpty.stdout, /No active connector-level mutes/i);

      const capsMainZero = (await callMcpAs(mcp2, restarted.socketPath, "claude", "main", "hyp_capabilities", {}, "cz1")).json() as { mutes: number };
      const capsSideZero = (await callMcpAs(mcp2, restarted.socketPath, "antigravity", "side", "hyp_capabilities", {}, "cz2")).json() as { mutes: number };
      assert.equal(capsMainZero.mutes, 0);
      assert.equal(capsSideZero.mutes, 0);

      // Send 1 item from all 5 previously muted classes -> ALL 5 now delivered to claude:main!
      await alice.daemon.connector.call("claude:noisy", "hyp_send", {
        to: "alex@laptop/main",
        text: "UNMUTED_EXACT_PEER",
      });
      await jack.daemon.connector.call("codex:bot1", "hyp_send", {
        to: "alex@laptop/main",
        text: "UNMUTED_WILDCARD_PEER",
      });
      await alice.daemon.connector.call("antigravity:quiet", "hyp_channel_post", {
        channel: "#noisy-room",
        text: "UNMUTED_CHANNEL_POST",
      });
      await publishTopicEvent(router.url, ciToken, "builds", {
        specversion: "1.0",
        id: "build-unmuted-1",
        source: "ci/team",
        type: "com.ci.build",
        datacontenttype: "application/json",
        data: { build: "UNMUTED_TOPIC_EVENT" },
      });
      const hookUnmuted = await deliverSignedWebhook({
        url: `http://127.0.0.1:${hookPort}/hook`,
        secret: hookSecret,
        deliveryId: "hook-unmuted-1",
        payload: { type: "com.local.hook", data: { note: "UNMUTED_PLUGIN_EVENT" } },
      });
      assert.equal(hookUnmuted.status, 202);

      await waitFor(() => restarted.state.pendingCount("claude:main") >= 5, {
        timeoutMs: 8_000,
        label: "all 5 unmuted classes delivered to claude:main",
      });
      const inboxAll = (await callMcpAs(mcp2, restarted.socketPath, "claude", "main", "hyp_inbox", { acknowledgeAll: true }, "in1")).json() as {
        unread: number;
        items: Array<{ text: string }>;
      };
      assert.equal(inboxAll.unread, 0);
      assert.equal(inboxAll.items.length, 5);
      const combined = inboxAll.items.map((i) => i.text).join("\n");
      assert.match(combined, /UNMUTED_EXACT_PEER/);
      assert.match(combined, /UNMUTED_WILDCARD_PEER/);
      assert.match(combined, /\[#noisy-room\] UNMUTED_CHANNEL_POST/);
      assert.match(combined, /UNMUTED_TOPIC_EVENT/);
      assert.match(combined, /UNMUTED_PLUGIN_EVENT/);
    } finally {
      await topo.cleanup();
    }
  },
);

test(
  "mixed unread digest & idempotent re-notification in notify mode across DM, #channel, router topic, and local webhook plugin + hyp_inbox pagination/ack",
  { timeout: 30_000 },
  async () => {
    const topo = new MeshTopology("hi-m2-");
    try {
      const bridgePort = await freePort();
      const bridgeSecret = "local-bridge-hmac-secret-77";

      const router = await topo.addRouter({
        name: "team",
        topics: new Map([["alerts", ["alert-bot"]]]),
      });
      const alertToken = router.core.events.addPublisher("alert-bot", ["alerts"]);

      const alex = await topo.addConnector({
        connectorId: "alex@laptop",
        links: [{ name: "primary", router }],
        secrets: { "bridge-secret": bridgeSecret },
        rawPlugins: [
          {
            name: "local-bridge",
            builtin: "webhook",
            env: {
              WEBHOOK_HOST: "127.0.0.1",
              WEBHOOK_PORT: String(bridgePort),
              WEBHOOK_PATH: "/bridge",
              WEBHOOK_TARGET: "inbox",
              WEBHOOK_SOURCE: "local-bridge/ops",
              WEBHOOK_SECRET: { secret: "bridge-secret" },
            },
            targets: [
              { name: "inbox", handle: "reader", coalesceSeconds: 0, maxWaitSeconds: 5, wakesPerHour: 120 },
            ],
          },
        ],
      });
      const alice = await topo.addConnector({
        connectorId: "alice@laptop",
        links: [{ name: "primary", router }],
      });
      const jack = await topo.addConnector({
        connectorId: "jack@prod",
        links: [{ name: "primary", router }],
      });

      alex.daemon.state.register("antigravity:reader", { kind: "antigravity" });
      alice.daemon.state.register("claude:ops", { kind: "claude" });
      jack.daemon.state.register("codex:prod", { kind: "codex" });

      await alex.daemon.connector.call("antigravity:reader", "hyp_join", { handle: "reader" });
      await alice.daemon.connector.call("claude:ops", "hyp_join", { handle: "ops" });
      await jack.daemon.connector.call("codex:prod", "hyp_join", { handle: "prod" });

      await alex.daemon.connector.call("antigravity:reader", "hyp_channel_join", { channel: "#incidents" });
      await jack.daemon.connector.call("codex:prod", "hyp_channel_join", { channel: "#incidents" });

      await alex.daemon.connector.call("antigravity:reader", "hyp_subscribe", {
        key: "ops:alerts",
        topic: "alerts",
        filters: [{ exact: { type: "com.alerts.fired" } }],
        coalesceSeconds: 0,
      });

      // Switch reader to `notify` mode
      const modeRes = await alex.daemon.connector.call("antigravity:reader", "hyp_mode", { mode: "notify" });
      assert.deepEqual(modeRes, { deliveryMode: "notify", unread: 0 });

      const secrets = [
        "SECRET_DM_BODY_ALPHA_111",
        "SECRET_INCIDENTS_CHANNEL_BETA_222",
        "SECRET_ALERTS_EVENT_GAMMA_333",
        "SECRET_PLUGIN_BRIDGE_DELTA_444",
      ] as const;

      // Deliver 4 items simultaneously from 4 distinct categories
      const [, , , webhookRes] = await Promise.all([
        // 1. Direct peer message
        alice.daemon.connector.call("claude:ops", "hyp_send", {
          to: "alex@laptop/reader",
          text: secrets[0],
        }),
        // 2. #incidents channel post
        jack.daemon.connector.call("codex:prod", "hyp_channel_post", {
          channel: "#incidents",
          text: secrets[1],
        }),
        // 3. Router CloudEvent (topic: alerts)
        publishTopicEvent(router.url, alertToken, "alerts", {
          specversion: "1.0",
          id: "alert-evt-1",
          source: "pager/prod",
          type: "com.alerts.fired",
          datacontenttype: "application/json",
          data: { detail: secrets[2] },
        }),
        // 4. Local plugin webhook event (plugin:local-bridge)
        deliverSignedWebhook({
          url: `http://127.0.0.1:${bridgePort}/bridge`,
          secret: bridgeSecret,
          deliveryId: "bridge-evt-1",
          payload: {
            type: "com.bridge.item",
            data: { detail: secrets[3] },
          },
        }),
      ]);
      assert.equal(webhookRes.status, 202);

      // Wait for all 4 items to land unnotified in the durable mailbox
      await waitFor(
        () =>
          alex.daemon.state.pendingCount("antigravity:reader") === 4 &&
          alex.daemon.state.unnotifiedCount("antigravity:reader") === 4,
        { timeoutMs: 8_000, label: "all 4 mixed items queued unnotified" },
      );

      // PreInvocation hook delivers ONE slim unread digest with exact breakdown + sources and ZERO secret body text!
      const preInv = await handleHookPayload(
        { conversationId: "reader" },
        { harness: "antigravity", event: "pre-invocation", socketPath: alex.socketPath },
      );
      const steps = Array.isArray(preInv.injectSteps) ? preInv.injectSteps : [];
      assert.equal(steps.length, 1);
      const digestText = JSON.stringify(steps[0]);
      assert.match(digestText, /hyphae notice · 4 unread \(2 messages, 1 event, 1 bridge item\)/);
      assert.match(digestText, /alice@laptop\/ops/);
      assert.match(digestText, /#incidents \(jack@prod\/prod\)/);
      assert.match(digestText, /\balerts\b/);
      assert.match(digestText, /plugin:local-bridge/);
      assert.match(digestText, /call hyp_inbox to read/);
      for (const secret of secrets) {
        assert.equal(digestText.includes(secret), false, `Slim digest must NEVER leak body '${secret}'`);
      }

      // ---- Verify idempotent re-notification (unnotified === 0, pending === 4) ----
      const statusAfterNotice = alex.daemon.connector.sessionStatus("antigravity:reader");
      assert.equal(statusAfterNotice?.pending, 4);
      assert.equal(statusAfterNotice?.unnotified, 0);

      const secondPreInv = await handleHookPayload(
        { conversationId: "reader" },
        { harness: "antigravity", event: "pre-invocation", socketPath: alex.socketPath },
      );
      assert.deepEqual(secondPreInv, {}, "Subsequent PreInvocation must emit nothing while unnotified === 0");

      const secondStop = await handleHookPayload(
        { conversationId: "reader", continuationActive: true },
        { harness: "antigravity", event: "stop", socketPath: alex.socketPath },
      );
      assert.deepEqual(secondStop, {}, "Subsequent Stop hook must emit nothing while unnotified === 0");

      // `hyp wait` with short timeout receives NOTHING when unnotified === 0
      const idleWait = alex.spawnWait({ sessionId: "antigravity:reader", timeoutSeconds: 1 });
      const idleWaitRes = await idleWait.output;
      assert.equal(idleWaitRes.code, 0, idleWaitRes.stderr);
      assert.equal(idleWaitRes.stdout.trim(), "", "hyp wait must not re-notify already-notified unread items");

      // ---- 5th item arrives -> unnotified transitions 0 -> 1, then fresh slim 5-unread notice fires via `hyp wait` ----
      const fifthSecret = "SECRET_FIFTH_MESSAGE_EPSILON_555";
      await alice.daemon.connector.call("claude:ops", "hyp_send", {
        to: "alex@laptop/reader",
        text: fifthSecret,
      });
      await waitFor(
        () =>
          alex.daemon.state.pendingCount("antigravity:reader") === 5 &&
          alex.daemon.state.unnotifiedCount("antigravity:reader") === 1,
        { label: "5th item arriving with unnotified === 1" },
      );

      const wakeWait = alex.spawnWait({ sessionId: "antigravity:reader", timeoutSeconds: 6 });
      const wakeWaitRes = await wakeWait.output;
      assert.equal(wakeWaitRes.code, 0, wakeWaitRes.stderr);
      assert.match(wakeWaitRes.stdout, /hyphae notice · 5 unread \(3 messages, 1 event, 1 bridge item\)/);
      assert.match(wakeWaitRes.stdout, /call hyp_inbox to read/);
      for (const secret of [...secrets, fifthSecret]) {
        assert.equal(wakeWaitRes.stdout.includes(secret), false, `hyp wait notice must NEVER leak body '${secret}'`);
      }

      const statusAfterFifth = alex.daemon.connector.sessionStatus("antigravity:reader");
      assert.equal(statusAfterFifth?.pending, 5);
      assert.equal(statusAfterFifth?.unnotified, 0);

      // ---- hyp_inbox pagination (`limit: 2`), selective receipt ack (`acknowledge: [r1, r2]`), and `acknowledgeAll: true` ----
      const page1 = (await alex.daemon.connector.call("antigravity:reader", "hyp_inbox", { limit: 2 })) as {
        deliveryMode: string;
        unread: number;
        items: Array<{ receipt: string; text: string }>;
      };
      assert.equal(page1.deliveryMode, "notify");
      assert.equal(page1.unread, 5);
      assert.equal(page1.items.length, 2);
      const [r1, r2] = page1.items.map((item) => item.receipt);
      assert.ok(r1 && r2 && r1 !== r2);

      const afterSelective = (await alex.daemon.connector.call("antigravity:reader", "hyp_inbox", {
        acknowledge: [r1, r2],
      })) as {
        unread: number;
        items: Array<{ receipt: string; text: string }>;
      };
      assert.equal(afterSelective.unread, 3);
      assert.equal(afterSelective.items.length, 3);
      assert.ok(!afterSelective.items.some((item) => item.receipt === r1 || item.receipt === r2));

      const afterClearAll = (await alex.daemon.connector.call("antigravity:reader", "hyp_inbox", {
        acknowledgeAll: true,
      })) as {
        unread: number;
        items: Array<{ receipt: string; text: string }>;
      };
      assert.equal(afterClearAll.unread, 0);
      assert.equal(afterClearAll.items.length, 3);

      // Confirm all 5 full secret payloads were faithfully preserved in hyp_inbox
      const allBodies = [...page1.items, ...afterClearAll.items].map((i) => i.text).join("\n");
      for (const secret of [...secrets, fifthSecret]) {
        assert.ok(allBodies.includes(secret), `Expected full payload '${secret}' inside hyp_inbox items`);
      }

      const finalEmpty = (await alex.daemon.connector.call("antigravity:reader", "hyp_inbox", {})) as {
        unread: number;
        items: unknown[];
      };
      assert.equal(finalEmpty.unread, 0);
      assert.equal(finalEmpty.items.length, 0);
    } finally {
      await topo.cleanup();
    }
  },
);

test(
  "notify mode actuation across hooks for all 5 harnesses (Antigravity, Claude, Cursor, OpenCode, Gemini) AND Claude native --claude-channel",
  { timeout: 30_000 },
  async () => {
    const topo = new MeshTopology("hi-m3-");
    try {
      const router = await topo.addRouter({ name: "team" });
      const alex = await topo.addConnector({ connectorId: "alex@laptop", links: [{ name: "primary", router }] });
      const alice = await topo.addConnector({ connectorId: "alice@laptop", links: [{ name: "primary", router }] });

      alice.daemon.state.register("claude:sender", { kind: "claude" });
      await alice.daemon.connector.call("claude:sender", "hyp_join", { handle: "ops" });

      // ---- Part A: All 5 harness hook contracts in `notify` mode ----
      const harnessSpecs = [
        { harness: "antigravity" as const, rawId: "ag-n", handle: "h-ag" },
        { harness: "claude" as const, rawId: "cl-n", handle: "h-cl" },
        { harness: "cursor" as const, rawId: "cur-n", handle: "h-cur" },
        { harness: "opencode" as const, rawId: "oc-n", handle: "h-oc" },
        { harness: "gemini" as const, rawId: "gem-n", handle: "h-gem" },
      ];

      for (const spec of harnessSpecs) {
        const sid = `${spec.harness}:${spec.rawId}`;
        alex.daemon.state.register(sid, { kind: spec.harness });
        await alex.daemon.connector.call(sid, "hyp_join", { handle: spec.handle });
        const mode = await alex.daemon.connector.call(sid, "hyp_mode", { mode: "notify" });
        assert.deepEqual(mode, { deliveryMode: "notify", unread: 0 });
      }

      // Round 1: Send 1 secret message to each harness -> test mid-turn hook injection (`PreInvocation` / `PostToolUse` / `afterMCPExecution` / `AfterTool`)
      await Promise.all(
        harnessSpecs.map((spec) =>
          alice.daemon.connector.call("claude:sender", "hyp_send", {
            to: `alex@laptop/${spec.handle}`,
            text: `SECRET_HOOK_R1_${spec.harness.toUpperCase()}`,
          }),
        ),
      );
      await waitFor(
        () => harnessSpecs.every((spec) => alex.daemon.state.pendingCount(`${spec.harness}:${spec.rawId}`) === 1),
        { label: "Round 1 messages arriving for all 5 harnesses" },
      );

      // 1. Antigravity PreInvocation -> injectSteps
      const agPre = await handleHookPayload(
        { conversationId: "ag-n" },
        { harness: "antigravity", event: "pre-invocation", socketPath: alex.socketPath },
      );
      assert.ok(Array.isArray(agPre.injectSteps) && agPre.injectSteps.length === 1);
      const agPreText = JSON.stringify(agPre.injectSteps);
      assert.match(agPreText, /hyphae notice · 1 unread \(1 message\) · from alice@laptop\/ops/);
      assert.doesNotMatch(agPreText, /SECRET_HOOK_R1_ANTIGRAVITY/);

      // 2. Claude PostToolUse -> hookSpecificOutput.additionalContext
      const clPost = await handleHookPayload(
        { session_id: "cl-n" },
        { harness: "claude", event: "post-tool-use", socketPath: alex.socketPath },
      );
      const clOut = object(clPost.hookSpecificOutput) ? clPost.hookSpecificOutput : {};
      assert.equal(clOut.hookEventName, "PostToolUse");
      assert.match(String(clOut.additionalContext), /hyphae notice · 1 unread \(1 message\) · from alice@laptop\/ops/);
      assert.doesNotMatch(String(clOut.additionalContext), /SECRET_HOOK_R1_CLAUDE/);

      // 3. Cursor afterMCPExecution (`post-tool-use`) -> additional_context
      const curPost = await handleHookPayload(
        { conversation_id: "cur-n" },
        { harness: "cursor", event: "post-tool-use", socketPath: alex.socketPath },
      );
      assert.match(String(curPost.additional_context), /hyphae notice · 1 unread \(1 message\) · from alice@laptop\/ops/);
      assert.doesNotMatch(String(curPost.additional_context), /SECRET_HOOK_R1_CURSOR/);

      // 4. OpenCode post-tool-use -> additionalContext
      const ocPost = await handleHookPayload(
        { session_id: "oc-n" },
        { harness: "opencode", event: "post-tool-use", socketPath: alex.socketPath },
      );
      assert.match(String(ocPost.additionalContext), /hyphae notice · 1 unread \(1 message\) · from alice@laptop\/ops/);
      assert.doesNotMatch(String(ocPost.additionalContext), /SECRET_HOOK_R1_OPENCODE/);

      // 5. Gemini AfterTool (`post-tool-use`) -> hookSpecificOutput.additionalContext
      const gemPost = await handleHookPayload(
        { session_id: "gem-n" },
        { harness: "gemini", event: "post-tool-use", socketPath: alex.socketPath },
      );
      const gemOut = object(gemPost.hookSpecificOutput) ? gemPost.hookSpecificOutput : {};
      assert.equal(gemOut.hookEventName, "AfterTool");
      assert.match(String(gemOut.additionalContext), /hyphae notice · 1 unread \(1 message\) · from alice@laptop\/ops/);
      assert.doesNotMatch(String(gemOut.additionalContext), /SECRET_HOOK_R1_GEMINI/);

      // Round 2: Send 2nd secret message to each harness -> test end-of-turn Stop / AfterAgent hook injection
      await Promise.all(
        harnessSpecs.map((spec) =>
          alice.daemon.connector.call("claude:sender", "hyp_send", {
            to: `alex@laptop/${spec.handle}`,
            text: `SECRET_HOOK_R2_${spec.harness.toUpperCase()}`,
          }),
        ),
      );
      await waitFor(
        () =>
          harnessSpecs.every((spec) => {
            const sid = `${spec.harness}:${spec.rawId}`;
            return alex.daemon.state.pendingCount(sid) === 2 && alex.daemon.state.unnotifiedCount(sid) === 1;
          }),
        { label: "Round 2 messages arriving for all 5 harnesses" },
      );

      // 1. Antigravity Stop -> decision: "continue"
      const agStop = await handleHookPayload(
        { conversationId: "ag-n", terminationReason: "NO_TOOL_CALL" },
        { harness: "antigravity", event: "stop", socketPath: alex.socketPath },
      );
      assert.equal(agStop.decision, "continue");
      assert.match(String(agStop.reason), /hyphae notice · 2 unread \(2 messages\) · from alice@laptop\/ops/);
      assert.doesNotMatch(String(agStop.reason), /SECRET_HOOK_R[12]_ANTIGRAVITY/);

      // 2. Claude Stop -> decision: "block"
      const clStop = await handleHookPayload(
        { session_id: "cl-n" },
        { harness: "claude", event: "stop", socketPath: alex.socketPath },
      );
      assert.equal(clStop.decision, "block");
      assert.match(String(clStop.reason), /hyphae notice · 2 unread \(2 messages\) · from alice@laptop\/ops/);
      assert.doesNotMatch(String(clStop.reason), /SECRET_HOOK_R[12]_CLAUDE/);

      // 3. Cursor stop -> followup_message
      const curStop = await handleHookPayload(
        { conversation_id: "cur-n", loop_count: 0 },
        { harness: "cursor", event: "stop", socketPath: alex.socketPath },
      );
      assert.match(String(curStop.followup_message), /hyphae notice · 2 unread \(2 messages\) · from alice@laptop\/ops/);
      assert.doesNotMatch(String(curStop.followup_message), /SECRET_HOOK_R[12]_CURSOR/);

      // 4. OpenCode stop -> followupMessage
      const ocStop = await handleHookPayload(
        { session_id: "oc-n" },
        { harness: "opencode", event: "stop", socketPath: alex.socketPath },
      );
      assert.match(String(ocStop.followupMessage), /hyphae notice · 2 unread \(2 messages\) · from alice@laptop\/ops/);
      assert.doesNotMatch(String(ocStop.followupMessage), /SECRET_HOOK_R[12]_OPENCODE/);

      // 5. Gemini AfterAgent (`stop`) -> decision: "deny"
      const gemStop = await handleHookPayload(
        { session_id: "gem-n" },
        { harness: "gemini", event: "stop", socketPath: alex.socketPath },
      );
      assert.equal(gemStop.decision, "deny");
      assert.match(String(gemStop.reason), /hyphae notice · 2 unread \(2 messages\) · from alice@laptop\/ops/);
      assert.doesNotMatch(String(gemStop.reason), /SECRET_HOOK_R[12]_GEMINI/);

      // Verify all 5 harnesses STILL retain both full secret messages in hyp_inbox
      for (const spec of harnessSpecs) {
        const sid = `${spec.harness}:${spec.rawId}`;
        const inbox = (await alex.daemon.connector.call(sid, "hyp_inbox", { acknowledgeAll: true })) as {
          unread: number;
          items: Array<{ text: string }>;
        };
        assert.equal(inbox.unread, 0);
        assert.equal(inbox.items.length, 2);
        const joined = inbox.items.map((i) => i.text).join("\n");
        assert.match(joined, new RegExp(`SECRET_HOOK_R1_${spec.harness.toUpperCase()}`));
        assert.match(joined, new RegExp(`SECRET_HOOK_R2_${spec.harness.toUpperCase()}`));
      }

      // ---- Part B: Claude Native MCP Channel (`--claude-channel`, `--ephemeral`) in `notify` mode ----
      const chanMcp = await alex.openMcp(["--claude-channel", "--ephemeral"]);

      const joinChan = await chanMcp.callTool("hyp_join", { handle: "claude-chan" });
      assert.equal(joinChan.isError, false, joinChan.text);
      assert.deepEqual(joinChan.json(), { address: "alex@laptop/claude-chan" });

      // Wait until native Claude channel transport is bound on the daemon
      await waitFor(async () => {
        const capsRes = await chanMcp.callTool("hyp_capabilities", {});
        const caps = capsRes.json() as { inbound?: string };
        return caps.inbound === "claude-channel";
      }, { label: "Claude native channel transport binding" });

      const chanMode = await chanMcp.callTool("hyp_mode", { mode: "notify" });
      assert.equal(chanMode.isError, false, chanMode.text);
      assert.deepEqual(chanMode.json(), { deliveryMode: "notify", unread: 0 });

      // Send a message with a secret body -> daemon pushes `notifications/claude/channel` containing ONLY slim notice!
      const channelSecret = "CLAUDE_CHANNEL_TOP_SECRET_PAYLOAD_999";
      await alice.daemon.connector.call("claude:sender", "hyp_send", {
        to: "alex@laptop/claude-chan",
        text: channelSecret,
      });

      const notif = await waitFor(
        () => chanMcp.notifications.find((n) => n.method === "notifications/claude/channel"),
        { label: "notifications/claude/channel push in notify mode" },
      );
      const notifParams = object(notif.params) ? notif.params : {};
      const notifContent = String(notifParams.content ?? "");
      assert.match(notifContent, /hyphae notice · 1 unread \(1 message\) · from alice@laptop\/ops · call hyp_inbox to read/);
      assert.equal(notifContent.includes(channelSecret), false, "Claude native channel MUST NOT leak full message body in notify mode");

      // Confirm no duplicate notification is pushed
      await new Promise((r) => setTimeout(r, 200));
      assert.equal(
        chanMcp.notifications.filter((n) => n.method === "notifications/claude/channel").length,
        1,
      );

      // Verify `hyp_inbox` STILL holds the full message until read & acknowledged
      const chanInboxPeek = await chanMcp.callTool("hyp_inbox", {});
      assert.equal(chanInboxPeek.isError, false, chanInboxPeek.text);
      const peeked = chanInboxPeek.json() as { unread: number; items: Array<{ receipt: string; text: string }> };
      assert.equal(peeked.unread, 1);
      assert.equal(peeked.items.length, 1);
      assert.match(peeked.items[0].text, new RegExp(channelSecret));

      const chanInboxAck = await chanMcp.callTool("hyp_inbox", { acknowledgeAll: true });
      assert.equal(chanInboxAck.isError, false, chanInboxAck.text);
      const acked = chanInboxAck.json() as { unread: number; items: Array<{ text: string }> };
      assert.equal(acked.unread, 0);
      assert.equal(acked.items.length, 1);
      assert.match(acked.items[0].text, new RegExp(channelSecret));

      // Switch back to `full` mode -> verify `--claude-channel` now pushes the FULL body immediately!
      const backFull = await chanMcp.callTool("hyp_mode", { mode: "full" });
      assert.equal(backFull.isError, false, backFull.text);
      assert.deepEqual(backFull.json(), { deliveryMode: "full", unread: 0 });

      const fullSecret = "CLAUDE_CHANNEL_FULL_MODE_PAYLOAD_777";
      await alice.daemon.connector.call("claude:sender", "hyp_send", {
        to: "alex@laptop/claude-chan",
        text: fullSecret,
      });

      const fullNotif = await waitFor(
        () => {
          const all = chanMcp.notifications.filter((n) => n.method === "notifications/claude/channel");
          return all.length >= 2 ? all[1] : null;
        },
        { label: "notifications/claude/channel push in full mode" },
      );
      const fullContent = String(object(fullNotif.params) ? fullNotif.params.content : "");
      assert.match(fullContent, new RegExp(fullSecret));
    } finally {
      await topo.cleanup();
    }
  },
);

test(
  "REAL Antigravity (agy) binary in notify mode: hyp_join -> hyp_mode(notify) -> Stop slim notice (no secret leak) -> hyp_inbox -> hyp_send reply",
  { skip: BINARIES.agy === null ? "agy CLI not installed locally" : false, timeout: 60_000 },
  async () => {
    const topo = new MeshTopology("hi-m4-");
    try {
      const router = await topo.addRouter({ name: "team" });
      const alex = await topo.addConnector({ connectorId: "alex@laptop", links: [{ name: "primary", router }] });
      const jack = await topo.addConnector({ connectorId: "jack@prod", links: [{ name: "primary", router }] });

      jack.daemon.state.register("claude:jack-ops", { kind: "claude" });
      await jack.daemon.connector.call("claude:jack-ops", "hyp_join", { handle: "prod-ops" });

      let stage = 0;
      let sawSlimNoticeWithoutSecret = false;
      let sawSecretAfterInbox = false;

      const { result, server } = await runRealAgy({
        baseDir: topo.subDir("agy"),
        socketPath: alex.socketPath,
        prompt: "Join hyphae as agy-quiet, switch to notify mode, read inbox on slim notice, and reply to jack@prod/prod-ops.",
        handler: async (ctx) => {
          // Turn 1: hyp_join
          if (stage === 0) {
            stage = 1;
            return ctx.callAgyMcpTool("hyp_join", { handle: "agy-quiet" });
          }

          // Turn 2: hyp_mode({ mode: "notify" })
          if (stage === 1) {
            assert.ok(ctx.hasText("alex@laptop/agy-quiet"), `Expected hyp_join result in agy context: ${ctx.allText()}`);
            stage = 2;
            return ctx.callAgyMcpTool("hyp_mode", { mode: "notify" });
          }

          // Turn 3: Remote peer sends secret payload; agy ends turn -> Stop hook wakes agy with ONLY slim notice
          if (stage === 2) {
            assert.ok(ctx.hasText("notify"), `Expected hyp_mode notify result in agy context: ${ctx.allText()}`);
            stage = 3;
            await jack.daemon.connector.call("claude:jack-ops", "hyp_send", {
              to: "alex@laptop/agy-quiet",
              text: "SUPER_SECRET_NOTIFY_PAYLOAD",
            });
            await waitFor(
              () => {
                const s = alex.daemon.state.byHandle("agy-quiet");
                return s && alex.daemon.state.pendingCount(s.id) >= 1;
              },
              { label: "SUPER_SECRET_NOTIFY_PAYLOAD queued for agy-quiet" },
            );
            return ctx.reply("Standing by in notify mode.");
          }

          // Turn 4: Stop hook injected ONLY slim notice (NEVER the secret body!) -> call hyp_inbox
          if (stage === 3 && ctx.hasText("hyphae notice")) {
            assert.equal(ctx.hasText("hyphae notice"), true, "Expected 'hyphae notice' banner from Stop hook");
            assert.equal(ctx.hasText("1 unread"), true, "Expected '1 unread' in Stop hook notice");
            assert.equal(
              ctx.hasText("SUPER_SECRET_NOTIFY_PAYLOAD"),
              false,
              "Stop hook in notify mode MUST NOT leak SUPER_SECRET_NOTIFY_PAYLOAD before hyp_inbox!",
            );
            sawSlimNoticeWithoutSecret = true;
            stage = 4;
            return ctx.callAgyMcpTool("hyp_inbox", { acknowledgeAll: true });
          }

          // Turn 5: hyp_inbox revealed SUPER_SECRET_NOTIFY_PAYLOAD -> reply across router via hyp_send
          if (stage === 4) {
            assert.equal(
              ctx.hasText("SUPER_SECRET_NOTIFY_PAYLOAD"),
              true,
              `Expected SUPER_SECRET_NOTIFY_PAYLOAD after hyp_inbox: ${ctx.allText()}`,
            );
            sawSecretAfterInbox = true;
            stage = 5;
            return ctx.callAgyMcpTool("hyp_send", {
              to: "jack@prod/prod-ops",
              text: "agy-quiet-read-notify-inbox-and-replied",
            });
          }

          return ctx.reply("Completed notify workflow.");
        },
      });

      assert.equal(
        result.code,
        0,
        `agy exited ${result.code}\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}\ntranscript:\n${JSON.stringify(server.transcript, null, 2)}`,
      );
      assert.equal(sawSlimNoticeWithoutSecret, true, "Real agy should wake on Stop hook with slim notify banner and zero secret leak");
      assert.equal(sawSecretAfterInbox, true, "Real agy should receive full secret payload after calling hyp_inbox");

      const agySession = alex.daemon.state.byHandle("agy-quiet");
      assert.ok(agySession);
      assert.match(agySession.id, /^antigravity:[0-9a-f-]+$/i);
      assert.equal(agySession.deliveryMode, "notify");
      assert.equal(alex.daemon.state.pendingCount(agySession.id), 0);

      const jackReply = await waitFor(() => {
        const items = jack.daemon.connector.drainMailbox("claude:jack-ops", 5);
        return items.length > 0 ? items : null;
      }, { label: "Jack receiving real agy reply across Team Router" });
      assert.match(jackReply[0].text, /hyphae from alex@laptop\/agy-quiet/);
      assert.match(jackReply[0].text, /agy-quiet-read-notify-inbox-and-replied/);
    } finally {
      await topo.cleanup();
    }
  },
);
