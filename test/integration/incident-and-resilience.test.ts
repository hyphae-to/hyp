import assert from "node:assert/strict";
import { chmodSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { loadConfig } from "../../src/config.ts";
import { startDaemon } from "../../src/daemon.ts";
import { handleHookPayload } from "../../src/hooks.ts";
import { object } from "../../src/protocol.ts";
import { writeSecret } from "../../src/secrets.ts";
import { runOnboard } from "../../src/setup.ts";
import { freePort, MeshTopology, waitFor } from "./harness/topology.ts";
import {
  deliverGithubWebhook,
  deliverSignedWebhook,
  makeGithubPullRequestPayload,
  makePrometheusAlertPayload,
  startMockSlackServer,
} from "./shims/services.ts";

test(
  "full multi-owner incident workflow: Team Router (GitHub + Prometheus streams) + Private Router + #deploys + Private Slack bridge & live handoff",
  { timeout: 30_000 },
  async () => {
    const topo = new MeshTopology("hyphae-incident-");
    try {
      // 1. Provision Team Router with BOTH GitHub webhook & Prometheus Alertmanager streams
      const teamRouterPort = await freePort();
      const ghPort = await freePort();
      const promPort = await freePort();
      const ghSecret = "team-github-hmac-secret";
      const promSecret = "team-prom-hmac-secret";

      const hubDir = topo.subDir("team-hub");
      writeSecret("gh-secret", ghSecret, hubDir);
      writeSecret("prom-secret", promSecret, hubDir);
      const hubConfigPath = join(hubDir, "connector.json");

      await runOnboard({
        configPath: hubConfigPath,
        connectorId: "jack@prod",
        port: teamRouterPort,
        harnesses: [],
        startDaemon: false,
        localRouterExposure: "private",
        localRouterStreams: [
          {
            name: "github",
            topic: "github",
            builtin: "github-webhook",
            env: {
              GITHUB_WEBHOOK_HOST: "127.0.0.1",
              GITHUB_WEBHOOK_PORT: String(ghPort),
              GITHUB_WEBHOOK_SECRET: { secret: "gh-secret" },
            },
          },
          {
            name: "prometheus",
            topic: "prometheus",
            builtin: "webhook-stream",
            env: {
              WEBHOOK_HOST: "127.0.0.1",
              WEBHOOK_PORT: String(promPort),
              WEBHOOK_PATH: "/prometheus",
              WEBHOOK_TARGET: "prometheus",
              WEBHOOK_SOURCE: "prometheus/prod",
              WEBHOOK_SECRET: { secret: "prom-secret" },
            },
          },
        ],
      });

      const jackDaemon = await startDaemon(loadConfig(hubConfigPath), { quiet: true });
      topo.track(() => jackDaemon.stop());
      const teamRouterUrl = jackDaemon.localRouterUrl!;

      // Issue Team Router tokens for Alex & Alice using the hub router's SQLite DB
      const { RouterCore } = await import("../../src/core/router/core.ts");
      const hubCoreAdmin = new RouterCore({ dbPath: join(hubDir, "router", "router.sqlite") });
      const alexTeamToken = hubCoreAdmin.addConnector("alex@laptop");
      const aliceTeamToken = hubCoreAdmin.addConnector("alice@laptop");
      hubCoreAdmin.close();

      // 2. Provision Alex's Private Router + Mock Slack Socket Mode server for Alex's private bridge
      const alexPrivateRouter = await topo.addRouter({
        name: "alex-private",
        topics: new Map([["personal-ops", ["alex-local"]]]),
      });
      const slackAppTok = "xapp-alex-incident-app";
      const slackBotTok = "xoxb-alex-incident-bot";
      const mockSlack = await startMockSlackServer({ appToken: slackAppTok, botToken: slackBotTok });
      topo.track(() => mockSlack.close());

      // Start Alex's connector linked to BOTH Team Router (primary) AND Private Router (private) + private Slack bridge
      const alexDir = topo.subDir("alex-conn");
      const alexTeamTokFile = join(alexDir, "team.token");
      const alexPrivTokFile = join(alexDir, "private.token");
      writeFileSync(alexTeamTokFile, alexTeamToken + "\n", { mode: 0o600 });
      chmodSync(alexTeamTokFile, 0o600);
      writeFileSync(alexPrivTokFile, alexPrivateRouter.addConnector("alex@laptop") + "\n", { mode: 0o600 });
      chmodSync(alexPrivTokFile, 0o600);
      writeSecret("slack-app", slackAppTok, alexDir);
      writeSecret("slack-bot", slackBotTok, alexDir);

      const alexCfgPath = join(alexDir, "connector.json");
      writeFileSync(
        alexCfgPath,
        JSON.stringify({
          connectorId: "alex@laptop",
          stateDir: "state",
          routers: [
            { name: "primary", url: teamRouterUrl, tokenFile: alexTeamTokFile },
            { name: "private", url: alexPrivateRouter.url, tokenFile: alexPrivTokFile },
          ],
          plugins: [
            {
              name: "slack",
              builtin: "slack",
              env: {
                SLACK_API_BASE: mockSlack.apiBaseUrl,
                SLACK_APP_TOKEN: { secret: "slack-app" },
                SLACK_BOT_TOKEN: { secret: "slack-bot" },
                SLACK_ALLOWED_USERS: "UALEX",
              },
              targets: [
                { name: "pm", handle: "alex-agy", coalesceSeconds: 0, maxWaitSeconds: 5, wakesPerHour: 120 },
              ],
            },
          ],
        }),
        { mode: 0o600 },
      );
      const alexDaemon = await startDaemon(loadConfig(alexCfgPath), { quiet: true });
      topo.track(() => alexDaemon.stop());

      // Start Alice's connector linked to Team Router
      const aliceDaemon = await startDaemon(
        {
          connectorId: "alice@laptop",
          directory: topo.subDir("alice-state"),
          routers: [{ name: "primary", url: teamRouterUrl, token: aliceTeamToken }],
        },
        { quiet: true },
      );
      topo.track(() => aliceDaemon.stop());

      // 3. Enroll agents across all 3 owners and join `#deploys`
      jackDaemon.state.register("codex:oncall", { kind: "codex" });
      alexDaemon.state.register("antigravity:alex-agy", { kind: "antigravity" });
      alexDaemon.state.register("claude:alex-claude", { kind: "claude" });
      aliceDaemon.state.register("opencode:alice-oc", { kind: "opencode" });

      await jackDaemon.connector.call("codex:oncall", "hyp_join", { handle: "oncall" });
      await alexDaemon.connector.call("antigravity:alex-agy", "hyp_join", { handle: "alex-agy" });
      await alexDaemon.connector.call("claude:alex-claude", "hyp_join", { handle: "alex-claude" });
      await aliceDaemon.connector.call("opencode:alice-oc", "hyp_join", { handle: "alice-lead" });

      await jackDaemon.connector.call("codex:oncall", "hyp_channel_join", { channel: "#deploys" });
      await alexDaemon.connector.call("claude:alex-claude", "hyp_channel_join", { channel: "#deploys" });
      await aliceDaemon.connector.call("opencode:alice-oc", "hyp_channel_join", { channel: "#deploys" });

      // Subscriptions: Jack watches Prometheus firing alerts; Alice watches acme/checkout PRs
      await jackDaemon.connector.call("codex:oncall", "hyp_subscribe", {
        key: "prom:critical",
        topic: "prometheus",
        filters: [{ exact: { type: "com.prometheus.alert.firing" } }],
        coalesceSeconds: 0,
      });
      await aliceDaemon.connector.call("opencode:alice-oc", "hyp_subscribe", {
        key: "gh:checkout",
        topic: "github",
        filters: [{ exact: { type: "com.github.pull_request.opened", repo: "acme/checkout" } }],
        coalesceSeconds: 0,
      });

      await mockSlack.waitForConnected(8_000);

      // STEP A: Prometheus Alertmanager fires CheckoutHigh5xx -> wakes Jack's on-call agent
      const promRes = await deliverSignedWebhook({
        url: `http://127.0.0.1:${promPort}/prometheus`,
        secret: promSecret,
        payload: makePrometheusAlertPayload({
          alertname: "CheckoutHigh5xx",
          severity: "critical",
          service: "checkout-api",
          summary: "503 spike after release-v9",
        }),
      });
      assert.equal(promRes.status, 202);

      const jackAlert = await waitFor(() => {
        const items = jackDaemon.connector.drainMailbox("codex:oncall", 5);
        return items.length > 0 ? items[0] : null;
      }, { label: "Jack receiving Prometheus CheckoutHigh5xx" });
      assert.match(jackAlert.text, /CheckoutHigh5xx/);

      // STEP B: Jack broadcasts incident into `#deploys` -> fans out to Alex (Claude) and Alice (OpenCode)
      const chPost = (await jackDaemon.connector.call("codex:oncall", "hyp_channel_post", {
        channel: "#deploys",
        text: "INC-404: CheckoutHigh5xx on checkout-api, investigating rollback",
      })) as { deliveredTo: string[] };
      assert.deepEqual(chPost.deliveredTo, ["alex@laptop/alex-claude", "alice@laptop/alice-lead"]);

      const [alexInc, aliceInc] = await Promise.all([
        waitFor(() => {
          const items = alexDaemon.connector.drainMailbox("claude:alex-claude", 5);
          return items.length > 0 ? items[0] : null;
        }, { label: "Alex receiving #deploys incident" }),
        waitFor(() => {
          const items = aliceDaemon.connector.drainMailbox("opencode:alice-oc", 5);
          return items.length > 0 ? items[0] : null;
        }, { label: "Alice receiving #deploys incident" }),
      ]);
      assert.match(alexInc.text, /\[#deploys\] INC-404/);
      assert.match(aliceInc.text, /\[#deploys\] INC-404/);

      // STEP C: GitHub PR hotfix webhook arrives on Team Router -> delivered to Alice's subscribed OpenCode session
      const ghRes = await deliverGithubWebhook({
        receiverUrl: `http://127.0.0.1:${ghPort}`,
        secret: ghSecret,
        event: "pull_request",
        payload: makeGithubPullRequestPayload({
          repo: "acme/checkout",
          number: 901,
          title: "Revert broken retry middleware (fixes INC-404)",
          author: "alex",
        }),
      });
      assert.equal(ghRes.status, 202);

      const alicePr = await waitFor(() => {
        const items = aliceDaemon.connector.drainMailbox("opencode:alice-oc", 5);
        return items.length > 0 ? items[0] : null;
      }, { label: "Alice receiving GitHub hotfix PR" });
      assert.match(alicePr.text, /Revert broken retry middleware/);

      // STEP D: Alex receives a private Slack DM via his local Slack bridge -> hands off live to `alex-claude`!
      const env1 = mockSlack.pushEvent({
        type: "message",
        channel_type: "im",
        channel: "DPM01",
        user: "UALEX",
        ts: "1700100001.000100",
        text: "ETA on INC-404 hotfix?",
      });
      await mockSlack.waitForAck(env1);

      const alexSlack1 = await waitFor(() => {
        const items = alexDaemon.connector.drainMailbox("antigravity:alex-agy", 5);
        return items.length > 0 ? items[0] : null;
      }, { label: "Alex Antigravity receiving private Slack DM" });
      assert.match(alexSlack1.text, /ETA on INC-404 hotfix\?/);
      // Private Slack DM never leaks to Alice or Jack
      assert.equal(aliceDaemon.state.pendingCount("opencode:alice-oc"), 0);
      assert.equal(jackDaemon.state.pendingCount("codex:oncall"), 0);

      // Hand off `slack/pm` from Antigravity to Claude on Alex's connector
      await alexDaemon.connector.call("antigravity:alex-agy", "hyp_plugin_handoff", {
        plugin: "slack",
        target: "pm",
        handle: "alex-claude",
      });
      const env2 = mockSlack.pushEvent({
        type: "message",
        channel_type: "im",
        channel: "DPM01",
        user: "UALEX",
        ts: "1700100002.000100",
        text: "Confirm once PR #901 is merged",
      });
      await mockSlack.waitForAck(env2);

      const alexSlack2 = await waitFor(() => {
        const items = alexDaemon.connector.drainMailbox("claude:alex-claude", 5);
        return items.length > 0 ? items[0] : null;
      }, { label: "Alex Claude receiving Slack DM after live handoff" });
      assert.match(alexSlack2.text, /Confirm once PR #901 is merged/);
    } finally {
      await topo.cleanup();
    }
  },
);

test(
  "concurrent 6-harness session multiplexing over ONE shared MCP subprocess with zero cross-session leaks",
  { timeout: 20_000 },
  async () => {
    const topo = new MeshTopology("hyphae-mux-6-");
    try {
      const router = await topo.addRouter({ name: "team" });
      const conn = await topo.addConnector({ connectorId: "dev@workstation", links: [{ name: "primary", router }] });
      const sharedMcp = await conn.openMcp();

      type AgentSpec = {
        readonly harness: "antigravity" | "claude" | "codex" | "opencode" | "cursor" | "gemini";
        readonly rawId: string;
        readonly handle: string;
      };
      const agents: AgentSpec[] = [
        { harness: "antigravity", rawId: "ag-1", handle: "h-agy" },
        { harness: "claude", rawId: "cl-2", handle: "h-claude" },
        { harness: "codex", rawId: "cx-3", handle: "h-codex" },
        { harness: "opencode", rawId: "oc-4", handle: "h-opencode" },
        { harness: "cursor", rawId: "cur-5", handle: "h-cursor" },
        { harness: "gemini", rawId: "gem-6", handle: "h-gemini" },
      ];

      // Helper performing each harness's authentic PreToolUse hook + shared MCP call
      const callAs = async (agent: AgentSpec, tool: string, args: Record<string, unknown>, seq: string) => {
        const callId = `${agent.harness}_call_${seq}`;
        let callArgs = { ...args };
        let meta: Record<string, unknown> | undefined;

        if (agent.harness === "antigravity") {
          const pre = await handleHookPayload(
            { conversationId: agent.rawId, toolCall: { id: callId, name: tool, args } },
            { harness: "antigravity", event: "pre-tool-use", socketPath: conn.socketPath },
          );
          if (object(pre.overwrite)) callArgs = { ...callArgs, ...pre.overwrite };
        } else if (agent.harness === "claude") {
          await handleHookPayload(
            { session_id: agent.rawId, tool_use_id: callId, tool_name: `mcp__hyphae__${tool}` },
            { harness: "claude", event: "pre-tool-use", socketPath: conn.socketPath },
          );
          meta = { "claudecode/toolUseId": callId };
        } else if (agent.harness === "codex") {
          await handleHookPayload(
            { session_id: agent.rawId, tool_use_id: callId, tool_name: `hyphae.${tool}` },
            { harness: "codex", event: "pre-tool-use", socketPath: conn.socketPath },
          );
          meta = { callId };
        } else if (agent.harness === "opencode") {
          const pre = await handleHookPayload(
            { session_id: agent.rawId, call_id: callId, tool_name: `hyphae_${tool}` },
            { harness: "opencode", event: "pre-tool-use", socketPath: conn.socketPath },
          );
          if (typeof pre.callToken === "string") callArgs._meshCall = pre.callToken;
        } else if (agent.harness === "cursor") {
          await handleHookPayload(
            { conversation_id: agent.rawId, tool_use_id: callId, tool_name: `hyphae_${tool}` },
            { harness: "cursor", event: "pre-tool-use", socketPath: conn.socketPath },
          );
          meta = { toolUseId: callId };
        } else if (agent.harness === "gemini") {
          const pre = await handleHookPayload(
            { session_id: agent.rawId, tool_name: `mcp_hyphae_${tool}`, tool_input: args },
            { harness: "gemini", event: "pre-tool-use", socketPath: conn.socketPath },
          );
          const out = object(pre.hookSpecificOutput) && object(pre.hookSpecificOutput.tool_input)
            ? pre.hookSpecificOutput.tool_input
            : {};
          callArgs = { ...callArgs, ...out };
        }

        return sharedMcp.callTool(tool, callArgs, meta);
      };

      // Enroll all 6 harnesses CONCURRENTLY through the single shared MCP subprocess!
      const joins = await Promise.all(agents.map((a, idx) => callAs(a, "hyp_join", { handle: a.handle }, `join_${idx}`)));
      for (let i = 0; i < agents.length; i++) {
        assert.equal(joins[i].isError, false, `Join failed for ${agents[i].harness}: ${joins[i].text}`);
        assert.deepEqual(joins[i].json(), { address: `dev@workstation/${agents[i].handle}` });
      }

      // Handle collision across harnesses must be rejected (`handle_taken`)
      const hijack = await callAs(agents[1], "hyp_join", { handle: "h-agy" }, "hijack");
      assert.equal(hijack.isError, true);
      assert.match(hijack.text, /handle_taken/);

      // Ring send: every agent sends a unique secret token to the next agent concurrently!
      await Promise.all(
        agents.map((sender, idx) => {
          const recipient = agents[(idx + 1) % agents.length];
          return callAs(
            sender,
            "hyp_send",
            { to: `dev@workstation/${recipient.handle}`, text: `ONLY_FOR_${recipient.handle}_FROM_${sender.handle}` },
            `send_${idx}`,
          ).then((res) => assert.equal(res.isError, false, `Send failed for ${sender.handle}: ${res.text}`));
        }),
      );

      // Verify EVERY session receives ONLY its own secret message — zero cross-session leaks!
      for (let i = 0; i < agents.length; i++) {
        const recipient = agents[i];
        const expectedSender = agents[(i + agents.length - 1) % agents.length];
        const sid = `${recipient.harness}:${recipient.rawId}`;
        const items = await waitFor(() => {
          const drained = conn.daemon.connector.drainMailbox(sid, 10);
          return drained.length > 0 ? drained : null;
        }, { label: `${sid} receiving ring message` });
        assert.equal(items.length, 1);
        assert.match(items[0].text, new RegExp(`ONLY_FOR_${recipient.handle}_FROM_${expectedSender.handle}`));
        // Confirm no other agent's secret leaked into this mailbox
        for (const other of agents) {
          if (other.handle !== recipient.handle) {
            assert.doesNotMatch(items[0].text, new RegExp(`ONLY_FOR_${other.handle}_`));
          }
        }
      }
    } finally {
      await topo.cleanup();
    }
  },
);

test(
  "resilience & security fail-closed: router restart/reconnect, stale socket recovery, forged/replayed tokens, and 0644 secret rejection",
  { timeout: 30_000 },
  async () => {
    const topo = new MeshTopology("hyphae-resilience-");
    try {
      const router = await topo.addRouter({ name: "team" });
      const alex = await topo.addConnector({ connectorId: "alex@laptop", links: [{ name: "primary", router }] });
      const alice = await topo.addConnector({ connectorId: "alice@laptop", links: [{ name: "primary", router }] });

      alex.daemon.state.register("claude:a1", { kind: "claude" });
      alice.daemon.state.register("antigravity:b1", { kind: "antigravity" });
      await alex.daemon.connector.call("claude:a1", "hyp_join", { handle: "alex" });
      await alice.daemon.connector.call("antigravity:b1", "hyp_join", { handle: "alice" });

      // 1. Router restart mid-session -> connectors auto-reconnect, re-sync handles, and deliver new messages!
      await router.restart();

      // Wait until both connectors have re-attached SSE & re-synced handles on the restarted router
      await waitFor(async () => {
        try {
          const peers = (await alex.daemon.connector.call("claude:a1", "hyp_peers", {})) as {
            peers: Array<{ address: string; online: boolean }>;
          };
          const onlineAddrs = peers.peers.filter((p) => p.online).map((p) => p.address).sort();
          return onlineAddrs.length === 2 && onlineAddrs[0] === "alex@laptop/alex" && onlineAddrs[1] === "alice@laptop/alice";
        } catch {
          return false;
        }
      }, { timeoutMs: 12_000, intervalMs: 150, label: "connectors reconnecting after router restart" });

      await alex.daemon.connector.call("claude:a1", "hyp_send", {
        to: "alice@laptop/alice",
        text: "survived-router-restart",
      });
      const afterRestart = await waitFor(() => {
        const items = alice.daemon.connector.drainMailbox("antigravity:b1", 5);
        return items.length > 0 ? items[0] : null;
      }, { label: "Alice receiving message after router restart" });
      assert.match(afterRestart.text, /survived-router-restart/);

      // 2. Unverified MCP calls, forged token, replayed single-use token, and cross-tool token misuse ALL fail closed!
      const mcp = await alex.openMcp();

      const unverified = await mcp.callTool("hyp_peers", {});
      assert.equal(unverified.isError, true);
      assert.match(unverified.text, /caller_unverifiable/);

      const forged = await mcp.callTool("hyp_peers", { _meshCall: "forged-token-xyz" });
      assert.equal(forged.isError, true);
      assert.match(forged.text, /caller_not_found/);

      // Register a valid single-use token for `hyp_peers`
      const pre = await handleHookPayload(
        { conversationId: "sec-1", toolCall: { id: "sec_call_1", name: "hyp_peers", args: {} } },
        { harness: "antigravity", event: "pre-tool-use", socketPath: alex.socketPath },
      );
      const token = object(pre.overwrite) && typeof pre.overwrite._meshCall === "string" ? pre.overwrite._meshCall : "";
      assert.ok(token.length > 10);

      // Misusing a `hyp_peers` token for `hyp_send` MUST fail closed!
      const wrongTool = await mcp.callTool("hyp_send", { to: "alice@laptop/alice", text: "spoof", _meshCall: token });
      assert.equal(wrongTool.isError, true);
      assert.match(wrongTool.text, /caller_not_found/);

      // Using it on the right tool succeeds once
      const okOnce = await mcp.callTool("hyp_peers", { _meshCall: token });
      assert.equal(okOnce.isError, false);

      // Replaying the consumed token MUST fail closed!
      const replayed = await mcp.callTool("hyp_peers", { _meshCall: token });
      assert.equal(replayed.isError, true);
      assert.match(replayed.text, /caller_not_found/);

      // 3. Stale socket recovery & duplicate live daemon refusal
      const recoveryDir = topo.subDir("stale-sock-recovery");
      const recToken = router.addConnector("rec@host");
      const recCfg = {
        connectorId: "rec@host",
        directory: recoveryDir,
        routers: [{ name: "primary", url: router.url, token: recToken }],
      };
      // Plant a stale dead socket file before startup
      writeFileSync(join(recoveryDir, "connector.sock"), "");
      const recovered = await startDaemon(recCfg, { quiet: true });
      try {
        // Duplicate live daemon must refuse to clobber active socket
        await assert.rejects(() => startDaemon(recCfg, { quiet: true }), /already running/);
      } finally {
        await recovered.stop();
      }

      // 4. Overly broad `0644` secret file fails closed during `loadConfig`
      const badSecDir = topo.subDir("bad-secret-perms");
      const tokPath = join(badSecDir, "router.token");
      writeFileSync(tokPath, recToken + "\n", { mode: 0o600 });
      chmodSync(tokPath, 0o600);
      const secPath = writeSecret("bad-perm-secret", "super-secret", badSecDir);
      chmodSync(secPath, 0o644);
      const badCfgPath = join(badSecDir, "connector.json");
      writeFileSync(
        badCfgPath,
        JSON.stringify({
          connectorId: "bad@host",
          stateDir: "state",
          routers: [{ name: "primary", url: router.url, tokenFile: tokPath }],
          plugins: [
            {
              name: "hook",
              builtin: "webhook",
              env: { WEBHOOK_SECRET: { secret: "bad-perm-secret" } },
              targets: [{ name: "ops", handle: "ops" }],
            },
          ],
        }),
        { mode: 0o600 },
      );
      assert.throws(() => loadConfig(badCfgPath), /overly broad permissions/i);
    } finally {
      await topo.cleanup();
    }
  },
);
