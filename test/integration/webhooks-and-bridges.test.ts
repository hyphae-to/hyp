import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { freePort, MeshTopology, waitFor } from "./harness/topology.ts";
import {
  deliverGithubWebhook,
  deliverSignedWebhook,
  makeGithubPullRequestPayload,
  makePrometheusAlertPayload,
  startMockSlackServer,
  startMockTelegramServer,
} from "./shims/services.ts";

test(
  "router streams: github-webhook (X-Hub-Signature-256) + Prometheus webhook-stream with 0600 {secret} resolution",
  { timeout: 25_000 },
  async () => {
    const topo = new MeshTopology("hyphae-streams-");
    try {
      const routerPort = await freePort();
      const ghPort = await freePort();
      const promPort = await freePort();

      const ghSecret = "gh-webhook-hmac-secret-99";
      const promSecret = "prom-alertmanager-hmac-42";

      // Host connector running an embedded local router with BOTH builtin streams (`github-webhook` + `webhook-stream`)
      // configured via `loadConfig` using `0600` `{ secret: "<name>" }` references!
      const teamRouterSeed = await topo.addRouter({ name: "dummy-seed" });
      await teamRouterSeed.close();

      // Build an embedded-router connector via `runOnboard`-style config (localRouter + 0600 secrets)
      const routerHostDir = topo.subDir("hub");
      const { writeSecret } = await import("../../src/secrets.ts");
      const { runOnboard } = await import("../../src/setup.ts");
      const { loadConfig } = await import("../../src/config.ts");
      const { startDaemon } = await import("../../src/daemon.ts");

      writeSecret("github-webhook-secret", ghSecret, routerHostDir);
      writeSecret("prom-webhook-secret", promSecret, routerHostDir);

      const configPath = join(routerHostDir, "connector.json");
      await runOnboard({
        configPath,
        connectorId: "team@hub",
        port: routerPort,
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
              GITHUB_WEBHOOK_SECRET: { secret: "github-webhook-secret" },
            },
          },
          {
            name: "prometheus",
            topic: "prometheus",
            builtin: "webhook-stream",
            env: {
              WEBHOOK_HOST: "127.0.0.1",
              WEBHOOK_PORT: String(promPort),
              WEBHOOK_PATH: "/alerts",
              WEBHOOK_TARGET: "prometheus",
              WEBHOOK_SOURCE: "prometheus/prod",
              WEBHOOK_SECRET: { secret: "prom-webhook-secret" },
            },
          },
        ],
      });

      // Verify secret values were NEVER written into connector.json
      const rawJson = readFileSync(configPath, "utf8");
      assert.equal(rawJson.includes(ghSecret), false);
      assert.equal(rawJson.includes(promSecret), false);

      const hubDaemon = await startDaemon(loadConfig(configPath), { quiet: true });
      topo.track(() => hubDaemon.stop());

      // Register two agents: one subscribed to GitHub PRs in acme/checkout, one to critical Prometheus alerts
      hubDaemon.state.register("claude:reviewer", { kind: "claude" });
      hubDaemon.state.register("codex:oncall", { kind: "codex" });
      await hubDaemon.connector.call("claude:reviewer", "hyp_join", { handle: "reviewer" });
      await hubDaemon.connector.call("codex:oncall", "hyp_join", { handle: "oncall" });

      await hubDaemon.connector.call("claude:reviewer", "hyp_subscribe", {
        key: "gh:checkout-prs",
        topic: "github",
        filters: [{ exact: { type: "com.github.pull_request.opened", repo: "acme/checkout" } }],
        coalesceSeconds: 0,
      });
      await hubDaemon.connector.call("codex:oncall", "hyp_subscribe", {
        key: "prom:firing",
        topic: "prometheus",
        filters: [{ exact: { type: "com.prometheus.alert.firing" } }],
        coalesceSeconds: 0,
      });

      // 1. GitHub invalid & missing X-Hub-Signature-256 MUST fail closed with 401
      const ghPayload = makeGithubPullRequestPayload({
        repo: "acme/checkout",
        number: 412,
        title: "Fix nil deref in payment handler",
        author: "alice",
      });
      const badGh1 = await deliverGithubWebhook({
        receiverUrl: `http://127.0.0.1:${ghPort}`,
        secret: ghSecret,
        event: "pull_request",
        payload: ghPayload,
        overrideSignature: "sha256=" + "0".repeat(64),
      });
      assert.equal(badGh1.status, 401);

      const badGh2 = await deliverGithubWebhook({
        receiverUrl: `http://127.0.0.1:${ghPort}`,
        secret: ghSecret,
        event: "pull_request",
        payload: ghPayload,
        overrideSignature: null,
      });
      assert.equal(badGh2.status, 401);

      // 2. GitHub valid signature -> 202 and normalized CloudEvent delivered to `reviewer`
      const okGh = await deliverGithubWebhook({
        receiverUrl: `http://127.0.0.1:${ghPort}`,
        secret: ghSecret,
        event: "pull_request",
        payload: ghPayload,
      });
      assert.equal(okGh.status, 202);

      // Unmatched repo PR should be stored (202) but NOT delivered to `reviewer`
      const otherRepoGh = await deliverGithubWebhook({
        receiverUrl: `http://127.0.0.1:${ghPort}`,
        secret: ghSecret,
        event: "pull_request",
        payload: makeGithubPullRequestPayload({ repo: "acme/other-repo", number: 9, title: "Ignored PR" }),
      });
      assert.equal(otherRepoGh.status, 202);

      // 3. Prometheus webhook-stream: bad signature rejected with 401, valid signature -> 202 delivered to `oncall`
      const promAlert = makePrometheusAlertPayload({
        alertname: "CheckoutHigh5xx",
        severity: "critical",
        service: "checkout-api",
        summary: "5xx rate > 5% for 2m",
      });
      const badProm = await deliverSignedWebhook({
        url: `http://127.0.0.1:${promPort}/alerts`,
        secret: promSecret,
        payload: promAlert,
        overrideSignature: "sha256=deadbeef",
      });
      assert.equal(badProm.status, 401);

      const okProm = await deliverSignedWebhook({
        url: `http://127.0.0.1:${promPort}/alerts`,
        secret: promSecret,
        payload: promAlert,
      });
      assert.equal(okProm.status, 202);

      const [ghItems, promItems] = await Promise.all([
        waitFor(() => {
          const items = hubDaemon.connector.drainMailbox("claude:reviewer", 5);
          return items.length > 0 ? items : null;
        }, { label: "reviewer receiving GitHub PR event" }),
        waitFor(() => {
          const items = hubDaemon.connector.drainMailbox("codex:oncall", 5);
          return items.length > 0 ? items : null;
        }, { label: "oncall receiving Prometheus alert event" }),
      ]);

      assert.equal(ghItems.length, 1);
      assert.match(ghItems[0].text, /Fix nil deref in payment handler/);
      assert.doesNotMatch(ghItems[0].text, /Ignored PR/);

      assert.equal(promItems.length, 1);
      assert.match(promItems[0].text, /CheckoutHigh5xx/);
      assert.match(promItems[0].text, /checkout-api/);
    } finally {
      await topo.cleanup();
    }
  },
);

test(
  "real built-in Slack Socket Mode bridge: 0600 {secret} resolution, allowlist filtering, plugin mute, and live hyp_plugin_handoff",
  { timeout: 25_000 },
  async () => {
    const topo = new MeshTopology("hyphae-slack-");
    try {
      const appToken = "xapp-1-local-test-app-token";
      const botToken = "xoxb-local-test-bot-token";
      const mockSlack = await startMockSlackServer({ appToken, botToken, botUserId: "UBOT42", teamId: "TACME" });
      topo.track(() => mockSlack.close());

      const router = await topo.addRouter({ name: "private" });
      const alex = await topo.addConnector({
        connectorId: "alex@laptop",
        links: [{ name: "primary", router }],
        secrets: {
          "slack-app-token": appToken,
          "slack-bot-token": botToken,
        },
        rawPlugins: [
          {
            name: "slack",
            builtin: "slack",
            env: {
              SLACK_API_BASE: mockSlack.apiBaseUrl,
              SLACK_APP_TOKEN: { secret: "slack-app-token" },
              SLACK_BOT_TOKEN: { secret: "slack-bot-token" },
              SLACK_ALLOWED_USERS: "UALEX01",
            },
            targets: [
              { name: "pm", handle: "pm-agy", coalesceSeconds: 0, maxWaitSeconds: 5, wakesPerHour: 120 },
            ],
          },
        ],
      });

      // Verify raw secrets were NOT written into connector.json
      const cfgRaw = readFileSync(alex.configPath, "utf8");
      assert.equal(cfgRaw.includes(appToken), false);
      assert.equal(cfgRaw.includes(botToken), false);

      // Register two sessions across harnesses: Antigravity (`pm-agy`) and Claude (`pm-claude`)
      alex.daemon.state.register("antigravity:pm-1", { kind: "antigravity" });
      alex.daemon.state.register("claude:pm-2", { kind: "claude" });
      await alex.daemon.connector.call("antigravity:pm-1", "hyp_join", { handle: "pm-agy" });
      await alex.daemon.connector.call("claude:pm-2", "hyp_join", { handle: "pm-claude" });

      // Wait for real plugins/slack/index.mjs to complete auth.test + WebSocket handshake
      await mockSlack.waitForConnected(8_000);
      assert.deepEqual(mockSlack.authCalls, [botToken]);

      // 1. Unauthorized Slack user MUST be ignored by SLACK_ALLOWED_USERS allowlist
      const strangerEnv = mockSlack.pushEvent({
        type: "message",
        channel_type: "im",
        channel: "DSTRANGER",
        user: "USTRANGER99",
        ts: "1700000001.000100",
        text: "unauthorized-prompt-injection",
      });
      await mockSlack.waitForAck(strangerEnv);

      // 2. Allowed user sends a DM -> delivered to `pm-agy`!
      const dmEnv = mockSlack.pushEvent({
        type: "message",
        channel_type: "im",
        channel: "DALEX01",
        user: "UALEX01",
        ts: "1700000002.000100",
        text: "Can you check checkout-api latency?",
      });
      await mockSlack.waitForAck(dmEnv);

      const agyItems = await waitFor(() => {
        const items = alex.daemon.connector.drainMailbox("antigravity:pm-1", 5);
        return items.length > 0 ? items : null;
      }, { label: "pm-agy receiving Slack DM" });
      assert.equal(agyItems.length, 1);
      assert.match(agyItems[0].text, /hyphae event plugin:slack/);
      assert.match(agyItems[0].text, /Can you check checkout-api latency\?/);
      assert.doesNotMatch(agyItems[0].text, /unauthorized-prompt-injection/);

      // 3. Mute `plugin:slack` at connector level -> mention dropped cleanly
      await alex.daemon.connector.call("antigravity:pm-1", "hyp_mute", { target: "plugin:slack" });
      const mutedEnv = mockSlack.pushEvent({
        type: "app_mention",
        channel: "COPS01",
        user: "UALEX01",
        ts: "1700000003.000100",
        text: "<@UBOT42> this-should-be-muted",
      });
      await mockSlack.waitForAck(mutedEnv);
      await new Promise((r) => setTimeout(r, 250));
      assert.equal(alex.daemon.state.pendingCount("antigravity:pm-1"), 0);
      await alex.daemon.connector.call("antigravity:pm-1", "hyp_unmute", { target: "plugin:slack" });

      // 4. Inspect `hyp_plugin_targets` & live `hyp_plugin_handoff` from Antigravity -> Claude!
      const targets = (await alex.daemon.connector.call("antigravity:pm-1", "hyp_plugin_targets", {})) as {
        targets: Array<{ plugin: string; target: string; handle: string | null }>;
      };
      assert.deepEqual(targets.targets.map((t) => `${t.plugin}/${t.target}`), ["slack/pm"]);

      const handoff = await alex.daemon.connector.call("antigravity:pm-1", "hyp_plugin_handoff", {
        plugin: "slack",
        target: "pm",
        handle: "pm-claude",
      });
      assert.deepEqual(handoff, { plugin: "slack", target: "pm", sessionId: "claude:pm-2" });

      // 5. Thread follow-up on the previously mentioned thread now routes directly to Claude (`pm-claude`)!
      const threadEnv = mockSlack.pushEvent({
        type: "message",
        channel: "COPS01",
        user: "UALEX01",
        ts: "1700000004.000100",
        thread_ts: "1700000003.000100",
        text: "follow-up-routed-to-claude-after-handoff",
      });
      await mockSlack.waitForAck(threadEnv);

      const claudeItems = await waitFor(() => {
        const items = alex.daemon.connector.drainMailbox("claude:pm-2", 5);
        return items.length > 0 ? items : null;
      }, { label: "pm-claude receiving Slack thread reply after handoff" });
      assert.equal(claudeItems.length, 1);
      assert.match(claudeItems[0].text, /follow-up-routed-to-claude-after-handoff/);
      assert.equal(alex.daemon.state.pendingCount("antigravity:pm-1"), 0);
    } finally {
      await topo.cleanup();
    }
  },
);

test(
  "real built-in Telegram long-polling bridge: 0600 {secret} resolution, allowlist filtering, offset persistence, and handoff",
  { timeout: 25_000 },
  async () => {
    const topo = new MeshTopology("hyphae-tg-");
    try {
      const botToken = "123456:ABC-local-telegram-secret";
      const mockTg = await startMockTelegramServer(botToken, 100);
      topo.track(() => mockTg.close());

      const router = await topo.addRouter({ name: "private" });
      const offsetFile = join(topo.subDir("tg-state"), "offset.json");

      const alice = await topo.addConnector({
        connectorId: "alice@laptop",
        links: [{ name: "primary", router }],
        secrets: { "telegram-bot-token": botToken },
        rawPlugins: [
          {
            name: "telegram",
            builtin: "telegram",
            env: {
              TELEGRAM_API_BASE: mockTg.apiBaseUrl,
              TELEGRAM_BOT_TOKEN: { secret: "telegram-bot-token" },
              TELEGRAM_ALLOWED_USERS: "77001",
              TELEGRAM_STATE_FILE: offsetFile,
            },
            targets: [
              { name: "assistant", handle: "tg-codex", coalesceSeconds: 0, maxWaitSeconds: 5, wakesPerHour: 120 },
            ],
          },
        ],
      });

      alice.daemon.state.register("codex:tg-1", { kind: "codex" });
      alice.daemon.state.register("opencode:tg-2", { kind: "opencode" });
      await alice.daemon.connector.call("codex:tg-1", "hyp_join", { handle: "tg-codex" });
      await alice.daemon.connector.call("opencode:tg-2", "hyp_join", { handle: "tg-opencode" });

      await mockTg.waitForPoll(1, 8_000);

      // Push one disallowed user update + one allowed user update
      mockTg.pushUpdate({
        update_id: 500,
        message: {
          message_id: 1,
          chat: { id: 99999, type: "private" },
          from: { id: 99999, username: "intruder" },
          text: "must-be-dropped",
        },
      });
      mockTg.pushUpdate({
        update_id: 501,
        message: {
          message_id: 2,
          chat: { id: 77001, type: "private" },
          from: { id: 77001, username: "alice", first_name: "Alice" },
          text: "status update from telegram",
        },
      });

      const codexItems = await waitFor(() => {
        const items = alice.daemon.connector.drainMailbox("codex:tg-1", 5);
        return items.length > 0 ? items : null;
      }, { label: "tg-codex receiving Telegram update" });
      assert.equal(codexItems.length, 1);
      assert.match(codexItems[0].text, /hyphae event plugin:telegram/);
      assert.match(codexItems[0].text, /status update from telegram/);
      assert.doesNotMatch(codexItems[0].text, /must-be-dropped/);

      // Verify offset checkpoint file persisted update_id + 1 = 502
      await waitFor(() => existsSync(offsetFile), { label: "Telegram offset checkpoint file" });
      const savedOffset = JSON.parse(readFileSync(offsetFile, "utf8")) as { offset: number };
      assert.equal(savedOffset.offset, 502);

      // Live handoff from Codex -> OpenCode and deliver update 502
      await alice.daemon.connector.call("codex:tg-1", "hyp_plugin_handoff", {
        plugin: "telegram",
        target: "assistant",
        handle: "tg-opencode",
      });
      mockTg.pushUpdate({
        update_id: 502,
        message: {
          message_id: 3,
          chat: { id: 77001, type: "private" },
          from: { id: 77001, username: "alice" },
          text: "handed-off-to-opencode",
        },
      });

      const ocItems = await waitFor(() => {
        const items = alice.daemon.connector.drainMailbox("opencode:tg-2", 5);
        return items.length > 0 ? items : null;
      }, { label: "tg-opencode receiving Telegram update after handoff" });
      assert.equal(ocItems.length, 1);
      assert.match(ocItems[0].text, /handed-off-to-opencode/);
    } finally {
      await topo.cleanup();
    }
  },
);
