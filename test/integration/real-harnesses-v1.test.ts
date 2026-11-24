import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { resolveEnvWithSecrets, writeSecret } from "../../src/secrets.ts";
import { BINARIES, runRealAgy, runRealClaude, runRealOpenCode } from "./harness/drivers.ts";
import { freePort, MeshTopology, waitFor } from "./harness/topology.ts";
import {
  deliverGithubWebhook,
  makeGithubPullRequestPayload,
  startMockSlackServer,
  startMockTelegramServer,
} from "./shims/services.ts";

interface Deferred {
  readonly promise: Promise<void>;
  resolve(): void;
  reject(err: Error): void;
}

function createDeferred(): Deferred {
  let resolve!: () => void;
  let reject!: (err: Error) => void;
  const promise = new Promise<void>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  // Prevent unhandled rejection if one peer rejects a deferred the other peer never awaits.
  promise.catch(() => {});
  return { promise, resolve, reject };
}

function awaitWithTimeout(promise: Promise<void>, timeoutMs: number, label: string): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(`Timed out after ${timeoutMs}ms waiting for ${label}`));
    }, timeoutMs).unref();
    promise.then(
      () => {
        clearTimeout(timer);
        resolve();
      },
      (err) => {
        clearTimeout(timer);
        reject(err);
      },
    );
  });
}

async function deliverGithubWebhookWithRetry(
  input: Parameters<typeof deliverGithubWebhook>[0],
  timeoutMs = 5_000,
): Promise<{ status: number; body: unknown }> {
  const deadline = Date.now() + timeoutMs;
  while (true) {
    try {
      return await deliverGithubWebhook(input);
    } catch (err) {
      if (Date.now() >= deadline) throw err;
      await new Promise((r) => setTimeout(r, 80));
    }
  }
}

test(
  "REAL Claude binary: hyp_topics -> GitHub reachability lint self-correction (strict: true) -> PR webhook + Slack app_mention -> hyp_bridge_link -> outbound hyp_plugin_post",
  { skip: BINARIES.claude === null ? "claude CLI not installed locally" : false, timeout: 90_000 },
  async () => {
    const topo = new MeshTopology("hi-rv1-cl-");
    try {
      const ghSecret = "gh-v1-real-claude-hmac-secret";
      const appToken = "xapp-1-v1-real-claude-app-token";
      const botToken = "xoxb-v1-real-claude-bot-token";

      const mockSlack = await startMockSlackServer({
        appToken,
        botToken,
        botUserId: "UBOT123",
        teamId: "TV1CLAUDE",
      });
      topo.track(() => mockSlack.close());

      const ghPort = await freePort();
      const secretsConfigDir = topo.subDir("sec");
      writeSecret("gh-v1-sec", ghSecret, secretsConfigDir);
      const ghStreamEnv = resolveEnvWithSecrets(
        {
          GITHUB_WEBHOOK_HOST: "127.0.0.1",
          GITHUB_WEBHOOK_PORT: String(ghPort),
          GITHUB_WEBHOOK_SECRET: { secret: "gh-v1-sec" },
          GITHUB_REPOS: "hyphae-to/hyp",
        },
        secretsConfigDir,
        "Stream 'github'",
      ).env;

      const teamRouter = await topo.addRouter({
        name: "team",
        streams: [
          {
            name: "github",
            topic: "github",
            builtin: "github-webhook",
            args: [],
            env: ghStreamEnv,
            cwd: topo.rootDir,
            scope: { repos: ["hyphae-to/hyp"] },
          },
        ],
      });

      const alex = await topo.addConnector({
        connectorId: "alex@laptop",
        links: [{ name: "primary", router: teamRouter }],
        secrets: {
          "sl-v1-app": appToken,
          "sl-v1-bot": botToken,
        },
        rawPlugins: [
          {
            name: "slack",
            builtin: "slack",
            env: {
              SLACK_API_BASE: mockSlack.apiBaseUrl,
              SLACK_ALLOWED_CHANNELS: "C-V1",
              SLACK_ALLOWED_USERS: "UOPS1",
              SLACK_APP_TOKEN: { secret: "sl-v1-app" },
              SLACK_BOT_TOKEN: { secret: "sl-v1-bot" },
              SLACK_TARGET: "slack-v1",
            },
            targets: [
              { name: "slack-v1", handle: "claude-v1", coalesceSeconds: 1, maxWaitSeconds: 5, wakesPerHour: 120 },
            ],
          },
        ],
      });

      // Verify raw secret values were never persisted into connector.json
      const cfgRaw = readFileSync(alex.configPath, "utf8");
      assert.equal(cfgRaw.includes(appToken), false, "Slack app token must not appear in connector.json");
      assert.equal(cfgRaw.includes(botToken), false, "Slack bot token must not appear in connector.json");

      await mockSlack.waitForConnected(8_000);
      assert.deepEqual(mockSlack.authCalls, [botToken]);

      // Register a local peer session on alex@laptop that Claude will link into the Slack bridge
      alex.daemon.state.register("antigravity:rev-1", { kind: "antigravity" });
      await alex.daemon.connector.call("antigravity:rev-1", "hyp_join", { handle: "reviewer" });

      let stage = 0;
      let sawGithubEvent = false;
      let sawSlackMention = false;
      let postedSlackReply = false;

      const { result, server } = await runRealClaude({
        baseDir: topo.subDir("claude-v1"),
        socketPath: alex.socketPath,
        timeoutMs: 75_000,
        prompt:
          "Join hyphae as claude-v1, inspect hyp_topics, test GitHub subscription reachability lint and fix it with strict mode, link reviewer to slack/slack-v1, wait for GitHub PR and Slack mention events, and reply to Slack via hyp_plugin_post.",
        handler: async (ctx) => {
          // Stage 0: Load deferred MCP tools via Claude's ToolSearch when deferred loading is active
          if (stage === 0 && !ctx.findTool("hyp_session") && ctx.findTool("ToolSearch")) {
            return ctx.selectClaudeTools([
              "hyp_session",
              "hyp_stream",
              "hyp_bridge",
            ]);
          }

          if (stage === 0) {
            stage = 1;
            return ctx.callTool("hyp_session", { action: "join", handle: "claude-v1" });
          }

          if (stage === 1) {
            assert.ok(ctx.hasText("alex@laptop/claude-v1"), `Expected hyp_session join address in context: ${ctx.allText()}`);
            stage = 2;
            return ctx.callTool("hyp_stream", { action: "topics" });
          }

          if (stage === 2) {
            assert.ok(ctx.hasText("github"), `Expected github topic in hyp_stream topics output: ${ctx.allText()}`);
            assert.ok(ctx.hasText("hyphae-to/hyp"), `Expected monitored repo scope in hyp_stream topics output: ${ctx.allText()}`);
            stage = 3;
            // Deliberately subscribe with the wrong GitHub `subject` attribute to trigger dead-subscription reachability lint
            return ctx.callTool("hyp_stream", {
              action: "subscribe",
              key: "gh:bad-subject",
              topic: "github",
              filters: [{ exact: { subject: "hyphae-to/hyp" } }],
              coalesceSeconds: 0,
            });
          }

          if (stage === 3) {
            const text = ctx.allText();
            assert.match(text, /reachable\\?":\s*false/, `Expected reachable: false diagnostic in context: ${text}`);
            assert.ok(
              ctx.hasText("invalid_github_subject_filter") && ctx.hasText("suggestedFilter"),
              `Expected invalid_github_subject_filter + suggestedFilter in context: ${text}`,
            );
            stage = 4;
            // Clean up the dead subscription before creating the corrected strict subscription
            return ctx.callTool("hyp_stream", { action: "unsubscribe", key: "gh:bad-subject" });
          }

          if (stage === 4) {
            assert.match(ctx.allText(), /removed\\?":\s*true/, `Expected dead subscription removal: ${ctx.allText()}`);
            stage = 5;
            // Self-correct using the suggested `repo` attribute with strict: true
            return ctx.callTool("hyp_stream", {
              action: "subscribe",
              key: "gh:hyp-prs",
              topic: "github",
              filters: [{ exact: { repo: "hyphae-to/hyp" } }],
              coalesceSeconds: 0,
              strict: true,
            });
          }

          if (stage === 5) {
            const text = ctx.allText();
            assert.match(text, /reachable\\?":\s*true/, `Expected strict subscription reachable: true in context: ${text}`);
            assert.equal(ctx.hasText("unreachable_subscription"), false, `Unexpected strict failure in context: ${text}`);
            stage = 6;
            return ctx.callTool("hyp_bridge", {
              action: "link",
              plugin: "slack",
              target: "slack-v1",
              handle: "reviewer",
            });
          }

          if (stage === 6) {
            assert.ok(ctx.hasText("reviewer"), `Expected linked reviewer in hyp_bridge_link result: ${ctx.allText()}`);
            stage = 7;

            // Deliver BOTH a signed GitHub PR webhook AND a Slack app_mention!
            const ghDelivery = await deliverGithubWebhookWithRetry({
              receiverUrl: `http://127.0.0.1:${ghPort}`,
              secret: ghSecret,
              event: "pull_request",
              deliveryId: "rv1-claude-pr-77",
              payload: makeGithubPullRequestPayload({
                repo: "hyphae-to/hyp",
                number: 77,
                title: "v1-real-claude-pr-77",
              }),
            });
            assert.equal(ghDelivery.status, 202, `Expected 202 from GitHub receiver, got ${ghDelivery.status}`);

            const envId = mockSlack.pushEvent({
              type: "app_mention",
              channel: "C-V1",
              user: "UOPS1",
              ts: "1700077.0001",
              text: "<@UBOT123> confirm PR 77 status",
            });
            await mockSlack.waitForAck(envId, 5_000);

            await waitFor(
              () => {
                const s = alex.daemon.state.byHandle("claude-v1");
                return s && alex.daemon.state.pendingCount(s.id) >= 2;
              },
              { timeoutMs: 10_000, label: "GitHub PR + Slack app_mention queued in claude-v1 mailbox" },
            );

            // End turn so Claude's Stop hook drains and injects BOTH items into the next turn!
            return ctx.reply("Waiting for events.");
          }

          if (stage === 7 && ctx.hasText("v1-real-claude-pr-77") && ctx.hasText("confirm PR 77 status")) {
            sawGithubEvent = true;
            sawSlackMention = true;
            stage = 8;
            return ctx.callTool("hyp_bridge", {
              action: "post",
              plugin: "slack",
              target: "slack-v1",
              threadTs: "1700077.0001",
              text: "ACK PR #77 from real Claude",
            });
          }

          if (stage === 8) {
            const text = ctx.allText();
            assert.ok(ctx.hasText("C-V1"), `Expected Slack channel C-V1 in hyp_plugin_post result: ${text}`);
            assert.doesNotMatch(text, /plugin_post_failed|not_target_holder/, `hyp_plugin_post failed: ${text}`);
            postedSlackReply = true;
            stage = 9;
            return ctx.reply("Done.");
          }

          return ctx.reply("Done.");
        },
      });

      assert.equal(
        result.code,
        0,
        `claude exited ${result.code}\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}\ntranscript:\n${JSON.stringify(server.transcript, null, 2)}`,
      );
      assert.equal(sawGithubEvent, true, "Real Claude should receive signed GitHub PR webhook via Stop hook");
      assert.equal(sawSlackMention, true, "Real Claude should receive Slack app_mention via Stop hook");
      assert.equal(postedSlackReply, true, "Real Claude should send outbound Slack reply via hyp_plugin_post");

      const claudeSession = alex.daemon.state.byHandle("claude-v1");
      assert.ok(claudeSession, "Expected claude-v1 session enrolled on alex@laptop");
      assert.match(claudeSession.id, /^claude:.+/);

      const posts = await mockSlack.waitForPost(1, 5_000);
      assert.equal(posts.length, 1);
      assert.equal(posts[0].channel, "C-V1");
      assert.equal(posts[0].thread_ts, "1700077.0001");
      assert.equal(posts[0].text, "ACK PR #77 from real Claude");

      // Verify linked peer `antigravity:rev-1` ALSO received the Slack mention via multi-thread bridge fan-in
      const reviewerItems = await waitFor(
        () => {
          const items = alex.daemon.connector.drainMailbox("antigravity:rev-1", 5);
          return items.length > 0 ? items : null;
        },
        { timeoutMs: 6_000, label: "linked reviewer receiving Slack app_mention fan-in" },
      );
      assert.match(reviewerItems.map((i) => i.text).join("\n"), /confirm PR 77 status/);
    } finally {
      await topo.cleanup();
    }
  },
);

test(
  "REAL agy + REAL opencode binaries: live cross-harness multi-thread Telegram bridge collaboration (hyp_bridge_link -> fan-in -> linked hyp_plugin_post)",
  {
    skip:
      BINARIES.agy === null || BINARIES.opencode === null
        ? "requires both agy and opencode CLIs installed locally"
        : false,
    timeout: 90_000,
  },
  async () => {
    const topo = new MeshTopology("hi-rv1-ao-");
    try {
      const botToken = "777010:V1-REAL-AGY-OPENCODE-TG-BOT";
      const mockTg = await startMockTelegramServer(botToken, 80);
      topo.track(() => mockTg.close());

      const teamRouter = await topo.addRouter({ name: "team" });
      const alex = await topo.addConnector({
        connectorId: "alex@laptop",
        links: [{ name: "primary", router: teamRouter }],
        secrets: { "tg-v1-bot": botToken },
        rawPlugins: [
          {
            name: "telegram",
            builtin: "telegram",
            env: {
              TELEGRAM_API_BASE: mockTg.apiBaseUrl,
              TELEGRAM_ALLOWED_CHATS: "77701",
              TELEGRAM_ALLOWED_USERS: "8001",
              TELEGRAM_BOT_TOKEN: { secret: "tg-v1-bot" },
              TELEGRAM_TARGET: "tg-team",
            },
            targets: [
              { name: "tg-team", handle: "agy-lead", coalesceSeconds: 1, maxWaitSeconds: 5, wakesPerHour: 120 },
            ],
          },
        ],
      });

      const cfgRaw = readFileSync(alex.configPath, "utf8");
      assert.equal(cfgRaw.includes(botToken), false, "Telegram bot token must not appear in connector.json");

      await mockTg.waitForPoll(1, 8_000);

      const ocJoined = createDeferred();
      const linkedReady = createDeferred();
      const tgReplied = createDeferred();

      let agyStage = 0;
      let ocStage = 0;
      let agySawTelegram = false;
      let ocSawTelegram = false;

      const agyPromise = runRealAgy({
        baseDir: topo.subDir("agy-v1"),
        socketPath: alex.socketPath,
        timeoutMs: 75_000,
        prompt:
          "Join hyphae as agy-lead, link oc-responder to telegram/tg-team, receive the incoming Telegram message, and coordinate with OpenCode.",
        handler: async (ctx) => {
          if (agyStage === 0) {
            agyStage = 1;
            return ctx.callAgyMcpTool("hyp_session", { action: "join", handle: "agy-lead" }, "hyphae_hyphae");
          }

          if (agyStage === 1) {
            assert.ok(ctx.hasText("alex@laptop/agy-lead"), `Expected agy-lead join address in context: ${ctx.allText()}`);
            await awaitWithTimeout(ocJoined.promise, 30_000, "opencode enrolling as oc-responder");
            agyStage = 2;
            return ctx.callAgyMcpTool(
              "hyp_bridge",
              { action: "link", plugin: "telegram", target: "tg-team", handle: "oc-responder" },
              "hyphae_hyphae",
            );
          }

          if (agyStage === 2) {
            assert.ok(ctx.hasText("oc-responder"), `Expected oc-responder in hyp_bridge_link result: ${ctx.allText()}`);
            linkedReady.resolve();

            mockTg.pushUpdate({
              update_id: 901,
              message: {
                message_id: 99,
                chat: { id: 77701, type: "private" },
                from: { id: 8001, username: "boss" },
                text: "DEPLOY_CHECK_99",
              },
            });

            await waitFor(
              () => {
                const s = alex.daemon.state.byHandle("agy-lead");
                return s && alex.daemon.state.pendingCount(s.id) >= 1;
              },
              { timeoutMs: 10_000, label: "Telegram update queued in agy-lead mailbox" },
            );

            agyStage = 3;
            // Call hyp_session peers so Antigravity's PreInvocation/Stop hooks push the queued Telegram update into agy's turn
            return ctx.callAgyMcpTool("hyp_session", { action: "peers" }, "hyphae_hyphae");
          }

          if (agyStage === 3) {
            if (ctx.hasText("DEPLOY_CHECK_99")) {
              agySawTelegram = true;
              agyStage = 4;
              await awaitWithTimeout(tgReplied.promise, 30_000, "opencode posting Telegram reply");
              return ctx.reply("Agy saw Telegram message and coordinated with OpenCode.");
            }
            // If PreInvocation did not drain between tool turns, ending the turn invokes Stop hook to inject DEPLOY_CHECK_99
            return ctx.reply("Standing by for Telegram event delivery.");
          }

          return ctx.reply("Agy saw Telegram message and coordinated with OpenCode.");
        },
      }).then(
        (res) => {
          linkedReady.reject(new Error(`agy exited (code=${res.result.code}) before linking oc-responder`));
          return res;
        },
        (err) => {
          linkedReady.reject(err instanceof Error ? err : new Error(String(err)));
          throw err;
        },
      );

      const ocPromise = runRealOpenCode({
        baseDir: topo.subDir("oc-v1"),
        socketPath: alex.socketPath,
        timeoutMs: 75_000,
        prompt:
          "Join hyphae as oc-responder, receive the fanned-in Telegram message on tg-team, and reply to Telegram via hyp_plugin_post.",
        handler: async (ctx) => {
          if (ocStage === 0) {
            ocStage = 1;
            return ctx.callOpenCodeTool("hyp_session", { action: "join", handle: "oc-responder" });
          }

          if (ocStage === 1) {
            assert.ok(ctx.hasText("alex@laptop/oc-responder"), `Expected oc-responder join address in context: ${ctx.allText()}`);
            ocJoined.resolve();
            await awaitWithTimeout(linkedReady.promise, 30_000, "agy linking oc-responder to telegram/tg-team");

            await waitFor(
              () => {
                const s = alex.daemon.state.byHandle("oc-responder");
                return s && alex.daemon.state.pendingCount(s.id) >= 1;
              },
              { timeoutMs: 15_000, label: "Telegram fan-in queued in oc-responder mailbox" },
            );

            ocStage = 2;
            // OpenCode's v2 `execute.after` hook drains and injects the fanned-in Telegram message into the next turn!
            return ctx.callOpenCodeTool("hyp_session", { action: "peers" });
          }

          if (ocStage === 2) {
            assert.ok(ctx.hasText("DEPLOY_CHECK_99"), `Expected DEPLOY_CHECK_99 pushed into OpenCode context: ${ctx.allText()}`);
            ocSawTelegram = true;
            ocStage = 3;
            return ctx.callOpenCodeTool("hyp_bridge", {
              action: "post",
              plugin: "telegram",
              target: "tg-team",
              replyTo: "99",
              text: "DEPLOY_OK_FROM_OPENCODE",
            });
          }

          if (ocStage === 3) {
            const text = ctx.allText();
            assert.ok(ctx.hasText("77701"), `Expected Telegram chatId 77701 in hyp_plugin_post result: ${text}`);
            assert.doesNotMatch(text, /plugin_post_failed|not_target_holder/, `hyp_plugin_post failed: ${text}`);
            tgReplied.resolve();
            ocStage = 4;
            return ctx.reply("OpenCode replied to Telegram.");
          }

          return ctx.reply("OpenCode replied to Telegram.");
        },
      }).then(
        (res) => {
          ocJoined.reject(new Error(`opencode exited (code=${res.result.code}) before joining`));
          tgReplied.reject(new Error(`opencode exited (code=${res.result.code}) before posting Telegram reply`));
          return res;
        },
        (err) => {
          const error = err instanceof Error ? err : new Error(String(err));
          ocJoined.reject(error);
          tgReplied.reject(error);
          throw err;
        },
      );

      const [agyRes, ocRes] = await Promise.all([agyPromise, ocPromise]);

      assert.equal(
        agyRes.result.code,
        0,
        `agy exited ${agyRes.result.code}\nstdout:\n${agyRes.result.stdout}\nstderr:\n${agyRes.result.stderr}\ntranscript:\n${JSON.stringify(agyRes.server.transcript, null, 2)}`,
      );
      assert.equal(
        ocRes.result.code,
        0,
        `opencode exited ${ocRes.result.code}\nstdout:\n${ocRes.result.stdout}\nstderr:\n${ocRes.result.stderr}\ntranscript:\n${JSON.stringify(ocRes.server.transcript, null, 2)}`,
      );
      assert.equal(agySawTelegram, true, "Real agy should receive inbound Telegram message");
      assert.equal(ocSawTelegram, true, "Real OpenCode should receive fanned-in Telegram message via execute.after");

      const agySession = alex.daemon.state.byHandle("agy-lead");
      const ocSession = alex.daemon.state.byHandle("oc-responder");
      assert.ok(agySession && /^antigravity:[0-9a-f-]+$/i.test(agySession.id), `Unexpected agy session: ${agySession?.id}`);
      assert.ok(ocSession && /^opencode:ses_.+/.test(ocSession.id), `Unexpected opencode session: ${ocSession?.id}`);

      const sent = await mockTg.waitForSent(1, 5_000);
      assert.equal(sent.length, 1);
      assert.equal(sent[0].chat_id, "77701");
      assert.equal(sent[0].text, "DEPLOY_OK_FROM_OPENCODE");
      assert.equal(sent[0].reply_to_message_id, 99);
    } finally {
      await topo.cleanup();
    }
  },
);
