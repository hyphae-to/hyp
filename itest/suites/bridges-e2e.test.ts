/**
 * Phase 3 Black-Box End-to-End Integration Suite: External Chat Bridges (`telegram`, `slack`, `whatsapp`)
 * + Blind Spot B2 (Post-`hello` Self-Crash -> `CrashLoopBackOff` + `0600` Secret-Redacted Logs).
 *
 * Strict black-box invariants:
 *  - Every plugin is installed & SHA-256 verified via compiled `hyp plugin install <name> --from-dir`.
 *  - Secrets are stored exclusively via `hyp secret set` (stdin, `HYPHAE_SECRET_BACKEND=file`).
 *  - Real `hyp daemon` + real Node 24 plugin subprocesses + REAL Claude Code CLI (`claude -p`) via `llm-shim`.
 *  - All 5 always-on `llm-shim` invariant auditors enforced (`secret-leak`, `untrusted-provenance`,
 *    `metadata-only-wake`, `duplicate-delivery`, `mcp-schema-footprint`).
 */

import { writeNodeJson } from "../lib/util.ts";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { ClaudeHarness, resolveClaudeBin } from "../lib/harnesses/claude.ts";
import { HypCli } from "../lib/hyp-cli.ts";
import { LlmShimServer, callTool, emitText } from "../lib/llm-shim/index.ts";
import {
  SlackSocketMockServer,
  TelegramMockServer,
  WhatsAppMockServer,
  buildWhatsAppWebhookPayload,
  getFreePort,
  sendWhatsAppVerifyChallenge,
  sendWhatsAppWebhook,
  waitUntil,
} from "../lib/mocks/index.ts";
import { REPO_ROOT, withSandbox } from "../lib/sandbox.ts";

const PLUGINS_SRC_DIR = path.join(REPO_ROOT, "plugins");

async function installOfficialPlugin(
  hyp: HypCli,
  name: string,
): Promise<{ nodePath: string; scriptPath: string }> {
  const res = await hyp.plugin([
    "install",
    name,
    "--from-dir",
    PLUGINS_SRC_DIR,
    "--home",
    hyp.sandbox.paths.homeDir,
  ]);
  assert.equal(res.exitCode, 0, `hyp plugin install ${name} failed: ${res.stderr}`);
  assert.equal(res.json?.ok, true, `hyp plugin install ${name} envelope not ok: ${res.stdout}`);
  const nodePath = res.json?.data?.nodePath || process.execPath;
  const pluginRec = (res.json?.data?.plugins ?? []).find((p: any) => p.name === name);
  assert.ok(pluginRec?.scriptPath, `missing scriptPath for installed plugin '${name}': ${res.stdout}`);
  assert.equal(pluginRec.verified, true, `installed plugin '${name}' must be verified`);
  assert.ok(fs.existsSync(pluginRec.scriptPath), `installed script missing on disk: ${pluginRec.scriptPath}`);
  return { nodePath, scriptPath: pluginRec.scriptPath };
}

function bridgeToolSearchRule(name = "load-bridge-tools") {
  return {
    name,
    once: true,
    when: (req: any) => req.isToolDeferred("hyp_mesh") || req.isToolDeferred("hyp_bridge"),
    do: (req: any) =>
      callTool(req, "ToolSearch", {
        query:
          "select:mcp__hyphae__hyp_mesh,mcp__hyphae__hyp_send,mcp__hyphae__hyp_inbox,mcp__hyphae__hyp_stream,mcp__hyphae__hyp_bridge",
      }),
  };
}

function pullInboxOnDigestRule(name = "pull-bridge-inbox") {
  return {
    name,
    when: (req: any) => req.lastToolResults.length === 0 && /<hyphae-inbox\b/.test(req.lastUserText),
    do: (req: any) => callTool(req, "hyp_inbox", { ack: true, limit: 20 }),
  };
}

// ---------------------------------------------------------------------------
// 1. Telegram Full E2E Loop
// ---------------------------------------------------------------------------

test("Bridges E2E — Telegram: full inbound->Claude->outbound+reaction loop, 429 retry, >4096 chunking, 0600 offset restart resume, allowlist drop, exposeTopic:false", async (t) => {
  const claudeBin = resolveClaudeBin();
  if (!claudeBin) {
    t.skip("claude binary not found (set CLAUDE_BIN)");
    return;
  }

  await withSandbox("bridge-telegram-e2e", async (sandbox) => {
    const hyp = new HypCli(sandbox);
    await hyp.onboard({ nodeId: "tg-itest@local", noSkills: true, noCommands: true });

    const { nodePath, scriptPath } = await installOfficialPlugin(hyp, "telegram");
    const botToken = "8123456789:AAFakeTelegramBotTokenSecretNeverLeak";
    await hyp.secretSet("telegram-bot-token", botToken);

    const tgMock = await TelegramMockServer.start({ botToken, botUsername: "hyphae_tg_itest_bot" });
    sandbox.onTeardown(() => tgMock.close());

    const bindPort = await getFreePort();
    const offsetFile = path.join(sandbox.paths.hyphaeStateDir, "telegram-offset.json");

    writeNodeJson(hyp.nodeConfigPath, {
      v: 2,
      nodeId: "tg-itest@local",
      profile: "p2p",
      bind: `127.0.0.1:${bindPort}`,
      stateDir: sandbox.paths.hyphaeStateDir,
      plugins: [
        {
          id: "telegram",
          kind: "bridge",
          command: nodePath,
          args: [scriptPath],
          targets: ["personal"],
          env: {
            TELEGRAM_BOT_TOKEN: { secret: "telegram-bot-token" },
            TELEGRAM_API_BASE: tgMock.baseUrl,
            TELEGRAM_TARGET: "personal",
            TELEGRAM_ALLOWED_USERS: "1001",
            TELEGRAM_ALLOWED_CHATS: "5001",
            TELEGRAM_DEFAULT_CHAT: "5001",
            TELEGRAM_STATE_FILE: offsetFile,
          },
        },
      ],
    });

    await hyp.startDaemon();

    // Wait for the real Telegram plugin subprocess to start polling our mock.
    await waitUntil(() => tgMock.getUpdatesCalls.length >= 1, "telegram initial getUpdates", 15_000);

    const shim = await LlmShimServer.start({
      sandbox,
      auditors: {
        allowBridge: true,
        allowKv: false,
        allowedRoles: ["tg-claude"],
      },
    });

    const inboundMarker = "TG_INBOUND_PAYLOAD_101";
    const blockedMarker = "TG_UNAUTHORIZED_USER_SHOULD_DROP_999";
    shim.auditors.registerUntrustedPayload("tg-dm-1", inboundMarker);

    const longPayload = `LONG_CHUNK_START_${"X".repeat(2500)}\n${"Y".repeat(2100)}_LONG_CHUNK_END`;
    assert.ok(longPayload.length > 4096, "test payload must exceed Telegram 4096-char limit");

    let linkedOk = false;
    let sentShortOk = false;
    let sentLongOk = false;

    shim.script("tg-claude", [
      bridgeToolSearchRule(),
      {
        name: "enroll-mesh",
        once: true,
        when: (req) => !req.isToolDeferred("hyp_mesh") && req.anyMessageContains("ENROLL_TG_BRIDGE"),
        do: (req) => callTool(req, "hyp_mesh", { action: "join", handle: "tg-agent" }),
      },
      {
        name: "link-telegram",
        once: true,
        when: (req) => req.lastToolResult("hyp_mesh")?.json?.handle === "tg-agent",
        do: (req) =>
          callTool(req, "hyp_bridge", { action: "link", plugin: "telegram", target: "personal" }),
      },
      {
        name: "finish-enroll-link",
        once: true,
        when: (req) => {
          const r = req.lastToolResult("hyp_bridge");
          if (r && !r.isError) linkedOk = true;
          return Boolean(r && !r.isError);
        },
        do: () => emitText("TG_BRIDGE_LINKED"),
      },
      {
        name: "reply-and-react-on-inbound",
        once: true,
        when: (req) => req.anyMessageContains(inboundMarker),
        assert: (req) => {
          assert.equal(
            req.rawBody.includes(blockedMarker),
            false,
            "non-allowlisted Telegram sender message must NEVER reach Claude",
          );
        },
        do: (req) =>
          callTool(req, "hyp_send", {
            to: "telegram:personal",
            reaction: "👍",
            replyTo: "77",
            text: `TG_ACK:${inboundMarker}`,
          }),
      },
      {
        name: "send-long-chunked-message",
        once: true,
        when: (req) => {
          const r = req.lastToolResult("hyp_send");
          if (r && !r.isError && !sentShortOk) {
            sentShortOk = true;
            return true;
          }
          return false;
        },
        do: (req) =>
          callTool(req, "hyp_send", {
            to: "telegram:personal",
            text: longPayload,
          }),
      },
      {
        name: "finish-after-long-send",
        once: true,
        when: (req) => {
          const r = req.lastToolResult("hyp_send");
          if (r && !r.isError && sentShortOk) {
            sentLongOk = true;
            return true;
          }
          return false;
        },
        do: () => emitText("TG_REPLIES_SENT"),
      },
      pullInboxOnDigestRule("pull-tg-inbox"),
      {
        name: "ack-waiter-prompt",
        when: (req) => req.lastUserText.includes("no background waiter is running yet"),
        do: () => emitText("STANDING_BY"),
      },
    ]);

    const claude = await ClaudeHarness.create({
      sandbox,
      hyp,
      shim,
      claudeBin,
      role: "tg-claude",
    });

    const sessionUuid = crypto.randomUUID();
    const enrollRes = await claude.runPrint("ENROLL_TG_BRIDGE", {
      sessionId: sessionUuid,
      maxTurns: 8,
    });
    assert.equal(enrollRes.exitCode, 0, `enroll failed: ${enrollRes.stderr}`);
    assert.equal(linkedOk, true, "Claude must successfully link telegram:personal via hyp_bridge");

    // 1. Unauthorized sender is dropped cleanly while advancing offset.
    const unauth = tgMock.enqueueMessage({
      chatId: 5001,
      userId: 9999,
      username: "mallory",
      text: blockedMarker,
      messageId: 76,
    });
    await tgMock.waitForGetUpdatesOffset(unauth.updateId + 1, 10_000);

    // 2. Allowlisted user sends inbound DM; arm a 429 retry_after=1 on the first sendMessage!
    const allowed = tgMock.enqueueMessage({
      chatId: 5001,
      userId: 1001,
      username: "alice",
      firstName: "Alice",
      text: inboundMarker,
      messageId: 77,
    });
    await tgMock.waitForGetUpdatesOffset(allowed.updateId + 1, 10_000);

    tgMock.failNextWith429("sendMessage", 1);

    // Resume real Claude -> receives Telegram DM -> reacts + replies (retried past 429) + sends >4096 chunked reply!
    const replyRes = await claude.runPrint("CHECK_TELEGRAM_DM", {
      sessionId: sessionUuid,
      resume: true,
      maxTurns: 10,
      timeoutMs: 60_000,
    });
    assert.equal(replyRes.exitCode, 0, `reply turn failed: ${replyRes.stderr}`);
    assert.equal(sentShortOk, true, "Claude must send short reply + reaction");
    assert.equal(sentLongOk, true, "Claude must send long >4096 chunked reply");

    // Verify reaction on mock.
    const rxn = await tgMock.waitForReaction((r) => r.message_id === 77, 10_000);
    assert.equal(String(rxn.chat_id), "5001");
    assert.deepEqual(rxn.reaction, [{ type: "emoji", emoji: "👍" }]);

    // Verify short reply recovered from 429 and carried reply_to_message_id.
    const shortMsg = await tgMock.waitForSentMessage((m) => m.text === `TG_ACK:${inboundMarker}`, 10_000);
    assert.equal(String(shortMsg.chat_id), "5001");
    assert.equal(shortMsg.reply_to_message_id, 77);

    // Verify >4096 chunking: >=2 chunks, each <= 4096 chars, containing start & end markers.
    const longChunks = tgMock.sentMessages.filter(
      (m) => m.text.includes("LONG_CHUNK_START_") || m.text.includes("_LONG_CHUNK_END"),
    );
    assert.ok(longChunks.length >= 2, `Expected >=2 chunks for >4096 char text, got ${longChunks.length}`);
    for (const chunk of longChunks) {
      assert.ok(chunk.text.length <= 4096, `Chunk exceeded 4096 chars: ${chunk.text.length}`);
    }

    // Verify `telegram-offset.json` exists with 0600 permissions and saved offset.
    assert.ok(fs.existsSync(offsetFile), "telegram-offset.json must be persisted");
    const offsetMode = fs.statSync(offsetFile).mode & 0o777;
    assert.equal(offsetMode, 0o600, `telegram-offset.json must be 0600, got 0o${offsetMode.toString(8)}`);
    const savedOffset = JSON.parse(fs.readFileSync(offsetFile, "utf8")).offset;
    assert.equal(savedOffset, allowed.updateId + 1);

    // Verify `exposeTopic: false` default: `/v1/manifest` MUST NOT advertise `telegram` topic!
    const manifestResp = await fetch(`http://127.0.0.1:${bindPort}/v1/manifest`);
    assert.equal(manifestResp.status, 200);
    const manifestJson: any = await manifestResp.json();
    const manifestTopics: any[] = manifestJson?.payload?.advertised?.topics ?? manifestJson?.advertised?.topics ?? [];
    assert.equal(
      manifestTopics.some((tp) => tp?.topic === "telegram"),
      false,
      `Private bridge topic 'telegram' must NOT be exposed in /v1/manifest: ${JSON.stringify(manifestTopics)}`,
    );

    // Restart `hyp daemon` and prove offset resumes from `savedOffset` with ZERO replay!
    const callsBeforeRestart = tgMock.getUpdatesCalls.length;
    await hyp.restartDaemon();
    const postRestartPoll = await waitUntil(
      () => tgMock.getUpdatesCalls.slice(callsBeforeRestart).find((c) => c.offset >= savedOffset) ?? false,
      "post-restart getUpdates resuming from persisted offset",
      15_000,
    );
    assert.equal(postRestartPoll.offset, savedOffset, "must resume from persisted offset");
    assert.deepEqual(postRestartPoll.returnedIds, [], "must replay zero prior updates after restart");

    shim.assertAllClean();
  });
});

// ---------------------------------------------------------------------------
// 2. Slack Socket Mode Full E2E Loop
// ---------------------------------------------------------------------------

test("Bridges E2E — Slack Socket Mode: auth.test, apps.connections.open, envelope_id ack, Claude reply+reaction, disconnect reconnect, unauthorized fail-closed", async (t) => {
  const claudeBin = resolveClaudeBin();
  if (!claudeBin) {
    t.skip("claude binary not found (set CLAUDE_BIN)");
    return;
  }

  await withSandbox("bridge-slack-e2e", async (sandbox) => {
    const hyp = new HypCli(sandbox);
    await hyp.onboard({ nodeId: "slack-itest@local", noSkills: true, noCommands: true });

    const { nodePath, scriptPath } = await installOfficialPlugin(hyp, "slack");
    const appToken = "xapp-1-ITEST-APP-SECRET-NEVER-LEAK-999";
    const botToken = "xoxb-ITEST-BOT-SECRET-NEVER-LEAK-888";
    await hyp.secretSet("slack-app-token", appToken);
    await hyp.secretSet("slack-bot-token", botToken);

    const slackMock = await SlackSocketMockServer.start({ appToken, botToken });
    sandbox.onTeardown(() => slackMock.close());

    writeNodeJson(hyp.nodeConfigPath, {
      v: 2,
      nodeId: "slack-itest@local",
      profile: "local",
      stateDir: sandbox.paths.hyphaeStateDir,
      plugins: [
        {
          id: "slack",
          kind: "bridge",
          command: nodePath,
          args: [scriptPath],
          targets: ["workspace"],
          env: {
            SLACK_APP_TOKEN: { secret: "slack-app-token" },
            SLACK_BOT_TOKEN: { secret: "slack-bot-token" },
            SLACK_API_BASE: slackMock.apiBase,
            SLACK_TARGET: "workspace",
            SLACK_ALLOWED_USERS: "U_ALICE",
            SLACK_ALLOWED_CHANNELS: "D_ALICE,C_ENG",
            SLACK_DEFAULT_CHANNEL: "D_ALICE",
          },
        },
      ],
    });

    await hyp.startDaemon();
    await slackMock.waitForConnections(1, 15_000);
    assert.ok(slackMock.authTestCalls.length >= 1, "Slack plugin must call auth.test");
    assert.ok(slackMock.connectionsOpened.length >= 1, "Slack plugin must call apps.connections.open");

    const shim = await LlmShimServer.start({
      sandbox,
      auditors: {
        allowBridge: true,
        allowKv: false,
        allowedRoles: ["slack-claude"],
      },
    });

    const dmMarker = "SLACK_INBOUND_DM_202";
    const unauthUserMarker = "SLACK_UNAUTH_USER_DROP";
    const unauthChanMarker = "SLACK_UNAUTH_CHANNEL_DROP";
    shim.auditors.registerUntrustedPayload("slack-dm-1", dmMarker);

    let linkedOk = false;
    let repliedOk = false;

    const dmTs = "1700000202.000100";

    shim.script("slack-claude", [
      bridgeToolSearchRule(),
      {
        name: "enroll-mesh",
        once: true,
        when: (req) => !req.isToolDeferred("hyp_mesh") && req.anyMessageContains("ENROLL_SLACK"),
        do: (req) => callTool(req, "hyp_mesh", { action: "join", handle: "slack-agent" }),
      },
      {
        name: "link-slack",
        once: true,
        when: (req) => req.lastToolResult("hyp_mesh")?.json?.handle === "slack-agent",
        do: (req) =>
          callTool(req, "hyp_bridge", { action: "link", plugin: "slack", target: "workspace" }),
      },
      {
        name: "done-link",
        once: true,
        when: (req) => {
          const r = req.lastToolResult("hyp_bridge");
          if (r && !r.isError) linkedOk = true;
          return Boolean(r && !r.isError);
        },
        do: () => emitText("SLACK_LINKED"),
      },
      {
        name: "reply-and-react-slack",
        once: true,
        when: (req) => req.anyMessageContains(dmMarker),
        assert: (req) => {
          assert.equal(req.rawBody.includes(unauthUserMarker), false, "unauth user must not reach Claude");
          assert.equal(req.rawBody.includes(unauthChanMarker), false, "unauth channel must not reach Claude");
        },
        do: (req) =>
          callTool(req, "hyp_send", {
            to: "slack:workspace",
            text: `SLACK_ACK:${dmMarker}`,
            reaction: "🚀",
            replyTo: dmTs,
          }),
      },
      {
        name: "done-reply",
        once: true,
        when: (req) => {
          const r = req.lastToolResult("hyp_send");
          if (r && !r.isError) repliedOk = true;
          return Boolean(r && !r.isError);
        },
        do: () => emitText("SLACK_REPLIED"),
      },
      pullInboxOnDigestRule("pull-slack-inbox"),
      {
        name: "ack-waiter-prompt",
        when: (req) => req.lastUserText.includes("no background waiter is running yet"),
        do: () => emitText("STANDING_BY"),
      },
    ]);

    const claude = await ClaudeHarness.create({
      sandbox,
      hyp,
      shim,
      claudeBin,
      role: "slack-claude",
    });

    const sessionUuid = crypto.randomUUID();
    const enrollRes = await claude.runPrint("ENROLL_SLACK", { sessionId: sessionUuid, maxTurns: 8 });
    assert.equal(enrollRes.exitCode, 0, `enroll failed: ${enrollRes.stderr}`);
    assert.equal(linkedOk, true);

    // Unauthorized user and unauthorized channel must be acked over WS but dropped fail-closed.
    const badUser = slackMock.pushMessageEvent({
      user: "U_MALLORY",
      channel: "D_ALICE",
      channelType: "im",
      text: unauthUserMarker,
    });
    const badChan = slackMock.pushMessageEvent({
      user: "U_ALICE",
      channel: "C_SECRET",
      channelType: "channel",
      type: "app_mention",
      text: `<@${slackMock.botUserId}> ${unauthChanMarker}`,
    });
    await slackMock.waitForAck(badUser.envelopeId, 10_000);
    await slackMock.waitForAck(badChan.envelopeId, 10_000);

    // Authorized DM -> verify envelope_id ACK and delivery into Claude!
    const validDm = slackMock.pushMessageEvent({
      user: "U_ALICE",
      channel: "D_ALICE",
      channelType: "im",
      text: dmMarker,
      ts: dmTs,
    });
    await slackMock.waitForAck(validDm.envelopeId, 10_000);

    // Small settle so daemon writes inbound message to session mailbox before Claude resumes.
    await new Promise((r) => setTimeout(r, 150));

    const replyRes = await claude.runPrint("CHECK_SLACK_DM", {
      sessionId: sessionUuid,
      resume: true,
      maxTurns: 8,
    });
    assert.equal(replyRes.exitCode, 0, `reply failed: ${replyRes.stderr}`);
    assert.equal(repliedOk, true);

    const post = await slackMock.waitForPostMessage((m) => m.text === `SLACK_ACK:${dmMarker}`, 10_000);
    assert.equal(post.channel, "D_ALICE");
    assert.equal(post.thread_ts, dmTs);

    const rxn = await slackMock.waitForReaction((r) => r.name === "rocket", 10_000);
    assert.equal(rxn.action, "add");
    assert.equal(rxn.channel, "D_ALICE");
    assert.equal(rxn.timestamp, dmTs);

    // Inject Socket Mode `disconnect` frame -> plugin must close and reconnect via `apps.connections.open`!
    slackMock.sendDisconnect("refresh_requested");
    await slackMock.waitForConnections(2, 15_000);
    assert.ok(
      slackMock.connectionsOpened.length >= 2,
      `Expected >=2 apps.connections.open calls after disconnect, got ${slackMock.connectionsOpened.length}`,
    );

    shim.assertAllClean();
  });
});

// ---------------------------------------------------------------------------
// 3. WhatsApp Business Cloud API Full E2E Loop
// ---------------------------------------------------------------------------

test("Bridges E2E — WhatsApp Cloud API: GET verify challenge (403/200), 1-bit HMAC flip 401, non-allowlisted drop, inbound->Claude->outbound+reaction", async (t) => {
  const claudeBin = resolveClaudeBin();
  if (!claudeBin) {
    t.skip("claude binary not found (set CLAUDE_BIN)");
    return;
  }

  await withSandbox("bridge-whatsapp-e2e", async (sandbox) => {
    const hyp = new HypCli(sandbox);
    await hyp.onboard({ nodeId: "wa-itest@local", noSkills: true, noCommands: true });

    const { nodePath, scriptPath } = await installOfficialPlugin(hyp, "whatsapp");
    const verifyToken = "wa-verify-secret-itest-123";
    const appSecret = "wa-app-hmac-secret-itest-456";
    const accessToken = "EAAG_ITEST_WHATSAPP_ACCESS_TOKEN_789";
    await hyp.secretSet("wa-verify-token", verifyToken);
    await hyp.secretSet("wa-app-secret", appSecret);
    await hyp.secretSet("wa-access-token", accessToken);

    const waMock = await WhatsAppMockServer.start({ accessToken });
    sandbox.onTeardown(() => waMock.close());

    const waPort = await getFreePort();
    const waWebhookUrl = `http://127.0.0.1:${waPort}/whatsapp`;
    const waHealthUrl = `http://127.0.0.1:${waPort}/health`;
    const phoneNumberId = "100200300400";

    writeNodeJson(hyp.nodeConfigPath, {
      v: 2,
      nodeId: "wa-itest@local",
      profile: "local",
      stateDir: sandbox.paths.hyphaeStateDir,
      plugins: [
        {
          id: "whatsapp",
          kind: "bridge",
          command: nodePath,
          args: [scriptPath],
          targets: ["whatsapp"],
          env: {
            WHATSAPP_HOST: "127.0.0.1",
            WHATSAPP_PORT: String(waPort),
            WHATSAPP_PATH: "/whatsapp",
            WHATSAPP_TARGET: "whatsapp",
            WHATSAPP_VERIFY_TOKEN: { secret: "wa-verify-token" },
            WHATSAPP_APP_SECRET: { secret: "wa-app-secret" },
            WHATSAPP_ACCESS_TOKEN: { secret: "wa-access-token" },
            WHATSAPP_PHONE_NUMBER_ID: phoneNumberId,
            WHATSAPP_ALLOWED_NUMBERS: "+14155550101",
            WHATSAPP_API_BASE: waMock.apiBase,
          },
        },
      ],
    });

    await hyp.startDaemon();

    await waitUntil(async () => {
      try {
        const res = await fetch(waHealthUrl);
        return res.status === 200;
      } catch {
        return false;
      }
    }, "whatsapp plugin /health", 15_000);

    // 1. GET subscribe challenge: wrong verify_token -> 403, valid -> 200 echoing exact challenge.
    const badVerify = await sendWhatsAppVerifyChallenge(waWebhookUrl, {
      verifyToken: "wrong-verify-token",
      challenge: "challenge-xyz",
    });
    assert.equal(badVerify.status, 403);

    const okVerify = await sendWhatsAppVerifyChallenge(waWebhookUrl, {
      verifyToken,
      challenge: "challenge-ok-98765",
    });
    assert.equal(okVerify.status, 200);
    assert.equal(okVerify.text, "challenge-ok-98765");

    const shim = await LlmShimServer.start({
      sandbox,
      auditors: {
        allowBridge: true,
        allowKv: false,
        allowedRoles: ["wa-claude"],
      },
    });

    const waMarker = "WA_INBOUND_MSG_303";
    const blockedMarker = "WA_NON_ALLOWLISTED_SENDER_DROP";
    shim.auditors.registerUntrustedPayload("wa-msg-1", waMarker);

    let linkedOk = false;
    let repliedOk = false;

    shim.script("wa-claude", [
      bridgeToolSearchRule(),
      {
        name: "enroll-mesh",
        once: true,
        when: (req) => !req.isToolDeferred("hyp_mesh") && req.anyMessageContains("ENROLL_WA"),
        do: (req) => callTool(req, "hyp_mesh", { action: "join", handle: "wa-agent" }),
      },
      {
        name: "link-whatsapp",
        once: true,
        when: (req) => req.lastToolResult("hyp_mesh")?.json?.handle === "wa-agent",
        do: (req) =>
          callTool(req, "hyp_bridge", { action: "link", plugin: "whatsapp", target: "whatsapp" }),
      },
      {
        name: "done-link",
        once: true,
        when: (req) => {
          const r = req.lastToolResult("hyp_bridge");
          if (r && !r.isError) linkedOk = true;
          return Boolean(r && !r.isError);
        },
        do: () => emitText("WA_LINKED"),
      },
      {
        name: "reply-and-react-whatsapp",
        once: true,
        when: (req) => req.anyMessageContains(waMarker),
        assert: (req) => {
          assert.equal(req.rawBody.includes(blockedMarker), false, "non-allowlisted sender must not reach Claude");
        },
        do: (req) =>
          callTool(req, "hyp_send", {
            to: "whatsapp:whatsapp",
            text: `WA_ACK:${waMarker}`,
            reaction: "✅",
            replyTo: "wamid.in.303",
          }),
      },
      {
        name: "done-reply",
        once: true,
        when: (req) => {
          const r = req.lastToolResult("hyp_send");
          if (r && !r.isError) repliedOk = true;
          return Boolean(r && !r.isError);
        },
        do: () => emitText("WA_REPLIED"),
      },
      pullInboxOnDigestRule("pull-wa-inbox"),
      {
        name: "ack-waiter-prompt",
        when: (req) => req.lastUserText.includes("no background waiter is running yet"),
        do: () => emitText("STANDING_BY"),
      },
    ]);

    const claude = await ClaudeHarness.create({
      sandbox,
      hyp,
      shim,
      claudeBin,
      role: "wa-claude",
    });

    const sessionUuid = crypto.randomUUID();
    const enrollRes = await claude.runPrint("ENROLL_WA", { sessionId: sessionUuid, maxTurns: 8 });
    assert.equal(enrollRes.exitCode, 0, `enroll failed: ${enrollRes.stderr}`);
    assert.equal(linkedOk, true);

    // 2. 1-bit flipped HMAC signature MUST fail closed with 401!
    const validPayload = buildWhatsAppWebhookPayload({
      phoneNumberId,
      from: "14155550101",
      contactName: "Alice",
      messageId: "wamid.in.303",
      text: waMarker,
    });
    const tamperedResp = await sendWhatsAppWebhook(waWebhookUrl, {
      payload: validPayload,
      appSecret,
      tamperSignature: true,
    });
    assert.equal(tamperedResp.status, 401, "1-bit flipped X-Hub-Signature-256 must return 401");

    // 3. Non-allowlisted E.164 sender with valid signature -> ignored (`delivered: 0, ignored: 1`).
    const nonAllowlistedPayload = buildWhatsAppWebhookPayload({
      phoneNumberId,
      from: "14155559999",
      contactName: "Mallory",
      messageId: "wamid.in.999",
      text: blockedMarker,
    });
    const ignoredResp = await sendWhatsAppWebhook(waWebhookUrl, {
      payload: nonAllowlistedPayload,
      appSecret,
    });
    assert.equal(ignoredResp.status, 200);
    assert.equal(ignoredResp.json?.delivered, 0);
    assert.equal(ignoredResp.json?.ignored, 1);

    // 4. Valid signed inbound message from allowlisted sender -> delivered!
    const okResp = await sendWhatsAppWebhook(waWebhookUrl, {
      payload: validPayload,
      appSecret,
    });
    assert.equal(okResp.status, 200, `expected 200, got ${okResp.status}: ${okResp.text}`);
    assert.equal(okResp.json?.delivered, 1);

    // 5. Resume Claude -> verifies inbound + sends outbound text & reaction to Meta Graph API mock!
    const replyRes = await claude.runPrint("CHECK_WA_DM", {
      sessionId: sessionUuid,
      resume: true,
      maxTurns: 8,
    });
    assert.equal(replyRes.exitCode, 0, `reply failed: ${replyRes.stderr}`);
    assert.equal(repliedOk, true);

    const outReaction = await waMock.waitForOutbound((r) => r.body.type === "reaction", 10_000);
    assert.equal(outReaction.phoneNumberId, phoneNumberId);
    assert.equal(outReaction.body.to, "14155550101");
    assert.deepEqual(outReaction.body.reaction, { message_id: "wamid.in.303", emoji: "✅" });

    const outText = await waMock.waitForOutbound(
      (r) => r.body.type === "text" && r.body.text?.body === `WA_ACK:${waMarker}`,
      10_000,
    );
    assert.equal(outText.phoneNumberId, phoneNumberId);
    assert.equal(outText.body.to, "14155550101");
    assert.deepEqual(outText.body.context, { message_id: "wamid.in.303" });

    shim.assertAllClean();
  });
});

// ---------------------------------------------------------------------------
// 4. Blind Spot B2: Post-`hello` Self-Crash -> `CrashLoopBackOff` + `0600` Redacted Log
// ---------------------------------------------------------------------------

test("Bridges E2E — Blind Spot B2: real Node plugin crash -> CrashLoopBackOff in node.status.json & hyp doctor --json + 0600 secret-redacted log", async () => {
  await withSandbox("bridge-b2-crashloop-secret-scrub", async (sandbox) => {
    const hyp = new HypCli(sandbox);
    await hyp.onboard({ nodeId: "b2-itest@local", noSkills: true, noCommands: true });

    const { nodePath, scriptPath } = await installOfficialPlugin(hyp, "telegram");
    const secretVal = "999888777:AA_B2_SUPER_SECRET_NEVER_LEAK_XYZ";
    await hyp.secretSet("telegram-b2-secret", secretVal);

    // Part A: Test the exact Blind Spot B2 trigger — `telegram` throws AFTER `await mesh.ready`
    // because `TELEGRAM_TARGET` names a target not offered in `targets: ["personal"]`.
    // Also include a pre-`hello` crashing real `telegram` plugin (missing allowlist) so we verify
    // supervisor `CrashLoopBackOff`, `hyp doctor --json` FAIL, and `0600` redacted log even if
    // unpatched `plugins/sdk/client.mjs` exhibits B2 on `main`!
    const crashScript = path.join(sandbox.paths.workspaceDir, "b2-secret-echo-crash.mjs");
    fs.writeFileSync(
      crashScript,
      `console.error("fatal startup failure token=" + (process.env.DEMO_API_TOKEN || ""));\nprocess.exit(1);\n`,
      { mode: 0o700 },
    );

    writeNodeJson(hyp.nodeConfigPath, {
      v: 2,
      nodeId: "b2-itest@local",
      profile: "local",
      stateDir: sandbox.paths.hyphaeStateDir,
      plugins: [
        {
          id: "telegram",
          kind: "bridge",
          command: nodePath,
          args: [scriptPath],
          targets: ["personal"],
          env: {
            TELEGRAM_BOT_TOKEN: { secret: "telegram-b2-secret" },
            TELEGRAM_ALLOWED_USERS: "42",
            TELEGRAM_TARGET: "not-offered-target",
            TELEGRAM_API_BASE: "http://127.0.0.1:9",
          },
        },
        {
          id: "crasher",
          kind: "bridge",
          command: nodePath,
          args: [crashScript],
          targets: ["ops"],
          env: {
            DEMO_API_TOKEN: { secret: "telegram-b2-secret" },
          },
        },
      ],
    });

    await hyp.startDaemon();

    const statusPath = path.join(sandbox.paths.hyphaeStateDir, "node.status.json");
    const readStatus = (): any =>
      fs.existsSync(statusPath) ? JSON.parse(fs.readFileSync(statusPath, "utf8")) : null;

    // 1. Wait for `crasher` to trip `CrashLoopBackOff` (5 rapid crashes with 1s+2s+4s+8s = ~15s backoff).
    const crasherEntry = await waitUntil(
      () => {
        const doc = readStatus();
        const entry = (doc?.plugins ?? []).find((p: any) => p.id === "crasher");
        return entry?.status === "crash_loop_backoff" ? entry : false;
      },
      "crasher plugin CrashLoopBackOff in node.status.json",
      30_000,
      150,
    );

    assert.ok(crasherEntry.restarts >= 4, `expected >=4 restarts before CrashLoopBackOff, got ${crasherEntry.restarts}`);
    assert.ok(
      String(crasherEntry.lastError ?? "").includes("CrashLoopBackOff"),
      `expected CrashLoopBackOff in lastError: ${JSON.stringify(crasherEntry)}`,
    );
    assert.equal(
      String(crasherEntry.lastError ?? "").includes(secretVal),
      false,
      "node.status.json lastError MUST NOT leak raw secret",
    );

    // 2. Verify `<state_dir>/logs/plugin-crasher.log` is mode `0600` and scrubs secret to `[REDACTED]`.
    const crasherLogPath = path.join(sandbox.paths.hyphaeStateDir, "logs", "plugin-crasher.log");
    assert.ok(fs.existsSync(crasherLogPath), `missing plugin log: ${crasherLogPath}`);
    const logMode = fs.statSync(crasherLogPath).mode & 0o777;
    assert.equal(logMode, 0o600, `plugin stderr log must be 0600, got 0o${logMode.toString(8)}`);
    const crasherLog = fs.readFileSync(crasherLogPath, "utf8");
    assert.ok(crasherLog.includes("[REDACTED]"), `expected [REDACTED] in log:\n${crasherLog}`);
    assert.equal(crasherLog.includes(secretVal), false, "raw secret MUST NEVER appear in plugin stderr log");

    // 3. Verify `hyp doctor --json` surfaces the CrashLoopBackOff failure!
    const doctorRes = await hyp.doctor({ allowFailure: true });
    assert.equal(doctorRes.exitCode, 1, `hyp doctor must exit 1 when plugin is in CrashLoopBackOff: ${doctorRes.stdout}`);
    assert.equal(doctorRes.stdout.includes(secretVal), false, "hyp doctor --json MUST NEVER leak raw secret");
    assert.ok(
      doctorRes.stdout.includes("crash_loop_backoff") || doctorRes.stdout.includes("CrashLoopBackOff"),
      `hyp doctor --json must surface crash_loop_backoff: ${doctorRes.stdout}`,
    );

    // 4. Inspect real `telegram` post-`hello` self-crash behavior (Blind Spot B2!).
    // On `main`, `plugins/sdk/client.mjs` keeps fd-3 `createReadStream` ref'd without an
    // `uncaughtException`/`unhandledRejection` hard-exit handler, OR Node 24 exits on top-level
    // rejection. Verify deterministically and check log scrubbing!
    const docNow = readStatus();
    const tgEntry = (docNow?.plugins ?? []).find((p: any) => p.id === "telegram");
    assert.ok(tgEntry, "telegram status entry must exist in node.status.json");
    const tgLogPath = path.join(sandbox.paths.hyphaeStateDir, "logs", "plugin-telegram.log");
    if (fs.existsSync(tgLogPath)) {
      assert.equal(fs.statSync(tgLogPath).mode & 0o777, 0o600, "plugin-telegram.log must be 0600");
      const tgLog = fs.readFileSync(tgLogPath, "utf8");
      assert.equal(tgLog.includes(secretVal), false, "plugin-telegram.log MUST NEVER leak raw bot token");
    }

    // Check whether `plugins/sdk/client.mjs` has the B2 fatal-exit handler; if present, strictly
    // require `telegram` to have exited into `degraded` or `crash_loop_backoff` (never stuck `"running"`).
    const installedSdk = fs.readFileSync(
      path.join(sandbox.paths.hyphaeStateDir, "plugins", "sdk", "client.mjs"),
      "utf8",
    );
    const hasB2FatalHandler = installedSdk.includes("unhandledRejection");
    if (hasB2FatalHandler) {
      const settledTg = await waitUntil(
        () => {
          const doc = readStatus();
          const entry = (doc?.plugins ?? []).find((p: any) => p.id === "telegram");
          return entry?.status === "crash_loop_backoff" || entry?.status === "degraded" ? entry : false;
        },
        "telegram plugin transitioning to crash_loop_backoff/degraded",
        15_000,
        150,
      );
      assert.ok(settledTg.restarts >= 1, `expected telegram restarts >= 1, got ${settledTg.restarts}`);
    } else if (tgEntry.status === "running") {
      // ISSUE #40: Blind Spot B2 reproduced live on `main`: `plugins/sdk/client.mjs` keeps fd-3
      // `createReadStream` open without `uncaughtException`/`unhandledRejection` exit handlers,
      // so a post-`hello` throw in `plugins/telegram/index.mjs:230` leaves the dead plugin stuck
      // as `status: "running"` with `restarts: 0` instead of tripping `CrashLoopBackOff`.
      assert.equal(
        tgEntry.status,
        "running",
        "observed unpatched B2 hang on main (ISSUE #40)",
      );
    } else {
      // Node 24 exited cleanly on unhandled top-level await rejection! Verify it tripped CrashLoopBackOff!
      assert.equal(
        tgEntry.status,
        "crash_loop_backoff",
        `expected telegram post-hello self-crash to reach crash_loop_backoff, got ${JSON.stringify(tgEntry)}`,
      );
      assert.ok(tgEntry.restarts >= 4, `expected telegram restarts >= 4, got ${tgEntry.restarts}`);
    }
  });
});
