import assert from "node:assert/strict";
import { createHmac, timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer as createHttpServer } from "node:http";
import { test } from "node:test";
import { handleHookPayload } from "../../src/hooks.ts";
import { object } from "../../src/protocol.ts";
import { freePort, MeshTopology, waitFor, type ManagedConnector, type McpClient } from "./harness/topology.ts";
import { deliverSignedWebhook, startMockSlackServer, startMockTelegramServer } from "./shims/services.ts";

type ToolResult = { text: string; isError: boolean; json(): unknown };

interface EnrolledMcpSession {
  readonly handle: string;
  readonly harness: "antigravity" | "claude" | "codex" | "opencode";
  readonly sessionId: string;
  readonly client: McpClient;
  call(tool: string, args?: Record<string, unknown>): Promise<ToolResult>;
}

interface PluginTargetsResponse {
  readonly targets: Array<{
    readonly plugin: string;
    readonly target: string;
    readonly sessionId: string | null;
    readonly handle: string | null;
    readonly linkedSessions: Array<{ readonly sessionId: string; readonly handle: string | null }>;
  }>;
}

/**
 * Opens a dedicated real `hyp mcp` subprocess for a harness and enrolls `handle`.
 * For `codex`, uses authentic PreToolUse hook caller verification so the daemon registers a
 * genuine `backend: "codex"` durable-mailbox session rather than falling back to `claude`.
 */
async function openEnrolledSession(
  conn: ManagedConnector,
  harness: EnrolledMcpSession["harness"],
  handle: string,
): Promise<EnrolledMcpSession> {
  if (harness === "codex") {
    const client = await conn.openMcp();
    const rawId = `${handle}-thread`;
    let seq = 0;
    const call = async (tool: string, args: Record<string, unknown> = {}): Promise<ToolResult> => {
      const callId = `codex_${handle}_${++seq}`;
      await handleHookPayload(
        { session_id: rawId, tool_use_id: callId, tool_name: `hyphae.${tool}` },
        { harness: "codex", event: "pre-tool-use", socketPath: conn.socketPath },
      );
      return client.callTool(tool, args, { callId });
    };
    const joinRes = await call("hyp_join", { handle });
    assert.equal(joinRes.isError, false, `codex hyp_join(${handle}) failed: ${joinRes.text}`);
    const caps = (await call("hyp_capabilities", {})).json() as { sessionId: string; backend: string };
    assert.equal(caps.backend, "codex");
    return { handle, harness, sessionId: caps.sessionId, client, call };
  }

  const client = await conn.openMcp(["--backend", harness, "--ephemeral"]);
  const call = (tool: string, args: Record<string, unknown> = {}) => client.callTool(tool, args);
  const joinRes = await call("hyp_join", { handle });
  assert.equal(joinRes.isError, false, `${harness} hyp_join(${handle}) failed: ${joinRes.text}`);
  const caps = (await call("hyp_capabilities", {})).json() as { sessionId: string; backend: string };
  assert.equal(caps.backend, harness);
  return { handle, harness, sessionId: caps.sessionId, client, call };
}

test(
  "bidirectional Slack Socket Mode bridge: multi-thread hyp_bridge_link/unlink, allowlists, outbound hyp_plugin_post, upstream error recovery, and session mute",
  { timeout: 30_000 },
  async () => {
    const topo = new MeshTopology("hi-bsl-");
    try {
      const appToken = "xapp-1-bi-slack-app-token";
      const botToken = "xoxb-bi-slack-bot-token";
      const mockSlack = await startMockSlackServer({ appToken, botToken, botUserId: "UBOT123", teamId: "TBIOPS" });
      topo.track(() => mockSlack.close());

      const router = await topo.addRouter({ name: "team" });
      const conn = await topo.addConnector({
        connectorId: "ops@slack-host",
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
              SLACK_ALLOWED_CHANNELS: "C-OPS,C-DEV",
              SLACK_ALLOWED_USERS: "UALICE,UBOB",
              SLACK_TARGET: "slack-ops",
            },
            targets: [
              { name: "slack-ops", handle: "lead", coalesceSeconds: 0, maxWaitSeconds: 5, wakesPerHour: 240 },
            ],
          },
        ],
      });

      const cfgRaw = readFileSync(conn.configPath, "utf8");
      assert.equal(cfgRaw.includes(appToken), false, "slack app token must not appear in connector.json");
      assert.equal(cfgRaw.includes(botToken), false, "slack bot token must not appear in connector.json");

      // Connect 4 real McpClient sessions across distinct harnesses
      const [lead, reviewer, builder, outsider] = await Promise.all([
        openEnrolledSession(conn, "antigravity", "lead"),
        openEnrolledSession(conn, "claude", "reviewer"),
        openEnrolledSession(conn, "codex", "builder"),
        openEnrolledSession(conn, "opencode", "outsider"),
      ]);

      await mockSlack.waitForConnected(8_000);
      assert.deepEqual(mockSlack.authCalls, [botToken]);

      // Outsider fails closed on post, link, handoff, and sees no targets
      const outsiderTargets = (await outsider.call("hyp_plugin_targets", {})).json() as PluginTargetsResponse;
      assert.deepEqual(outsiderTargets.targets, []);

      const outsiderPost = await outsider.call("hyp_plugin_post", {
        plugin: "slack",
        target: "slack-ops",
        text: "unauthorized message",
        channel: "C-OPS",
      });
      assert.equal(outsiderPost.isError, true);
      assert.match(outsiderPost.text, /not_target_holder/);

      const outsiderLink = await outsider.call("hyp_bridge_link", {
        plugin: "slack",
        target: "slack-ops",
        handle: "outsider",
      });
      assert.equal(outsiderLink.isError, true);
      assert.match(outsiderLink.text, /not_target_holder/);

      const outsiderHandoff = await outsider.call("hyp_plugin_handoff", {
        plugin: "slack",
        target: "slack-ops",
        handle: "outsider",
      });
      assert.equal(outsiderHandoff.isError, true);
      assert.match(outsiderHandoff.text, /not_target_holder/);

      // Primary holder `lead` links BOTH `reviewer` (by handle) and `builder` (by sessionId)
      const linkReviewer = await lead.call("hyp_bridge_link", {
        plugin: "slack",
        target: "slack-ops",
        handle: "reviewer",
      });
      assert.equal(linkReviewer.isError, false, linkReviewer.text);

      const linkBuilder = await lead.call("hyp_bridge_link", {
        plugin: "slack",
        target: "slack-ops",
        sessionId: builder.sessionId,
      });
      assert.equal(linkBuilder.isError, false, linkBuilder.text);

      const expectedLinkedIds = [reviewer.sessionId, builder.sessionId].sort();
      for (const member of [lead, reviewer, builder]) {
        const res = await member.call("hyp_plugin_targets", {});
        assert.equal(res.isError, false, res.text);
        const parsed = res.json() as PluginTargetsResponse;
        assert.equal(parsed.targets.length, 1);
        assert.equal(parsed.targets[0].plugin, "slack");
        assert.equal(parsed.targets[0].target, "slack-ops");
        assert.equal(parsed.targets[0].sessionId, lead.sessionId);
        assert.deepEqual(
          parsed.targets[0].linkedSessions.map((s) => s.sessionId).sort(),
          expectedLinkedIds,
        );
      }

      // Inbound Slack app_mention in C-OPS fans in to all 3 linked/primary sessions; outsider receives nothing
      const env1 = mockSlack.pushEvent({
        type: "app_mention",
        channel: "C-OPS",
        user: "UALICE",
        ts: "1700001.0001",
        thread_ts: "1700001.0001",
        text: "<@UBOT123> deploy status for checkout-api?",
      });
      await mockSlack.waitForAck(env1);

      await waitFor(
        () =>
          conn.daemon.state.pendingCount(lead.sessionId) >= 1 &&
          conn.daemon.state.pendingCount(reviewer.sessionId) >= 1 &&
          conn.daemon.state.pendingCount(builder.sessionId) >= 1,
        { label: "Slack fan-in to lead, reviewer, builder" },
      );
      for (const member of [lead, reviewer, builder]) {
        const items = conn.daemon.connector.drainMailbox(member.sessionId, 5);
        assert.equal(items.length, 1);
        assert.match(items[0].text, /deploy status for checkout-api\?/);
      }
      assert.equal(conn.daemon.state.pendingCount(outsider.sessionId), 0);

      // Outbound 1: `lead` posts WITHOUT `channel` -> auto-replies to `lastChannel` (C-OPS)
      const autoReply = await lead.call("hyp_plugin_post", {
        plugin: "slack",
        target: "slack-ops",
        text: "Investigating checkout-api now",
      });
      assert.equal(autoReply.isError, false, autoReply.text);
      const posts1 = await mockSlack.waitForPost(1);
      assert.equal(posts1[0].channel, "C-OPS");
      assert.equal(posts1[0].text, "Investigating checkout-api now");
      assert.equal(posts1[0].thread_ts, undefined);

      // Outbound 2: linked `reviewer` posts to explicit `C-DEV` with `threadTs`
      const threadedReply = await reviewer.call("hyp_plugin_post", {
        plugin: "slack",
        target: "slack-ops",
        text: "PR review completed",
        channel: "C-DEV",
        threadTs: "1700001.0001",
      });
      assert.equal(threadedReply.isError, false, threadedReply.text);
      const posts2 = await mockSlack.waitForPost(2);
      assert.equal(posts2[1].channel, "C-DEV");
      assert.equal(posts2[1].text, "PR review completed");
      assert.equal(posts2[1].thread_ts, "1700001.0001");

      // Outbound 3: linked `builder` posting to disallowed channel `C-SECRET` fails closed
      const disallowedPost = await builder.call("hyp_plugin_post", {
        plugin: "slack",
        target: "slack-ops",
        text: "should be rejected",
        channel: "C-SECRET",
      });
      assert.equal(disallowedPost.isError, true);
      assert.match(disallowedPost.text, /plugin_post_failed/);
      assert.match(disallowedPost.text, /SLACK_ALLOWED_CHANNELS/);
      assert.equal(mockSlack.postedMessages.length, 2);

      // Outbound 4: injected upstream Slack API error fails cleanly, then recovers once cleared
      mockSlack.setPostError("channel_not_found");
      const injectedFail = await lead.call("hyp_plugin_post", {
        plugin: "slack",
        target: "slack-ops",
        text: "expected upstream failure",
        channel: "C-OPS",
      });
      assert.equal(injectedFail.isError, true);
      assert.match(injectedFail.text, /plugin_post_failed/);
      assert.match(injectedFail.text, /channel_not_found/);
      assert.equal(mockSlack.postedMessages.length, 2);

      mockSlack.setPostError(null);
      const recoveredPost = await lead.call("hyp_plugin_post", {
        plugin: "slack",
        target: "slack-ops",
        text: "Recovered after transient Slack error",
        channel: "C-OPS",
      });
      assert.equal(recoveredPost.isError, false, recoveredPost.text);
      const posts3 = await mockSlack.waitForPost(3);
      assert.equal(posts3[2].channel, "C-OPS");
      assert.equal(posts3[2].text, "Recovered after transient Slack error");

      // Multi-thread session-scoped mute: reviewer mutes plugin:slack, lead & builder still receive
      const muteRes = await reviewer.call("hyp_mute", { target: "plugin:slack", scope: "session" });
      assert.equal(muteRes.isError, false, muteRes.text);

      const env2 = mockSlack.pushEvent({
        type: "message",
        channel: "C-OPS",
        user: "UBOB",
        ts: "1700001.0002",
        thread_ts: "1700001.0001",
        text: "metrics look steady after canary",
      });
      await mockSlack.waitForAck(env2);

      await waitFor(
        () =>
          conn.daemon.state.pendingCount(lead.sessionId) >= 1 &&
          conn.daemon.state.pendingCount(builder.sessionId) >= 1,
        { label: "Slack delivery to unmuted lead and builder" },
      );
      assert.match(conn.daemon.connector.drainMailbox(lead.sessionId, 5)[0].text, /metrics look steady after canary/);
      assert.match(conn.daemon.connector.drainMailbox(builder.sessionId, 5)[0].text, /metrics look steady after canary/);
      await new Promise((r) => setTimeout(r, 150));
      assert.equal(conn.daemon.state.pendingCount(reviewer.sessionId), 0, "Muted reviewer must not receive Slack fan-in");

      // Unmute reviewer; verify non-primary linked builder cannot unlink others or use all=true
      const unmuteRes = await reviewer.call("hyp_unmute", { target: "plugin:slack", scope: "session" });
      assert.equal(unmuteRes.isError, false, unmuteRes.text);

      const unlinkOtherFail = await builder.call("hyp_bridge_unlink", {
        plugin: "slack",
        target: "slack-ops",
        handle: "reviewer",
      });
      assert.equal(unlinkOtherFail.isError, true);
      assert.match(unlinkOtherFail.text, /not_target_holder/);

      const unlinkAllFail = await builder.call("hyp_bridge_unlink", {
        plugin: "slack",
        target: "slack-ops",
        all: true,
      });
      assert.equal(unlinkAllFail.isError, true);
      assert.match(unlinkAllFail.text, /not_target_holder/);

      // Builder self-unlinks -> can no longer post and no longer receives fan-in
      const selfUnlink = await builder.call("hyp_bridge_unlink", {
        plugin: "slack",
        target: "slack-ops",
      });
      assert.equal(selfUnlink.isError, false, selfUnlink.text);
      const selfUnlinkData = selfUnlink.json() as { removed: boolean; removedCount: number; linkedSessions: Array<{ sessionId: string }> };
      assert.equal(selfUnlinkData.removed, true);
      assert.equal(selfUnlinkData.removedCount, 1);
      assert.deepEqual(selfUnlinkData.linkedSessions.map((s) => s.sessionId), [reviewer.sessionId]);

      const postAfterUnlink = await builder.call("hyp_plugin_post", {
        plugin: "slack",
        target: "slack-ops",
        text: "builder post after unlink",
        channel: "C-OPS",
      });
      assert.equal(postAfterUnlink.isError, true);
      assert.match(postAfterUnlink.text, /not_target_holder/);

      const env3 = mockSlack.pushEvent({
        type: "message",
        channel: "C-OPS",
        user: "UALICE",
        ts: "1700001.0003",
        thread_ts: "1700001.0001",
        text: "update after builder unlinked",
      });
      await mockSlack.waitForAck(env3);

      await waitFor(
        () =>
          conn.daemon.state.pendingCount(lead.sessionId) >= 1 &&
          conn.daemon.state.pendingCount(reviewer.sessionId) >= 1,
        { label: "Slack delivery to lead and unmuted reviewer after builder self-unlink" },
      );
      assert.match(conn.daemon.connector.drainMailbox(lead.sessionId, 5)[0].text, /update after builder unlinked/);
      assert.match(conn.daemon.connector.drainMailbox(reviewer.sessionId, 5)[0].text, /update after builder unlinked/);
      await new Promise((r) => setTimeout(r, 150));
      assert.equal(conn.daemon.state.pendingCount(builder.sessionId), 0);
      assert.equal(conn.daemon.state.pendingCount(outsider.sessionId), 0);

      // Lead unlinks all -> linkedSessions empty and only lead receives the next Slack message
      const unlinkAll = await lead.call("hyp_bridge_unlink", {
        plugin: "slack",
        target: "slack-ops",
        all: true,
      });
      assert.equal(unlinkAll.isError, false, unlinkAll.text);
      const unlinkAllData = unlinkAll.json() as { removed: boolean; removedCount: number; linkedSessions: unknown[] };
      assert.equal(unlinkAllData.removed, true);
      assert.equal(unlinkAllData.removedCount, 1);
      assert.deepEqual(unlinkAllData.linkedSessions, []);

      const leadTargetsAfter = (await lead.call("hyp_plugin_targets", {})).json() as PluginTargetsResponse;
      assert.deepEqual(leadTargetsAfter.targets[0].linkedSessions, []);
      const reviewerTargetsAfter = (await reviewer.call("hyp_plugin_targets", {})).json() as PluginTargetsResponse;
      assert.deepEqual(reviewerTargetsAfter.targets, []);

      const env4 = mockSlack.pushEvent({
        type: "message",
        channel: "C-OPS",
        user: "UALICE",
        ts: "1700001.0004",
        thread_ts: "1700001.0001",
        text: "final lead-only slack message",
      });
      await mockSlack.waitForAck(env4);

      await waitFor(() => conn.daemon.state.pendingCount(lead.sessionId) >= 1, { label: "lead-only Slack delivery" });
      assert.match(conn.daemon.connector.drainMailbox(lead.sessionId, 5)[0].text, /final lead-only slack message/);
      await new Promise((r) => setTimeout(r, 150));
      assert.equal(conn.daemon.state.pendingCount(reviewer.sessionId), 0);
      assert.equal(conn.daemon.state.pendingCount(builder.sessionId), 0);
      assert.equal(conn.daemon.state.pendingCount(outsider.sessionId), 0);
    } finally {
      await topo.cleanup();
    }
  },
);

test(
  "bidirectional Telegram Bot bridge: multi-thread linking, auto-reply lastChatId, numeric chatId/replyTo, allowlist, error recovery, and live handoff",
  { timeout: 30_000 },
  async () => {
    const topo = new MeshTopology("hi-btg-");
    try {
      const botToken = "987654:XYZ-bi-telegram-bot-secret";
      const mockTg = await startMockTelegramServer(botToken, 80);
      topo.track(() => mockTg.close());

      const router = await topo.addRouter({ name: "team" });
      const conn = await topo.addConnector({
        connectorId: "ops@tg-host",
        links: [{ name: "primary", router }],
        secrets: { "telegram-bot-token": botToken },
        rawPlugins: [
          {
            name: "telegram",
            builtin: "telegram",
            env: {
              TELEGRAM_API_BASE: mockTg.apiBaseUrl,
              TELEGRAM_BOT_TOKEN: { secret: "telegram-bot-token" },
              TELEGRAM_ALLOWED_CHATS: "55501,55502",
              TELEGRAM_ALLOWED_USERS: "9001",
              TELEGRAM_TARGET: "tg-ops",
            },
            targets: [
              { name: "tg-ops", handle: "tg-lead", coalesceSeconds: 0, maxWaitSeconds: 5, wakesPerHour: 240 },
            ],
          },
        ],
      });

      const cfgRaw = readFileSync(conn.configPath, "utf8");
      assert.equal(cfgRaw.includes(botToken), false, "telegram bot token must not appear in connector.json");

      const [tgLead, tgHelper] = await Promise.all([
        openEnrolledSession(conn, "claude", "tg-lead"),
        openEnrolledSession(conn, "codex", "tg-helper"),
      ]);

      await mockTg.waitForPoll(1, 8_000);

      // Primary tg-lead links tg-helper via hyp_bridge_link
      const linkRes = await tgLead.call("hyp_bridge_link", {
        plugin: "telegram",
        target: "tg-ops",
        handle: "tg-helper",
      });
      assert.equal(linkRes.isError, false, linkRes.text);

      // Push inbound Telegram message -> fans in to both tg-lead and tg-helper
      mockTg.pushUpdate({
        update_id: 1001,
        message: {
          message_id: 42,
          chat: { id: 55501, type: "private" },
          from: { id: 9001, username: "oncall", first_name: "Ada" },
          text: "Check Redis memory pressure",
        },
      });

      await waitFor(
        () =>
          conn.daemon.state.pendingCount(tgLead.sessionId) >= 1 &&
          conn.daemon.state.pendingCount(tgHelper.sessionId) >= 1,
        { label: "Telegram fan-in to tg-lead and tg-helper" },
      );
      assert.match(conn.daemon.connector.drainMailbox(tgLead.sessionId, 5)[0].text, /Check Redis memory pressure/);
      assert.match(conn.daemon.connector.drainMailbox(tgHelper.sessionId, 5)[0].text, /Check Redis memory pressure/);

      // Outbound 1: tg-lead posts with NO chatId -> auto-replies to lastChatId (55501)
      const autoReply = await tgLead.call("hyp_plugin_post", {
        plugin: "telegram",
        target: "tg-ops",
        text: "Redis is at 62%, healthy",
      });
      assert.equal(autoReply.isError, false, autoReply.text);
      const sent1 = await mockTg.waitForSent(1);
      assert.equal(sent1[0].chat_id, "55501");
      assert.equal(sent1[0].text, "Redis is at 62%, healthy");
      assert.equal(sent1[0].reply_to_message_id, undefined);

      // Outbound 2: linked tg-helper posts with numeric chatId=55502 and replyTo="42"
      const explicitReply = await tgHelper.call("hyp_plugin_post", {
        plugin: "telegram",
        target: "tg-ops",
        text: "Escalation note in ops group",
        chatId: 55502,
        replyTo: "42",
      });
      assert.equal(explicitReply.isError, false, explicitReply.text);
      const sent2 = await mockTg.waitForSent(2);
      assert.equal(sent2[1].chat_id, "55502");
      assert.equal(sent2[1].text, "Escalation note in ops group");
      assert.equal(sent2[1].reply_to_message_id, 42);

      // Outbound 3: disallowed chatId=99999 fails closed
      const disallowedChat = await tgHelper.call("hyp_plugin_post", {
        plugin: "telegram",
        target: "tg-ops",
        text: "blocked chat",
        chatId: 99999,
      });
      assert.equal(disallowedChat.isError, true);
      assert.match(disallowedChat.text, /plugin_post_failed/);
      assert.match(disallowedChat.text, /TELEGRAM_ALLOWED_CHATS/);
      assert.equal(mockTg.sentMessages.length, 2);

      // Outbound 4: injected 403 upstream error fails cleanly, then recovers once cleared
      mockTg.setSendError("Forbidden: bot was blocked by the user", 403);
      const blockedErr = await tgLead.call("hyp_plugin_post", {
        plugin: "telegram",
        target: "tg-ops",
        text: "should fail with 403",
        chatId: 55501,
      });
      assert.equal(blockedErr.isError, true);
      assert.match(blockedErr.text, /plugin_post_failed/);
      assert.match(blockedErr.text, /Forbidden: bot was blocked by the user/);
      assert.equal(mockTg.sentMessages.length, 2);

      mockTg.setSendError(null);
      const recoveredSend = await tgLead.call("hyp_plugin_post", {
        plugin: "telegram",
        target: "tg-ops",
        text: "Recovered Telegram reply",
        chatId: 55501,
      });
      assert.equal(recoveredSend.isError, false, recoveredSend.text);
      const sent3 = await mockTg.waitForSent(3);
      assert.equal(sent3[2].chat_id, "55501");
      assert.equal(sent3[2].text, "Recovered Telegram reply");

      // Live hyp_plugin_handoff from tg-lead -> tg-helper; tg-helper becomes primary holder
      const handoffRes = await tgLead.call("hyp_plugin_handoff", {
        plugin: "telegram",
        target: "tg-ops",
        handle: "tg-helper",
      });
      assert.equal(handoffRes.isError, false, handoffRes.text);
      assert.deepEqual(handoffRes.json(), { plugin: "telegram", target: "tg-ops", sessionId: tgHelper.sessionId });

      // New primary tg-helper can unlink all sessions and receives subsequent updates exclusively
      const unlinkAllRes = await tgHelper.call("hyp_bridge_unlink", {
        plugin: "telegram",
        target: "tg-ops",
        all: true,
      });
      assert.equal(unlinkAllRes.isError, false, unlinkAllRes.text);
      const helperTargets = (await tgHelper.call("hyp_plugin_targets", {})).json() as PluginTargetsResponse;
      assert.equal(helperTargets.targets.length, 1);
      assert.equal(helperTargets.targets[0].sessionId, tgHelper.sessionId);
      assert.deepEqual(helperTargets.targets[0].linkedSessions, []);

      mockTg.pushUpdate({
        update_id: 1002,
        message: {
          message_id: 43,
          chat: { id: 55501, type: "private" },
          from: { id: 9001, username: "oncall" },
          text: "Routed directly to new primary tg-helper",
        },
      });
      await waitFor(() => conn.daemon.state.pendingCount(tgHelper.sessionId) >= 1, {
        label: "tg-helper receiving Telegram update as new primary holder",
      });
      assert.match(conn.daemon.connector.drainMailbox(tgHelper.sessionId, 5)[0].text, /Routed directly to new primary tg-helper/);
      await new Promise((r) => setTimeout(r, 150));
      assert.equal(conn.daemon.state.pendingCount(tgLead.sessionId), 0);

      // New primary tg-helper can also hand off cleanly back to tg-lead
      const handoffBack = await tgHelper.call("hyp_plugin_handoff", {
        plugin: "telegram",
        target: "tg-ops",
        handle: "tg-lead",
      });
      assert.equal(handoffBack.isError, false, handoffBack.text);
      assert.deepEqual(handoffBack.json(), { plugin: "telegram", target: "tg-ops", sessionId: tgLead.sessionId });
    } finally {
      await topo.cleanup();
    }
  },
);

test(
  "bidirectional Webhook bridge: signed inbound fan-in, HMAC-signed outbound WEBHOOK_POST_URL callback, unconfigured fail-closed, and >16 KiB rejection",
  { timeout: 30_000 },
  async () => {
    const topo = new MeshTopology("hi-bwh-");
    try {
      const biPort = await freePort();
      const roPort = await freePort();
      const biSecret = "wh-bi-hmac-secret-512";
      const roSecret = "wh-ro-hmac-secret-256";

      interface CallbackRecord {
        readonly signature: string;
        readonly signatureValid: boolean;
        readonly body: Record<string, unknown>;
      }
      const receivedCallbacks: CallbackRecord[] = [];

      // Loopback callback receiver verifying X-Webhook-Signature-256 HMAC-SHA256
      const callbackServer = createHttpServer(async (req, res) => {
        const chunks: Buffer[] = [];
        for await (const chunk of req) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk)));
        const raw = Buffer.concat(chunks);
        const signature = String(req.headers["x-webhook-signature-256"] ?? "");
        const expected = "sha256=" + createHmac("sha256", biSecret).update(raw).digest("hex");
        const signatureValid =
          signature.length === expected.length && timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
        if (!signatureValid) {
          res.writeHead(401, { "content-type": "application/json" }).end(JSON.stringify({ ok: false, error: "bad_signature" }));
          return;
        }
        const parsed: unknown = JSON.parse(raw.toString("utf8"));
        receivedCallbacks.push({
          signature,
          signatureValid,
          body: object(parsed) ? parsed : {},
        });
        res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ ok: true }));
      });
      await new Promise<void>((resolve) => callbackServer.listen(0, "127.0.0.1", resolve));
      topo.track(
        () =>
          new Promise<void>((resolve) => {
            callbackServer.closeAllConnections();
            callbackServer.close(() => resolve());
          }),
      );
      const cbAddr = callbackServer.address();
      assert.ok(cbAddr && typeof cbAddr === "object");
      const callbackUrl = `http://127.0.0.1:${cbAddr.port}/callback`;

      const router = await topo.addRouter({ name: "team" });
      const conn = await topo.addConnector({
        connectorId: "ops@webhook-host",
        links: [{ name: "primary", router }],
        secrets: {
          "wh-bi-secret": biSecret,
          "wh-ro-secret": roSecret,
        },
        rawPlugins: [
          {
            name: "webhook-bi",
            builtin: "webhook",
            env: {
              WEBHOOK_HOST: "127.0.0.1",
              WEBHOOK_PORT: String(biPort),
              WEBHOOK_PATH: "/bi",
              WEBHOOK_TARGET: "ops",
              WEBHOOK_SOURCE: "pager/bi",
              WEBHOOK_SECRET: { secret: "wh-bi-secret" },
              WEBHOOK_POST_URL: callbackUrl,
            },
            targets: [
              { name: "ops", handle: "wh-lead", coalesceSeconds: 0, maxWaitSeconds: 5, wakesPerHour: 240 },
            ],
          },
          {
            name: "webhook-ro",
            builtin: "webhook",
            env: {
              WEBHOOK_HOST: "127.0.0.1",
              WEBHOOK_PORT: String(roPort),
              WEBHOOK_PATH: "/ro",
              WEBHOOK_TARGET: "readonly",
              WEBHOOK_SOURCE: "pager/ro",
              WEBHOOK_SECRET: { secret: "wh-ro-secret" },
            },
            targets: [
              { name: "readonly", handle: "wh-lead", coalesceSeconds: 0, maxWaitSeconds: 5, wakesPerHour: 240 },
            ],
          },
        ],
      });

      const cfgRaw = readFileSync(conn.configPath, "utf8");
      assert.equal(cfgRaw.includes(biSecret), false, "webhook-bi secret must not appear in connector.json");
      assert.equal(cfgRaw.includes(roSecret), false, "webhook-ro secret must not appear in connector.json");

      const [whLead, whWorker] = await Promise.all([
        openEnrolledSession(conn, "antigravity", "wh-lead"),
        openEnrolledSession(conn, "claude", "wh-worker"),
      ]);

      // Link wh-worker to webhook-bi/ops
      const linkRes = await whLead.call("hyp_bridge_link", {
        plugin: "webhook-bi",
        target: "ops",
        handle: "wh-worker",
      });
      assert.equal(linkRes.isError, false, linkRes.text);

      // Deliver tampered signature -> 401; valid signed inbound POST -> 202 and fan-in to both primary + linked
      const badInbound = await deliverSignedWebhook({
        url: `http://127.0.0.1:${biPort}/bi`,
        secret: biSecret,
        payload: { type: "com.pager.incident", data: { summary: "spoofed" } },
        overrideSignature: "sha256=" + "0".repeat(64),
      });
      assert.equal(badInbound.status, 401);

      const okInbound = await deliverSignedWebhook({
        url: `http://127.0.0.1:${biPort}/bi`,
        secret: biSecret,
        deliveryId: "evt-bi-9001",
        payload: {
          type: "com.pager.incident",
          subject: "checkout/latency",
          data: { incident: "INC-9001", summary: "p99 latency above SLO" },
        },
      });
      assert.equal(okInbound.status, 202);

      await waitFor(
        () =>
          conn.daemon.state.pendingCount(whLead.sessionId) >= 1 &&
          conn.daemon.state.pendingCount(whWorker.sessionId) >= 1,
        { label: "webhook-bi inbound fan-in to primary and linked session" },
      );
      assert.match(conn.daemon.connector.drainMailbox(whLead.sessionId, 5)[0].text, /p99 latency above SLO/);
      assert.match(conn.daemon.connector.drainMailbox(whWorker.sessionId, 5)[0].text, /p99 latency above SLO/);

      // Linked session sends outbound hyp_plugin_post -> callback server receives valid HMAC-signed JSON payload
      const outRes = await whWorker.call("hyp_plugin_post", {
        plugin: "webhook-bi",
        target: "ops",
        channel: "#ops-alerts",
        replyTo: "evt-bi-9001",
        text: "Mitigation deployed and SLO restored",
      });
      assert.equal(outRes.isError, false, outRes.text);
      assert.deepEqual(outRes.json(), {
        plugin: "webhook-bi",
        target: "ops",
        result: { ok: true, status: 200 },
      });

      assert.equal(receivedCallbacks.length, 1);
      assert.equal(receivedCallbacks[0].signatureValid, true);
      assert.equal(receivedCallbacks[0].body.target, "ops");
      assert.equal(receivedCallbacks[0].body.channel, "#ops-alerts");
      assert.equal(receivedCallbacks[0].body.replyTo, "evt-bi-9001");
      assert.equal(receivedCallbacks[0].body.text, "Mitigation deployed and SLO restored");
      assert.equal(typeof receivedCallbacks[0].body.timestamp, "string");

      // Wait until webhook-ro child process has completed mesh.ready & bound its HTTP port
      await waitFor(async () => {
        try {
          const r = await fetch(`http://127.0.0.1:${roPort}/ro`);
          return r.status === 404;
        } catch {
          return false;
        }
      }, { label: "webhook-ro HTTP listener ready" });

      // Outbound hyp_plugin_post on read-only webhook-ro fails closed mentioning WEBHOOK_POST_URL
      const roPost = await whLead.call("hyp_plugin_post", {
        plugin: "webhook-ro",
        target: "readonly",
        text: "cannot post without WEBHOOK_POST_URL",
      });
      assert.equal(roPost.isError, true);
      assert.match(roPost.text, /plugin_post_failed/);
      assert.match(roPost.text, /WEBHOOK_POST_URL/);

      // Oversized hyp_plugin_post text (>16 KiB) fails closed (`invalid`) BEFORE reaching the plugin
      const oversized = await whWorker.call("hyp_plugin_post", {
        plugin: "webhook-bi",
        target: "ops",
        text: "x".repeat(16_385),
      });
      assert.equal(oversized.isError, true);
      assert.match(oversized.text, /invalid/);
      assert.match(oversized.text, /16 KiB/);
      assert.equal(receivedCallbacks.length, 1, "Oversized post must be rejected before invoking the plugin");
    } finally {
      await topo.cleanup();
    }
  },
);
