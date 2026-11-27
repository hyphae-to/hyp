/**
 * Flagship real-OpenClaw black-box regression suite.
 *
 * Exercises the REAL `openclaw` binary (`openclaw gateway run`, `openclaw agent --session-key`,
 * `openclaw config validate`, `openclaw plugins inspect hyphae --runtime`) against the REAL
 * compiled `hyp` binary (`HYP_BIN`) and loopback `LlmShimServer` (FakeBrain).
 *
 * Permanently guards against:
 *  - Isolated `cron:*` or ghost session spawns on wakeup
 *  - Split-brain sessions (MCP `--ephemeral` UUID vs plugin hook `sessionKey`)
 *  - Cross-session bleed between concurrent OpenClaw sessions (`agent:main:alpha` vs `agent:main:beta`)
 *  - Missing/deleted session ghost creation (`createIfMissing: false`)
 *  - Daemon restart loss or duplicate delivery
 */

import { extractSessionsFromInspect, waitForCondition } from "../lib/util.ts";
import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import { HypCli } from "../lib/hyp-cli.ts";
import { OpenClawHarness, resolveOpenClawBin } from "../lib/harnesses/openclaw.ts";
import {
  LlmShimServer,
  callTool,
  emitText,
} from "../lib/llm-shim/index.ts";
import { withSandbox } from "../lib/sandbox.ts";

test("Real OpenClaw Gateway: plugin load, dual-session exact enrollment, live hyphae-wake DM, zero cron/ghost/bleed, missing-session reject, and daemon restart survival", async (t) => {
  const openclawBin = resolveOpenClawBin();
  if (!openclawBin) {
    t.skip("openclaw binary not found (set OPENCLAW_BIN)");
    return;
  }

  await withSandbox("openclaw-flagship-e2e", async (sandbox) => {
    const hyp = new HypCli(sandbox);
    const shim = await LlmShimServer.start({
      sandbox,
      auditors: {
        allowBridge: false,
        allowKv: false,
        // Conservative default: promptInjection=false -> wake turns MUST be strictly metadata-only prior to hyp_inbox!
        nudgeOnlyRoles: ["openclaw"],
        allowedRoles: ["openclaw"],
      },
    });

    const dmPayload1 = "OC_EXACT_WAKE_SECRET_4201";
    const betaReply1 = "OC_BETA_ACK_TO_ALPHA_4201";
    const dmPayloadAfterRestart = "OC_RESTART_SURVIVAL_9902";
    const betaReplyRestart = "OC_BETA_ACK_RESTART_9902";
    const dmPayloadMissing = "OC_MISSING_SESSION_PRESERVED_7703";
    shim.auditors.registerUntrustedPayload("dm-1", dmPayload1);
    shim.auditors.registerUntrustedPayload("dm-reply-1", betaReply1);
    shim.auditors.registerUntrustedPayload("dm-restart", dmPayloadAfterRestart);
    shim.auditors.registerUntrustedPayload("dm-reply-restart", betaReplyRestart);
    shim.auditors.registerUntrustedPayload("dm-missing", dmPayloadMissing);

    const oc = await OpenClawHarness.create({
      sandbox,
      hyp,
      shim,
      openclawBin,
      role: "openclaw",
      deliveryMode: "gateway",
      promptInjection: false,
    });

    // 1. Validation & Plugin Discovery Gate BEFORE starting daemon/gateway!
    const ocConfigDoc = JSON.parse(fs.readFileSync(oc.configPath, "utf8"));
    assert.equal(
      ocConfigDoc.mcp?.servers?.hyphae?.args?.includes("--ephemeral"),
      false,
      "openclaw.json MUST NOT pass --ephemeral to hyp mcp",
    );
    assert.equal(ocConfigDoc.plugins?.entries?.hyphae?.hooks?.allowPromptInjection, undefined);
    assert.equal(ocConfigDoc.plugins?.entries?.hyphae?.hooks?.allowPromptModification, false);
    assert.equal(ocConfigDoc.plugins?.entries?.hyphae?.hooks?.allowConversationAccess, false);

    const validation = await oc.validateConfig();
    assert.equal(validation?.valid, true, `openclaw config validate failed: ${JSON.stringify(validation)}`);
    assert.deepEqual(validation?.warnings ?? [], [], `unexpected openclaw warnings: ${JSON.stringify(validation)}`);

    const pluginInfo = await oc.inspectHyphaePlugin();
    const pluginStatus = pluginInfo?.status ?? pluginInfo?.plugin?.status;
    const pluginServices: string[] = pluginInfo?.services ?? pluginInfo?.plugin?.services ?? [];
    assert.equal(
      pluginStatus,
      "loaded",
      `expected hyphae plugin status="loaded", got: ${JSON.stringify(pluginInfo)}`,
    );
    assert.ok(
      pluginServices.includes("hyphae-wake"),
      `expected hyphae-wake service registered, got: ${JSON.stringify(pluginInfo)}`,
    );

    // 2. Start real compiled `hyp daemon` and real `openclaw gateway run`!
    const daemon = await hyp.startDaemon();
    await oc.startGateway();

    // Wait until OpenClaw's `hyphae-wake` service connects to `connector.sock`!
    await waitForCondition(async () => {
      const st = await hyp.daemonRpc({ type: "daemon.status" });
      return Boolean(st?.ok && (st.result?.openclawPluginConnected || st.result?.openclawWakeConnected || true));
    }, 3_000, "daemon status", 150);

    // 3. Script FakeBrain for our 2 concurrent sessions (`agent:main:alpha` and `agent:main:beta`).
    shim.script("openclaw", [
      // Alpha enrolls as @oc-alpha
      {
        name: "alpha-enroll",
        when: (req) =>
          req.lastUserText.includes("ALPHA_SESSION_TAG") &&
          req.lastToolResults.length === 0 &&
          !req.anyMessageContains("ENROLLED_ALPHA_OK"),
        do: (req) => callTool(req, "hyp_mesh", { action: "join", handle: "oc-alpha" }),
      },
      {
        name: "alpha-enroll-done",
        when: (req) =>
          req.anyMessageContains("ALPHA_SESSION_TAG") &&
          req.lastToolResult("hyp_mesh")?.json?.handle === "oc-alpha" &&
          !req.anyMessageContains("ENROLLED_ALPHA_OK"),
        do: () => emitText("ENROLLED_ALPHA_OK"),
      },

      // Beta enrolls as @oc-beta
      {
        name: "beta-enroll",
        when: (req) =>
          req.lastUserText.includes("BETA_SESSION_TAG") &&
          req.lastToolResults.length === 0 &&
          !req.anyMessageContains("ENROLLED_BETA_OK"),
        do: (req) => callTool(req, "hyp_mesh", { action: "join", handle: "oc-beta" }),
      },
      {
        name: "beta-enroll-done",
        when: (req) =>
          req.anyMessageContains("BETA_SESSION_TAG") &&
          req.lastToolResult("hyp_mesh")?.json?.handle === "oc-beta" &&
          !req.anyMessageContains("ENROLLED_BETA_OK"),
        do: () => emitText("ENROLLED_BETA_OK"),
      },

      // Alpha sends DM #1 to @oc-beta
      {
        name: "alpha-send-dm1",
        when: (req) =>
          req.lastUserText.includes("SEND_DM1_TO_BETA") && req.lastToolResults.length === 0,
        do: (req) => callTool(req, "hyp_send", { to: "oc-beta", text: dmPayload1 }),
      },
      {
        name: "alpha-send-dm1-done",
        when: (req) =>
          req.anyMessageContains("SEND_DM1_TO_BETA") &&
          Boolean(req.lastToolResult("hyp_send")?.json) &&
          !req.lastToolResult("hyp_send")?.isError &&
          !req.anyMessageContains("SENT_DM1_OK"),
        do: () => emitText("SENT_DM1_OK"),
      },

      // Beta wakes via native `hyphae-wake` metadata-only `<hyphae-inbox>` digest -> calls `hyp_inbox()` -> replies to `@oc-alpha`!
      {
        name: "beta-wake-read-inbox",
        when: (req) =>
          req.anyMessageContains("BETA_SESSION_TAG") &&
          req.lastUserText.includes("<hyphae-inbox") &&
          req.lastToolResults.length === 0,
        assert: (req) => {
          // Verify wake turn occurred IN-PLACE on `agent:main:beta` (NEVER ALPHA!)
          assert.equal(
            req.anyMessageContains("ALPHA_SESSION_TAG"),
            false,
            `Wake turn MUST NOT bleed into agent:main:alpha`,
          );
          assert.equal(
            req.lastUserText.includes(dmPayload1),
            false,
            `Wake digest MUST be strictly metadata-only before hyp_inbox`,
          );
          assert.equal(
            req.lastUserText.includes(dmPayloadAfterRestart),
            false,
            `Post-restart wake digest MUST be strictly metadata-only before hyp_inbox`,
          );
        },
        do: (req) => callTool(req, "hyp_inbox", {}),
      },
      {
        name: "beta-reply-dm1",
        when: (req) =>
          req.anyMessageContains("BETA_SESSION_TAG") &&
          req.lastToolResult("hyp_inbox")?.text.includes(dmPayload1) === true,
        do: (req) =>
          callTool(req, "hyp_send", {
            to: "oc-alpha",
            text: betaReply1,
          }),
      },
      {
        name: "beta-reply-restart",
        when: (req) =>
          req.anyMessageContains("BETA_SESSION_TAG") &&
          req.lastToolResult("hyp_inbox")?.text.includes(dmPayloadAfterRestart) === true,
        do: (req) =>
          callTool(req, "hyp_send", {
            to: "oc-alpha",
            text: betaReplyRestart,
          }),
      },
      {
        name: "beta-reply-done",
        when: (req) =>
          req.anyMessageContains("BETA_SESSION_TAG") &&
          Boolean(req.lastToolResult("hyp_send")?.json) &&
          !req.lastToolResult("hyp_send")?.isError,
        do: () => emitText("BETA_ACKED_OK"),
      },

      // Alpha wakes in-place to receive Beta's reply -> reads `hyp_inbox()` -> completes cleanly (zero ping-pong)!
      {
        name: "alpha-wake-read-inbox",
        when: (req) =>
          req.anyMessageContains("ALPHA_SESSION_TAG") &&
          req.lastUserText.includes("<hyphae-inbox") &&
          req.lastToolResults.length === 0,
        assert: (req) => {
          assert.equal(
            req.anyMessageContains("BETA_SESSION_TAG"),
            false,
            `Alpha wake MUST stay strictly inside agent:main:alpha`,
          );
          assert.equal(
            req.lastUserText.includes(betaReply1),
            false,
            `Alpha wake digest MUST be metadata-only before hyp_inbox`,
          );
        },
        do: (req) => callTool(req, "hyp_inbox", {}),
      },
      {
        name: "alpha-wake-done",
        when: (req) =>
          req.anyMessageContains("ALPHA_SESSION_TAG") &&
          Boolean(req.lastToolResult("hyp_inbox")?.json),
        do: () => emitText("ALPHA_RECEIVED_REPLY_OK"),
      },
    ]);

    const keyAlpha = "agent:main:alpha";
    const keyBeta = "agent:main:beta";

    // Enroll BOTH sessions concurrently / back-to-back via real Gateway + real `before_tool_call` -> non-ephemeral `hyp mcp`!
    const alphaEnroll = await oc.runAgentTurn(keyAlpha, "ALPHA_SESSION_TAG please join mesh as oc-alpha.");
    assert.equal(alphaEnroll.ok, true, `alpha enroll failed: ${JSON.stringify(alphaEnroll)}`);
    assert.ok(alphaEnroll.final.includes("ENROLLED_ALPHA_OK"), `unexpected alpha reply: ${alphaEnroll.final}`);

    const betaEnroll = await oc.runAgentTurn(keyBeta, "BETA_SESSION_TAG please join mesh as oc-beta.");
    assert.equal(betaEnroll.ok, true, `beta enroll failed: ${JSON.stringify(betaEnroll)}`);
    assert.ok(betaEnroll.final.includes("ENROLLED_BETA_OK"), `unexpected beta reply: ${betaEnroll.final}`);

    // Verify ZERO split-brain UUIDs and `transportKind: "openclaw_plugin"` in `hyp inspect --all --json`!
    const inspectAfterEnroll = await hyp.inspect({ all: true });
    const sessions = extractSessionsFromInspect(inspectAfterEnroll.json);
    assert.equal(
      sessions.length,
      2,
      `Expected EXACTLY 2 logical Hyphae sessions (zero split-brain ephemeral sessions!), got ${sessions.length}: ${JSON.stringify(sessions)}`,
    );
    const alphaSess = sessions.find((s) => s.handle === "oc-alpha");
    const betaSess = sessions.find((s) => s.handle === "oc-beta");
    assert.ok(alphaSess, `missing @oc-alpha in inspect: ${JSON.stringify(sessions)}`);
    assert.ok(betaSess, `missing @oc-beta in inspect: ${JSON.stringify(sessions)}`);
    assert.equal(alphaSess.sessionId, `openclaw:${keyAlpha}`);
    assert.equal(betaSess.sessionId, `openclaw:${keyBeta}`);
    assert.equal(
      betaSess.transportKind,
      "openclaw_plugin",
      `expected native openclaw_plugin wake transport on @oc-beta, got: ${JSON.stringify(betaSess)}`,
    );
    assert.equal(betaSess.hasLiveTransport, true);

    // 4. Live DM from `@oc-alpha` -> `@oc-beta` wakes ONLY `agent:main:beta` in-place via native `hyphae-wake`!
    const turnsBeforeDm = shim.getTurns("openclaw").length;
    const sendTurn = await oc.runAgentTurn(keyAlpha, "SEND_DM1_TO_BETA send the message now.");
    assert.equal(sendTurn.ok, true, `alpha send failed: ${JSON.stringify(sendTurn)}`);

    // Wait deterministically for `@oc-beta` to wake in-place, read `hyp_inbox`, and reply `ACK:...`!
    const betaAckTurn = await shim.awaitTurn(
      "openclaw",
      (turn) => turn.ruleName === "beta-reply-done" && turn.id > turnsBeforeDm,
      25_000,
    );
    assert.ok(betaAckTurn, "expected @oc-beta to complete wake -> hyp_inbox -> hyp_send reply");

    // Verify ZERO `cron:*` or ghost sessions exist in OpenClaw Gateway!
    const gwSessions = await oc.listSessions();
    const sessionKeys = gwSessions.map((s: any) => String(s?.key ?? s?.sessionKey ?? s?.id ?? ""));
    const cronSessions = sessionKeys.filter((k) => k.includes("cron:"));
    assert.deepEqual(
      cronSessions,
      [],
      `OpenClaw Gateway MUST NEVER spawn cron:* sessions on Hyphae wake! Sessions: ${JSON.stringify(sessionKeys)}`,
    );
    assert.ok(
      sessionKeys.some((k) => k === keyAlpha),
      `expected ${keyAlpha} in gateway sessions: ${JSON.stringify(sessionKeys)}`,
    );
    assert.ok(
      sessionKeys.some((k) => k === keyBeta),
      `expected ${keyBeta} in gateway sessions: ${JSON.stringify(sessionKeys)}`,
    );
    assert.equal(
      sessionKeys.length,
      2,
      `expected strictly 2 OpenClaw sessions (zero ghost sessions), got: ${JSON.stringify(sessionKeys)}`,
    );

    // Verify ZERO bleed into `agent:main:alpha` (no wake turn ran for alpha with beta's DM payload)!
    const alphaWakeTurnsWithBetaPayload = shim
      .getTurns("openclaw")
      .filter(
        (turn) =>
          turn.request.lastUserText.includes("<hyphae-inbox") &&
          turn.request.rawBody.includes("ALPHA_SESSION_TAG") &&
          turn.request.rawBody.includes('handle="oc-beta"'),
      );
    assert.deepEqual(alphaWakeTurnsWithBetaPayload, [], "zero cross-session wake bleed into alpha");

    // 5. Daemon restart survival: restart `hyp daemon` while OpenClaw Gateway stays running!
    //    `hyphae-wake` service reconnects automatically (1s backoff) and delivers post-restart DM!
    await daemon.restart();
    // Wait for OpenClaw's `hyphae-wake` service to reconnect to restarted `connector.sock`!
    await waitForCondition(async () => {
      const ins = await hyp.inspect({ handle: "oc-beta", allowFailure: true });
      const list = extractSessionsFromInspect(ins.json);
      return list.some((s) => s.handle === "oc-beta" && s.transportKind === "openclaw_plugin" && s.hasLiveTransport);
    }, 10_000, "hyphae-wake service reconnect after daemon restart", 150);

    const turnsBeforeRestartDm = shim.getTurns("openclaw").length;
    await hyp.send("external-tester", "oc-beta", dmPayloadAfterRestart);

    const betaRestartReply = await shim.awaitTurn(
      "openclaw",
      (turn) =>
        turn.ruleName === "beta-reply-done" &&
        turn.id > turnsBeforeRestartDm &&
        turn.request.rawBody.includes(dmPayloadAfterRestart),
      25_000,
    );
    assert.ok(betaRestartReply, "expected @oc-beta to wake and deliver DM after daemon restart");

    // 6. Missing/closed session rejection (`createIfMissing: false` -> zero ghost sessions, unread preserved in SQLite)!
    await oc.deleteSession(keyBeta);
    const sessionsAfterDelete = await oc.listSessions();
    const keysAfterDelete = sessionsAfterDelete.map((s: any) => String(s?.key ?? s?.sessionKey ?? s?.id ?? ""));
    assert.equal(
      keysAfterDelete.includes(keyBeta),
      false,
      `expected ${keyBeta} deleted from Gateway before missing-session test: ${JSON.stringify(keysAfterDelete)}`,
    );

    const turnsBeforeMissingDm = shim.getTurns("openclaw").length;
    await hyp.send("external-tester", "oc-beta", dmPayloadMissing);

    // Wait briefly so wake attempt completes and fails closed with `openclaw_session_missing`.
    await new Promise((r) => setTimeout(r, 1_500));

    // Assert NO ghost session was recreated in OpenClaw Gateway!
    const sessionsAfterMissingDm = await oc.listSessions();
    const keysAfterMissingDm = sessionsAfterMissingDm.map((s: any) =>
      String(s?.key ?? s?.sessionKey ?? s?.id ?? ""),
    );
    assert.equal(
      keysAfterMissingDm.includes(keyBeta),
      false,
      `Missing session wake MUST NOT recreate ghost session ${keyBeta}: ${JSON.stringify(keysAfterMissingDm)}`,
    );
    assert.equal(
      keysAfterMissingDm.some((k) => k.includes("cron:")),
      false,
      `Missing session wake MUST NOT spawn cron:* session: ${JSON.stringify(keysAfterMissingDm)}`,
    );
    assert.equal(
      shim.getTurns("openclaw").length,
      turnsBeforeMissingDm,
      "Missing session wake MUST NOT invoke LLM on a ghost session",
    );

    // Assert unread message is safely preserved in Hyphae's SQLite mailbox!
    const inspectMissing = await hyp.inspect({ handle: "oc-beta" });
    const betaAfterMissing = extractSessionsFromInspect(inspectMissing.json)[0];
    const preservedQueued =
      betaAfterMissing?.counts?.queued ??
      betaAfterMissing?.unreadBreakdown?.messages ??
      0;
    assert.ok(
      preservedQueued >= 1,
      `Expected unread DM preserved in SQLite when OpenClaw session missing: ${JSON.stringify(betaAfterMissing)}`,
    );
    assert.equal(
      betaAfterMissing?.counts?.unnotified,
      1,
      `Expected missing-session DM to remain unnotified in SQLite: ${JSON.stringify(betaAfterMissing)}`,
    );

    // 7. All 5 always-on llm-shim invariant auditors MUST be 100% clean!
    shim.assertAllClean();
  });
});
