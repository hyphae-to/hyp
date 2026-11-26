/**
 * Real black-box Claude Code (`claude`) integration suite.
 *
 * Exercises the REAL `claude` CLI (`claude -p --session-id <uuid>`, `--resume <uuid>`)
 * configured via `hyp setup --harness claude --claude-config-dir <tmp>` pointed at our
 * loopback `LlmShimServer` (`ANTHROPIC_BASE_URL`) and compiled `hyp` binary (`HYP_BIN`).
 *
 * Verifies:
 *  1. Verified caller binding via real `PreToolUse` -> `hyp_mesh(join)` -> `hyp_send`
 *     (plus compact 4-tool MCP schema audit).
 *  2. Deterministic tool-boundary latch (`pauseUntil(gate)`) proving:
 *     - `PostToolUse` HOLDS `queue` DMs mid-turn (never leaks mid-turn!)
 *     - `PostToolUse` IMMEDIATELY injects an `interrupt` digest mid-turn.
 *     - `Stop` hook flushes the held `queue` DM cleanly on TurnEnd with ZERO duplicates!
 *  3. Multi-session isolation (`claude` Session A vs Session B sharing one `hyp daemon`,
 *     strict per-session routing and zero cross-session bleed).
 */

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { HypCli } from "../lib/hyp-cli.ts";
import { ClaudeHarness, resolveClaudeBin } from "../lib/harnesses/claude.ts";
import {
  LlmShimServer,
  callTool,
  createGate,
  emitText,
  pauseUntil,
} from "../lib/llm-shim/index.ts";
import { withSandbox } from "../lib/sandbox.ts";

function extractSessionsFromInspect(inspectJson: any): any[] {
  const data = inspectJson?.data ?? inspectJson ?? {};
  if (Array.isArray(data.sessions)) return data.sessions;
  if (Array.isArray(data.items)) return data.items;
  if (data.session) return [data.session];
  return [];
}

test("Real Claude Code: verified PreToolUse enrollment, tool-boundary pauseUntil(gate) queue-hold / interrupt-inject / Stop-flush, and zero duplicates", async (t) => {
  const claudeBin = resolveClaudeBin();
  if (!claudeBin) {
    t.skip("claude binary not found (set CLAUDE_BIN)");
    return;
  }

  await withSandbox("claude-latch-e2e", async (sandbox) => {
    const hyp = new HypCli(sandbox);
    await hyp.onboard({ nodeId: "claude-itest@local", noSkills: true, noCommands: true });
    await hyp.startDaemon();

    const shim = await LlmShimServer.start({
      sandbox,
      auditors: {
        allowBridge: false,
        allowKv: false,
        allowedRoles: ["claude-main"],
      },
    });

    const queuePayload = "CLAUDE_QUEUE_HELD_MIDTURN_301";
    const interruptPayload = "CLAUDE_INTERRUPT_PREEMPT_402";
    shim.auditors.registerUntrustedPayload("dm-queue", queuePayload);
    shim.auditors.registerUntrustedPayload("dm-interrupt", interruptPayload);

    const sampleFile = path.join(sandbox.paths.workspaceDir, "note.txt");
    fs.writeFileSync(sampleFile, "hello from hermetic workspace\n");

    const claude = await ClaudeHarness.create({
      sandbox,
      hyp,
      shim,
      claudeBin,
      role: "claude-main",
    });

    const peerNormal = await hyp.openPeer("bob");
    const peerVip = await hyp.openPeer("vip");
    const receiverPeer = await hyp.openPeer("sink");

    const gateBeforeRead1 = createGate("before-read-1");
    const gateBeforeRead2 = createGate("before-read-2");

    let sawRead1ResultWithoutQueue = false;
    let sawInterruptInPostToolUse = false;
    let sawQueueInStopContinuation = false;

    shim.script("claude-main", [
      // Load deferred Hyphae MCP tool schemas via Claude Code's native ToolSearch when deferred.
      {
        name: "load-hyphae-tools",
        once: true,
        when: (req) => req.isToolDeferred("hyp_mesh"),
        do: (req) =>
          callTool(req, "ToolSearch", {
            query: "select:mcp__hyphae__hyp_mesh,mcp__hyphae__hyp_send,mcp__hyphae__hyp_inbox,mcp__hyphae__hyp_stream",
          }),
      },
      // Turn 0/1: Enroll via real PreToolUse -> mcp__hyphae__hyp_mesh(join)
      {
        name: "enroll",
        once: true,
        when: (req) =>
          !req.isToolDeferred("hyp_mesh") && req.anyMessageContains("START_LATCH_TEST"),
        do: (req) => callTool(req, "hyp_mesh", { action: "join", handle: "claude-latch" }),
      },
      // Turn 1: After `hyp_mesh` succeeds, PAUSE on `gateBeforeRead1` so test can inject a `queue` DM
      //         while Claude is mid-turn, then release to issue `Read(note.txt)` -> triggers `PostToolUse`!
      {
        name: "pause-then-read-1",
        once: true,
        when: (req) => req.lastToolResult("hyp_mesh")?.json?.handle === "claude-latch",
        do: (req) =>
          pauseUntil(gateBeforeRead1, callTool(req, "Read", { file_path: sampleFile })),
      },
      // Turn 2: `PostToolUse` just ran after `Read` #1!
      //         `queuePayload` MUST be HELD (zero `<hyphae-inbox>`, zero body!).
      //         Now PAUSE on `gateBeforeRead2` so test configures VIP `interrupt` rule + sends `interruptPayload`,
      //         then release to issue `Read(note.txt)` #2 -> triggers `PostToolUse`!
      {
        name: "assert-queue-held-then-pause-read-2",
        once: true,
        when: (req) =>
          Boolean(req.lastToolResult("Read")) && !req.anyMessageContains('urgency="interrupt"'),
        assert: (req) => {
          assert.equal(
            req.rawBody.includes(queuePayload),
            false,
            `PostToolUse MUST HOLD queue DM '${queuePayload}' mid-turn instead of injecting it!`,
          );
          assert.equal(
            req.anyMessageContains("<hyphae-inbox "),
            false,
            `PostToolUse #1 MUST NOT emit a digest for a fresh queue DM before long-turn interval!`,
          );
          sawRead1ResultWithoutQueue = true;
        },
        do: (req) =>
          pauseUntil(gateBeforeRead2, callTool(req, "Read", { file_path: sampleFile })),
      },
      // Turn 3: `PostToolUse` just ran after `Read` #2!
      //         RFC 0004: `PostToolUse` injects a metadata-only `<hyphae-inbox ... urgency="interrupt">`
      //         digest for `@vip` (ZERO `interruptPayload`, ZERO `queuePayload`!), while `@bob`'s
      //         `queue` DM stays held until `Stop`! Read ONLY `@vip` via `hyp_inbox` (default ack: true).
      {
        name: "assert-interrupt-digest-and-read-vip",
        once: true,
        when: (req) =>
          req.anyMessageContains('urgency="interrupt"') &&
          req.anyMessageContains('from="claude-itest@local/vip"') &&
          !req.anyMessageContains(interruptPayload),
        assert: (req) => {
          assert.equal(
            req.rawBody.includes(interruptPayload),
            false,
            `RFC 0004: PostToolUse digest MUST NEVER leak raw interrupt body '${interruptPayload}'!`,
          );
          assert.equal(
            req.rawBody.includes(queuePayload),
            false,
            `Queue DM '${queuePayload}' MUST STILL be held until Stop hook!`,
          );
          sawInterruptInPostToolUse = true;
        },
        do: (req) =>
          callTool(req, "hyp_inbox", {
            filter: { from: "claude-itest@local/vip" },
          }),
      },
      // Turn 4: `hyp_inbox` returned `@vip`'s `interruptPayload` with structured provenance and acked it!
      //         Emit plain text to trigger the `Stop` hook for `@bob`'s held `queue` DM!
      {
        name: "after-vip-inbox-end-turn",
        once: true,
        when: (req) =>
          req.lastToolResult("hyp_inbox")?.text.includes(interruptPayload) === true &&
          !req.anyMessageContains(queuePayload),
        assert: (req) => {
          const inboxJson = req.lastToolResult("hyp_inbox")?.json;
          assert.equal(inboxJson?.acked, 1, "hyp_inbox must ack by default (RFC 0004 Decision #3)");
          assert.equal(inboxJson?.items?.[0]?.untrusted, true);
          assert.equal(typeof inboxJson?.items?.[0]?.trustTier, "string");
          assert.equal(inboxJson?.items?.[0]?.provenance, undefined);
        },
        do: () => emitText("MID_TURN_DONE_TRIGGERING_STOP"),
      },
      // Turn 5: `Stop` hook blocked TurnEnd with a metadata-only `<hyphae-inbox ... urgency="queue">`
      //         digest for `@bob` (ZERO `queuePayload` body!). Call `hyp_inbox()` (default ack: true)!
      {
        name: "stop-digest-read-queue-inbox",
        once: true,
        when: (req) =>
          req.anyMessageContains('urgency="queue"') &&
          req.anyMessageContains('from="claude-itest@local/bob"') &&
          !req.anyMessageContains(queuePayload),
        assert: (req) => {
          assert.equal(
            req.rawBody.includes(queuePayload),
            false,
            `RFC 0004: Stop continuation digest MUST NEVER leak raw queue body '${queuePayload}'!`,
          );
          sawQueueInStopContinuation = true;
        },
        do: (req) => callTool(req, "hyp_inbox", {}),
      },
      // Turn 6: `hyp_inbox` returned `queuePayload` -> send confirmation DM to `@sink` via `hyp_send`!
      {
        name: "stop-flushed-queue-send-ack",
        once: true,
        when: (req) => req.lastToolResult("hyp_inbox")?.text.includes(queuePayload) === true,
        assert: (req) => {
          const inboxJson = req.lastToolResult("hyp_inbox")?.json;
          assert.equal(inboxJson?.acked, 1, "hyp_inbox must ack by default");
          assert.equal(inboxJson?.unread, 0);
        },
        do: (req) =>
          callTool(req, "hyp_send", {
            to: "sink",
            text: `ACK:${interruptPayload}+${queuePayload}`,
          }),
      },
      // Turn 5: `hyp_send` succeeded -> finish cleanly!
      {
        name: "finish-all",
        when: (req) =>
          Boolean(req.lastToolResult("hyp_send")?.json) && !req.lastToolResult("hyp_send")?.isError,
        do: () => emitText("LATCH_TEST_COMPLETE"),
      },
      // Turn 6 (optional): Stop hook prompts once to arm background `hyp watch`/`hyp wait`.
      {
        name: "ack-waiter-prompt",
        when: (req) => req.lastUserText.includes("no background waiter is running yet"),
        do: () => emitText("STANDING_BY"),
      },
    ]);

    const sessionUuid = crypto.randomUUID();
    const run = claude.spawnPrint("START_LATCH_TEST", {
      sessionId: sessionUuid,
      maxTurns: 14,
      timeoutMs: 60_000,
    });

    // Step 1: Wait deterministically until Claude enrolled and hit `gateBeforeRead1`!
    await gateBeforeRead1.waitForWaiters(1, 30_000);

    // Verify `claude:<uuid>` is enrolled with verified PreToolUse caller in `hyp inspect`!
    const inspectEnrolled = await hyp.inspect({ session: `claude:${sessionUuid}` });
    const enrolledSess = extractSessionsFromInspect(inspectEnrolled.json)[0];
    assert.equal(enrolledSess?.handle, "claude-latch");
    assert.equal(enrolledSess?.sessionId, `claude:${sessionUuid}`);

    // Send a normal `queue` DM from `@bob` while Claude is paused mid-turn, then release `gateBeforeRead1`!
    await peerNormal.send("claude-latch", queuePayload);
    gateBeforeRead1.release();

    // Step 2: Wait deterministically until `Read` #1 + `PostToolUse` finished and hit `gateBeforeRead2`!
    await gateBeforeRead2.waitForWaiters(1, 20_000);

    // Configure an `interrupt` delivery rule for `@vip` and send an `interrupt` DM!
    await hyp.session([
      "--session",
      `claude:${sessionUuid}`,
      "rule",
      "claude-itest@local/vip",
      "interrupt",
    ]);
    await peerVip.send("claude-latch", interruptPayload);
    gateBeforeRead2.release();

    // Step 3: Wait for Claude to finish cleanly (including `Stop` flush + `hyp_send` ACK)!
    const result = await run.done;
    assert.equal(
      result.exitCode,
      0,
      `claude exited with ${result.exitCode}\nSTDOUT:\n${result.stdout.slice(-2000)}\nSTDERR:\n${result.stderr.slice(-2000)}`,
    );
    assert.equal(sawRead1ResultWithoutQueue, true, "must verify queue DM held across PostToolUse #1");
    assert.equal(sawInterruptInPostToolUse, true, "must verify interrupt DM injected on PostToolUse #2");
    assert.equal(sawQueueInStopContinuation, true, "must verify held queue DM flushed on Stop hook");

    // Verify `@sink` received Claude's outbound `hyp_send` confirmation!
    const sinkInbox = await receiverPeer.inbox({ ack: true });
    assert.ok(
      JSON.stringify(sinkInbox).includes(`ACK:${interruptPayload}+${queuePayload}`),
      `Expected @sink to receive Claude's outbound ACK DM, got: ${JSON.stringify(sinkInbox)}`,
    );

    // Verify all 5 always-on llm-shim invariant auditors (including 4-tool MCP schema footprint & zero duplicates)!
    shim.assertAllClean();
  });
});

test("Real Claude Code: multi-session isolation (Session A vs Session B sharing one hyp daemon, zero cross-bleed)", async (t) => {
  const claudeBin = resolveClaudeBin();
  if (!claudeBin) {
    t.skip("claude binary not found (set CLAUDE_BIN)");
    return;
  }

  await withSandbox("claude-multi-session-isolation", async (sandbox) => {
    const hyp = new HypCli(sandbox);
    await hyp.onboard({ nodeId: "claude-multi@local", noSkills: true, noCommands: true });
    await hyp.startDaemon();

    const shim = await LlmShimServer.start({
      sandbox,
      auditors: {
        allowBridge: false,
        allowKv: false,
        allowedRoles: ["claude-a", "claude-b"],
      },
    });

    const msgForA = "SECRET_FOR_SESSION_A_ONLY_511";
    const msgForB = "SECRET_FOR_SESSION_B_ONLY_622";
    shim.auditors.registerUntrustedPayload("dm-a", msgForA);
    shim.auditors.registerUntrustedPayload("dm-b", msgForB);

    const claudeA = await ClaudeHarness.create({
      sandbox,
      hyp,
      shim,
      claudeBin,
      role: "claude-a",
      profileName: "claude-profile-a",
    });
    const claudeB = await ClaudeHarness.create({
      sandbox,
      hyp,
      shim,
      claudeBin,
      role: "claude-b",
      profileName: "claude-profile-b",
    });

    shim.script("claude-a", [
      {
        name: "a-load-tools",
        once: true,
        when: (req) => req.isToolDeferred("hyp_mesh"),
        do: (req) =>
          callTool(req, "ToolSearch", {
            query: "select:mcp__hyphae__hyp_mesh,mcp__hyphae__hyp_send,mcp__hyphae__hyp_inbox",
          }),
      },
      {
        name: "a-enroll",
        once: true,
        when: (req) => !req.isToolDeferred("hyp_mesh") && req.anyMessageContains("ENROLL_A"),
        do: (req) => callTool(req, "hyp_mesh", { action: "join", handle: "claude-a" }),
      },
      {
        name: "a-enroll-done",
        once: true,
        when: (req) => req.lastToolResult("hyp_mesh")?.json?.handle === "claude-a",
        do: () => emitText("A_ENROLLED"),
      },
      {
        name: "a-resume-read-inbox",
        once: true,
        when: (req) => req.anyMessageContains("<hyphae-inbox ") && !req.anyMessageContains(msgForA),
        assert: (req) => {
          assert.equal(req.rawBody.includes(msgForA), false, "RFC 0004: UserPromptSubmit digest MUST NOT leak body");
          assert.equal(req.rawBody.includes(msgForB), false, "Session A MUST NEVER see Session B's DM");
        },
        do: (req) => callTool(req, "hyp_inbox", {}),
      },
      {
        name: "a-resume-reply",
        when: (req) => req.anyMessageContains(msgForA),
        assert: (req) => {
          assert.equal(req.rawBody.includes(msgForB), false, "Session A MUST NEVER see Session B's DM");
        },
        do: () => emitText("A_GOT_OWN_DM"),
      },
    ]);

    shim.script("claude-b", [
      {
        name: "b-load-tools",
        once: true,
        when: (req) => req.isToolDeferred("hyp_mesh"),
        do: (req) =>
          callTool(req, "ToolSearch", {
            query: "select:mcp__hyphae__hyp_mesh,mcp__hyphae__hyp_send,mcp__hyphae__hyp_inbox",
          }),
      },
      {
        name: "b-enroll",
        once: true,
        when: (req) => !req.isToolDeferred("hyp_mesh") && req.anyMessageContains("ENROLL_B"),
        do: (req) => callTool(req, "hyp_mesh", { action: "join", handle: "claude-b" }),
      },
      {
        name: "b-enroll-done",
        once: true,
        when: (req) => req.lastToolResult("hyp_mesh")?.json?.handle === "claude-b",
        do: () => emitText("B_ENROLLED"),
      },
      {
        name: "b-resume-read-inbox",
        once: true,
        when: (req) => req.anyMessageContains("<hyphae-inbox ") && !req.anyMessageContains(msgForB),
        assert: (req) => {
          assert.equal(req.rawBody.includes(msgForB), false, "RFC 0004: UserPromptSubmit digest MUST NOT leak body");
          assert.equal(req.rawBody.includes(msgForA), false, "Session B MUST NEVER see Session A's DM");
        },
        do: (req) => callTool(req, "hyp_inbox", {}),
      },
      {
        name: "b-resume-reply",
        when: (req) => req.anyMessageContains(msgForB),
        assert: (req) => {
          assert.equal(req.rawBody.includes(msgForA), false, "Session B MUST NEVER see Session A's DM");
        },
        do: () => emitText("B_GOT_OWN_DM"),
      },
    ]);

    const uuidA = crypto.randomUUID();
    const uuidB = crypto.randomUUID();

    // Run Session A and Session B CONCURRENTLY against the same `hyp daemon`!
    const [resA1, resB1] = await Promise.all([
      claudeA.runPrint("ENROLL_A", { sessionId: uuidA, maxTurns: 5 }),
      claudeB.runPrint("ENROLL_B", { sessionId: uuidB, maxTurns: 5 }),
    ]);
    assert.equal(resA1.exitCode, 0, `Session A failed: ${resA1.stderr}`);
    assert.equal(resB1.exitCode, 0, `Session B failed: ${resB1.stderr}`);

    // Verify `hyp inspect --all` tracks strictly 2 distinct `claude:<uuid>` sessions.
    const ins = await hyp.inspect({ all: true });
    const sessions = extractSessionsFromInspect(ins.json);
    assert.equal(sessions.length, 2, `Expected 2 Claude sessions: ${JSON.stringify(sessions)}`);
    assert.ok(sessions.some((s) => s.sessionId === `claude:${uuidA}` && s.handle === "claude-a"));
    assert.ok(sessions.some((s) => s.sessionId === `claude:${uuidB}` && s.handle === "claude-b"));

    // Send targeted DMs to each session independently.
    const dispatcher = await hyp.openPeer("dispatcher");
    await dispatcher.send("claude-a", msgForA);
    await dispatcher.send("claude-b", msgForB);

    // Resume both sessions concurrently -> `UserPromptSubmit` hook injects ONLY each session's own `<hyphae-inbox>` digest!
    const [resA2, resB2] = await Promise.all([
      claudeA.runPrint("CHECK_A", { sessionId: uuidA, resume: true, maxTurns: 6 }),
      claudeB.runPrint("CHECK_B", { sessionId: uuidB, resume: true, maxTurns: 6 }),
    ]);
    assert.equal(resA2.exitCode, 0, `Session A resume failed: ${resA2.stderr}`);
    assert.equal(resB2.exitCode, 0, `Session B resume failed: ${resB2.stderr}`);

    const aSawOwn = shim.getTurns("claude-a").some((tr) => tr.request.rawBody.includes(msgForA));
    const bSawOwn = shim.getTurns("claude-b").some((tr) => tr.request.rawBody.includes(msgForB));
    const aSawB = shim.getTurns("claude-a").some((tr) => tr.request.rawBody.includes(msgForB));
    const bSawA = shim.getTurns("claude-b").some((tr) => tr.request.rawBody.includes(msgForA));

    assert.equal(aSawOwn, true, "Session A must receive its own DM");
    assert.equal(bSawOwn, true, "Session B must receive its own DM");
    assert.equal(aSawB, false, "Session A MUST NOT see Session B's DM");
    assert.equal(bSawA, false, "Session B MUST NOT see Session A's DM");

    shim.assertAllClean();
  });
});
