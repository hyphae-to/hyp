/**
 * Real black-box Codex CLI (`codex`) integration suite.
 *
 * Exercises the REAL `codex` binary (`0.172.0+`) configured strictly via
 * `hyp setup --harness codex` + `[model_providers.fakebrain]` (`wire_api = "responses"`):
 *
 *  1. `codex exec` lifecycle hooks (`SessionStart`, `PreToolUse`, `PostToolUse`, `Stop`),
 *     real `$CODEX_HOME/sessions/.../rollout-<ts>-<uuid>.jsonl` verification, refusal to auto-attach
 *     `codex_queue` on non-interactive `codex exec` rollouts (#35), strict `UNTRUSTED_PROVENANCE`
 *     on Codex `role: "developer"` hook injections (#23), and deterministic mid-turn `pauseUntil(gate)`
 *     queue-hold -> interrupt-inject -> `Stop` flush with zero duplicates!
 *  2. Live interactive Codex PTY + real `codex queue --thread <uuid>` idle DM wakeup
 *     (metadata-only `<hyphae-wake>` nudge -> `hyp_inbox` -> `hyp_send` reply), automatic zero-pending
 *     transport rehydration across daemon restart (#34), AND Tier 4 cold-revival
 *     `deliveryRetry.codexResume` fail-closed (`false`) vs opt-in (`true`)!
 */

import { waitForCondition } from "../lib/util.ts";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import {
  CodexHarness,
  findCodexRolloutFiles,
  resolveCodexBin,
} from "../lib/harnesses/codex.ts";
import { extractSessionsFromInspect } from "../lib/harnesses/types.ts";
import { HypCli } from "../lib/hyp-cli.ts";
import {
  LlmShimServer,
  callTool,
  createGate,
  emitText,
  pauseUntil,
} from "../lib/llm-shim/index.ts";
import { withSandbox } from "../lib/sandbox.ts";

test("Real Codex CLI: hyp setup, rollout JSONL verification, codex exec no auto-attach (#35), strict developer provenance (#23), and mid-turn PostToolUse/Stop latch", async (t) => {
  const codexBin = resolveCodexBin();
  if (!codexBin) {
    t.skip("codex binary not found (set CODEX_BIN)");
    return;
  }

  await withSandbox(
    "codex-exec-hooks-latch",
    { extraPathDirs: [path.dirname(codexBin)] },
    async (sandbox) => {
      const hyp = new HypCli(sandbox);
      await hyp.onboard({ nodeId: "codex-itest@local", noSkills: true, noCommands: true });
      await hyp.startDaemon();

      const shim = await LlmShimServer.start({
        sandbox,
        auditors: {
          allowBridge: false,
          allowKv: false,
          allowedRoles: ["codex-exec"],
        },
      });

      const queuePayload = "CODEX_QUEUE_HELD_MIDTURN_711";
      const interruptPayload = "CODEX_INTERRUPT_PREEMPT_822";
      shim.auditors.registerUntrustedPayload("cx-queue", queuePayload);
      shim.auditors.registerUntrustedPayload("cx-interrupt", interruptPayload);

      const codex = await CodexHarness.create({
        sandbox,
        hyp,
        shim,
        codexBin,
        role: "codex-exec",
      });

      // Verify `hyp setup --harness codex` created both config.toml MCP block and hooks.json!
      assert.ok(fs.existsSync(codex.configPath), "config.toml must exist");
      assert.ok(fs.existsSync(codex.hooksPath), "hooks.json must exist");
      const hooksDoc = JSON.parse(fs.readFileSync(codex.hooksPath, "utf8"));
      for (const ev of ["SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "Stop"]) {
        assert.ok(hooksDoc.hooks?.[ev], `hooks.json must wire ${ev}`);
      }

      const peerNormal = await hyp.openPeer("bob");
      const peerVip = await hyp.openPeer("vip");
      const sink = await hyp.openPeer("sink");

      const gateBeforeCmd1 = createGate("codex-before-cmd-1");
      const gateBeforeCmd2 = createGate("codex-before-cmd-2");

      let sawCmd1WithoutQueue = false;
      let sawInterruptInPostToolUse = false;
      let sawQueueInStopContinuation = false;

      shim.script("codex-exec", [
        // Ignore Codex's background thread-title generation turn (`tools: []`).
        {
          name: "ignore-title",
          when: (req) => req.advertisedTools.length === 0,
          do: () => emitText("Codex Latch Test"),
        },
        {
          name: "cx-enroll",
          once: true,
          when: (req) =>
            req.advertisedTools.some((tool) => tool.canonicalHyphaeName === "hyp_mesh") &&
            req.anyMessageContains("START_CODEX_LATCH"),
          do: (req) => callTool(req, "hyp_mesh", { action: "join", handle: "cx-latch" }),
        },
        {
          name: "pause-then-cmd-1",
          once: true,
          when: (req) => req.lastToolResult("hyp_mesh")?.json?.handle === "cx-latch",
          do: (req) =>
            pauseUntil(gateBeforeCmd1, callTool(req, "exec_command", { cmd: "echo STEP_ONE" })),
        },
        {
          name: "assert-queue-held-then-cmd-2",
          once: true,
          when: (req) =>
            Boolean(req.lastToolResult("exec_command")?.text.includes("STEP_ONE")) &&
            !req.anyMessageContains('urgency="interrupt"'),
          assert: (req) => {
            assert.equal(
              req.rawBody.includes(queuePayload),
              false,
              `Codex PostToolUse MUST hold queue DM '${queuePayload}' mid-turn!`,
            );
            assert.equal(
              req.anyMessageContains("<hyphae-inbox "),
              false,
              `Codex PostToolUse #1 MUST NOT emit a digest for a fresh queue DM!`,
            );
            sawCmd1WithoutQueue = true;
          },
          do: (req) =>
            pauseUntil(gateBeforeCmd2, callTool(req, "exec_command", { cmd: "echo STEP_TWO" })),
        },
        {
          name: "assert-interrupt-digest-and-read-vip",
          once: true,
          when: (req) =>
            req.anyMessageContains('urgency="interrupt"') &&
            req.anyMessageContains('from="codex-itest@local/vip"') &&
            !req.anyMessageContains(interruptPayload),
          assert: (req) => {
            assert.equal(
              req.rawBody.includes(interruptPayload),
              false,
              `RFC 0004: Codex PostToolUse digest MUST NEVER leak raw interrupt body '${interruptPayload}'!`,
            );
            assert.equal(
              req.rawBody.includes(queuePayload),
              false,
              "Queue DM must remain held until Stop hook",
            );
            sawInterruptInPostToolUse = true;
          },
          do: (req) =>
            callTool(req, "hyp_inbox", {
              filter: { from: "codex-itest@local/vip" },
            }),
        },
        {
          name: "after-vip-inbox-end-turn",
          once: true,
          when: (req) =>
            req.lastToolResult("hyp_inbox")?.text.includes(interruptPayload) === true &&
            !req.anyMessageContains(queuePayload),
          assert: (req) => {
            const inboxJson = req.lastToolResult("hyp_inbox")?.json;
            assert.equal(inboxJson?.acked, 1, "hyp_inbox must ack by default");
            assert.equal(inboxJson?.items?.[0]?.untrusted, true);
            assert.equal(typeof inboxJson?.items?.[0]?.trustTier, "string");
            assert.equal(inboxJson?.items?.[0]?.provenance, undefined);
          },
          do: () => emitText("CODEX_END_TURN_TO_TRIGGER_STOP"),
        },
        {
          name: "stop-digest-read-queue-inbox",
          once: true,
          when: (req) =>
            req.anyMessageContains('urgency="queue"') &&
            req.anyMessageContains('from="codex-itest@local/bob"') &&
            !req.anyMessageContains(queuePayload),
          assert: (req) => {
            assert.equal(
              req.rawBody.includes(queuePayload),
              false,
              `RFC 0004: Codex Stop digest MUST NEVER leak raw queue body '${queuePayload}'!`,
            );
            sawQueueInStopContinuation = true;
          },
          do: (req) => callTool(req, "hyp_inbox", {}),
        },
        {
          name: "stop-flushed-queue-send-ack",
          once: true,
          when: (req) => req.lastToolResult("hyp_inbox")?.text.includes(queuePayload) === true,
          do: (req) =>
            callTool(req, "hyp_send", {
              to: "sink",
              text: `CODEX_ACK:${interruptPayload}+${queuePayload}`,
            }),
        },
        {
          name: "finish-after-send",
          when: (req) =>
            Boolean(req.lastToolResult("hyp_send")?.json) &&
            !req.lastToolResult("hyp_send")?.isError,
          do: () => emitText("CODEX_LATCH_COMPLETE"),
        },
        {
          name: "ack-waiter-prompt",
          when: (req) => req.anyMessageContains("no background waiter is running yet"),
          do: () => emitText("CODEX_STANDING_BY"),
        },
      ]);

      const run = codex.spawnExec("START_CODEX_LATCH");

      // Step 1: Wait until Codex enrolled and paused before exec_command #1.
      await gateBeforeCmd1.waitForWaiters(1, 30_000);

      // Verify `hyp inspect` shows enrolled `codex:<uuid>` + rollout file exists on disk!
      const ins = await hyp.inspect({ handle: "cx-latch" });
      const sess = extractSessionsFromInspect(ins.json)[0];
      assert.ok(sess, `expected enrolled cx-latch session: ${JSON.stringify(ins.json)}`);
      assert.ok(sess.sessionId.startsWith("codex:"), `expected codex:<uuid>, got ${sess.sessionId}`);
      const threadUuid = sess.sessionId.slice("codex:".length);

      const rollouts = findCodexRolloutFiles(codex.codexHome);
      assert.ok(
        rollouts.some((f) => f.includes(threadUuid)),
        `expected real Codex rollout JSONL for ${threadUuid} in ${JSON.stringify(rollouts)}`,
      );
      // Issue #35: Non-interactive `codex exec` rollouts MUST NOT auto-attach `codex_queue`
      // even when `codex` is on PATH and the rollout JSONL exists!
      assert.notEqual(
        sess.transportKind,
        "codex_queue",
        `Non-interactive codex exec MUST NOT auto-attach codex_queue (#35), got: ${JSON.stringify(sess)}`,
      );
      assert.equal(
        sess.hasLiveTransport,
        false,
        `Non-interactive codex exec MUST have hasLiveTransport=false (#35), got: ${JSON.stringify(sess)}`,
      );

      // Inject a `queue` DM while Codex is mid-turn, then release exec_command #1.
      await peerNormal.send("cx-latch", queuePayload);
      gateBeforeCmd1.release();

      // Step 2: Wait until PostToolUse #1 completed (holding queue DM) and paused before exec_command #2.
      await gateBeforeCmd2.waitForWaiters(1, 20_000);

      // Configure `@vip` -> `interrupt` rule and send an `interrupt` DM!
      await hyp.session([
        "--session",
        sess.sessionId,
        "rule",
        "codex-itest@local/vip",
        "interrupt",
      ]);
      await peerVip.send("cx-latch", interruptPayload);
      gateBeforeCmd2.release();

      // Step 3: Wait for Codex to complete Stop flush and outbound `hyp_send` ACK!
      const result = await run.done;
      assert.equal(
        result.exitCode,
        0,
        `codex exec failed (exit=${result.exitCode})\nSTDOUT:\n${result.stdout.slice(-2000)}\nSTDERR:\n${result.stderr.slice(-2000)}`,
      );
      assert.equal(sawCmd1WithoutQueue, true, "PostToolUse #1 must hold queue DM");
      assert.equal(sawInterruptInPostToolUse, true, "PostToolUse #2 must inject interrupt DM");
      assert.equal(sawQueueInStopContinuation, true, "Stop hook must flush held queue DM");

      const sinkInbox = await sink.inbox({ ack: true });
      assert.ok(
        JSON.stringify(sinkInbox).includes(`CODEX_ACK:${interruptPayload}+${queuePayload}`),
        `Expected @sink to receive Codex ACK DM, got: ${JSON.stringify(sinkInbox)}`,
      );

      shim.assertAllClean();
    },
  );
});

test("Real Codex CLI: live interactive PTY `codex queue --thread` wakeup + Tier 4 codexResume fail-closed vs opt-in", async (t) => {
  const codexBin = resolveCodexBin();
  if (!codexBin) {
    t.skip("codex binary not found (set CODEX_BIN)");
    return;
  }

  await withSandbox(
    "codex-pty-queue-and-resume",
    { extraPathDirs: [path.dirname(codexBin)] },
    async (sandbox) => {
      const hyp = new HypCli(sandbox);
      await hyp.onboard({ nodeId: "codex-pty@local", noSkills: true, noCommands: true });
      const daemon = await hyp.startDaemon();

      const shim = await LlmShimServer.start({
        sandbox,
        auditors: {
          allowBridge: false,
          allowKv: false,
          // Note: `<hyphae-wake>` tag itself is strictly audited metadata-only on every role;
          // Codex's `UserPromptSubmit` hook drains queued messages into developer context on submit!
          allowedRoles: ["codex-pty"],
        },
      });

      const liveDmPayload = "CODEX_LIVE_QUEUE_WAKE_SECRET_901";
      const postRestartDmPayload = "CODEX_POST_RESTART_ZERO_PENDING_WAKE_904";
      const coldStoppedPayload = "CODEX_COLD_FAILCLOSED_902";
      const optInResumePayload = "CODEX_OPTIN_RESUME_903";
      shim.auditors.registerUntrustedPayload("cx-live-wake", liveDmPayload);
      shim.auditors.registerUntrustedPayload("cx-restart-wake", postRestartDmPayload);
      shim.auditors.registerUntrustedPayload("cx-cold-closed", coldStoppedPayload);
      shim.auditors.registerUntrustedPayload("cx-optin-resume", optInResumePayload);

      const codex = await CodexHarness.create({
        sandbox,
        hyp,
        shim,
        codexBin,
        role: "codex-pty",
      });

      const sender = await hyp.openPeer("alice");

      shim.script("codex-pty", [
        {
          name: "ignore-title",
          when: (req) => req.advertisedTools.length === 0,
          do: () => emitText("Codex PTY Live"),
        },
        {
          name: "pty-enroll",
          once: true,
          when: (req) =>
            req.advertisedTools.some((tool) => tool.canonicalHyphaeName === "hyp_mesh") &&
            req.anyMessageContains("ENROLL_PTY_CODEX"),
          do: (req) => callTool(req, "hyp_mesh", { action: "join", handle: "cx-live-pty" }),
        },
        {
          name: "pty-enroll-done",
          once: true,
          when: (req) => req.lastToolResult("hyp_mesh")?.json?.handle === "cx-live-pty",
          do: () => emitText("CODEX_PTY_READY"),
        },
        {
          name: "pty-reply-after-wake",
          once: true,
          when: (req) =>
            req.anyMessageContains(liveDmPayload) &&
            !req.anyMessageContains(`PTY_ACK:${liveDmPayload}`),
          assert: (req) => {
            // The `<hyphae-wake>` prompt itself MUST be strictly metadata-only!
            assert.equal(
              req.lastUserText.includes(liveDmPayload),
              false,
              "codex queue <hyphae-wake> prompt MUST be strictly metadata-only",
            );
          },
          do: (req) =>
            callTool(req, "hyp_send", {
              to: "alice",
              text: `PTY_ACK:${liveDmPayload}`,
            }),
        },
        {
          name: "pty-reply-after-restart-wake",
          once: true,
          when: (req) =>
            req.anyMessageContains(postRestartDmPayload) &&
            !req.anyMessageContains(`PTY_RESTART_ACK:${postRestartDmPayload}`),
          assert: (req) => {
            assert.equal(
              req.lastUserText.includes(postRestartDmPayload),
              false,
              "post-restart codex queue <hyphae-wake> prompt MUST be strictly metadata-only",
            );
          },
          do: (req) =>
            callTool(req, "hyp_send", {
              to: "alice",
              text: `PTY_RESTART_ACK:${postRestartDmPayload}`,
            }),
        },
        {
          name: "pty-wake-read-inbox",
          when: (req) =>
            req.lastUserText.includes("<hyphae-inbox") && req.lastToolResults.length === 0,
          assert: (req) => {
            assert.equal(
              req.lastUserText.includes(liveDmPayload),
              false,
              "codex queue wake digest MUST be strictly metadata-only prior to hyp_inbox",
            );
            assert.equal(
              req.lastUserText.includes(postRestartDmPayload),
              false,
              "post-restart codex queue wake digest MUST be strictly metadata-only prior to hyp_inbox",
            );
          },
          do: (req) => callTool(req, "hyp_inbox", {}),
        },
        {
          name: "pty-reply-done",
          when: (req) =>
            Boolean(req.lastToolResult("hyp_send")?.json) &&
            !req.lastToolResult("hyp_send")?.isError,
          do: () => emitText("CODEX_PTY_REPLIED"),
        },
      ]);

      // 1. Launch real interactive Codex in a POSIX PTY!
      const ptyProc = codex.spawnInteractivePty("ENROLL_PTY_CODEX please join as cx-live-pty");

      let enrolledSess: any = null;
      await waitForCondition(async () => {
        const ins = await hyp.inspect({ handle: "cx-live-pty", allowFailure: true });
        const row = extractSessionsFromInspect(ins.json)[0];
        if (row?.enrolled && row?.transportKind === "codex_queue" && row?.hasLiveTransport) {
          enrolledSess = row;
          return true;
        }
        return false;
      }, 25_000, "interactive Codex PTY enrollment with codex_queue transport");

      assert.equal(enrolledSess.transportKind, "codex_queue");
      assert.equal(enrolledSess.hasLiveTransport, true);

      // Wait briefly until initial enroll turn completes and Codex settles at idle prompt.
      await shim.awaitTurn("codex-pty", (turn) => turn.ruleName === "pty-enroll-done", 15_000);
      await new Promise((r) => setTimeout(r, 800));

      // 2. Send DM while interactive Codex is idle -> daemon invokes REAL `codex queue --thread <uuid>`!
      await sender.send("cx-live-pty", liveDmPayload);
      await shim.awaitTurn("codex-pty", (turn) => turn.ruleName === "pty-reply-done", 25_000);

      const aliceInbox = await sender.inbox({ ack: true });
      assert.ok(
        JSON.stringify(aliceInbox).includes(`PTY_ACK:${liveDmPayload}`),
        `Expected @alice to receive live Codex PTY reply, got: ${JSON.stringify(aliceInbox)}`,
      );

      // 2b. Issue #34: Restart daemon while interactive Codex PTY is alive with ZERO pending items!
      //     `LocalDaemon` MUST automatically rehydrate `codex_queue` on startup with ZERO manual
      //     hook call, and a subsequent DM MUST wake the live PTY immediately!
      await waitForCondition(async () => {
        const ins = await hyp.inspect({ handle: "cx-live-pty", allowFailure: true });
        const row = extractSessionsFromInspect(ins.json)[0];
        return (row?.counts?.queued ?? 0) === 0;
      }, 5_000, "zero pending items before daemon restart (#34)");

      await daemon.restart();
      await waitForCondition(async () => {
        const ins = await hyp.inspect({ handle: "cx-live-pty", allowFailure: true });
        const row = extractSessionsFromInspect(ins.json)[0];
        return row?.transportKind === "codex_queue" && row?.hasLiveTransport === true;
      }, 10_000, "automatic zero-pending codex_queue rehydration on daemon restart (#34)");

      const turnsBeforeRestartWake = shim.getTurns("codex-pty").length;
      await sender.send("cx-live-pty", postRestartDmPayload);
      await shim.awaitTurn(
        "codex-pty",
        (turn) => turn.ruleName === "pty-reply-done" && turn.id > turnsBeforeRestartWake,
        25_000,
      );
      const aliceInbox2 = await sender.inbox({ ack: true });
      assert.ok(
        JSON.stringify(aliceInbox2).includes(`PTY_RESTART_ACK:${postRestartDmPayload}`),
        `Expected @alice to receive post-restart live Codex PTY reply (#34), got: ${JSON.stringify(aliceInbox2)}`,
      );

      // 3. Tier 4 Cold Revival Fail-Closed (`deliveryRetry.codexResume: false` default):
      //    Kill the live interactive Codex PTY, send a DM, and prove ZERO cold revival spawns!
      await ptyProc.kill(2_000);
      await new Promise((r) => setTimeout(r, 400));

      const turnsAfterKill = shim.getTurns("codex-pty").length;
      await sender.send("cx-live-pty", coldStoppedPayload);
      await new Promise((r) => setTimeout(r, 1_500));

      assert.equal(
        shim.getTurns("codex-pty").length,
        turnsAfterKill,
        "With default codexResume=false, stopped Codex thread MUST NOT trigger unexpected cold LLM turn",
      );

      // Unread DM remains safely preserved in SQLite mailbox (not lost or falsely acked)!
      const insClosed = await hyp.inspect({ handle: "cx-live-pty" });
      const closedRow = extractSessionsFromInspect(insClosed.json)[0];
      assert.ok(
        (closedRow?.counts?.queued ?? 0) >= 1,
        `Stopped Codex DM must stay preserved in SQLite mailbox: ${JSON.stringify(closedRow)}`,
      );

      // 4. Tier 4 Opt-In (`deliveryRetry.codexResume: true`):
      //    Wrap `codex` with a transparent recording shim script in sandbox.paths.binDir that
      //    records exact argv passed by `hyp daemon` and forwards straight to the real `codex` binary!
      const argvLog = path.join(sandbox.paths.tmpDir, "codex-queue-argv.jsonl");
      const recorderWrapper = path.join(sandbox.paths.binDir, "codex");
      fs.writeFileSync(
        recorderWrapper,
        [
          "#!/bin/sh",
          `${JSON.stringify(process.execPath)} -e 'process.stdout.write(JSON.stringify(process.argv.slice(1)) + "\\n")' -- "$@" >> ${JSON.stringify(argvLog)}`,
          `exec ${JSON.stringify(codexBin)} "$@"`,
        ].join("\n") + "\n",
        { mode: 0o700 },
      );

      // Enable `deliveryRetry.codexResume: true` in node.json and restart daemon!
      // Issues #22 + #34: Daemon automatically rehydrates `codex_queue` (with `codexResume=true`)
      // on startup WITHOUT any manual SessionStart hook re-ping AND flushes pending mailbox items!
      const nodeCfg = JSON.parse(fs.readFileSync(hyp.nodeConfigPath, "utf8"));
      nodeCfg.deliveryRetry = {
        ...(nodeCfg.deliveryRetry || {}),
        codexResume: true,
      };
      fs.writeFileSync(hyp.nodeConfigPath, JSON.stringify(nodeCfg, null, 2) + "\n");
      await daemon.restart();

      // Wait for automatic startup transport rehydration (#34) with ZERO manual hook call!
      try {
        await waitForCondition(async () => {
          const ins = await hyp.inspect({ handle: "cx-live-pty", allowFailure: true });
          const row = extractSessionsFromInspect(ins.json)[0];
          return row?.transportKind === "codex_queue" && row?.hasLiveTransport === true;
        }, 10_000, "automatic codex_queue rehydration with codexResume=true (#34)");
      } catch (err) {
        const logData = fs.existsSync(argvLog) ? fs.readFileSync(argvLog, "utf8") : "<no argvLog>";
        const rollouts = findCodexRolloutFiles(codex.codexHome);
        throw new Error(
          `${(err as Error).message} | argvLog=${JSON.stringify(logData)} | codexHome=${codex.codexHome} | rollouts=${JSON.stringify(rollouts)} | wrapper=${fs.existsSync(recorderWrapper)}`,
        );
      }

      // Send another DM (and/or observe startup flush of `coldStoppedPayload`) -> verify daemon passes
      // `--resume` to real `codex queue --thread <uuid>` with strictly metadata-only XML digest!
      const sender2 = await hyp.openPeer("alice-resume");
      await sender2.send("cx-live-pty", optInResumePayload);
      await waitForCondition(
        () =>
          fs.existsSync(argvLog) &&
          fs.readFileSync(argvLog, "utf8").includes("--resume"),
        10_000,
        "hyp daemon invoking `codex queue ... --resume` when deliveryRetry.codexResume=true",
      );

      const recordedCalls: string[][] = fs
        .readFileSync(argvLog, "utf8")
        .trim()
        .split(/\r?\n/)
        .filter(Boolean)
        .map((l) => JSON.parse(l) as string[])
        .filter((args) => args[0] === "queue" && args[1] === "--thread");
      assert.ok(
        recordedCalls.some((args) => {
          const joined = args.join(" ");
          return (
            joined.includes(enrolledSess.sessionId.slice("codex:".length)) &&
            args.includes("--resume") &&
            joined.includes("<hyphae-inbox ") &&
            !joined.includes(coldStoppedPayload) &&
            !joined.includes(optInResumePayload)
          );
        }),
        `Expected real codex queue invocation with --resume and metadata-only <hyphae-inbox> digest, got: ${JSON.stringify(recordedCalls)}`,
      );

      shim.assertAllClean();
    },
  );
});
