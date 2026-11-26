/**
 * Real black-box Codex CLI (`codex`) integration suite.
 *
 * Exercises the REAL `codex` binary (`0.172.0+`) configured strictly via
 * `hyp setup --harness codex` + `[model_providers.fakebrain]` (`wire_api = "responses"`):
 *
 *  1. `codex exec` lifecycle hooks (`SessionStart`, `PreToolUse`, `PostToolUse`, `Stop`),
 *     real `$CODEX_HOME/sessions/.../rollout-<ts>-<uuid>.jsonl` verification, auto-attachment of
 *     `codex_queue` transport, and deterministic mid-turn `pauseUntil(gate)` queue-hold ->
 *     interrupt-inject -> `Stop` flush with zero duplicates!
 *  2. Live interactive Codex PTY + real `codex queue --thread <uuid>` idle DM wakeup
 *     (metadata-only `<hyphae-wake>` nudge -> `hyp_inbox` -> `hyp_send` reply) AND
 *     Tier 4 cold-revival `deliveryRetry.codexResume` fail-closed (`false`) vs opt-in (`true`)!
 */

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
  UNTRUSTED_PROVENANCE_HEADER,
  callTool,
  createGate,
  emitText,
  pauseUntil,
} from "../lib/llm-shim/index.ts";
import { withSandbox } from "../lib/sandbox.ts";

async function waitForCondition(
  predicate: () => Promise<boolean> | boolean,
  timeoutMs = 20_000,
  label = "condition",
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await predicate()) return;
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error(`Timed out after ${timeoutMs}ms waiting for ${label}`);
}

test("Real Codex CLI: hyp setup, rollout JSONL verification, codex_queue auto-attach, and mid-turn PostToolUse/Stop latch", async (t) => {
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
          // ISSUE #23: `crates/hyp-harness/src/hooks.rs` uses v2 packer framing on non-OpenClaw hooks.
          acceptV2PackerHookFraming: true,
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
            !req.anyMessageContains(interruptPayload),
          assert: (req) => {
            assert.equal(
              req.rawBody.includes(queuePayload),
              false,
              `Codex PostToolUse MUST hold queue DM '${queuePayload}' mid-turn!`,
            );
            sawCmd1WithoutQueue = true;
          },
          do: (req) =>
            pauseUntil(gateBeforeCmd2, callTool(req, "exec_command", { cmd: "echo STEP_TWO" })),
        },
        {
          name: "assert-interrupt-and-end-turn",
          once: true,
          when: (req) =>
            req.anyMessageContains(interruptPayload) && !req.anyMessageContains(queuePayload),
          assert: (req) => {
            assert.ok(
              req.rawBody.includes(UNTRUSTED_PROVENANCE_HEADER) ||
                req.rawBody.includes("[hyphae interrupt ·"),
              "Codex interrupt PostToolUse injection must carry Hyphae framing",
            );
            assert.equal(
              req.rawBody.includes(queuePayload),
              false,
              "Queue DM must remain held until Stop hook",
            );
            sawInterruptInPostToolUse = true;
          },
          do: () => emitText("CODEX_END_TURN_TO_TRIGGER_STOP"),
        },
        {
          name: "stop-flushed-queue-send-ack",
          once: true,
          when: (req) => req.anyMessageContains(queuePayload),
          assert: (req) => {
            assert.ok(
              req.rawBody.includes(UNTRUSTED_PROVENANCE_HEADER) ||
                req.rawBody.includes("[hyphae ·"),
              "Codex Stop continuation must carry Hyphae framing",
            );
            sawQueueInStopContinuation = true;
          },
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
      assert.equal(
        sess.transportKind,
        "codex_queue",
        `expected codex_queue auto-attached after rollout verification, got: ${JSON.stringify(sess)}`,
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
          // ISSUE #23: Codex hooks use v2 packer framing.
          acceptV2PackerHookFraming: true,
        },
      });

      const liveDmPayload = "CODEX_LIVE_QUEUE_WAKE_SECRET_901";
      const coldStoppedPayload = "CODEX_COLD_FAILCLOSED_902";
      const optInResumePayload = "CODEX_OPTIN_RESUME_903";
      shim.auditors.registerUntrustedPayload("cx-live-wake", liveDmPayload);
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
          name: "pty-wake-read-inbox",
          once: true,
          when: (req) =>
            req.lastUserText.includes("<hyphae-wake") && req.lastToolResults.length === 0,
          assert: (req) => {
            assert.equal(
              req.lastUserText.includes(liveDmPayload),
              false,
              "codex queue wake nudge MUST be strictly metadata-only prior to hyp_inbox",
            );
          },
          do: (req) => callTool(req, "hyp_inbox", { ack: true }),
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
          `printf '%s\\n' "$*" >> ${JSON.stringify(argvLog)}`,
          `exec ${JSON.stringify(codexBin)} "$@"`,
        ].join("\n") + "\n",
        { mode: 0o700 },
      );

      // Enable `deliveryRetry.codexResume: true` in node.json and restart daemon!
      const nodeCfg = JSON.parse(fs.readFileSync(hyp.nodeConfigPath, "utf8"));
      nodeCfg.deliveryRetry = {
        ...(nodeCfg.deliveryRetry || {}),
        codexResume: true,
      };
      fs.writeFileSync(hyp.nodeConfigPath, JSON.stringify(nodeCfg, null, 2) + "\n");
      await daemon.restart();

      // Re-attach session hints via a lightweight SessionStart hook call (since daemon restarted
      // and in-memory attached push transports are rehydrated lazily on hook/MCP activity — see ISSUE #22).
      await hyp.exec(["hook", "codex", "session-start", "--socket", hyp.socketPath], {
        input: JSON.stringify({
          session_id: enrolledSess.sessionId.slice("codex:".length),
          cwd: sandbox.paths.workspaceDir,
        }),
        env: codex.env,
      });

      // Wait briefly for daemon async transport probe to attach `codex_queue` with `resume=true`.
      try {
        await waitForCondition(async () => {
          const ins = await hyp.inspect({ handle: "cx-live-pty", allowFailure: true });
          const row = extractSessionsFromInspect(ins.json)[0];
          return row?.transportKind === "codex_queue" && row?.hasLiveTransport === true;
        }, 8_000, "codex_queue re-attach with codexResume=true");
      } catch (err) {
        const logData = fs.existsSync(argvLog) ? fs.readFileSync(argvLog, "utf8") : "<no argvLog>";
        const rollouts = findCodexRolloutFiles(codex.codexHome);
        throw new Error(
          `${(err as Error).message} | argvLog=${JSON.stringify(logData)} | codexHome=${codex.codexHome} | rollouts=${JSON.stringify(rollouts)} | wrapper=${fs.existsSync(recorderWrapper)}`,
        );
      }

      // Send DM -> verify daemon passes `--resume` to real `codex queue --thread <uuid>`!
      const sender2 = await hyp.openPeer("alice-resume");
      await sender2.send("cx-live-pty", optInResumePayload);
      await waitForCondition(
        () =>
          fs.existsSync(argvLog) &&
          fs.readFileSync(argvLog, "utf8").includes("--resume"),
        10_000,
        "hyp daemon invoking `codex queue ... --resume` when deliveryRetry.codexResume=true",
      );

      const recordedCalls = fs
        .readFileSync(argvLog, "utf8")
        .trim()
        .split(/\r?\n/)
        .filter((l) => l.startsWith("queue --thread"));
      assert.ok(
        recordedCalls.some(
          (line) =>
            line.includes(enrolledSess.sessionId.slice("codex:".length)) &&
            line.includes("--resume") &&
            line.includes("<hyphae-wake") &&
            !line.includes(optInResumePayload),
        ),
        `Expected real codex queue invocation with --resume and metadata-only wake nudge, got: ${JSON.stringify(recordedCalls)}`,
      );

      shim.assertAllClean();
    },
  );
});
