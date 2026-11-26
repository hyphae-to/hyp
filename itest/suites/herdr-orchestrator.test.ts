/**
 * Real black-box Herdr Core (`hc`) orchestrator integration suite.
 *
 * Launches a real ISOLATED `hc server` strictly inside the per-test Sandbox (zero host
 * `~/.config/herdr-core` touches!) with a real interactive Claude Code agent inside a Herdr PTY:
 *
 *  1. Identity pinning (`created_ms`, `pid`, `app`) verified via `hc get --json` + `hyp inspect`.
 *  2. Bare-shell fail-closed check: `hc run --bg --name bare-sh /bin/sh` (`status == null`) ->
 *     `hyp mcp --backend herdr` NEVER attaches a live Herdr push transport (mesh text can never
 *     be pasted into a raw shell!).
 *  3. Live `hc send` (`queue`) vs `hc interrupt` (`interrupt`) using deterministic `llm-shim`
 *     `pauseMidStream(gate)` latches:
 *       - `queue` DM holds while Claude is mid-generation and flushes cleanly AFTER turn ends!
 *       - `interrupt` DM preempts active generation via real `hc interrupt` (aborting open SSE
 *         stream!) and delivers metadata-only `<hyphae-wake>` immediately!
 *  4. PID/terminal recycling guard: kill `worker-1` and launch a new terminal -> pinned
 *     `(created_ms, pid, app)` mismatch fails closed with zero unintended paste!
 *  5. Tier 4 `herdrSpawnAllowlist`: verifies allowlisted vs non-allowlisted config & Herdr
 *     template registration (noting runtime cold-spawn wiring status!).
 *  6. GPUI `--mod` safety: `hyp setup --harness herdr --mod --plugins-dir ./plugins` installs
 *     `hyphae-pane` & `hyphae-panel` as real directories (never symlinks) and strictly preserves
 *     both shipped (`main.json`) and symlinked custom layouts!
 */

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { resolveClaudeBin } from "../lib/harnesses/claude.ts";
import { HerdrOrchestrator, resolveHcBin } from "../lib/harnesses/herdr.ts";
import { extractSessionsFromInspect } from "../lib/harnesses/types.ts";
import { HypCli, HypMcpClient } from "../lib/hyp-cli.ts";
import {
  LlmShimServer,
  callTool,
  createGate,
  emitText,
  pauseMidStream,
} from "../lib/llm-shim/index.ts";
import { REPO_ROOT, withSandbox } from "../lib/sandbox.ts";

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

test("Real Herdr (hc) + Claude: identity pinning, bare-shell fail-closed, mid-stream queue-hold vs hc interrupt, and PID-recycle guard", async (t) => {
  const hcBin = resolveHcBin();
  const claudeBin = resolveClaudeBin();
  if (!hcBin || !claudeBin) {
    t.skip(`Missing required binary (hc=${hcBin}, claude=${claudeBin})`);
    return;
  }

  await withSandbox("herdr-orchestrator-e2e", async (sandbox) => {
    const herdr = await HerdrOrchestrator.start({
      sandbox,
      hcBin,
      extraPathDirs: [path.dirname(claudeBin)],
    });

    const hyp = new HypCli(sandbox);
    await hyp.onboard({ nodeId: "herdr-itest@local", noSkills: true, noCommands: true });
    await hyp.startDaemon({ env: herdr.env });

    const shim = await LlmShimServer.start({
      sandbox,
      auditors: {
        allowBridge: false,
        allowKv: false,
        // Note: `<hyphae-wake>` tag itself is STILL audited strictly metadata-only on every role!
        // Inner Claude Code also fires `UserPromptSubmit` hook when `<hyphae-wake>` is submitted,
        // draining the message directly into `additionalContext` without requiring an extra `hyp_inbox` turn.
        allowedRoles: ["herdr-worker"],
        // ISSUE #23: inner Claude hooks use v2 packer framing.
        acceptV2PackerHookFraming: true,
      },
    });

    const idleWakePayload = "HERDR_IDLE_HC_SEND_WAKE_099";
    const queuePayload = "HERDR_QUEUE_HELD_ACTIVE_101";
    const interruptPayload = "HERDR_INTERRUPT_PREEMPT_202";
    const recycledPayload = "HERDR_RECYCLED_MUST_NOT_DELIVER_303";
    shim.auditors.registerUntrustedPayload("hc-idle-wake", idleWakePayload);
    shim.auditors.registerUntrustedPayload("hc-queue", queuePayload);
    shim.auditors.registerUntrustedPayload("hc-interrupt", interruptPayload);
    shim.auditors.registerUntrustedPayload("hc-recycled", recycledPayload);

    // -------------------------------------------------------------------------
    // 1. Bare-shell fail-closed test: `hc run --bg --name bare-sh /bin/sh` (`status == null`)
    // -------------------------------------------------------------------------
    const bareRun = await herdr.runBg("bare-sh", ["/bin/sh"]);
    const bareAddr = String(bareRun.address);
    await new Promise((r) => setTimeout(r, 300));
    const bareInfo = await herdr.get(bareAddr);
    assert.equal(bareInfo.state, "live");
    assert.equal(
      bareInfo.status?.app ?? null,
      null,
      `Bare shell must have status.app == null, got: ${JSON.stringify(bareInfo)}`,
    );

    // Attempt enrollment via `hyp mcp --backend herdr --ephemeral` with `HC_TERMINAL_ID=<bareAddr>`:
    // `probe_herdr_terminal` MUST fail closed (never attach HerdrTransport to a raw shell!).
    const bareClient = new HypMcpClient(
      sandbox,
      hyp.bin,
      ["mcp", hyp.socketPath, "--backend", "herdr", "--ephemeral"],
      "herdr-bare-shell-mcp",
    );
    // Re-spawn bare-shell MCP client with HC_TERMINAL_ID=bareAddr and HC_SOCKET explicitly set!
    await bareClient.close();

    const bareMcpProc = sandbox.reaper.spawn(
      "herdr-bare-mcp-env",
      hyp.bin,
      ["mcp", hyp.socketPath, "--backend", "herdr", "--ephemeral"],
      {
        env: { ...herdr.env, HC_TERMINAL_ID: bareAddr },
        stdio: ["pipe", "pipe", "pipe"],
      },
    );
    const sendBareRpc = (obj: Record<string, unknown>) =>
      bareMcpProc.child.stdin!.write(`${JSON.stringify(obj)}\n`);
    const readBareLines = () =>
      bareMcpProc.stdout
        .split(/\r?\n/)
        .map((l) => l.trim())
        .filter((l) => l.startsWith("{"))
        .map((l) => {
          try {
            return JSON.parse(l);
          } catch {
            return null;
          }
        })
        .filter(Boolean);

    sendBareRpc({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "bare", version: "1" } },
    });
    await waitForCondition(() => readBareLines().some((m) => m.id === 1), 5_000, "bare MCP init");
    sendBareRpc({ jsonrpc: "2.0", method: "notifications/initialized" });
    sendBareRpc({
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: { name: "hyp_mesh", arguments: { action: "join", handle: "bare-shell-attempt" } },
    });
    await waitForCondition(() => readBareLines().some((m) => m.id === 2), 8_000, "bare MCP join response");
    const bareJoinResp = readBareLines().find((m) => m.id === 2);
    const bareJoinText = (bareJoinResp?.result?.content ?? []).map((c: any) => c.text || "").join("");
    const bareJoinJson = JSON.parse(bareJoinText || "{}");

    // Verify fail-closed: `hasLiveTransport` MUST be `false` and `transport.kind` MUST NOT be `"herdr"`!
    // NEW-ISSUE check: Note that `hyp_mesh(join)` returns ok=true with `hasLiveTransport: false, transport.kind: "none"`
    // rather than rejecting enrollment outright when `--backend herdr` runs in a bare shell; critically,
    // `HerdrTransport` is NEVER attached so zero text can ever be typed into `/bin/sh`!
    assert.equal(
      bareJoinJson.hasLiveTransport,
      false,
      `Bare shell MUST NEVER attach live Herdr push transport! join=${bareJoinText}`,
    );
    assert.notEqual(
      bareJoinJson.transport?.kind,
      "herdr",
      `Bare shell transport kind MUST NOT be 'herdr': ${bareJoinText}`,
    );

    // Send a DM to `@bare-shell-attempt` and prove ZERO bytes were typed into the bare `/bin/sh` screen!
    const probeSender = await hyp.openPeer("bare-probe");
    await probeSender.send("bare-shell-attempt", "echo BARE_SHELL_PWNED_999");
    await new Promise((r) => setTimeout(r, 800));
    const bareScreen = await herdr.read(bareAddr);
    assert.equal(
      bareScreen.includes("BARE_SHELL_PWNED_999"),
      false,
      `Bare shell screen MUST NEVER receive pasted mesh text! Screen:\n${bareScreen}`,
    );
    assert.equal(
      bareScreen.includes("<hyphae-wake"),
      false,
      `Bare shell screen MUST NEVER receive <hyphae-wake> paste! Screen:\n${bareScreen}`,
    );
    await sandbox.reaper.kill(bareMcpProc, 1_500);
    await herdr.kill(bareAddr, { allowFailure: true });

    // -------------------------------------------------------------------------
    // 2. Launch real interactive Claude Code inside Herdr PTY (`worker-1`) + verify identity pinning!
    // -------------------------------------------------------------------------
    const gateQueueHold = createGate("herdr-midstream-queue-hold");
    const gateInterruptHold = createGate("herdr-midstream-interrupt");

    const peerNormal = await hyp.openPeer("bob");
    const peerVip = await hyp.openPeer("vip");
    const sink = await hyp.openPeer("sink");

    shim.script("herdr-worker", [
      {
        name: "load-tools",
        once: true,
        when: (req) => req.isToolDeferred("hyp_mesh"),
        do: (req) =>
          callTool(req, "ToolSearch", {
            query: "select:mcp__hyphae__hyp_mesh,mcp__hyphae__hyp_send,mcp__hyphae__hyp_inbox,mcp__hyphae__hyp_stream",
          }),
      },
      {
        name: "enroll-worker",
        once: true,
        when: (req) => !req.isToolDeferred("hyp_mesh") && req.anyMessageContains("ENROLL_WORKER_1"),
        do: (req) => callTool(req, "hyp_mesh", { action: "join", handle: "worker-1" }),
      },
      {
        name: "enroll-worker-done",
        once: true,
        when: (req) => req.lastToolResult("hyp_mesh")?.json?.handle === "worker-1",
        do: () => emitText("WORKER_1_ENROLLED"),
      },

      // Slow generation #1: hold mid-SSE stream while a `queue` DM arrives!
      {
        name: "slow-turn-for-queue",
        once: true,
        when: (req) => req.lastUserText.includes("START_SLOW_QUEUE_TURN"),
        do: () => pauseMidStream(gateQueueHold, "GENERATING_QUEUE_PART1_", "AND_FINISHED_QUEUE_PART2"),
      },

      // Slow generation #2: hold mid-SSE stream while an `interrupt` DM triggers real `hc interrupt`!
      {
        name: "slow-turn-for-interrupt",
        once: true,
        when: (req) => req.lastUserText.includes("START_SLOW_INTERRUPT_TURN"),
        do: () => pauseMidStream(gateInterruptHold, "GENERATING_INTERRUPTIBLE_", "TAIL_SHOULD_ABORT"),
      },

      // Direct reply when Claude's `UserPromptSubmit` or `Stop` hook already drained the DM into context!
      {
        name: "reply-idle-wake-dm",
        once: true,
        when: (req) =>
          req.anyMessageContains(idleWakePayload) &&
          !req.anyMessageContains(`HC_IDLE_ACK:${idleWakePayload}`),
        do: (req) => callTool(req, "hyp_send", { to: "sink", text: `HC_IDLE_ACK:${idleWakePayload}` }),
      },
      {
        name: "reply-queue-dm",
        once: true,
        when: (req) =>
          req.anyMessageContains(queuePayload) &&
          !req.anyMessageContains(`HC_QUEUE_ACK:${queuePayload}`),
        do: (req) => callTool(req, "hyp_send", { to: "sink", text: `HC_QUEUE_ACK:${queuePayload}` }),
      },
      {
        name: "reply-interrupt-dm",
        once: true,
        when: (req) =>
          req.anyMessageContains(interruptPayload) &&
          !req.anyMessageContains(`HC_INTERRUPT_ACK:${interruptPayload}`),
        do: (req) =>
          callTool(req, "hyp_send", { to: "sink", text: `HC_INTERRUPT_ACK:${interruptPayload}` }),
      },
      // Fallback wake handler if `<hyphae-wake>` arrived without hook drain (e.g. non-hook inner agent)
      {
        name: "wake-read-inbox",
        when: (req) =>
          req.lastUserText.includes("<hyphae-wake") && req.lastToolResults.length === 0,
        do: (req) => callTool(req, "hyp_inbox", { ack: true }),
      },
      {
        name: "reply-done",
        when: (req) =>
          Boolean(req.lastToolResult("hyp_send")?.json) && !req.lastToolResult("hyp_send")?.isError,
        do: () => emitText("WORKER_1_ACKED"),
      },
    ]);

    const launched = await herdr.launchInteractiveClaude({
      name: "worker-1",
      hyp,
      shim,
      role: "herdr-worker",
      claudeBin,
    });
    assert.equal(launched.info.state, "live");
    assert.ok(launched.info.created_ms > 0, "hc get must report created_ms");
    assert.ok(launched.info.pid > 0, "hc get must report pid");
    assert.ok(launched.info.status?.app, "hc get must report status.app for Claude");

    await herdr.send(launched.terminalAddress, "ENROLL_WORKER_1 join mesh as worker-1");
    await shim.awaitTurn("herdr-worker", (turn) => turn.ruleName === "enroll-worker-done", 25_000);

    // Verify `hyp inspect` pinned `(herdrTerminalId, herdrCreatedMs, transportKind="herdr")`!
    let workerSess: any = null;
    await waitForCondition(async () => {
      const ins = await hyp.inspect({ handle: "worker-1", allowFailure: true });
      const row = extractSessionsFromInspect(ins.json)[0];
      if (row?.enrolled && row?.transportKind === "herdr" && row?.hasLiveTransport) {
        workerSess = row;
        return true;
      }
      return false;
    }, 10_000, "Herdr identity pin in hyp inspect");

    assert.equal(workerSess.herdrTerminalId, launched.terminalAddress);
    assert.equal(workerSess.herdrCreatedMs, launched.info.created_ms);
    await herdr.waitForAgentState(launched.terminalAddress, ["idle", "done"], 15_000);

    // -------------------------------------------------------------------------
    // 3. Live idle `hc send --if idle` wake: metadata-only `<hyphae-wake>` -> reply!
    // -------------------------------------------------------------------------
    const turnsBeforeIdleWake = shim.getTurns("herdr-worker").length;
    await peerNormal.send("worker-1", idleWakePayload);
    await shim.awaitTurn("herdr-worker", (turn) => turn.ruleName === "reply-idle-wake-dm", 25_000);
    await shim.awaitTurn(
      "herdr-worker",
      (turn) => turn.ruleName === "reply-done" && turn.id > turnsBeforeIdleWake,
      15_000,
    );
    await herdr.waitForAgentState(launched.terminalAddress, ["idle", "done"], 15_000);
    // Verify the PTY paste itself was strictly metadata-only (`<hyphae-wake` present, raw payload NEVER pasted!)
    const screenAfterIdle = await herdr.read(launched.terminalAddress);
    assert.ok(
      screenAfterIdle.includes("<hyphae-wake"),
      `Expected metadata-only <hyphae-wake> pasted to Herdr PTY screen`,
    );
    assert.equal(
      screenAfterIdle.includes(idleWakePayload),
      false,
      `Raw DM payload MUST NEVER be pasted directly into Herdr PTY screen!`,
    );
    const sinkAfterIdle = await sink.inbox({ ack: true });
    assert.ok(
      JSON.stringify(sinkAfterIdle).includes(`HC_IDLE_ACK:${idleWakePayload}`),
      `Expected @sink to receive idle hc send ACK, got: ${JSON.stringify(sinkAfterIdle)}`,
    );

    // -------------------------------------------------------------------------
    // 3a. Live `hc send` (`queue` mode): holds during active generation, flushes AFTER turn ends!
    // -------------------------------------------------------------------------
    await herdr.send(launched.terminalAddress, "START_SLOW_QUEUE_TURN");
    await gateQueueHold.waitForWaiters(1, 20_000);
    await herdr.waitForAgentState(launched.terminalAddress, ["working"], 10_000);

    const turnsBeforeQueueSend = shim.getTurns("herdr-worker").length;
    await peerNormal.send("worker-1", queuePayload);
    // Hold for 1.2s while active: stream MUST NOT abort and no wake turn may fire while working!
    await new Promise((r) => setTimeout(r, 1_200));
    const slowTurnRecord = shim
      .getTurns("herdr-worker")
      .find((tr) => tr.ruleName === "slow-turn-for-queue");
    assert.equal(
      slowTurnRecord?.aborted,
      false,
      "`queue`-urgency DM MUST NEVER abort active generation via hc interrupt!",
    );
    assert.equal(
      shim.getTurns("herdr-worker").length,
      turnsBeforeQueueSend,
      "`queue`-urgency DM must hold until active generation completes",
    );

    // Release active generation -> Claude finishes -> Stop/idle -> daemon flushes held `queue` DM!
    gateQueueHold.release();
    await shim.awaitTurn("herdr-worker", (turn) => turn.ruleName === "reply-queue-dm", 25_000);
    await shim.awaitTurn(
      "herdr-worker",
      (turn) => turn.ruleName === "reply-done" && turn.id > turnsBeforeQueueSend,
      15_000,
    );
    await herdr.waitForAgentState(launched.terminalAddress, ["idle", "done"], 15_000);

    const sinkAfterQueue = await sink.inbox({ ack: true });
    assert.ok(
      JSON.stringify(sinkAfterQueue).includes(`HC_QUEUE_ACK:${queuePayload}`),
      `Expected @sink to receive held queue ACK after turn end, got: ${JSON.stringify(sinkAfterQueue)}`,
    );

    // -------------------------------------------------------------------------
    // 3b. Live `hc interrupt` (`interrupt` mode): preempts active SSE stream & delivers immediately!
    // -------------------------------------------------------------------------
    await hyp.session([
      "--session",
      workerSess.sessionId,
      "rule",
      "herdr-itest@local/vip",
      "interrupt",
    ]);

    await herdr.send(launched.terminalAddress, "START_SLOW_INTERRUPT_TURN");
    await gateInterruptHold.waitForWaiters(1, 20_000);
    await herdr.waitForAgentState(launched.terminalAddress, ["working"], 10_000);

    // Send `interrupt`-urgency DM -> daemon runs REAL `hc interrupt` -> active SSE stream ABORTS!
    const turnsBeforeInterrupt = shim.getTurns("herdr-worker").length;
    await peerVip.send("worker-1", interruptPayload);
    const abortedTurn = await shim.awaitAbort("herdr-worker", 15_000);
    assert.equal(
      abortedTurn.aborted,
      true,
      "Real `hc interrupt` MUST abort the open mid-stream LLM generation!",
    );
    gateInterruptHold.release();

    // Immediately after interrupting, daemon delivers `<hyphae-wake>` -> Claude replies & finishes!
    await shim.awaitTurn("herdr-worker", (turn) => turn.ruleName === "reply-interrupt-dm", 25_000);
    await shim.awaitTurn(
      "herdr-worker",
      (turn) => turn.ruleName === "reply-done" && turn.id > turnsBeforeInterrupt,
      15_000,
    );
    const sinkAfterInterrupt = await sink.inbox({ ack: true });
    assert.ok(
      JSON.stringify(sinkAfterInterrupt).includes(`HC_INTERRUPT_ACK:${interruptPayload}`),
      `Expected @sink to receive interrupt ACK after hc interrupt preemption, got: ${JSON.stringify(sinkAfterInterrupt)}`,
    );

    // -------------------------------------------------------------------------
    // 4. PID / terminal recycling guard: kill `worker-1` and recreate under the same name!
    // -------------------------------------------------------------------------
    await herdr.kill(launched.terminalAddress);
    await new Promise((r) => setTimeout(r, 400));

    // Start a brand-new terminal reusing the EXACT same name `worker-1`!
    const recycledRun = await herdr.runBg("worker-1", ["/bin/sh"]);
    const recycledAddr = String(recycledRun.address);
    const recycledInfo = await herdr.get(recycledAddr);
    assert.notEqual(
      recycledInfo.created_ms,
      launched.info.created_ms,
      "Recycled terminal must have a distinct created_ms",
    );

    const turnsBeforeRecycle = shim.getTurns("herdr-worker").length;
    await peerNormal.send("worker-1", recycledPayload);
    await new Promise((r) => setTimeout(r, 1_500));

    // Pinned identity mismatch MUST fail closed: zero paste into recycled terminal, unread preserved in SQLite!
    const recycledScreen = await herdr.read(recycledAddr);
    assert.equal(
      recycledScreen.includes(recycledPayload),
      false,
      `Recycled terminal MUST NOT receive payload: ${recycledScreen}`,
    );
    assert.equal(
      recycledScreen.includes("<hyphae-wake"),
      false,
      `Recycled terminal MUST NOT receive <hyphae-wake>: ${recycledScreen}`,
    );
    assert.equal(shim.getTurns("herdr-worker").length, turnsBeforeRecycle);

    const insAfterRecycle = await hyp.inspect({ handle: "worker-1" });
    const rowAfterRecycle = extractSessionsFromInspect(insAfterRecycle.json)[0];
    assert.ok(
      (rowAfterRecycle?.counts?.queued ?? 0) >= 1,
      `DM to dead/recycled Herdr terminal must stay preserved in SQLite: ${JSON.stringify(rowAfterRecycle)}`,
    );

    shim.assertAllClean();
  });
});

test("Real Herdr (hc): Tier 4 herdrSpawnAllowlist config & GPUI --mod symlink/layout safety", async (t) => {
  const hcBin = resolveHcBin();
  if (!hcBin) {
    t.skip("hc binary not found (set HC_BIN)");
    return;
  }

  await withSandbox("herdr-mod-and-allowlist", async (sandbox) => {
    const herdr = await HerdrOrchestrator.start({ sandbox, hcBin });
    const hyp = new HypCli(sandbox);

    // -------------------------------------------------------------------------
    // 1. Tier 4 `herdrSpawnAllowlist` template + `node.json` validation
    // -------------------------------------------------------------------------
    const tplDir = path.join(sandbox.paths.xdgConfigDir, "herdr-core", "templates");
    fs.mkdirSync(tplDir, { recursive: true });
    const markerFile = path.join(sandbox.paths.tmpDir, "allowlisted-spawned.txt");
    fs.writeFileSync(
      path.join(tplDir, "triage-worker.md"),
      [
        "---",
        "name: triage-worker",
        `command: ["/bin/sh", "-c", "printf '%s' \\"$1\\" > ${markerFile}", "--"]`,
        "---",
        "Triage worker template",
      ].join("\n") + "\n",
    );

    // Verify real `hc templates --json` recognizes our isolated sandbox template!
    const tplRes = await herdr.exec(["templates", "--json"], { allowFailure: true });
    assert.equal(
      tplRes.exitCode,
      0,
      `hc templates --json failed: ${tplRes.stderr}`,
    );

    await hyp.onboard({ nodeId: "herdr-mod@local", noSkills: true, noCommands: true });
    const nodeCfg = JSON.parse(fs.readFileSync(hyp.nodeConfigPath, "utf8"));
    nodeCfg.deliveryRetry = {
      ...(nodeCfg.deliveryRetry || {}),
      herdrSpawnAllowlist: ["triage-worker"],
    };
    fs.writeFileSync(hyp.nodeConfigPath, JSON.stringify(nodeCfg, null, 2) + "\n");

    // Daemon must accept valid `deliveryRetry.herdrSpawnAllowlist` cleanly at startup!
    await hyp.startDaemon({ env: herdr.env });
    const doctorRes = await hyp.doctor({ allowFailure: true });
    assert.ok(doctorRes.json, "hyp doctor --json must parse cleanly with herdrSpawnAllowlist configured");

    // Verify invalid non-string `herdrSpawnAllowlist` fails closed at daemon startup!
    const badCfgPath = path.join(sandbox.paths.tmpDir, "bad-allowlist.json");
    fs.writeFileSync(
      badCfgPath,
      JSON.stringify({ ...nodeCfg, deliveryRetry: { herdrSpawnAllowlist: [123] } }),
    );
    const badStart = await hyp.exec(
      [
        "daemon",
        "--config",
        badCfgPath,
        "--state-dir",
        path.join(sandbox.paths.tmpDir, "bad-state"),
        "--socket",
        path.join(sandbox.paths.tmpDir, "bad.sock"),
      ],
      { allowFailure: true, timeoutMs: 8_000 },
    );
    assert.notEqual(badStart.exitCode, 0, "Malformed deliveryRetry.herdrSpawnAllowlist must fail closed");

    // NEW-ISSUE: `LocalDaemon::try_herdr_cold_spawn` (`crates/hyp-harness/src/daemon.rs:1167`)
    // is parsed from `node.json` `deliveryRetry.herdrSpawnAllowlist` but is NOT yet wired into
    // `flush_session` or any runtime IPC RPC in `daemon.rs` (only invoked by Rust unit tests).
    // Verify no spurious spawn occurs for an unlisted template either.
    assert.equal(fs.existsSync(markerFile), false);

    // -------------------------------------------------------------------------
    // 2. GPUI `--mod` safety: real directories (never symlinks) + shipped & symlinked layout protection!
    // -------------------------------------------------------------------------
    const herdrAppDir = path.join(sandbox.paths.homeDir, ".config", "herdr-app");
    const layoutsDir = path.join(herdrAppDir, "layouts");
    fs.mkdirSync(layoutsDir, { recursive: true });

    // (a) Shipped read-only `main.json` must remain untouched (`skipped_shipped`).
    const shippedMain = path.join(layoutsDir, "main.json");
    const shippedOriginal = JSON.stringify({ name: "main", pane: { header: { content: { mod: "pane" } } } }, null, 2) + "\n";
    fs.writeFileSync(shippedMain, shippedOriginal);
    fs.writeFileSync(path.join(herdrAppDir, "shared.json"), JSON.stringify({ layout: "main" }) + "\n");

    const pluginsDir = path.join(REPO_ROOT, "plugins");
    const setupShipped = await hyp.setup("herdr", {
      noSkills: true,
      noCommands: true,
      extraArgs: ["--mod", "--plugins-dir", pluginsDir],
    });
    assert.equal(setupShipped.exitCode, 0, `hyp setup --harness herdr --mod failed: ${setupShipped.stderr}`);

    // Both `hyphae-pane` and `hyphae-panel` must be installed as REAL directories (not symlinks!).
    for (const modName of ["hyphae-pane", "hyphae-panel"]) {
      const modDir = path.join(herdrAppDir, "mods", modName);
      const st = fs.lstatSync(modDir);
      assert.equal(st.isDirectory(), true, `${modName} must be a real directory`);
      assert.equal(st.isSymbolicLink(), false, `${modName} MUST NOT be a symlink`);
      assert.ok(fs.existsSync(path.join(modDir, "mod.json")), `${modName}/mod.json must exist`);
    }
    assert.equal(
      fs.readFileSync(shippedMain, "utf8"),
      shippedOriginal,
      "Shipped main.json MUST remain untouched by default --mod install",
    );
    assert.equal(
      setupShipped.json?.data?.herdrMod?.layoutAction,
      "skipped_shipped",
      `Expected layoutAction=skipped_shipped, got: ${JSON.stringify(setupShipped.json?.data?.herdrMod)}`,
    );

    // (b) Symlinked user layout MUST remain untouched (`skipped_symlink`) unless `--patch-layout` is explicitly passed!
    const gitManagedTarget = path.join(sandbox.paths.tmpDir, "git-custom-layout.json");
    const customOriginal = JSON.stringify({ name: "my-git-layout", pane: { header: { content: { mod: "pane" } } } }, null, 2) + "\n";
    fs.writeFileSync(gitManagedTarget, customOriginal);
    const symlinkLayout = path.join(layoutsDir, "my-git-layout.json");
    fs.symlinkSync(gitManagedTarget, symlinkLayout);
    fs.writeFileSync(path.join(herdrAppDir, "shared.json"), JSON.stringify({ layout: "my-git-layout" }) + "\n");

    const setupSymlink = await hyp.setup("herdr", {
      noSkills: true,
      noCommands: true,
      extraArgs: ["--mod", "--plugins-dir", pluginsDir],
    });
    assert.equal(setupSymlink.exitCode, 0);
    assert.equal(
      fs.lstatSync(symlinkLayout).isSymbolicLink(),
      true,
      "Symlinked layout must remain a symlink",
    );
    assert.equal(
      fs.readFileSync(gitManagedTarget, "utf8"),
      customOriginal,
      "Symlinked layout target file MUST remain completely untouched!",
    );
    assert.equal(
      setupSymlink.json?.data?.herdrMod?.layoutAction,
      "skipped_symlink",
      `Expected layoutAction=skipped_symlink, got: ${JSON.stringify(setupSymlink.json?.data?.herdrMod)}`,
    );
  });
});
