/**
 * Phase 4 Black-Box Suite: Cursor & Antigravity IDE Lifecycle Replay + Opt-In Tier 3 Live Smoke.
 *
 * Drives 100% real compiled `hyp` binaries (`hyp setup`, `hyp hook`, `hyp mcp`, `hyp wait`,
 * `hyp statusline`, `hyp node start --if-not-running`) with wire-exact IDE hook payloads:
 *  1. Cursor: `hyp setup --harness cursor` (preserves pre-existing MCP/hooks), verified `call_id`
 *     binding, spoofed caller rejection, `UNTRUSTED_PROVENANCE` framing, `beforeSubmitPrompt` +
 *     `afterMCPExecution` mid-turn (`interrupt` immediate vs `queue` held) vs `stop` (`followup_message`)
 *     drain, anti-loop `loop_count > 0`, and `hyp wait --session cursor:<id>` idle wakeup.
 *  2. Antigravity: `hyp setup --harness antigravity --statusline` (plugin manifest, hooks, rules,
 *     sidecar `--if-not-running` dedup, stacked custom statusLine preservation + live execution +
 *     `--restore-statusline`), direct + lazy `call_mcp_tool` `_meshCall` injection & single-use
 *     replay/spoof rejection, `PreInvocation` (`injectSteps`) vs `PostToolUse` (no mid-turn drain)
 *     vs `Stop` (`decision: "continue"`, `continuationActive: true` anti-loop, `USER_CANCELED` guard),
 *     and `hyp wait --session antigravity:<id>` idle wakeup.
 *  3. Opt-in Tier 3 live smoke hooks (`HYPHAE_ITEST_LIVE_CURSOR=1`, `HYPHAE_ITEST_LIVE_AGY=1`)
 *     cleanly skipped by default when env vars are unset.
 */

import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import {
  AntigravityReplayDriver,
  CursorReplayDriver,
  resolveLiveIdeBinary,
} from "../lib/harnesses/replay-cursor-agy.ts";
import { extractSessionsFromInspect } from "../lib/harnesses/types.ts";
import { HypCli } from "../lib/hyp-cli.ts";
import { UNTRUSTED_PROVENANCE_HEADER } from "../lib/llm-shim/index.ts";
import { waitUntil } from "../lib/mocks/helpers.ts";
import { withSandbox } from "../lib/sandbox.ts";

// ---------------------------------------------------------------------------
// 1. Cursor Wire-Exact Setup & Lifecycle Replay
// ---------------------------------------------------------------------------

test("IDE Replay — Cursor: setup preservation, verified call_id, spoof rejection, provenance framing, mid-turn vs TurnEnd drain, and hyp wait", async () => {
  await withSandbox("ide-replay-cursor", async (sandbox) => {
    const hyp = new HypCli(sandbox);
    await hyp.onboard({ nodeId: "cursor-itest@local", noSkills: true, noCommands: true });

    // Seed pre-existing Cursor MCP & hooks config to verify non-destructive merge preservation!
    const cursorDir = path.join(sandbox.paths.homeDir, ".cursor");
    fs.mkdirSync(cursorDir, { recursive: true, mode: 0o700 });
    const mcpPath = path.join(cursorDir, "mcp.json");
    const hooksPath = path.join(cursorDir, "hooks.json");
    fs.writeFileSync(
      mcpPath,
      JSON.stringify({ mcpServers: { existing_tool: { command: "echo", args: ["keep-me"] } } }, null, 2),
    );
    fs.writeFileSync(
      hooksPath,
      JSON.stringify(
        {
          version: 1,
          hooks: {
            beforeSubmitPrompt: [{ command: "echo pre-existing-cursor-hook", timeout: 5 }],
          },
        },
        null,
        2,
      ),
    );

    const setupRes = await hyp.setup("cursor", { noSkills: true, noCommands: true });
    assert.equal(setupRes.exitCode, 0, `hyp setup --harness cursor failed: ${setupRes.stderr}`);

    const mcpDoc = JSON.parse(fs.readFileSync(mcpPath, "utf8"));
    assert.ok(mcpDoc.mcpServers.existing_tool, "Existing Cursor MCP server must be preserved");
    assert.equal(mcpDoc.mcpServers.hyphae.command, hyp.bin);
    assert.ok(
      Array.isArray(mcpDoc.mcpServers.hyphae.args) && mcpDoc.mcpServers.hyphae.args.includes(hyp.socketPath),
      `Cursor mcp.json must wire explicit socket: ${JSON.stringify(mcpDoc.mcpServers.hyphae)}`,
    );

    const hooksDoc = JSON.parse(fs.readFileSync(hooksPath, "utf8"));
    assert.equal(hooksDoc.version, 1);
    for (const ev of ["beforeSubmitPrompt", "beforeMCPExecution", "afterMCPExecution", "stop"]) {
      const list = hooksDoc.hooks?.[ev];
      assert.ok(Array.isArray(list) && list.length >= 1, `Missing Cursor hook group '${ev}'`);
      assert.ok(
        list.some((h: any) => typeof h?.command === "string" && h.command.includes("hook cursor")),
        `Cursor hook '${ev}' must invoke 'hyp hook cursor': ${JSON.stringify(list)}`,
      );
    }
    assert.ok(
      hooksDoc.hooks.beforeSubmitPrompt.some((h: any) => h.command === "echo pre-existing-cursor-hook"),
      "Pre-existing Cursor beforeSubmitPrompt hook must be preserved",
    );

    await hyp.startDaemon();

    const cur = await CursorReplayDriver.create({
      sandbox,
      hyp,
      conversationId: "cur-conv-001",
      runSetup: false,
    });

    // Verify lean 4-core MCP tool catalog.
    const tools = await cur.mcp.listTools();
    const toolNames = tools.map((t: any) => t.name).sort();
    assert.deepEqual(toolNames, ["hyp_inbox", "hyp_mesh", "hyp_send", "hyp_stream"]);

    // 1a. Spoofed / unverified caller rejection (no `beforeMCPExecution` registration).
    const noMeta = await cur.callSpoofedTool("hyp_mesh", { action: "join", handle: "spoof-cursor" });
    assert.equal(noMeta.isError, true, "Unverified Cursor tool call without callId must fail closed");
    assert.equal(noMeta.json?.code, "caller_unverifiable");

    const forgedId = await cur.callSpoofedTool(
      "hyp_mesh",
      { action: "join", handle: "spoof-cursor" },
      { callId: "forged-unregistered-call-id" },
    );
    assert.equal(forgedId.isError, true, "Forged Cursor callId must fail closed");
    assert.equal(forgedId.json?.code, "caller_not_found");

    // 1b. Verified enrollment via `beforeMCPExecution` -> `tools/call` -> `afterMCPExecution`.
    const join = await cur.callVerifiedTool("hyp_mesh", { action: "join", handle: "cursor-agent" });
    assert.equal(join.preHook?.permission, "allow");
    assert.equal(join.tool.isError, false, `Cursor verified join failed: ${join.tool.text}`);
    assert.ok(join.tool.text.includes("cursor-agent"), `Unexpected join output: ${join.tool.text}`);

    // 1c. Mid-turn vs TurnEnd drain semantics:
    //     Configure receiver-side `interrupt` rule for `peer-vip` (while `peer-a` stays default `queue`).
    //     Send a `queue` DM while turn is active -> `afterMCPExecution` MUST hold it!
    //     Send an `interrupt` DM from `peer-vip` -> `afterMCPExecution` MUST drain it immediately with UNTRUSTED_PROVENANCE!
    //     Then `stop` (TurnEnd) MUST flush the held `queue` DM with `followup_message` + UNTRUSTED_PROVENANCE!
    await hyp.session(["--session", cur.sessionId, "rule", "cursor-itest@local/peer-vip", "interrupt"]);

    const queueMarker = "CURSOR_QUEUE_HELD_FOR_STOP_111";
    const interruptMarker = "CURSOR_INTERRUPT_MID_TURN_222";
    await hyp.send("peer-a", "cursor-agent", queueMarker);

    const afterWhileQueue = await cur.afterMcpExecution("read_file", "non-mesh-1");
    assert.equal(
      afterWhileQueue?.additional_context,
      undefined,
      `Cursor afterMCPExecution must HOLD queue DM mid-turn: ${JSON.stringify(afterWhileQueue)}`,
    );

    await hyp.send("peer-vip", "cursor-agent", interruptMarker);
    const afterInterrupt = await cur.afterMcpExecution("read_file", "non-mesh-2");
    assert.ok(
      typeof afterInterrupt?.additional_context === "string" &&
        afterInterrupt.additional_context.includes("<hyphae-inbox") &&
        afterInterrupt.additional_context.includes('urgency="interrupt"') &&
        afterInterrupt.additional_context.includes('from="cursor-itest@local/peer-vip"'),
      `Cursor afterMCPExecution must immediately inject metadata-only interrupt XML digest: ${JSON.stringify(afterInterrupt)}`,
    );
    assert.equal(
      afterInterrupt.additional_context.includes(interruptMarker),
      false,
      "RFC 0004: Cursor afterMCPExecution MUST NEVER include raw interrupt body",
    );
    assert.equal(
      afterInterrupt.additional_context.includes(queueMarker),
      false,
      "Queue DM must remain held during mid-turn interrupt drain",
    );
    const vipInbox = await cur.callVerifiedTool("hyp_inbox", {
      filter: { from: "cursor-itest@local/peer-vip" },
    });
    assert.ok(vipInbox.tool.text.includes(interruptMarker));
    assert.ok(vipInbox.tool.text.includes(UNTRUSTED_PROVENANCE_HEADER));

    // TurnEnd (`stop`) emits metadata-only XML digest for held `queue` DM into `followup_message`!
    const stopDrain = await cur.stop({ loopCount: 0 });
    assert.ok(
      typeof stopDrain?.followup_message === "string" &&
        stopDrain.followup_message.includes("<hyphae-inbox") &&
        stopDrain.followup_message.includes('urgency="queue"') &&
        stopDrain.followup_message.includes('from="cursor-itest@local/peer-a"'),
      `Cursor stop hook must flush held queue XML digest into followup_message: ${JSON.stringify(stopDrain)}`,
    );
    assert.equal(
      stopDrain.followup_message.includes(queueMarker),
      false,
      "RFC 0004: Cursor stop followup_message MUST NEVER include raw queue body",
    );
    const queueInbox = await cur.callVerifiedTool("hyp_inbox", {});
    assert.ok(queueInbox.tool.text.includes(queueMarker));
    assert.ok(queueInbox.tool.text.includes(UNTRUSTED_PROVENANCE_HEADER));

    // Next `stop` (mailbox empty, no waiter armed) emits waiter-arm `followup_message` once;
    // `loop_count: 1` returns `{}` (anti-loop guard!).
    const stopArm = await cur.stop({ loopCount: 0 });
    assert.ok(
      typeof stopArm?.followup_message === "string" &&
        stopArm.followup_message.includes(`wait --session ${cur.sessionId}`),
      `Cursor stop must prompt to arm hyp wait: ${JSON.stringify(stopArm)}`,
    );
    const stopAntiLoop = await cur.stop({ loopCount: 1 });
    assert.deepEqual(stopAntiLoop, {}, "Cursor stop with loop_count > 0 must not loop");

    // 1d. `beforeSubmitPrompt` pre-turn metadata-only XML digest + `hyp_inbox` read/ack!
    const preTurnMarker = "CURSOR_PRE_SUBMIT_PROMPT_333";
    await hyp.send("peer-a", "cursor-agent", preTurnMarker, { urgency: "queue" });
    const preSubmit = await cur.beforeSubmitPrompt("continue");
    assert.equal(preSubmit?.continue, true);
    assert.ok(
      typeof preSubmit?.additional_context === "string" &&
        preSubmit.additional_context.includes("<hyphae-inbox") &&
        preSubmit.additional_context.includes('from="cursor-itest@local/peer-a"'),
      `Cursor beforeSubmitPrompt must inject metadata-only XML digest: ${JSON.stringify(preSubmit)}`,
    );
    assert.equal(preSubmit.additional_context.includes(preTurnMarker), false);
    const preInbox = await cur.callVerifiedTool("hyp_inbox", {});
    assert.ok(preInbox.tool.text.includes(preTurnMarker));

    // 1e. Live `hyp wait --session cursor:<id>` idle wakeup!
    const waitHandle = cur.spawnWait(15);
    await waitUntil(
      async () => {
        const ins = await hyp.inspect({ handle: "cursor-agent", allowFailure: true });
        const row = extractSessionsFromInspect(ins.json)[0];
        return row?.hasLiveTransport === true;
      },
      "cursor hyp wait registered as live transport",
      8_000,
      50,
    );

    const idleWakeMarker = "CURSOR_IDLE_WAIT_WAKEUP_444";
    await hyp.send("peer-a", "cursor-agent", idleWakeMarker);
    const waitOut = await waitHandle.done;
    assert.equal(waitOut.exitCode, 0, `cursor hyp wait failed: ${waitOut.stderr}`);
    assert.equal(waitOut.json?.ok, true);
    const items = waitOut.json?.data?.items ?? [];
    assert.ok(
      items.some(
        (i: any) =>
          String(i?.text ?? "").includes("<hyphae-inbox") &&
          !String(i?.text ?? "").includes(idleWakeMarker),
      ),
      `cursor hyp wait must return metadata-only XML digest: ${waitOut.stdout}`,
    );
    const waitInbox = await cur.callVerifiedTool("hyp_inbox", {});
    assert.ok(waitInbox.tool.text.includes(idleWakeMarker));

    await cur.close();
  });
});

// ---------------------------------------------------------------------------
// 2. Antigravity Wire-Exact Setup, Stacked StatusLine, Sidecar & Lazy `call_mcp_tool` Replay
// ---------------------------------------------------------------------------

test("IDE Replay — Antigravity: setup, stacked statusline preservation & restore, sidecar --if-not-running dedup, lazy call_mcp_tool _meshCall unwrapping, PreInvocation & hyp wait", async () => {
  await withSandbox("ide-replay-antigravity", async (sandbox) => {
    const hyp = new HypCli(sandbox);
    await hyp.onboard({ nodeId: "agy-itest@local", noSkills: true, noCommands: true });

    // Seed pre-existing Antigravity CLI settings with a custom user statusLine command!
    const agySettingsDir = path.join(sandbox.paths.homeDir, ".gemini", "antigravity-cli");
    fs.mkdirSync(agySettingsDir, { recursive: true, mode: 0o700 });
    const agySettingsPath = path.join(agySettingsDir, "settings.json");
    const customMarker = "CUSTOM_USER_STATUSLINE_PILL_OK";
    fs.writeFileSync(
      agySettingsPath,
      JSON.stringify(
        {
          theme: "dark",
          statusLine: {
            type: "command",
            command: `printf '${customMarker}'`,
          },
        },
        null,
        2,
      ) + "\n",
    );

    const setupRes = await hyp.setup("antigravity", {
      noSkills: true,
      noCommands: true,
      extraArgs: ["--statusline"],
    });
    assert.equal(setupRes.exitCode, 0, `hyp setup --harness antigravity failed: ${setupRes.stderr}`);

    // Verify all Antigravity plugin artifacts written under `~/.gemini/config/plugins/hyphae/`.
    const pluginDir = path.join(sandbox.paths.homeDir, ".gemini", "config", "plugins", "hyphae");
    for (const rel of [
      "plugin.json",
      "mcp_config.json",
      "hooks.json",
      path.join("sidecars", "daemon", "sidecar.json"),
      path.join("rules", "AGENTS.md"),
    ]) {
      assert.ok(fs.existsSync(path.join(pluginDir, rel)), `Missing Antigravity plugin artifact: ${rel}`);
    }

    const sidecarCfg = JSON.parse(
      fs.readFileSync(path.join(pluginDir, "sidecars", "daemon", "sidecar.json"), "utf8"),
    );
    assert.equal(sidecarCfg.command, hyp.bin);
    assert.deepEqual(sidecarCfg.args, ["node", "start", "--if-not-running"]);
    assert.equal(sidecarCfg.restart_policy, "on-failure");

    const hooksCfg = JSON.parse(fs.readFileSync(path.join(pluginDir, "hooks.json"), "utf8"));
    assert.equal(hooksCfg.hyphae.PreToolUse[0].matcher, "call_mcp_tool|.*hyp_.*");

    // Verify stacked statusLine preservation in `~/.gemini/antigravity-cli/settings.json` + chain file!
    const agySettings = JSON.parse(fs.readFileSync(agySettingsPath, "utf8"));
    assert.equal(agySettings.theme, "dark", "Unrelated Antigravity settings keys must be preserved");
    assert.ok(
      typeof agySettings.statusLine?.command === "string" &&
        agySettings.statusLine.command.includes("statusline --harness antigravity") &&
        agySettings.statusLine.command.includes("--chain-file"),
      `Expected chained Hyphae statusLine command: ${JSON.stringify(agySettings.statusLine)}`,
    );
    const chainFilePath = path.join(sandbox.paths.hyphaeStateDir, "antigravity-statusline-chain.json");
    assert.ok(fs.existsSync(chainFilePath), "Antigravity statusLine chain backup file must exist");

    // Start real daemon and verify sidecar `hyp node start --if-not-running` deduplicates cleanly (exit 0)!
    await hyp.startDaemon();
    const sidecarDedup = await hyp.exec([
      "node",
      "start",
      "--if-not-running",
      "--state-dir",
      sandbox.paths.hyphaeStateDir,
      "--socket",
      hyp.socketPath,
      "--json",
    ]);
    assert.equal(
      sidecarDedup.exitCode,
      0,
      `Sidecar --if-not-running must exit 0 when daemon is already healthy: ${sidecarDedup.stderr}`,
    );

    const agy = await AntigravityReplayDriver.create({
      sandbox,
      hyp,
      conversationId: "agy-conv-777",
      runSetup: false,
    });

    // 2a. Non-mesh lazy `call_mcp_tool` passes through untouched (no overwrite!).
    const otherPre = await agy.preToolUseLazyWrapper("list_issues", { repo: "acme/app" }, { serverName: "github" });
    assert.deepEqual(otherPre, { decision: "allow" });

    // 2b. Direct `PreToolUse` -> `overwrite._meshCall` -> verified `hyp_mesh` join!
    const join = await agy.callVerifiedTool(
      "hyp_mesh",
      { action: "join", handle: "agy-agent" },
      { mode: "direct" },
    );
    assert.equal(join.preHook?.decision, "allow");
    assert.ok(
      typeof join.meshCallToken === "string" && join.meshCallToken.startsWith("ct_"),
      `Expected ct_* _meshCall token in PreToolUse overwrite: ${JSON.stringify(join.preHook)}`,
    );
    assert.equal(join.tool.isError, false, `Antigravity direct join failed: ${join.tool.text}`);
    assert.deepEqual(join.postHook, {}, "Antigravity PostToolUse must return {}");

    // 2c. Single-use `_meshCall` replay rejection + forged `_meshCall` rejection!
    const replayRes = await agy.mcp.callTool("hyp_mesh", {
      action: "status",
      _meshCall: join.meshCallToken,
    });
    assert.equal(replayRes.isError, true, "Replayed Antigravity _meshCall token must fail closed");
    assert.equal(replayRes.json?.code, "caller_not_found");

    const spoofRes = await agy.mcp.callTool("hyp_mesh", {
      action: "status",
      _meshCall: "ct_forged_invalid_token_0000000000000000000",
    });
    assert.equal(spoofRes.isError, true, "Forged Antigravity _meshCall token must fail closed");
    assert.equal(spoofRes.json?.code, "caller_not_found");

    // 2d. Lazy `call_mcp_tool` wrapper `{ ServerName: "hyphae_hyphae", ToolName: "hyp_send", Arguments: ... }`
    //     unwrapping -> `overwrite.Arguments._meshCall` -> verified `hyp_send` delivery to a peer!
    const receiverPeer = await hyp.openPeer("agy-peer");
    const lazyBody = "AGY_LAZY_CALL_MCP_TOOL_MSG_888";
    const lazySend = await agy.callVerifiedTool(
      "hyp_send",
      { to: "agy-peer", text: lazyBody },
      { mode: "lazy", serverName: "hyphae_hyphae" },
    );
    assert.equal(lazySend.preHook?.decision, "allow");
    assert.ok(
      typeof lazySend.preHook?.overwrite?.Arguments?._meshCall === "string" &&
        lazySend.preHook.overwrite.Arguments._meshCall.startsWith("ct_"),
      `Lazy call_mcp_tool PreToolUse must inject overwrite.Arguments._meshCall: ${JSON.stringify(lazySend.preHook)}`,
    );
    assert.equal(lazySend.preHook.overwrite.Arguments.to, "agy-peer");
    assert.equal(lazySend.preHook.overwrite.Arguments.text, lazyBody);
    assert.equal(lazySend.tool.isError, false, `Lazy hyp_send failed: ${lazySend.tool.text}`);

    const peerInbox = await receiverPeer.inbox({ ack: true });
    assert.ok(
      JSON.stringify(peerInbox).includes(lazyBody),
      `Receiver peer must receive message sent via Antigravity lazy call_mcp_tool: ${JSON.stringify(peerInbox)}`,
    );

    // 2e. Execute real stacked `hyp statusline --harness antigravity --chain-file`!
    const slRes = await hyp.exec(
      [
        "statusline",
        "--harness",
        "antigravity",
        "--socket",
        hyp.socketPath,
        "--chain-file",
        chainFilePath,
        "--plain",
      ],
      { input: JSON.stringify({ conversationId: agy.conversationId }) },
    );
    assert.equal(slRes.exitCode, 0, `hyp statusline failed: ${slRes.stderr}`);
    assert.ok(
      slRes.stdout.includes(customMarker),
      `Stacked Antigravity statusline must include chained user output: ${slRes.stdout}`,
    );
    assert.ok(
      slRes.stdout.includes("agy-agent"),
      `Stacked Antigravity statusline must include enrolled handle 'agy-agent': ${slRes.stdout}`,
    );

    // 2f. `PreInvocation` emits metadata-only XML digest into `injectSteps[0].systemMessage.systemMessage`!
    const preInvMarker = "AGY_PRE_INVOCATION_INJECT_999";
    await receiverPeer.send("agy-agent", preInvMarker);
    const preInv = await agy.preInvocation();
    const injectedText = preInv?.injectSteps?.[0]?.systemMessage?.systemMessage;
    assert.ok(
      typeof injectedText === "string" &&
        injectedText.includes("<hyphae-inbox") &&
        injectedText.includes('from="agy-itest@local/agy-peer"'),
      `Antigravity PreInvocation must inject metadata-only XML digest: ${JSON.stringify(preInv)}`,
    );
    assert.equal(injectedText.includes(preInvMarker), false, "RFC 0004: PreInvocation must not leak body");
    const agyPreInbox = await agy.callVerifiedTool("hyp_inbox", {}, { mode: "direct" });
    assert.ok(agyPreInbox.tool.text.includes(preInvMarker));
    assert.ok(agyPreInbox.tool.text.includes(UNTRUSTED_PROVENANCE_HEADER));

    // 2g. `Stop` semantics: `NO_TOOL_CALL` arms `hyp wait` with WaitMsBeforeAsync hint;
    //     `continuationActive: true` never loops; `USER_CANCELED` does not arm!
    const stopArm = await agy.stop({ continuationActive: false, terminationReason: "NO_TOOL_CALL" });
    assert.equal(stopArm?.decision, "continue");
    assert.ok(
      typeof stopArm?.reason === "string" &&
        stopArm.reason.includes(`wait --session ${agy.sessionId}`) &&
        stopArm.reason.includes("WaitMsBeforeAsync: 500"),
      `Antigravity Stop must prompt WaitMsBeforeAsync hyp wait: ${JSON.stringify(stopArm)}`,
    );
    assert.deepEqual(
      await agy.stop({ continuationActive: true, terminationReason: "NO_TOOL_CALL" }),
      {},
      "Antigravity Stop with continuationActive=true must not loop",
    );
    assert.deepEqual(
      await agy.stop({ continuationActive: false, terminationReason: "USER_CANCELED" }),
      {},
      "Antigravity Stop on USER_CANCELED must not arm waiter",
    );

    // 2h. Live `hyp wait --session antigravity:<id>` idle wakeup!
    const waitHandle = agy.spawnWait(15);
    await waitUntil(
      async () => {
        const ins = await hyp.inspect({ handle: "agy-agent", allowFailure: true });
        const row = extractSessionsFromInspect(ins.json)[0];
        return row?.hasLiveTransport === true;
      },
      "antigravity hyp wait registered as live transport",
      8_000,
      50,
    );
    const agyWakeMarker = "AGY_IDLE_WAIT_WAKEUP_1010";
    await receiverPeer.send("agy-agent", agyWakeMarker);
    const waitOut = await waitHandle.done;
    assert.equal(waitOut.exitCode, 0, `antigravity hyp wait failed: ${waitOut.stderr}`);
    assert.ok(
      (waitOut.json?.data?.items ?? []).some(
        (i: any) =>
          String(i?.text ?? "").includes("<hyphae-inbox") &&
          !String(i?.text ?? "").includes(agyWakeMarker),
      ),
      `antigravity hyp wait must receive metadata-only XML digest: ${waitOut.stdout}`,
    );
    const agyWaitInbox = await agy.callVerifiedTool("hyp_inbox", {}, { mode: "direct" });
    assert.ok(agyWaitInbox.tool.text.includes(agyWakeMarker));

    // 2i. `--restore-statusline` restores original user statusLine cleanly and deletes chain file!
    const restoreRes = await hyp.setup("antigravity", {
      noSkills: true,
      noCommands: true,
      extraArgs: ["--restore-statusline"],
    });
    assert.equal(restoreRes.exitCode, 0, `restore-statusline failed: ${restoreRes.stderr}`);
    const restoredSettings = JSON.parse(fs.readFileSync(agySettingsPath, "utf8"));
    assert.equal(restoredSettings.statusLine?.command, `printf '${customMarker}'`);
    assert.equal(fs.existsSync(chainFilePath), false, "Chain backup file must be removed after restore");

    await receiverPeer.close();
    await agy.close();
  });
});

// ---------------------------------------------------------------------------
// 3. Opt-In Tier 3 Live Authenticated Smoke Hooks (Skipped by Default in CI)
// ---------------------------------------------------------------------------

test("IDE Tier 3 Live Smoke — Cursor (opt-in via HYPHAE_ITEST_LIVE_CURSOR=1)", async (t) => {
  if (process.env.HYPHAE_ITEST_LIVE_CURSOR !== "1") {
    t.skip("Opt-in Tier 3 live Cursor smoke disabled (set HYPHAE_ITEST_LIVE_CURSOR=1 to run)");
    return;
  }
  const bin = resolveLiveIdeBinary("cursor-agent");
  if (!bin) {
    t.skip("cursor-agent binary not found on host");
    return;
  }

  await withSandbox("ide-tier3-live-cursor", { egressBlackhole: false }, async (sandbox) => {
    const hyp = new HypCli(sandbox);
    await hyp.onboard({ nodeId: "cursor-live@local", noSkills: true, noCommands: true });
    await hyp.setup("cursor", { noSkills: true, noCommands: true });
    await hyp.startDaemon();

    const out = await new Promise<{ code: number; stdout: string; stderr: string }>((resolve) => {
      execFile(
        bin,
        ["-p", "Reply strictly with LIVE_CURSOR_OK without modifying files.", "--force"],
        {
          env: { ...process.env, HOME: sandbox.paths.homeDir, HYPHAE_SOCKET: hyp.socketPath },
          cwd: sandbox.paths.workspaceDir,
          timeout: 60_000,
        },
        (err, stdout, stderr) => resolve({ code: err ? 1 : 0, stdout, stderr }),
      );
    });
    assert.equal(out.code, 0, `Live cursor-agent failed: ${out.stderr}`);
    assert.ok(out.stdout.includes("LIVE_CURSOR_OK"), `Unexpected live cursor-agent output: ${out.stdout}`);
  });
});

test("IDE Tier 3 Live Smoke — Antigravity (opt-in via HYPHAE_ITEST_LIVE_AGY=1)", async (t) => {
  if (process.env.HYPHAE_ITEST_LIVE_AGY !== "1") {
    t.skip("Opt-in Tier 3 live Antigravity smoke disabled (set HYPHAE_ITEST_LIVE_AGY=1 to run)");
    return;
  }
  const bin = resolveLiveIdeBinary("agy");
  if (!bin) {
    t.skip("agy binary not found on host");
    return;
  }

  await withSandbox("ide-tier3-live-agy", { egressBlackhole: false }, async (sandbox) => {
    const hyp = new HypCli(sandbox);
    await hyp.onboard({ nodeId: "agy-live@local", noSkills: true, noCommands: true });
    await hyp.setup("antigravity", { noSkills: true, noCommands: true });
    await hyp.startDaemon();

    const out = await new Promise<{ code: number; stdout: string; stderr: string }>((resolve) => {
      execFile(
        bin,
        ["-p", "Reply strictly with LIVE_AGY_OK without modifying files.", "--dangerously-skip-permissions"],
        {
          env: { ...process.env, HOME: sandbox.paths.homeDir, HYPHAE_SOCKET: hyp.socketPath },
          cwd: sandbox.paths.workspaceDir,
          timeout: 60_000,
        },
        (err, stdout, stderr) => resolve({ code: err ? 1 : 0, stdout, stderr }),
      );
    });
    assert.equal(out.code, 0, `Live agy failed: ${out.stderr}`);
    assert.ok(out.stdout.includes("LIVE_AGY_OK"), `Unexpected live agy output: ${out.stdout}`);
  });
});
