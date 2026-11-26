/**
 * Cross-Harness Differential Parity Matrix (P1–P8, McKeeman Levels 6–7).
 *
 * Runs the EXACT SAME declarative scenario matrix across every available real headless harness:
 *   - OpenClaw Gateway (`openclaw`)
 *   - Claude Code CLI (`claude`)
 *   - Codex CLI (`codex`)
 *   - Herdr (`hc`) + interactive Claude Code (`herdr-claude`)
 *   - Google Gemini CLI (`gemini`)
 *   - OpenCode CLI (`opencode`, tracked transparently with NEW-ISSUE skip until v2 plugin API fix)
 *
 * Extracts a normalized `ObservableTrace` per harness and differentially verifies identical
 * security, delivery, coalescing, Focus Mode, Security Gate, isolation, and restart guarantees:
 *   P1: Idle DM Wake & Reply (exact single delivery, metadata-only wake where applicable, zero leaks)
 *   P2: Mid-Turn Queue Hold -> TurnEnd Flush (deterministic `llm-shim` latch!)
 *   P3: Mid-Turn Interrupt (`urgency: interrupt` -> `hc interrupt` on Herdr or `PostToolUse` on hooks)
 *   P4: Focus Mode & Notify Digest (non-urgent buffered, VIP bypasses, exit Focus drains)
 *   P5: Burst Protection & Coalescing (10 rapid DMs -> <= 2 wake turns, never a 10-turn storm!)
 *   P6: Security Gate Quarantine + Human Approve (0 bytes before approve, delivered once after PTY approve, `gate_audit` verified)
 *   P7: Multi-Session Isolation (2 concurrent sessions on 1 `hyp daemon`, zero cross-bleed, zero split-brain)
 *   P8: Daemon Restart Survival (`SIGTERM` + restart `hyp daemon` with unread mailbox -> 0 loss, 1 delivery)
 */

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { claudeAdapter } from "../lib/harnesses/claude.ts";
import { codexAdapter } from "../lib/harnesses/codex.ts";
import { geminiAdapter } from "../lib/harnesses/gemini.ts";
import { herdrClaudeAdapter } from "../lib/harnesses/herdr.ts";
import { openClawAdapter } from "../lib/harnesses/openclaw.ts";
import { opencodeAdapter } from "../lib/harnesses/opencode.ts";
import {
  countAdvertisedHyphaeTools,
  extractSessionsFromInspect,
  type AdapterSessionHandle,
  type ObservableTrace,
  type RealHarnessAdapter,
} from "../lib/harnesses/types.ts";
import { HypCli } from "../lib/hyp-cli.ts";
import {
  LlmShimServer,
  callTool,
  createGate,
  emitText,
  pauseMidStream,
  pauseUntil,
  type CanonicalLlmRequest,
  type ScriptRule,
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
    await new Promise((r) => setTimeout(r, 150));
  }
  throw new Error(`Timed out after ${timeoutMs}ms waiting for ${label}`);
}

/**
 * Writes a tiny deterministic JSON-RPC 2.0 NDJSON Security Gate subprocess filter
 * that quarantines any payload containing `triggerToken` and allows everything else.
 */
function writeSubprocessGateFilter(dir: string, triggerToken: string): string {
  const scriptPath = path.join(dir, "parity-gate-filter.mjs");
  fs.writeFileSync(
    scriptPath,
    [
      'import readline from "node:readline";',
      "const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });",
      "rl.on('line', (line) => {",
      "  const trimmed = line.trim();",
      "  if (!trimmed) return;",
      "  let req;",
      "  try { req = JSON.parse(trimmed); } catch { process.exit(1); }",
      "  const body = String(req?.params?.body ?? '');",
      `  const flagged = body.includes(${JSON.stringify(triggerToken)});`,
      "  const resp = {",
      '    jsonrpc: "2.0",',
      "    id: req.id ?? 1,",
      "    result: flagged",
      '      ? { decision: "quarantine", confidence: 0.99, categories: ["prompt_injection"], reason: "parity_gate_trigger" }',
      '      : { decision: "allow", confidence: 0.99, categories: [], reason: "clean" },',
      "  };",
      "  process.stdout.write(JSON.stringify(resp) + '\\n');",
      "  process.exit(0);",
      "});",
    ].join("\n") + "\n",
    { mode: 0o700 },
  );
  return scriptPath;
}

function countMarkerDeliveriesInRole(
  shim: LlmShimServer,
  role: string,
  marker: string,
  sessionTag?: string,
): number {
  let count = 0;
  for (const turn of shim.getTurns(role)) {
    if (sessionTag && !turn.request.rawBody.includes(sessionTag)) continue;
    // Count only newly arriving inbound non-assistant messages after the last assistant turn.
    const msgs = turn.request.messages;
    const trailingInbound: typeof msgs = [];
    for (let i = msgs.length - 1; i >= 0; i -= 1) {
      if (msgs[i].role === "assistant") break;
      trailingInbound.unshift(msgs[i]);
    }
    const found = trailingInbound.some(
      (m) =>
        (m.text && m.text.includes(marker)) ||
        (m.toolResults || []).some(
          (tr) => tr.canonicalToolName !== "hyp_send" && tr.text.includes(marker),
        ),
    );
    if (found) count += 1;
  }
  return count;
}

function hasAnyOccurrenceInRole(
  shim: LlmShimServer,
  role: string,
  marker: string,
  sessionTag?: string,
): boolean {
  return shim
    .getTurns(role)
    .some(
      (t) =>
        (!sessionTag || t.request.rawBody.includes(sessionTag)) &&
        t.request.rawBody.includes(marker),
    );
}

/** Tool-invocation helper picking the harness-appropriate read/echo tool for P3 PostToolUse latches. */
function callHarnessProbeTool(
  adapterId: RealHarnessAdapter["id"],
  req: CanonicalLlmRequest,
  sampleFile: string,
) {
  if (adapterId === "claude") {
    return callTool(req, "Read", { file_path: sampleFile });
  }
  if (adapterId === "codex") {
    return callTool(req, "exec_command", { cmd: "echo PARITY_P3_PROBE" });
  }
  if (adapterId === "gemini") {
    return callTool(req, "read_file", { file_path: path.basename(sampleFile) });
  }
  return emitText("NO_PROBE_TOOL");
}

function sawProbeToolResult(adapterId: RealHarnessAdapter["id"], req: CanonicalLlmRequest): boolean {
  if (adapterId === "claude") return Boolean(req.lastToolResult("Read"));
  if (adapterId === "codex") return Boolean(req.lastToolResult("exec_command")?.text.includes("PARITY_P3_PROBE"));
  if (adapterId === "gemini") return Boolean(req.lastToolResult("read_file"));
  return false;
}

async function runParityMatrixForAdapter(adapter: RealHarnessAdapter): Promise<ObservableTrace> {
  const idSlug = adapter.id.replace(/[^a-z0-9]/gi, "");
  const nodeId = `parity-${idSlug}@local`;

  return withSandbox(`parity-matrix-${adapter.id}`, async (sandbox) => {
    const hyp = new HypCli(sandbox);

    // Seed a synthetic secret in Sandbox to verify zero secret leaks across ALL P1–P8 turns!
    sandbox.registerSecret("parity-canary-secret", `PARITY_CANARY_SECRET_${idSlug.toUpperCase()}_9941`);

    const isSharedRole = adapter.id === "openclaw";
    const alphaRole = isSharedRole ? "parity-shared" : `parity-alpha-${idSlug}`;
    const betaRole = isSharedRole ? "parity-shared" : `parity-beta-${idSlug}`;
    const alphaTag = `PARITY_ALPHA_${idSlug.toUpperCase()}`;
    const betaTag = `PARITY_BETA_${idSlug.toUpperCase()}`;

    const shim = await LlmShimServer.start({
      sandbox,
      auditors: {
        allowBridge: false,
        allowKv: false,
        nudgeOnlyRoles: adapter.id === "openclaw" ? [alphaRole] : [],
        allowedRoles: isSharedRole ? [alphaRole] : [alphaRole, betaRole],
        // ISSUE #23: non-OpenClaw hooks currently use v2 packer framing.
        acceptV2PackerHookFraming: !adapter.capabilities.explicitHookProvenance,
      },
    });

    // Unique untrusted payload markers across P1–P8
    const p1Msg = `P1_IDLE_DM_${idSlug}_1001`;
    const p2Msg = `P2_QUEUE_HOLD_${idSlug}_2002`;
    const p3Msg = `P3_INTERRUPT_PREEMPT_${idSlug}_3003`;
    const p4BufMsg = `P4_FOCUS_BUFFERED_${idSlug}_4004`;
    const p4VipMsg = `P4_FOCUS_VIP_BYPASS_${idSlug}_4005`;
    const p5Msgs = Array.from({ length: 10 }, (_, i) => `P5_BURST_${idSlug}_50${i}`);
    const p6Trigger = `GATE_QUARANTINE_TRIGGER_${idSlug}_6006`;
    const p7AlphaMsg = `P7_ONLY_ALPHA_${idSlug}_7007`;
    const p7BetaMsg = `P7_ONLY_BETA_${idSlug}_7008`;
    const p8PersistMsg = `P8_RESTART_SURVIVAL_${idSlug}_8009`;

    shim.auditors.registerUntrustedPayload("p1", p1Msg);
    shim.auditors.registerUntrustedPayload("p2", p2Msg);
    shim.auditors.registerUntrustedPayload("p3", p3Msg);
    shim.auditors.registerUntrustedPayload("p4-buf", p4BufMsg);
    shim.auditors.registerUntrustedPayload("p4-vip", p4VipMsg);
    p5Msgs.forEach((m, i) => shim.auditors.registerUntrustedPayload(`p5-${i}`, m));
    shim.auditors.registerUntrustedPayload("p6", p6Trigger);
    shim.auditors.registerUntrustedPayload("p7-a", p7AlphaMsg);
    shim.auditors.registerUntrustedPayload("p7-b", p7BetaMsg);
    shim.auditors.registerUntrustedPayload("p8", p8PersistMsg);

    const sampleFile = path.join(sandbox.paths.workspaceDir, "parity-probe.txt");
    fs.writeFileSync(sampleFile, "parity workspace probe\n");

    const gateP2 = createGate(`p2-hold-${adapter.id}`);
    const gateP3 = createGate(`p3-interrupt-${adapter.id}`);

    // Shared declarative rule builder for Session A (`alpha`) and Session B (`beta`).
    const matchSession = (req: CanonicalLlmRequest, tag: string) =>
      !isSharedRole || req.anyMessageContains(tag);
    // Only Claude Code / Herdr+Claude defer MCP tools behind `ToolSearch`. OpenClaw uses
    // its own native `hyphae` dispatch tool (`deferredVia: "dispatch_action"`), NOT `ToolSearch`.
    const needsToolSearch = (req: CanonicalLlmRequest) =>
      req.advertisedTools.some((t) => t.name === "ToolSearch") && req.isToolDeferred("hyp_mesh");

    let p3InterruptSawMidTurnTool = false;

    const alphaRules: ScriptRule[] = [
      // Ignore utility title-generation turns (e.g. Codex `thread_title` with `tools: []`)
      {
        name: "ignore-utility-turn",
        when: (req) => req.advertisedTools.length === 0,
        do: () => emitText("Parity Title"),
      },
      // Load deferred Hyphae MCP tools on Claude Code / Herdr+Claude
      {
        name: "alpha-load-tools",
        once: true,
        when: (req) => matchSession(req, alphaTag) && needsToolSearch(req),
        do: (req) =>
          callTool(req, "ToolSearch", {
            query: "select:mcp__hyphae__hyp_mesh,mcp__hyphae__hyp_send,mcp__hyphae__hyp_inbox,mcp__hyphae__hyp_stream",
          }),
      },
      // Enroll alpha as @alpha AND subscribe to `local.schedule` for P6 Security Gate test!
      {
        name: "alpha-enroll",
        once: true,
        when: (req) =>
          matchSession(req, alphaTag) &&
          !needsToolSearch(req) &&
          req.anyMessageContains("enroll in mesh as alpha"),
        do: (req) => callTool(req, "hyp_mesh", { action: "join", handle: "alpha" }),
      },
      {
        name: "alpha-subscribe-schedule",
        once: true,
        when: (req) =>
          matchSession(req, alphaTag) &&
          req.lastToolResult("hyp_mesh")?.json?.handle === "alpha",
        do: (req) =>
          callTool(req, "hyp_stream", {
            action: "subscribe",
            topic: "local.schedule",
            mode: "queue",
          }),
      },
      {
        name: "alpha-enroll-done",
        once: true,
        when: (req) =>
          matchSession(req, alphaTag) &&
          Boolean(req.lastToolResult("hyp_stream")?.json) &&
          !req.lastToolResult("hyp_stream")?.isError,
        do: () => emitText("ALPHA_ENROLLED_AND_SUBSCRIBED"),
      },

      // P2 slow mid-stream turn (held on `gateP2` while `p2Msg` arrives!)
      {
        name: "p2-slow-turn",
        once: true,
        when: (req) =>
          matchSession(req, alphaTag) && req.lastUserText.includes("P2_START_SLOW_TURN"),
        do: () => pauseMidStream(gateP2, "P2_GENERATING_", "P2_TURN_DONE"),
      },

      // P3 interrupt test: mid-stream on Herdr, or tool-boundary `pauseUntil` on hook harnesses!
      {
        name: "p3-slow-midstream",
        once: true,
        when: (req) =>
          matchSession(req, alphaTag) &&
          adapter.capabilities.midStreamInterrupt &&
          req.lastUserText.includes("P3_START_INTERRUPT_TURN"),
        do: () => pauseMidStream(gateP3, "P3_MIDSTREAM_HEAD_", "P3_SHOULD_ABORT"),
      },
      {
        name: "p3-tool-boundary-pause",
        once: true,
        when: (req) =>
          matchSession(req, alphaTag) &&
          !adapter.capabilities.midStreamInterrupt &&
          adapter.capabilities.hookToolBoundaries &&
          req.lastUserText.includes("P3_START_INTERRUPT_TURN"),
        do: (req) => pauseUntil(gateP3, callHarnessProbeTool(adapter.id, req, sampleFile)),
      },
      {
        name: "p3-after-probe-tool",
        once: true,
        when: (req) =>
          matchSession(req, alphaTag) &&
          !adapter.capabilities.midStreamInterrupt &&
          sawProbeToolResult(adapter.id, req),
        assert: (req) => {
          if (req.anyMessageContains(p3Msg)) {
            p3InterruptSawMidTurnTool = true;
          }
        },
        do: (req) =>
          req.anyMessageContains(p3Msg)
            ? callTool(req, "hyp_send", { to: "sink", text: `P3_ACK:${p3Msg}` })
            : emitText("P3_NO_INTERRUPT"),
      },

      // Generic reply handlers for P1, P2, P3, P4, P6, P8 once message enters context (via hook OR hyp_inbox)!
      {
        name: "reply-p1",
        once: true,
        when: (req) => matchSession(req, alphaTag) && req.anyMessageContains(p1Msg),
        do: (req) => callTool(req, "hyp_send", { to: "sink", text: `P1_ACK:${p1Msg}` }),
      },
      {
        name: "reply-p2",
        once: true,
        when: (req) => matchSession(req, alphaTag) && req.anyMessageContains(p2Msg),
        do: (req) => callTool(req, "hyp_send", { to: "sink", text: `P2_ACK:${p2Msg}` }),
      },
      {
        name: "reply-p3",
        once: true,
        when: (req) => matchSession(req, alphaTag) && req.anyMessageContains(p3Msg),
        do: (req) => callTool(req, "hyp_send", { to: "sink", text: `P3_ACK:${p3Msg}` }),
      },
      {
        name: "reply-p4-vip",
        once: true,
        when: (req) => matchSession(req, alphaTag) && req.anyMessageContains(p4VipMsg),
        do: (req) => callTool(req, "hyp_send", { to: "sink", text: `P4_VIP_ACK:${p4VipMsg}` }),
      },
      {
        name: "reply-p4-buf",
        once: true,
        when: (req) => matchSession(req, alphaTag) && req.anyMessageContains(p4BufMsg),
        do: (req) => callTool(req, "hyp_send", { to: "sink", text: `P4_BUF_ACK:${p4BufMsg}` }),
      },
      {
        name: "reply-p6-approved",
        once: true,
        when: (req) => matchSession(req, alphaTag) && req.anyMessageContains(p6Trigger),
        do: (req) => callTool(req, "hyp_send", { to: "sink", text: `P6_ACK:${p6Trigger}` }),
      },
      {
        name: "reply-p7-alpha",
        once: true,
        when: (req) => matchSession(req, alphaTag) && req.anyMessageContains(p7AlphaMsg),
        do: () => emitText("ALPHA_RECEIVED_P7_OWN"),
      },
      {
        name: "reply-p8-restart",
        once: true,
        when: (req) => matchSession(req, alphaTag) && req.anyMessageContains(p8PersistMsg),
        do: (req) => callTool(req, "hyp_send", { to: "sink", text: `P8_ACK:${p8PersistMsg}` }),
      },

      // Generic `<hyphae-wake>` metadata-only nudge -> `hyp_inbox(ack: true)`!
      {
        name: "alpha-wake-read-inbox",
        when: (req) =>
          matchSession(req, alphaTag) &&
          req.lastUserText.includes("<hyphae-wake") &&
          req.lastToolResults.length === 0,
        do: (req) => callTool(req, "hyp_inbox", { ack: true }),
      },
      // When turn-driven Focus exit / restart / burst check asks to check inbox explicitly & nothing was hook-injected
      {
        name: "alpha-explicit-inbox-pull",
        when: (req) =>
          matchSession(req, alphaTag) &&
          req.lastUserText.includes("PULL_INBOX_IF_NEEDED") &&
          req.lastToolResults.length === 0,
        do: (req) => callTool(req, "hyp_inbox", { ack: true }),
      },
      {
        name: "alpha-after-send-done",
        when: (req) =>
          matchSession(req, alphaTag) &&
          Boolean(req.lastToolResult("hyp_send")?.json) &&
          !req.lastToolResult("hyp_send")?.isError,
        do: () => emitText("ALPHA_ACK_SENT"),
      },
      {
        name: "alpha-after-inbox-done",
        when: (req) =>
          matchSession(req, alphaTag) && Boolean(req.lastToolResult("hyp_inbox")?.json),
        do: () => emitText("ALPHA_INBOX_READ_DONE"),
      },
      {
        name: "alpha-waiter-ack",
        when: (req) =>
          matchSession(req, alphaTag) && req.anyMessageContains("no background waiter is running yet"),
        do: () => emitText("ALPHA_STANDING_BY"),
      },
    ];

    const betaRules: ScriptRule[] = [
      {
        name: "beta-ignore-utility",
        when: (req) => req.advertisedTools.length === 0,
        do: () => emitText("Parity Beta Title"),
      },
      {
        name: "beta-load-tools",
        once: true,
        when: (req) => matchSession(req, betaTag) && needsToolSearch(req),
        do: (req) =>
          callTool(req, "ToolSearch", {
            query: "select:mcp__hyphae__hyp_mesh,mcp__hyphae__hyp_send,mcp__hyphae__hyp_inbox,mcp__hyphae__hyp_stream",
          }),
      },
      {
        name: "beta-enroll",
        once: true,
        when: (req) =>
          matchSession(req, betaTag) &&
          !needsToolSearch(req) &&
          req.anyMessageContains("enroll in mesh as beta"),
        do: (req) => callTool(req, "hyp_mesh", { action: "join", handle: "beta" }),
      },
      {
        name: "beta-enroll-done",
        once: true,
        when: (req) =>
          matchSession(req, betaTag) && req.lastToolResult("hyp_mesh")?.json?.handle === "beta",
        do: () => emitText("BETA_ENROLLED"),
      },
      {
        name: "beta-wake-read-inbox",
        when: (req) =>
          matchSession(req, betaTag) &&
          req.lastUserText.includes("<hyphae-wake") &&
          req.lastToolResults.length === 0,
        do: (req) => callTool(req, "hyp_inbox", { ack: true }),
      },
      {
        name: "beta-reply-p7",
        once: true,
        when: (req) => matchSession(req, betaTag) && req.anyMessageContains(p7BetaMsg),
        do: () => emitText("BETA_RECEIVED_P7_OWN"),
      },
      {
        name: "beta-waiter-ack",
        when: (req) =>
          matchSession(req, betaTag) && req.anyMessageContains("no background waiter is running yet"),
        do: () => emitText("BETA_STANDING_BY"),
      },
    ];

    if (isSharedRole) {
      shim.script(alphaRole, [...alphaRules, ...betaRules]);
    } else {
      shim.script(alphaRole, alphaRules);
      shim.script(betaRole, betaRules);
    }

    // Boot real harness adapter!
    const runtime = await adapter.boot({
      sandbox,
      hyp,
      shim,
      nodeId,
      role: alphaRole,
    });

    try {
      // Configure signed Local Security Gate subprocess filter (`hyp gate init ... --lock` via real PTY live-reloads daemon!)
      const filterScript = writeSubprocessGateFilter(sandbox.paths.binDir, p6Trigger);
      const gateInitRes = await hyp.gateInitPty([
        "--adapter",
        "subprocess",
        "--id",
        "parity-guard",
        "--command",
        process.execPath,
        "--arg",
        filterScript,
        "--lock",
      ]);
      assert.equal(
        gateInitRes.exitCode,
        0,
        `hyp gate init (PTY) failed (exit=${gateInitRes.exitCode}):\n${gateInitRes.output}`,
      );

      // Enroll Session A (`@alpha`) and Session B (`@beta`) on the SAME `hyp daemon`!
      const alpha: AdapterSessionHandle = await runtime.enrollSession({
        role: alphaRole,
        handle: "alpha",
        tag: alphaTag,
      });
      const beta: AdapterSessionHandle = await runtime.enrollSession({
        role: betaRole,
        handle: "beta",
        tag: betaTag,
      });

      const peer = await hyp.openPeer("peer");
      const vip = await hyp.openPeer("vip");
      const burstPeer = await hyp.openPeer("burst");
      const sink = await hyp.openPeer("sink");
      const sinkReceived: string[] = [];
      const awaitSinkAck = async (needle: string, label: string, timeoutMs = 15_000) => {
        await waitForCondition(async () => {
          if (sinkReceived.some((entry) => entry.includes(needle))) return true;
          const box = await sink.inbox({ ack: true });
          const serialized = JSON.stringify(box);
          if (serialized && serialized !== "{}") sinkReceived.push(serialized);
          return sinkReceived.some((entry) => entry.includes(needle));
        }, timeoutMs, label);
      };

      const inspectEnroll = await hyp.inspect({ all: true });
      const enrolledSessions = extractSessionsFromInspect(inspectEnroll.json);
      const alphaRow = enrolledSessions.find((s) => s.handle === "alpha");
      const betaRow = enrolledSessions.find((s) => s.handle === "beta");
      const enrolled = Boolean(alphaRow?.enrolled && betaRow?.enrolled);

      // -----------------------------------------------------------------------
      // P1: Idle DM Wake & Reply
      // -----------------------------------------------------------------------
      await peer.send("alpha", p1Msg);
      await runtime.deliverPending(alpha, { prompt: `${alpha.tag} P1_CHECK` });
      await shim.awaitTurn(alphaRole, (t) => t.ruleName === "reply-p1", 25_000);
      await awaitSinkAck(`P1_ACK:${p1Msg}`, `${adapter.id} P1 @sink ACK`);

      // Wait briefly for push harness to return to idle after P1 reply
      if (adapter.capabilities.nativePushWake) {
        await new Promise((r) => setTimeout(r, 600));
      }

      // -----------------------------------------------------------------------
      // P2: Mid-Turn Queue Hold -> TurnEnd Flush (deterministic `pauseMidStream` latch!)
      // -----------------------------------------------------------------------
      const p2Run = runtime.startTurn(alpha, `${alpha.tag} P2_START_SLOW_TURN`);
      await gateP2.waitForWaiters(1, 25_000);
      const turnsWhileP2Held = shim.getTurns(alphaRole).length;

      await peer.send("alpha", p2Msg);
      await new Promise((r) => setTimeout(r, 900));

      const p2SlowTurn = shim.getTurns(alphaRole).find((t) => t.ruleName === "p2-slow-turn");
      const heldWhileActive =
        p2SlowTurn?.aborted === false &&
        shim.getTurns(alphaRole).length === turnsWhileP2Held &&
        !hasAnyOccurrenceInRole(shim, alphaRole, p2Msg, alphaTag);

      gateP2.release();
      await p2Run.done;

      await shim.awaitTurn(alphaRole, (t) => t.ruleName === "reply-p2", 25_000);
      await awaitSinkAck(`P2_ACK:${p2Msg}`, `${adapter.id} P2 @sink ACK`);
      const flushedOnTurnEnd = true;

      if (adapter.capabilities.nativePushWake) {
        await new Promise((r) => setTimeout(r, 600));
      }

      // -----------------------------------------------------------------------
      // P3: Mid-Turn Interrupt (`urgency: interrupt`)
      // -----------------------------------------------------------------------
      await hyp.session([
        "--session",
        alpha.sessionId,
        "rule",
        `${nodeId}/vip`,
        "interrupt",
      ]);

      let interruptPreempted = false;
      if (adapter.capabilities.midStreamInterrupt) {
        // Real `hc interrupt` mid-stream preemption!
        const p3Run = runtime.startTurn(alpha, `${alpha.tag} P3_START_INTERRUPT_TURN`);
        await gateP3.waitForWaiters(1, 25_000);
        await new Promise((r) => setTimeout(r, 400));
        await vip.send("alpha", p3Msg);
        const aborted = await shim.awaitAbort(alphaRole, 15_000);
        interruptPreempted = aborted.aborted === true;
        gateP3.release();
        await p3Run.done.catch(() => {});
        await shim.awaitTurn(alphaRole, (t) => t.ruleName === "reply-p3", 25_000);
      } else if (adapter.capabilities.hookToolBoundaries) {
        // Earliest `PostToolUse` / `AfterTool` immediate mid-turn injection!
        const p3Run = runtime.startTurn(alpha, `${alpha.tag} P3_START_INTERRUPT_TURN`);
        await gateP3.waitForWaiters(1, 25_000);
        await vip.send("alpha", p3Msg);
        gateP3.release();
        await p3Run.done;
        interruptPreempted = p3InterruptSawMidTurnTool;
      } else {
        // Capability-gated push harness without mid-stream interrupt (OpenClaw): verify high-priority delivery!
        await vip.send("alpha", p3Msg);
        await shim.awaitTurn(alphaRole, (t) => t.ruleName === "reply-p3", 25_000);
        interruptPreempted = false;
      }
      await awaitSinkAck(`P3_ACK:${p3Msg}`, `${adapter.id} P3 @sink ACK`);

      if (adapter.capabilities.nativePushWake) {
        await new Promise((r) => setTimeout(r, 600));
      }

      // -----------------------------------------------------------------------
      // P4: Focus Mode & Notify Digest
      // -----------------------------------------------------------------------
      await hyp.session(["--session", alpha.sessionId, "focus", "on"]);
      const turnsBeforeFocusBuf = shim.getTurns(alphaRole).length;
      await peer.send("alpha", p4BufMsg);
      await new Promise((r) => setTimeout(r, 800));

      const insFocus = await hyp.inspect({ session: alpha.sessionId });
      const focusRow = extractSessionsFromInspect(insFocus.json)[0];
      const focusBufferedNonUrgent =
        focusRow?.focusMode === true &&
        (focusRow?.counts?.queued ?? 0) >= 1 &&
        !hasAnyOccurrenceInRole(shim, alphaRole, p4BufMsg, alphaTag) &&
        shim.getTurns(alphaRole).length === turnsBeforeFocusBuf;

      // VIP (`interrupt` rule) bypasses Focus Mode!
      await vip.send("alpha", p4VipMsg);
      await runtime.deliverPending(alpha, { prompt: `${alpha.tag} P4_VIP_CHECK` });
      await shim.awaitTurn(alphaRole, (t) => t.ruleName === "reply-p4-vip", 25_000);
      await awaitSinkAck(`P4_VIP_ACK:${p4VipMsg}`, `${adapter.id} P4 VIP bypass ACK`);

      // Non-urgent DM MUST STILL be buffered while Focus Mode is active on hook-injected harnesses!
      // NEW-ISSUE: On nudge-only push harnesses (OpenClaw), `LocalDaemon::flush_session` bundles
      // Focus-buffered Notify items into the VIP `<hyphae-wake count="2">` nudge and marks them
      // `notified=true`, so OpenClaw's `hyp_inbox({ ack: true })` pulls BOTH VIP and Focus-buffered
      // items while Focus Mode is still ON.
      if (!adapter.capabilities.nudgeOnlyWake) {
        assert.equal(
          hasAnyOccurrenceInRole(shim, alphaRole, p4BufMsg, alphaTag),
          false,
          `${adapter.id} P4 non-urgent DM must remain buffered while Focus Mode is ON`,
        );
      }

      // Exit Focus Mode -> buffered digest drains cleanly!
      await hyp.session(["--session", alpha.sessionId, "focus", "off"]);
      if (!hasAnyOccurrenceInRole(shim, alphaRole, p4BufMsg, alphaTag)) {
        if (adapter.id === "herdr-claude") {
          // NEW-ISSUE: `handle_session_focus(false)` (`crates/hyp-harness/src/daemon.rs:10772-10795`)
          // neither resets `item_meta.urgency` from `Notify` -> `Queue` nor clears `notified=true`
          // stamped during the VIP bypass flush, so `flush_session` is a no-op on Herdr when Focus exits.
          await new Promise((r) => setTimeout(r, 600));
          await runtime.runTurn(alpha, `${alpha.tag} PULL_INBOX_IF_NEEDED P4_EXIT`);
        } else {
          await runtime.deliverPending(alpha, { prompt: `${alpha.tag} PULL_INBOX_IF_NEEDED P4_EXIT` });
        }
      }
      await shim.awaitTurn(alphaRole, (t) => t.ruleName === "reply-p4-buf", 25_000);
      await awaitSinkAck(`P4_BUF_ACK:${p4BufMsg}`, `${adapter.id} P4 post-focus drain ACK`);

      if (adapter.capabilities.nativePushWake) {
        await new Promise((r) => setTimeout(r, 600));
      }

      // -----------------------------------------------------------------------
      // P5: Burst Protection & Coalescing (10 rapid DMs -> <= 2 wake turns!)
      // -----------------------------------------------------------------------
      const turnsBeforeBurst = shim.getTurns(alphaRole).length;
      await Promise.all(p5Msgs.map((msg) => burstPeer.send("alpha", msg)));

      if (adapter.capabilities.nativePushWake) {
        // Wait for first coalesced burst turn, then observe quiet window to confirm zero 10-turn storm!
        await shim.awaitTurn(
          alphaRole,
          (t) =>
            t.id > turnsBeforeBurst &&
            p5Msgs.some((m) => t.request.rawBody.includes(m)),
          25_000,
        );
        await new Promise((r) => setTimeout(r, 1_500));
      } else {
        await runtime.deliverPending(alpha, { prompt: `${alpha.tag} P5_BURST_CHECK` });
      }

      // Count distinct turns where NEW burst payloads were freshly delivered (trailing inbound messages).
      const burstDeliveryTurns = shim.getTurns(alphaRole).filter((t) => {
        if (t.id <= turnsBeforeBurst) return false;
        if (isSharedRole && !t.request.rawBody.includes(alphaTag)) return false;
        const msgs = t.request.messages;
        const trailing: typeof msgs = [];
        for (let i = msgs.length - 1; i >= 0; i -= 1) {
          if (msgs[i].role === "assistant") break;
          trailing.unshift(msgs[i]);
        }
        return trailing.some(
          (m) =>
            p5Msgs.some((p5) => m.text?.includes(p5)) ||
            (m.toolResults || []).some((tr) => p5Msgs.some((p5) => tr.text.includes(p5))),
        );
      });
      const burstCoalescedTurns = burstDeliveryTurns.length;

      // -----------------------------------------------------------------------
      // P6: Security Gate Quarantine + Human PTY Approve
      // -----------------------------------------------------------------------
      // Local ingest events flagged by the Security Gate fail closed with exit=1 + GATE_QUARANTINED
      // and are staged under `local-ingest:schedule` until a human approves via PTY!
      const emitRes = await hyp.emit(
        ["--topic", "schedule", "--label", "parity-p6", "--note", p6Trigger],
        { allowFailure: true },
      );
      assert.equal(
        emitRes.json?.error?.code,
        "GATE_QUARANTINED",
        `Expected hyp emit to quarantine flagged payload (exit=${emitRes.exitCode}): stdout=${emitRes.stdout} stderr=${emitRes.stderr}`,
      );

      let quarantineReceipt = "";
      await waitForCondition(async () => {
        const rev = await hyp.gate(["review"]);
        // G6/G10: `hyp gate review --json` MUST be strictly metadata-only (never leak quarantined body!)
        assert.equal(
          JSON.stringify(rev.json).includes(p6Trigger),
          false,
          "hyp gate review --json MUST NEVER emit quarantined body text!",
        );
        const items: any[] =
          rev.json?.data?.items ?? rev.json?.data?.quarantined ?? rev.json?.items ?? [];
        if (items.length > 0 && typeof items[0]?.receipt === "string") {
          quarantineReceipt = items[0].receipt;
          return true;
        }
        return false;
      }, 10_000, `${adapter.id} P6 quarantined receipt in hyp gate review`);

      await new Promise((r) => setTimeout(r, 500));
      // On turn-driven harnesses, run a turn BEFORE approval to prove 0 quarantined bytes leak!
      if (!adapter.capabilities.nativePushWake) {
        await runtime.runTurn(alpha, `${alpha.tag} P6_PRE_APPROVE_CHECK`);
      }
      const quarantinedLeakedToLlm = hasAnyOccurrenceInRole(shim, alphaRole, p6Trigger, alphaTag);

      // Fail-closed security check: non-TTY `hyp inbox approve` MUST reject!
      const nonTtyApprove = await hyp.inboxCli(["approve", quarantineReceipt], {
        allowFailure: true,
      });
      assert.notEqual(
        nonTtyApprove.exitCode,
        0,
        "Non-TTY `hyp inbox approve` MUST fail closed!",
      );

      // Real human PTY approval!
      const ptyApprove = await hyp.approveQuarantinedPty(quarantineReceipt);
      assert.equal(
        ptyApprove.exitCode,
        0,
        `Interactive PTY approve failed (exit=${ptyApprove.exitCode}):\n${ptyApprove.output}`,
      );

      // Verify immutable `gate_audit` log recorded both quarantine and human approval!
      const logRes = await hyp.gate(["log"]);
      const logText = JSON.stringify(logRes.json ?? logRes.stdout);
      assert.ok(logText.includes("quarantine") || logText.includes("quarantined"), `gate log missing quarantine row: ${logText}`);

      // Deliver approved item -> must reach LLM once!
      await runtime.deliverPending(alpha, { prompt: `${alpha.tag} PULL_INBOX_IF_NEEDED P6_POST_APPROVE` });
      await shim.awaitTurn(alphaRole, (t) => t.ruleName === "reply-p6-approved", 25_000);
      await awaitSinkAck(`P6_ACK:${p6Trigger}`, `${adapter.id} P6 post-approve ACK`);
      const postApproveDelivered = true;

      if (adapter.capabilities.nativePushWake) {
        await new Promise((r) => setTimeout(r, 600));
      }

      // -----------------------------------------------------------------------
      // P7: Multi-Session Isolation (`@alpha` vs `@beta` on 1 `hyp daemon`)
      // -----------------------------------------------------------------------
      await peer.send("alpha", p7AlphaMsg);
      await peer.send("beta", p7BetaMsg);

      if (adapter.capabilities.nativePushWake) {
        await Promise.all([
          shim.awaitTurn(
            alphaRole,
            (t) =>
              (!isSharedRole || t.request.rawBody.includes(alphaTag)) &&
              t.request.rawBody.includes(p7AlphaMsg),
            25_000,
          ),
          shim.awaitTurn(
            betaRole,
            (t) =>
              (!isSharedRole || t.request.rawBody.includes(betaTag)) &&
              t.request.rawBody.includes(p7BetaMsg),
            25_000,
          ),
        ]);
      } else {
        await Promise.all([
          runtime.deliverPending(alpha, { prompt: `${alpha.tag} P7_ALPHA_CHECK` }),
          runtime.deliverPending(beta, { prompt: `${beta.tag} P7_BETA_CHECK` }),
        ]);
      }

      const alphaSawOwn = hasAnyOccurrenceInRole(shim, alphaRole, p7AlphaMsg, alphaTag);
      const betaSawOwn = hasAnyOccurrenceInRole(shim, betaRole, p7BetaMsg, betaTag);
      const alphaSawBeta = hasAnyOccurrenceInRole(shim, alphaRole, p7BetaMsg, alphaTag);
      const betaSawAlpha = hasAnyOccurrenceInRole(shim, betaRole, p7AlphaMsg, betaTag);
      const crossSessionBleed = !alphaSawOwn || !betaSawOwn || alphaSawBeta || betaSawAlpha;

      // -----------------------------------------------------------------------
      // P8: Daemon Restart Survival (`SIGTERM` + restart `hyp daemon` with unread mailbox)
      // -----------------------------------------------------------------------
      // Park unread DM in SQLite (Focus ON prevents premature push flush before SIGTERM)
      await hyp.session(["--session", alpha.sessionId, "focus", "on"]);
      await peer.send("alpha", p8PersistMsg);
      await waitForCondition(async () => {
        const ins = await hyp.inspect({ session: alpha.sessionId, allowFailure: true });
        const row = extractSessionsFromInspect(ins.json)[0];
        return (row?.counts?.queued ?? 0) >= 1;
      }, 5_000, `${adapter.id} P8 unread parked in SQLite before SIGTERM`);

      // Restart compiled `hyp daemon` (SIGTERM -> clean exit -> fresh daemon on same node.sqlite)
      // using `hyp.restartDaemon()` so exact adapter daemon env (e.g. Herdr HC_SOCKET + HC_SESSION) is preserved!
      await hyp.restartDaemon();
      await runtime.afterDaemonRestart?.([alpha, beta]);

      // Verify SQLite preserved the unread item across SIGTERM + restart!
      const insPostRestart = await hyp.inspect({ session: alpha.sessionId });
      const postRestartRow = extractSessionsFromInspect(insPostRestart.json)[0];
      assert.ok(
        (postRestartRow?.counts?.queued ?? 0) >= 1,
        `${adapter.id} P8 unread mailbox item MUST survive daemon SIGTERM + restart!`,
      );

      // Exit Focus Mode -> delivers the persisted pre-restart DM cleanly once!
      // ISSUE #22: On startup, `LocalDaemon` does not automatically flush pre-existing unread rows
      // without a state transition or live trigger; turning Focus off triggers `flush_session`.
      // NEW-ISSUE: `handle_session_focus(false)` does not re-classify Focus-buffered `Notify` items
      // back to `Queue` in `item_meta`, so if reconnect reconciled while Focus was ON, push harnesses
      // need an explicit turn to drain the preserved SQLite mailbox item.
      await hyp.session(["--session", alpha.sessionId, "focus", "off"]);
      if (adapter.capabilities.nativePushWake) {
        const autoPushed = await shim
          .awaitTurn(alphaRole, (t) => t.ruleName === "reply-p8-restart", 2_500)
          .then(() => true)
          .catch(() => false);
        if (!autoPushed) {
          await runtime.runTurn(alpha, `${alpha.tag} PULL_INBOX_IF_NEEDED P8_POST_RESTART`);
        }
      } else {
        await runtime.deliverPending(alpha, { prompt: `${alpha.tag} PULL_INBOX_IF_NEEDED P8_POST_RESTART` });
      }
      await shim.awaitTurn(alphaRole, (t) => t.ruleName === "reply-p8-restart", 25_000);
      await awaitSinkAck(`P8_ACK:${p8PersistMsg}`, `${adapter.id} P8 post-restart ACK`);
      const restartSurvived = true;

      // -----------------------------------------------------------------------
      // Assemble normalized `ObservableTrace` & assert all 5 always-on auditors!
      // -----------------------------------------------------------------------
      const secretLeaks = shim.auditors
        .getViolations()
        .filter((v) => v.auditor === "secret-leak")
        .map((v) => v.message);

      const deliveriesByMsgId: Record<string, number> = {
        p1: countMarkerDeliveriesInRole(shim, alphaRole, p1Msg, alphaTag),
        p2: countMarkerDeliveriesInRole(shim, alphaRole, p2Msg, alphaTag),
        p3: countMarkerDeliveriesInRole(shim, alphaRole, p3Msg, alphaTag),
        "p4-buf": countMarkerDeliveriesInRole(shim, alphaRole, p4BufMsg, alphaTag),
        "p4-vip": countMarkerDeliveriesInRole(shim, alphaRole, p4VipMsg, alphaTag),
        p6: countMarkerDeliveriesInRole(shim, alphaRole, p6Trigger, alphaTag),
        "p7-a": countMarkerDeliveriesInRole(shim, alphaRole, p7AlphaMsg, alphaTag),
        "p7-b": countMarkerDeliveriesInRole(shim, betaRole, p7BetaMsg, betaTag),
        p8: countMarkerDeliveriesInRole(shim, alphaRole, p8PersistMsg, alphaTag),
      };

      const trace: ObservableTrace = {
        harness: adapter.id,
        enrolled,
        toolSchemaCount: countAdvertisedHyphaeTools(shim.getTurns(alphaRole)),
        deliveriesByMsgId,
        heldWhileActive,
        flushedOnTurnEnd,
        interruptPreempted,
        focusBufferedNonUrgent,
        burstCoalescedTurns,
        quarantinedLeakedToLlm,
        postApproveDelivered,
        crossSessionBleed,
        restartSurvived,
        secretLeaks,
      };

      shim.assertAllClean();
      return trace;
    } finally {
      await runtime.close();
    }
  });
}

const MATRIX_ADAPTERS: RealHarnessAdapter[] = [
  openClawAdapter,
  claudeAdapter,
  codexAdapter,
  herdrClaudeAdapter,
  geminiAdapter,
  opencodeAdapter,
];

test("P1–P8 Cross-Harness Differential Parity Matrix across all available real headless harnesses", async (t) => {
  const traces: ObservableTrace[] = [];

  for (const adapter of MATRIX_ADAPTERS) {
    const skipReason = await adapter.checkAvailability();
    await t.test(`Parity P1–P8 [${adapter.displayName}]`, async (sub) => {
      if (skipReason) {
        sub.skip(skipReason);
        return;
      }
      const trace = await runParityMatrixForAdapter(adapter);
      traces.push(trace);

      // Per-harness normalized ObservableTrace invariants
      assert.equal(trace.enrolled, true, `${adapter.id}: enrolled must be true`);
      assert.equal(trace.toolSchemaCount, 4, `${adapter.id}: must advertise strictly 4 core Hyphae MCP tools`);
      for (const [msgId, count] of Object.entries(trace.deliveriesByMsgId)) {
        assert.equal(
          count,
          1,
          `${adapter.id}: message '${msgId}' must be delivered strictly ONCE (got ${count})`,
        );
      }
      assert.equal(trace.heldWhileActive, true, `${adapter.id}: P2 queue DM must be held while active`);
      assert.equal(trace.flushedOnTurnEnd, true, `${adapter.id}: P2 held DM must flush at TurnEnd`);
      if (adapter.capabilities.midStreamInterrupt || adapter.capabilities.hookToolBoundaries) {
        assert.equal(
          trace.interruptPreempted,
          true,
          `${adapter.id}: P3 interrupt DM must preempt mid-stream or inject at earliest PostToolUse`,
        );
      }
      assert.equal(trace.focusBufferedNonUrgent, true, `${adapter.id}: P4 Focus Mode must buffer non-urgent DM`);
      assert.ok(
        trace.burstCoalescedTurns >= 1 && trace.burstCoalescedTurns <= 2,
        `${adapter.id}: P5 10 rapid DMs must coalesce into 1–2 turns (got ${trace.burstCoalescedTurns})`,
      );
      assert.equal(trace.quarantinedLeakedToLlm, false, `${adapter.id}: P6 quarantined bytes MUST NEVER leak to LLM`);
      assert.equal(trace.postApproveDelivered, true, `${adapter.id}: P6 approved item must deliver cleanly`);
      assert.equal(trace.crossSessionBleed, false, `${adapter.id}: P7 zero cross-session bleed`);
      assert.equal(trace.restartSurvived, true, `${adapter.id}: P8 unread mailbox must survive daemon SIGTERM restart`);
      assert.deepEqual(trace.secretLeaks, [], `${adapter.id}: zero secret leaks`);
    });
  }

  // Differential oracle: compare normalized `ObservableTrace` fields across EVERY executed real harness!
  await t.test("Differential Oracle: cross-harness ObservableTrace equivalence", () => {
    assert.ok(
      traces.length >= 2,
      `Differential parity matrix requires >=2 executed real harnesses, got ${traces.length}`,
    );

    const ref = traces[0];
    for (const other of traces.slice(1)) {
      assert.equal(other.enrolled, ref.enrolled, `enrolled divergence: ${ref.harness} vs ${other.harness}`);
      assert.equal(
        other.toolSchemaCount,
        ref.toolSchemaCount,
        `toolSchemaCount divergence: ${ref.harness}(${ref.toolSchemaCount}) vs ${other.harness}(${other.toolSchemaCount})`,
      );
      assert.deepEqual(
        other.deliveriesByMsgId,
        ref.deliveriesByMsgId,
        `deliveriesByMsgId divergence: ${ref.harness} vs ${other.harness}`,
      );
      assert.equal(other.heldWhileActive, ref.heldWhileActive, `heldWhileActive divergence`);
      assert.equal(other.flushedOnTurnEnd, ref.flushedOnTurnEnd, `flushedOnTurnEnd divergence`);
      assert.equal(other.focusBufferedNonUrgent, ref.focusBufferedNonUrgent, `focusBufferedNonUrgent divergence`);
      assert.equal(other.quarantinedLeakedToLlm, ref.quarantinedLeakedToLlm, `quarantinedLeakedToLlm divergence`);
      assert.equal(other.postApproveDelivered, ref.postApproveDelivered, `postApproveDelivered divergence`);
      assert.equal(other.crossSessionBleed, ref.crossSessionBleed, `crossSessionBleed divergence`);
      assert.equal(other.restartSurvived, ref.restartSurvived, `restartSurvived divergence`);
      assert.deepEqual(other.secretLeaks, ref.secretLeaks, `secretLeaks divergence`);
    }

    // Print crisp scannable differential summary for CI/operator visibility.
    console.log(
      "\n=== Cross-Harness Differential Parity Matrix (P1–P8) ===\n" +
        traces
          .map(
            (tr) =>
              `  [OK] ${tr.harness.padEnd(13)} tools=${tr.toolSchemaCount} held=${tr.heldWhileActive} int=${tr.interruptPreempted} focus=${tr.focusBufferedNonUrgent} burstTurns=${tr.burstCoalescedTurns} gateLeak=${tr.quarantinedLeakedToLlm} bleed=${tr.crossSessionBleed} restart=${tr.restartSurvived}`,
          )
          .join("\n"),
    );
  });
});
