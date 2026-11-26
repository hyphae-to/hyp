/**
 * Real black-box Google Gemini CLI (`@google/gemini-cli`) integration suite.
 *
 * Always runs:
 *  1. Real `hyp setup --harness gemini` + compiled-binary Gemini hook lifecycle
 *     (`BeforeAgent`, `BeforeTool` `_meshCall` injection, `AfterTool`, `AfterAgent`) + `hyp mcp`.
 *
 * And whenever `@google/gemini-cli` is available (cached via `provision.mjs --tools gemini` or host):
 *  2. Real `gemini -p --yolo --skip-trust --output-format stream-json` pointed at our loopback
 *     `LlmShimServer` via `GOOGLE_GEMINI_BASE_URL` + `GEMINI_API_KEY`:
 *       - Verifies `BeforeTool` `_meshCall` injection -> `hyp_mesh(join)` enrollment & 4-tool schema!
 *       - Verifies deterministic tool-boundary latch (`pauseUntil(gate)`) proving `AfterTool` holds
 *         `queue` DMs mid-turn, injects `interrupt` DMs mid-turn, and `AfterAgent` flushes held
 *         `queue` DMs cleanly with zero duplicates!
 *       - Verifies multi-session isolation (`--session-id` + `--resume`) across 2 concurrent Gemini
 *         sessions sharing one `hyp daemon` with zero cross-bleed!
 */

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { GeminiHarness, resolveGeminiBin } from "../lib/harnesses/gemini.ts";
import { extractSessionsFromInspect } from "../lib/harnesses/types.ts";
import { HypCli, HypMcpClient } from "../lib/hyp-cli.ts";
import {
  LlmShimServer,
  callTool,
  createGate,
  emitText,
  pauseUntil,
} from "../lib/llm-shim/index.ts";
import { withSandbox } from "../lib/sandbox.ts";

test("Compiled hyp: `hyp setup --harness gemini` + BeforeTool _meshCall + AfterTool + AfterAgent hook contract", async () => {
  await withSandbox("gemini-setup-and-hooks-contract", async (sandbox) => {
    const hyp = new HypCli(sandbox);
    await hyp.onboard({ nodeId: "gem-contract@local", noSkills: true, noCommands: true });
    await hyp.startDaemon();

    const setupRes = await hyp.setup("gemini", { noSkills: true, noCommands: true });
    assert.equal(setupRes.exitCode, 0);

    const settingsPath = path.join(sandbox.paths.homeDir, ".gemini", "settings.json");
    assert.ok(fs.existsSync(settingsPath), "settings.json must be written by hyp setup --harness gemini");
    const settings = JSON.parse(fs.readFileSync(settingsPath, "utf8"));
    assert.equal(settings.tools?.enableHooks, true);
    assert.ok(settings.mcpServers?.hyphae, "mcpServers.hyphae must be configured");
    for (const ev of ["BeforeAgent", "BeforeTool", "AfterTool", "AfterAgent"]) {
      const groups = settings.hooks?.[ev];
      assert.ok(Array.isArray(groups) && groups.length > 0, `Gemini hook ${ev} must be configured`);
      const timeouts = groups.flatMap((g: any) =>
        (Array.isArray(g?.hooks) ? g.hooks : []).map((hk: any) => hk?.timeout),
      );
      assert.ok(
        timeouts.length > 0 && timeouts.every((ms: unknown) => ms === 10_000),
        `Gemini hook ${ev} must configure timeout=10000ms (#31), got: ${JSON.stringify(timeouts)}`,
      );
    }

    // Exercise real compiled `hyp hook gemini pre-tool-use` -> injects `_meshCall` -> real `hyp mcp` enrolls!
    const sid = crypto.randomUUID();
    const preRes = await hyp.exec(["hook", "gemini", "pre-tool-use", "--socket", hyp.socketPath], {
      input: JSON.stringify({
        session_id: sid,
        tool_name: "mcp_hyphae_hyp_mesh",
        tool_input: { action: "join", handle: "gem-hook-ok" },
      }),
    });
    assert.equal(preRes.json?.decision, "allow");
    const meshCall = preRes.json?.hookSpecificOutput?.tool_input?._meshCall;
    assert.equal(typeof meshCall, "string", `BeforeTool must return _meshCall: ${preRes.stdout}`);

    const mcp = new HypMcpClient(sandbox, hyp.bin, ["mcp", hyp.socketPath], "gem-mcp-contract");
    await mcp.initialize("gemini-contract");
    const joinRes = await mcp.callTool("hyp_mesh", {
      action: "join",
      handle: "gem-hook-ok",
      _meshCall: meshCall,
    });
    assert.equal(joinRes.isError, false, `Verified Gemini MCP join failed: ${joinRes.text}`);
    assert.equal(joinRes.json?.handle, "gem-hook-ok");

    // Queue DM -> AfterTool holds mid-turn -> AfterAgent denies TurnEnd and flushes!
    const peer = await hyp.openPeer("bob");
    await peer.send("gem-hook-ok", "GEM_CONTRACT_QUEUE_111");

    const afterToolRes = await hyp.exec(["hook", "gemini", "post-tool-use", "--socket", hyp.socketPath], {
      input: JSON.stringify({ session_id: sid, tool_name: "read_file" }),
    });
    assert.equal(
      afterToolRes.stdout.includes("GEM_CONTRACT_QUEUE_111"),
      false,
      "AfterTool must hold queue DM mid-turn",
    );

    const afterAgentRes = await hyp.exec(["hook", "gemini", "stop", "--socket", hyp.socketPath], {
      input: JSON.stringify({ session_id: sid }),
    });
    assert.equal(afterAgentRes.json?.decision, "deny");
    const afterAgentReason = String(afterAgentRes.json?.reason ?? "");
    assert.ok(
      afterAgentReason.includes('<hyphae-inbox handle="gem-hook-ok" unread="1" urgency="queue">') &&
        afterAgentReason.includes('<dm from="gem-contract@local/bob" count="1"/>') &&
        !afterAgentReason.includes("GEM_CONTRACT_QUEUE_111"),
      `AfterAgent must emit metadata-only XML digest for held queue DM (RFC 0004): ${afterAgentRes.stdout}`,
    );

    await mcp.close();
  });
});

test("Real Gemini CLI: BeforeTool enrollment, AfterTool/AfterAgent pauseUntil(gate) latch, and multi-session isolation", async (t) => {
  const geminiBin = resolveGeminiBin();
  if (!geminiBin) {
    t.skip(
      "gemini binary not found (run `node itest/scripts/provision.mjs --tools gemini` or set GEMINI_BIN)",
    );
    return;
  }

  await withSandbox("gemini-cli-live-e2e", async (sandbox) => {
    const hyp = new HypCli(sandbox);
    await hyp.onboard({ nodeId: "gem-live@local", noSkills: true, noCommands: true });
    await hyp.startDaemon();

    const shim = await LlmShimServer.start({
      sandbox,
      auditors: {
        allowBridge: false,
        allowKv: false,
        allowedRoles: ["gemini-main", "gemini-peer"],
      },
    });

    const queuePayload = "GEMINI_QUEUE_HELD_MIDTURN_601";
    const interruptPayload = "GEMINI_INTERRUPT_PREEMPT_602";
    const peerOnlyPayload = "GEMINI_SESSION_B_ONLY_603";
    shim.auditors.registerUntrustedPayload("gem-queue", queuePayload);
    shim.auditors.registerUntrustedPayload("gem-int", interruptPayload);
    shim.auditors.registerUntrustedPayload("gem-b-only", peerOnlyPayload);

    const sampleFile = path.join(sandbox.paths.workspaceDir, "gem-note.txt");
    fs.writeFileSync(sampleFile, "gemini hermetic workspace note\n");

    const gemMain = await GeminiHarness.create({
      sandbox,
      hyp,
      shim,
      geminiBin,
      role: "gemini-main",
    });
    const gemPeer = await GeminiHarness.create({
      sandbox,
      hyp,
      shim,
      geminiBin,
      role: "gemini-peer",
      profileHomeDir: path.join(sandbox.paths.rootDir, "gem-peer-home"),
    });

    const peerNormal = await hyp.openPeer("bob");
    const peerVip = await hyp.openPeer("vip");
    const sink = await hyp.openPeer("sink");

    const gateBeforeRead1 = createGate("gem-before-read-1");
    const gateBeforeRead2 = createGate("gem-before-read-2");

    let sawRead1WithoutQueue = false;
    let sawInterruptInAfterTool = false;
    let sawQueueInAfterAgent = false;

    shim.script("gemini-main", [
      {
        name: "gem-enroll",
        once: true,
        when: (req) =>
          req.advertisedTools.some((tool) => tool.canonicalHyphaeName === "hyp_mesh") &&
          req.anyMessageContains("START_GEMINI_LATCH"),
        do: (req) => callTool(req, "hyp_mesh", { action: "join", handle: "gem-main" }),
      },
      {
        name: "gem-pause-read-1",
        once: true,
        when: (req) => req.lastToolResult("hyp_mesh")?.json?.handle === "gem-main",
        do: (req) =>
          pauseUntil(gateBeforeRead1, callTool(req, "read_file", { file_path: "gem-note.txt" })),
      },
      {
        name: "gem-assert-queue-held-pause-read-2",
        once: true,
        when: (req) =>
          Boolean(req.lastToolResult("read_file")) &&
          !req.anyMessageContains(/urgency=\\?"interrupt\\?"/),
        assert: (req) => {
          assert.equal(
            req.rawBody.includes(queuePayload),
            false,
            `Gemini AfterTool MUST hold queue DM '${queuePayload}' mid-turn!`,
          );
          assert.equal(
            req.anyMessageContains(/(?:<|&lt;)hyphae-inbox\s/),
            false,
            `Gemini AfterTool #1 MUST NOT emit a digest for fresh queue DM!`,
          );
          sawRead1WithoutQueue = true;
        },
        do: (req) =>
          pauseUntil(gateBeforeRead2, callTool(req, "read_file", { file_path: "gem-note.txt" })),
      },
      {
        name: "gem-assert-interrupt-digest-and-read-vip",
        once: true,
        when: (req) =>
          req.anyMessageContains(/urgency=\\?"interrupt\\?"/) &&
          req.anyMessageContains(/from=\\?"gem-live@local\/vip\\?"/) &&
          !req.anyMessageContains(interruptPayload),
        assert: (req) => {
          assert.equal(
            req.rawBody.includes(interruptPayload),
            false,
            `RFC 0004: Gemini AfterTool digest MUST NEVER leak raw interrupt body '${interruptPayload}'`,
          );
          assert.equal(
            req.rawBody.includes(queuePayload),
            false,
            "Queue DM must stay held until AfterAgent",
          );
          sawInterruptInAfterTool = true;
        },
        do: (req) =>
          callTool(req, "hyp_inbox", {
            filter: { from: "gem-live@local/vip" },
          }),
      },
      {
        name: "gem-after-vip-inbox-end-turn",
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
        do: () => emitText("GEMINI_END_TURN_FOR_AFTER_AGENT"),
      },
      {
        name: "gem-after-agent-queue-digest-read-inbox",
        once: true,
        when: (req) =>
          req.anyMessageContains('urgency="queue"') &&
          req.anyMessageContains('from="gem-live@local/bob"') &&
          !req.anyMessageContains(queuePayload),
        assert: (req) => {
          assert.equal(
            req.rawBody.includes(queuePayload),
            false,
            `RFC 0004: Gemini AfterAgent digest MUST NEVER leak raw queue body '${queuePayload}'`,
          );
          assert.equal(
            req.rawBody.includes(peerOnlyPayload),
            false,
            "Session A must NEVER see Session B's DM",
          );
          sawQueueInAfterAgent = true;
        },
        do: (req) => callTool(req, "hyp_inbox", {}),
      },
      {
        name: "gem-after-agent-queue-send-ack",
        once: true,
        when: (req) => req.lastToolResult("hyp_inbox")?.text.includes(queuePayload) === true,
        assert: (req) => {
          assert.equal(
            req.rawBody.includes(peerOnlyPayload),
            false,
            "Session A must NEVER see Session B's DM",
          );
        },
        do: (req) =>
          callTool(req, "hyp_send", {
            to: "sink",
            text: `GEM_ACK:${interruptPayload}+${queuePayload}`,
          }),
      },
      {
        name: "gem-finish",
        when: (req) =>
          Boolean(req.lastToolResult("hyp_send")?.json) &&
          !req.lastToolResult("hyp_send")?.isError,
        do: () => emitText("GEMINI_LATCH_COMPLETE"),
      },
      {
        name: "gem-waiter-ack",
        when: (req) => req.anyMessageContains("no background waiter is running yet"),
        do: () => emitText("GEMINI_STANDING_BY"),
      },
    ]);

    shim.script("gemini-peer", [
      {
        name: "peer-enroll",
        once: true,
        when: (req) =>
          req.advertisedTools.some((tool) => tool.canonicalHyphaeName === "hyp_mesh") &&
          req.anyMessageContains("ENROLL_GEM_B"),
        do: (req) => callTool(req, "hyp_mesh", { action: "join", handle: "gem-peer" }),
      },
      {
        name: "peer-enroll-done",
        once: true,
        when: (req) => req.lastToolResult("hyp_mesh")?.json?.handle === "gem-peer",
        do: () => emitText("GEM_B_ENROLLED"),
      },
      {
        name: "peer-read-digest",
        once: true,
        when: (req) =>
          req.anyMessageContains(/(?:<|&lt;)hyphae-inbox\s/) &&
          !req.anyMessageContains(peerOnlyPayload),
        assert: (req) => {
          assert.equal(req.rawBody.includes(peerOnlyPayload), false, "RFC 0004: hook must not leak raw body");
          assert.equal(req.rawBody.includes(queuePayload), false, "Session B must NEVER see Session A's DM");
          assert.equal(req.rawBody.includes(interruptPayload), false, "Session B must NEVER see Session A's DM");
        },
        do: (req) => callTool(req, "hyp_inbox", {}),
      },
      {
        name: "peer-receive-own",
        when: (req) => req.anyMessageContains(peerOnlyPayload),
        assert: (req) => {
          assert.equal(req.rawBody.includes(queuePayload), false, "Session B must NEVER see Session A's DM");
          assert.equal(req.rawBody.includes(interruptPayload), false, "Session B must NEVER see Session A's DM");
        },
        do: () => emitText("GEM_B_GOT_OWN"),
      },
      {
        name: "peer-waiter-ack",
        when: (req) => req.anyMessageContains("no background waiter is running yet"),
        do: () => emitText("GEM_B_STANDING_BY"),
      },
    ]);

    // Enroll Session B first so both sessions share the same `hyp daemon` during Session A's latch test!
    const peerUuid = crypto.randomUUID();
    const peerRes1 = await gemPeer.runPrint("ENROLL_GEM_B", { sessionId: peerUuid });
    assert.equal(peerRes1.exitCode, 0, `Gemini Session B enroll failed: ${peerRes1.stderr}`);
    await peerNormal.send("gem-peer", peerOnlyPayload);

    // Run Session A latch test!
    const mainUuid = crypto.randomUUID();
    const runMain = gemMain.spawnPrint("START_GEMINI_LATCH", { sessionId: mainUuid });

    await gateBeforeRead1.waitForWaiters(1, 30_000);
    const insMain = await hyp.inspect({ handle: "gem-main" });
    const mainSess = extractSessionsFromInspect(insMain.json)[0];
    assert.equal(mainSess?.sessionId, `gemini:${mainUuid}`);

    await peerNormal.send("gem-main", queuePayload);
    gateBeforeRead1.release();

    await gateBeforeRead2.waitForWaiters(1, 20_000);
    await hyp.session([
      "--session",
      `gemini:${mainUuid}`,
      "rule",
      "gem-live@local/vip",
      "interrupt",
    ]);
    await peerVip.send("gem-main", interruptPayload);
    gateBeforeRead2.release();

    const mainResult = await runMain.done;
    assert.equal(
      mainResult.exitCode,
      0,
      `Gemini Session A failed (exit=${mainResult.exitCode})\nSTDOUT:\n${mainResult.stdout.slice(-2000)}\nSTDERR:\n${mainResult.stderr.slice(-2000)}`,
    );
    assert.equal(sawRead1WithoutQueue, true, "AfterTool #1 must hold queue DM");
    assert.equal(sawInterruptInAfterTool, true, "AfterTool #2 must inject interrupt DM");
    assert.equal(sawQueueInAfterAgent, true, "AfterAgent must flush held queue DM");

    const sinkInbox = await sink.inbox({ ack: true });
    assert.ok(
      JSON.stringify(sinkInbox).includes(`GEM_ACK:${interruptPayload}+${queuePayload}`),
      `Expected @sink to receive Gemini ACK DM, got: ${JSON.stringify(sinkInbox)}`,
    );

    // Resume Session B -> receives ONLY `peerOnlyPayload` via `BeforeAgent` hook!
    const peerRes2 = await gemPeer.runPrint("CHECK_GEM_B", { resume: peerRes1.sessionId ?? "latest" });
    assert.equal(peerRes2.exitCode, 0, `Gemini Session B resume failed: ${peerRes2.stderr}`);
    assert.ok(
      shim.getTurns("gemini-peer").some((tr) => tr.request.rawBody.includes(peerOnlyPayload)),
      "Session B must receive its own DM on resume",
    );

    shim.assertAllClean();
  });
});
