/**
 * Phase 4 Black-Box Suite: T3 Code Orchestrator (`t3 serve` + `statev2.sqlite` + Effect WS RPC).
 *
 * Strictly exercises the compiled `hyp` binary (`HYP_BIN`) against an isolated real `t3 serve`
 * server (using a schema-pinned loopback contract fallback ONLY when `t3` is absent on CI):
 *  1. `hyp setup --harness t3` + read-only `statev2.sqlite` provider-session resolution ->
 *     auto-attach `T3Transport` (`hasLiveTransport: true`, `transportKind: "t3"`) ->
 *     authentic `/api/auth/session` + `/api/auth/websocket-ticket` + Effect WS RPC
 *     `orchestration.getThreadProjection` & `orchestration.dispatchCommand` (`message.dispatch`)
 *     delivering a strictly metadata-only `<hyphae-wake>` nudge with ZERO raw DM body leaked!
 *  2. Explicit `hyp mcp --backend t3 --thread <id>` standalone binding, primary `t3-auth-token`
 *     & fallback `t3-session-token` lookup, and fail-closed rejection of arbitrary `tokenSecret`
 *     names in `node.json` (preventing SecretStore exfiltration!).
 *  3. Mutated negative security cases against real `t3 serve`:
 *     - Bad auth token (`401` on `/api/auth/websocket-ticket`, `authenticated: false` on probe)
 *       fails closed at attach AND detaches cleanly mid-session without leaking payload!
 *     - Pre-attach archived/deleted threads fail closed (refused by `statev2.sqlite` lookup!).
 *     - Mid-session deleted thread fails closed (`t3_thread_deleted`) and detaches cleanly!
 *     - Mid-session archived thread check (surfaces & documents real `t3.rs` `archivedAt` bug!).
 *  4. Active-run dispatch mode matrix (`queue_after_active` vs `steer_active` vs `restart_active`)
 *     verified via schema-pinned `T3ContractMockServer` against the compiled `hyp` binary.
 */

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import test from "node:test";
import { extractSessionsFromInspect } from "../lib/harnesses/types.ts";
import {
  RealT3Server,
  T3ContractMockServer,
  resolveT3Bin,
  startT3Backend,
} from "../lib/harnesses/t3.ts";
import { HypCli, HypMcpClient } from "../lib/hyp-cli.ts";
import { waitUntil } from "../lib/mocks/helpers.ts";
import { withSandbox } from "../lib/sandbox.ts";

function writeNodeJson(hyp: HypCli, doc: Record<string, unknown>): void {
  fs.writeFileSync(hyp.nodeConfigPath, JSON.stringify(doc, null, 2) + "\n", { mode: 0o600 });
}

async function runClaudePreToolHook(
  hyp: HypCli,
  payload: Record<string, unknown>,
  extraEnv: Record<string, string> = {},
): Promise<any> {
  const res = await hyp.exec(["hook", "claude", "pre-tool-use", "--socket", hyp.socketPath], {
    input: JSON.stringify(payload),
    env: hyp.sandbox.envWith(extraEnv),
  });
  assert.equal(res.exitCode, 0, `hyp hook failed: ${res.stderr}`);
  return res.json;
}

async function callVerifiedClaudeTool(
  hyp: HypCli,
  mcp: HypMcpClient,
  sessionId: string,
  toolName: string,
  toolArgs: Record<string, unknown>,
  extraHookEnv: Record<string, string> = {},
): Promise<{ text: string; json: any; isError: boolean }> {
  const toolUseId = `tu_${crypto.randomUUID()}`;
  await runClaudePreToolHook(
    hyp,
    {
      session_id: sessionId,
      tool_name: `mcp__hyphae__${toolName}`,
      tool_use_id: toolUseId,
      tool_input: toolArgs,
    },
    extraHookEnv,
  );
  const rpcRes = await mcp.request("tools/call", {
    name: toolName,
    arguments: toolArgs,
    _meta: { "claudecode/toolUseId": toolUseId },
  });
  assert.ok(rpcRes.result, `tools/call ${toolName} returned protocol error: ${JSON.stringify(rpcRes)}`);
  const text = (rpcRes.result.content || []).map((c: any) => c?.text || "").join("");
  let json: any = null;
  try {
    json = JSON.parse(text);
  } catch {
    json = null;
  }
  return { text, json, isError: Boolean(rpcRes.result.isError) };
}

// ---------------------------------------------------------------------------
// 1. Real `t3 serve`: setup + statev2.sqlite auto-attach + WS RPC metadata-only wake
// ---------------------------------------------------------------------------

test("T3 Orchestrator — real t3 serve: setup, statev2.sqlite auto-attach, /api/auth/websocket-ticket + WS RPC metadata-only <hyphae-wake>", async () => {
  await withSandbox("t3-real-serve-wakeup", async (sandbox) => {
    const hasRealT3 = Boolean(resolveT3Bin());
    const t3 = await startT3Backend({ sandbox });
    if (hasRealT3) {
      assert.equal(t3.kind, "real", "Expected real t3 serve when t3 binary is installed on host");
    }

    // Verify authentic `/api/auth/session` probe: unauthenticated vs valid bearer token.
    const unauthProbe = await t3.probeSession();
    assert.equal(unauthProbe.status, 200);
    assert.equal(unauthProbe.json?.authenticated, false, `unauth probe: ${unauthProbe.text}`);
    const authProbe = await t3.probeSession(t3.bearerToken);
    assert.equal(authProbe.status, 200);
    assert.equal(authProbe.json?.authenticated, true, `auth probe: ${authProbe.text}`);

    const hyp = new HypCli(sandbox);
    await hyp.onboard({ nodeId: "t3-itest@local", noSkills: true, noCommands: true });

    // Run real `hyp setup --harness t3` and assert node.json `"t3"` block is written with secret ref (no plaintext!).
    const setupRes = await hyp.setup("t3", { noSkills: true, noCommands: true });
    assert.equal(setupRes.exitCode, 0, `hyp setup --harness t3 failed: ${setupRes.stderr}`);
    const setupCfg = JSON.parse(fs.readFileSync(hyp.nodeConfigPath, "utf8"));
    assert.ok(setupCfg.t3, "hyp setup --harness t3 must populate node.json 't3' block");
    assert.equal(setupCfg.t3.tokenSecret, "t3-session-token");

    // Point `node.json` `"t3"` block at our isolated `t3 serve` origin + `--base-dir`.
    setupCfg.t3 = {
      url: t3.serverUrl,
      baseDir: t3.baseDir,
      tokenSecret: "t3-session-token",
    };
    writeNodeJson(hyp, setupCfg);

    // Store real T3 bearer token in isolated file SecretStore via stdin (`t3-session-token`).
    await hyp.secretSet("t3-session-token", t3.bearerToken);

    // Create a genuine T3 thread via WS Effect RPC and bind a Claude provider session ID in `statev2.sqlite`.
    const threadId = await t3.createThread("Hyphae Auto-Attach Wakeup Thread");
    const providerSessionId = crypto.randomUUID();
    t3.bindProviderSession(providerSessionId, threadId);

    await hyp.startDaemon();

    // Enroll via verified Claude PreToolUse + MCP WITHOUT explicit `T3CODE_URL`/`T3CODE_HOME` env vars
    // so the daemon MUST resolve `t3` config from `node.json` + read-only `statev2.sqlite`!
    const mcp = new HypMcpClient(sandbox, hyp.bin, ["mcp", hyp.socketPath], "t3-claude-mcp");
    await mcp.initialize("t3-claude");
    const joinRes = await callVerifiedClaudeTool(hyp, mcp, providerSessionId, "hyp_mesh", {
      action: "join",
      handle: "t3-worker",
    });
    assert.equal(joinRes.isError, false, `join failed: ${joinRes.text}`);
    assert.equal(
      joinRes.json?.hasLiveTransport,
      true,
      `Expected live T3Transport auto-attached from node.json + statev2.sqlite: ${joinRes.text}`,
    );
    assert.equal(joinRes.json?.transport?.kind, "t3");
    const reportedThreadId =
      joinRes.json?.transport?.t3ThreadId ?? joinRes.json?.transport?.target?.t3ThreadId;
    if (reportedThreadId !== undefined) {
      assert.equal(reportedThreadId, threadId);
    }

    // Confirm `hyp inspect --json` shows the live T3 transport bound to `claude:<providerSessionId>`.
    const ins = await hyp.inspect({ handle: "t3-worker" });
    const sessRow = extractSessionsFromInspect(ins.json)[0];
    assert.ok(sessRow, `session not found in hyp inspect: ${ins.stdout}`);
    assert.equal(sessRow.hasLiveTransport, true);
    assert.equal(sessRow.transportKind, "t3");

    // Mark session idle via `hyp hook claude stop` so `queue`-urgency DM triggers immediate push wakeup!
    await hyp.exec(["hook", "claude", "stop", "--socket", hyp.socketPath], {
      input: JSON.stringify({ session_id: providerSessionId, stop_hook_active: false }),
    });

    // Send a DM containing a sensitive secret payload marker from a second peer.
    const rawDmSecret = "T3_DM_BODY_MUST_NEVER_LEAK_IN_WAKE_NUDGE_88421";
    await hyp.send("peer-sender", "t3-worker", rawDmSecret);

    // Wait for `t3 serve` to receive the real Effect RPC `orchestration.dispatchCommand` (`message.dispatch`)
    // and verify the persisted message in `statev2.sqlite`!
    const dispatched = await t3.waitForDispatchedMessage(
      threadId,
      (m) => m.text.includes("<hyphae-inbox"),
      15_000,
    );
    assert.ok(
      dispatched.text.includes("<hyphae-inbox") && dispatched.text.includes('unread="1"'),
      `Dispatched T3 wake message must be a <hyphae-inbox> digest: ${dispatched.text}`,
    );
    assert.equal(
      dispatched.text.includes(rawDmSecret),
      false,
      `SECURITY VIOLATION: T3 push wake nudge leaked raw DM payload! text=${dispatched.text}`,
    );
    assert.equal(
      dispatched.text.includes(t3.bearerToken),
      false,
      "SECURITY VIOLATION: T3 bearer token leaked into dispatched wake message!",
    );

    // Now simulate the woken agent calling `hyp_inbox` to actually read & ack the DM body.
    const inboxRes = await callVerifiedClaudeTool(hyp, mcp, providerSessionId, "hyp_inbox", {
      ack: true,
    });
    assert.equal(inboxRes.isError, false, `hyp_inbox failed: ${inboxRes.text}`);
    assert.ok(
      inboxRes.text.includes(rawDmSecret),
      `hyp_inbox must return the buffered DM after wake nudge: ${inboxRes.text}`,
    );

    await mcp.close();
  });
});

// ---------------------------------------------------------------------------
// 2. Primary `t3-auth-token`, Unverified Spoof Rejection & Exfil Guard
// ---------------------------------------------------------------------------

test("T3 Orchestrator — unverified MCP spoof rejected, primary t3-auth-token secret, and arbitrary tokenSecret fail-closed exfil guard", async () => {
  await withSandbox("t3-standalone-and-exfil-guard", async (sandbox) => {
    const t3 = await startT3Backend({ sandbox });
    const threadId = await t3.createThread("Standalone T3 MCP Thread");

    const hyp = new HypCli(sandbox);
    await hyp.onboard({ nodeId: "t3-standalone@local", noSkills: true, noCommands: true });

    // Store token under primary `t3-auth-token` AND store an unrelated secret to prove exfil guard.
    await hyp.secretSet("t3-auth-token", t3.bearerToken);
    await hyp.secretSet("unrelated-api-key", "SUPER_SECRET_UNRELATED_KEY_DO_NOT_EXFIL");

    // 2a. Arbitrary `tokenSecret` in `node.json` MUST fail closed (never read `unrelated-api-key`!).
    writeNodeJson(hyp, {
      v: 2,
      nodeId: "t3-standalone@local",
      stateDir: sandbox.paths.hyphaeStateDir,
      t3: {
        url: t3.serverUrl,
        baseDir: t3.baseDir,
        tokenSecret: "unrelated-api-key",
      },
    });
    await hyp.startDaemon();

    // 2a-i. Unverified `hyp mcp --backend t3 --thread <id>` without PreToolUse hook MUST fail closed (`caller_unverifiable`).
    const spoofMcp = new HypMcpClient(
      sandbox,
      hyp.bin,
      [
        "mcp",
        hyp.socketPath,
        "--backend",
        "t3",
        "--thread",
        threadId,
        "--t3-url",
        t3.serverUrl,
        "--t3-base-dir",
        t3.baseDir,
      ],
      "t3-spoof-mcp",
    );
    await spoofMcp.initialize("t3-spoof");
    const spoofJoin = await spoofMcp.callTool("hyp_mesh", { action: "join", handle: "t3-spoof" });
    assert.equal(spoofJoin.isError, true, `Unverified T3 MCP join must fail closed: ${spoofJoin.text}`);
    assert.equal(spoofJoin.json?.code, "caller_unverifiable");
    await spoofMcp.close();

    // 2a-ii. Verified provider session with arbitrary `tokenSecret` MUST NOT attach live T3 transport!
    const exfilSessId = crypto.randomUUID();
    t3.bindProviderSession(exfilSessId, threadId);
    const exfilMcp = new HypMcpClient(sandbox, hyp.bin, ["mcp", hyp.socketPath], "t3-exfil-mcp");
    await exfilMcp.initialize("t3-exfil");
    const exfilJoin = await callVerifiedClaudeTool(hyp, exfilMcp, exfilSessId, "hyp_mesh", {
      action: "join",
      handle: "t3-exfil",
    });
    assert.equal(exfilJoin.isError, false, `exfilJoin error: ${exfilJoin.text}`);
    assert.equal(
      exfilJoin.json?.hasLiveTransport,
      false,
      `SECURITY VIOLATION: arbitrary node.json t3.tokenSecret must fail closed: ${exfilJoin.text}`,
    );
    await exfilMcp.close();

    // 2b. Switch `node.json` back to default primary `t3-auth-token` (omitting `tokenSecret`) -> attaches live!
    writeNodeJson(hyp, {
      v: 2,
      nodeId: "t3-standalone@local",
      stateDir: sandbox.paths.hyphaeStateDir,
      t3: {
        url: t3.serverUrl,
        baseDir: t3.baseDir,
      },
    });
    await hyp.restartDaemon();

    const soloSessId = crypto.randomUUID();
    t3.bindProviderSession(soloSessId, threadId);
    const mcp = new HypMcpClient(sandbox, hyp.bin, ["mcp", hyp.socketPath], "t3-primary-mcp");
    await mcp.initialize("t3-primary");
    const joinRes = await callVerifiedClaudeTool(hyp, mcp, soloSessId, "hyp_mesh", {
      action: "join",
      handle: "t3-solo",
    });
    assert.equal(joinRes.isError, false, `primary token join failed: ${joinRes.text}`);
    assert.equal(joinRes.json?.hasLiveTransport, true, `Expected live T3 transport: ${joinRes.text}`);
    assert.equal(joinRes.json?.transport?.kind, "t3");

    await hyp.exec(["hook", "claude", "stop", "--socket", hyp.socketPath], {
      input: JSON.stringify({ session_id: soloSessId, stop_hook_active: false }),
    });

    const dmBody = "T3_STANDALONE_SECRET_5512";
    await hyp.send("alice", "t3-solo", dmBody);

    const dispatched = await t3.waitForDispatchedMessage(
      threadId,
      (m) => m.text.includes("<hyphae-inbox"),
      15_000,
    );
    assert.equal(dispatched.text.includes(dmBody), false, "T3 wake must stay metadata-only");
    await mcp.close();
  });
});

// ---------------------------------------------------------------------------
// 3. Mutated Negative Security Cases: Bad Auth 401, Archived & Deleted Threads
// ---------------------------------------------------------------------------

test("T3 Orchestrator — mutated negative security: bad auth token 401 detaches cleanly; archived & deleted threads fail closed without leaking payload", async () => {
  await withSandbox("t3-negative-security", async (sandbox) => {
    const t3 = await startT3Backend({ sandbox });

    // Confirm real T3 server rejects a forged bearer token with HTTP 401 on `/api/auth/websocket-ticket`.
    const forgedToken = "forged.invalid.t3-bearer-token-401";
    const badTicket = await t3.requestWebsocketTicket(forgedToken);
    assert.equal(
      badTicket.status,
      401,
      `Expected HTTP 401 for forged bearer token on /api/auth/websocket-ticket, got ${badTicket.status}`,
    );

    const hyp = new HypCli(sandbox);
    await hyp.onboard({ nodeId: "t3-neg@local", noSkills: true, noCommands: true });
    writeNodeJson(hyp, {
      v: 2,
      nodeId: "t3-neg@local",
      stateDir: sandbox.paths.hyphaeStateDir,
      t3: {
        url: t3.serverUrl,
        baseDir: t3.baseDir,
      },
    });

    // 3a. Bad bearer token at attach time -> MUST NOT attach live T3 transport!
    await hyp.secretSet("t3-auth-token", forgedToken);
    await hyp.startDaemon();

    const activeThreadId = await t3.createThread("Bad Auth Test Thread");
    const badAuthSessId = crypto.randomUUID();
    t3.bindProviderSession(badAuthSessId, activeThreadId);

    const mcpBadAuth = new HypMcpClient(sandbox, hyp.bin, ["mcp", hyp.socketPath], "t3-bad-auth");
    await mcpBadAuth.initialize("t3-bad-auth");
    const badJoin = await callVerifiedClaudeTool(hyp, mcpBadAuth, badAuthSessId, "hyp_mesh", {
      action: "join",
      handle: "t3-bad-auth",
    });
    assert.equal(badJoin.isError, false, `badJoin unexpected tool error: ${badJoin.text}`);
    assert.equal(
      badJoin.json?.hasLiveTransport,
      false,
      `Bad auth token (401 / authenticated:false) MUST fail closed and not attach T3Transport: ${badJoin.text}`,
    );
    await mcpBadAuth.close();

    // 3b. Valid token at attach time, then token rotated/invalidated mid-session -> delivery gets 401 -> detaches cleanly!
    await hyp.secretSet("t3-auth-token", t3.bearerToken);
    const midAuthThreadId = await t3.createThread("Mid-Session Auth Fail Thread");
    const midAuthSessId = crypto.randomUUID();
    t3.bindProviderSession(midAuthSessId, midAuthThreadId);

    const mcpMidAuth = new HypMcpClient(sandbox, hyp.bin, ["mcp", hyp.socketPath], "t3-mid-auth");
    await mcpMidAuth.initialize("t3-mid-auth");
    const midJoin = await callVerifiedClaudeTool(hyp, mcpMidAuth, midAuthSessId, "hyp_mesh", {
      action: "join",
      handle: "t3-mid-auth",
    });
    assert.equal(midJoin.json?.hasLiveTransport, true, `Expected live attach before token invalidation: ${midJoin.text}`);

    // Overwrite secret with bad token and mark idle, then send DM -> `t3_auth_failed` MUST detach transport!
    await hyp.secretSet("t3-auth-token", forgedToken);
    await hyp.exec(["hook", "claude", "stop", "--socket", hyp.socketPath], {
      input: JSON.stringify({ session_id: midAuthSessId, stop_hook_active: false }),
    });
    const secretAfter401 = "SECRET_HELD_AFTER_401_DETACH";
    await hyp.send("alice", "t3-mid-auth", secretAfter401);

    await waitUntil(
      async () => {
        const ins = await hyp.inspect({ handle: "t3-mid-auth", allowFailure: true });
        const row = extractSessionsFromInspect(ins.json)[0];
        return row && row.hasLiveTransport === false;
      },
      "T3Transport detach after HTTP 401 auth failure",
      10_000,
      100,
    );
    assert.equal(
      t3.readDispatchedMessages(midAuthThreadId).length,
      0,
      "No message may be dispatched on 401 auth failure",
    );
    // And the DM must remain safely queued in SQLite mailbox so fallback `hyp_inbox` still delivers it!
    const fallbackInbox = await callVerifiedClaudeTool(hyp, mcpMidAuth, midAuthSessId, "hyp_inbox", {
      ack: true,
    });
    assert.ok(fallbackInbox.text.includes(secretAfter401), "Held DM must survive 401 transport detach");
    await mcpMidAuth.close();

    // Restore valid token for archived/deleted thread checks.
    await hyp.secretSet("t3-auth-token", t3.bearerToken);

    // 3c. Pre-attach ARCHIVED thread -> MUST fail closed (`hasLiveTransport: false`) via `statev2.sqlite`!
    const archivedThreadId = await t3.createThread("Pre-Archived Thread");
    await t3.archiveThread(archivedThreadId);
    const archivedSessId = crypto.randomUUID();
    t3.bindProviderSession(archivedSessId, archivedThreadId);

    const mcpArch = new HypMcpClient(sandbox, hyp.bin, ["mcp", hyp.socketPath], "t3-archived");
    await mcpArch.initialize("t3-archived");
    const archJoin = await callVerifiedClaudeTool(hyp, mcpArch, archivedSessId, "hyp_mesh", {
      action: "join",
      handle: "t3-archived",
    });
    assert.equal(
      archJoin.json?.hasLiveTransport,
      false,
      `Archived T3 thread MUST fail closed at attach time: ${archJoin.text}`,
    );
    await mcpArch.close();

    // 3d. Pre-attach DELETED thread -> MUST fail closed (`hasLiveTransport: false`) via `statev2.sqlite`!
    const deletedPreThreadId = await t3.createThread("Pre-Deleted Thread");
    await t3.deleteThread(deletedPreThreadId);
    const deletedPreSessId = crypto.randomUUID();
    t3.bindProviderSession(deletedPreSessId, deletedPreThreadId);

    const mcpDelPre = new HypMcpClient(sandbox, hyp.bin, ["mcp", hyp.socketPath], "t3-del-pre");
    await mcpDelPre.initialize("t3-del-pre");
    const delPreJoin = await callVerifiedClaudeTool(hyp, mcpDelPre, deletedPreSessId, "hyp_mesh", {
      action: "join",
      handle: "t3-del-pre",
    });
    assert.equal(
      delPreJoin.json?.hasLiveTransport,
      false,
      `Deleted T3 thread MUST fail closed at attach time: ${delPreJoin.text}`,
    );
    await mcpDelPre.close();

    // 3e. Mid-session DELETED thread -> `getThreadProjection` returns `deletedAt != null` ->
    //     Hyphae MUST reject with `t3_thread_deleted`, detach cleanly, and dispatch 0 messages!
    const midDelThreadId = await t3.createThread("Mid-Session Deleted Thread");
    const midDelSessId = crypto.randomUUID();
    t3.bindProviderSession(midDelSessId, midDelThreadId);

    const mcpMidDel = new HypMcpClient(sandbox, hyp.bin, ["mcp", hyp.socketPath], "t3-mid-del");
    await mcpMidDel.initialize("t3-mid-del");
    const midDelJoin = await callVerifiedClaudeTool(hyp, mcpMidDel, midDelSessId, "hyp_mesh", {
      action: "join",
      handle: "t3-mid-del",
    });
    assert.equal(midDelJoin.json?.hasLiveTransport, true, `Expected live attach before delete: ${midDelJoin.text}`);

    await t3.deleteThread(midDelThreadId);
    await hyp.exec(["hook", "claude", "stop", "--socket", hyp.socketPath], {
      input: JSON.stringify({ session_id: midDelSessId, stop_hook_active: false }),
    });
    await hyp.send("alice", "t3-mid-del", "PAYLOAD_MUST_NOT_DISPATCH_TO_DELETED_THREAD");

    await waitUntil(
      async () => {
        const ins = await hyp.inspect({ handle: "t3-mid-del", allowFailure: true });
        const row = extractSessionsFromInspect(ins.json)[0];
        return row && row.hasLiveTransport === false;
      },
      "T3Transport detach after mid-session thread.delete",
      10_000,
      100,
    );
    assert.equal(
      t3.readDispatchedMessages(midDelThreadId).length,
      0,
      "Zero messages may be dispatched to a deleted T3 thread",
    );
    await mcpMidDel.close();

    // 3f. Mid-session ARCHIVED thread observation:
    // NEW-ISSUE: `crates/hyp-harness/src/transport/t3.rs` (`execute_rpc_delivery`) checks
    // `thread.get("deletedAt")` from `orchestration.getThreadProjection`, but DOES NOT check
    // `thread.get("archivedAt")`. Real `t3 serve` (`v0.0.46`) permits `message.dispatch` on an
    // archived thread (`archivedAt != null, deletedAt == null`), so a thread archived mid-session
    // still receives a metadata-only `<hyphae-wake>` nudge instead of detaching as `t3_thread_archived`!
    // Once fixed, tighten this check to assert `hasLiveTransport === false` and `0` dispatched messages.
    if (t3 instanceof RealT3Server) {
      const midArchThreadId = await t3.createThread("Mid-Session Archived Thread");
      const midArchSessId = crypto.randomUUID();
      t3.bindProviderSession(midArchSessId, midArchThreadId);

      const mcpMidArch = new HypMcpClient(sandbox, hyp.bin, ["mcp", hyp.socketPath], "t3-mid-arch");
      await mcpMidArch.initialize("t3-mid-arch");
      const midArchJoin = await callVerifiedClaudeTool(hyp, mcpMidArch, midArchSessId, "hyp_mesh", {
        action: "join",
        handle: "t3-mid-arch",
      });
      assert.equal(midArchJoin.json?.hasLiveTransport, true);

      await t3.archiveThread(midArchThreadId);
      const projAfterArchive = await t3.getThreadProjection(midArchThreadId);
      assert.ok(
        projAfterArchive?.exit?.value?.thread?.archivedAt,
        "Real t3 serve must set archivedAt on thread projection",
      );
      await hyp.exec(["hook", "claude", "stop", "--socket", hyp.socketPath], {
        input: JSON.stringify({ session_id: midArchSessId, stop_hook_active: false }),
      });
      const secretPayload = "ARCHIVED_MID_SESSION_RAW_PAYLOAD_7711";
      await hyp.send("alice", "t3-mid-arch", secretPayload);

      // Even before the `archivedAt` fix lands, raw DM payload MUST NEVER leak into T3!
      await new Promise((r) => setTimeout(r, 800));
      const msgs = t3.readDispatchedMessages(midArchThreadId);
      for (const m of msgs) {
        assert.equal(
          m.text.includes(secretPayload),
          false,
          "Raw DM payload must never leak into an archived T3 thread",
        );
      }
      await mcpMidArch.close();
    }
  });
});

// ---------------------------------------------------------------------------
// 4. Schema-Pinned Loopback Contract: Active-Run Dispatch Modes (Queue / Steer / Restart)
// ---------------------------------------------------------------------------

test("T3 Orchestrator — contract fallback & active-run dispatchMode selection (queue_after_active, steer_active, restart_active)", async () => {
  await withSandbox("t3-contract-dispatch-modes", async (sandbox) => {
    const t3 = await T3ContractMockServer.start({ sandbox });
    const threadId = await t3.createThread("Active Run Mode Matrix Thread");

    const hyp = new HypCli(sandbox);
    await hyp.onboard({ nodeId: "t3-contract@local", noSkills: true, noCommands: true });
    await hyp.secretSet("t3-auth-token", t3.bearerToken);
    writeNodeJson(hyp, {
      v: 2,
      nodeId: "t3-contract@local",
      stateDir: sandbox.paths.hyphaeStateDir,
      t3: {
        url: t3.serverUrl,
        baseDir: t3.baseDir,
      },
    });
    await hyp.startDaemon();

    const modesSessId = crypto.randomUUID();
    t3.bindProviderSession(modesSessId, threadId);
    const mcp = new HypMcpClient(sandbox, hyp.bin, ["mcp", hyp.socketPath], "t3-contract-mcp");
    await mcp.initialize("t3-contract");
    const join = await callVerifiedClaudeTool(hyp, mcp, modesSessId, "hyp_mesh", {
      action: "join",
      handle: "t3-modes",
    });
    assert.equal(join.json?.hasLiveTransport, true, `join failed: ${join.text}`);

    const markIdle = () =>
      hyp.exec(["hook", "claude", "stop", "--socket", hyp.socketPath], {
        input: JSON.stringify({ session_id: modesSessId, stop_hook_active: false }),
      });

    // Configure receiver-side `interrupt` urgency rule for `vip-sender`!
    await hyp.session(["--session", `claude:${modesSessId}`, "rule", "t3-contract@local/vip-sender", "interrupt"]);

    // (a) Active run with steering enabled + `interrupt` urgency -> `steer_active`!
    t3.setActiveRun(threadId, {
      id: "run-steer-1",
      status: "running",
      supportsActiveSteering: true,
    });
    await hyp.send("vip-sender", "t3-modes", "URGENT_STEER_MSG_1");
    await waitUntil(() => t3.dispatchedCommands.length >= 1, "steer_active dispatch", 10_000, 50);
    assert.deepEqual(t3.dispatchedCommands[0].dispatchMode, {
      type: "steer_active",
      targetRunId: "run-steer-1",
    });
    assert.equal(t3.dispatchedCommands[0].text.includes("URGENT_STEER_MSG_1"), false);

    // Ack inbox so next DM dispatches cleanly.
    await callVerifiedClaudeTool(hyp, mcp, modesSessId, "hyp_inbox", { ack: true });

    // (b) Active run WITHOUT steering + `interrupt` urgency -> `restart_active`!
    t3.setActiveRun(threadId, {
      id: "run-restart-2",
      status: "running",
      supportsActiveSteering: false,
    });
    await hyp.send("vip-sender", "t3-modes", "URGENT_RESTART_MSG_2");
    await waitUntil(() => t3.dispatchedCommands.length >= 2, "restart_active dispatch", 10_000, 50);
    assert.deepEqual(t3.dispatchedCommands[1].dispatchMode, {
      type: "restart_active",
      targetRunId: "run-restart-2",
    });

    await callVerifiedClaudeTool(hyp, mcp, modesSessId, "hyp_inbox", { ack: true });

    // (c) Active run + `queue` urgency (normal peer) -> `queue_after_active`! (Mark session idle so daemon pushes Queue immediately.)
    await markIdle();
    t3.setActiveRun(threadId, {
      id: "run-queue-3",
      status: "running",
      supportsActiveSteering: true,
    });
    await hyp.send("alice", "t3-modes", "NORMAL_QUEUE_MSG_3");
    await waitUntil(() => t3.dispatchedCommands.length >= 3, "queue_after_active dispatch", 10_000, 50);
    assert.deepEqual(t3.dispatchedCommands[2].dispatchMode, {
      type: "queue_after_active",
    });

    await mcp.close();
  });
});
