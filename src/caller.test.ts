import assert from "node:assert/strict";
import { test } from "node:test";
import { CallRegistry } from "./caller.ts";
import { handleHookPayload } from "./hooks.ts";
import { extractMetaCallId } from "./mcp.ts";
import { normalizeMeshToolName } from "./protocol.ts";
import { inferSessionIdFromEnv } from "./wait.ts";

test("normalizeMeshToolName handles plain and harness-prefixed MCP names", () => {
  assert.equal(normalizeMeshToolName("mesh_join"), "mesh_join");
  assert.equal(normalizeMeshToolName("mcp__hyphae__mesh_send"), "mesh_send");
  assert.equal(normalizeMeshToolName("mcp_hyphae_mesh_join"), "mesh_join");
  assert.equal(normalizeMeshToolName("hyphae_mesh_peers"), "mesh_peers");
  assert.equal(normalizeMeshToolName("hyphae.mesh_subscribe"), "mesh_subscribe");
  assert.equal(normalizeMeshToolName("hyphae/mesh_peers"), "mesh_peers");
  assert.equal(normalizeMeshToolName("run_command"), null);
  assert.equal(normalizeMeshToolName("mcp__other__foo"), null);
});

test("CallRegistry resolves per-call identity, enforces tool match, single-use, and fails closed", async () => {
  const registry = new CallRegistry();
  const reg = registry.register({
    harness: "claude",
    sessionId: "claude:sess-1",
    backend: { kind: "claude" },
    tool: "mcp__hyphae__mesh_join",
    callId: "toolu_abc",
  });

  // Wrong tool name must not match
  const wrongTool = await registry.resolve("mesh_send", "toolu_abc", undefined, 0);
  assert.equal(wrongTool.ok, false);
  if (!wrongTool.ok) assert.equal(wrongTool.code, "caller_not_found");

  // Matching callId + tool resolves and consumes single-use entry
  const resolved = await registry.resolve("mesh_join", "toolu_abc", undefined, 0);
  assert.equal(resolved.ok, true);
  if (resolved.ok) {
    assert.equal(resolved.sessionId, "claude:sess-1");
    assert.equal(resolved.verifiedBy, "callId");
  }

  // Replaying either callId or token after consumption fails closed
  const replayId = await registry.resolve("mesh_join", "toolu_abc", undefined, 0);
  assert.equal(replayId.ok, false);
  const replayToken = await registry.resolve("mesh_join", undefined, reg.token, 0);
  assert.equal(replayToken.ok, false);

  // Missing both callId and token fails closed with caller_unverifiable
  const unverified = await registry.resolve("mesh_join", undefined, undefined, 0);
  assert.equal(unverified.ok, false);
  if (!unverified.ok) assert.equal(unverified.code, "caller_unverifiable");
});

test("CallRegistry resolves Antigravity PreToolUse overwrite tokens and blocks cross-session spoofing", async () => {
  const registry = new CallRegistry();
  const convA = registry.register({
    harness: "antigravity",
    sessionId: "antigravity:conv-a",
    backend: { kind: "antigravity" },
    tool: "mesh_send",
    callId: "call_1",
  });
  const convB = registry.register({
    harness: "antigravity",
    sessionId: "antigravity:conv-b",
    backend: { kind: "antigravity" },
    tool: "mesh_send",
    callId: "call_2",
  });

  const forged = await registry.resolve("mesh_send", undefined, "forged-token", 0);
  assert.equal(forged.ok, false);

  const resB = await registry.resolve("mesh_send", undefined, convB.token, 0);
  assert.equal(resB.ok, true);
  if (resB.ok) assert.equal(resB.sessionId, "antigravity:conv-b");

  const resA = await registry.resolve("mesh_send", undefined, convA.token, 0);
  assert.equal(resA.ok, true);
  if (resA.ok) assert.equal(resA.sessionId, "antigravity:conv-a");
});

test("Antigravity PreToolUse overwrites _meshCall, PreInvocation injects queued items, Stop auto-arms once", async () => {
  const calls: Record<string, unknown>[] = [];
  let queued = [{ text: "mesh from bob/ops · reply with mesh_send\n\nhello" }];
  let hasLiveTransport = false;

  const rpc = async (_socket: string, packet: Record<string, unknown>) => {
    calls.push(packet);
    if (packet.type === "call.start") return { ok: true, result: { callToken: "tok_123" } };
    if (packet.type === "mailbox.drain") {
      const items = queued;
      queued = [];
      return { ok: true, result: { items } };
    }
    if (packet.type === "session.status") {
      return { ok: true, result: { enrolled: true, hasLiveTransport } };
    }
    return { ok: true, result: {} };
  };

  // PreToolUse returns allow + overwrite _meshCall for direct MCP tool calls
  const pre = await handleHookPayload(
    { conversationId: "conv-42", toolCall: { id: "tc-1", name: "mesh_join", args: { handle: "a", _meshCall: "spoof" } } },
    { harness: "antigravity", event: "pre-tool-use", socketPath: "/tmp/unused.sock", rpc },
  );
  assert.deepEqual(pre, { decision: "allow", overwrite: { _meshCall: "tok_123" } });

  // PreToolUse also handles Antigravity's lazy `call_mcp_tool` wrapper cleanly without touching non-mesh MCP tools
  const preLazy = await handleHookPayload(
    {
      conversationId: "conv-42",
      toolCall: {
        id: "tc-2",
        name: "call_mcp_tool",
        args: { ServerName: "hyphae_hyphae", ToolName: "mesh_join", Arguments: { handle: "a" } },
      },
    },
    { harness: "antigravity", event: "pre-tool-use", socketPath: "/tmp/unused.sock", rpc },
  );
  assert.deepEqual(preLazy, { decision: "allow", overwrite: { Arguments: { handle: "a", _meshCall: "tok_123" } } });

  const preOtherMcp = await handleHookPayload(
    {
      conversationId: "conv-42",
      toolCall: {
        id: "tc-3",
        name: "call_mcp_tool",
        args: { ServerName: "other-server", ToolName: "list_issues", Arguments: {} },
      },
    },
    { harness: "antigravity", event: "pre-tool-use", socketPath: "/tmp/unused.sock", rpc },
  );
  assert.deepEqual(preOtherMcp, { decision: "allow" });

  // PreInvocation drains queued message into injectSteps
  const preInv = await handleHookPayload(
    { conversationId: "conv-42" },
    { harness: "antigravity", event: "pre-invocation", socketPath: "/tmp/unused.sock", rpc },
  );
  assert.ok(Array.isArray(preInv.injectSteps) && preInv.injectSteps.length === 1);

  // Stop with empty mailbox and no waiter prompts once to arm `hph wait`
  const stop1 = await handleHookPayload(
    { conversationId: "conv-42", continuationActive: false, terminationReason: "NO_TOOL_CALL" },
    { harness: "antigravity", event: "stop", socketPath: "/tmp/unused.sock", cliPath: "hph", rpc },
  );
  assert.equal(stop1.decision, "continue");
  assert.match(String(stop1.reason), /hph wait --session antigravity:conv-42/);

  // Stop with continuationActive=true never loops
  const stopLoop = await handleHookPayload(
    { conversationId: "conv-42", continuationActive: true, terminationReason: "NO_TOOL_CALL" },
    { harness: "antigravity", event: "stop", socketPath: "/tmp/unused.sock", rpc },
  );
  assert.deepEqual(stopLoop, {});

  // Stop once waiter is running allows clean idle
  hasLiveTransport = true;
  const stopIdle = await handleHookPayload(
    { conversationId: "conv-42", continuationActive: false, terminationReason: "NO_TOOL_CALL" },
    { harness: "antigravity", event: "stop", socketPath: "/tmp/unused.sock", rpc },
  );
  assert.deepEqual(stopIdle, {});
});

test("extractMetaCallId and inferSessionIdFromEnv cover Antigravity, Claude, and Codex", () => {
  assert.equal(extractMetaCallId({ "claudecode/toolUseId": "toolu_1" }), "toolu_1");
  assert.equal(extractMetaCallId({ callId: "call_2" }), "call_2");
  assert.equal(extractMetaCallId({ "antigravity/toolCallId": "ag_3" }), "ag_3");
  assert.equal(extractMetaCallId({}), undefined);

  assert.equal(
    inferSessionIdFromEnv({
      ANTIGRAVITY_SOURCE_METADATA: JSON.stringify({ tool: { conversationId: "abc-123" } }),
    }),
    "antigravity:abc-123",
  );
  assert.equal(inferSessionIdFromEnv({ CLAUDE_SESSION_ID: "sess-9" }), "claude:sess-9");
  assert.equal(inferSessionIdFromEnv({ CODEX_THREAD_ID: "thr-7" }), "codex:thr-7");
});

test("Cursor, OpenCode, and Gemini CLI hook payloads map cleanly to each harness schema", async () => {
  let queued = [{ text: "mesh from peer/a: ping" }];
  const rpc = async (_socket: string, packet: Record<string, unknown>) => {
    if (packet.type === "call.start") return { ok: true, result: { callToken: "tok_xyz" } };
    if (packet.type === "mailbox.drain") {
      const items = queued;
      queued = [];
      return { ok: true, result: { items } };
    }
    if (packet.type === "session.status") return { ok: true, result: { enrolled: true, hasLiveTransport: false } };
    return { ok: true, result: {} };
  };

  // Cursor: beforeMCPExecution -> permission:allow, stop -> followup_message (loop_count guarded)
  const curPre = await handleHookPayload(
    { conversation_id: "c-1", tool_name: "mesh_join" },
    { harness: "cursor", event: "pre-tool-use", socketPath: "/tmp/u.sock", rpc },
  );
  assert.deepEqual(curPre, { permission: "allow" });
  const curStop = await handleHookPayload(
    { conversation_id: "c-1", loop_count: 0 },
    { harness: "cursor", event: "stop", socketPath: "/tmp/u.sock", rpc },
  );
  assert.match(String(curStop.followup_message), /mesh from peer\/a: ping/);
  const curLoopGuard = await handleHookPayload(
    { conversation_id: "c-1", loop_count: 1 },
    { harness: "cursor", event: "stop", socketPath: "/tmp/u.sock", rpc },
  );
  assert.deepEqual(curLoopGuard, {});

  // OpenCode: pre-tool-use -> callToken, stop -> followupMessage
  const ocPre = await handleHookPayload(
    { session_id: "oc-9", tool_name: "hyphae_mesh_join", call_id: "call-1" },
    { harness: "opencode", event: "pre-tool-use", socketPath: "/tmp/u.sock", rpc },
  );
  assert.deepEqual(ocPre, { callToken: "tok_xyz", sessionId: "opencode:oc-9" });
  const ocStop = await handleHookPayload(
    { session_id: "oc-9" },
    { harness: "opencode", event: "stop", socketPath: "/tmp/u.sock", cliPath: "hph", rpc },
  );
  assert.match(String(ocStop.followupMessage), /hph wait --session opencode:oc-9/);

  // Gemini CLI: BeforeTool -> tool_input._meshCall, AfterTool -> additionalContext, AfterAgent -> decision:deny
  const gemPre = await handleHookPayload(
    { session_id: "gem-7", tool_name: "mcp_hyphae_mesh_join", tool_input: { handle: "g" } },
    { harness: "gemini", event: "pre-tool-use", socketPath: "/tmp/u.sock", rpc },
  );
  assert.deepEqual(gemPre, {
    decision: "allow",
    hookSpecificOutput: { hookEventName: "BeforeTool", tool_input: { handle: "g", _meshCall: "tok_xyz" } },
  });
  queued = [{ text: "mesh from peer/b: hi gemini" }];
  const gemAfter = await handleHookPayload(
    { session_id: "gem-7" },
    { harness: "gemini", event: "post-tool-use", socketPath: "/tmp/u.sock", rpc },
  );
  assert.match(
    String((gemAfter.hookSpecificOutput as { additionalContext: string }).additionalContext),
    /hi gemini/,
  );
  const gemStop = await handleHookPayload(
    { session_id: "gem-7" },
    { harness: "gemini", event: "stop", socketPath: "/tmp/u.sock", cliPath: "hph", rpc },
  );
  assert.equal(gemStop.decision, "deny");
  assert.match(String(gemStop.reason), /hph wait --session gemini:gem-7/);
});
