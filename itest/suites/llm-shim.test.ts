/**
 * Self-test suite for `llm-shim` (all 4 protocols, latches, abort tracking, fault injection,
 * dynamic tool resolution, all 5 always-on invariant auditors including mutated negative cases)
 * and `Sandbox` hermeticity (Blind Spot B5 poisoned-env scrubbing, HostCanary, ProcessReaper).
 */

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import {
  HostCanary,
  Sandbox,
  withSandbox,
} from "../lib/sandbox.ts";
import {
  LlmShimServer,
  UNTRUSTED_PROVENANCE_HEADER,
  abortMidStream,
  callTool,
  chunkDelayMs,
  createGate,
  delayBeforeHeadersMs,
  emitText,
  failOnceWith,
  pauseMidStream,
  pauseUntil,
} from "../lib/llm-shim/index.ts";

function isPidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

test("Sandbox B5: strips poisoned ambient harness & LLM env vars and enforces short socket path", async () => {
  const poisonedEnv: Record<string, string> = {
    USER: "tester",
    PATH: "/usr/bin:/bin",
    CLAUDECODE: "1",
    CLAUDE_ENV_FILE: "/tmp/poison-claude-env",
    CLAUDE_CONFIG_DIR: "/tmp/poison-claude-cfg",
    HYPHAE_SESSION_ID: "claude:poison-session",
    HYPHAE_SESSION_TOKEN: "poison-tok",
    HC_TERMINAL_ID: "t99",
    HERDR_SOCKET: "/tmp/poison-herdr.sock",
    CODEX_HOME: "/tmp/poison-codex",
    OPENCLAW_STATE_DIR: "/tmp/poison-openclaw",
    OPENCLAW_CONFIG_PATH: "/tmp/poison-openclaw/openclaw.json",
    ANTHROPIC_API_KEY: "sk-ant-real-host-key",
    ANTHROPIC_BASE_URL: "https://api.anthropic.com",
    OPENAI_API_KEY: "sk-real-openai-key",
    GEMINI_API_KEY: "real-gemini-key",
    TAILSCALE_BIN: "/usr/local/bin/tailscale",
    SSH_AUTH_SOCK: "/tmp/ssh-agent.sock",
  };

  await withSandbox("sandbox-poison-b5", { sourceEnv: poisonedEnv }, async (sandbox) => {
    for (const forbidden of [
      "CLAUDECODE",
      "CLAUDE_ENV_FILE",
      "CLAUDE_CONFIG_DIR",
      "HYPHAE_SESSION_ID",
      "HYPHAE_SESSION_TOKEN",
      "HC_TERMINAL_ID",
      "HERDR_SOCKET",
      "CODEX_HOME",
      "OPENCLAW_STATE_DIR",
      "OPENCLAW_CONFIG_PATH",
      "ANTHROPIC_API_KEY",
      "ANTHROPIC_BASE_URL",
      "OPENAI_API_KEY",
      "GEMINI_API_KEY",
      "SSH_AUTH_SOCK",
    ]) {
      assert.equal(
        sandbox.env[forbidden],
        undefined,
        `Poisoned ambient env var '${forbidden}' MUST be stripped`,
      );
    }

    assert.equal(sandbox.env.HYPHAE_SECRET_BACKEND, "file");
    assert.equal(sandbox.env.HYPHAE_TAILSCALE_BIN, "none");
    assert.equal(sandbox.env.TAILSCALE_BIN, "none");
    assert.equal(sandbox.env.HYPHAE_NO_OPEN, "1");
    assert.equal(sandbox.env.HYPHAE_NO_SERVICE, "1");
    assert.equal(sandbox.env.HOME, sandbox.paths.homeDir);
    assert.equal(sandbox.env.HYPHAE_SOCKET, sandbox.paths.socketPath);
    assert.ok(
      Buffer.byteLength(sandbox.paths.socketPath, "utf8") < 90,
      `Unix socket path must stay well below macOS SUN_LEN (104B): ${sandbox.paths.socketPath}`,
    );
  });
});

test("HostCanary detects mutation of watched file and ProcessReaper kills entire -pgid group", async () => {
  await withSandbox("canary-and-reaper", async (sandbox) => {
    // 1. HostCanary negative check on an isolated canary target file inside our own TempDir.
    const fakeHostCfg = path.join(sandbox.paths.tmpDir, "fake-host-config.json");
    fs.writeFileSync(fakeHostCfg, '{"ok":true}\n');
    const canary = HostCanary.capture([fakeHostCfg]);
    canary.assertUntouched();

    fs.writeFileSync(fakeHostCfg, '{"ok":true,"mutated":1}\n');
    assert.throws(() => canary.assertUntouched(), /HostCanary VIOLATION/);

    // 2. ProcessReaper kills parent + spawned grandchild in detached process group.
    const pidFile = path.join(sandbox.paths.tmpDir, "grandchild.pid");
    const proc = sandbox.reaper.spawn(
      "pgid-test",
      "/bin/sh",
      ["-c", `sleep 60 & echo $! > "${pidFile}"; wait`],
      { env: sandbox.env },
    );

    // Wait for grandchild PID to be written.
    const deadline = Date.now() + 3_000;
    while (!fs.existsSync(pidFile) && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 25));
    }
    const grandchildPid = Number(fs.readFileSync(pidFile, "utf8").trim());
    assert.ok(grandchildPid > 0, `expected valid grandchild PID, got ${grandchildPid}`);
    assert.equal(isPidAlive(grandchildPid), true);

    await sandbox.reaper.kill(proc, 1_500);
    await new Promise((r) => setTimeout(r, 100));
    assert.equal(isPidAlive(proc.pid), false, "parent process must be terminated");
    assert.equal(isPidAlive(grandchildPid), false, "grandchild in -pgid must be terminated");
  });
});

test("llm-shim serves all 4 model protocols (JSON + SSE + tool calls + dynamic tool resolution)", async () => {
  await withSandbox("llm-shim-4-protocols", async (sandbox) => {
    const shim = await LlmShimServer.start({ sandbox });

    // 1. Anthropic Messages (SSE + tool_use + count_tokens + dynamic mcp__hyphae__ resolution)
    shim.script("anthropic-agent", [
      {
        name: "call-mesh-join",
        when: (req) => req.turnIndex === 0,
        do: (req) => callTool(req, "hyp_mesh", { action: "join", handle: "alice" }),
      },
      {
        name: "finish",
        when: (req) => req.lastToolResult("hyp_mesh")?.json?.ok === true,
        do: () => emitText("ANTHROPIC_DONE"),
      },
    ]);

    const ctRes = await fetch(`${shim.roleBaseUrl("anthropic-agent")}/v1/messages/count_tokens`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-api-key": "sk-ant-itest" },
      body: JSON.stringify({ model: "claude-sonnet-4-5", messages: [{ role: "user", content: "hi" }] }),
    });
    assert.equal(ctRes.status, 200);
    const ctJson: any = await ctRes.json();
    assert.ok(ctJson.input_tokens > 0);

    const antRes1 = await fetch(`${shim.roleBaseUrl("anthropic-agent")}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-api-key": "sk-ant-itest" },
      body: JSON.stringify({
        model: "claude-sonnet-4-5",
        stream: true,
        tools: [
          { name: "mcp__hyphae__hyp_mesh", input_schema: { type: "object" } },
          { name: "mcp__hyphae__hyp_send", input_schema: { type: "object" } },
          { name: "mcp__hyphae__hyp_inbox", input_schema: { type: "object" } },
          { name: "mcp__hyphae__hyp_stream", input_schema: { type: "object" } },
        ],
        messages: [{ role: "user", content: "Join the mesh." }],
      }),
    });
    assert.equal(antRes1.status, 200);
    const antSse = await antRes1.text();
    assert.ok(antSse.includes("event: message_start"));
    assert.ok(antSse.includes("mcp__hyphae__hyp_mesh"), `must resolve dynamic prefix: ${antSse}`);
    assert.ok(antSse.includes("event: message_stop"));

    const antRes2 = await fetch(`${shim.roleBaseUrl("anthropic-agent")}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-api-key": "sk-ant-itest" },
      body: JSON.stringify({
        model: "claude-sonnet-4-5",
        stream: false,
        messages: [
          { role: "user", content: "Join the mesh." },
          {
            role: "assistant",
            content: [
              {
                type: "tool_use",
                id: "toolu_1",
                name: "mcp__hyphae__hyp_mesh",
                input: { action: "join", handle: "alice" },
              },
            ],
          },
          {
            role: "user",
            content: [{ type: "tool_result", tool_use_id: "toolu_1", content: '{"ok":true}' }],
          },
        ],
      }),
    });
    const antJson2: any = await antRes2.json();
    assert.equal(antJson2.content[0].text, "ANTHROPIC_DONE");

    // 2. OpenAI Chat Completions (SSE + tool_calls + GET /v1/models)
    shim.script("chat-agent", [
      {
        name: "chat-tool",
        when: (req) => req.turnIndex === 0,
        do: (req) => callTool(req, "hyp_send", { to: "@bob", text: "hello" }),
      },
    ]);
    const modelsRes = await fetch(`${shim.roleBaseUrl("chat-agent")}/v1/models`);
    assert.equal(modelsRes.status, 200);
    const modelsJson: any = await modelsRes.json();
    assert.ok(Array.isArray(modelsJson.data) && modelsJson.data.length > 0);

    const chatRes = await fetch(`${shim.roleBaseUrl("chat-agent")}/v1/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: "Bearer sk-itest-chat" },
      body: JSON.stringify({
        model: "shim-1",
        stream: true,
        tools: [
          { type: "function", function: { name: "hyphae__hyp_send", parameters: {} } },
          { type: "function", function: { name: "hyphae__hyp_inbox", parameters: {} } },
        ],
        messages: [{ role: "user", content: "Send hi" }],
      }),
    });
    const chatSse = await chatRes.text();
    assert.ok(chatSse.includes("hyphae__hyp_send"));
    assert.ok(chatSse.includes("data: [DONE]"));

    // 3. OpenAI Responses (SSE + function_call + non-streaming JSON)
    shim.script("resp-agent", [
      {
        name: "resp-tool",
        when: (req) => req.turnIndex === 0,
        do: (req) => callTool(req, "hyp_inbox", { ack: true }),
      },
      {
        name: "resp-done",
        when: (req) => req.lastToolResult("hyp_inbox")?.json?.unread === 0,
        do: () => emitText("RESPONSES_DONE"),
      },
    ]);
    const respSseRes = await fetch(`${shim.roleBaseUrl("resp-agent")}/v1/responses`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: "Bearer sk-itest-resp" },
      body: JSON.stringify({
        model: "gpt-5-shim",
        stream: true,
        tools: [{ type: "function", name: "mcp__hyphae__hyp_inbox", parameters: {} }],
        input: [{ role: "user", content: "Check inbox" }],
      }),
    });
    const respSse = await respSseRes.text();
    assert.ok(respSse.includes("event: response.created"));
    assert.ok(respSse.includes("mcp__hyphae__hyp_inbox"));
    assert.ok(respSse.includes("event: response.completed"));

    const respJsonRes = await fetch(`${shim.roleBaseUrl("resp-agent")}/v1/responses`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        model: "gpt-5-shim",
        stream: false,
        input: [
          { role: "user", content: "Check inbox" },
          { type: "function_call", call_id: "fc_1", name: "mcp__hyphae__hyp_inbox", arguments: '{"ack":true}' },
          { type: "function_call_output", call_id: "fc_1", output: '{"unread":0,"items":[]}' },
        ],
      }),
    });
    const respJson: any = await respJsonRes.json();
    assert.equal(respJson.output[0].content[0].text, "RESPONSES_DONE");

    // 4. Google Gemini (`:generateContent` + `:streamGenerateContent?alt=sse` + functionCall)
    shim.script("gemini-agent", [
      {
        name: "gem-tool",
        when: (req) => req.turnIndex === 0,
        do: (req) => callTool(req, "hyp_stream", { action: "topics" }),
      },
      {
        name: "gem-done",
        when: (req) => req.lastToolResult("hyp_stream")?.json?.topics?.length === 1,
        do: () => emitText("GEMINI_DONE"),
      },
    ]);
    const gemRes1 = await fetch(
      `${shim.roleBaseUrl("gemini-agent")}/v1beta/models/gemini-2.5-pro:generateContent`,
      {
        method: "POST",
        headers: { "content-type": "application/json", "x-goog-api-key": "itest-gemini" },
        body: JSON.stringify({
          tools: [{ functionDeclarations: [{ name: "hyphae_hyp_stream", parameters: {} }] }],
          contents: [{ role: "user", parts: [{ text: "List topics" }] }],
        }),
      },
    );
    const gemJson1: any = await gemRes1.json();
    assert.equal(gemJson1.candidates[0].content.parts[0].functionCall.name, "hyphae_hyp_stream");

    const gemRes2 = await fetch(
      `${shim.roleBaseUrl("gemini-agent")}/v1beta/models/gemini-2.5-pro:streamGenerateContent?alt=sse`,
      {
        method: "POST",
        headers: { "content-type": "application/json", "x-goog-api-key": "itest-gemini" },
        body: JSON.stringify({
          contents: [
            { role: "user", parts: [{ text: "List topics" }] },
            { role: "model", parts: [{ functionCall: { name: "hyphae_hyp_stream", args: { action: "topics" } } }] },
            { role: "user", parts: [{ functionResponse: { name: "hyphae_hyp_stream", response: { topics: ["local.schedule"] } } }] },
          ],
        }),
      },
    );
    const gemSse2 = await gemRes2.text();
    assert.ok(gemSse2.includes("GEMINI_DONE"));

    shim.assertAllClean();
  });
});

test("llm-shim deterministic latches (pauseUntil, pauseMidStream + abort tracking), delays, and failOnceWith", async () => {
  await withSandbox("llm-shim-latches-faults", async (sandbox) => {
    const shim = await LlmShimServer.start({ sandbox });

    // 1. pauseUntil(gate) holds before HTTP headers until gate.release()
    const beforeHeadersGate = createGate("before-headers");
    shim.script("latch-before", [
      {
        name: "hold-headers",
        when: () => true,
        do: () => pauseUntil(beforeHeadersGate, emitText("RELEASED_OK")),
      },
    ]);

    let completedBeforeRelease = false;
    const reqPromise = fetch(`${shim.roleBaseUrl("latch-before")}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ model: "claude-sonnet-4-5", stream: false, messages: [{ role: "user", content: "hold" }] }),
    }).then(async (r) => {
      completedBeforeRelease = true;
      return r.json();
    });

    await beforeHeadersGate.waitForWaiters(1, 5_000);
    await new Promise((r) => setTimeout(r, 40));
    assert.equal(completedBeforeRelease, false, "response MUST stay paused until gate.release()");
    beforeHeadersGate.release();
    const heldJson: any = await reqPromise;
    assert.equal(heldJson.content[0].text, "RELEASED_OK");

    // 2. pauseMidStream(gate) sends initial SSE token immediately, then tracks client abort!
    const midGate = createGate("mid-stream-abort");
    shim.script("latch-mid", [
      {
        name: "mid-stream-hold",
        when: () => true,
        do: () => pauseMidStream(midGate, "INITIAL_TOKEN_", "TAIL_NEVER_SENT"),
      },
    ]);

    const abortCtrl = new AbortController();
    const midRes = await fetch(`${shim.roleBaseUrl("latch-mid")}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      signal: abortCtrl.signal,
      body: JSON.stringify({ model: "claude-sonnet-4-5", stream: true, messages: [{ role: "user", content: "stream" }] }),
    });
    assert.equal(midRes.status, 200);
    const reader = midRes.body!.getReader();
    const firstChunk = await reader.read();
    const firstText = new TextDecoder().decode(firstChunk.value);
    assert.ok(firstText.includes("INITIAL_TOKEN_"), `expected initial SSE token immediately, got: ${firstText}`);
    await midGate.waitForWaiters(1, 5_000);

    // Abort mid-stream (simulating `hc interrupt`!).
    abortCtrl.abort();
    const abortedTurn = await shim.awaitAbort("latch-mid", 5_000);
    assert.equal(abortedTurn.aborted, true, "shim MUST track aborted=true when client disconnects mid-stream");

    // 3. failOnceWith(429, { retryAfter: 1 }) fails once then recovers cleanly
    shim.script("fault-429", [
      {
        name: "rate-limit-once",
        when: () => true,
        do: () =>
          failOnceWith(429, {
            retryAfter: 1,
            key: "rl-1",
            then: delayBeforeHeadersMs(15, chunkDelayMs(5, emitText("RECOVERED_429"))),
          }),
      },
    ]);

    const r1 = await fetch(`${shim.roleBaseUrl("fault-429")}/v1/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ model: "shim-1", stream: false, messages: [{ role: "user", content: "go" }] }),
    });
    assert.equal(r1.status, 429);
    assert.equal(r1.headers.get("retry-after"), "1");

    const r2 = await fetch(`${shim.roleBaseUrl("fault-429")}/v1/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ model: "shim-1", stream: true, messages: [{ role: "user", content: "go" }] }),
    });
    assert.equal(r2.status, 200);
    assert.ok((await r2.text()).includes("RECOVERED_429"));

    // 4. abortMidStream() drops socket cleanly after initial chunk
    shim.script("fault-abort", [
      {
        name: "server-abort",
        when: () => true,
        do: () => abortMidStream("DROPPED_"),
      },
    ]);
    await assert.rejects(async () => {
      const r = await fetch(`${shim.roleBaseUrl("fault-abort")}/v1/chat/completions`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ model: "shim-1", stream: true, messages: [{ role: "user", content: "drop" }] }),
      });
      await r.text();
    });

    shim.assertAllClean();
  });
});

test("llm-shim all 5 invariant auditors catch mutated negative violations", async () => {
  await withSandbox("llm-shim-5-auditors-negative", async (sandbox) => {
    const shim = await LlmShimServer.start({
      sandbox,
      auditors: {
        allowBridge: false,
        allowKv: false,
        nudgeOnlyRoles: ["nudge-only"],
        allowedRoles: ["audit-ok", "audit-bad", "nudge-only"],
      },
    });

    sandbox.registerSecret("openclaw-hooks-token", "SUPER_SECRET_TOKEN_XYZ_999");
    shim.auditors.registerUntrustedPayload("msg-1", "UNTRUSTED_PAYLOAD_MARKER_77");

    // (A) Clean request passes all 5 auditors!
    await fetch(`${shim.roleBaseUrl("audit-ok")}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-api-key": "sk-ant-itest" },
      body: JSON.stringify({
        model: "claude-sonnet-4-5",
        stream: false,
        tools: [
          { name: "mcp__hyphae__hyp_mesh", input_schema: {} },
          { name: "mcp__hyphae__hyp_send", input_schema: {} },
          { name: "mcp__hyphae__hyp_inbox", input_schema: {} },
          { name: "mcp__hyphae__hyp_stream", input_schema: {} },
        ],
        messages: [
          {
            role: "user",
            content: `${UNTRUSTED_PROVENANCE_HEADER}\n\n[hyphae dm] UNTRUSTED_PAYLOAD_MARKER_77`,
          },
        ],
      }),
    });
    assert.deepEqual(shim.auditors.getViolations(), []);

    // (B) History replay on Turn 2 of `audit-ok` with fresh user message ALSO passes!
    await fetch(`${shim.roleBaseUrl("audit-ok")}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-api-key": "sk-ant-itest" },
      body: JSON.stringify({
        model: "claude-sonnet-4-5",
        stream: false,
        messages: [
          {
            role: "user",
            content: `${UNTRUSTED_PROVENANCE_HEADER}\n\n[hyphae dm] UNTRUSTED_PAYLOAD_MARKER_77`,
          },
          { role: "assistant", content: "Acknowledged UNTRUSTED_PAYLOAD_MARKER_77." },
          { role: "user", content: "Follow-up turn with no new DM." },
        ],
      }),
    });
    assert.deepEqual(shim.auditors.getViolations(), []);

    // (C) Mutated negative case 1: Secret leak + pairing prefix leak!
    await fetch(`${shim.roleBaseUrl("audit-bad")}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-custom-leak": "SUPER_SECRET_TOKEN_XYZ_999" },
      body: JSON.stringify({
        model: "claude-sonnet-4-5",
        messages: [{ role: "user", content: "Here is hp2p1_abcdef1234567890" }],
      }),
    });
    assert.ok(
      shim.auditors.getViolations().some((v) => v.auditor === "secret-leak" && v.message.includes("openclaw-hooks-token")),
      "must flag registered secret leak",
    );
    assert.ok(
      shim.auditors.getViolations().some((v) => v.auditor === "secret-leak" && v.message.includes("pairing:hp2p1_")),
      "must flag hp2p1_ pairing token leak",
    );
    shim.auditors.resetViolations();

    // (D) Mutated negative case 2: Untrusted payload WITHOUT provenance wrapper!
    await fetch(`${shim.roleBaseUrl("audit-bad")}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        model: "claude-sonnet-4-5",
        system: "Trusted system prompt with UNTRUSTED_PAYLOAD_MARKER_77",
        messages: [{ role: "user", content: "Raw UNTRUSTED_PAYLOAD_MARKER_77 without wrapper" }],
      }),
    });
    assert.ok(
      shim.auditors.getViolations().some((v) => v.auditor === "untrusted-provenance"),
      "must flag missing untrusted provenance wrapper",
    );
    shim.auditors.resetViolations();

    // (E) Mutated negative case 3: Wake nudge leaks raw untrusted payload!
    await fetch(`${shim.roleBaseUrl("nudge-only")}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        model: "claude-sonnet-4-5",
        messages: [
          {
            role: "user",
            content: `${UNTRUSTED_PROVENANCE_HEADER}\n<hyphae-wake count="1" handle="bob">UNTRUSTED_PAYLOAD_MARKER_77</hyphae-wake>`,
          },
        ],
      }),
    });
    assert.ok(
      shim.auditors.getViolations().some((v) => v.auditor === "metadata-only-wake"),
      "must flag raw payload inside <hyphae-wake> and nudge-only wake turn",
    );
    shim.auditors.resetViolations();

    // (F) Mutated negative case 4: Duplicate delivery (re-delivered on new turn) + unexpected role!
    await fetch(`${shim.roleBaseUrl("audit-ok")}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        model: "claude-sonnet-4-5",
        messages: [
          {
            role: "user",
            content: `${UNTRUSTED_PROVENANCE_HEADER}\n[hyphae] UNTRUSTED_PAYLOAD_MARKER_77`,
          },
        ],
      }),
    });
    assert.ok(
      shim.auditors.getViolations().some((v) => v.auditor === "duplicate-delivery"),
      "must flag duplicate re-delivery to same role on later turn",
    );
    shim.auditors.resetViolations();

    await fetch(`${shim.roleBaseUrl("cron-ghost")}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ model: "claude-sonnet-4-5", messages: [{ role: "user", content: "ghost" }] }),
    });
    assert.ok(
      shim.auditors.getViolations().some((v) => v.auditor === "duplicate-delivery" && v.message.includes("cron-ghost")),
      "must flag unexpected session/role coherence violation",
    );
    shim.auditors.resetViolations();

    // (G) Mutated negative case 5: MCP tool schema bloat (hyp_bridge when unconfigured + legacy hyp_session)!
    await fetch(`${shim.roleBaseUrl("audit-bad")}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        model: "claude-sonnet-4-5",
        tools: [
          { name: "mcp__hyphae__hyp_mesh", input_schema: {} },
          { name: "mcp__hyphae__hyp_bridge", input_schema: {} },
          { name: "mcp__hyphae__hyp_session", input_schema: {} },
        ],
        messages: [{ role: "user", content: "hi" }],
      }),
    });
    const schemaViolations = shim.auditors
      .getViolations()
      .filter((v) => v.auditor === "mcp-schema-footprint");
    assert.ok(schemaViolations.length >= 2, `expected >=2 schema bloat violations, got ${JSON.stringify(schemaViolations)}`);
    assert.throws(() => shim.assertAllClean(), /llm-shim Auditor FAILED/);
  });
});
