/**
 * Real black-box OpenCode (`opencode`) integration suite.
 *
 * Covers TWO layers cleanly and strictly:
 *  1. Real `opencode run --standalone --auto --format json` (v2.3.2+) wired strictly via
 *     `hyp setup --harness opencode`:
 *       - Verifies `opencode.json` + `~/.config/opencode/plugins/hyphae.ts` generation.
 *       - Verifies ZERO `PluginModule.LoadError` on OpenCode v2.3.2 (#30).
 *       - Verifies real OpenCode connects to `hyp mcp --backend opencode` and discovers strictly
 *         the 4 core Hyphae tools (`mcp connected server=hyphae tools=4`, visible in Code Mode catalog).
 *       - Verifies live Code Mode verified caller binding (`hyp_mesh(join)`, `hyp_send`, `hyp_inbox`)
 *         and strict `UNTRUSTED_PROVENANCE` framing (#23, #30)!
 *  2. Real execution of the EXACT installed `~/.config/opencode/plugins/hyphae.ts` plugin written by
 *     `hyp setup --harness opencode` against the REAL compiled `hyp` binary (`hyp daemon` +
 *     `hyp hook opencode pre-tool-use/post-tool-use/stop` + `hyp mcp --backend opencode`):
 *       - Verifies v2 default definition export (`{ id: "hyphae", setup(api) }`) alongside v1 factory.
 *       - `tool.execute.before`: injects verified `_meshCall` token -> real `hyp mcp` enrolls
 *         `opencode:<sessionID>` (and fails closed without `_meshCall`!).
 *       - `tool.execute.after`: holds `queue` DM mid-turn, injects `interrupt` DM on BOTH string
 *         outputs and structured/non-string outputs (preserving structured payload via
 *         `output.metadata.hyphaeAdditionalContext`).
 *       - `event` (`session.idle`): flushes held `queue` DM via `client.session.prompt` AND proves
 *         the `idleReminderSent` anti-loop guard prevents infinite idle waiter loops!
 */

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { pathToFileURL } from "node:url";
import { OpenCodeHarness, resolveOpenCodeBin } from "../lib/harnesses/opencode.ts";
import { extractSessionsFromInspect } from "../lib/harnesses/types.ts";
import { HypCli, HypMcpClient } from "../lib/hyp-cli.ts";
import { LlmShimServer, callTool, emitText } from "../lib/llm-shim/index.ts";
import { withSandbox } from "../lib/sandbox.ts";

test("Real OpenCode v2.3.2 CLI: hyp setup wiring, zero LoadError, 4-tool MCP discovery, live Code Mode hyp_mesh/hyp_send/hyp_inbox", async (t) => {
  const opencodeBin = resolveOpenCodeBin();
  if (!opencodeBin) {
    t.skip("opencode binary not found (set OPENCODE_BIN)");
    return;
  }

  await withSandbox("opencode-real-cli", async (sandbox) => {
    const hyp = new HypCli(sandbox);
    await hyp.onboard({ nodeId: "opencode-itest@local", noSkills: true, noCommands: true });
    await hyp.startDaemon();

    const shim = await LlmShimServer.start({
      sandbox,
      auditors: {
        allowBridge: false,
        allowKv: false,
        allowedRoles: ["opencode"],
      },
    });

    const liveInboundPayload = "OPENCODE_LIVE_V2_DM_PAYLOAD_404";
    shim.auditors.registerUntrustedPayload("oc-live-dm", liveInboundPayload);

    const oc = await OpenCodeHarness.create({
      sandbox,
      hyp,
      shim,
      opencodeBin,
      role: "opencode",
    });

    // Verify `hyp setup --harness opencode` wrote `opencode.json` and `plugins/hyphae.ts` with embedded paths.
    assert.ok(fs.existsSync(oc.configPath), "opencode.json must exist");
    assert.ok(fs.existsSync(oc.pluginPath), "plugins/hyphae.ts must exist");
    const pluginSource = fs.readFileSync(oc.pluginPath, "utf8");
    assert.ok(pluginSource.includes(hyp.bin), "hyphae.ts must embed compiled HYP_BIN");
    assert.ok(pluginSource.includes(hyp.socketPath), "hyphae.ts must embed sandbox socket path");

    const peer = await hyp.openPeer("alice");
    const sink = await hyp.openPeer("sink");

    let sawVerifiedJoin = false;
    let sawVerifiedSend = false;
    let sawVerifiedInbox = false;

    shim.script("opencode", [
      {
        name: "oc-title",
        when: (req) => req.advertisedTools.length === 0,
        do: () => emitText("OpenCode Live V2"),
      },
      {
        name: "oc-call-mesh-join",
        once: true,
        when: (req) =>
          req.advertisedTools.some((tool) => tool.canonicalHyphaeName === "hyp_mesh") &&
          req.anyMessageContains("Join mesh as oc-cli"),
        do: (req) => callTool(req, "hyp_mesh", { action: "join", handle: "oc-cli" }),
      },
      {
        name: "oc-call-send",
        once: true,
        when: (req) => {
          const r = req.lastToolResult("hyp_mesh");
          if (r && !r.isError && r.json?.handle === "oc-cli") {
            sawVerifiedJoin = true;
            return true;
          }
          return false;
        },
        do: (req) =>
          callTool(req, "hyp_send", {
            to: "sink",
            text: "OPENCODE_V2_HELLO_SINK",
          }),
      },
      {
        name: "oc-call-inbox",
        once: true,
        when: (req) => {
          const r = req.lastToolResult("hyp_send");
          if (r && !r.isError && r.json) {
            sawVerifiedSend = true;
            return true;
          }
          return false;
        },
        do: (req) => callTool(req, "hyp_inbox", { ack: true }),
      },
      {
        name: "oc-finish-enroll",
        once: true,
        when: (req) => {
          const r = req.lastToolResult("hyp_inbox");
          if (r && !r.isError && r.json) {
            sawVerifiedInbox = true;
            return true;
          }
          return false;
        },
        do: () => emitText("OPENCODE_RUN_DONE"),
      },
      {
        name: "oc-read-live-dm-digest",
        once: true,
        when: (req) => req.anyMessageContains("<hyphae-inbox ") && !req.anyMessageContains(liveInboundPayload),
        assert: (req) => {
          assert.equal(
            req.rawBody.includes(liveInboundPayload),
            false,
            "RFC 0004: OpenCode prompt hook MUST emit metadata-only XML digest, never raw DM body",
          );
        },
        do: (req) => callTool(req, "hyp_inbox", {}),
      },
      {
        name: "oc-ack-live-dm",
        once: true,
        when: (req) => req.lastToolResult("hyp_inbox")?.text.includes(liveInboundPayload) === true,
        do: (req) =>
          callTool(req, "hyp_send", {
            to: "sink",
            text: `OC_LIVE_DM_ACK:${liveInboundPayload}`,
          }),
      },
      {
        name: "oc-after-dm-send",
        when: (req) => Boolean(req.lastToolResult("hyp_send")?.json),
        do: () => emitText("OPENCODE_DM_ACKED"),
      },
      {
        name: "oc-waiter-reminder",
        when: (req) => req.anyMessageContains("no background waiter is running yet"),
        do: () => emitText("OPENCODE_STANDING_BY"),
      },
    ]);

    const res = await oc.run("Join mesh as oc-cli", { printLogs: true, logLevel: "warn" });
    assert.equal(res.exitCode, 0, `opencode run failed: ${res.stderr}`);
    assert.ok(res.sessionId, "opencode run --format json must emit a sessionID");

    // 1. Strictly assert ZERO PluginModule.LoadError on OpenCode v2.3.2 (#30)!
    assert.equal(
      res.stderr.includes("PluginModule.LoadError"),
      false,
      `OpenCode v2.3.2 MUST load plugins/hyphae.ts with zero PluginModule.LoadError!\nSTDERR:\n${res.stderr.slice(-2000)}`,
    );
    assert.equal(
      res.stderr.includes("Plugin must export a default definition"),
      false,
      `OpenCode v2.3.2 MUST accept v2 default plugin definition!\nSTDERR:\n${res.stderr.slice(-2000)}`,
    );

    // 2. Verify OpenCode connected to our compiled `hyp mcp --backend opencode` and saw strictly 4 core tools!
    assert.ok(
      res.stderr.includes('message="mcp connected" server=hyphae tools=4'),
      `Expected OpenCode to connect to hyp mcp with 4 core tools, stderr:\n${res.stderr.slice(-2000)}`,
    );

    const agentTurn = shim
      .getTurns("opencode")
      .find((tr) => tr.request.advertisedTools.some((tool) => tool.canonicalHyphaeName));
    assert.ok(agentTurn, "Expected llm-shim to observe Hyphae tools advertised via OpenCode");
    const hyphaeCanonical = agentTurn.request.advertisedTools
      .filter((tool) => tool.canonicalHyphaeName)
      .map((tool) => tool.canonicalHyphaeName)
      .sort();
    assert.deepEqual(
      hyphaeCanonical,
      ["hyp_inbox", "hyp_mesh", "hyp_send", "hyp_stream"],
      `Expected strictly 4 core Hyphae tools advertised in OpenCode Code Mode, got: ${JSON.stringify(hyphaeCanonical)}`,
    );

    // 3. Strictly assert live enrollment + verified Code Mode hyp_mesh / hyp_send / hyp_inbox calls!
    assert.equal(sawVerifiedJoin, true, "Expected live verified Code Mode hyp_mesh(join) result");
    assert.equal(sawVerifiedSend, true, "Expected live verified Code Mode hyp_send result");
    assert.equal(sawVerifiedInbox, true, "Expected live verified Code Mode hyp_inbox result");

    const ins = await hyp.inspect({ handle: "oc-cli" });
    const row = extractSessionsFromInspect(ins.json)[0];
    assert.equal(row?.enrolled, true, `Expected live OpenCode enrollment: ${JSON.stringify(ins.json)}`);
    assert.equal(row?.sessionId, `opencode:${res.sessionId}`);

    const sinkBox1 = await sink.inbox({ ack: true });
    assert.ok(
      JSON.stringify(sinkBox1).includes("OPENCODE_V2_HELLO_SINK"),
      `Expected @sink to receive verified Code Mode hyp_send DM, got: ${JSON.stringify(sinkBox1)}`,
    );

    // 4. Send a DM from @alice and resume the same OpenCode session -> verify live `api.session.hook("prompt")`
    //    delivers it with explicit UNTRUSTED_PROVENANCE framing (#23, #30)!
    await peer.send("oc-cli", liveInboundPayload);
    const res2 = await oc.run("Check inbox for alice", {
      sessionId: res.sessionId,
      printLogs: true,
      logLevel: "warn",
    });
    assert.equal(res2.exitCode, 0, `opencode resume failed: ${res2.stderr}`);
    assert.equal(res2.stderr.includes("PluginModule.LoadError"), false);

    const sinkBox2 = await sink.inbox({ ack: true });
    assert.ok(
      JSON.stringify(sinkBox2).includes(`OC_LIVE_DM_ACK:${liveInboundPayload}`),
      `Expected @sink to receive OpenCode reply to live DM, got: ${JSON.stringify(sinkBox2)}`,
    );

    shim.assertAllClean();
  });
});

test("Real installed OpenCode plugin (plugins/hyphae.ts) + compiled hyp: tool.execute.before _meshCall, tool.execute.after string/structured drain, session.idle wakeup & anti-loop guard", async () => {
  await withSandbox("opencode-installed-plugin-live-hyp", async (sandbox) => {
    const hyp = new HypCli(sandbox);
    await hyp.onboard({ nodeId: "oc-plugin@local", noSkills: true, noCommands: true });
    await hyp.startDaemon();
    await hyp.setup("opencode", { noSkills: true, noCommands: true });

    const installedPluginPath = path.join(
      sandbox.paths.homeDir,
      ".config",
      "opencode",
      "plugins",
      "hyphae.ts",
    );
    assert.ok(fs.existsSync(installedPluginPath), "hyp setup must write plugins/hyphae.ts");

    // Import the EXACT TypeScript plugin file rendered by `hyp setup --harness opencode`!
    const mod = await import(`${pathToFileURL(installedPluginPath).href}?t=${Date.now()}`);
    assert.equal(typeof mod.HyphaePlugin, "function", "HyphaePlugin v1 factory must be exported");
    assert.equal(mod.default?.id, "hyphae", "default export must be OpenCode v2 plugin definition with id='hyphae'");
    assert.equal(typeof mod.default?.setup, "function", "default export must expose setup(api)");

    const idlePrompts: Array<{ sessionId: string; text: string }> = [];
    const hooks = await mod.HyphaePlugin({
      directory: sandbox.paths.workspaceDir,
      client: {
        session: {
          prompt: async (input: any) => {
            idlePrompts.push({
              sessionId: String(input?.path?.id ?? ""),
              text: (input?.body?.parts ?? []).map((p: any) => p?.text ?? "").join(""),
            });
          },
        },
      },
    });

    // Open a REAL non-ephemeral `hyp mcp --backend opencode` subprocess!
    const mcp = new HypMcpClient(
      sandbox,
      hyp.bin,
      ["mcp", hyp.socketPath, "--backend", "opencode"],
      "opencode-mcp",
    );
    await mcp.initialize("opencode-plugin-test");
    const tools = await mcp.listTools();
    assert.deepEqual(
      tools.map((t: any) => t.name).sort(),
      ["hyp_inbox", "hyp_mesh", "hyp_send", "hyp_stream"],
    );

    const sessionId = "ses_opencode_verified_001";

    // 1. Negative security check: calling `hyp_mesh` WITHOUT `tool.execute.before` `_meshCall` fails closed!
    const unverified = await mcp.callTool("hyp_mesh", { action: "join", handle: "spoofed" });
    assert.equal(unverified.isError, true, "Unverified MCP call must fail closed");
    assert.ok(unverified.text.includes("caller_unverifiable"));

    // 2. Real `tool.execute.before` -> calls compiled `hyp hook opencode pre-tool-use` -> injects `_meshCall`!
    const beforeOut: { args: Record<string, unknown> } = {
      args: { action: "join", handle: "oc-verified" },
    };
    await hooks["tool.execute.before"](
      { tool: "hyphae_hyp_mesh", sessionID: sessionId, callID: "call-join-1" },
      beforeOut,
    );
    assert.equal(
      typeof beforeOut.args._meshCall,
      "string",
      `tool.execute.before MUST inject _meshCall token, got: ${JSON.stringify(beforeOut)}`,
    );

    // Execute real `hyp_mesh(join)` with the injected `_meshCall` token!
    const joinRes = await mcp.callTool("hyp_mesh", beforeOut.args);
    assert.equal(joinRes.isError, false, `Verified join failed: ${joinRes.text}`);
    assert.equal(joinRes.json?.handle, "oc-verified");

    const ins = await hyp.inspect({ session: `opencode:${sessionId}` });
    const sessRow = extractSessionsFromInspect(ins.json)[0];
    assert.equal(sessRow?.handle, "oc-verified");
    assert.equal(sessRow?.sessionId, `opencode:${sessionId}`);

    // 3. `tool.execute.after` mid-turn behavior:
    //    - Queue DM is HELD (not appended to tool output mid-turn!)
    //    - Interrupt DM IS injected cleanly into BOTH string output AND structured non-string output!
    const peerNormal = await hyp.openPeer("bob");
    const peerVip = await hyp.openPeer("vip");
    const queueMsg = "OC_PLUGIN_QUEUE_HELD_501";
    const intMsg1 = "OC_PLUGIN_INT_STRING_502";
    const intMsg2 = "OC_PLUGIN_INT_STRUCTURED_503";

    await peerNormal.send("oc-verified", queueMsg);
    const afterQueueOut: { output: unknown } = { output: "file contents ok" };
    await hooks["tool.execute.after"](
      { tool: "read", sessionID: sessionId, callID: "call-read-1" },
      afterQueueOut,
    );
    assert.equal(
      afterQueueOut.output,
      "file contents ok",
      "tool.execute.after MUST hold queue DM mid-turn without mutating tool output",
    );

    // Configure `@vip` -> `interrupt` rule!
    await hyp.session([
      "--session",
      `opencode:${sessionId}`,
      "rule",
      "oc-plugin@local/vip",
      "interrupt",
    ]);

    // (a) Interrupt drain into string tool output
    await peerVip.send("oc-verified", intMsg1);
    const afterStrOut: { output: unknown } = { output: "bash stdout" };
    await hooks["tool.execute.after"](
      { tool: "bash", sessionID: sessionId, callID: "call-bash-1" },
      afterStrOut,
    );
    assert.equal(typeof afterStrOut.output, "string");
    assert.ok(
      String(afterStrOut.output).startsWith("bash stdout\n\n<hyphae-inbox "),
      `String output must preserve original tool result + append metadata-only XML digest: ${afterStrOut.output}`,
    );
    assert.ok(
      String(afterStrOut.output).includes('urgency="interrupt"') &&
        String(afterStrOut.output).includes('from="oc-plugin@local/vip"'),
      `Interrupt XML digest missing expected attributes: ${afterStrOut.output}`,
    );
    assert.equal(
      String(afterStrOut.output).includes(intMsg1),
      false,
      "RFC 0004: tool.execute.after MUST NEVER leak raw interrupt body",
    );
    assert.equal(
      String(afterStrOut.output).includes(queueMsg),
      false,
      "Queue DM must remain held during interrupt drain",
    );

    // (b) Interrupt drain into structured/non-string tool output (must NOT corrupt object!)
    await peerVip.send("oc-verified", intMsg2);
    const structuredPayload = { rows: [1, 2, 3] };
    const afterStructOut: { output: unknown; metadata: Record<string, unknown> } = {
      output: structuredPayload,
      metadata: { source: "sql" },
    };
    await hooks["tool.execute.after"](
      { tool: "query", sessionID: sessionId, callID: "call-query-1" },
      afterStructOut,
    );
    assert.deepEqual(
      afterStructOut.output,
      structuredPayload,
      "Structured non-string output MUST remain intact!",
    );
    const structCtx = String(afterStructOut.metadata.hyphaeAdditionalContext ?? "");
    assert.ok(
      structCtx.startsWith("<hyphae-inbox ") &&
        structCtx.includes('urgency="interrupt"') &&
        structCtx.includes('from="oc-plugin@local/vip"'),
      `Structured output must receive metadata-only XML digest via metadata.hyphaeAdditionalContext: ${JSON.stringify(afterStructOut)}`,
    );
    assert.equal(structCtx.includes(intMsg2), false, "RFC 0004: structured metadata must not leak raw body");

    // 4. `event` (`session.idle`): flushes held `queueMsg` metadata-only XML digest via `client.session.prompt`!
    await hooks.event({ event: { type: "session.idle", properties: { sessionID: sessionId } } });
    assert.equal(idlePrompts.length, 1, `Expected 1 idle prompt flushing held queue XML digest, got: ${JSON.stringify(idlePrompts)}`);
    assert.equal(idlePrompts[0].sessionId, sessionId);
    assert.ok(
      idlePrompts[0].text.startsWith("<hyphae-inbox ") &&
        idlePrompts[0].text.includes('from="oc-plugin@local/bob"'),
      `Idle prompt must deliver metadata-only XML digest for held queue DM: ${idlePrompts[0].text}`,
    );
    assert.equal(
      idlePrompts[0].text.includes(queueMsg),
      false,
      "RFC 0004: idle prompt MUST NEVER leak raw queue DM body",
    );

    // 5. `idleReminderSent` anti-loop guard:
    //    - Next idle (empty mailbox) fires the one-time "no background waiter" reminder (idlePrompts.length -> 2).
    //    - Immediate consecutive idle MUST be suppressed (`continuationActive: true` -> stays at 2, zero infinite loop!).
    await hooks.event({ event: { type: "session.idle", properties: { sessionID: sessionId } } });
    const countAfterFirstEmptyIdle = idlePrompts.length;
    assert.equal(
      countAfterFirstEmptyIdle,
      2,
      `Expected one-time waiter reminder on first empty idle: ${JSON.stringify(idlePrompts)}`,
    );
    assert.ok(idlePrompts[1].text.includes("no background waiter"));

    await hooks.event({ event: { type: "session.idle", properties: { sessionID: sessionId } } });
    assert.equal(
      idlePrompts.length,
      countAfterFirstEmptyIdle,
      `idleReminderSent anti-loop guard MUST suppress repeated idle reminders! prompts=${JSON.stringify(idlePrompts)}`,
    );

    await mcp.close();
  });
});
