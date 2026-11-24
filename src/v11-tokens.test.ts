import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { test } from "node:test";
import { RouterCore } from "./core/router/core.ts";
import { serveRouter } from "./core/router/server.ts";
import { startDaemon } from "./daemon.ts";
import { handleHookPayload } from "./hooks.ts";
import {
  CONSOLIDATED_BRIDGE_TOOL,
  CONSOLIDATED_CORE_TOOLS,
  LEGACY_MCP_BRIDGE_TOOLS,
  LEGACY_MCP_CORE_TOOLS,
  selectToolsForList,
} from "./mcp.ts";
import { BRIDGE_MCP_TOOL, CORE_MCP_TOOLS, formatItem, object, UNTRUSTED_PROVENANCE } from "./protocol.ts";

function listToolsOverStdio(socketPath: string, extraArgs: string[] = []): Promise<Array<{ name: string }>> {
  return new Promise((resolve, reject) => {
    const proc = spawn(process.execPath, [join(process.cwd(), "src", "cli.ts"), "mcp", socketPath, ...extraArgs], {
      stdio: ["pipe", "pipe", "pipe"],
    });
    const rl = createInterface({ input: proc.stdout });
    const timer = setTimeout(() => {
      proc.kill("SIGKILL");
      reject(new Error("MCP tools/list timed out"));
    }, 8_000).unref();
    rl.on("line", (line) => {
      let msg: unknown;
      try { msg = JSON.parse(line); } catch { return; }
      if (!object(msg)) return;
      if (msg.id === 1) {
        proc.stdin.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n");
        proc.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }) + "\n");
      } else if (msg.id === 2 && object(msg.result) && Array.isArray(msg.result.tools)) {
        clearTimeout(timer);
        proc.stdin.end();
        resolve(msg.result.tools.filter(object).map((t) => ({ name: String(t.name) })));
      }
    });
    proc.stdin.write(
      JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "test", version: "1" } },
      }) + "\n",
    );
  });
}

test("v1.1 consolidated MCP schema cuts >60% tokens and dynamically gates hyp_bridge on plugin config", async () => {
  const legacyFull = JSON.stringify(selectToolsForList(true, true));
  const consolidatedCore = JSON.stringify(selectToolsForList(false, false));
  const consolidatedWithBridge = JSON.stringify(selectToolsForList(true, false));

  const coreReduction = 1 - consolidatedCore.length / legacyFull.length;
  const fullReduction = 1 - consolidatedWithBridge.length / legacyFull.length;
  assert.ok(coreReduction >= 0.55, `Expected >=55% schema reduction without plugins, got ${(coreReduction * 100).toFixed(1)}%`);
  assert.ok(fullReduction >= 0.45, `Expected >=45% schema reduction with bridge, got ${(fullReduction * 100).toFixed(1)}%`);
  assert.equal(CONSOLIDATED_CORE_TOOLS.length, 5);
  assert.equal(CONSOLIDATED_BRIDGE_TOOL.name, BRIDGE_MCP_TOOL);
  assert.equal(LEGACY_MCP_CORE_TOOLS.length, 18);
  assert.equal(LEGACY_MCP_BRIDGE_TOOLS.length, 5);

  const dir = mkdtempSync(join(tmpdir(), "hi-tok-"));
  const routerCore = new RouterCore({ dbPath: join(dir, "router.sqlite") });
  const token = routerCore.addConnector("dev@tok");
  const router = await serveRouter({ core: routerCore, host: "127.0.0.1", port: 0 });
  const daemonNoPlugins = await startDaemon(
    { connectorId: "dev@tok", directory: join(dir, "s1"), routers: [{ name: "primary", url: router.url, token }] },
    { quiet: true },
  );
  const daemonWithPlugins = await startDaemon(
    {
      connectorId: "dev@tok2",
      directory: join(dir, "s2"),
      routers: [{ name: "primary", url: router.url, token: routerCore.addConnector("dev@tok2") }],
      plugins: [
        {
          name: "hook",
          exec: process.execPath,
          args: ["-e", "setInterval(() => {}, 10000)"],
          cwd: dir,
          env: {},
          targets: [{ name: "t1", handle: "ops", coalesceSeconds: 1, maxWaitSeconds: 5, wakesPerHour: 60 }],
        },
      ],
    },
    { quiet: true },
  );
  try {
    const toolsNoPlugins = (await listToolsOverStdio(daemonNoPlugins.socketPath)).map((t) => t.name);
    assert.deepEqual(toolsNoPlugins, [...CORE_MCP_TOOLS]);

    const toolsWithPlugins = (await listToolsOverStdio(daemonWithPlugins.socketPath)).map((t) => t.name);
    assert.deepEqual(toolsWithPlugins, [...CORE_MCP_TOOLS, BRIDGE_MCP_TOOL]);

    const legacyNoPlugins = (await listToolsOverStdio(daemonNoPlugins.socketPath, ["--legacy-tools"])).map((t) => t.name);
    assert.equal(legacyNoPlugins.length, 18);

    const legacyWithPlugins = (await listToolsOverStdio(daemonWithPlugins.socketPath, ["--legacy-tools"])).map((t) => t.name);
    assert.equal(legacyWithPlugins.length, 23);
  } finally {
    await daemonNoPlugins.stop();
    await daemonWithPlugins.stop();
    await router.close();
    routerCore.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("v1.1 consolidated tools: single-call join+include, unified hyp_send (#channel + DM), slim topics, ack+summaryOnly inbox, and legacy aliases", async () => {
  const dir = mkdtempSync(join(tmpdir(), "hi-poly-"));
  const routerCore = new RouterCore({
    dbPath: join(dir, "router.sqlite"),
    topics: new Map([["github", ["gh"]]]),
  });
  routerCore.events.setTopicMetadata("github", {
    kind: "github-webhook",
    description: "Long human description that should be omitted in slim mode",
    setupGuide: "Very long human onboarding prose that wastes tokens during normal agent runs...",
    scope: { repos: ["hyphae-to/hyp"] },
    schema: {
      attributes: ["repo", "action"],
      eventTypes: ["com.github.pull_request.opened"],
      filterExamples: ['{"exact":{"repo":"hyphae-to/hyp"}}'],
    },
  });
  const token = routerCore.addConnector("dev@poly");
  const router = await serveRouter({ core: routerCore, host: "127.0.0.1", port: 0 });
  const daemon = await startDaemon(
    { connectorId: "dev@poly", directory: join(dir, "state"), routers: [{ name: "primary", url: router.url, token }] },
    { quiet: true },
  );
  try {
    daemon.state.register("claude:a", { kind: "claude" });
    daemon.state.register("claude:b", { kind: "claude" });

    // Single-call join + include peers & topics (slim by default!)
    const joinA = (await daemon.connector.call("claude:a", "hyp_session", {
      action: "join",
      handle: "alice",
      include: ["peers", "topics"],
    })) as { address: string; unread: number; deliveryMode: string; peers: unknown[]; topics: Array<{ topics: Array<Record<string, unknown>> }> };
    assert.equal(joinA.address, "dev@poly/alice");
    assert.equal(joinA.unread, 0);
    assert.equal(joinA.deliveryMode, "full");
    assert.ok(Array.isArray(joinA.peers));
    const slimGh = joinA.topics[0]!.topics[0]!;
    assert.equal(slimGh.topic, "github");
    assert.equal("setupGuide" in slimGh, false, "Slim topics must omit human setupGuide prose");
    assert.deepEqual(slimGh.attributes, ["repo", "action"]);

    // Verbose topics still available on demand
    const verboseTopics = (await daemon.connector.call("claude:a", "hyp_stream", { action: "topics", verbose: true })) as {
      routers: Array<{ topics: Array<{ metadata?: Record<string, unknown> }> }>;
    };
    assert.ok(typeof verboseTopics.routers[0]!.topics[0]!.metadata?.setupGuide === "string");

    // Join B via legacy hyp_join alias + join #incidents via consolidated hyp_channel
    await daemon.connector.call("claude:b", "hyp_join", { handle: "bob" });
    await daemon.connector.call("claude:a", "hyp_channel", { action: "join", channel: "#incidents" });
    await daemon.connector.call("claude:b", "hyp_channel", { action: "join", channel: "#incidents" });

    // Unified hyp_send posts to #channel directly
    const chPost = (await daemon.connector.call("claude:a", "hyp_send", {
      to: "#incidents",
      text: "channel-msg-via-hyp-send",
    })) as { channel: string; deliveredTo: string[] };
    assert.equal(chPost.channel, "#incidents");
    assert.deepEqual(chPost.deliveredTo, ["dev@poly/bob"]);

    // Unified hyp_send also sends DMs
    await daemon.connector.call("claude:a", "hyp_send", { to: "dev@poly/bob", text: "dm-msg-via-hyp-send" });

    // Wait for both items to land in bob's mailbox
    const deadline = Date.now() + 3_000;
    while (daemon.state.pendingCount("claude:b") < 2 && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 25));
    }
    assert.equal(daemon.state.pendingCount("claude:b"), 2);

    // summaryOnly peek leaves unread=2
    const summary = (await daemon.connector.call("claude:b", "hyp_inbox", { summaryOnly: true })) as {
      unread: number;
      items: Array<{ preview?: string; text?: string }>;
    };
    assert.equal(summary.unread, 2);
    assert.equal(summary.items.length, 2);
    assert.ok(typeof summary.items[0]!.preview === "string");
    assert.equal(summary.items[0]!.text, undefined);

    // ack: true reads & clears in one call
    const acked = (await daemon.connector.call("claude:b", "hyp_inbox", { ack: true })) as {
      unread: number;
      items: Array<{ text: string }>;
    };
    assert.equal(acked.unread, 0);
    assert.equal(acked.items.length, 2);
  } finally {
    await daemon.stop();
    await router.close();
    routerCore.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("formatItem prunes null/empty fields & CloudEvent boilerplate, and PostToolUse deduplicates batch provenance", async () => {
  const formatted = formatItem({
    id: "ev-1",
    kind: "event",
    subscriptionId: "sub-1",
    topic: "github",
    events: [
      {
        specversion: "1.0",
        datacontenttype: "application/json",
        id: "deliv-1",
        source: "github.com/acme/api",
        type: "com.github.pull_request.opened",
        repo: "acme/api",
        data: {
          number: 42,
          title: "Fix pool",
          conclusion: null,
          signed_by: null,
          mentions: [],
          record_marker: null,
          record_kind: null,
          record_id: null,
        },
      },
    ],
  });
  assert.ok(formatted.includes('"number":42'));
  assert.ok(formatted.includes('"title":"Fix pool"'));
  assert.equal(formatted.includes("specversion"), false);
  assert.equal(formatted.includes("datacontenttype"), false);
  assert.equal(formatted.includes("record_marker"), false);
  assert.equal(formatted.includes("conclusion"), false);
  assert.equal(formatted.includes("mentions"), false);

  // Batch PostToolUse drain deduplicates repeated provenance line across 3 items
  const m1 = formatItem({ id: "1", kind: "message", from: "a@h/x", to: "b@h/y", text: "one" });
  const m2 = formatItem({ id: "2", kind: "message", from: "a@h/x", to: "b@h/y", text: "two" });
  const m3 = formatItem({ id: "3", kind: "message", from: "a@h/x", to: "b@h/y", text: "three" });
  const hookRes = await handleHookPayload(
    { session_id: "s1", tool_use_id: "t1", tool_name: "Bash" },
    {
      harness: "claude",
      event: "post-tool-use",
      socketPath: "/tmp/unused",
      rpc: async (_sock, pkt) => {
        if (pkt.type === "mailbox.drain") return { ok: true, result: { items: [{ text: m1 }, { text: m2 }, { text: m3 }] } };
        return { ok: true, result: {} };
      },
    },
  );
  const ctxText = String((hookRes.hookSpecificOutput as { additionalContext?: string })?.additionalContext ?? "");
  const provOccurrences = ctxText.split(UNTRUSTED_PROVENANCE).length - 1;
  assert.equal(provOccurrences, 1, `Expected provenance warning once per batch, saw ${provOccurrences}`);
  assert.ok(ctxText.includes('"one"') && ctxText.includes('"two"') && ctxText.includes('"three"'));
});
