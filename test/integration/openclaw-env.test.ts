import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { loadConfig } from "../../src/config.ts";
import { RouterCore } from "../../src/core/router/core.ts";
import { startDaemon } from "../../src/daemon.ts";
import { detectLocalEnvironment } from "../../src/discover.ts";
import { handleHookPayload } from "../../src/hooks.ts";
import { MESH_TOOLS, object } from "../../src/protocol.ts";
import { writeSecret } from "../../src/secrets.ts";
import { runDoctor, runOnboard, setupOpenClaw } from "../../src/setup.ts";
import { BINARIES, devRuntime, runRealClaude, runRealOpenCode } from "./harness/drivers.ts";
import { freePort, McpClient, MeshTopology, waitFor } from "./harness/topology.ts";
import { VirtualOpenClawEnv, type OpenClawToolResult } from "./shims/openclaw-env.ts";
import { deliverSignedWebhook, makePrometheusAlertPayload } from "./shims/services.ts";

const UUID_RE = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi;

async function callVerifiedHookMcp(
  mcp: McpClient,
  socketPath: string,
  harness: "antigravity" | "codex",
  rawId: string,
  tool: string,
  args: Record<string, unknown>,
  seq: string,
): Promise<OpenClawToolResult> {
  const callId = `${harness}_${rawId}_${seq}`;
  let callArgs: Record<string, unknown> = { ...args };
  let meta: Record<string, unknown> | undefined;

  if (harness === "antigravity") {
    const pre = await handleHookPayload(
      { conversationId: rawId, toolCall: { id: callId, name: tool, args } },
      { harness: "antigravity", event: "pre-tool-use", socketPath },
    );
    if (object(pre.overwrite)) callArgs = { ...callArgs, ...pre.overwrite };
  } else {
    await handleHookPayload(
      { session_id: rawId, tool_use_id: callId, tool_name: `hyphae.${tool}` },
      { harness: "codex", event: "pre-tool-use", socketPath },
    );
    meta = { callId };
  }

  return mcp.callTool(tool, callArgs, meta) as Promise<OpenClawToolResult>;
}

test(
  "OpenClaw Gateway setup, non-destructive merge, doctor checks, perturbed configs, exact-config MCP boot, and concurrent session isolation",
  { timeout: 30_000 },
  async () => {
    const topo = new MeshTopology("hi-oc1-");
    try {
      const router = await topo.addRouter({ name: "team" });

      // Provision a real 0600 connector.json so `runDoctor` verifies node, config, daemon, router:primary, AND openclaw!
      const gwDir = topo.subDir("gw");
      const tokenPath = join(gwDir, "primary.token");
      writeFileSync(tokenPath, router.addConnector("gw@openclaw") + "\n", { mode: 0o600 });
      chmodSync(tokenPath, 0o600);
      const gwConfigPath = join(gwDir, "connector.json");
      writeFileSync(
        gwConfigPath,
        JSON.stringify(
          {
            connectorId: "gw@openclaw",
            stateDir: "s",
            routers: [{ name: "primary", url: router.url, tokenFile: tokenPath }],
          },
          null,
          2,
        ) + "\n",
        { mode: 0o600 },
      );
      chmodSync(gwConfigPath, 0o600);

      const gwDaemon = await startDaemon(loadConfig(gwConfigPath), { quiet: true });
      topo.track(() => gwDaemon.stop());

      // 1. Pre-seed ~/.openclaw/openclaw.json with existing gateway settings & another MCP server (before setup)
      const ocHome = topo.subDir("oc-home");
      const seededConfig = {
        gateway: {
          host: "127.0.0.1",
          port: 18789,
          auth: { mode: "token", rotateDays: 30 },
        },
        channels: {
          whatsapp: { enabled: true },
          telegram: { enabled: true },
        },
        mcp: {
          timeoutMs: 30_000,
          servers: {
            filesystem: {
              command: "npx",
              args: ["-y", "@modelcontextprotocol/server-filesystem", "/srv/work"],
            },
          },
        },
      };

      const ocEnv = new VirtualOpenClawEnv({
        scope: "user",
        homeDir: ocHome,
        socketPath: gwDaemon.socketPath,
        seedConfig: seededConfig,
        runSetup: false,
      });
      topo.track(() => ocEnv.close());

      // Before `setupOpenClaw`: `detectLocalEnvironment` sees ~/.openclaw, and `runDoctor` flags OpenClaw as unconfigured
      const detectedBefore = detectLocalEnvironment(ocHome, {});
      assert.equal(detectedBefore.openclaw, true);
      const doctorBefore = await runDoctor(gwConfigPath, gwDaemon.socketPath, ocHome);
      const ocCheckBefore = doctorBefore.find((c) => c.name === "openclaw");
      assert.ok(ocCheckBefore, "Expected openclaw check in runDoctor before setup");
      assert.equal(ocCheckBefore.ok, false);
      assert.match(ocCheckBefore.fix ?? "", /hyp setup openclaw/);

      // 2. Run `setupOpenClaw` TWICE -> prove non-destructive merge AND byte-for-byte idempotency
      const res1 = ocEnv.setup();
      assert.equal(res1.harness, "openclaw");
      assert.deepEqual(res1.files, [ocEnv.configPath, ocEnv.skillPath]);
      const cfgAfter1 = readFileSync(ocEnv.configPath, "utf8");
      const skillAfter1 = ocEnv.readSkill();

      const res2 = ocEnv.setup();
      assert.deepEqual(res2.files, res1.files);
      assert.equal(readFileSync(ocEnv.configPath, "utf8"), cfgAfter1, "Second setupOpenClaw run must be byte-for-byte idempotent");
      assert.equal(ocEnv.readSkill(), skillAfter1, "SKILL.md must be byte-for-byte idempotent");

      // Verify preserved gateway settings, sibling MCP server, generated hyphae entry, and SKILL.md
      const merged = ocEnv.readConfig();
      assert.deepEqual(merged.gateway, seededConfig.gateway);
      assert.deepEqual(merged.channels, seededConfig.channels);
      assert.ok(object(merged.mcp) && merged.mcp.timeoutMs === 30_000);
      assert.ok(object(merged.mcp.servers));
      assert.deepEqual(merged.mcp.servers.filesystem, seededConfig.mcp.servers.filesystem);

      const hyphaeSpec = ocEnv.readHyphaeServerConfig();
      assert.equal(hyphaeSpec.command, process.execPath);
      assert.ok(hyphaeSpec.args.includes("mcp"));
      assert.ok(hyphaeSpec.args.includes(gwDaemon.socketPath));
      assert.ok(hyphaeSpec.args.includes("--backend"));
      assert.ok(hyphaeSpec.args.includes("openclaw"));
      assert.ok(hyphaeSpec.args.includes("--ephemeral"));

      assert.match(skillAfter1, /name: hyphae/);
      assert.match(skillAfter1, /hyp_join/);
      assert.match(skillAfter1, /#incidents/);
      assert.match(skillAfter1, /hyp_subscribe/);
      assert.match(skillAfter1, /untrusted external data/i);

      // Verify `detectLocalEnvironment` & `runDoctor` now pass cleanly for OpenClaw + core daemon/router
      assert.equal(detectLocalEnvironment(ocHome, {}).openclaw, true);
      const doctorAfter = await runDoctor(gwConfigPath, gwDaemon.socketPath, ocHome);
      for (const name of ["node", "config", "daemon", "router:primary", "openclaw"]) {
        const check = doctorAfter.find((c) => c.name === name);
        assert.ok(check, `Missing doctor check '${name}'`);
        assert.equal(check.ok, true, `Doctor check '${name}' failed: ${check.detail}`);
      }

      // 3. Project scope isolation + perturbed/malformed config boundary checks (McKeeman)
      const projHome = topo.subDir("oc-proj-home");
      const projDir = topo.subDir("oc-proj-ws");
      const projEnv = new VirtualOpenClawEnv({
        scope: "project",
        homeDir: projHome,
        projectDir: projDir,
        socketPath: gwDaemon.socketPath,
      });
      topo.track(() => projEnv.close());
      assert.equal(existsSync(join(projDir, ".openclaw", "openclaw.json")), true);
      assert.equal(existsSync(join(projDir, ".openclaw", "skills", "hyphae", "SKILL.md")), true);
      assert.equal(existsSync(join(projHome, ".openclaw")), false, "Project scope must never write to homeDir");

      // Non-object openclaw.json values & corrupt JSON must fail closed cleanly
      for (const [label, raw] of [
        ["array", "[]\n"],
        ["null", "null\n"],
        ["string", '"not-an-object"\n'],
        ["number", "42\n"],
        ["corrupt", "{ broken json"],
      ] as const) {
        const badHome = topo.subDir(`bad-oc-${label}`);
        mkdirSync(join(badHome, ".openclaw"), { recursive: true });
        writeFileSync(join(badHome, ".openclaw", "openclaw.json"), raw, "utf8");
        assert.throws(
          () => setupOpenClaw({ scope: "user", homeDir: badHome, socketPath: gwDaemon.socketPath, runtime: devRuntime() }),
          label === "corrupt" ? SyntaxError : /Expected JSON object/,
          `Expected setupOpenClaw to throw cleanly on ${label} openclaw.json`,
        );
      }

      // Nearby-altered openclaw.json with non-object `mcp` or `mcp.servers` recovers without losing `gateway`
      const repairHome = topo.subDir("oc-repair");
      const repairEnv = new VirtualOpenClawEnv({
        scope: "user",
        homeDir: repairHome,
        socketPath: gwDaemon.socketPath,
        seedConfig: { gateway: { port: 18799 }, mcp: "unexpected-string" },
      });
      topo.track(() => repairEnv.close());
      const repaired = repairEnv.readConfig();
      assert.deepEqual(repaired.gateway, { port: 18799 });
      assert.equal(repairEnv.readHyphaeServerConfig().command, process.execPath);

      // 4. Boot Session 1 strictly from generated `openclaw.json` -> verify 19 tools, capabilities & boundary errors
      const s1 = await ocEnv.openSession();
      const listedTools = await s1.listTools();
      assert.equal(listedTools.length, 19, `Expected all 19 Hyphae tools, got ${listedTools.length}`);
      assert.deepEqual(
        new Set(listedTools.map((t) => t.name)),
        MESH_TOOLS,
        "Advertised MCP tool set must exactly match MESH_TOOLS",
      );

      assert.ok(s1.capabilities);
      assert.match(s1.capabilities.sessionId, /^openclaw:[0-9a-f-]{36}$/);
      assert.equal(s1.capabilities.backend, "openclaw");
      assert.deepEqual(s1.capabilities.modes, ["queue"]);
      assert.equal(s1.capabilities.deliveryMode, "full");
      assert.equal(s1.capabilities.unread, 0);
      assert.equal(s1.capabilities.mutes, 0);
      assert.deepEqual(s1.capabilities.routers, ["primary"]);
      assert.equal(s1.capabilities.inbound, "hooks-and-waiter");

      // Forgotten/boundary inputs before `hyp_join` fail cleanly
      const sendBeforeJoin = await s1.callTool("hyp_send", { to: "gw@openclaw/nobody", text: "early" });
      assert.equal(sendBeforeJoin.isError, true);
      assert.match(sendBeforeJoin.text, /not_enrolled/);

      // Even if an OpenClaw client sends a random `_meta.callId` without hooks, ephemeral identity still resolves
      const sendWithMeta = await s1.callTool("hyp_send", { to: "gw@openclaw/nobody", text: "early" }, { callId: "oc-meta-1" });
      assert.equal(sendWithMeta.isError, true);
      assert.match(sendWithMeta.text, /not_enrolled/);
      assert.doesNotMatch(sendWithMeta.text, /caller_not_found/);

      const chanBeforeJoin = await s1.callTool("hyp_channel_join", { channel: "#incidents" });
      assert.equal(chanBeforeJoin.isError, true);
      assert.match(chanBeforeJoin.text, /not_enrolled/);

      const badHandle = await s1.callTool("hyp_join", { handle: "INVALID HANDLE!" });
      assert.equal(badHandle.isError, true);
      assert.match(badHandle.text, /Invalid handle/i);

      const badMode = await s1.callTool("hyp_mode", { mode: "silent" });
      assert.equal(badMode.isError, true);
      assert.match(badMode.text, /invalid/i);

      const interruptSub = await s1.callTool("hyp_subscribe", {
        key: "ops:int",
        topic: "alerts",
        filters: [],
        mode: "interrupt",
      });
      assert.equal(interruptSub.isError, true);
      assert.match(interruptSub.text, /unsupported_mode/);

      // 5. Boot a SECOND concurrent OpenClaw session from the EXACT SAME `openclaw.json`
      const join1 = await s1.callTool("hyp_join", { handle: "orch-alpha" });
      assert.equal(join1.isError, false, join1.text);
      assert.deepEqual(join1.json(), { address: "gw@openclaw/orch-alpha" });

      const s2 = await ocEnv.openSession();
      assert.ok(s2.sessionId);
      assert.match(s2.sessionId, /^openclaw:[0-9a-f-]{36}$/);
      assert.notEqual(s2.sessionId, s1.sessionId, "Concurrent ephemeral OpenClaw subprocesses must get distinct UUIDs");

      // Handle collision protection across concurrent OpenClaw sessions
      const hijack = await s2.callTool("hyp_join", { handle: "orch-alpha" });
      assert.equal(hijack.isError, true);
      assert.match(hijack.text, /handle_taken/);

      const join2 = await s2.callTool("hyp_join", { handle: "orch-beta" });
      assert.equal(join2.isError, false, join2.text);
      assert.deepEqual(join2.json(), { address: "gw@openclaw/orch-beta" });

      // Cross-send distinct secrets and verify zero cross-session mailbox leakage
      const send12 = await s1.callTool("hyp_send", { to: "gw@openclaw/orch-beta", text: "SECRET_ONLY_FOR_BETA_101" });
      assert.equal(send12.isError, false, send12.text);
      const send21 = await s2.callTool("hyp_send", { to: "gw@openclaw/orch-alpha", text: "SECRET_ONLY_FOR_ALPHA_202" });
      assert.equal(send21.isError, false, send21.text);

      await waitFor(
        () => gwDaemon.state.pendingCount(s1.sessionId!) >= 1 && gwDaemon.state.pendingCount(s2.sessionId!) >= 1,
        { label: "both concurrent OpenClaw sessions receiving their private messages" },
      );

      const inbox1 = (await s1.callTool("hyp_inbox", { acknowledgeAll: true })).json<{ unread: number; items: Array<{ text: string }> }>();
      const inbox2 = (await s2.callTool("hyp_inbox", { acknowledgeAll: true })).json<{ unread: number; items: Array<{ text: string }> }>();

      assert.equal(inbox1.unread, 0);
      assert.equal(inbox1.items.length, 1);
      assert.match(inbox1.items[0].text, /SECRET_ONLY_FOR_ALPHA_202/);
      assert.doesNotMatch(inbox1.items[0].text, /SECRET_ONLY_FOR_BETA_101/);

      assert.equal(inbox2.unread, 0);
      assert.equal(inbox2.items.length, 1);
      assert.match(inbox2.items[0].text, /SECRET_ONLY_FOR_BETA_101/);
      assert.doesNotMatch(inbox2.items[0].text, /SECRET_ONLY_FOR_ALPHA_202/);
    } finally {
      await topo.cleanup();
    }
  },
);

test(
  "Multi-connector fleet orchestration: OpenClaw orchestrator + Prometheus stream (0600 secret) + Antigravity & Codex workers + #incidents + notify mode + Stop hook",
  { timeout: 35_000 },
  async () => {
    const topo = new MeshTopology("hi-oc2-");
    try {
      // 1. Provision Team Router with a signed `prometheus` webhook-stream backed by a strict 0600 secret
      const teamRouterPort = await freePort();
      const promPort = await freePort();
      const promSecret = "fleet-prom-hmac-secret-99";

      const hubDir = topo.subDir("hub");
      const promSecretPath = writeSecret("prom-secret", promSecret, hubDir);
      assert.equal(statSync(promSecretPath).mode & 0o777, 0o600);

      const hubConfigPath = join(hubDir, "connector.json");
      await runOnboard({
        configPath: hubConfigPath,
        connectorId: "jack@prod",
        port: teamRouterPort,
        harnesses: [],
        startDaemon: false,
        localRouterExposure: "private",
        localRouterStreams: [
          {
            name: "prometheus",
            topic: "prometheus",
            builtin: "webhook-stream",
            env: {
              WEBHOOK_HOST: "127.0.0.1",
              WEBHOOK_PORT: String(promPort),
              WEBHOOK_PATH: "/prometheus",
              WEBHOOK_TARGET: "prometheus",
              WEBHOOK_SOURCE: "prometheus/prod",
              WEBHOOK_SECRET: { secret: "prom-secret" },
            },
          },
        ],
      });

      const jackDaemon = await startDaemon(loadConfig(hubConfigPath), { quiet: true });
      topo.track(() => jackDaemon.stop());
      const teamRouterUrl = jackDaemon.localRouterUrl!;

      // Issue connector tokens on the Team Router for `gw@openclaw` and `alex@laptop`
      const adminCore = new RouterCore({ dbPath: join(hubDir, "router", "router.sqlite") });
      const gwToken = adminCore.addConnector("gw@openclaw");
      const alexToken = adminCore.addConnector("alex@laptop");
      adminCore.close();

      const gwDaemon = await startDaemon(
        {
          connectorId: "gw@openclaw",
          directory: topo.subDir("gw-s"),
          routers: [{ name: "primary", url: teamRouterUrl, token: gwToken }],
        },
        { quiet: true },
      );
      topo.track(() => gwDaemon.stop());

      const alexDaemon = await startDaemon(
        {
          connectorId: "alex@laptop",
          directory: topo.subDir("al-s"),
          routers: [{ name: "primary", url: teamRouterUrl, token: alexToken }],
        },
        { quiet: true },
      );
      topo.track(() => alexDaemon.stop());

      // 2. Boot OpenClaw orchestrator on `gw@openclaw` via VirtualOpenClawEnv
      const ocEnv = new VirtualOpenClawEnv({
        scope: "user",
        homeDir: topo.subDir("oc-home"),
        socketPath: gwDaemon.socketPath,
      });
      topo.track(() => ocEnv.close());

      const orch = await ocEnv.openSession();
      assert.equal((await orch.callTool("hyp_join", { handle: "orchestrator" })).isError, false);
      assert.equal((await orch.callTool("hyp_channel_join", { channel: "#incidents" })).isError, false);
      const subRes = await orch.callTool("hyp_subscribe", {
        key: "ops:prometheus",
        topic: "prometheus",
        filters: [{ exact: { type: "com.prometheus.alert.firing" } }],
        coalesceSeconds: 0,
      });
      assert.equal(subRes.isError, false, subRes.text);

      // Arm a real blocking `hyp wait` background waiter on OpenClaw!
      const promWaiter = orch.spawnWait({ timeoutSeconds: 20 });
      await promWaiter.waitUntilReady();

      // Verify capabilities now show `push-waiter` while waiter is armed
      const capsArmed = await orch.getCapabilities();
      assert.equal(capsArmed.inbound, "push-waiter");

      // 3. Enroll multi-harness worker agents via hook-verified MCP across `alex@laptop` (Antigravity) and `jack@prod` (Codex)
      const alexMcp = new McpClient(alexDaemon.socketPath);
      topo.track(() => alexMcp.close());
      await alexMcp.initialize();

      const jackMcp = new McpClient(jackDaemon.socketPath);
      topo.track(() => jackMcp.close());
      await jackMcp.initialize();

      assert.equal(
        (await callVerifiedHookMcp(alexMcp, alexDaemon.socketPath, "antigravity", "ag-triage-1", "hyp_join", { handle: "agy-triage" }, "1")).isError,
        false,
      );
      assert.equal(
        (await callVerifiedHookMcp(alexMcp, alexDaemon.socketPath, "antigravity", "ag-triage-1", "hyp_channel_join", { channel: "#incidents" }, "2")).isError,
        false,
      );

      assert.equal(
        (await callVerifiedHookMcp(jackMcp, jackDaemon.socketPath, "codex", "cx-db-1", "hyp_join", { handle: "codex-db" }, "1")).isError,
        false,
      );
      assert.equal(
        (await callVerifiedHookMcp(jackMcp, jackDaemon.socketPath, "codex", "cx-db-1", "hyp_channel_join", { channel: "#incidents" }, "2")).isError,
        false,
      );

      // Verify OpenClaw discovers the entire 3-connector fleet & #incidents membership
      const peersRes = (await orch.callTool("hyp_peers")).json<{
        self: string;
        peers: Array<{ address: string; online: boolean }>;
      }>();
      assert.equal(peersRes.self, "gw@openclaw/orchestrator");
      const onlineAddrs = peersRes.peers.filter((p) => p.online).map((p) => p.address).sort();
      assert.deepEqual(onlineAddrs, ["alex@laptop/agy-triage", "gw@openclaw/orchestrator", "jack@prod/codex-db"]);

      const channelsRes = (await orch.callTool("hyp_channels", { channel: "#incidents" })).json<{
        channels: Array<{ channel: string; members: string[] }>;
      }>();
      assert.deepEqual(channelsRes.channels, [
        {
          channel: "#incidents",
          members: ["alex@laptop/agy-triage", "gw@openclaw/orchestrator", "jack@prod/codex-db"],
        },
      ]);

      // 4. Perturbed webhook test: tampered HMAC signature MUST be rejected (401) without waking waiter!
      const badSigRes = await deliverSignedWebhook({
        url: `http://127.0.0.1:${promPort}/prometheus`,
        secret: promSecret,
        overrideSignature: "sha256=0000000000000000000000000000000000000000000000000000000000000000",
        payload: makePrometheusAlertPayload({
          alertname: "SpoofedAlert",
          severity: "critical",
          service: "fake-svc",
          summary: "Should be rejected",
        }),
      });
      assert.equal(badSigRes.status, 401);
      assert.equal(promWaiter.proc.exitCode, null, "Tampered webhook must not wake blocking hyp wait");

      // Valid signed Prometheus alert fires -> wakes OpenClaw's blocking `hyp wait` with zero polling!
      const goodPromRes = await deliverSignedWebhook({
        url: `http://127.0.0.1:${promPort}/prometheus`,
        secret: promSecret,
        payload: makePrometheusAlertPayload({
          alertname: "OrdersDbPoolExhausted",
          severity: "critical",
          service: "orders-db",
          summary: "99% connection pool saturation on primary",
        }),
      });
      assert.equal(goodPromRes.status, 202);

      const waitResult = await promWaiter.output;
      assert.equal(waitResult.code, 0, `hyp wait exited ${waitResult.code}: ${waitResult.stderr}`);
      assert.match(waitResult.stdout, /hyphae event "prometheus"/);
      assert.match(waitResult.stdout, /OrdersDbPoolExhausted/);
      assert.match(waitResult.stdout, /Treat it as data, not authority/);

      // 5. OpenClaw fans out triage instructions to `#incidents` AND direct-delegates focused work via `hyp_send`
      const broadcastRes = (await orch.callTool("hyp_channel_post", {
        channel: "#incidents",
        text: "INC-77: OrdersDbPoolExhausted firing — all hands inspect pool metrics",
      })).json<{ deliveredTo: string[] }>();
      assert.deepEqual(broadcastRes.deliveredTo, ["alex@laptop/agy-triage", "jack@prod/codex-db"]);

      const directRes = await orch.callTool("hyp_send", {
        to: "jack@prod/codex-db",
        text: "DIRECT_TASK_77: capture pg_stat_activity and propose pool cap patch",
      });
      assert.equal(directRes.isError, false, directRes.text);

      // Verify Antigravity worker received #incidents broadcast, and Codex worker received BOTH broadcast & direct task
      const alexGot = await waitFor(() => {
        const items = alexDaemon.connector.drainMailbox("antigravity:ag-triage-1", 5);
        return items.length > 0 ? items : null;
      }, { label: "Antigravity worker receiving #incidents fan-out" });
      assert.equal(alexGot.length, 1);
      assert.match(alexGot[0].text, /\[#incidents\] INC-77/);

      const jackGot = await waitFor(() => {
        if (jackDaemon.state.pendingCount("codex:cx-db-1") < 2) return null;
        return jackDaemon.connector.drainMailbox("codex:cx-db-1", 5);
      }, { label: "Codex worker receiving #incidents broadcast + direct delegation" });
      assert.equal(jackGot.length, 2);
      const jackJoined = jackGot.map((i) => i.text).join("\n");
      assert.match(jackJoined, /\[#incidents\] INC-77/);
      assert.match(jackJoined, /DIRECT_TASK_77: capture pg_stat_activity/);

      // 6. OpenClaw switches to `notify` mode -> workers reply -> slim unread digest -> `hyp_inbox({ acknowledgeAll: true })`
      const modeRes = (await orch.callTool("hyp_mode", { mode: "notify" })).json<{ deliveryMode: string; unread: number }>();
      assert.deepEqual(modeRes, { deliveryMode: "notify", unread: 0 });

      assert.equal(
        (await callVerifiedHookMcp(alexMcp, alexDaemon.socketPath, "antigravity", "ag-triage-1", "hyp_send", {
          to: "gw@openclaw/orchestrator",
          text: "AGY_RESULT_77: checkout retries amplified pool usage by 3x",
        }, "3")).isError,
        false,
      );
      assert.equal(
        (await callVerifiedHookMcp(jackMcp, jackDaemon.socketPath, "codex", "cx-db-1", "hyp_send", {
          to: "gw@openclaw/orchestrator",
          text: "CODEX_RESULT_77: pool_max=200 patch ready in PR #412",
        }, "3")).isError,
        false,
      );

      await waitFor(() => gwDaemon.state.pendingCount(orch.sessionId!) >= 2, {
        label: "2 worker completion replies queued in OpenClaw notify inbox",
      });

      // OpenClaw `stop` hook delivers ONLY the slim unread digest (without leaking full message bodies!)
      const stopDigest = await orch.runHook("stop");
      assert.equal(stopDigest.decision, "block");
      const digestReason = String(stopDigest.reason ?? "");
      assert.match(digestReason, /hyphae notice · 2 unread \(2 messages\)/);
      assert.match(digestReason, /alex@laptop\/agy-triage/);
      assert.match(digestReason, /jack@prod\/codex-db/);
      assert.doesNotMatch(digestReason, /AGY_RESULT_77/, "Notify digest must not leak full payload before hyp_inbox");
      assert.doesNotMatch(digestReason, /CODEX_RESULT_77/, "Notify digest must not leak full payload before hyp_inbox");

      // OpenClaw reads full worker results and acknowledges all in one call
      const fullInbox = (await orch.callTool("hyp_inbox", { acknowledgeAll: true })).json<{
        deliveryMode: string;
        unread: number;
        items: Array<{ text: string; kind?: string; source?: string }>;
      }>();
      assert.equal(fullInbox.deliveryMode, "notify");
      assert.equal(fullInbox.unread, 0);
      assert.equal(fullInbox.items.length, 2);
      const inboxJoined = fullInbox.items.map((i) => i.text).join("\n");
      assert.match(inboxJoined, /AGY_RESULT_77: checkout retries amplified/);
      assert.match(inboxJoined, /CODEX_RESULT_77: pool_max=200 patch ready/);

      // 7. OpenClaw `Stop` hook auto-arms background waiter ONCE, respects `stop_hook_active: true`, and stands down when watcher is active
      const stopArm = await orch.runHook("stop");
      assert.equal(stopArm.decision, "block");
      assert.match(String(stopArm.reason ?? ""), /no background waiter is running yet/i);
      assert.match(String(stopArm.reason ?? ""), new RegExp(`wait --session ${orch.sessionId}`));

      // Already-qualified `openclaw:<uuid>` from `hyp_capabilities` MUST also work cleanly without double-prefixing!
      const stopQualified = await orch.runHook("stop", { session_id: orch.sessionId });
      assert.equal(stopQualified.decision, "block");
      assert.match(String(stopQualified.reason ?? ""), new RegExp(`wait --session ${orch.sessionId}`));

      // Malformed empty suffix `"openclaw:"` fails closed cleanly
      assert.deepEqual(await orch.runHook("stop", { session_id: "openclaw:" }), {});

      // Must NOT loop when `stop_hook_active: true`!
      const stopNoLoop = await orch.runHook("stop", { stop_hook_active: true });
      assert.deepEqual(stopNoLoop, {});

      // Perturbed/forgotten hook payload (missing session_id) fails open cleanly
      const stopMissingSession = await orch.runHook("stop", {}, { autoAttachSessionId: false });
      assert.deepEqual(stopMissingSession, {});

      // Switch back to full mode -> verify `post-tool-use` drains incoming message cleanly via CLI hook
      await orch.callTool("hyp_mode", { mode: "full" });
      assert.equal(
        (await callVerifiedHookMcp(jackMcp, jackDaemon.socketPath, "codex", "cx-db-1", "hyp_send", {
          to: "gw@openclaw/orchestrator",
          text: "POST_TOOL_HOOK_STATUS_77",
        }, "4")).isError,
        false,
      );
      await waitFor(() => gwDaemon.state.pendingCount(orch.sessionId!) >= 1, {
        label: "post-tool-use test message queued for OpenClaw",
      });
      const postToolRes = await orch.runHook("post-tool-use", { session_id: orch.sessionId, tool_name: "hyp_peers" });
      assert.ok(object(postToolRes.hookSpecificOutput));
      assert.equal(postToolRes.hookSpecificOutput.hookEventName, "PostToolUse");
      assert.match(String(postToolRes.hookSpecificOutput.additionalContext ?? ""), /POST_TOOL_HOOK_STATUS_77/);

      // Arm a streaming `hyp watch` -> `stop` hook sees live transport & returns `{}`
      const watcher = orch.spawnWatch();
      await watcher.waitUntilReady();
      assert.deepEqual(await orch.runHook("stop"), {});

      assert.equal(
        (await callVerifiedHookMcp(alexMcp, alexDaemon.socketPath, "antigravity", "ag-triage-1", "hyp_send", {
          to: "gw@openclaw/orchestrator",
          text: "INC-77_RESOLVED_ALL_CLEAR",
        }, "4")).isError,
        false,
      );
      const streamedLine = await watcher.waitForLine((line) => line.includes("INC-77_RESOLVED_ALL_CLEAR"));
      const streamedEvent = JSON.parse(streamedLine) as { router: string; text: string };
      assert.equal(streamedEvent.router, "primary");
      assert.match(streamedEvent.text, /INC-77_RESOLVED_ALL_CLEAR/);
      watcher.stop();
    } finally {
      await topo.cleanup();
    }
  },
);

test(
  "OpenClaw orchestrator delegating LIVE over Team Router to a REAL local harness binary (opencode or claude) and receiving reply via blocking hyp wait",
  {
    skip:
      BINARIES.opencode === null && BINARIES.claude === null
        ? "neither opencode nor claude CLI binary installed locally"
        : false,
    timeout: 75_000,
  },
  async () => {
    const topo = new MeshTopology("hi-oc3-");
    try {
      const teamRouter = await topo.addRouter({ name: "team" });
      const gw = await topo.addConnector({ connectorId: "gw@openclaw", links: [{ name: "primary", router: teamRouter }] });
      const alex = await topo.addConnector({ connectorId: "alex@laptop", links: [{ name: "primary", router: teamRouter }] });

      // Boot OpenClaw orchestrator strictly from generated openclaw.json
      const ocEnv = new VirtualOpenClawEnv({
        scope: "user",
        homeDir: topo.subDir("oc-home"),
        socketPath: gw.socketPath,
      });
      topo.track(() => ocEnv.close());

      const orch = await ocEnv.openSession();
      assert.equal((await orch.callTool("hyp_join", { handle: "orchestrator" })).isError, false);

      // Arm blocking `hyp wait` on OpenClaw BEFORE delegating so the real binary's reply wakes it with zero polling!
      const replyWaiter = orch.spawnWait({ timeoutSeconds: 50 });
      await replyWaiter.waitUntilReady();

      const useOpenCode = BINARIES.opencode !== null;
      const delegatedPayload = "OPENCLAW_DELEGATION_TASK_42: audit-auth-middleware";
      const expectedReply = useOpenCode
        ? "REAL_OPENCODE_AUDIT_COMPLETE_42"
        : "REAL_CLAUDE_AUDIT_COMPLETE_42";

      let workerSawDelegatedTask = false;

      // Run OpenClaw delegation concurrently with the real local binary!
      const openClawDelegatePromise = (async () => {
        await waitFor(() => Boolean(alex.daemon.state.byHandle("live-worker")), {
          timeoutMs: 30_000,
          label: "real local harness binary enrolling as live-worker",
        });

        const peers = (await orch.callTool("hyp_peers")).json<{
          peers: Array<{ address: string; online: boolean }>;
        }>();
        assert.ok(
          peers.peers.some((p) => p.address === "alex@laptop/live-worker" && p.online),
          `Expected OpenClaw to discover alex@laptop/live-worker in hyp_peers: ${JSON.stringify(peers)}`,
        );

        const sent = await orch.callTool("hyp_send", {
          to: "alex@laptop/live-worker",
          text: delegatedPayload,
        });
        assert.equal(sent.isError, false, `OpenClaw hyp_send failed: ${sent.text}`);
      })();

      const workerPromise = useOpenCode
        ? runRealOpenCode({
            baseDir: topo.subDir("oc-worker"),
            socketPath: alex.socketPath,
            prompt: "Enroll as live-worker, receive task from gw@openclaw/orchestrator, and reply with audit result.",
            handler: async (ctx) => {
              if (ctx.turnIndex === 0) {
                return ctx.callOpenCodeTool("hyp_join", { handle: "live-worker" });
              }
              if (ctx.turnIndex === 1) {
                await waitFor(() => {
                  const s = alex.daemon.state.byHandle("live-worker");
                  return s && alex.daemon.state.pendingCount(s.id) >= 1;
                }, { timeoutMs: 25_000, label: "OpenClaw delegation landing in real OpenCode mailbox" });
                // Calling hyp_peers triggers OpenCode v2's `execute.after` hook which drains & injects OpenClaw's task!
                return ctx.callOpenCodeTool("hyp_peers", {});
              }
              if (ctx.turnIndex === 2) {
                if (ctx.hasText(delegatedPayload)) workerSawDelegatedTask = true;
                return ctx.callOpenCodeTool("hyp_send", {
                  to: "gw@openclaw/orchestrator",
                  text: expectedReply,
                });
              }
              return ctx.reply("Completed OpenClaw delegated task.");
            },
          })
        : runRealClaude({
            baseDir: topo.subDir("cl-worker"),
            socketPath: alex.socketPath,
            prompt: "Enroll as live-worker, receive task from gw@openclaw/orchestrator, and reply with audit result.",
            handler: async (ctx) => {
              if (!ctx.findTool("hyp_join") && ctx.findTool("ToolSearch")) {
                return ctx.selectClaudeTools(["hyp_join", "hyp_send"]);
              }
              if (!alex.daemon.state.byHandle("live-worker")) {
                return ctx.callTool("hyp_join", { handle: "live-worker" });
              }
              if (ctx.hasText(delegatedPayload)) {
                workerSawDelegatedTask = true;
                if (!ctx.hasText("messageId")) {
                  return ctx.callTool("hyp_send", {
                    to: "gw@openclaw/orchestrator",
                    text: expectedReply,
                  });
                }
                return ctx.reply("Completed OpenClaw delegated task.");
              }
              await waitFor(() => {
                const s = alex.daemon.state.byHandle("live-worker");
                return s && alex.daemon.state.pendingCount(s.id) >= 1;
              }, { timeoutMs: 25_000, label: "OpenClaw delegation landing in real Claude mailbox" });
              return ctx.reply("Awaiting OpenClaw delegation via Stop hook.");
            },
          });

      const [, workerRun, waiterOut] = await Promise.all([
        openClawDelegatePromise,
        workerPromise,
        replyWaiter.output,
      ]);

      assert.equal(
        workerRun.result.code,
        0,
        `Real ${useOpenCode ? "opencode" : "claude"} exited ${workerRun.result.code}\nstdout:\n${workerRun.result.stdout}\nstderr:\n${workerRun.result.stderr}`,
      );
      assert.equal(workerSawDelegatedTask, true, "Real binary must receive OpenClaw's delegated task in its turn context");

      const workerSession = alex.daemon.state.byHandle("live-worker");
      assert.ok(workerSession);
      assert.match(workerSession.id, useOpenCode ? /^opencode:ses_.+/ : /^claude:.+/);

      // OpenClaw's blocking `hyp wait` received the real binary's reply across the Team Router!
      assert.equal(waiterOut.code, 0, `OpenClaw hyp wait exited ${waiterOut.code}: ${waiterOut.stderr}`);
      assert.match(waiterOut.stdout, /hyphae from alex@laptop\/live-worker/);
      assert.match(waiterOut.stdout, new RegExp(expectedReply));
    } finally {
      await topo.cleanup();
    }
  },
);

test(
  "Differential post-state & perturbed-input equivalence (McKeeman): OpenClaw ephemeral vs hook-verified Antigravity",
  { timeout: 30_000 },
  async () => {
    const topo = new MeshTopology("hi-oc4-");
    try {
      const router = await topo.addRouter({ name: "team" });
      const ocConn = await topo.addConnector({ connectorId: "oc@host", links: [{ name: "primary", router }] });
      const agConn = await topo.addConnector({ connectorId: "ag@host", links: [{ name: "primary", router }] });
      const peerConn = await topo.addConnector({ connectorId: "peer@remote", links: [{ name: "primary", router }] });

      // Provision deterministic remote peers (`ally` and `noisy`) on `peer@remote`
      peerConn.daemon.state.register("claude:ally-1", { kind: "claude" });
      peerConn.daemon.state.register("claude:noisy-1", { kind: "claude" });
      await peerConn.daemon.connector.call("claude:ally-1", "hyp_join", { handle: "ally" });
      await peerConn.daemon.connector.call("claude:noisy-1", "hyp_join", { handle: "noisy" });
      await peerConn.daemon.connector.call("claude:ally-1", "hyp_channel_join", { channel: "#diff-room" });

      interface SubjectDriver {
        readonly connectorId: string;
        readonly daemon: typeof ocConn.daemon;
        getSessionId(): string;
        call(tool: string, args?: Record<string, unknown>): Promise<OpenClawToolResult>;
        stopHook(): Promise<Record<string, unknown>>;
      }

      const normalizeText = (raw: string, selfConnectorId: string): string =>
        raw
          .replaceAll(selfConnectorId, "<SELF_CONN>")
          .replaceAll(UUID_RE, "<UUID>");

      const extractErrorCode = (res: OpenClawToolResult): string => {
        assert.equal(res.isError, true, `Expected error result, got ok: ${res.text}`);
        try {
          const parsed = res.json<{ code?: string }>();
          return typeof parsed.code === "string" ? parsed.code : "error";
        } catch {
          return "error";
        }
      };

      const runDifferentialScenario = async (subject: SubjectDriver) => {
        const selfAddr = `${subject.connectorId}/agent`;

        // 1. Join handle & join #diff-room (using perturbed channel casing/whitespace)
        const joinRes = await subject.call("hyp_join", { handle: "agent" });
        assert.equal(joinRes.isError, false, joinRes.text);
        const joinedAddr = normalizeText(joinRes.json<{ address: string }>().address, subject.connectorId);

        const chJoinRes = await subject.call("hyp_channel_join", { channel: "  DIFF-ROOM  " });
        assert.equal(chJoinRes.isError, false, chJoinRes.text);
        const chJoinData = chJoinRes.json<{ channel: string; address: string; members: string[] }>();
        const normalizedChJoin = {
          channel: chJoinData.channel,
          address: normalizeText(chJoinData.address, subject.connectorId),
          members: chJoinData.members.map((m) => normalizeText(m, subject.connectorId)),
        };

        // 2. Switch to notify mode
        const modeRes = (await subject.call("hyp_mode", { mode: "notify" })).json<{ deliveryMode: string; unread: number }>();

        // 3. Receive peer DM + #diff-room post from `peer@remote/ally`
        await peerConn.daemon.connector.call("claude:ally-1", "hyp_send", {
          to: selfAddr,
          text: "DIFF_DM_1_HELLO",
        });
        await peerConn.daemon.connector.call("claude:ally-1", "hyp_channel_post", {
          channel: "#diff-room",
          text: "DIFF_ROOM_1_ALERT",
        });

        await waitFor(() => subject.daemon.state.pendingCount(subject.getSessionId()) >= 2, {
          label: `${subject.connectorId} receiving initial DM + #diff-room post`,
        });

        const capsMid = (await subject.call("hyp_capabilities")).json<{
          modes: string[];
          deliveryMode: string;
          unread: number;
          mutes: number;
          routers: string[];
          inbound: string;
        }>();

        // Trigger stop hook -> both harnesses must emit the exact same slim unread digest text!
        const stopOut = await subject.stopHook();
        const stopReason = normalizeText(String(stopOut.reason ?? ""), subject.connectorId);

        // 4. Add BOTH a session-scoped peer mute AND a connector-scoped perturbed #channel mute
        const mutePeer = (await subject.call("hyp_mute", { target: "  PEER@REMOTE/NOISY  ", scope: "session" })).json<{
          muted: string;
          scope: string;
        }>();
        const muteRoom = (await subject.call("hyp_mute", { target: "  #DIFF-ROOM ", scope: "connector" })).json<{
          muted: string;
          scope: string;
        }>();

        // Perturbed invalid inputs must yield identical error codes on both harnesses
        const invalidCodes = {
          badMute: extractErrorCode(await subject.call("hyp_mute", { target: "invalid target ***" })),
          badMode: extractErrorCode(await subject.call("hyp_mode", { mode: "quiet" })),
          badSend: extractErrorCode(await subject.call("hyp_send", { to: "missing-slash", text: "x" })),
        };

        // 5. Deliver muted peer DM, muted #diff-room post, AND unmuted peer DM
        const mutedDm = (await peerConn.daemon.connector.call("claude:noisy-1", "hyp_send", {
          to: selfAddr,
          text: "SHOULD_BE_MUTED_PEER_DM",
        })) as { messageId: string };
        await waitFor(() => subject.daemon.state.receipt("primary", mutedDm.messageId) === "muted", {
          label: `${subject.connectorId} recording muted receipt for noisy DM`,
        });

        // Both sent by `ally` sequentially so router SSE FIFO guarantees room post is processed before unmuted DM!
        await peerConn.daemon.connector.call("claude:ally-1", "hyp_channel_post", {
          channel: "#diff-room",
          text: "SHOULD_BE_MUTED_ROOM_POST",
        });
        await peerConn.daemon.connector.call("claude:ally-1", "hyp_send", {
          to: selfAddr,
          text: "DIFF_DM_2_UNMUTED",
        });

        await waitFor(() => subject.daemon.state.pendingCount(subject.getSessionId()) >= 3, {
          label: `${subject.connectorId} receiving unmuted DM #2`,
        });

        // 6. Inspect normalized mute list
        const mutesRaw = (await subject.call("hyp_mutes")).json<{
          mutes: Array<{ pattern: string; scope: string; mutedBy: string }>;
        }>();
        const normalizedMutes = mutesRaw.mutes
          .map((m) => ({
            pattern: m.pattern,
            scope: m.scope,
            mutedBy: normalizeText(m.mutedBy, subject.connectorId),
          }))
          .sort((a, b) => `${a.scope}:${a.pattern}`.localeCompare(`${b.scope}:${b.pattern}`));

        // 7. Read & acknowledge entire inbox
        const inboxRes = (await subject.call("hyp_inbox", { acknowledgeAll: true })).json<{
          deliveryMode: string;
          unread: number;
          items: Array<{ router: string; text: string; kind?: string; source?: string }>;
        }>();
        const normalizedInbox = {
          deliveryMode: inboxRes.deliveryMode,
          unreadAfterAck: inboxRes.unread,
          items: inboxRes.items.map((item) => ({
            router: item.router,
            kind: item.kind ?? "message",
            source: item.source ?? "",
            text: normalizeText(item.text, subject.connectorId),
          })),
        };

        // 8. Channels before & after `hyp_leave` (plus idempotent second `hyp_leave`)
        const channelsBeforeLeave = (await subject.call("hyp_channels", { channel: "#diff-room" })).json<{
          channels: Array<{ channel: string; members: string[] }>;
        }>();
        const leave1 = (await subject.call("hyp_leave")).json<{ left: boolean }>();
        const leave2 = (await subject.call("hyp_leave")).json<{ left: boolean }>();
        const channelsAfterLeave = (await subject.call("hyp_channels", { channel: "#diff-room" })).json<{
          channels: Array<{ channel: string; members: string[] }>;
        }>();

        const finalCaps = (await subject.call("hyp_capabilities")).json<{
          deliveryMode: string;
          unread: number;
          mutes: number;
        }>();

        return {
          joinedAddr,
          normalizedChJoin,
          modeRes,
          capsMid: {
            modes: capsMid.modes,
            deliveryMode: capsMid.deliveryMode,
            unread: capsMid.unread,
            mutes: capsMid.mutes,
            routers: capsMid.routers,
            inbound: capsMid.inbound,
          },
          stopReason,
          mutePeer,
          muteRoom,
          invalidCodes,
          normalizedMutes,
          normalizedInbox,
          channelsBeforeLeave: channelsBeforeLeave.channels.map((c) => ({
            channel: c.channel,
            members: c.members.map((m) => normalizeText(m, subject.connectorId)),
          })),
          leave1,
          leave2,
          channelsAfterLeave: channelsAfterLeave.channels.map((c) => ({
            channel: c.channel,
            members: c.members.map((m) => normalizeText(m, subject.connectorId)),
          })),
          finalCaps: {
            deliveryMode: finalCaps.deliveryMode,
            unread: finalCaps.unread,
            mutes: finalCaps.mutes,
          },
        };
      };

      // Subject A: OpenClaw ephemeral session booted from generated `openclaw.json`
      const ocEnv = new VirtualOpenClawEnv({
        scope: "user",
        homeDir: topo.subDir("oc-diff-home"),
        socketPath: ocConn.socketPath,
      });
      topo.track(() => ocEnv.close());
      const ocSession = await ocEnv.openSession();

      const openClawPostState = await runDifferentialScenario({
        connectorId: "oc@host",
        daemon: ocConn.daemon,
        getSessionId: () => ocSession.sessionId!,
        call: (tool, args) => ocSession.callTool(tool, args ?? {}),
        stopHook: () => ocSession.runHook("stop"),
      });

      // Subject B: Hook-verified Antigravity session over standard shared `hyp mcp`
      const agMcp = await agConn.openMcp();
      const agRawId = "ag-diff-conv-1";
      let agSeq = 0;

      const antigravityPostState = await runDifferentialScenario({
        connectorId: "ag@host",
        daemon: agConn.daemon,
        getSessionId: () => `antigravity:${agRawId}`,
        call: (tool, args) =>
          callVerifiedHookMcp(agMcp, agConn.socketPath, "antigravity", agRawId, tool, args ?? {}, String(++agSeq)),
        stopHook: () =>
          handleHookPayload(
            { conversationId: agRawId, terminationReason: "NO_TOOL_CALL" },
            { harness: "antigravity", event: "stop", socketPath: agConn.socketPath },
          ),
      });

      // Assert exact observable post-state equivalence between OpenClaw ephemeral & hook-verified Antigravity!
      assert.deepEqual(
        openClawPostState,
        antigravityPostState,
        "Observable post-state of OpenClaw ephemeral session must match hook-verified Antigravity identically",
      );

      // Sanity assertions on key invariant values inside the shared post-state
      assert.equal(openClawPostState.normalizedInbox.unreadAfterAck, 0);
      assert.equal(openClawPostState.normalizedInbox.items.length, 3);
      const deliveredTexts = openClawPostState.normalizedInbox.items.map((i) => i.text).join("\n");
      assert.match(deliveredTexts, /DIFF_DM_1_HELLO/);
      assert.match(deliveredTexts, /\[#diff-room\] DIFF_ROOM_1_ALERT/);
      assert.match(deliveredTexts, /DIFF_DM_2_UNMUTED/);
      assert.doesNotMatch(deliveredTexts, /SHOULD_BE_MUTED/);
      assert.deepEqual(openClawPostState.leave1, { left: true });
      assert.deepEqual(openClawPostState.leave2, { left: false });
      assert.deepEqual(openClawPostState.channelsAfterLeave, [
        { channel: "#diff-room", members: ["peer@remote/ally"] },
      ]);
    } finally {
      await topo.cleanup();
    }
  },
);
