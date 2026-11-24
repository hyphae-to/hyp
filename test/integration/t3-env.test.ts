import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { test } from "node:test";
import { loadConfig } from "../../src/config.ts";
import {
  issueGrant,
  openGrant,
  parsePairingCode,
  signBinding,
  verifyEntry,
  type Entry,
  type Identity,
} from "../../src/core/identity/grant.ts";
import { generatePrivateKey, publicKeyFromRaw, rawPublicKey, type Signed } from "../../src/core/identity/keys.ts";
import { DEFAULT_LIMITS, RouterCore } from "../../src/core/router/core.ts";
import { serveRouter, type RunningRouter } from "../../src/core/router/server.ts";
import { open as openTransfer, OpenError, seal as sealTransfer } from "../../src/core/transfer/seal.ts";
import { startDaemon } from "../../src/daemon.ts";
import { detectLocalEnvironment } from "../../src/discover.ts";
import { daemonRpc, handleHookPayload } from "../../src/hooks.ts";
import { object } from "../../src/protocol.ts";
import { runDoctor } from "../../src/setup.ts";
import { BINARIES } from "./harness/drivers.ts";
import { freePort, McpClient, MeshTopology, waitFor } from "./harness/topology.ts";
import { readAuditEvents, startIsolatedDaemonSubprocess } from "./shims/herdr-env.ts";
import { deliverSignedWebhook } from "./shims/services.ts";
import {
  openRouterInboxSse,
  seedVirtualT3MeshHome,
  startRealT3Server,
  startVirtualCodexCli,
} from "./shims/t3-env.ts";

// ---------------------------------------------------------------------------
// Local helpers
// ---------------------------------------------------------------------------

async function callClaudeVerified(
  mcp: McpClient,
  socketPath: string,
  rawSessionId: string,
  tool: string,
  args: Record<string, unknown>,
  seq: string,
): Promise<{ text: string; isError: boolean; json(): unknown }> {
  const callId = `toolu_t3_${rawSessionId}_${seq}`;
  await handleHookPayload(
    { session_id: rawSessionId, tool_use_id: callId, tool_name: `mcp__hyphae__${tool}` },
    { harness: "claude", event: "pre-tool-use", socketPath },
  );
  return mcp.callTool(tool, args, { "claudecode/toolUseId": callId });
}

async function callCodexVerified(
  mcp: McpClient,
  socketPath: string,
  rawThreadId: string,
  tool: string,
  args: Record<string, unknown>,
  seq: string,
): Promise<{ text: string; isError: boolean; json(): unknown }> {
  const callId = `call_t3_${rawThreadId}_${seq}`;
  await handleHookPayload(
    { session_id: rawThreadId, tool_use_id: callId, tool_name: `hyphae.${tool}` },
    { harness: "codex", event: "pre-tool-use", socketPath },
  );
  return mcp.callTool(tool, args, { callId });
}

function encodeTransferHeader(signed: Signed): string {
  return Buffer.from(JSON.stringify(signed), "utf8").toString("base64url");
}

function snapshotStat(path: string): { exists: boolean; mtimeMs: number | null } {
  if (!existsSync(path)) return { exists: false, mtimeMs: null };
  return { exists: true, mtimeMs: statSync(path).mtimeMs };
}

// ---------------------------------------------------------------------------
// Test 1: Real `t3 serve` Boot + Isolated `~/.t3-mesh` Detection & Doctor Interop
// ---------------------------------------------------------------------------

test(
  "T3 env Test 1: isolated ~/.t3-mesh detection & doctor secret non-leakage + real t3 serve side-by-side boot",
  { timeout: 45_000 },
  async () => {
    const rootDir = mkdtempSync(join(tmpdir(), "hi-"));
    const realT3Before = snapshotStat(join(homedir(), ".t3"));
    const realT3MeshBefore = snapshotStat(join(homedir(), ".t3-mesh"));

    let t3Server: Awaited<ReturnType<typeof startRealT3Server>> | undefined;
    let daemon: Awaited<ReturnType<typeof startDaemon>> | undefined;
    let mcp: McpClient | undefined;

    try {
      // 1a. Seed isolated fake HOME with ~/.t3, ~/.t3-mesh/config.json, and 0600 secret token files
      const homeDir = join(rootDir, "h1");
      const seeded = seedVirtualT3MeshHome(homeDir, {
        connectorId: "t3@studio",
        routerUrl: "https://mesh.studio.ts.net",
        plugins: ["slack-bridge", "ops-webhook"],
        secretToken: "SUPER_SECRET_T3_TOKEN",
      });

      const env = detectLocalEnvironment(homeDir);
      assert.equal(env.t3.installed, true);
      assert.equal(env.t3.homeDir, seeded.t3Dir);
      assert.equal(env.t3.meshConfigured, true);
      assert.equal(env.t3.connectorId, "t3@studio");
      assert.equal(env.t3.routerUrl, "https://mesh.studio.ts.net");
      assert.deepEqual(env.t3.plugins, ["slack-bridge", "ops-webhook"]);

      const checksBeforeDaemon = await runDoctor(
        join(rootDir, "missing-connector.json"),
        join(rootDir, "missing.sock"),
        homeDir,
      );
      const t3Check = checksBeforeDaemon.find((c) => c.name === "t3");
      assert.ok(t3Check, "runDoctor must include a `t3` check");
      assert.equal(t3Check.ok, true);
      assert.match(t3Check.detail, /t3-mesh active/);
      assert.match(t3Check.detail, /t3@studio/);
      assert.match(t3Check.detail, /https:\/\/mesh\.studio\.ts\.net/);
      assert.match(t3Check.detail, /slack-bridge, ops-webhook/);

      // Security invariant: NEVER read or leak any token/secret string!
      assert.equal(
        JSON.stringify(env).includes("SUPER_SECRET_T3_TOKEN"),
        false,
        "detectLocalEnvironment must never expose t3-mesh secrets",
      );
      assert.equal(
        JSON.stringify(checksBeforeDaemon).includes("SUPER_SECRET_T3_TOKEN"),
        false,
        "runDoctor must never expose t3-mesh secrets",
      );

      // 1b. Differential boundary checks: T3 installed without ~/.t3-mesh/config.json, and malformed config.json
      const homeNoMesh = join(rootDir, "h2");
      seedVirtualT3MeshHome(homeNoMesh, { omitMeshConfig: true, secretToken: "SUPER_SECRET_T3_TOKEN" });
      const envNoMesh = detectLocalEnvironment(homeNoMesh);
      assert.equal(envNoMesh.t3.installed, true);
      assert.equal(envNoMesh.t3.meshConfigured, false);
      assert.equal(envNoMesh.t3.connectorId, undefined);
      assert.deepEqual(envNoMesh.t3.plugins, []);
      const doctorNoMesh = await runDoctor(join(rootDir, "missing.json"), join(rootDir, "missing.sock"), homeNoMesh);
      assert.match(doctorNoMesh.find((c) => c.name === "t3")?.detail ?? "", /no ~\/\.t3-mesh\/config\.json/i);

      const homeCorrupt = join(rootDir, "h3");
      seedVirtualT3MeshHome(homeCorrupt, {
        rawMeshConfig: "{corrupt-json: SUPER_SECRET_T3_TOKEN",
        secretToken: "SUPER_SECRET_T3_TOKEN",
      });
      const envCorrupt = detectLocalEnvironment(homeCorrupt);
      assert.equal(envCorrupt.t3.installed, true);
      assert.equal(envCorrupt.t3.meshConfigured, true);
      assert.equal(envCorrupt.t3.connectorId, undefined);
      assert.deepEqual(envCorrupt.t3.plugins, []);
      assert.equal(JSON.stringify(envCorrupt).includes("SUPER_SECRET_T3_TOKEN"), false);

      // 1c. Real `t3 serve` boot in isolated `--base-dir` alongside a real Hyphae daemon
      if (BINARIES.t3 !== null) {
        t3Server = await startRealT3Server(join(rootDir, "t3s"));
        assert.ok(t3Server.port > 0, "t3 serve must bind a positive loopback port");
        assert.ok(
          t3Server.initialHttpStatus >= 100 && t3Server.initialHttpStatus < 600,
          `Expected valid HTTP status from real t3 serve, got ${t3Server.initialHttpStatus}`,
        );

        // Confirm live HTTP response on 127.0.0.1:<port>
        const liveRes = await fetch(`${t3Server.url}/`);
        await liveRes.arrayBuffer();
        assert.ok(liveRes.status >= 100 && liveRes.status < 600);

        // Confirm isolated `--base-dir` received runtime state while real ~/.t3 was untouched
        assert.ok(
          readdirSync(t3Server.baseDir).length > 0,
          "Expected real t3 serve to write its runtime state inside isolated --base-dir",
        );

        // Run a real Hyphae daemon with an embedded local router cleanly alongside `t3 serve`
        const hypDir = join(rootDir, "hd");
        const hypState = join(hypDir, "s");
        const hypRouterDir = join(hypDir, "r");
        mkdirSync(hypState, { recursive: true, mode: 0o700 });
        mkdirSync(hypRouterDir, { recursive: true, mode: 0o700 });

        const routerDb = join(hypRouterDir, "router.sqlite");
        const seedCore = new RouterCore({ dbPath: routerDb });
        const tok = seedCore.addConnector("dev@t3side");
        seedCore.close();

        const tokenFile = join(hypDir, "primary.token");
        writeFileSync(tokenFile, `${tok}\n`, { mode: 0o600 });
        chmodSync(tokenFile, 0o600);

        const routerPort = await freePort();
        const cfgPath = join(hypDir, "connector.json");
        writeFileSync(
          cfgPath,
          JSON.stringify(
            {
              connectorId: "dev@t3side",
              stateDir: "s",
              routers: [{ name: "primary", url: `http://127.0.0.1:${routerPort}`, tokenFile }],
              localRouter: { host: "127.0.0.1", port: routerPort, db: "r/router.sqlite" },
            },
            null,
            2,
          ) + "\n",
          { mode: 0o600 },
        );
        chmodSync(cfgPath, 0o600);

        daemon = await startDaemon(loadConfig(cfgPath), { quiet: true });
        mcp = new McpClient(daemon.socketPath, ["--ephemeral"]);
        await mcp.initialize();
        const joinRes = await mcp.callTool("hyp_join", { handle: "sidecar" });
        assert.equal(joinRes.isError, false, joinRes.text);
        assert.deepEqual(joinRes.json(), { address: "dev@t3side/sidecar" });

        // runDoctor against running Hyphae daemon + seeded ~/.t3-mesh home
        const liveChecks = await runDoctor(cfgPath, daemon.socketPath, homeDir);
        assert.equal(liveChecks.find((c) => c.name === "daemon")?.ok, true);
        assert.equal(liveChecks.find((c) => c.name === "router:primary")?.ok, true);
        assert.equal(liveChecks.find((c) => c.name === "t3")?.ok, true);
        assert.equal(JSON.stringify(liveChecks).includes("SUPER_SECRET_T3_TOKEN"), false);
      }

      // Differential isolation post-state check: real user ~/.t3 and ~/.t3-mesh untouched
      assert.deepEqual(snapshotStat(join(homedir(), ".t3")), realT3Before, "Real ~/.t3 must never be modified!");
      assert.deepEqual(snapshotStat(join(homedir(), ".t3-mesh")), realT3MeshBefore, "Real ~/.t3-mesh must never be modified!");
    } finally {
      await mcp?.close().catch(() => {});
      await daemon?.stop().catch(() => {});
      await t3Server?.stop().catch(() => {});
      if (t3Server) {
        assert.ok(
          t3Server.proc.exitCode !== null || t3Server.proc.signalCode !== null,
          "Real t3 serve subprocess must be terminated after stop()",
        );
      }
      rmSync(rootDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
    }
  },
);

// ---------------------------------------------------------------------------
// Test 2: `t3-mesh` Wire Interop — Grants/Pairing, Origin-Tagged Messages,
//         Sealed Transfers & `byThreadId` Plugin Handoff
// ---------------------------------------------------------------------------

test(
  "T3 env Test 2: t3-mesh wire interop (Ed25519 pairing/grants, origin metadata, sealed transfers, and byThreadId plugin handoff)",
  { timeout: 35_000 },
  async () => {
    const rootDir = mkdtempSync(join(tmpdir(), "hi-"));
    const auditPath = join(rootDir, "audit.jsonl");

    let core: RouterCore | undefined;
    let router: RunningRouter | undefined;
    let alexDaemon: Awaited<ReturnType<typeof startDaemon>> | undefined;
    let alexMcp: McpClient | undefined;
    let t3Sse: Awaited<ReturnType<typeof openRouterInboxSse>> | undefined;

    try {
      // 2a. Stand up RouterCore with Ed25519 admin key + requirePairing: true
      const adminKey = generatePrivateKey("ed25519");
      const adminPubRaw = rawPublicKey(adminKey);
      const adminPubKey = publicKeyFromRaw(adminPubRaw, "ed25519");

      core = new RouterCore({
        dbPath: join(rootDir, "router.sqlite"),
        auditPath,
        adminKey: adminPubRaw,
        requirePairing: true,
        transferDir: join(rootDir, "xfers"),
      });
      router = await serveRouter({ core, host: "127.0.0.1", port: 0 });

      // Unpaired connector token must be refused when requirePairing is true
      const unpairedToken = core.addConnector("rogue@unpaired");
      const unpairedRes = await fetch(`${router.url}/v1/peers`, {
        headers: { authorization: `Bearer ${unpairedToken}` },
      });
      assert.equal(unpairedRes.status, 401, "Unpaired connector token must fail closed with 401");

      // Perturbed invalid grant signatures must fail closed (400/401)
      const rogueAdminKey = generatePrivateKey("ed25519");
      const rogueGrant = issueGrant(rogueAdminKey, "rogue@desktop", ["messages:*"], 60_000);
      const badAdminRes = await fetch(`${router.url}/v1/grants`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(rogueGrant.signed),
      });
      assert.equal(badAdminRes.status, 401, "Grant signed by unknown admin key must fail closed with 401");

      const legitForTamper = issueGrant(adminKey, "tamper@desktop", ["messages:*"], 60_000);
      const tamperedGrantRes = await fetch(`${router.url}/v1/grants`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          payload: legitForTamper.signed.payload.replace("tamper@desktop", "hijack@desktop"),
          sig: legitForTamper.signed.sig,
        }),
      });
      assert.equal(tamperedGrantRes.status, 401, "Tampered grant payload must fail closed with 401");

      const malformedGrantRes = await fetch(`${router.url}/v1/grants`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ nope: true }),
      });
      assert.equal(malformedGrantRes.status, 400, "Malformed grant body must fail closed with 400");

      // 2b. Pair `t3@desktop` and `alex@laptop` over real HTTP pairing routes
      const pairConnectorOverHttp = async (
        connectorId: string,
        scopes: readonly string[],
        testPerturbedBinding = false,
      ) => {
        const issued = issueGrant(adminKey, connectorId, scopes, 60_000);
        const postGrant = await fetch(`${router!.url}/v1/grants`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(issued.signed),
        });
        assert.equal(postGrant.status, 200, `POST /v1/grants failed for ${connectorId}: ${await postGrant.clone().text()}`);
        const { grantId } = (await postGrant.json()) as { grantId: string };
        assert.equal(grantId, issued.grant.id);

        const getPending = await fetch(`${router!.url}/v1/pairing/${grantId}`);
        assert.equal(getPending.status, 200);
        const pending = (await getPending.json()) as { grant: Signed; adminKey: string };
        assert.equal(pending.adminKey, adminPubRaw);
        const verifiedGrant = openGrant(pending.grant, publicKeyFromRaw(pending.adminKey, "ed25519"));
        assert.ok(verifiedGrant, "Pending grant signature must verify against admin key");
        assert.equal(verifiedGrant.connectorId, connectorId);

        const parsedCode = parsePairingCode(issued.code);
        assert.ok(parsedCode, "Pairing code must parse cleanly");

        const signingKey = generatePrivateKey("ed25519");
        const encryptionKey = generatePrivateKey("x25519");
        const binding = signBinding(verifiedGrant, parsedCode, signingKey, encryptionKey);

        if (testPerturbedBinding) {
          // Corrupt pairingSig -> must fail closed 401 without consuming the grant
          const badPair = await fetch(`${router!.url}/v1/pairing/${grantId}`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
              binding: { ...binding, pairingSig: "A".repeat(binding.pairingSig.length) },
            }),
          });
          assert.equal(badPair.status, 401, "Tampered binding pairingSig must fail closed with 401");
        }

        const postPair = await fetch(`${router!.url}/v1/pairing/${grantId}`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ binding }),
        });
        assert.equal(postPair.status, 200, `POST /v1/pairing failed for ${connectorId}: ${await postPair.clone().text()}`);
        const paired = (await postPair.json()) as { connectorId: string; token: string; scopes: string[] };
        assert.equal(paired.connectorId, connectorId);
        assert.ok(paired.token.startsWith("t3m_"));

        // Replay of the already-used grant must fail closed with 409 already_paired
        const replayPair = await fetch(`${router!.url}/v1/pairing/${grantId}`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ binding }),
        });
        assert.equal(replayPair.status, 409, "Replaying a used pairing grant must fail closed with 409");

        return { connectorId, token: paired.token, signingKey, encryptionKey, grantId };
      };

      const t3Node = await pairConnectorOverHttp("t3@desktop", ["messages:*", "files:*"], true);
      const alexNode = await pairConnectorOverHttp("alex@laptop", ["messages:*", "files:*", "events:*"]);

      // Verify GET /v1/directory returns both cryptographically verifiable identities
      const dirRes = await fetch(`${router.url}/v1/directory`, {
        headers: { authorization: `Bearer ${t3Node.token}` },
      });
      assert.equal(dirRes.status, 200);
      const directory = (await dirRes.json()) as {
        adminKey: string;
        entries: Entry[];
        revocations: Signed[];
      };
      assert.equal(directory.adminKey, adminPubRaw);
      assert.equal(directory.entries.length, 2);
      assert.equal(directory.revocations.length, 0);

      const verifiedByConnector = new Map<string, Identity>();
      for (const entry of directory.entries) {
        const checked = verifyEntry(entry, adminPubKey);
        assert.equal(checked.ok, true, `Directory entry failed verification: ${checked.ok ? "" : checked.reason}`);
        verifiedByConnector.set(checked.identity.connectorId, checked.identity);
      }
      const t3Identity = verifiedByConnector.get("t3@desktop")!;
      const alexIdentity = verifiedByConnector.get("alex@laptop")!;
      assert.equal(t3Identity.signingKey, rawPublicKey(t3Node.signingKey));
      assert.equal(t3Identity.encryptionKey, rawPublicKey(t3Node.encryptionKey));
      assert.equal(alexIdentity.signingKey, rawPublicKey(alexNode.signingKey));
      assert.equal(alexIdentity.encryptionKey, rawPublicKey(alexNode.encryptionKey));

      // 2c. Start real Hyphae connector daemon for `alex@laptop` with built-in webhook plugin targeting `threadId`
      const webhookPort = await freePort();
      const webhookSecret = "t3-wire-webhook-secret-42";
      const codexUuid = "11111111-2222-4333-8444-555555555555";
      const claudeThreadId = "claude-holder-99";

      const alexCfgDir = join(rootDir, "c0");
      mkdirSync(join(alexCfgDir, "s"), { recursive: true, mode: 0o700 });
      const alexTokenFile = join(alexCfgDir, "primary.token");
      const webhookSecretFile = join(alexCfgDir, "webhook.secret");
      writeFileSync(alexTokenFile, `${alexNode.token}\n`, { mode: 0o600 });
      writeFileSync(webhookSecretFile, `${webhookSecret}\n`, { mode: 0o600 });
      chmodSync(alexTokenFile, 0o600);
      chmodSync(webhookSecretFile, 0o600);

      const alexCfgPath = join(alexCfgDir, "connector.json");
      writeFileSync(
        alexCfgPath,
        JSON.stringify(
          {
            connectorId: "alex@laptop",
            stateDir: "s",
            routers: [{ name: "primary", url: router.url, tokenFile: alexTokenFile }],
            plugins: [
              {
                name: "t3-webhook",
                builtin: "webhook",
                env: {
                  WEBHOOK_HOST: "127.0.0.1",
                  WEBHOOK_PORT: String(webhookPort),
                  WEBHOOK_PATH: "/hook",
                  WEBHOOK_TARGET: "t3-ops",
                  WEBHOOK_SECRET_FILE: webhookSecretFile,
                  WEBHOOK_SOURCE: "t3/local-alerts",
                  WEBHOOK_EVENT_TYPE: "com.t3.alert",
                },
                targets: [
                  // Configured by bare `threadId` (resolved via State.byThreadId -> `codex:<codexUuid>`)
                  { name: "t3-ops", threadId: codexUuid, coalesceSeconds: 0, maxWaitSeconds: 5, wakesPerHour: 120 },
                ],
              },
            ],
          },
          null,
          2,
        ) + "\n",
        { mode: 0o600 },
      );
      chmodSync(alexCfgPath, 0o600);

      alexDaemon = await startDaemon(loadConfig(alexCfgPath), { quiet: true });
      alexMcp = new McpClient(alexDaemon.socketPath);
      await alexMcp.initialize();

      // Enroll `codex:<codexUuid>` and `claude:<claudeThreadId>` via PreToolUse-verified MCP calls
      const joinCodex = await callCodexVerified(alexMcp, alexDaemon.socketPath, codexUuid, "hyp_join", { handle: "alex-codex" }, "1");
      assert.equal(joinCodex.isError, false, joinCodex.text);
      const joinClaude = await callClaudeVerified(alexMcp, alexDaemon.socketPath, claudeThreadId, "hyp_join", { handle: "alex-claude" }, "1");
      assert.equal(joinClaude.isError, false, joinClaude.text);

      // Wait until `alex@laptop` is attached online on the router
      await waitFor(
        () => readAuditEvents(auditPath).some((ev) => ev.event === "connector.online" && ev.connector === "alex@laptop"),
        { label: "alex@laptop online on paired router" },
      );

      // 2d. Origin-tagged message from `t3@desktop` -> Hyphae session on `alex@laptop`
      const putHandles = await fetch(`${router.url}/v1/handles`, {
        method: "PUT",
        headers: { authorization: `Bearer ${t3Node.token}`, "content-type": "application/json" },
        body: JSON.stringify({ handles: ["t3-main"] }),
      });
      assert.equal(putHandles.status, 200);

      const originMsgId = randomUUID();
      const sendOriginRes = await fetch(`${router.url}/v1/messages`, {
        method: "POST",
        headers: { authorization: `Bearer ${t3Node.token}`, "content-type": "application/json" },
        body: JSON.stringify({
          id: originMsgId,
          fromHandle: "t3-main",
          to: "alex@laptop/alex-codex",
          text: "Origin-tagged greeting from T3 Code!",
          origin: { environmentId: "env-t3", threadId: "thr-123" },
        }),
      });
      assert.equal(sendOriginRes.status, 200, await sendOriginRes.clone().text());
      assert.deepEqual(await sendOriginRes.json(), { status: "stored" });

      // Wait for Hyphae session `codex:<codexUuid>` to receive the origin-tagged message cleanly
      await waitFor(
        () => alexDaemon!.state.pendingCount(`codex:${codexUuid}`) === 1,
        { label: "origin-tagged message delivered to alex@laptop/alex-codex" },
      );
      const inboxRes = await callCodexVerified(
        alexMcp,
        alexDaemon.socketPath,
        codexUuid,
        "hyp_inbox",
        { acknowledgeAll: true },
        "2",
      );
      assert.equal(inboxRes.isError, false, inboxRes.text);
      const inboxPayload = inboxRes.json() as { unread: number; items: Array<{ text: string }> };
      assert.equal(inboxPayload.unread, 0);
      assert.equal(inboxPayload.items.length, 1);
      assert.match(inboxPayload.items[0].text, /hyphae from t3@desktop\/t3-main/);
      assert.match(inboxPayload.items[0].text, /Origin-tagged greeting from T3 Code!/);

      await waitFor(
        () => readAuditEvents(auditPath).some((ev) => ev.event === "message.delivered" && ev.id === originMsgId),
        { label: "router audit confirms origin-tagged message delivered" },
      );

      // Differential post-state check: router SQLite persisted origin metadata + settled state
      const inspectDb = new DatabaseSync(join(rootDir, "router.sqlite"), { readOnly: true });
      try {
        const msgRow = inspectDb
          .prepare("SELECT state, origin_environment_id, origin_thread_id FROM messages WHERE id = ?")
          .get(originMsgId) as { state?: string; origin_environment_id?: string; origin_thread_id?: string } | undefined;
        assert.deepEqual(msgRow ? { ...msgRow } : undefined, {
          state: "delivered",
          origin_environment_id: "env-t3",
          origin_thread_id: "thr-123",
        });
      } finally {
        inspectDb.close();
      }

      // 2e. Real end-to-end sealed transfer: alex@laptop -> t3@desktop (SSE offer -> GET -> open -> ack)
      t3Sse = await openRouterInboxSse(router.url, t3Node.token);

      const transferId = randomUUID();
      const plaintext = Buffer.concat([
        Buffer.from("T3_MESH_SEALED_PATCH_V1\nfile=src/app.ts\n", "utf8"),
        Buffer.from([0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff]),
        Buffer.from("END_OF_BINARY_ARCHIVE", "utf8"),
      ]);
      const sealed = sealTransfer(
        {
          id: transferId,
          type: "files",
          from: "alex@laptop",
          to: "t3@desktop",
          toHandle: "t3-main",
          ttlMs: 60_000,
        },
        plaintext,
        alexNode.signingKey,
        t3Identity.encryptionKey,
      );

      // Perturbed transfer uploads MUST fail closed before storing!
      // (i) Tampered signature in T3-Mesh-Transfer header -> 401
      const tamperedSigHeader: Signed = {
        payload: sealed.header.payload,
        sig: "B".repeat(sealed.header.sig.length),
      };
      const badSigPut = await fetch(`${router.url}/v1/transfers/${transferId}`, {
        method: "PUT",
        headers: {
          authorization: `Bearer ${alexNode.token}`,
          "t3-mesh-transfer": encodeTransferHeader(tamperedSigHeader),
        },
        body: new Uint8Array(sealed.ciphertext),
      });
      assert.equal(badSigPut.status, 401, "Tampered T3-Mesh-Transfer signature must fail closed with 401");

      // (ii) Tampered header payload (altered toHandle without re-signing) -> 401
      const tamperedPayloadHeader: Signed = {
        payload: sealed.header.payload.replace('"t3-main"', '"t3-evil"'),
        sig: sealed.header.sig,
      };
      const badPayloadPut = await fetch(`${router.url}/v1/transfers/${transferId}`, {
        method: "PUT",
        headers: {
          authorization: `Bearer ${alexNode.token}`,
          "t3-mesh-transfer": encodeTransferHeader(tamperedPayloadHeader),
        },
        body: new Uint8Array(sealed.ciphertext),
      });
      assert.equal(badPayloadPut.status, 401, "Tampered T3-Mesh-Transfer payload must fail closed with 401");

      // (iii) Path ID mismatch -> 400
      const mismatchPut = await fetch(`${router.url}/v1/transfers/${randomUUID()}`, {
        method: "PUT",
        headers: {
          authorization: `Bearer ${alexNode.token}`,
          "t3-mesh-transfer": encodeTransferHeader(sealed.header),
        },
        body: new Uint8Array(sealed.ciphertext),
      });
      assert.equal(mismatchPut.status, 400, "Transfer path/header ID mismatch must fail closed with 400");

      // (iv) Valid header + corrupted ciphertext byte -> 400 (SHA-256 mismatch)
      const corruptedCipher = Buffer.from(sealed.ciphertext);
      corruptedCipher[0] ^= 0xff;
      const badBodyPut = await fetch(`${router.url}/v1/transfers/${transferId}`, {
        method: "PUT",
        headers: {
          authorization: `Bearer ${alexNode.token}`,
          "t3-mesh-transfer": encodeTransferHeader(sealed.header),
        },
        body: new Uint8Array(corruptedCipher),
      });
      assert.equal(badBodyPut.status, 400, "Ciphertext SHA-256 mismatch must fail closed with 400");

      // Valid PUT /v1/transfers/:id
      const okPut = await fetch(`${router.url}/v1/transfers/${transferId}`, {
        method: "PUT",
        headers: {
          authorization: `Bearer ${alexNode.token}`,
          "t3-mesh-transfer": encodeTransferHeader(sealed.header),
        },
        body: new Uint8Array(sealed.ciphertext),
      });
      assert.equal(okPut.status, 200, `Valid transfer upload failed: ${await okPut.clone().text()}`);
      assert.deepEqual(await okPut.json(), { status: "stored" });

      // Wait for SSE `transfer` offer on t3@desktop's `/v1/inbox` stream
      const offerEvent = await t3Sse.waitForEvent(
        (ev) => ev.event === "transfer" && ev.data.kind === "transfer" && ev.data.id === transferId,
      );
      assert.equal(offerEvent.data.from, "alex@laptop");
      assert.equal(offerEvent.data.type, "files");
      assert.equal(offerEvent.data.size, sealed.ciphertext.length);
      assert.ok(object(offerEvent.data.header), "Transfer offer must carry signed header");
      const offeredHeader: Signed = {
        payload: String(offerEvent.data.header.payload),
        sig: String(offerEvent.data.header.sig),
      };

      // Download ciphertext via GET /v1/transfers/:id as t3@desktop
      const getXfer = await fetch(`${router.url}/v1/transfers/${transferId}`, {
        headers: { authorization: `Bearer ${t3Node.token}` },
      });
      assert.equal(getXfer.status, 200);
      const downloaded = Buffer.from(await getXfer.arrayBuffer());
      assert.equal(downloaded.length, sealed.ciphertext.length);

      // Sender (not recipient) attempting GET /v1/transfers/:id must fail closed with 404
      const wrongReaderGet = await fetch(`${router.url}/v1/transfers/${transferId}`, {
        headers: { authorization: `Bearer ${alexNode.token}` },
      });
      assert.equal(wrongReaderGet.status, 404, "Non-recipient must not download another connector's transfer");

      // Open & decrypt using alex@laptop's directory signing key + t3@desktop's X25519 private key
      const alexPubSigning = publicKeyFromRaw(alexIdentity.signingKey, "ed25519");
      const opened = openTransfer(offeredHeader, downloaded, alexPubSigning, t3Node.encryptionKey);
      assert.equal(opened.header.id, transferId);
      assert.equal(opened.header.toHandle, "t3-main");
      assert.equal(Buffer.compare(opened.plaintext, plaintext), 0, "Decrypted transfer payload must match byte-for-byte");

      // Perturbed openTransfer assertions: wrong sender key -> bad_signature; altered ciphertext -> corrupt
      assert.throws(
        () => openTransfer(offeredHeader, downloaded, publicKeyFromRaw(t3Identity.signingKey, "ed25519"), t3Node.encryptionKey),
        (err: unknown) => err instanceof OpenError && err.reason === "bad_signature",
      );
      const alteredDownload = Buffer.from(downloaded);
      alteredDownload[alteredDownload.length - 1] ^= 0x01;
      assert.throws(
        () => openTransfer(offeredHeader, alteredDownload, alexPubSigning, t3Node.encryptionKey),
        (err: unknown) => err instanceof OpenError && err.reason === "corrupt",
      );

      // Ack transfer delivered and assert router cleans up ciphertext (subsequent GET -> 404)
      const ackXfer = await fetch(`${router.url}/v1/messages/${encodeURIComponent(transferId)}/ack`, {
        method: "POST",
        headers: { authorization: `Bearer ${t3Node.token}`, "content-type": "application/json" },
        body: JSON.stringify({ outcome: "delivered" }),
      });
      assert.equal(ackXfer.status, 200);
      const afterAckGet = await fetch(`${router.url}/v1/transfers/${transferId}`, {
        headers: { authorization: `Bearer ${t3Node.token}` },
      });
      assert.equal(afterAckGet.status, 404, "Acked transfer ciphertext must be deleted immediately");

      // 2f. `byThreadId` Plugin Target + `hyp_plugin_targets` + Live `hyp_plugin_handoff` by `threadId`
      const codexTargetsRes = await callCodexVerified(alexMcp, alexDaemon.socketPath, codexUuid, "hyp_plugin_targets", {}, "3");
      assert.equal(codexTargetsRes.isError, false, codexTargetsRes.text);
      const codexTargets = codexTargetsRes.json() as {
        targets: Array<{ plugin: string; target: string; sessionId: string | null; handle: string | null }>;
      };
      assert.deepEqual(codexTargets.targets, [
        { plugin: "t3-webhook", target: "t3-ops", sessionId: `codex:${codexUuid}`, handle: "alex-codex" },
      ]);

      // Before handoff, Claude does NOT hold the target and cannot steal it
      const claudeTargetsBefore = await callClaudeVerified(alexMcp, alexDaemon.socketPath, claudeThreadId, "hyp_plugin_targets", {}, "2");
      assert.equal(claudeTargetsBefore.isError, false, claudeTargetsBefore.text);
      assert.deepEqual((claudeTargetsBefore.json() as { targets: unknown[] }).targets, []);

      const stealAttempt = await callClaudeVerified(
        alexMcp,
        alexDaemon.socketPath,
        claudeThreadId,
        "hyp_plugin_handoff",
        { plugin: "t3-webhook", target: "t3-ops", threadId: claudeThreadId },
        "3",
      );
      assert.equal(stealAttempt.isError, true, "Non-holder must not be able to hand off a plugin target");
      assert.match(stealAttempt.text, /not_target_holder/);

      // Deliver signed webhook #1 -> lands in `codex:<codexUuid>` via byThreadId
      const webhookUrl = `http://127.0.0.1:${webhookPort}/hook`;
      const hook1 = await deliverSignedWebhook({
        url: webhookUrl,
        secret: webhookSecret,
        deliveryId: "t3-hook-1",
        payload: { severity: "high", msg: "ALERT_FOR_CODEX_THREAD" },
        waitForReadyMs: 6_000,
      });
      assert.equal(hook1.status, 202, `Expected 202 from signed webhook #1, got ${hook1.status}`);

      // Forged webhook signature must fail closed 401
      const forgedHook = await deliverSignedWebhook({
        url: webhookUrl,
        secret: webhookSecret,
        overrideSignature: "sha256=deadbeef",
        payload: { msg: "FORGED_ALERT" },
      });
      assert.equal(forgedHook.status, 401, "Bad HMAC signature must fail closed with 401");

      await waitFor(
        () => alexDaemon!.state.pendingCount(`codex:${codexUuid}`) === 1,
        { label: "webhook #1 delivered to codex:<uuid> via byThreadId" },
      );
      assert.equal(alexDaemon.state.pendingCount(`claude:${claudeThreadId}`), 0);

      const codexHookInbox = await callCodexVerified(
        alexMcp,
        alexDaemon.socketPath,
        codexUuid,
        "hyp_inbox",
        { acknowledgeAll: true },
        "4",
      );
      assert.equal(codexHookInbox.isError, false, codexHookInbox.text);
      const codexHookItems = (codexHookInbox.json() as { items: Array<{ text: string }> }).items;
      assert.equal(codexHookItems.length, 1);
      assert.match(codexHookItems[0].text, /ALERT_FOR_CODEX_THREAD/);

      // Perturbed handoff to nonexistent threadId fails closed with unknown_session
      const badHandoff = await callCodexVerified(
        alexMcp,
        alexDaemon.socketPath,
        codexUuid,
        "hyp_plugin_handoff",
        { plugin: "t3-webhook", target: "t3-ops", threadId: "nonexistent-thread-404" },
        "5",
      );
      assert.equal(badHandoff.isError, true);
      assert.match(badHandoff.text, /unknown_session/);

      // Live handoff by bare `threadId` from `codex:<codexUuid>` -> `claude:<claudeThreadId>`
      const handoffRes = await callCodexVerified(
        alexMcp,
        alexDaemon.socketPath,
        codexUuid,
        "hyp_plugin_handoff",
        { plugin: "t3-webhook", target: "t3-ops", threadId: claudeThreadId },
        "6",
      );
      assert.equal(handoffRes.isError, false, handoffRes.text);
      assert.deepEqual(handoffRes.json(), {
        plugin: "t3-webhook",
        target: "t3-ops",
        sessionId: `claude:${claudeThreadId}`,
      });

      // Verify `hyp_plugin_targets` now shows Claude as the live holder
      const claudeTargetsAfter = await callClaudeVerified(alexMcp, alexDaemon.socketPath, claudeThreadId, "hyp_plugin_targets", {}, "4");
      assert.equal(claudeTargetsAfter.isError, false, claudeTargetsAfter.text);
      assert.deepEqual((claudeTargetsAfter.json() as { targets: unknown[] }).targets, [
        { plugin: "t3-webhook", target: "t3-ops", sessionId: `claude:${claudeThreadId}`, handle: "alex-claude" },
      ]);

      // Deliver signed webhook #2 -> lands in `claude:<claudeThreadId>` (and NOT in `codex:<codexUuid>`)!
      const hook2 = await deliverSignedWebhook({
        url: webhookUrl,
        secret: webhookSecret,
        deliveryId: "t3-hook-2",
        payload: { severity: "info", msg: "ALERT_AFTER_THREAD_HANDOFF" },
      });
      assert.equal(hook2.status, 202);

      await waitFor(
        () => alexDaemon!.state.pendingCount(`claude:${claudeThreadId}`) === 1,
        { label: "webhook #2 delivered to claude:<id> after threadId handoff" },
      );
      assert.equal(alexDaemon.state.pendingCount(`codex:${codexUuid}`), 0, "Previous holder must not receive post-handoff webhook");

      const claudeHookInbox = await callClaudeVerified(
        alexMcp,
        alexDaemon.socketPath,
        claudeThreadId,
        "hyp_inbox",
        { acknowledgeAll: true },
        "5",
      );
      assert.equal(claudeHookInbox.isError, false, claudeHookInbox.text);
      const claudeHookItems = (claudeHookInbox.json() as { items: Array<{ text: string }> }).items;
      assert.equal(claudeHookItems.length, 1);
      assert.match(claudeHookItems[0].text, /ALERT_AFTER_THREAD_HANDOFF/);
    } finally {
      await t3Sse?.close().catch(() => {});
      await alexMcp?.close().catch(() => {});
      await alexDaemon?.stop().catch(() => {});
      await router?.close().catch(() => {});
      try { core?.close(); } catch {}
      rmSync(rootDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
    }
  },
);

// ---------------------------------------------------------------------------
// Test 3: Codex `--thread` + `--remote ws://...` + `--resume` Actuation,
//         Offline Hold -> Retry Recovery, Hard Error Reject & `notify` Mode
// ---------------------------------------------------------------------------

test(
  "T3 env Test 3: Codex --thread + --remote + --resume actuation, offline hold/retry, hard-error reject, and notify digest isolation",
  { timeout: 35_000 },
  async () => {
    const rootDir = mkdtempSync(join(tmpdir(), "hi-"));
    const auditPath = join(rootDir, "audit.jsonl");

    let core: RouterCore | undefined;
    let router: RunningRouter | undefined;
    let virtualCodex: Awaited<ReturnType<typeof startVirtualCodexCli>> | undefined;
    let daemon: Awaited<ReturnType<typeof startIsolatedDaemonSubprocess>> | undefined;

    try {
      core = new RouterCore({
        dbPath: join(rootDir, "r.sqlite"),
        auditPath,
        limits: { ...DEFAULT_LIMITS, holdRetryMs: 250 },
      });
      const token = core.addConnector("dev@codex");
      router = await serveRouter({ core, host: "127.0.0.1", port: 0 });
      virtualCodex = await startVirtualCodexCli(join(rootDir, "vc"));

      daemon = await startIsolatedDaemonSubprocess({
        rootDir,
        name: "d0",
        connectorId: "dev@codex",
        routerUrl: router.url,
        token,
        env: virtualCodex.envWithVirtualCodex(),
        auditPath,
      });

      const threadUuid = "3f2504e0-4f89-41d3-9a0c-0305e82c3301";
      const remoteUrl = "ws://127.0.0.1:4444";
      const customCodexHome = join(rootDir, "isolated-codex-home");
      mkdirSync(customCodexHome, { recursive: true, mode: 0o700 });

      const codexMcp = await daemon.openMcp(
        ["--thread", threadUuid, "--remote", remoteUrl, "--resume"],
        { CODEX_HOME: customCodexHome },
      );

      // Verify capabilities report codex / codex-queue / ["queue"]
      const capsRes = await codexMcp.callTool("hyp_capabilities", {});
      assert.equal(capsRes.isError, false, capsRes.text);
      const caps = capsRes.json() as {
        sessionId: string;
        backend: string;
        inbound: string;
        modes: string[];
        deliveryMode: string;
      };
      assert.equal(caps.sessionId, `codex:${threadUuid}`);
      assert.equal(caps.backend, "codex");
      assert.equal(caps.inbound, "codex-queue");
      assert.deepEqual(caps.modes, ["queue"]);
      assert.equal(caps.deliveryMode, "full");

      const joinCodex = await codexMcp.callTool("hyp_join", { handle: "codex-remote" });
      assert.equal(joinCodex.isError, false, joinCodex.text);
      assert.deepEqual(joinCodex.json(), { address: "dev@codex/codex-remote" });

      const peerMcp = await daemon.openMcp(["--ephemeral"]);
      const joinPeer = await peerMcp.callTool("hyp_join", { handle: "peer-sender" });
      assert.equal(joinPeer.isError, false, joinPeer.text);

      // 3a. Offline `codex` remote -> hold (`codex_queue_unavailable`) -> automatic retry on recovery!
      virtualCodex.setMode({ kind: "offline", stderr: "connect refused: app-server offline\n" });

      const send1 = await peerMcp.callTool("hyp_send", {
        to: "dev@codex/codex-remote",
        text: "REMOTE_RETRY_PAYLOAD_1",
      });
      assert.equal(send1.isError, false, send1.text);
      const msg1Id = (send1.json() as { messageId: string }).messageId;

      // Confirm daemon attempted `codex queue`, hit offline refusal, and held cleanly on the router
      const failedAttempt = await virtualCodex.waitForInvocation(
        (inv) => inv.subcommand === "queue" && inv.exitCode === 1,
      );
      assert.equal(failedAttempt.threadId, threadUuid);
      assert.equal(failedAttempt.resume, true);
      assert.equal(failedAttempt.remote, remoteUrl);
      assert.equal(failedAttempt.codexHome, customCodexHome);

      await waitFor(
        () =>
          readAuditEvents(auditPath).some(
            (ev) => ev.event === "message.hold" && ev.id === msg1Id && ev.reason === "codex_queue_unavailable",
          ),
        { label: "router audit records codex_queue_unavailable hold" },
      );
      assert.equal(virtualCodex.queuedMessages.length, 0, "Offline refusal must not record a delivered message");

      // Bring virtual `codex` back online -> router auto-retries and delivers with exact argv!
      virtualCodex.setMode({ kind: "ok" });
      const delivered1 = await virtualCodex.waitForQueueMessage(
        (m) => m.message.includes("REMOTE_RETRY_PAYLOAD_1"),
      );
      assert.deepEqual(
        delivered1.args,
        [
          "queue",
          "--thread",
          threadUuid,
          "--message",
          delivered1.message,
          "--resume",
          "--remote",
          remoteUrl,
        ],
        "codex queue must pass exact --thread / --message / --resume / --remote flags",
      );
      assert.match(delivered1.message, /hyphae from dev@codex\/peer-sender/);
      assert.equal(delivered1.codexHome, customCodexHome);

      await waitFor(
        () => readAuditEvents(auditPath).some((ev) => ev.event === "message.delivered" && ev.id === msg1Id),
        { label: "router audit records delivery after codex recovery" },
      );

      // 3b. Perturbed hard CLI error (non-transient stderr) -> rejected (`codex_queue_outcome_unknown`), NOT held!
      virtualCodex.setMode({ kind: "error", code: 2, stderr: "invalid json payload schema\n" });
      const sendHardErr = await peerMcp.callTool("hyp_send", {
        to: "dev@codex/codex-remote",
        text: "HARD_ERROR_PAYLOAD_2",
      });
      assert.equal(sendHardErr.isError, false, sendHardErr.text);
      const msg2Id = (sendHardErr.json() as { messageId: string }).messageId;

      await waitFor(
        () =>
          readAuditEvents(auditPath).some(
            (ev) => ev.event === "message.rejected" && ev.id === msg2Id && ev.reason === "codex_queue_outcome_unknown",
          ),
        { label: "router audit records codex_queue_outcome_unknown rejection on hard error" },
      );
      virtualCodex.setMode({ kind: "ok" });

      // 3c. `notify` mode: `codex queue` receives ONLY slim unread digest, NEVER `SECRET_CODEX_BODY`!
      const modeRes = await codexMcp.callTool("hyp_mode", { mode: "notify" });
      assert.equal(modeRes.isError, false, modeRes.text);
      assert.deepEqual(modeRes.json(), { deliveryMode: "notify", unread: 0 });

      const sendSecret = await peerMcp.callTool("hyp_send", {
        to: "dev@codex/codex-remote",
        text: "SECRET_CODEX_BODY",
      });
      assert.equal(sendSecret.isError, false, sendSecret.text);

      const slimNotice = await virtualCodex.waitForQueueMessage((m) => m.message.includes("hyphae notice"));
      assert.match(slimNotice.message, /hyphae notice · 1 unread/);
      assert.equal(
        slimNotice.message.includes("SECRET_CODEX_BODY"),
        false,
        "notify mode must NEVER send full message body through codex queue!",
      );
      assert.equal(slimNotice.resume, true);
      assert.equal(slimNotice.remote, remoteUrl);
      assert.equal(slimNotice.codexHome, customCodexHome);

      // Full secret body stays durably in hyp_inbox until acknowledged
      const inboxRes = await codexMcp.callTool("hyp_inbox", { acknowledgeAll: true });
      assert.equal(inboxRes.isError, false, inboxRes.text);
      const inbox = inboxRes.json() as { deliveryMode: string; unread: number; items: Array<{ text: string }> };
      assert.equal(inbox.deliveryMode, "notify");
      assert.equal(inbox.unread, 0);
      assert.equal(inbox.items.length, 1);
      assert.match(inbox.items[0].text, /SECRET_CODEX_BODY/);
    } finally {
      await daemon?.stop().catch(() => {});
      await virtualCodex?.close().catch(() => {});
      await router?.close().catch(() => {});
      try { core?.close(); } catch {}
      rmSync(rootDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
    }
  },
);

// ---------------------------------------------------------------------------
// Test 4: Claude Native Channel (`--claude-channel`) Full Lifecycle:
//         Live Push, Disconnect -> Durable Mailbox -> Reconnect Auto-Flush, & `notify` Mode
// ---------------------------------------------------------------------------

test(
  "T3 env Test 4: --claude-channel full lifecycle (live push, disconnect -> SQLite buffer -> reconnect auto-flush, and notify digest)",
  { timeout: 30_000 },
  async () => {
    const topo = new MeshTopology("hi-");
    try {
      const router = await topo.addRouter({ name: "team" });
      const conn = await topo.addConnector({
        connectorId: "dev@claude",
        links: [{ name: "primary", router }],
      });

      const claudeRawId = "chan-1";
      const claudeSessionId = `claude:${claudeRawId}`;

      // 4a. Connect `--claude-channel` MCP client, verify experimental capability, enroll with PreToolUse verification
      const chanMcp1 = new McpClient(conn.socketPath, ["--claude-channel"]);
      topo.track(() => chanMcp1.close());
      const init1 = await chanMcp1.initialize();
      const initResult = object(init1.result) ? init1.result : {};
      const initCaps = object(initResult.capabilities) ? initResult.capabilities : {};
      const experimental = object(initCaps.experimental) ? initCaps.experimental : {};
      assert.ok(
        object(experimental["claude/channel"]),
        `Expected initialize capabilities.experimental["claude/channel"], got: ${JSON.stringify(init1)}`,
      );

      const joinChan = await callClaudeVerified(chanMcp1, conn.socketPath, claudeRawId, "hyp_join", { handle: "claude-chan" }, "j1");
      assert.equal(joinChan.isError, false, joinChan.text);
      assert.deepEqual(joinChan.json(), { address: "dev@claude/claude-chan" });

      const caps1Res = await callClaudeVerified(chanMcp1, conn.socketPath, claudeRawId, "hyp_capabilities", {}, "c1");
      assert.equal(caps1Res.isError, false, caps1Res.text);
      const caps1 = caps1Res.json() as { sessionId: string; backend: string; inbound: string; deliveryMode: string };
      assert.equal(caps1.sessionId, claudeSessionId);
      assert.equal(caps1.backend, "claude");
      assert.equal(caps1.inbound, "claude-channel");
      assert.equal(caps1.deliveryMode, "full");

      // Peer sender on same mesh
      const peerMcp = await conn.openMcp(["--ephemeral"]);
      const joinPeer = await peerMcp.callTool("hyp_join", { handle: "peer-a" });
      assert.equal(joinPeer.isError, false, joinPeer.text);

      // 4b. Msg #1 -> immediate `notifications/claude/channel` JSON-RPC push over stdio
      const send1 = await peerMcp.callTool("hyp_send", {
        to: "dev@claude/claude-chan",
        text: "LIVE_CHANNEL_MSG_1",
      });
      assert.equal(send1.isError, false, send1.text);

      const notif1 = await waitFor(
        () =>
          chanMcp1.notifications.find(
            (n) =>
              n.method === "notifications/claude/channel" &&
              object(n.params) &&
              typeof n.params.content === "string" &&
              n.params.content.includes("LIVE_CHANNEL_MSG_1"),
          ),
        { label: "live notifications/claude/channel push for msg #1" },
      );
      assert.equal(notif1.jsonrpc, "2.0");
      assert.match(String((notif1.params as Record<string, unknown>).content), /hyphae from dev@claude\/peer-a/);

      // After ack, SQLite mailbox must be empty (0 pending)
      await waitFor(() => conn.daemon.state.pendingCount(claudeSessionId) === 0, {
        label: "mailbox drained after channel ack of msg #1",
      });

      // 4c. Disconnect `--claude-channel` subprocess -> send msg #2 -> durably buffered in SQLite (`pendingCount === 1`)
      await chanMcp1.close();
      await waitFor(
        async () => {
          const st = await daemonRpc(conn.socketPath, { type: "session.status", sessionId: claudeSessionId });
          return st.ok && st.result?.hasLiveTransport === false;
        },
        { label: "daemon detects disconnected claude channel" },
      );

      const send2 = await peerMcp.callTool("hyp_send", {
        to: "dev@claude/claude-chan",
        text: "BUFFERED_OFFLINE_MSG_2",
      });
      assert.equal(send2.isError, false, send2.text);

      await waitFor(() => conn.daemon.state.pendingCount(claudeSessionId) === 1, {
        label: "msg #2 durably buffered in SQLite mailbox while channel offline",
      });
      const offlineStatus = conn.daemon.connector.sessionStatus(claudeSessionId);
      assert.equal(offlineStatus?.hasLiveTransport, false);
      assert.equal(offlineStatus?.pending, 1);

      // 4d. Reconnect fresh `--claude-channel` MCP subprocess -> bind via verified `hyp_capabilities` -> auto-flush!
      const chanMcp2 = new McpClient(conn.socketPath, ["--claude-channel"]);
      topo.track(() => chanMcp2.close());
      await chanMcp2.initialize();

      // Security check: before PreToolUse-verified binding, the fresh socket must NOT receive another session's mailbox
      await new Promise((r) => setTimeout(r, 150));
      assert.equal(chanMcp2.notifications.length, 0, "Unbound --claude-channel socket must not receive buffered items");

      // Perturbed check: unverified tool call still fails closed on a `--claude-channel` socket
      const unverifiedCall = await chanMcp2.callTool("hyp_capabilities", {});
      assert.equal(unverifiedCall.isError, true);
      assert.match(unverifiedCall.text, /caller_unverifiable/);

      // Single verified `hyp_capabilities` binds `claude:chan-1` AND triggers immediate auto-flush of msg #2!
      const caps2Res = await callClaudeVerified(chanMcp2, conn.socketPath, claudeRawId, "hyp_capabilities", {}, "c2");
      assert.equal(caps2Res.isError, false, caps2Res.text);
      const caps2 = caps2Res.json() as { inbound: string; sessionId: string };
      assert.equal(caps2.sessionId, claudeSessionId);
      assert.equal(caps2.inbound, "claude-channel");

      const notif2 = await waitFor(
        () =>
          chanMcp2.notifications.find(
            (n) =>
              n.method === "notifications/claude/channel" &&
              object(n.params) &&
              typeof n.params.content === "string" &&
              n.params.content.includes("BUFFERED_OFFLINE_MSG_2"),
          ),
        { label: "auto-flush of buffered msg #2 over reconnected --claude-channel" },
      );
      assert.match(String((notif2.params as Record<string, unknown>).content), /BUFFERED_OFFLINE_MSG_2/);

      await waitFor(() => conn.daemon.state.pendingCount(claudeSessionId) === 0, {
        label: "mailbox drained after reconnect auto-flush",
      });

      // 4e. Switch to `notify` mode -> send msg #3 (`SECRET_CHAN_BODY`) -> slim digest ONLY on channel, full body in hyp_inbox!
      const modeRes = await callClaudeVerified(chanMcp2, conn.socketPath, claudeRawId, "hyp_mode", { mode: "notify" }, "m1");
      assert.equal(modeRes.isError, false, modeRes.text);
      assert.deepEqual(modeRes.json(), { deliveryMode: "notify", unread: 0 });

      const notifCountBefore = chanMcp2.notifications.length;
      const send3 = await peerMcp.callTool("hyp_send", {
        to: "dev@claude/claude-chan",
        text: "SECRET_CHAN_BODY",
      });
      assert.equal(send3.isError, false, send3.text);

      const notif3 = await waitFor(
        () =>
          chanMcp2.notifications
            .slice(notifCountBefore)
            .find((n) => n.method === "notifications/claude/channel" && object(n.params) && typeof n.params.content === "string"),
        { label: "slim notify digest on notifications/claude/channel" },
      );
      const noticeText = String((notif3.params as Record<string, unknown>).content);
      assert.match(noticeText, /hyphae notice · 1 unread/);
      assert.equal(
        noticeText.includes("SECRET_CHAN_BODY"),
        false,
        "notify mode over --claude-channel must NEVER leak full body in notification!",
      );

      // Item remains unread in SQLite mailbox (pending=1, unnotified=0) until queried via hyp_inbox
      await waitFor(
        () =>
          conn.daemon.state.pendingCount(claudeSessionId) === 1 &&
          conn.daemon.state.unnotifiedCount(claudeSessionId) === 0,
        { label: "mailbox marked notified while retaining full item" },
      );

      const inbox3Res = await callClaudeVerified(
        chanMcp2,
        conn.socketPath,
        claudeRawId,
        "hyp_inbox",
        { acknowledgeAll: true },
        "i1",
      );
      assert.equal(inbox3Res.isError, false, inbox3Res.text);
      const inbox3 = inbox3Res.json() as { deliveryMode: string; unread: number; items: Array<{ text: string }> };
      assert.equal(inbox3.deliveryMode, "notify");
      assert.equal(inbox3.unread, 0);
      assert.equal(inbox3.items.length, 1);
      assert.match(inbox3.items[0].text, /SECRET_CHAN_BODY/);
    } finally {
      await topo.cleanup();
    }
  },
);
