/**
 * Phase 3 Black-Box End-to-End Integration Suite:
 *  - Section A: GitHub polling and repository webhooks, the Alertmanager and generic
 *    webhook plugins, and localIngest / hyp emit
 *    wired end-to-end into a REAL Claude Code harness (`claude -p`) via `llm-shim`.
 *  - Section B: All 6 SaaS source plugin wire-mock protocol & fault-injection self-tests
 *    (always run on `main`) + full black-box E2E tests (including B1, B3, Notion handshake
 *    hijack, isolated Tailscale LocalAPI Funnel) auto-enabled whenever the 6 SaaS plugins exist in
 *    `./plugins` or `HYPHAE_ITEST_SAAS_PLUGINS_DIR`.
 */

import { writeNodeJson } from "../lib/util.ts";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import path from "node:path";
import test from "node:test";
import { ClaudeHarness, resolveClaudeBin } from "../lib/harnesses/claude.ts";
import { HypCli } from "../lib/hyp-cli.ts";
import { LlmShimServer, callTool, emitText } from "../lib/llm-shim/index.ts";
import {
  AgentMailMockServer,
  GitHubMockServer,
  GmailMockServer,
  GoogleCalendarMockServer,
  GoogleOAuthMockServer,
  NotionMockServer,
  SentryMockServer,
  VercelMockServer,
  WebhookCallbackServer,
  buildAlertmanagerPayload,
  buildGitHubApiPullRequestEvent,
  buildGitHubPullRequestWebhook,
  buildOversizedAlertmanagerBody,
  flipHexBit,
  getFreePort,
  sendAlertmanagerWebhook,
  sendGenericWebhook,
  sendGitHubWebhook,
  sendNotionVerificationHandshake,
  sendNotionWebhookEvent,
  sendSentryWebhook,
  sendVercelWebhook,
  signNotionWebhook,
  signSentryWebhook,
  signVercelWebhook,
  waitUntil,
} from "../lib/mocks/index.ts";
import { runInteractivePtyCommand } from "../lib/pty.ts";
import { REPO_ROOT, withSandbox } from "../lib/sandbox.ts";

const PLUGINS_SRC_DIR = path.join(REPO_ROOT, "plugins");
const SAAS_PLUGIN_NAMES = [
  "agentmail",
  "gmail",
  "google-calendar",
  "sentry",
  "vercel",
  "notion",
] as const;

function resolveSaasPluginsDir(): string | null {
  const candidates = [
    process.env.HYPHAE_ITEST_SAAS_PLUGINS_DIR?.trim() || "",
    PLUGINS_SRC_DIR,
  ].filter(Boolean);
  for (const dir of candidates) {
    const allPresent = SAAS_PLUGIN_NAMES.every((name) =>
      fs.existsSync(path.join(dir, name, "index.mjs")),
    );
    if (allPresent) return dir;
  }
  return null;
}

async function installOfficialPlugin(
  hyp: HypCli,
  name: string,
): Promise<{ nodePath: string; scriptPath: string }> {
  const res = await hyp.plugin([
    "install",
    name,
    "--from-dir",
    PLUGINS_SRC_DIR,
    "--home",
    hyp.sandbox.paths.homeDir,
  ]);
  assert.equal(res.exitCode, 0, `hyp plugin install ${name} failed: ${res.stderr}`);
  const nodePath = res.json?.data?.nodePath || process.execPath;
  const pluginRec = (res.json?.data?.plugins ?? []).find((p: any) => p.name === name);
  assert.ok(pluginRec?.scriptPath, `missing scriptPath for '${name}'`);
  return { nodePath, scriptPath: pluginRec.scriptPath };
}

function coreToolSearchRule(includeBridge = false) {
  const tools = [
    "mcp__hyphae__hyp_mesh",
    "mcp__hyphae__hyp_send",
    "mcp__hyphae__hyp_inbox",
    "mcp__hyphae__hyp_stream",
    ...(includeBridge ? ["mcp__hyphae__hyp_bridge"] : []),
  ].join(",");
  return {
    name: "load-hyphae-tools",
    once: true,
    when: (req: any) =>
      req.isToolDeferred("hyp_mesh") ||
      req.isToolDeferred("hyp_stream") ||
      (includeBridge && req.isToolDeferred("hyp_bridge")),
    do: (req: any) => callTool(req, "ToolSearch", { query: `select:${tools}` }),
  };
}

/**
 * Stream subscriptions deliver metadata-only notify nudges (`[hyphae notify ...]` or
 * `[hyphae +N more unread ...] -> hyp_inbox(...)`) on `UserPromptSubmit`. When Claude sees
 * a notify nudge on a fresh prompt turn (before calling `hyp_inbox`), pull the unread
 * stream batch via `hyp_inbox`.
 */
function pullInboxOnNotifyRule(name = "pull-stream-inbox", topic?: string) {
  return {
    name,
    when: (req: any) =>
      req.lastToolResults.length === 0 &&
      /<hyphae-inbox\b|\[hyphae (?:notify|\+\d+ more unread)/.test(req.lastUserText),
    do: (req: any) =>
      callTool(req, "hyp_inbox", {
        ...(topic ? { filter: { topic } } : {}),
        ack: true,
        limit: 20,
      }),
  };
}

function sendRawIngestLine(socketPath: string, line: string, timeoutMs = 5_000): Promise<any> {
  return new Promise((resolve, reject) => {
    const conn = net.createConnection(socketPath);
    let buf = "";
    const timer = setTimeout(() => {
      conn.destroy();
      reject(new Error(`ingest.sock timed out after ${timeoutMs}ms`));
    }, timeoutMs);
    conn.on("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });
    conn.on("connect", () => {
      conn.write(line.endsWith("\n") ? line : `${line}\n`);
    });
    conn.on("data", (chunk: Buffer) => {
      buf += chunk.toString("utf8");
      const nl = buf.indexOf("\n");
      if (nl !== -1) {
        clearTimeout(timer);
        conn.end();
        try {
          resolve(JSON.parse(buf.slice(0, nl)));
        } catch {
          resolve({ raw: buf.slice(0, nl) });
        }
      }
    });
    conn.on("end", () => {
      clearTimeout(timer);
      if (buf.trim()) {
        try {
          resolve(JSON.parse(buf.trim()));
        } catch {
          resolve({ raw: buf.trim() });
        }
      } else {
        resolve({ closedWithoutBody: true });
      }
    });
  });
}

// ===========================================================================
// SECTION A: Compiled-In Pure-Rust Sources E2E into Real Claude Code Harness
// ===========================================================================

test("Sources E2E — github-public: 200->304->429->200 ETag polling, strict multi-org repoTokens isolation, and real Claude delivery", async (t) => {
  const claudeBin = resolveClaudeBin();
  if (!claudeBin) {
    t.skip("claude binary not found (set CLAUDE_BIN)");
    return;
  }

  await withSandbox("source-github-public-e2e", async (sandbox) => {
    const hyp = new HypCli(sandbox);
    await hyp.onboard({ nodeId: "ghpub-itest@local", noSkills: true, noCommands: true });

    const acmePat = "ghp_ACME_SCOPED_PAT_NEVER_LEAK_111";
    const alicePat = "ghp_ALICE_SCOPED_PAT_NEVER_LEAK_222";
    await hyp.secretSet("gh-acme-pat", acmePat);
    await hyp.secretSet("gh-alice-pat", alicePat);

    const ghMock = await GitHubMockServer.start({ pollIntervalSeconds: 1 });
    sandbox.onTeardown(() => ghMock.close());

    const pr1Title = "GH_PUBLIC_POLL_PR1_INITIAL_401";
    const pr2Title = "GH_PUBLIC_POLL_PR2_AFTER_429_402";

    ghMock.registerRepo("acme/private-app", {
      visibility: "private",
      requiredToken: acmePat,
      initialEvents: [
        buildGitHubApiPullRequestEvent({
          id: "gh-evt-1001",
          repo: "acme/private-app",
          number: 11,
          title: pr1Title,
          author: "bob",
        }),
      ],
    });
    ghMock.registerRepo("alice/private-lib", {
      visibility: "private",
      requiredToken: alicePat,
      initialEvents: [],
    });
    ghMock.registerRepo("publicorg/open-repo", {
      visibility: "public",
      initialEvents: [],
    });
    ghMock.registerRepo("otherorg/unscoped-private", {
      visibility: "private",
      requiredToken: "ghp_OTHER_NOT_CONFIGURED",
      initialEvents: [],
    });

    writeNodeJson(hyp.nodeConfigPath, {
      v: 2,
      nodeId: "ghpub-itest@local",
      profile: "local",
      stateDir: sandbox.paths.hyphaeStateDir,
      sources: [
        {
          kind: "github-public",
          id: "github-public",
          topic: "github",
          apiBaseUrl: ghMock.apiBaseUrl,
          minPollIntervalSeconds: 1,
          basePollIntervalSeconds: 1,
          graceWindowSeconds: 0,
          allowPrivateWithToken: true,
          repoTokens: {
            "acme/*": { secret: "gh-acme-pat" },
            "alice/*": { secret: "gh-alice-pat" },
          },
        },
      ],
    });

    await hyp.startDaemon();

    // Open a secondary black-box MCP peer to subscribe to `publicorg/open-repo` and test fail-closed
    // rejection of `otherorg/unscoped-private` (no matching repoToken!).
    const watcherPeer = await hyp.openPeer("gh-watcher");
    const badSub = await watcherPeer.client.callTool("hyp_stream", {
      action: "subscribe",
      topic: "local.github",
      filters: [{ exact: { repo: "otherorg/unscoped-private" } }],
      mode: "queue",
      strict: true,
    });
    assert.ok(
      badSub.isError ||
        JSON.stringify(badSub.json ?? badSub.text).toLowerCase().includes("private") ||
        JSON.stringify(badSub.json ?? badSub.text).toLowerCase().includes("not found"),
      `Unscoped private repo subscription must fail closed / diagnose error: ${badSub.text}`,
    );

    const pubSub = await watcherPeer.client.callTool("hyp_stream", {
      action: "subscribe",
      topic: "local.github",
      filters: [{ exact: { repo: "publicorg/open-repo" } }],
      mode: "queue",
    });
    assert.equal(pubSub.isError, false, `publicorg/open-repo subscribe failed: ${pubSub.text}`);

    const shim = await LlmShimServer.start({
      sandbox,
      auditors: {
        allowBridge: false,
        allowKv: false,
        allowedRoles: ["ghpub-claude"],
      },
    });
    shim.auditors.registerUntrustedPayload("gh-pr1", pr1Title);
    shim.auditors.registerUntrustedPayload("gh-pr2", pr2Title);

    let subOk = false;
    let sawPr1 = false;
    let sawPr2 = false;

    shim.script("ghpub-claude", [
      coreToolSearchRule(false),
      {
        name: "enroll",
        once: true,
        when: (req) => !req.isToolDeferred("hyp_mesh") && req.anyMessageContains("ENROLL_GHPUB"),
        do: (req) => callTool(req, "hyp_mesh", { action: "join", handle: "ghpub-agent" }),
      },
      {
        name: "subscribe-acme",
        once: true,
        when: (req) => req.lastToolResult("hyp_mesh")?.json?.handle === "ghpub-agent",
        do: (req) =>
          callTool(req, "hyp_stream", {
            action: "subscribe",
            topic: "local.github",
            filters: [{ exact: { repo: "acme/private-app" } }],
            mode: "queue",
          }),
      },
      {
        name: "done-sub",
        once: true,
        when: (req) => {
          const r = req.lastToolResult("hyp_stream");
          if (r && !r.isError) subOk = true;
          return Boolean(r && !r.isError);
        },
        do: () => emitText("GHPUB_SUBSCRIBED"),
      },
      {
        name: "ack-pr1",
        once: true,
        when: (req) => req.anyMessageContains(pr1Title),
        do: () => {
          sawPr1 = true;
          return emitText("GOT_GH_PR1");
        },
      },
      {
        name: "ack-pr2",
        once: true,
        when: (req) => req.anyMessageContains(pr2Title),
        do: () => {
          sawPr2 = true;
          return emitText("GOT_GH_PR2");
        },
      },
      pullInboxOnNotifyRule("pull-ghpub-inbox", "local.github"),
      {
        name: "ack-waiter-prompt",
        when: (req) => req.lastUserText.includes("no background waiter is running yet"),
        do: () => emitText("STANDING_BY"),
      },
    ]);

    const claude = await ClaudeHarness.create({
      sandbox,
      hyp,
      shim,
      claudeBin,
      role: "ghpub-claude",
    });

    const sessionUuid = crypto.randomUUID();
    const res1 = await claude.runPrint("ENROLL_GHPUB", { sessionId: sessionUuid, maxTurns: 8 });
    assert.equal(res1.exitCode, 0, `enroll/sub failed: ${res1.stderr}`);
    assert.equal(subOk, true);

    // Wait for `200` initial poll AND subsequent `304 Not Modified` (proving `If-None-Match`!).
    await ghMock.waitForEventPollStatus("acme/private-app", 200, 1, 15_000);
    const poll304s = await ghMock.waitForEventPollStatus("acme/private-app", 304, 1, 15_000);
    assert.ok(poll304s[0].ifNoneMatch, "304 poll must have sent If-None-Match ETag header");

    // Resume Claude -> receives PR #1 from `200` poll!
    const res2 = await claude.runPrint("CHECK_PR1", {
      sessionId: sessionUuid,
      resume: true,
      maxTurns: 6,
    });
    assert.equal(res2.exitCode, 0);
    assert.equal(sawPr1, true, "Claude must receive initial GitHub ETag poll PR #1");

    // Inject `429 Retry-After: 1` backoff, then push PR #2 so after backoff the poller fetches `200`!
    ghMock.failNextEventsPollWith429("acme/private-app", 1);
    await ghMock.waitForEventPollStatus("acme/private-app", 429, 1, 15_000);

    ghMock.pushRepoEvent(
      "acme/private-app",
      buildGitHubApiPullRequestEvent({
        id: "gh-evt-1002",
        repo: "acme/private-app",
        number: 12,
        title: pr2Title,
        author: "carol",
      }),
    );
    await ghMock.waitForEventPollStatus("acme/private-app", 200, 2, 15_000);

    const res3 = await claude.runPrint("CHECK_PR2", {
      sessionId: sessionUuid,
      resume: true,
      maxTurns: 6,
    });
    assert.equal(res3.exitCode, 0);
    assert.equal(sawPr2, true, "Claude must receive PR #2 after 429 Retry-After backoff recovery");

    // Strict multi-org `repoTokens` isolation assertions!
    await ghMock.waitForEventPollStatus("publicorg/open-repo", 200, 1, 15_000);
    const acmeReqs = ghMock.requestsForRepo("acme/private-app");
    assert.ok(acmeReqs.length >= 3);
    for (const r of acmeReqs) {
      assert.equal(r.authorization, `Bearer ${acmePat}`, "acme/* must receive ONLY acme PAT");
    }

    const publicReqs = ghMock.requestsForRepo("publicorg/open-repo");
    assert.ok(publicReqs.length >= 1);
    for (const r of publicReqs) {
      assert.equal(
        r.authorization,
        null,
        `SECURITY VIOLATION: public repo received Authorization header (${r.authorization})`,
      );
    }

    const otherReqs = ghMock.requestsForRepo("otherorg/unscoped-private");
    for (const r of otherReqs) {
      assert.equal(
        r.authorization,
        null,
        `SECURITY VIOLATION: unscoped private repo received another org's PAT (${r.authorization})`,
      );
    }

    await watcherPeer.close();
    shim.assertAllClean();
  });
});

test("Sources E2E — github-webhook: valid HMAC -> Claude, 1-bit flip 401, non-allowlisted org ignored, raw-body SHA-256 replay dedup", async (t) => {
  const claudeBin = resolveClaudeBin();
  if (!claudeBin) {
    t.skip("claude binary not found (set CLAUDE_BIN)");
    return;
  }

  await withSandbox("source-github-webhook-e2e", async (sandbox) => {
    const hyp = new HypCli(sandbox);
    await hyp.onboard({ nodeId: "ghwh-itest@local", noSkills: true, noCommands: true });

    const whSecret = "ghwh-super-secret-hmac-key-777";
    await hyp.secretSet("gh-wh-secret", whSecret);

    const bindPort = await getFreePort();
    writeNodeJson(hyp.nodeConfigPath, {
      v: 2,
      nodeId: "ghwh-itest@local",
      profile: "p2p",
      bind: `127.0.0.1:${bindPort}`,
      stateDir: sandbox.paths.hyphaeStateDir,
      sources: [
        {
          kind: "github-webhook",
          id: "github",
          topic: "github-webhooks",
          secret: { secret: "gh-wh-secret" },
          allowedOrgs: ["acme"],
        },
      ],
    });

    await hyp.startDaemon();
    const webhookUrl = `http://127.0.0.1:${bindPort}/v1/webhooks/github`;

    const shim = await LlmShimServer.start({
      sandbox,
      auditors: {
        allowBridge: false,
        allowKv: false,
        allowedRoles: ["ghwh-claude"],
      },
    });

    const prTitle = "GH_WEBHOOK_SIGNED_PR_409";
    const evilTitle = "GH_WEBHOOK_UNALLOWED_ORG_DROP";
    shim.auditors.registerUntrustedPayload("gh-wh-1", prTitle);

    let subOk = false;
    let sawPr = false;

    shim.script("ghwh-claude", [
      coreToolSearchRule(false),
      {
        name: "enroll",
        once: true,
        when: (req) => !req.isToolDeferred("hyp_mesh") && req.anyMessageContains("ENROLL_GHWH"),
        do: (req) => callTool(req, "hyp_mesh", { action: "join", handle: "ghwh-agent" }),
      },
      {
        name: "subscribe",
        once: true,
        when: (req) => req.lastToolResult("hyp_mesh")?.json?.handle === "ghwh-agent",
        do: (req) =>
          callTool(req, "hyp_stream", {
            action: "subscribe",
            topic: "local.github-webhooks",
            mode: "queue",
          }),
      },
      {
        name: "done-sub",
        once: true,
        when: (req) => {
          const r = req.lastToolResult("hyp_stream");
          if (r && !r.isError) subOk = true;
          return Boolean(r && !r.isError);
        },
        do: () => emitText("GHWH_SUBSCRIBED"),
      },
      {
        name: "ack-pr",
        once: true,
        when: (req) => req.anyMessageContains(prTitle),
        assert: (req) => {
          assert.equal(req.rawBody.includes(evilTitle), false, "non-allowlisted org must not reach Claude");
        },
        do: () => {
          sawPr = true;
          return emitText("GHWH_DELIVERED");
        },
      },
      pullInboxOnNotifyRule("pull-ghwh-inbox", "local.github-webhooks"),
      {
        name: "ack-waiter-prompt",
        when: (req) => req.lastUserText.includes("no background waiter is running yet"),
        do: () => emitText("STANDING_BY"),
      },
    ]);

    const claude = await ClaudeHarness.create({
      sandbox,
      hyp,
      shim,
      claudeBin,
      role: "ghwh-claude",
    });

    const sessionUuid = crypto.randomUUID();
    const res1 = await claude.runPrint("ENROLL_GHWH", { sessionId: sessionUuid, maxTurns: 8 });
    assert.equal(res1.exitCode, 0);
    assert.equal(subOk, true);

    const payload = buildGitHubPullRequestWebhook({
      repo: "acme/web",
      number: 42,
      title: prTitle,
      body: "Fix race condition",
    });

    // 1. 1-bit flipped HMAC signature -> 401!
    const badSig = await sendGitHubWebhook(webhookUrl, {
      event: "pull_request",
      deliveryId: "del-bad-1",
      payload,
      secret: whSecret,
      tamperSignature: true,
    });
    assert.equal(badSig.status, 401, "1-bit flipped GitHub HMAC must return 401");

    // 2. Non-allowlisted org with valid HMAC -> ignored (zero delivery)!
    const evilResp = await sendGitHubWebhook(webhookUrl, {
      event: "pull_request",
      deliveryId: "del-evil-1",
      payload: buildGitHubPullRequestWebhook({
        repo: "mallory/evil",
        number: 666,
        title: evilTitle,
      }),
      secret: whSecret,
    });
    assert.equal(evilResp.status, 200);
    assert.equal(evilResp.json?.status, "ignored");

    // 3. Valid signed webhook -> published!
    const rawValid = JSON.stringify(payload);
    const okResp = await sendGitHubWebhook(webhookUrl, {
      event: "pull_request",
      deliveryId: "del-ok-1",
      payload: rawValid,
      secret: whSecret,
    });
    assert.ok(okResp.status === 200 || okResp.status === 202, `expected 200/202, got ${okResp.status}: ${okResp.text}`);

    // 4. Replay IDENTICAL raw body with a DIFFERENT unsigned X-GitHub-Delivery header ->
    //    must deduplicate via raw-body SHA-256 (`publishStatus: "duplicate"` + identical `eventId`)!
    const replayResp = await sendGitHubWebhook(webhookUrl, {
      event: "pull_request",
      deliveryId: "del-spoofed-replay-2",
      payload: rawValid,
      secret: whSecret,
    });
    assert.ok(replayResp.status === 200 || replayResp.status === 202);
    assert.equal(
      replayResp.json?.publishStatus ?? replayResp.json?.outcome,
      "duplicate",
      `raw-body replay with spoofed X-GitHub-Delivery must deduplicate: ${replayResp.text}`,
    );
    assert.equal(
      replayResp.json?.eventId,
      okResp.json?.eventId,
      "raw-body SHA-256 dedup must yield identical eventId even with a different X-GitHub-Delivery header",
    );

    const res2 = await claude.runPrint("CHECK_GHWH", {
      sessionId: sessionUuid,
      resume: true,
      maxTurns: 6,
    });
    assert.equal(res2.exitCode, 0);
    assert.equal(sawPr, true, "Claude must receive signed GitHub webhook PR");

    shim.assertAllClean();
  });
});

test("Sources E2E — Prometheus plugin: signed delivery, bearer or basic auth, body cap, and local wakes", async (t) => {
  const claudeBin = resolveClaudeBin();
  if (!claudeBin) {
    t.skip("claude binary not found (set CLAUDE_BIN)");
    return;
  }

  await withSandbox("source-prom-e2e", async (sandbox) => {
    const hyp = new HypCli(sandbox);
    await hyp.onboard({ nodeId: "prom-itest@local", noSkills: true, noCommands: true });

    const { nodePath, scriptPath } = await installOfficialPlugin(hyp, "prometheus");
    const promBearer = "prom-bearer-secret-111";
    const promBasicPass = "prom-basic-pass-222";
    const promHmac = "prom-hmac-secret-333";
    await hyp.secretSet("prom-bearer", promBearer);
    await hyp.secretSet("prom-basic-auth", `prom:${promBasicPass}`);
    await hyp.secretSet("prom-hmac", promHmac);

    const nodePromPort = await getFreePort();

    writeNodeJson(hyp.nodeConfigPath, {
      v: 2,
      nodeId: "prom-itest@local",
      profile: "p2p",
      bind: "127.0.0.1:0",
      stateDir: sandbox.paths.hyphaeStateDir,
      plugins: [
        {
          id: "prometheus",
          kind: "source",
          command: nodePath,
          args: [scriptPath],
          targets: ["alerts-node"],
          env: {
            PROMETHEUS_HOST: "127.0.0.1",
            PROMETHEUS_PORT: String(nodePromPort),
            PROMETHEUS_PATH: "/alerts",
            PROMETHEUS_TOPIC: "alerts-node",
            PROMETHEUS_BEARER_TOKEN: { secret: "prom-bearer" },
            PROMETHEUS_BASIC_AUTH: { secret: "prom-basic-auth" },
            PROMETHEUS_LEGACY_NATIVE: "1",
            PROMETHEUS_WEBHOOK_SECRET: { secret: "prom-hmac" },
          },
        },
      ],
    });

    await hyp.startDaemon();
    const nodeUrl = `http://127.0.0.1:${nodePromPort}/alerts`;

    await waitUntil(async () => {
      try {
        const res = await fetch(`http://127.0.0.1:${nodePromPort}/health`);
        return res.status === 200;
      } catch {
        return false;
      }
    }, "node prometheus plugin /health", 15_000);

    const nodeSubPeer = await hyp.openPeer("prom-node-sub");
    const subNodeRes = await nodeSubPeer.client.callTool("hyp_stream", {
      action: "subscribe",
      topic: "local.alerts-node",
      mode: "queue",
    });
    assert.equal(subNodeRes.isError, false, `subscribe local.alerts-node failed: ${subNodeRes.text}`);

    const nodeCoalescePeer = await hyp.openPeer("prom-node-coalesce");
    const subCoalesceRes = await nodeCoalescePeer.client.callTool("hyp_stream", {
      action: "subscribe",
      topic: "local.alerts-node",
      mode: "queue",
      coalesceSeconds: 1,
    });
    assert.equal(subCoalesceRes.isError, false, `subscribe coalesce local.alerts-node failed: ${subCoalesceRes.text}`);

    const shim = await LlmShimServer.start({
      sandbox,
      auditors: {
        allowBridge: false,
        allowKv: false,
        allowedRoles: ["prom-claude"],
      },
    });

    const alertSummary = "PROM_ALERT_HIGH_LATENCY_501";
    const resolvedSummary = "PROM_ALERT_LATENCY_RESOLVED_502";
    // Note: Prometheus CloudEvents intentionally mirror `annotations.summary` into top-level
    // `data.summary`, so register the unique `fingerprint` / `id` prefixes for the exact-once
    // substring duplicate-delivery auditor (which counts raw occurrences per turn).
    shim.auditors.registerUntrustedPayload("prom-fire", "fp-prom-diff-1:firing:");
    shim.auditors.registerUntrustedPayload("prom-res", "fp-prom-diff-2:resolved:");

    let subOk = false;
    let sawFiringAndResolved = false;
    let claudeInbox: unknown = null;

    shim.script("prom-claude", [
      coreToolSearchRule(false),
      {
        name: "enroll",
        once: true,
        when: (req) => !req.isToolDeferred("hyp_mesh") && req.anyMessageContains("ENROLL_PROM"),
        do: (req) => callTool(req, "hyp_mesh", { action: "join", handle: "prom-agent" }),
      },
      {
        name: "sub-alerts",
        once: true,
        when: (req) => req.lastToolResult("hyp_mesh")?.json?.handle === "prom-agent",
        do: (req) =>
          callTool(req, "hyp_stream", {
            action: "subscribe",
            topic: "local.alerts-node",
            mode: "queue",
          }),
      },
      {
        name: "done-sub",
        once: true,
        when: (req) => {
          const r = req.lastToolResult("hyp_stream");
          if (r && !r.isError) subOk = true;
          return Boolean(r && !r.isError);
        },
        do: () => emitText("PROM_SUBSCRIBED"),
      },
      {
        name: "ack-alerts",
        once: true,
        when: (req) =>
          req.anyMessageContains(alertSummary) && req.anyMessageContains(resolvedSummary),
        do: (req) => {
          claudeInbox = req.lastToolResult("hyp_inbox")?.json ?? req.lastToolResult("hyp_inbox")?.text;
          sawFiringAndResolved = true;
          return emitText("PROM_ALERTS_RECEIVED");
        },
      },
      pullInboxOnNotifyRule("pull-prom-inbox", "local.alerts-node"),
      {
        name: "ack-waiter-prompt",
        when: (req) => req.lastUserText.includes("no background waiter is running yet"),
        do: () => emitText("STANDING_BY"),
      },
    ]);

    const claude = await ClaudeHarness.create({
      sandbox,
      hyp,
      shim,
      claudeBin,
      role: "prom-claude",
    });

    const sessionUuid = crypto.randomUUID();
    const r1 = await claude.runPrint("ENROLL_PROM", { sessionId: sessionUuid, maxTurns: 8 });
    assert.equal(r1.exitCode, 0);
    assert.equal(subOk, true);

    const alertPayload = buildAlertmanagerPayload([
      {
        status: "firing",
        alertname: "HighP99Latency",
        severity: "critical",
        service: "checkout-api",
        summary: alertSummary,
        fingerprint: "fp-prom-diff-1",
      },
      {
        status: "resolved",
        alertname: "HighP99Latency",
        severity: "critical",
        service: "checkout-api",
        summary: resolvedSummary,
        fingerprint: "fp-prom-diff-2",
      },
    ]);

    // Reject invalid signatures and oversized bodies.
    {
      const label = "Prometheus plugin";
      const targetUrl = nodeUrl;
      const wrongBearer = await sendAlertmanagerWebhook(targetUrl, {
        payload: alertPayload,
        bearerToken: "wrong-token",
        hmacSecret: promHmac,
      });
      assert.equal(wrongBearer.status, 401, `${label}: wrong Bearer must return 401`);

      const wrongHmac = await sendAlertmanagerWebhook(targetUrl, {
        payload: alertPayload,
        bearerToken: promBearer,
        hmacSecret: promHmac,
        tamperSignature: true,
      });
      assert.equal(wrongHmac.status, 401, `${label}: 1-bit flipped HMAC must return 401`);

      const oversized = await sendAlertmanagerWebhook(targetUrl, {
        rawOverride: buildOversizedAlertmanagerBody(1_100_000),
        bearerToken: promBearer,
        hmacSecret: promHmac,
      });
      assert.equal(oversized.status, 413, `${label}: >1 MiB body must return 413`);
    }

    // Also test wrong Basic auth also fails.
    const wrongBasic = await sendAlertmanagerWebhook(nodeUrl, {
      payload: alertPayload,
      basicAuth: { user: "prom", pass: "wrong-pass" },
      hmacSecret: promHmac,
    });
    assert.equal(wrongBasic.status, 401, "Prometheus plugin wrong Basic auth must return 401");

    // Both configured authorization schemes accept the same signed alert batch.
    const basicOk = await sendAlertmanagerWebhook(nodeUrl, {
      payload: alertPayload,
      basicAuth: { user: "prom", pass: promBasicPass },
      hmacSecret: promHmac,
    });
    assert.equal(basicOk.status, 200, basicOk.text);

    const nodeOk = await sendAlertmanagerWebhook(nodeUrl, {
      payload: alertPayload,
      bearerToken: promBearer,
      hmacSecret: promHmac,
    });
    assert.equal(nodeOk.status, 200, `node prom failed: ${nodeOk.status} ${nodeOk.text}`);
    assert.equal(nodeOk.json?.alerts, 2, "node prometheus plugin must ack both alerts");

    // 3. Verify real Claude receives firing + resolved alerts from the plugin.
    const r2 = await claude.runPrint("CHECK_PROM_ALERTS", {
      sessionId: sessionUuid,
      resume: true,
      maxTurns: 6,
    });
    assert.equal(r2.exitCode, 0);
    assert.equal(sawFiringAndResolved, true, "Claude must receive both firing and resolved Alertmanager alerts");

    // Immediate and coalesced subscribers both receive complete externally sourced events.
    for (const peer of [nodeSubPeer, nodeCoalescePeer]) {
      const inbox = await waitUntil(async () => {
        const box = await peer.inbox({ ack: false });
        const text = JSON.stringify(box);
        return text.includes(alertSummary) && text.includes(resolvedSummary) ? text : false;
      }, "Prometheus plugin local delivery", 5_000, 150);
      assert.ok(inbox.includes("HighP99Latency"));
      assert.ok(inbox.includes("io.prometheus.alert.firing"));
      assert.ok(inbox.includes("external-webhook"));
    }
    assert.ok(JSON.stringify(claudeInbox).includes("HighP99Latency"));

    await nodeCoalescePeer.close();
    await nodeSubPeer.close();
    shim.assertAllClean();
  });
});

test("Sources E2E — webhook plugin: signed source events, expiry and body caps, and outbound bridge callbacks", async (t) => {
  const claudeBin = resolveClaudeBin();
  if (!claudeBin) {
    t.skip("claude binary not found (set CLAUDE_BIN)");
    return;
  }

  await withSandbox("source-webhook-e2e", async (sandbox) => {
    const hyp = new HypCli(sandbox);
    await hyp.onboard({ nodeId: "whdiff-itest@local", noSkills: true, noCommands: true });

    const { nodePath, scriptPath } = await installOfficialPlugin(hyp, "webhook");
    const whSecret = "wh-diff-hmac-secret-444";
    await hyp.secretSet("wh-diff-secret", whSecret);

    const callbackServer = await WebhookCallbackServer.start({ secret: whSecret });
    sandbox.onTeardown(() => callbackServer.close());

    const sourcePort = await getFreePort();
    const nodeWhPort = await getFreePort();

    writeNodeJson(hyp.nodeConfigPath, {
      v: 2,
      nodeId: "whdiff-itest@local",
      profile: "p2p",
      bind: "127.0.0.1:0",
      stateDir: sandbox.paths.hyphaeStateDir,
      plugins: [
        {
          id: "webhook-source",
          kind: "source",
          command: nodePath,
          args: [scriptPath],
          targets: ["wh-source"],
          env: {
            WEBHOOK_PORT: String(sourcePort),
            WEBHOOK_PATH: "/webhook-source",
            WEBHOOK_TARGET: "wh-source",
            WEBHOOK_SECRET: { secret: "wh-diff-secret" },
            WEBHOOK_LEGACY_NATIVE: "1",
          },
        },
        {
          id: "webhook",
          kind: "bridge",
          command: nodePath,
          args: [scriptPath],
          targets: ["ops"],
          env: {
            WEBHOOK_HOST: "127.0.0.1",
            WEBHOOK_PORT: String(nodeWhPort),
            WEBHOOK_PATH: "/webhook",
            WEBHOOK_TARGET: "ops",
            WEBHOOK_SECRET: { secret: "wh-diff-secret" },
            WEBHOOK_POST_URL: callbackServer.url,
          },
        },
      ],
    });

    await hyp.startDaemon();
    const sourceUrl = `http://127.0.0.1:${sourcePort}/webhook-source`;
    const nodeUrl = `http://127.0.0.1:${nodeWhPort}/webhook`;

    // The HTTP listeners can respond before the daemon registers the bridge poster.
    // Claude needs the capability advertised by the daemon when it discovers its MCP tools.
    await waitUntil(async () => {
      const ready = await Promise.all([fetch(nodeUrl), fetch(sourceUrl)]);
      if (!ready.every((response) => response.status === 404)) return false;
      const caps = await hyp.daemonRpc({ type: "mcp.caps", id: 1 }, 1_000);
      return caps?.result?.hasPlugins === true;
    }, "webhook listeners and daemon bridge capability", 15_000);

    const shim = await LlmShimServer.start({
      sandbox,
      auditors: {
        allowBridge: true,
        allowKv: false,
        allowedRoles: ["whdiff-claude"],
      },
    });

    const sourceMarker = "WH_SOURCE_PAYLOAD_601";
    const nodeMarker = "WH_NODE_PAYLOAD_602";
    shim.auditors.registerUntrustedPayload("wh-source-ev", sourceMarker);
    shim.auditors.registerUntrustedPayload("wh-node-ev", nodeMarker);

    let subOk = false;
    let linkOk = false;
    let repliedOk = false;

    shim.script("whdiff-claude", [
      coreToolSearchRule(true),
      {
        name: "enroll",
        once: true,
        when: (req) => !req.isToolDeferred("hyp_mesh") && req.anyMessageContains("ENROLL_WHDIFF"),
        do: (req) => callTool(req, "hyp_mesh", { action: "join", handle: "whdiff-agent" }),
      },
      {
        name: "sub-source",
        once: true,
        when: (req) => req.lastToolResult("hyp_mesh")?.json?.handle === "whdiff-agent",
        do: (req) =>
          callTool(req, "hyp_stream", {
            action: "subscribe",
            topic: "local.wh-source",
            mode: "queue",
          }),
      },
      {
        name: "link-node-bridge",
        once: true,
        when: (req) => {
          const r = req.lastToolResult("hyp_stream");
          if (r && !r.isError) subOk = true;
          return Boolean(r && !r.isError);
        },
        do: (req) =>
          callTool(req, "hyp_bridge", { action: "link", plugin: "webhook", target: "ops" }),
      },
      {
        name: "done-setup",
        once: true,
        when: (req) => {
          const r = req.lastToolResult("hyp_bridge");
          if (r && !r.isError) linkOk = true;
          return Boolean(r && !r.isError);
        },
        do: () => emitText("WHDIFF_READY"),
      },
      {
        name: "reply-via-webhook-bridge",
        once: true,
        when: (req) => req.anyMessageContains(sourceMarker) && req.anyMessageContains(nodeMarker),
        do: (req) =>
          callTool(req, "hyp_send", {
            to: "webhook:ops",
            text: `WH_CALLBACK_ACK:${sourceMarker}+${nodeMarker}`,
          }),
      },
      pullInboxOnNotifyRule("pull-wh-both-inbox"),
      {
        name: "done-reply",
        once: true,
        when: (req) => {
          const r = req.lastToolResult("hyp_send");
          if (r && !r.isError) repliedOk = true;
          return Boolean(r && !r.isError);
        },
        do: () => emitText("WHDIFF_DONE"),
      },
      {
        name: "ack-waiter-prompt",
        when: (req) => req.lastUserText.includes("no background waiter is running yet"),
        do: () => emitText("STANDING_BY"),
      },
    ]);

    const claude = await ClaudeHarness.create({
      sandbox,
      hyp,
      shim,
      claudeBin,
      role: "whdiff-claude",
    });

    const sessionUuid = crypto.randomUUID();
    const r1 = await claude.runPrint("ENROLL_WHDIFF", { sessionId: sessionUuid, maxTurns: 10 });
    assert.equal(r1.exitCode, 0, `setup failed: ${r1.stderr}`);
    assert.equal(subOk, true);
    assert.equal(linkOk, true);

    // 1. Security guards on both plugin receiver modes:
    for (const [label, targetUrl] of [
      ["source webhook plugin", sourceUrl],
      ["bridge webhook plugin", nodeUrl],
    ] as const) {
      const badHmac = await sendGenericWebhook(targetUrl, {
        payload: { text: "bad-sig" },
        secret: whSecret,
        timestamp: "now",
        tamperSignature: true,
      });
      assert.equal(badHmac.status, 401, `${label}: 1-bit flipped HMAC must return 401`);

      const expiredTs = await sendGenericWebhook(targetUrl, {
        payload: { text: "old-ts" },
        secret: whSecret,
        timestamp: "expired",
      });
      assert.equal(expiredTs.status, 401, `${label}: expired (>5m) X-Webhook-Timestamp must return 401`);

      const tooBig = await sendGenericWebhook(targetUrl, {
        rawOverride: JSON.stringify({ text: "Z".repeat(70_000) }),
        secret: whSecret,
        timestamp: "now",
      });
      assert.equal(tooBig.status, 413, `${label}: >64 KiB body must return 413`);
    }

    // 2. Send valid signed webhooks with fresh timestamp to BOTH!
    const sourceOk = await sendGenericWebhook(sourceUrl, {
      payload: {
        specversion: "1.0",
        id: "discard-sender-id",
        type: "ci.deploy",
        source: "ci/source",
        subject: "service/ci",
        time: "2026-11-24T14:00:00Z",
        data: { text: sourceMarker },
      },
      secret: whSecret,
      timestamp: "now",
    });
    assert.equal(sourceOk.status, 202, sourceOk.text);
    assert.match(sourceOk.json?.id, /^wh-[a-f0-9]{64}$/);
    assert.notEqual(sourceOk.json?.id, "discard-sender-id");

    const nodeOk = await sendGenericWebhook(nodeUrl, {
      payload: { type: "ci.deploy", source: "ci/node", text: nodeMarker },
      secret: whSecret,
      timestamp: "now",
    });
    assert.equal(nodeOk.status, 202, `node webhook failed: ${nodeOk.status} ${nodeOk.text}`);

    // 3. Resume Claude -> verifies BOTH arrived and replies via `hyp_send(to: "webhook:ops")`!
    const r2 = await claude.runPrint("CHECK_BOTH_WEBHOOKS", {
      sessionId: sessionUuid,
      resume: true,
      maxTurns: 8,
    });
    assert.equal(r2.exitCode, 0, `reply turn failed: ${r2.stderr}`);
    assert.equal(repliedOk, true);

    // 4. Verify outbound callback reached `WEBHOOK_POST_URL` with valid HMAC-SHA256!
    const cb = await callbackServer.waitForCallback(
      (c) => c.json?.text === `WH_CALLBACK_ACK:${sourceMarker}+${nodeMarker}`,
      10_000,
    );
    assert.equal(cb.signatureValid, true, "outbound webhook callback MUST carry valid X-Webhook-Signature-256");
    assert.equal(cb.json?.target, "ops");

    shim.assertAllClean();
  });
});

test("Sources E2E — localIngest (ingest.sock / hyp emit): real Claude wake, >64 KiB line rejected, requireSignature:true fail-closed + signed Ed25519 hyphaesig", async (t) => {
  const claudeBin = resolveClaudeBin();
  if (!claudeBin) {
    t.skip("claude binary not found (set CLAUDE_BIN)");
    return;
  }

  await withSandbox("source-local-ingest-e2e", async (sandbox) => {
    const hyp = new HypCli(sandbox);
    await hyp.onboard({ nodeId: "ingest-itest@local", noSkills: true, noCommands: true });

    // Initialize local human Ed25519 admin authority (initial non-TTY `hyp auth init` succeeds).
    const authInit = await hyp.exec([
      "auth",
      "init",
      "--human-id",
      "alice",
      "--label",
      "itest-admin",
      "--state-dir",
      sandbox.paths.hyphaeStateDir,
      "--config",
      hyp.nodeConfigPath,
      "--json",
    ]);
    assert.equal(authInit.exitCode, 0, `hyp auth init failed: ${authInit.stderr}`);

    writeNodeJson(hyp.nodeConfigPath, {
      v: 2,
      nodeId: "ingest-itest@local",
      profile: "local",
      stateDir: sandbox.paths.hyphaeStateDir,
      localIngest: {
        enabled: true,
        defaultTopic: "schedule",
        routes: [
          {
            id: "default-schedule",
            allowedTypes: ["to.hyphae.scheduled.v1", "to.hyphae.local.v1"],
            allowedTopics: ["schedule"],
            requireSignature: false,
          },
          {
            id: "signed-only",
            allowedTypes: ["*"],
            allowedTopics: ["secure"],
            requireSignature: true,
          },
        ],
      },
    });

    await hyp.startDaemon();
    const ingestSock = path.join(sandbox.paths.hyphaeStateDir, "ingest.sock");
    await waitUntil(() => fs.existsSync(ingestSock), "ingest.sock created", 5_000, 50);
    assert.equal(fs.statSync(ingestSock).mode & 0o777, 0o600, "ingest.sock must be 0600");

    const shim = await LlmShimServer.start({
      sandbox,
      auditors: {
        allowBridge: false,
        allowKv: false,
        allowedRoles: ["ingest-claude"],
      },
    });

    const schedMarker = "LOCAL_INGEST_SCHEDULE_701";
    const signedMarker = "LOCAL_INGEST_HUMAN_SIGNED_702";
    shim.auditors.registerUntrustedPayload("ingest-sched", schedMarker);
    shim.auditors.registerUntrustedPayload("ingest-signed", signedMarker);

    let subsDone = false;
    let sawBoth = false;

    shim.script("ingest-claude", [
      coreToolSearchRule(false),
      {
        name: "enroll",
        once: true,
        when: (req) => !req.isToolDeferred("hyp_mesh") && req.anyMessageContains("ENROLL_INGEST"),
        do: (req) => callTool(req, "hyp_mesh", { action: "join", handle: "ingest-agent" }),
      },
      {
        name: "sub-schedule",
        once: true,
        when: (req) => req.lastToolResult("hyp_mesh")?.json?.handle === "ingest-agent",
        do: (req) =>
          callTool(req, "hyp_stream", {
            action: "subscribe",
            topic: "local.schedule",
            mode: "queue",
          }),
      },
      {
        name: "sub-secure",
        once: true,
        when: (req) => {
          const r = req.lastToolResult("hyp_stream");
          return Boolean(r && !r.isError && !subsDone);
        },
        do: (req) => {
          subsDone = true;
          return callTool(req, "hyp_stream", {
            action: "subscribe",
            topic: "local.secure",
            mode: "queue",
          });
        },
      },
      {
        name: "done-subs",
        once: true,
        when: (req) => subsDone && Boolean(req.lastToolResult("hyp_stream") && !req.lastToolResult("hyp_stream")?.isError),
        do: () => emitText("INGEST_SUBSCRIBED"),
      },
      {
        name: "ack-ingested",
        once: true,
        when: (req) => req.anyMessageContains(schedMarker) && req.anyMessageContains(signedMarker),
        do: () => {
          sawBoth = true;
          return emitText("INGEST_EVENTS_SEEN");
        },
      },
      pullInboxOnNotifyRule("pull-ingest-inbox"),
      {
        name: "ack-waiter-prompt",
        when: (req) => req.lastUserText.includes("no background waiter is running yet"),
        do: () => emitText("STANDING_BY"),
      },
    ]);

    const claude = await ClaudeHarness.create({
      sandbox,
      hyp,
      shim,
      claudeBin,
      role: "ingest-claude",
    });

    const sessionUuid = crypto.randomUUID();
    const r1 = await claude.runPrint("ENROLL_INGEST", { sessionId: sessionUuid, maxTurns: 10 });
    assert.equal(r1.exitCode, 0);
    assert.equal(subsDone, true);

    // 1. Unsigned `hyp emit` onto `local.schedule` succeeds!
    const emitOk = await hyp.emit(["--label", "nightly", "--note", schedMarker]);
    assert.equal(emitOk.exitCode, 0);
    assert.equal(emitOk.json?.ok, true);
    assert.equal(emitOk.json?.data?.topic, "local.schedule");

    // 2. Oversized >64 KiB NDJSON line sent directly over `ingest.sock` -> rejected fail-closed!
    const hugeLine = JSON.stringify({ topic: "schedule", note: "B".repeat(70_000) });
    const hugeReceipt = await sendRawIngestLine(ingestSock, hugeLine);
    assert.notEqual(hugeReceipt?.ok, true, `>64 KiB ingest line must fail closed: ${JSON.stringify(hugeReceipt)}`);

    // 3. `requireSignature: true` route (`secure`): unsigned emit fails closed!
    const unsignedSecure = await hyp.emit(["--topic", "secure", "--note", "UNSIGNED_MUST_FAIL"], {
      allowFailure: true,
    });
    assert.notEqual(unsignedSecure.exitCode, 0, "unsigned emit on requireSignature:true must fail closed");
    assert.match(unsignedSecure.stdout + unsignedSecure.stderr, /signature_required|SIGNATURE_REQUIRED/i);

    // 4. Tampered `hyphaesig` directly over `ingest.sock` -> fails closed (`invalid_signature`)!
    const tamperedReceipt = await sendRawIngestLine(
      ingestSock,
      JSON.stringify({
        specversion: "1.0",
        id: "tampered-1",
        source: "local-cli",
        type: "to.hyphae.local.v1",
        time: new Date().toISOString(),
        topic: "secure",
        hyphaesig: "v1.badkid.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        data: { note: "TAMPERED" },
      }),
    );
    assert.equal(tamperedReceipt?.ok, false);
    assert.equal(tamperedReceipt?.error, "invalid_signature");

    // 5. Real signed `hyp emit --sign` inside a real POSIX PTY (confirming `[y/N]`) upgrades to `HumanVerified`!
    const ptyEmit = await runInteractivePtyCommand(
      sandbox,
      "hyp-emit-sign",
      hyp.bin,
      [
        "emit",
        "--sign",
        "--topic",
        "secure",
        "--label",
        "ops-verified",
        "--note",
        signedMarker,
        "--state-dir",
        sandbox.paths.hyphaeStateDir,
        "--config",
        hyp.nodeConfigPath,
        "--json",
      ],
      {
        env: sandbox.env,
        promptPattern: /\[y\/N\]|HumanVerified/i,
        inputOnMatch: "y\n",
        timeoutMs: 15_000,
      },
    );
    assert.equal(ptyEmit.exitCode, 0, `hyp emit --sign PTY failed: ${ptyEmit.output}`);
    assert.match(ptyEmit.output, /human-verified/);

    // 6. Resume real Claude -> receives BOTH the scheduled event and the HumanVerified signed event!
    const r2 = await claude.runPrint("CHECK_INGEST_EVENTS", {
      sessionId: sessionUuid,
      resume: true,
      maxTurns: 6,
    });
    assert.equal(r2.exitCode, 0);
    assert.equal(sawBoth, true, "Claude must receive both unsigned schedule and HumanVerified signed events");

    shim.assertAllClean();
  });
});

// ===========================================================================
// SECTION B: All 6 SaaS Source Plugin Wire-Mock Self-Tests (Always Run on main)
// ===========================================================================

test("SaaS Wire-Mocks — AgentMail: inclusive after cursor + B3 live WS event interleaved mid-REST catch-up", async () => {
  const apiKey = "am_wire_test_key";
  const mock = await AgentMailMockServer.start({
    apiKey,
    inboxes: ["billing@agentmail.to"],
    pageSize: 2,
    inclusiveAfterCursor: true,
  });
  try {
    const mkMsg = (id: string, timestamp: string) => ({
      inbox_id: "billing@agentmail.to",
      thread_id: "thr_1",
      message_id: `<${id}@mail>`,
      from: "ops@example.com",
      to: ["billing@agentmail.to"],
      subject: `Msg ${id}`,
      preview: `Preview ${id}`,
      labels: ["received"],
      timestamp,
    });

    const t0 = "2026-11-24T15:00:00.000Z";
    const t1 = "2026-11-24T15:05:00.000Z";
    const t2 = "2026-11-24T15:10:00.000Z";
    mock.addStoredMessage(mkMsg("m0", t0));
    mock.addStoredMessage(mkMsg("m1", t1));
    mock.armInterleaveOnNextRestCatchup(mkMsg("m2", t2), 40);

    // Connect WS client, subscribe, and verify live m2 fires DURING REST catch-up!
    const receivedWsFrames: any[] = [];
    const ws = new WebSocket(`${mock.wsUrl}?api_key=${apiKey}`);
    await new Promise<void>((resolve, reject) => {
      ws.addEventListener("open", () => {
        ws.send(JSON.stringify({ type: "subscribe", event_types: ["message.received"] }));
      });
      ws.addEventListener("message", (ev) => {
        const frame = JSON.parse(String(ev.data));
        receivedWsFrames.push(frame);
        if (frame.type === "subscribed") resolve();
      });
      ws.addEventListener("error", () => reject(new Error("WS failed")));
    });

    // Hit REST catch-up with `after=t0` -> must return inclusive `m0` AND `m1` on page 1,
    // AND push live WS `m2` BEFORE the REST response resolves!
    const p1 = await fetch(
      `${mock.apiBase}/v0/inboxes/${encodeURIComponent("billing@agentmail.to")}/messages?after=${encodeURIComponent(t0)}&ascending=true&labels=received`,
      { headers: { authorization: `Bearer ${apiKey}` } },
    );
    assert.equal(p1.status, 200);
    const p1Json: any = await p1.json();
    assert.deepEqual(
      p1Json.messages.map((m: any) => m.message_id),
      ["<m0@mail>", "<m1@mail>"],
      "inclusive after cursor MUST include m0 at exact cursor instant",
    );
    assert.ok(p1Json.next_page_token, "must paginate remaining m2 onto page 2");

    // Verify B3 interleaved live WS frame arrived during REST catch-up!
    const liveM2 = await waitUntil(
      () => receivedWsFrames.find((f) => f.type === "event" && f.message?.message_id === "<m2@mail>") ?? false,
      "B3 interleaved live WS frame m2",
      3_000,
    );
    assert.equal(liveM2.event_type, "message.received");

    // Fetch page 2 -> returns m2 as well.
    const p2 = await fetch(
      `${mock.apiBase}/v0/inboxes/${encodeURIComponent("billing@agentmail.to")}/messages?after=${encodeURIComponent(t0)}&ascending=true&labels=received&page_token=${p1Json.next_page_token}`,
      { headers: { authorization: `Bearer ${apiKey}` } },
    );
    const p2Json: any = await p2.json();
    assert.deepEqual(
      p2Json.messages.map((m: any) => m.message_id),
      ["<m2@mail>"],
    );

    ws.close();
  } finally {
    await mock.close();
  }
});

test("SaaS Wire-Mocks — Google OAuth PKCE + Gmail (format=metadata only, 404/429) + Calendar (.created/.starting, 410 Gone, pagination)", async () => {
  const oauth = await GoogleOAuthMockServer.start({
    clientId: "cid-1.apps.googleusercontent.com",
    validRefreshToken: "rt-valid",
    issuedAccessToken: "at-valid",
  });
  const gmail = await GmailMockServer.start({
    accessToken: "at-valid",
    initialHistoryId: "100",
    strictMetadataOnly: true,
  });
  const gcal = await GoogleCalendarMockServer.start({
    accessToken: "at-valid",
    pageSize: 1,
  });
  try {
    // 1. RFC 7636 PKCE S256 verification.
    const verifier = "pkce-verifier-secret-value-1234567890";
    const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
    oauth.registerAuthCode("code-ok", challenge);

    const badPkce = await fetch(oauth.tokenUrl, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code: "code-ok",
        client_id: "cid-1.apps.googleusercontent.com",
        code_verifier: "wrong-verifier",
      }),
    });
    assert.equal(badPkce.status, 400);

    const goodPkce = await fetch(oauth.tokenUrl, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code: "code-ok",
        client_id: "cid-1.apps.googleusercontent.com",
        code_verifier: verifier,
      }),
    });
    assert.equal(goodPkce.status, 200);
    assert.equal(((await goodPkce.json()) as any).refresh_token, "rt-valid");

    // 2. Gmail metadata-only enforcement + 404 expired historyId + 429 Retry-After.
    gmail.addMessage({
      id: "m1",
      threadId: "t1",
      labelIds: ["INBOX", "UNREAD"],
      from: "grace@example.com",
      to: "ada@example.com",
      subject: "Hello",
      snippet: "Short snippet",
      historyId: "120",
    });
    const fullBlocked = await fetch(`${gmail.apiBase}/gmail/v1/users/me/messages/m1?format=full`, {
      headers: { authorization: "Bearer at-valid" },
    });
    assert.equal(fullBlocked.status, 400, "format=full must be rejected by strictMetadataOnly mock");
    assert.equal(gmail.nonMetadataRequests.length, 1);

    const metaOk = await fetch(`${gmail.apiBase}/gmail/v1/users/me/messages/m1?format=metadata`, {
      headers: { authorization: "Bearer at-valid" },
    });
    assert.equal(metaOk.status, 200);

    gmail.expireNextHistoryFetch();
    const expired = await fetch(`${gmail.apiBase}/gmail/v1/users/me/history?startHistoryId=5`, {
      headers: { authorization: "Bearer at-valid" },
    });
    assert.equal(expired.status, 404);

    // 3. Calendar 410 Gone + nextPageToken pagination.
    const now = new Date().toISOString();
    gcal.setChangeEvents("primary", [
      { id: "e1", status: "confirmed", summary: "Sync 1", created: now, updated: now },
      { id: "e2", status: "cancelled", summary: "Sync 2", updated: now },
    ]);
    gcal.expireNextUpdatedMin();
    const gone = await fetch(
      `${gcal.apiBase}/calendar/v3/calendars/primary/events?updatedMin=${encodeURIComponent(now)}`,
      { headers: { authorization: "Bearer at-valid" } },
    );
    assert.equal(gone.status, 410);

    const p1 = await fetch(
      `${gcal.apiBase}/calendar/v3/calendars/primary/events?updatedMin=${encodeURIComponent(now)}`,
      { headers: { authorization: "Bearer at-valid" } },
    );
    const p1Json: any = await p1.json();
    assert.equal(p1Json.items.length, 1);
    assert.ok(p1Json.nextPageToken);
  } finally {
    await Promise.all([oauth.close(), gmail.close(), gcal.close()]);
  }
});

test("SaaS Wire-Mocks — Sentry (HMAC-SHA256), Vercel (state machine + HMAC-SHA1), Notion (search + handshake + HMAC-SHA256)", async () => {
  const sentry = await SentryMockServer.start({ authToken: "sntrys_1", org: "acme" });
  const vercel = await VercelMockServer.start({ token: "vrc_1" });
  const notion = await NotionMockServer.start({ token: "ntn_1", expectedVersion: "2022-06-28" });
  try {
    sentry.addIssue({
      id: "99",
      shortId: "API-99",
      title: "NullPointer",
      firstSeen: new Date().toISOString(),
      project: { slug: "api" },
    });
    const sRes = await fetch(`${sentry.apiBase}/api/0/organizations/acme/issues/?project=api`, {
      headers: { authorization: "Bearer sntrys_1" },
    });
    assert.equal(sRes.status, 200);
    assert.equal(((await sRes.json()) as any[]).length, 1);
    const sSig = signSentryWebhook('{"a":1}', "sec");
    assert.equal(sSig.length, 64);
    assert.notEqual(flipHexBit(sSig), sSig);

    vercel.upsertDeployment({
      uid: "dpl_1",
      name: "web",
      projectId: "prj_1",
      created: Date.now(),
      readyState: "BUILDING",
      target: "production",
      url: "web.vercel.app",
    });
    vercel.transitionDeployment("dpl_1", "READY");
    const vRes = await fetch(`${vercel.apiBase}/v7/deployments`, {
      headers: { authorization: "Bearer vrc_1" },
    });
    const vJson: any = await vRes.json();
    assert.equal(vJson.deployments[0].readyState, "READY");
    const vSig = signVercelWebhook('{"a":1}', "sec");
    assert.equal(vSig.length, 40, "Vercel x-vercel-signature must be 40-char HMAC-SHA1 hex");

    notion.upsertPage({
      id: "pg-1",
      title: "Launch",
      created_time: new Date().toISOString(),
      last_edited_time: new Date().toISOString(),
    });
    const nRes = await fetch(`${notion.apiBase}/v1/search`, {
      method: "POST",
      headers: {
        authorization: "Bearer ntn_1",
        "notion-version": "2022-06-28",
        "content-type": "application/json",
      },
      body: JSON.stringify({ page_size: 10 }),
    });
    assert.equal(nRes.status, 200);
    assert.equal(((await nRes.json()) as any).results[0].id, "pg-1");
    assert.match(signNotionWebhook('{"a":1}', "tok"), /^sha256=[0-9a-f]{64}$/);
  } finally {
    await Promise.all([sentry.close(), vercel.close(), notion.close()]);
  }
});

// ===========================================================================
// SECTION C: Full Black-Box E2E for the 6 SaaS Source Plugins (Auto-Detected)
// ===========================================================================

test("SaaS Sources Full Black-Box E2E (B1, B3 AgentMail WS+REST race, Notion handshake hijack, Sentry Funnel, Vercel HMAC-SHA1, Gmail/Calendar) -> Real hyp daemon + Real Claude", async (t) => {
  const saasDir = resolveSaasPluginsDir();
  if (!saasDir) {
    t.skip(
      "6 SaaS source plugins (agentmail, gmail, google-calendar, sentry, vercel, notion) not yet merged into ./plugins — set HYPHAE_ITEST_SAAS_PLUGINS_DIR=/path/to/plugins to run full black-box E2E",
    );
    return;
  }
  const claudeBin = resolveClaudeBin();
  if (!claudeBin) {
    t.skip("claude binary not found (set CLAUDE_BIN)");
    return;
  }

  await withSandbox("saas-6-plugins-full-e2e", async (sandbox) => {
    const hyp = new HypCli(sandbox);
    await hyp.onboard({ nodeId: "saas-itest@local", noSkills: true, noCommands: true });

    // Secrets stored strictly via `hyp secret set` (stdin, file backend) and registered in leak scanner!
    const amKey = "am_saas_e2e_secret_111";
    const sentrySecret = "sentry_saas_e2e_secret_222";
    const vercelSecret = "vercel_saas_e2e_secret_333";
    const googleRefresh = "google_saas_e2e_refresh_444";
    await hyp.secretSet("agentmail-api-key", amKey);
    await hyp.secretSet("sentry-client-secret", sentrySecret);
    await hyp.secretSet("vercel-webhook-secret", vercelSecret);
    await hyp.secretSet("google-refresh-token", googleRefresh);

    // 1. Start coupled AgentMail WS+REST mock with B3 inclusive cursor + interleaved live WS!
    const amMock = await AgentMailMockServer.start({
      apiKey: amKey,
      inboxes: ["ops@agentmail.to"],
      pageSize: 2,
      inclusiveAfterCursor: true,
    });
    sandbox.onTeardown(() => amMock.close());

    const t0 = "2026-11-24T15:00:00.000Z";
    const t1 = "2026-11-24T15:05:00.000Z";
    const t2 = "2026-11-24T15:10:00.000Z";
    const amStateFile = path.join(sandbox.paths.hyphaeStateDir, "agentmail-state.json");
    fs.writeFileSync(
      amStateFile,
      JSON.stringify({
        cursors: { "ops@agentmail.to": t0 },
        atCursor: { "ops@agentmail.to": ["<m0@mail>"] },
      }),
      { mode: 0o600 },
    );
    const mkAm = (id: string, ts: string, subject: string) => ({
      inbox_id: "ops@agentmail.to",
      thread_id: "thr_b3",
      message_id: `<${id}@mail>`,
      from: "sender@example.com",
      to: ["ops@agentmail.to"],
      subject,
      preview: `Preview for ${subject}`,
      labels: ["received"],
      timestamp: ts,
    });
    amMock.addStoredMessage(mkAm("m0", t0, "AM_ALREADY_SEEN_AT_CURSOR"));
    amMock.addStoredMessage(mkAm("m1", t1, "AM_B3_CAUGHT_UP_M1"));
    amMock.armInterleaveOnNextRestCatchup(mkAm("m2", t2, "AM_B3_INTERLEAVED_M2"), 80);

    // 2. Isolated tailscaled LocalAPI. Exercise the real hyp binary and its conditional
    //    Serve write without touching the host’s tunnel.
    const tailscaleSocket = path.join(sandbox.paths.tmpDir, "ts.sock");
    const privateServe = {
      TCP: { "443": { HTTPS: true } },
      Web: { "itest-hub.tail9999.ts.net:443": { Handlers: { "/": { Proxy: "http://127.0.0.1:8790" } } } },
    };
    let tsConfig: unknown = privateServe;
    const tsWrites: Array<{ version: string | undefined; config: unknown }> = [];
    const tsServer = http.createServer(async (req, res) => {
      const respond = (status: number, body: unknown, headers: Record<string, string> = {}) =>
        res.writeHead(status, { "content-type": "application/json", ...headers }).end(JSON.stringify(body));
      if (req.method === "GET" && req.url === "/localapi/v0/status?peers=false") {
        return respond(200, {
          BackendState: "Running",
          Self: {
            DNSName: "itest-hub.tail9999.ts.net.",
            CapMap: { https: [], funnel: [], "https://tailscale.com/cap/funnel-ports?ports=443,8443,10000": [] },
          },
        });
      }
      if (req.url === "/localapi/v0/serve-config") {
        const etag = `itest-${tsWrites.length}`;
        if (req.method === "GET") return respond(200, tsConfig, { etag });
        if (req.method === "POST") {
          const version = typeof req.headers["if-match"] === "string" ? req.headers["if-match"] : undefined;
          if (version !== etag) return respond(412, { error: "stale" });
          const chunks: Buffer[] = [];
          for await (const chunk of req) chunks.push(Buffer.from(chunk));
          tsConfig = JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown;
          tsWrites.push({ version, config: tsConfig });
          return respond(200, {});
        }
      }
      return respond(404, { error: "unknown request" });
    });
    await new Promise<void>((resolve, reject) => tsServer.once("error", reject).listen(tailscaleSocket, resolve));
    sandbox.onTeardown(() => new Promise<void>((resolve, reject) =>
      tsServer.close((error) => error ? reject(error) : resolve()),
    ));

    // 3. Google OAuth + Gmail + Calendar mocks!
    const googleOAuth = await GoogleOAuthMockServer.start({
      clientId: "itest-google-client.apps.googleusercontent.com",
      validRefreshToken: googleRefresh,
      issuedAccessToken: "at-saas-e2e",
    });
    const gmailMock = await GmailMockServer.start({
      accessToken: "at-saas-e2e",
      initialHistoryId: "100",
      strictMetadataOnly: true,
    });
    gmailMock.addMessage({
      id: "gm-1",
      threadId: "gt-1",
      labelIds: ["INBOX", "UNREAD"],
      from: "boss@example.com",
      to: "ada@example.com",
      subject: "GMAIL_SAAS_E2E_SUBJECT_801",
      snippet: "Metadata snippet only",
      historyId: "120",
    });
    const gmailStateFile = path.join(sandbox.paths.hyphaeStateDir, "gmail-state.json");
    fs.writeFileSync(gmailStateFile, JSON.stringify({ historyId: "100", seen: {} }), { mode: 0o600 });

    const calMock = await GoogleCalendarMockServer.start({ accessToken: "at-saas-e2e" });
    const soonIso = new Date(Date.now() + 4 * 60_000).toISOString();
    calMock.setUpcomingEvents("primary", [
      {
        id: "cal-ev-1",
        status: "confirmed",
        summary: "GCAL_STARTING_MEETING_802",
        updated: new Date().toISOString(),
        start: { dateTime: soonIso },
        end: { dateTime: soonIso },
        attendees: [{ self: true, responseStatus: "accepted" }],
      },
    ]);
    const calStateFile = path.join(sandbox.paths.hyphaeStateDir, "gcal-state.json");
    fs.writeFileSync(
      calStateFile,
      JSON.stringify({ cursor: new Date().toISOString(), seen: {}, reminded: {} }),
      { mode: 0o600 },
    );
    sandbox.onTeardown(async () => {
      await Promise.all([googleOAuth.close(), gmailMock.close(), calMock.close()]);
    });

    const sentryPort = await getFreePort();
    const vercelPort = await getFreePort();
    const notionPort = await getFreePort();
    const notionTokenFile = path.join(sandbox.paths.hyphaeStateDir, "notion-verification-token");

    // Stage plugins read-only into sandbox's plugins dir (never mutating `saasDir`!).
    const stagedPluginsDir = path.join(sandbox.paths.hyphaeStateDir, "staged-saas-plugins");
    fs.cpSync(path.join(saasDir, "sdk"), path.join(stagedPluginsDir, "sdk"), { recursive: true });
    for (const name of SAAS_PLUGIN_NAMES) {
      fs.cpSync(path.join(saasDir, name), path.join(stagedPluginsDir, name), { recursive: true });
    }

    writeNodeJson(hyp.nodeConfigPath, {
      v: 2,
      nodeId: "saas-itest@local",
      profile: "local",
      stateDir: sandbox.paths.hyphaeStateDir,
      plugins: [
        {
          id: "agentmail",
          kind: "source",
          command: process.execPath,
          args: [path.join(stagedPluginsDir, "agentmail", "index.mjs")],
          targets: ["agentmail"],
          env: {
            AGENTMAIL_API_KEY: { secret: "agentmail-api-key" },
            AGENTMAIL_WS_URL: amMock.wsUrl,
            AGENTMAIL_API_BASE: amMock.apiBase,
            AGENTMAIL_INBOXES: "ops@agentmail.to",
            AGENTMAIL_STATE_FILE: amStateFile,
          },
        },
        {
          id: "sentry",
          kind: "source",
          command: process.execPath,
          args: [path.join(stagedPluginsDir, "sentry", "index.mjs")],
          targets: ["sentry"],
          env: {
            SENTRY_MODE: "webhook",
            SENTRY_CLIENT_SECRET: { secret: "sentry-client-secret" },
            SENTRY_WEBHOOK_PORT: String(sentryPort),
            SENTRY_WEBHOOK_PATH: "/sentry",
            SENTRY_WEBHOOK_FUNNEL: "8443",
            HYPHAE_BIN: hyp.bin,
            TAILSCALE_SOCKET: tailscaleSocket,
          },
        },
        {
          id: "vercel",
          kind: "source",
          command: process.execPath,
          args: [path.join(stagedPluginsDir, "vercel", "index.mjs")],
          targets: ["vercel"],
          env: {
            VERCEL_MODE: "webhook",
            VERCEL_WEBHOOK_SECRET: { secret: "vercel-webhook-secret" },
            VERCEL_WEBHOOK_PORT: String(vercelPort),
            VERCEL_WEBHOOK_PATH: "/vercel",
          },
        },
        {
          id: "notion",
          kind: "source",
          command: process.execPath,
          args: [path.join(stagedPluginsDir, "notion", "index.mjs")],
          targets: ["notion"],
          env: {
            NOTION_MODE: "webhook",
            NOTION_WEBHOOK_PORT: String(notionPort),
            NOTION_WEBHOOK_PATH: "/notion",
            NOTION_VERIFICATION_TOKEN_FILE: notionTokenFile,
          },
        },
        {
          id: "gmail",
          kind: "source",
          command: process.execPath,
          args: [path.join(stagedPluginsDir, "gmail", "index.mjs")],
          targets: ["gmail"],
          env: {
            GOOGLE_CLIENT_ID: "itest-google-client.apps.googleusercontent.com",
            GOOGLE_REFRESH_TOKEN: { secret: "google-refresh-token" },
            GOOGLE_TOKEN_URL: googleOAuth.tokenUrl,
            GMAIL_API_BASE: gmailMock.apiBase,
            GMAIL_STATE_FILE: gmailStateFile,
          },
        },
        {
          id: "google-calendar",
          kind: "source",
          command: process.execPath,
          args: [path.join(stagedPluginsDir, "google-calendar", "index.mjs")],
          targets: ["google-calendar"],
          env: {
            GOOGLE_CLIENT_ID: "itest-google-client.apps.googleusercontent.com",
            GOOGLE_REFRESH_TOKEN: { secret: "google-refresh-token" },
            GOOGLE_TOKEN_URL: googleOAuth.tokenUrl,
            CALENDAR_API_BASE: calMock.apiBase,
            CALENDAR_STATE_FILE: calStateFile,
          },
        },
      ],
    });

    await hyp.startDaemon();

    // 1. Wait for AgentMail B3 cursor to advance cleanly past BOTH m1 and interleaved live m2!
    await waitUntil(() => {
      try {
        const st = JSON.parse(fs.readFileSync(amStateFile, "utf8"));
        return st.cursors?.["ops@agentmail.to"] === t2;
      } catch {
        return false;
      }
    }, "AgentMail B3 cursor advanced to t2", 15_000);

    // 2. The Sentry plugin delegates activation to the host. Only the dedicated
    //    port becomes public, and the exact signed receiver path is retained.
    await waitUntil(() => tsWrites.length > 0, "Sentry Tailscale Funnel conditional write", 15_000);
    assert.deepEqual(tsWrites, [{
      version: "itest-0",
      config: {
        TCP: { ...privateServe.TCP, "8443": { HTTPS: true } },
        Web: {
          ...privateServe.Web,
          "itest-hub.tail9999.ts.net:8443": { Handlers: { "/sentry": { Proxy: `http://127.0.0.1:${sentryPort}/sentry` } } },
        },
        AllowFunnel: { "itest-hub.tail9999.ts.net:8443": true },
      },
    }]);

    const sentryPayload = {
      action: "created",
      data: {
        issue: {
          id: "9001",
          shortId: "API-9001",
          title: "SENTRY_SAAS_E2E_BOOM_803",
          level: "fatal",
          project: { slug: "api" },
        },
      },
    };
    assert.equal(
      (
        await sendSentryWebhook(`http://127.0.0.1:${sentryPort}/sentry`, {
          resource: "issue",
          payload: sentryPayload,
          clientSecret: sentrySecret,
          tamperSignature: true,
        })
      ).status,
      401,
    );
    assert.equal(
      (
        await sendSentryWebhook(`http://127.0.0.1:${sentryPort}/sentry`, {
          resource: "issue",
          payload: sentryPayload,
          clientSecret: sentrySecret,
        })
      ).status,
      202,
      "The configured receiver must accept a validly signed webhook",
    );

    assert.equal(
      (await sendSentryWebhook(`http://127.0.0.1:${sentryPort}/`, {
        resource: "issue",
        payload: sentryPayload,
        clientSecret: sentrySecret,
      })).status,
      404,
    );

    // 3. Verify Vercel HMAC-SHA1: 1-bit flip & wrong SHA-256 -> 401; valid SHA-1 -> 202!
    const vercelUrl = `http://127.0.0.1:${vercelPort}/vercel`;
    const vercelPayload = {
      id: "evt_vrc_804",
      type: "deployment.error",
      createdAt: Date.now(),
      payload: { target: "production", deployment: { id: "dpl_804", name: "web" } },
    };
    assert.equal(
      (await sendVercelWebhook(vercelUrl, { payload: vercelPayload, secret: vercelSecret, tamperSignature: true }))
        .status,
      401,
    );
    assert.equal(
      (await sendVercelWebhook(vercelUrl, { payload: vercelPayload, secret: vercelSecret, useWrongSha256: true }))
        .status,
      401,
    );
    assert.equal(
      (await sendVercelWebhook(vercelUrl, { payload: vercelPayload, secret: vercelSecret })).status,
      202,
    );

    // 4. Verify Notion one-time `verification_token` handshake security (2nd hijack attempt -> 401!)
    const notionUrl = `http://127.0.0.1:${notionPort}/notion`;
    const notionToken = "secret_NotionRealHandshakeToken_123456";
    sandbox.registerSecret("notion-verification-token", notionToken);

    const notionEvent = {
      id: "ntn_evt_805",
      timestamp: new Date().toISOString(),
      workspace_id: "ws-itest",
      type: "page.created",
      entity: { id: "page-805", type: "page" },
      data: { parent: { id: "root", type: "workspace" } },
    };
    // Before handshake -> 401
    assert.equal(
      (await sendNotionWebhookEvent(notionUrl, { payload: notionEvent, verificationToken: notionToken })).status,
      401,
    );
    // 1st valid handshake -> 200 + 0600 file saved
    assert.equal((await sendNotionVerificationHandshake(notionUrl, notionToken)).status, 200);
    assert.equal(fs.readFileSync(notionTokenFile, "utf8").trim(), notionToken);
    assert.equal(fs.statSync(notionTokenFile).mode & 0o777, 0o600);
    // 2nd hijack attempt -> 401 and pinned secret untouched!
    assert.equal(
      (await sendNotionVerificationHandshake(notionUrl, "attacker_hijack_token_9999999999")).status,
      401,
    );
    assert.equal(fs.readFileSync(notionTokenFile, "utf8").trim(), notionToken);
    // 1-bit flipped signature -> 401; valid signed event -> 202!
    assert.equal(
      (
        await sendNotionWebhookEvent(notionUrl, {
          payload: notionEvent,
          verificationToken: notionToken,
          tamperSignature: true,
        })
      ).status,
      401,
    );
    assert.equal(
      (await sendNotionWebhookEvent(notionUrl, { payload: notionEvent, verificationToken: notionToken })).status,
      202,
    );

    // 5. Verify Gmail metadata-only and Calendar `.starting` state persisted cleanly!
    await waitUntil(
      () => JSON.parse(fs.readFileSync(gmailStateFile, "utf8")).historyId === "120",
      "Gmail history cursor advanced to 120",
      15_000,
    );
    assert.equal(gmailMock.nonMetadataRequests.length, 0, "Gmail must ONLY request format=metadata");
    await waitUntil(
      () => Object.keys(JSON.parse(fs.readFileSync(calStateFile, "utf8")).reminded ?? {}).length >= 1,
      "Calendar .starting reminder recorded",
      15_000,
    );

    // 6. Verify real Claude harness receives a live Sentry webhook event via `hyp_stream`!
    const shim = await LlmShimServer.start({
      sandbox,
      auditors: {
        allowBridge: false,
        allowKv: false,
        allowedRoles: ["saas-claude"],
      },
    });
    const liveSentryMarker = "SENTRY_LIVE_CLAUDE_DELIVERY_809";
    shim.auditors.registerUntrustedPayload("sentry-live", liveSentryMarker);

    let subDone = false;
    let sawLiveSentry = false;

    shim.script("saas-claude", [
      coreToolSearchRule(false),
      {
        name: "enroll",
        once: true,
        when: (req) => !req.isToolDeferred("hyp_mesh") && req.anyMessageContains("ENROLL_SAAS"),
        do: (req) => callTool(req, "hyp_mesh", { action: "join", handle: "saas-agent" }),
      },
      {
        name: "sub-sentry",
        once: true,
        when: (req) => req.lastToolResult("hyp_mesh")?.json?.handle === "saas-agent",
        do: (req) =>
          callTool(req, "hyp_stream", {
            action: "subscribe",
            topic: "local.sentry",
            mode: "queue",
            // Pass coalesceSeconds=1 so we also verify delivery even if main lacks B1's immediate flush!
            coalesceSeconds: 1,
          }),
      },
      {
        name: "done-sub",
        once: true,
        when: (req) => {
          const r = req.lastToolResult("hyp_stream");
          if (r && !r.isError) subDone = true;
          return Boolean(r && !r.isError);
        },
        do: () => emitText("SAAS_SUBSCRIBED"),
      },
      {
        name: "ack-sentry",
        once: true,
        when: (req) => req.anyMessageContains(liveSentryMarker),
        do: () => {
          sawLiveSentry = true;
          return emitText("SAAS_SENTRY_DELIVERED");
        },
      },
      pullInboxOnNotifyRule("pull-saas-sentry-inbox", "local.sentry"),
      {
        name: "ack-waiter-prompt",
        when: (req) => req.lastUserText.includes("no background waiter is running yet"),
        do: () => emitText("STANDING_BY"),
      },
    ]);

    const claude = await ClaudeHarness.create({
      sandbox,
      hyp,
      shim,
      claudeBin,
      role: "saas-claude",
    });

    const sessionUuid = crypto.randomUUID();
    const r1 = await claude.runPrint("ENROLL_SAAS", { sessionId: sessionUuid, maxTurns: 8 });
    assert.equal(r1.exitCode, 0);
    assert.equal(subDone, true);

    const liveSentryRes = await sendSentryWebhook(`http://127.0.0.1:${sentryPort}/sentry`, {
      resource: "issue",
      payload: {
        action: "created",
        data: {
          issue: {
            id: "9009",
            shortId: "API-9009",
            title: liveSentryMarker,
            level: "error",
            project: { slug: "api" },
          },
        },
      },
      clientSecret: sentrySecret,
    });
    assert.equal(liveSentryRes.status, 202);

    // Wait >1.1s for the 1s coalesce window to close and flush into Claude's local mailbox!
    await new Promise((r) => setTimeout(r, 1_400));

    const r2 = await claude.runPrint("CHECK_SAAS_SENTRY", {
      sessionId: sessionUuid,
      resume: true,
      maxTurns: 6,
    });
    assert.equal(r2.exitCode, 0);
    assert.equal(sawLiveSentry, true, "Real Claude must receive live Sentry SaaS source CloudEvent");

    // Verify ZERO secrets leaked into per-plugin logs (`0600`) or LLM requests!
    for (const pluginId of SAAS_PLUGIN_NAMES) {
      const lp = path.join(sandbox.paths.hyphaeStateDir, "logs", `plugin-${pluginId}.log`);
      if (fs.existsSync(lp)) {
        assert.equal(fs.statSync(lp).mode & 0o777, 0o600, `plugin-${pluginId}.log must be 0600`);
        const content = fs.readFileSync(lp, "utf8");
        for (const secret of [amKey, sentrySecret, vercelSecret, googleRefresh, notionToken]) {
          assert.equal(content.includes(secret), false, `Secret leaked in plugin-${pluginId}.log!`);
        }
      }
    }

    shim.assertAllClean();
  });
});
