import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { spawn } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { loadConfig } from "./config.ts";
import { startDaemon } from "./daemon.ts";
import { onboardRemoteOverSsh, parseSshConfigHosts, probeRemoteHost } from "./discover.ts";
import { buildAgentOnboardingPrompt, gatherOnboardingContext } from "./assist.ts";
import { encodeInvite } from "./remote.ts";
import { captureSecretViaWeb, collectSecretRefs, deleteSecret, listSecrets, readSecret, writeSecret } from "./secrets.ts";
import { installSkill, runDoctor, runOnboard, setupOpenClaw } from "./setup.ts";
import { RouterCore } from "./core/router/core.ts";
import { serveRouter } from "./core/router/server.ts";

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = createServer();
    srv.listen(0, "127.0.0.1", () => {
      const addr = srv.address();
      srv.close(() => {
        if (addr && typeof addr === "object") resolve(addr.port);
        else reject(new Error("Could not allocate free port"));
      });
    });
  });
}

test("parseSshConfigHosts extracts host aliases and skips git forges and wildcards", () => {
  const sample = `
Host *
  ServerAliveInterval 60

Host github.com
  User git

Host great-northern gn
  HostName 100.64.0.2

Host solace
  HostName solace.tail.ts.net
`;
  assert.deepEqual(parseSshConfigHosts(sample), ["great-northern", "solace"]);
});

test("built-in webhook plugin delivers signed CloudEvents to Antigravity wait and hands off live to Claude", { timeout: 15_000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "am-plug-"));
  const routerCore = new RouterCore({ dbPath: join(dir, "router.sqlite") });
  const token = routerCore.addConnector("bogdan@plug");
  const router = await serveRouter({ core: routerCore, host: "127.0.0.1", port: 0 });
  const webhookPort = await freePort();

  const tokenFile = join(dir, "connector.token");
  const secretFile = join(dir, "webhook.secret");
  writeFileSync(tokenFile, token + "\n", { mode: 0o600 });
  writeFileSync(secretFile, "top-secret-hmac\n", { mode: 0o600 });
  chmodSync(tokenFile, 0o600);
  chmodSync(secretFile, 0o600);

  const configPath = join(dir, "connector.json");
  writeFileSync(configPath, JSON.stringify({
    connectorId: "bogdan@plug",
    stateDir: "state",
    routers: [{ name: "primary", url: router.url, tokenFile }],
    plugins: [
      {
        name: "alerts",
        builtin: "webhook",
        env: {
          WEBHOOK_HOST: "127.0.0.1",
          WEBHOOK_PORT: String(webhookPort),
          WEBHOOK_PATH: "/hook",
          WEBHOOK_SECRET_FILE: secretFile,
          WEBHOOK_SOURCE: "alerts/test",
          WEBHOOK_EVENT_TYPE: "com.ops.alert",
        },
        targets: [
          { name: "ops", handle: "ops-ag", coalesceSeconds: 0, maxWaitSeconds: 5, wakesPerHour: 120 },
        ],
      },
    ],
  }), { mode: 0o600 });

  const daemon = await startDaemon(loadConfig(configPath), { quiet: true });

  try {
    // Enroll Antigravity session under handle `ops-ag` and Claude session under `ops-claude`
    daemon.state.register("antigravity:ag-1", { kind: "antigravity" });
    await daemon.connector.call("antigravity:ag-1", "hyp_join", { handle: "ops-ag" });
    daemon.state.register("claude:cl-2", { kind: "claude" });
    await daemon.connector.call("claude:cl-2", "hyp_join", { handle: "ops-claude" });

    // Arm zero-polling `hyp wait` for Antigravity
    const waitProc = spawn(
      process.execPath,
      [join(process.cwd(), "src", "cli.ts"), "wait", "--session", "antigravity:ag-1", "--socket", daemon.socketPath],
      { stdio: ["ignore", "pipe", "pipe"] },
    );
    const waitOutput = new Promise<string>((resolve, reject) => {
      const chunks: Buffer[] = [];
      waitProc.stdout.on("data", (c: Buffer) => chunks.push(c));
      waitProc.once("exit", (code) => {
        if (code === 0) resolve(Buffer.concat(chunks).toString("utf8"));
        else reject(new Error(`wait exited ${code}`));
      });
    });

    // Wait for built-in webhook plugin HTTP server to come up
    const postSigned = async (id: string, bodyObj: Record<string, unknown>) => {
      const raw = JSON.stringify(bodyObj);
      const sig = "sha256=" + createHmac("sha256", "top-secret-hmac").update(raw).digest("hex");
      const deadline = Date.now() + 5_000;
      while (Date.now() < deadline) {
        try {
          const res = await fetch(`http://127.0.0.1:${webhookPort}/hook`, {
            method: "POST",
            headers: { "content-type": "application/json", "x-delivery-id": id, "x-webhook-signature-256": sig },
            body: raw,
          });
          return res;
        } catch {
          await new Promise((r) => setTimeout(r, 100));
        }
      }
      throw new Error("Webhook plugin did not start listening in time");
    };

    // 1. Bad signature must be rejected with 401
    const firstOk = await postSigned("evt-1", { severity: "high", msg: "disk-full" });
    assert.equal(firstOk.status, 202);
    const badSig = await fetch(`http://127.0.0.1:${webhookPort}/hook`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-webhook-signature-256": "sha256=deadbeef" },
      body: JSON.stringify({ msg: "forged" }),
    });
    assert.equal(badSig.status, 401);

    // Antigravity waiter wakes automatically with the plugin batch!
    const received = await waitOutput;
    assert.match(received, /hyphae event plugin:alerts/);
    assert.match(received, /disk-full/);

    // 2. Verify hyp_plugin_targets and hand off `alerts/ops` from Antigravity -> Claude!
    const targets = await daemon.connector.call("antigravity:ag-1", "hyp_plugin_targets", {}) as { targets: Array<{ plugin: string; target: string }> };
    assert.equal(targets.targets.length, 1);
    assert.equal(targets.targets[0].plugin, "alerts");

    const handoff = await daemon.connector.call("antigravity:ag-1", "hyp_plugin_handoff", {
      plugin: "alerts",
      target: "ops",
      handle: "ops-claude",
    });
    assert.deepEqual(handoff, { plugin: "alerts", target: "ops", sessionId: "claude:cl-2" });

    // 3. Second webhook routes directly into Claude's mailbox!
    const secondOk = await postSigned("evt-2", { severity: "low", msg: "handed-off-to-claude" });
    assert.equal(secondOk.status, 202);
    const deadline = Date.now() + 4_000;
    let claudeItems = daemon.connector.drainMailbox("claude:cl-2", 5);
    while (claudeItems.length === 0 && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 100));
      claudeItems = daemon.connector.drainMailbox("claude:cl-2", 5);
    }
    assert.equal(claudeItems.length, 1);
    assert.match(claudeItems[0].text, /handed-off-to-claude/);
  } finally {
    await daemon.stop();
    await router.close();
    routerCore.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("secrets store enforces 0600 permissions, tracks refs, and never leaks values", () => {
  const dir = mkdtempSync(join(tmpdir(), "am-sec-"));
  try {
    const saved = writeSecret("slack-app-token", "xapp-secret-123", dir);
    assert.equal(readSecret("slack-app-token", dir), "xapp-secret-123");
    const listed = listSecrets(dir);
    assert.equal(listed.length, 1);
    assert.equal(listed[0].name, "slack-app-token");
    assert.equal(listed[0].modeOk, true);

    // Broad permissions must be rejected fail-closed
    chmodSync(saved, 0o644);
    assert.throws(() => readSecret("slack-app-token", dir), /overly broad permissions/);
    chmodSync(saved, 0o600);

    const refs = collectSecretRefs({
      plugins: [{ name: "slack", env: { SLACK_APP_TOKEN: { secret: "slack-app-token" } } }],
      localRouter: { streams: [{ name: "gh", env: { GITHUB_WEBHOOK_SECRET: { secret: "gh-secret" } } }] },
    });
    assert.deepEqual(refs, [
      { owner: "plugin:slack", envKey: "SLACK_APP_TOKEN", secret: "slack-app-token" },
      { owner: "stream:gh", envKey: "GITHUB_WEBHOOK_SECRET", secret: "gh-secret" },
    ]);

    assert.equal(deleteSecret("slack-app-token", dir), true);
    assert.equal(listSecrets(dir).length, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("router data stream resolves {secret} from store and fans out CloudEvents to agents by hyp_subscribe filters", { timeout: 15_000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "am-str-"));
  const webhookPort = await freePort();
  const routerPort = await freePort();

  try {
    // Store webhook HMAC secret privately in secrets/ (never plaintext in connector.json)
    writeSecret("ci-stream-hmac", "stream-hmac-xyz", dir);

    const configPath = join(dir, "connector.json");
    const onboarded = await runOnboard({
      configPath,
      connectorId: "bogdan@streams",
      port: routerPort,
      harnesses: [],
      startDaemon: false,
      localRouterExposure: "private",
      localRouterStreams: [
        {
          name: "ci-feed",
          topic: "ci",
          builtin: "webhook-stream",
          env: {
            WEBHOOK_HOST: "127.0.0.1",
            WEBHOOK_PORT: String(webhookPort),
            WEBHOOK_PATH: "/ci",
            WEBHOOK_TARGET: "ci",
            WEBHOOK_SOURCE: "ci/build",
            WEBHOOK_SECRET: { secret: "ci-stream-hmac" },
          },
        },
      ],
    });
    assert.equal(onboarded.localRouter, true);

    const daemon = await startDaemon(loadConfig(configPath), { quiet: true });
    try {
      // Register two agents across different harnesses with DIFFERENT CloudEvents filters on topic `ci`
      daemon.state.register("antigravity:ag-ci", { kind: "antigravity" });
      await daemon.connector.call("antigravity:ag-ci", "hyp_join", { handle: "ag-ci" });
      await daemon.connector.call("antigravity:ag-ci", "hyp_subscribe", {
        key: "ci:fail",
        topic: "ci",
        filters: [{ exact: { type: "com.ci.failed" } }],
        coalesceSeconds: 0,
      });

      daemon.state.register("claude:cl-ci", { kind: "claude" });
      await daemon.connector.call("claude:cl-ci", "hyp_join", { handle: "cl-ci" });
      await daemon.connector.call("claude:cl-ci", "hyp_subscribe", {
        key: "ci:pass",
        topic: "ci",
        filters: [{ exact: { type: "com.ci.passed" } }],
        coalesceSeconds: 0,
      });

      const postEvent = async (id: string, type: string, msg: string) => {
        const raw = JSON.stringify({ type, source: "ci/build", data: { msg } });
        const sig = "sha256=" + createHmac("sha256", "stream-hmac-xyz").update(raw).digest("hex");
        const deadline = Date.now() + 5_000;
        while (Date.now() < deadline) {
          try {
            return await fetch(`http://127.0.0.1:${webhookPort}/ci`, {
              method: "POST",
              headers: { "content-type": "application/json", "x-delivery-id": id, "x-webhook-signature-256": sig },
              body: raw,
            });
          } catch {
            await new Promise((r) => setTimeout(r, 100));
          }
        }
        throw new Error("Stream webhook did not come up");
      };

      // Give subscriptions a brief beat to sync to the embedded router
      await new Promise((r) => setTimeout(r, 200));

      const resFail = await postEvent("ci-1", "com.ci.failed", "unit-test-red");
      assert.equal(resFail.status, 202);
      const resPass = await postEvent("ci-2", "com.ci.passed", "deploy-green");
      assert.equal(resPass.status, 202);

      // Poll mailboxes until delivered (router ticks on 1s interval or closes immediately at coalesceSeconds=0)
      const deadline = Date.now() + 5_000;
      let agItems = daemon.connector.drainMailbox("antigravity:ag-ci", 5);
      let clItems = daemon.connector.drainMailbox("claude:cl-ci", 5);
      while ((agItems.length === 0 || clItems.length === 0) && Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 100));
        if (agItems.length === 0) agItems = daemon.connector.drainMailbox("antigravity:ag-ci", 5);
        if (clItems.length === 0) clItems = daemon.connector.drainMailbox("claude:cl-ci", 5);
      }

      // Each agent receives ONLY the event matching its filter!
      assert.equal(agItems.length, 1);
      assert.match(agItems[0].text, /unit-test-red/);
      assert.doesNotMatch(agItems[0].text, /deploy-green/);

      assert.equal(clItems.length, 1);
      assert.match(clItems[0].text, /deploy-green/);
      assert.doesNotMatch(clItems[0].text, /unit-test-red/);
    } finally {
      await daemon.stop();
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("multi-router onboard sets up local private router AND joins a shared secondary router simultaneously", async () => {
  const dir = mkdtempSync(join(tmpdir(), "am-multi-"));
  const sharedCore = new RouterCore({ dbPath: join(dir, "shared.sqlite") });
  const sharedToken = sharedCore.addConnector("bogdan@laptop");
  const sharedRouter = await serveRouter({ core: sharedCore, host: "127.0.0.1", port: 0 });

  try {
    const sharedInvite = encodeInvite({
      connectorId: "bogdan@laptop",
      router: sharedRouter.url,
      token: sharedToken,
    });
    const configPath = join(dir, "connector.json");
    const localPort = await freePort();
    const res = await runOnboard({
      configPath,
      connectorId: "bogdan@laptop",
      port: localPort,
      harnesses: [],
      startDaemon: false,
      additionalRouters: [{ name: "team", inviteCode: sharedInvite }],
    });
    assert.equal(res.localRouter, true);
    const loaded = loadConfig(configPath);
    assert.deepEqual(loaded.routers.map((r) => r.name), ["primary", "team"]);
    assert.equal(loaded.routers[1].url, sharedRouter.url);
  } finally {
    await sharedRouter.close();
    sharedCore.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("security hardening: rejects SSH option injection, remoteBin injection, and builds secret-free onboarding prompt", async () => {
  const badProbe = await probeRemoteHost({ host: "-oProxyCommand=id", sources: ["test"] });
  assert.equal(badProbe.sshReachable, false);
  assert.match(badProbe.error ?? "", /unsafe SSH/i);

  const badSsh = await onboardRemoteOverSsh({ host: "okhost", inviteCode: "am1_x", remoteBin: "foo;rm -rf /" });
  assert.equal(badSsh.ok, false);
  assert.match(badSsh.stderr, /Unsafe remote binary/i);

  const dir = mkdtempSync(join(tmpdir(), "am-assist-"));
  try {
    writeSecret("super-secret-key", "DO_NOT_LEAK_THIS_VALUE", dir);
    const ctx = await gatherOnboardingContext(join(dir, "connector.json"), join(dir, "missing.sock"));
    const prompt = buildAgentOnboardingPrompt(ctx);
    assert.match(prompt, /Private Router/);
    assert.match(prompt, /Public Router/);
    assert.match(prompt, /NEVER read, print, log/);
    assert.ok(!prompt.includes("DO_NOT_LEAK_THIS_VALUE"), "Secret value must never appear in agent onboarding prompt!");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("setupOpenClaw configures openclaw.json + SKILL.md idempotently without clobbering existing MCP servers", async () => {
  const dir = mkdtempSync(join(tmpdir(), "am-oc-"));
  const home = join(dir, "home");
  const runtime = { nodeBin: "/opt/node24/bin/node", cliScript: "/opt/hyphae/bin/hyphae.mjs" };
  try {
    const ocDir = join(home, ".openclaw");
    const cfgPath = join(ocDir, "openclaw.json");
    const fs = await import("node:fs");
    fs.mkdirSync(ocDir, { recursive: true });
    writeFileSync(cfgPath, JSON.stringify({ gateway: { port: 18789 }, mcp: { servers: { existing: { command: "foo", args: [] } } } }));

    for (let i = 0; i < 2; i++) {
      setupOpenClaw({ scope: "user", homeDir: home, runtime });
    }
    const parsed = JSON.parse(fs.readFileSync(cfgPath, "utf8")) as {
      gateway: { port: number };
      mcp: { servers: Record<string, { command: string; args: string[] }> };
    };
    assert.equal(parsed.gateway.port, 18789);
    assert.ok(parsed.mcp.servers.existing);
    assert.equal(parsed.mcp.servers.hyphae.command, "/opt/node24/bin/node");
    assert.ok(parsed.mcp.servers.hyphae.args.includes("openclaw"));
    const skillText = fs.readFileSync(join(ocDir, "skills", "hyphae", "SKILL.md"), "utf8");
    assert.match(skillText, /hyp_channel_join/);

    const checks = await runDoctor(join(dir, "missing.json"), join(dir, "missing.sock"), home);
    assert.equal(checks.find((c) => c.name === "openclaw")?.ok, true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("multi-agent #channels fan out posts to all other members across harnesses and stop on leave", { timeout: 15_000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "am-chan-"));
  const routerCore = new RouterCore({ dbPath: join(dir, "router.sqlite") });
  const token = routerCore.addConnector("bogdan@fleet");
  const router = await serveRouter({ core: routerCore, host: "127.0.0.1", port: 0 });
  const daemon = await startDaemon({
    connectorId: "bogdan@fleet",
    directory: join(dir, "state"),
    routers: [{ name: "primary", url: router.url, token }],
  }, { quiet: true });

  try {
    // 3 sessions across 3 harnesses: OpenClaw orchestrator, Antigravity, and Codex
    daemon.state.register("openclaw:oc-1", { kind: "openclaw" });
    daemon.state.register("antigravity:ag-1", { kind: "antigravity" });
    daemon.state.register("codex:cx-1", { kind: "codex" });

    await daemon.connector.call("openclaw:oc-1", "hyp_join", { handle: "orchestrator" });
    await daemon.connector.call("antigravity:ag-1", "hyp_join", { handle: "agy" });
    await daemon.connector.call("codex:cx-1", "hyp_join", { handle: "backend" });

    // Posting before joining fails closed
    await assert.rejects(
      () => daemon.connector.call("openclaw:oc-1", "hyp_channel_post", { channel: "#incidents", text: "nope" }),
      /join #incidents before posting/i,
    );

    // Join `#incidents` (accepts with or without leading `#`)
    await daemon.connector.call("openclaw:oc-1", "hyp_channel_join", { channel: "incidents" });
    await daemon.connector.call("antigravity:ag-1", "hyp_channel_join", { channel: "#incidents" });
    const join3 = await daemon.connector.call("codex:cx-1", "hyp_channel_join", { channel: "#incidents" }) as { members: string[] };
    assert.deepEqual(join3.members, ["bogdan@fleet/agy", "bogdan@fleet/backend", "bogdan@fleet/orchestrator"]);

    const listed = await daemon.connector.call("openclaw:oc-1", "hyp_channels", {}) as { channels: Array<{ channel: string; members: string[] }> };
    assert.equal(listed.channels.length, 1);
    assert.equal(listed.channels[0].channel, "#incidents");

    // OpenClaw posts to #incidents -> delivered to agy & backend, NOT echoed back to orchestrator!
    const posted = await daemon.connector.call("openclaw:oc-1", "hyp_channel_post", {
      channel: "#incidents",
      text: "Prometheus HighErrorRate on checkout-api!",
    }) as { deliveredTo: string[] };
    assert.deepEqual(posted.deliveredTo, ["bogdan@fleet/agy", "bogdan@fleet/backend"]);

    const deadline = Date.now() + 4_000;
    let agMsgs = daemon.connector.drainMailbox("antigravity:ag-1", 5);
    let cxMsgs = daemon.connector.drainMailbox("codex:cx-1", 5);
    while ((agMsgs.length === 0 || cxMsgs.length === 0) && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 80));
      if (agMsgs.length === 0) agMsgs = daemon.connector.drainMailbox("antigravity:ag-1", 5);
      if (cxMsgs.length === 0) cxMsgs = daemon.connector.drainMailbox("codex:cx-1", 5);
    }
    assert.equal(agMsgs.length, 1);
    assert.match(agMsgs[0].text, /\[#incidents\] Prometheus HighErrorRate/);
    assert.equal(cxMsgs.length, 1);
    assert.match(cxMsgs[0].text, /\[#incidents\] Prometheus HighErrorRate/);
    assert.equal(daemon.connector.drainMailbox("openclaw:oc-1", 5).length, 0);

    // Codex leaves #incidents -> subsequent post only delivers to agy
    const left = await daemon.connector.call("codex:cx-1", "hyp_channel_leave", { channel: "#incidents" }) as { left: boolean };
    assert.equal(left.left, true);
    const posted2 = await daemon.connector.call("openclaw:oc-1", "hyp_channel_post", {
      channel: "#incidents",
      text: "Alert resolved.",
    }) as { deliveredTo: string[] };
    assert.deepEqual(posted2.deliveredTo, ["bogdan@fleet/agy"]);
  } finally {
    await daemon.stop();
    await router.close();
    routerCore.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("captureSecretViaWeb captures secret out-of-band on 127.0.0.1 with 0600 permissions and shuts down", async () => {
  const dir = mkdtempSync(join(tmpdir(), "hyphae-web-secret-"));
  try {
    let formUrl = "";
    const capturePromise = captureSecretViaWeb("telegram-bot-token", {
      configDir: dir,
      openBrowser: false,
      timeoutMs: 10_000,
      onReady: (url) => { formUrl = url; },
    });

    const deadline = Date.now() + 2_000;
    while (!formUrl && Date.now() < deadline) await new Promise((r) => setTimeout(r, 20));
    assert.match(formUrl, /^http:\/\/127\.0\.0\.1:\d+\/s\/[A-Za-z0-9_-]+$/);

    // Wrong path returns 404
    const parsed = new URL(formUrl);
    const badRes = await fetch(`${parsed.origin}/s/wrong-token`);
    assert.equal(badRes.status, 404);

    // GET valid one-shot URL returns password form
    const getRes = await fetch(formUrl);
    assert.equal(getRes.status, 200);
    const html = await getRes.text();
    assert.match(html, /type="password"/);

    // Wrong CSRF token rejected with 403
    const badPost = await fetch(formUrl, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ token: "bogus", value: "secret" }).toString(),
    });
    assert.equal(badPost.status, 403);

    // Valid POST saves 0600 secret and shuts down immediately
    const token = parsed.pathname.slice("/s/".length);
    const okPost = await fetch(formUrl, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ token, value: "bot-secret-999" }).toString(),
    });
    assert.equal(okPost.status, 200);

    const saved = await capturePromise;
    assert.equal(readSecret("telegram-bot-token", dir), "bot-secret-999");
    assert.equal(statSync(saved.path).mode & 0o777, 0o600);
    // Ensure result object never carries the secret value
    assert.equal(JSON.stringify(saved).includes("bot-secret-999"), false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("installSkill installs canonical skills/hyphae/SKILL.md across harnesses and project scope", () => {
  const dir = mkdtempSync(join(tmpdir(), "hyphae-skill-install-"));
  const proj = join(dir, "proj");
  mkdirSync(proj, { recursive: true });
  try {
    const res = installSkill("all", { homeDir: dir });
    assert.equal(res.files.length, 5);
    for (const f of res.files) {
      assert.ok(existsSync(f), `Expected skill installed at ${f}`);
      const txt = readFileSync(f, "utf8");
      assert.match(txt, /hyp secret set <name> --web/);
      assert.match(txt, /hyp_channel_join/);
    }
    const projRes = installSkill("project", { projectDir: proj });
    assert.equal(projRes.files.length, 1);
    assert.ok(existsSync(join(proj, ".agents", "skills", "hyphae", "SKILL.md")));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("connector-level muting drops messages from muted peers, connector wildcards, and #channels, and resumes on unmute", { timeout: 15_000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "hyphae-mute-"));
  const routerCore = new RouterCore({ dbPath: join(dir, "router.sqlite") });
  const token = routerCore.addConnector("bogdan@local");
  const router = await serveRouter({ core: routerCore, host: "127.0.0.1", port: 0 });
  const daemon = await startDaemon({
    connectorId: "bogdan@local",
    directory: join(dir, "state"),
    routers: [{ name: "primary", url: router.url, token }],
  }, { quiet: true });
  try {
    daemon.state.register("openclaw:oc-1", { kind: "openclaw" });
    daemon.state.register("claude:noisy", { kind: "claude" });
    daemon.state.register("antigravity:ally", { kind: "antigravity" });
    await daemon.connector.call("openclaw:oc-1", "hyp_join", { handle: "alice" });
    await daemon.connector.call("claude:noisy", "hyp_join", { handle: "noisy" });
    await daemon.connector.call("antigravity:ally", "hyp_join", { handle: "ally" });

    // Mute `bogdan@local/noisy` at connector level
    const muted = await daemon.connector.call("openclaw:oc-1", "hyp_mute", { target: "bogdan@local/noisy" });
    assert.deepEqual(muted, { muted: "bogdan@local/noisy", scope: "connector" });

    // Send from noisy (must be dropped) AND from ally (must be delivered to openclaw durable mailbox!)
    await daemon.connector.call("claude:noisy", "hyp_send", { to: "bogdan@local/alice", text: "spam 1" });
    await daemon.connector.call("antigravity:ally", "hyp_send", { to: "bogdan@local/alice", text: "important from ally" });

    const deadline = Date.now() + 3_000;
    while (daemon.state.pendingCount("openclaw:oc-1") < 1 && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 25));
    }
    const items1 = daemon.connector.drainMailbox("openclaw:oc-1", 10);
    assert.equal(items1.length, 1);
    assert.match(items1[0].text, /important from ally/);
    assert.doesNotMatch(items1[0].text, /spam 1/);

    // Mute #deploys channel at connector level
    await daemon.connector.call("openclaw:oc-1", "hyp_channel_join", { channel: "#deploys" });
    await daemon.connector.call("antigravity:ally", "hyp_channel_join", { channel: "#deploys" });
    await daemon.connector.call("openclaw:oc-1", "hyp_mute", { target: "#deploys" });
    await daemon.connector.call("antigravity:ally", "hyp_channel_post", { channel: "#deploys", text: "muted deploy chatter" });
    await new Promise((r) => setTimeout(r, 120));
    assert.equal(daemon.state.pendingCount("openclaw:oc-1"), 0);

    // Unmute noisy and verify delivery resumes
    const unmuted = await daemon.connector.call("openclaw:oc-1", "hyp_unmute", { target: "bogdan@local/noisy" });
    assert.equal((unmuted as { removed: boolean }).removed, true);
    await daemon.connector.call("claude:noisy", "hyp_send", { to: "bogdan@local/alice", text: "unmuted hello" });

    const deadline2 = Date.now() + 3_000;
    while (daemon.state.pendingCount("openclaw:oc-1") < 1 && Date.now() < deadline2) {
      await new Promise((r) => setTimeout(r, 25));
    }
    const items2 = daemon.connector.drainMailbox("openclaw:oc-1", 10);
    assert.equal(items2.length, 1);
    assert.match(items2[0].text, /unmuted hello/);
  } finally {
    await daemon.stop();
    await router.close();
    routerCore.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("notify mode pushes only a slim unread-count digest and keeps full items in hyp_inbox until queried", { timeout: 15_000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "hyphae-notify-"));
  const routerCore = new RouterCore({ dbPath: join(dir, "router.sqlite") });
  const token = routerCore.addConnector("bogdan@local");
  const router = await serveRouter({ core: routerCore, host: "127.0.0.1", port: 0 });
  const daemon = await startDaemon({
    connectorId: "bogdan@local",
    directory: join(dir, "state"),
    routers: [{ name: "primary", url: router.url, token }],
  }, { quiet: true });
  try {
    daemon.state.register("antigravity:reader", { kind: "antigravity" });
    daemon.state.register("claude:sender", { kind: "claude" });
    await daemon.connector.call("antigravity:reader", "hyp_join", { handle: "reader" });
    await daemon.connector.call("claude:sender", "hyp_join", { handle: "sender" });

    // Switch reader to slim notification mode
    const modeRes = await daemon.connector.call("antigravity:reader", "hyp_mode", { mode: "notify" });
    assert.deepEqual(modeRes, { deliveryMode: "notify", unread: 0 });

    // Send 2 full messages to reader
    await daemon.connector.call("claude:sender", "hyp_send", { to: "bogdan@local/reader", text: "secret full payload one" });
    await daemon.connector.call("claude:sender", "hyp_send", { to: "bogdan@local/reader", text: "secret full payload two" });

    const deadline = Date.now() + 3_000;
    while (daemon.state.pendingCount("antigravity:reader") < 2 && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 25));
    }

    // Hook/waiter drain returns ONE slim unread-count banner (NOT full payload bodies!)
    const pushed = daemon.connector.drainForPush("antigravity:reader", 10);
    assert.equal(pushed.length, 1);
    assert.match(pushed[0].text, /hyphae notice · 2 unread \(2 messages\) · from bogdan@local\/sender · call hyp_inbox to read/);
    assert.doesNotMatch(pushed[0].text, /secret full payload/);

    // Subsequent drain without new arrivals stays quiet, while unread items remain intact in SQLite
    assert.deepEqual(daemon.connector.drainForPush("antigravity:reader", 10), []);
    assert.equal(daemon.state.pendingCount("antigravity:reader"), 2);

    // Querying hyp_inbox returns all full unread items; acknowledgeAll clears them
    const inbox1 = await daemon.connector.call("antigravity:reader", "hyp_inbox", {}) as { unread: number; deliveryMode: string; items: Array<{ text: string; receipt: string }> };
    assert.equal(inbox1.deliveryMode, "notify");
    assert.equal(inbox1.unread, 2);
    assert.equal(inbox1.items.length, 2);
    assert.match(inbox1.items[0].text, /secret full payload one/);
    assert.match(inbox1.items[1].text, /secret full payload two/);

    const inbox2 = await daemon.connector.call("antigravity:reader", "hyp_inbox", { acknowledgeAll: true }) as { unread: number; items: Array<{ text: string }> };
    assert.equal(inbox2.items.length, 2);
    assert.equal(inbox2.unread, 0);
    assert.equal(daemon.state.pendingCount("antigravity:reader"), 0);
  } finally {
    await daemon.stop();
    await router.close();
    routerCore.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
