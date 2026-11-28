/**
 * Subprocess E2E & regression tests for:
 *   - Issue #40 (B2): MeshPluginClient exits non-zero promptly (<1.5s) on post-hello uncaught
 *     exceptions & unhandled rejections over real fd-3 pipes instead of hanging forever.
 *   - Issue #41: plugins/prometheus/index.mjs emits top-level CloudEvents 1.0 extensions
 *     (`alertname`, `severity`, `service`) matching Rust PrometheusWebhookAdapter semantics.
 *   - Issue #42: plugins/prometheus/index.mjs accepts EITHER valid Bearer OR valid Basic auth
 *     when both PROMETHEUS_BEARER_TOKEN and PROMETHEUS_BASIC_AUTH are configured, while
 *     preserving HMAC-SHA256 verification and non-loopback unsigned refusal invariants.
 *
 * Run with:
 *   node --test plugins/test/*.mjs
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash, createHmac } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import http from "node:http";
import net from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { createInterface } from "node:readline";
import { after, test } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { redactSlackInboundData } from "../slack/redact.mjs";

const PLUGINS_DIR = join(dirname(fileURLToPath(import.meta.url)), "..");
const SDK_URL = pathToFileURL(join(PLUGINS_DIR, "sdk", "client.mjs")).href;
const PROMETHEUS_SCRIPT = join(PLUGINS_DIR, "prometheus", "index.mjs");
const SLACK_SCRIPT = join(PLUGINS_DIR, "slack", "index.mjs");
const TELEGRAM_SCRIPT = join(PLUGINS_DIR, "telegram", "index.mjs");

const cleanups = [];
after(async () => {
  for (const fn of cleanups.reverse()) {
    await fn();
  }
});

async function until(check, label, timeoutMs = 5_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const value = await check();
    if (value) return value;
    await new Promise((r) => setTimeout(r, 15));
  }
  throw new Error(`timed out after ${timeoutMs}ms waiting for ${label}`);
}

/** Spawns an inline ESM Node 24 subprocess wired to a real fd-3 pipe like SubprocessSupervisor. */
function spawnFd3Script(code, { plugin = "test-plugin", targets = ["ops"], env = {}, sendHello = true } = {}) {
  const startedAt = Date.now();
  const child = spawn(process.execPath, ["--input-type=module", "-e", code], {
    env: {
      PATH: process.env.PATH,
      HOME: process.env.HOME,
      HYPHAE_FD: "3",
      HYPHAE_PLUGIN: plugin,
      SDK_URL,
      ...env,
    },
    stdio: ["ignore", "ignore", "pipe", "pipe"],
  });
  const channel = child.stdio[3];
  let stderr = "";
  let exitInfo = null;
  child.stderr.on("data", (chunk) => {
    stderr += chunk.toString("utf8");
  });
  const exitPromise = new Promise((resolve) => {
    child.on("exit", (codeVal, signal) => {
      exitInfo = { code: codeVal, signal, elapsedMs: Date.now() - startedAt };
      resolve(exitInfo);
    });
  });
  channel.on("error", () => {});
  if (sendHello) {
    channel.write(JSON.stringify({ jsonrpc: "2.0", method: "hyphae/hello", params: { protocol: 2, plugin, targets } }) + "\n");
  }
  cleanups.push(
    () =>
      new Promise((resolve) => {
        try {
          channel.destroy();
        } catch {}
        if (exitInfo !== null) return resolve();
        child.once("exit", () => resolve());
        child.kill("SIGKILL");
      }),
  );
  return {
    child,
    channel,
    stderr: () => stderr,
    waitExit: (timeoutMs = 1_500) =>
      Promise.race([
        exitPromise,
        new Promise((_, reject) =>
          setTimeout(
            () => reject(new Error(`child hung for >${timeoutMs}ms (stderr=${JSON.stringify(stderr)})`)),
            timeoutMs,
          ),
        ),
      ]),
  };
}

/** Spawns the real plugins/prometheus/index.mjs subprocess over fd 3 on an ephemeral loopback port. */
async function startPrometheusPlugin(env, { targets = ["alerts"] } = {}) {
  const child = spawn(process.execPath, [PROMETHEUS_SCRIPT], {
    env: {
      PATH: process.env.PATH,
      HOME: process.env.HOME,
      HYPHAE_FD: "3",
      HYPHAE_PLUGIN: "prometheus",
      PROMETHEUS_HOST: "127.0.0.1",
      PROMETHEUS_PORT: "0",
      PROMETHEUS_PATH: "/alerts",
      PROMETHEUS_TOPIC: targets[0],
      ...env,
    },
    stdio: ["ignore", "ignore", "pipe", "pipe"],
  });
  const channel = child.stdio[3];
  const events = [];
  let stderr = "";
  let exitInfo = null;

  child.stderr.on("data", (chunk) => {
    stderr += chunk.toString("utf8");
  });
  child.on("exit", (codeVal, signal) => {
    exitInfo = { code: codeVal, signal };
  });
  channel.on("error", () => {});

  createInterface({ input: channel }).on("line", (line) => {
    if (!line.trim()) return;
    const msg = JSON.parse(line);
    if (msg.method !== "hyphae/publish") return;
    events.push({ to: msg.params.to, event: msg.params.event });
    channel.write(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { status: "stored" } }) + "\n");
  });
  channel.write(JSON.stringify({ jsonrpc: "2.0", method: "hyphae/hello", params: { protocol: 2, plugin: "prometheus", targets } }) + "\n");

  const stop = () =>
    new Promise((resolve) => {
      try {
        channel.destroy();
      } catch {}
      if (exitInfo !== null) return resolve();
      child.once("exit", () => resolve());
      child.kill("SIGKILL");
    });
  cleanups.push(stop);

  const match = await until(
    () => {
      if (exitInfo !== null) {
        throw new Error(`prometheus exited early (${JSON.stringify(exitInfo)}): ${stderr}`);
      }
      return stderr.match(/listen=(http:\/\/127\.0\.0\.1:\d+\S*)/);
    },
    "prometheus listen URL",
  );

  return {
    url: match[1],
    events,
    stderr: () => stderr,
    stop,
  };
}

function hmacSha256Header(secret, body) {
  return "sha256=" + createHmac("sha256", secret).update(body).digest("hex");
}

function flipLastHexBit(sig) {
  return sig.slice(0, -1) + (parseInt(sig.at(-1), 16) ^ 1).toString(16);
}

// ============================================================================
// Issue #40 (B2): Post-hello uncaught exception / unhandled rejection exits <1.5s
// ============================================================================

test("Issue #40: top-level throw immediately after await mesh.ready exits non-zero <1.5s over fd 3", async () => {
  const proc = spawnFd3Script(
    `
      const { MeshPluginClient } = await import(process.env.SDK_URL);
      const mesh = new MeshPluginClient();
      const hello = await mesh.ready;
      if (!hello.targets.includes("missing-target")) {
        throw new Error("Target 'missing-target' not in configured targets: " + hello.targets.join(", "));
      }
    `,
    { plugin: "telegram", targets: ["ops"] },
  );

  const exit = await proc.waitExit(1_500);
  assert.equal(exit.code, 1, `expected clean exit code 1, got ${JSON.stringify(exit)}`);
  assert.equal(exit.signal, null);
  assert.ok(exit.elapsedMs < 1_500, `expected exit <1500ms, took ${exit.elapsedMs}ms`);
  assert.match(proc.stderr(), /telegram plugin fatal: Target 'missing-target' not in configured targets: ops/);
  assert.ok(!proc.stderr().includes("    at "), `fatal stderr must not include stack trace:\n${proc.stderr()}`);
});

test("Issue #40: delayed uncaughtException post-hello exits non-zero <1.5s while fd 3 is open", async () => {
  const proc = spawnFd3Script(
    `
      const { MeshPluginClient } = await import(process.env.SDK_URL);
      const mesh = new MeshPluginClient();
      await mesh.ready;
      setTimeout(() => {
        throw new Error("delayed-uncaught-sync-crash\\nwith-extra-line");
      }, 80);
    `,
    { plugin: "demo", targets: ["alerts"] },
  );

  const exit = await proc.waitExit(1_500);
  assert.equal(exit.code, 1, `expected exit code 1, got ${JSON.stringify(exit)}`);
  assert.equal(exit.signal, null);
  assert.ok(exit.elapsedMs < 1_500, `expected exit <1500ms, took ${exit.elapsedMs}ms`);
  assert.match(proc.stderr(), /demo plugin fatal: delayed-uncaught-sync-crash with-extra-line/);
  assert.ok(!proc.stderr().includes("    at "));
});

test("Issue #40: delayed unhandledRejection post-hello exits non-zero <1.5s while fd 3 is open", async () => {
  const proc = spawnFd3Script(
    `
      const { MeshPluginClient } = await import(process.env.SDK_URL);
      const mesh = new MeshPluginClient();
      await mesh.ready;
      setTimeout(() => {
        void Promise.reject(new Error("delayed-unhandled-rejection"));
      }, 80);
    `,
    { plugin: "demo", targets: ["alerts"] },
  );

  const exit = await proc.waitExit(1_500);
  assert.equal(exit.code, 1, `expected exit code 1, got ${JSON.stringify(exit)}`);
  assert.equal(exit.signal, null);
  assert.ok(exit.elapsedMs < 1_500, `expected exit <1500ms, took ${exit.elapsedMs}ms`);
  assert.match(proc.stderr(), /demo plugin fatal: delayed-unhandled-rejection/);
  assert.ok(!proc.stderr().includes("    at "));
});

test("Issue #40: real prometheus plugin with mismatched PROMETHEUS_TOPIC exits non-zero <1.5s post-hello", async () => {
  const startedAt = Date.now();
  const child = spawn(process.execPath, [PROMETHEUS_SCRIPT], {
    env: {
      PATH: process.env.PATH,
      HOME: process.env.HOME,
      HYPHAE_FD: "3",
      HYPHAE_PLUGIN: "prometheus",
      PROMETHEUS_HOST: "127.0.0.1",
      PROMETHEUS_PORT: "0",
      PROMETHEUS_BEARER_TOKEN: "valid-tok",
      PROMETHEUS_TOPIC: "nonexistent-topic",
    },
    stdio: ["ignore", "ignore", "pipe", "pipe"],
  });
  const channel = child.stdio[3];
  let stderr = "";
  let exitInfo = null;
  child.stderr.on("data", (chunk) => {
    stderr += chunk.toString("utf8");
  });
  const exitPromise = new Promise((resolve) => {
    child.on("exit", (codeVal, signal) => {
      exitInfo = { code: codeVal, signal, elapsedMs: Date.now() - startedAt };
      resolve(exitInfo);
    });
  });
  channel.on("error", () => {});
  channel.write(JSON.stringify({ jsonrpc: "2.0", method: "hyphae/hello", params: { protocol: 2, plugin: "prometheus", targets: ["alerts"] } }) + "\n");
  cleanups.push(
    () =>
      new Promise((resolve) => {
        try {
          channel.destroy();
        } catch {}
        if (exitInfo !== null) return resolve();
        child.once("exit", () => resolve());
        child.kill("SIGKILL");
      }),
  );

  const exit = await Promise.race([
    exitPromise,
    new Promise((_, reject) => setTimeout(() => reject(new Error(`prometheus hung >1500ms: ${stderr}`)), 1_500)),
  ]);
  assert.equal(exit.code, 1, `expected exit code 1, got ${JSON.stringify(exit)}`);
  assert.equal(exit.signal, null);
  assert.ok(exit.elapsedMs < 1_500);
  assert.match(stderr, /prometheus plugin fatal: Topic 'nonexistent-topic' not in configured targets: alerts/);
});

test("Issue #40: real telegram plugin with mismatched TELEGRAM_TARGET exits non-zero <1.5s post-hello", async () => {
  const startedAt = Date.now();
  const child = spawn(process.execPath, [TELEGRAM_SCRIPT], {
    env: {
      PATH: process.env.PATH,
      HOME: process.env.HOME,
      HYPHAE_FD: "3",
      HYPHAE_PLUGIN: "telegram",
      TELEGRAM_BOT_TOKEN: "123456:fake-test-token-never-sent",
      TELEGRAM_ALLOWED_USERS: "999",
      TELEGRAM_TARGET: "mismatched-target",
    },
    stdio: ["ignore", "ignore", "pipe", "pipe"],
  });
  const channel = child.stdio[3];
  let stderr = "";
  let exitInfo = null;
  child.stderr.on("data", (chunk) => {
    stderr += chunk.toString("utf8");
  });
  const exitPromise = new Promise((resolve) => {
    child.on("exit", (codeVal, signal) => {
      exitInfo = { code: codeVal, signal, elapsedMs: Date.now() - startedAt };
      resolve(exitInfo);
    });
  });
  channel.on("error", () => {});
  channel.write(JSON.stringify({ jsonrpc: "2.0", method: "hyphae/hello", params: { protocol: 2, plugin: "telegram", targets: ["ops"] } }) + "\n");
  cleanups.push(
    () =>
      new Promise((resolve) => {
        try {
          channel.destroy();
        } catch {}
        if (exitInfo !== null) return resolve();
        child.once("exit", () => resolve());
        child.kill("SIGKILL");
      }),
  );

  const exit = await Promise.race([
    exitPromise,
    new Promise((_, reject) => setTimeout(() => reject(new Error(`telegram hung >1500ms: ${stderr}`)), 1_500)),
  ]);
  assert.equal(exit.code, 1, `expected exit code 1, got ${JSON.stringify(exit)}`);
  assert.equal(exit.signal, null);
  assert.ok(exit.elapsedMs < 1_500);
  assert.match(stderr, /telegram plugin fatal: Target 'mismatched-target' not in configured targets: ops/);
  assert.ok(!stderr.includes("123456:fake-test-token-never-sent"), "bot token must never leak to stderr");
});

test("Issue #40: closing fd 3 gracefully post-hello still exits 0 cleanly", async () => {
  const proc = spawnFd3Script(
    `
      const { MeshPluginClient } = await import(process.env.SDK_URL);
      const mesh = new MeshPluginClient();
      await mesh.ready;
      console.error("READY");
    `,
    { plugin: "graceful", targets: ["ops"] },
  );
  await until(() => proc.stderr().includes("READY"), "child ready");
  proc.channel.end();

  const exit = await proc.waitExit(1_500);
  assert.equal(exit.code, 0, `expected clean exit code 0, got ${JSON.stringify(exit)}`);
  assert.equal(exit.signal, null);
});

test("Issue #40: LoopbackTcp fatal error redacts HYPHAE_PLUGIN_TOKEN from stderr and exits 1 <1.5s", async () => {
  const secretToken = "tok_secret_9876543210abcdef";
  const server = net.createServer((socket) => {
    const rl = createInterface({ input: socket });
    rl.once("line", () => {
      socket.write(JSON.stringify({ jsonrpc: "2.0", method: "hyphae/hello", params: { protocol: 2, plugin: "tcp-demo", targets: ["ops"] } }) + "\n");
    });
    socket.on("error", () => {});
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  cleanups.push(() => new Promise((resolve) => server.close(resolve)));
  const port = server.address().port;

  const startedAt = Date.now();
  const child = spawn(
    process.execPath,
    [
      "--input-type=module",
      "-e",
      `
        const { MeshPluginClient } = await import(process.env.SDK_URL);
        const mesh = new MeshPluginClient();
        await mesh.ready;
        throw new Error("boom with secret " + process.env.LEAK_COPY);
      `,
    ],
    {
      env: {
        PATH: process.env.PATH,
        HOME: process.env.HOME,
        HYPHAE_PLUGIN: "tcp-demo",
        HYPHAE_PLUGIN_ADDR: `127.0.0.1:${port}`,
        HYPHAE_PLUGIN_TOKEN: secretToken,
        LEAK_COPY: secretToken,
        SDK_URL,
      },
      stdio: ["ignore", "ignore", "pipe"],
    },
  );
  let stderr = "";
  let exitInfo = null;
  child.stderr.on("data", (chunk) => {
    stderr += chunk.toString("utf8");
  });
  const exitPromise = new Promise((resolve) => {
    child.on("exit", (codeVal, signal) => {
      exitInfo = { code: codeVal, signal, elapsedMs: Date.now() - startedAt };
      resolve(exitInfo);
    });
  });
  cleanups.push(
    () =>
      new Promise((resolve) => {
        if (exitInfo !== null) return resolve();
        child.once("exit", () => resolve());
        child.kill("SIGKILL");
      }),
  );

  const exit = await Promise.race([
    exitPromise,
    new Promise((_, reject) => setTimeout(() => reject(new Error(`tcp child hung: ${stderr}`)), 1_500)),
  ]);
  assert.equal(exit.code, 1);
  assert.ok(stderr.includes("tcp-demo plugin fatal: boom with secret [REDACTED]"), `unexpected stderr: ${stderr}`);
  assert.ok(!stderr.includes(secretToken), "handshake token must never leak to stderr");
});

test("Issue #40: handleFatalErrors: false opts out of process-wide exit handler for unit tests", async () => {
  const proc = spawnFd3Script(
    `
      const { MeshPluginClient } = await import(process.env.SDK_URL);
      process.on("unhandledRejection", (err) => {
        console.error("CUSTOM_CAUGHT:" + err.message);
        process.exit(42);
      });
      const mesh = new MeshPluginClient({ handleFatalErrors: false });
      await mesh.ready;
      void Promise.reject(new Error("custom-handled"));
    `,
    { plugin: "optout", targets: ["ops"] },
  );

  const exit = await proc.waitExit(1_500);
  assert.equal(exit.code, 42);
  assert.match(proc.stderr(), /CUSTOM_CAUGHT:custom-handled/);
});

// ============================================================================
// Issue #41: Top-level CloudEvent extensions (`alertname`, `severity`, `service`)
// ============================================================================

test("Issue #41: prometheus emits top-level alertname, severity, and service CloudEvent extensions matching Rust", async () => {
  const bearer = "prom-ext-bearer-secret";
  const prom = await startPrometheusPlugin({ PROMETHEUS_BEARER_TOKEN: bearer });

  const longAttr = "x".repeat(257);
  const payload = {
    version: "4",
    status: "firing",
    receiver: "oncall",
    commonLabels: {
      cluster: "prod-eu",
      service: "checkout-api",
    },
    alerts: [
      {
        status: "firing",
        fingerprint: "fp-common-svc",
        labels: {
          alertname: "CpuHot",
          severity: "warning",
        },
        startsAt: "2026-11-26T12:00:00Z",
      },
      {
        status: "resolved",
        fingerprint: "fp-override-svc",
        labels: {
          alertname: "DiskFull",
          severity: "critical",
          service: "payments-api",
        },
        startsAt: "2026-11-26T11:00:00Z",
        endsAt: "2026-11-26T12:05:00Z",
      },
      {
        status: "firing",
        fingerprint: "fp-job-fallback",
        labels: {
          alertname: "NodeDown",
          severity: "page",
          service: "   ",
          job: "node-exporter",
        },
        startsAt: "2026-11-26T12:01:00Z",
      },
      {
        status: "firing",
        fingerprint: "fp-defaults-no-svc",
        labels: {
          alertname: "  ",
          severity: "",
          service: "",
        },
        startsAt: "2026-11-26T12:02:00Z",
      },
      {
        status: "firing",
        fingerprint: "fp-oversized-ext",
        labels: {
          alertname: longAttr,
          severity: "info",
          service: longAttr,
        },
        startsAt: "2026-11-26T12:03:00Z",
      },
    ],
  };

  const res = await fetch(prom.url, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${bearer}`,
    },
    body: JSON.stringify(payload),
  });
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.deepEqual(body, { ok: true, alerts: 5 });
  assert.equal(prom.events.length, 5);

  // 1. commonLabels.service inherited
  const ev0 = prom.events[0].event;
  assert.equal(ev0.type, "io.prometheus.alert.firing");
  assert.equal(ev0.alertname, "CpuHot");
  assert.equal(ev0.severity, "warning");
  assert.equal(ev0.service, "checkout-api");
  assert.equal(ev0.data.alertname, "CpuHot");
  assert.equal(ev0.data.severity, "warning");
  assert.equal(ev0.data.service, "checkout-api");

  // 2. per-alert labels.service overrides commonLabels.service
  const ev1 = prom.events[1].event;
  assert.equal(ev1.type, "io.prometheus.alert.resolved");
  assert.equal(ev1.alertname, "DiskFull");
  assert.equal(ev1.severity, "critical");
  assert.equal(ev1.service, "payments-api");

  // 3. whitespace-only labels.service falls back to labels.job
  const ev2 = prom.events[2].event;
  assert.equal(ev2.alertname, "NodeDown");
  assert.equal(ev2.severity, "page");
  assert.equal(ev2.service, "node-exporter");

  // 4. empty alertname/severity default to "Alert"/"unknown"; empty service omitted entirely
  const ev3 = prom.events[3].event;
  assert.equal(ev3.alertname, "Alert");
  assert.equal(ev3.severity, "unknown");
  assert.equal("service" in ev3, false, "empty service must not be emitted as top-level extension");
  assert.equal("service" in ev3.data, false);

  // 5. >256-byte alertname/service omitted from top-level extensions (matching Rust MAX_ATTRIBUTE_CHARS)
  const ev4 = prom.events[4].event;
  assert.equal("alertname" in ev4, false, "oversized alertname must be omitted from top-level extensions");
  assert.equal(ev4.severity, "info");
  assert.equal("service" in ev4, false, "oversized service must be omitted from top-level extensions");
  assert.equal(ev4.data.alertname, longAttr);

  await prom.stop();
});

// ============================================================================
// Issue #42: Bearer OR Basic auth when both are configured + HMAC preservation
// ============================================================================

test("Issue #42: prometheus accepts EITHER valid Bearer OR valid Basic when both are configured", async () => {
  const bearer = "prom-dual-bearer-tok-123";
  const basicCreds = "alertmgr:s3cr3t-pass";
  const basicB64 = Buffer.from(basicCreds, "utf8").toString("base64");

  const prom = await startPrometheusPlugin({
    PROMETHEUS_BEARER_TOKEN: bearer,
    PROMETHEUS_BASIC_AUTH: basicCreds,
  });

  const makePayload = (fp) =>
    JSON.stringify({
      alerts: [
        {
          status: "firing",
          fingerprint: fp,
          labels: { alertname: "DualAuthCheck", severity: "warning" },
          startsAt: "2026-11-26T12:00:00Z",
        },
      ],
    });

  // Valid Bearer passes (200)
  const rBearer = await fetch(prom.url, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${bearer}` },
    body: makePayload("fp-bearer-ok"),
  });
  assert.equal(rBearer.status, 200);

  // Valid Basic passes (200)
  const rBasic = await fetch(prom.url, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Basic ${basicB64}` },
    body: makePayload("fp-basic-ok"),
  });
  assert.equal(rBasic.status, 200);

  // Lowercase scheme names pass (RFC 7235 case-insensitive auth scheme)
  const rLowerBearer = await fetch(prom.url, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `bearer ${bearer}` },
    body: makePayload("fp-bearer-lower"),
  });
  assert.equal(rLowerBearer.status, 200);

  const rLowerBasic = await fetch(prom.url, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `basic ${basicB64}` },
    body: makePayload("fp-basic-lower"),
  });
  assert.equal(rLowerBasic.status, 200);

  assert.equal(prom.events.length, 4);

  // Wrong Bearer fails (401)
  const rBadBearer = await fetch(prom.url, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${bearer}X` },
    body: makePayload("fp-bad-bearer"),
  });
  assert.equal(rBadBearer.status, 401);

  // Wrong Basic fails (401)
  const badBasicB64 = Buffer.from("alertmgr:wrong-pass", "utf8").toString("base64");
  const rBadBasic = await fetch(prom.url, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Basic ${badBasicB64}` },
    body: makePayload("fp-bad-basic"),
  });
  assert.equal(rBadBasic.status, 401);

  // Missing Authorization header fails (401)
  const rMissing = await fetch(prom.url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: makePayload("fp-missing-auth"),
  });
  assert.equal(rMissing.status, 401);

  // Malformed / unknown scheme fails (401)
  for (const badHdr of ["Bearer ", "Basic ", "Digest realm=x", bearer, basicB64]) {
    const r = await fetch(prom.url, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: badHdr },
      body: makePayload("fp-malformed"),
    });
    assert.equal(r.status, 401, `expected 401 for Authorization=${JSON.stringify(badHdr)}`);
  }

  // None of the unauthorized requests may publish events
  assert.equal(prom.events.length, 4);

  await prom.stop();
});

test("Issue #42: Bearer OR Basic combined with HMAC-SHA256 still enforces signature fail-closed", async () => {
  const bearer = "prom-tri-bearer";
  const basicCreds = "ops:tri-pass";
  const basicB64 = Buffer.from(basicCreds, "utf8").toString("base64");
  const secret = "prom-tri-hmac-secret";

  const prom = await startPrometheusPlugin({
    PROMETHEUS_BEARER_TOKEN: bearer,
    PROMETHEUS_BASIC_AUTH: basicCreds,
    PROMETHEUS_WEBHOOK_SECRET: secret,
  });

  const body = JSON.stringify({
    alerts: [
      {
        status: "firing",
        fingerprint: "fp-tri-1",
        labels: { alertname: "HmacGuard", severity: "critical" },
        startsAt: "2026-11-26T12:00:00Z",
      },
    ],
  });
  const goodSig = hmacSha256Header(secret, body);
  const badSig = flipLastHexBit(goodSig);

  // Valid Bearer + valid HMAC -> 200
  const ok1 = await fetch(prom.url, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${bearer}`,
      "x-webhook-signature-256": goodSig,
    },
    body,
  });
  assert.equal(ok1.status, 200);

  // Valid Basic + valid HMAC -> 200
  const ok2 = await fetch(prom.url, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Basic ${basicB64}`,
      "x-webhook-signature-256": goodSig,
    },
    body,
  });
  assert.equal(ok2.status, 200);

  // Valid Bearer + 1-bit flipped HMAC -> 401
  const failBadSig = await fetch(prom.url, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${bearer}`,
      "x-webhook-signature-256": badSig,
    },
    body,
  });
  assert.equal(failBadSig.status, 401);

  // Valid Basic + missing HMAC -> 401
  const failNoSig = await fetch(prom.url, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Basic ${basicB64}`,
    },
    body,
  });
  assert.equal(failNoSig.status, 401);

  // Wrong Bearer + valid HMAC -> 401
  const failBadAuth = await fetch(prom.url, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: "Bearer wrong",
      "x-webhook-signature-256": goodSig,
    },
    body,
  });
  assert.equal(failBadAuth.status, 401);

  assert.equal(prom.events.length, 2);
  await prom.stop();
});

test("Issue #42: prometheus still refuses unsigned startup on non-loopback and without PROMETHEUS_ALLOW_UNSIGNED=1", async () => {
  for (const [label, env, expectedRe] of [
    [
      "non-loopback unsigned",
      { PROMETHEUS_HOST: "0.0.0.0", PROMETHEUS_PORT: "0", PROMETHEUS_ALLOW_UNSIGNED: "1" },
      /non-loopback host/,
    ],
    [
      "loopback unsigned without opt-in",
      { PROMETHEUS_HOST: "127.0.0.1", PROMETHEUS_PORT: "0" },
      /PROMETHEUS_ALLOW_UNSIGNED=1/,
    ],
  ]) {
    const child = spawn(process.execPath, [PROMETHEUS_SCRIPT], {
      env: { PATH: process.env.PATH, HOME: process.env.HOME, ...env },
      stdio: ["ignore", "ignore", "pipe"],
    });
    let stderr = "";
    child.stderr.on("data", (d) => {
      stderr += d.toString("utf8");
    });
    const code = await new Promise((resolve) => child.on("exit", resolve));
    assert.notEqual(code, 0, `${label} must refuse to start`);
    assert.match(stderr, expectedRe, `${label} stderr mismatch: ${stderr}`);
  }
});

// ============================================================================
// Issue #29: MeshPluginClient `system.wake` JSON-RPC 2.0 notification dispatch
// ============================================================================

test("Issue #29: MeshPluginClient dispatches system.wake notification to onWake({ sleptMs }) with zero spurious reply", async () => {
  const proc = spawnFd3Script(
    `
      const { MeshPluginClient } = await import(process.env.SDK_URL);
      const wakes = [];
      const mesh = new MeshPluginClient({
        onWake: ({ sleptMs }) => {
          wakes.push(sleptMs);
          console.error("WAKE_CTOR:" + sleptMs);
        },
      });
      await mesh.ready;
      console.error("READY");
      setTimeout(() => {
        mesh.onWake(({ sleptMs }) => {
          console.error("WAKE_METHOD:" + sleptMs);
        });
        console.error("SWAPPED");
      }, 150);
    `,
    { plugin: "wake-sdk-test", targets: ["ops"] },
  );

  const inboundFrames = [];
  createInterface({ input: proc.channel }).on("line", (line) => {
    if (line.trim()) inboundFrames.push(line);
  });

  await until(() => proc.stderr().includes("READY"), "child ready");
  proc.channel.write(
    JSON.stringify({ jsonrpc: "2.0", method: "system.wake", params: { sleptMs: 600_000 } }) + "\n",
  );
  await until(() => proc.stderr().includes("WAKE_CTOR:600000"), "constructor onWake callback");

  await until(() => proc.stderr().includes("SWAPPED"), "onWake swapped");
  proc.channel.write(
    JSON.stringify({ jsonrpc: "2.0", method: "system.wake", params: { sleptMs: 42_500 } }) + "\n",
  );
  await until(() => proc.stderr().includes("WAKE_METHOD:42500"), "method onWake callback");

  assert.deepEqual(inboundFrames, [], "system.wake notification must not emit any response frame");
  proc.channel.end();
  const exit = await proc.waitExit(1_500);
  assert.equal(exit.code, 0);
});

test("Issue #29: MeshPluginClient safely ignores system.wake when no onWake handler is configured", async () => {
  const proc = spawnFd3Script(
    `
      const { MeshPluginClient } = await import(process.env.SDK_URL);
      const mesh = new MeshPluginClient();
      await mesh.ready;
      console.error("READY");
      setTimeout(async () => {
        const ack = await mesh.send("ops", {
          specversion: "1.0",
          id: "post-wake-ev",
          source: "test/no-wake-handler",
          type: "to.hyphae.test.ok",
          datacontenttype: "application/json",
          data: { ok: true },
        });
        console.error("ACK:" + ack.status);
      }, 80);
    `,
    { plugin: "no-wake-test", targets: ["ops"] },
  );

  createInterface({ input: proc.channel }).on("line", (line) => {
    if (!line.trim()) return;
    const msg = JSON.parse(line);
    if (msg.method === "hyphae/publish") {
      proc.channel.write(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { status: "stored" } }) + "\n");
    }
  });

  await until(() => proc.stderr().includes("READY"), "child ready");
  proc.channel.write(
    JSON.stringify({ jsonrpc: "2.0", method: "system.wake", params: { sleptMs: 120_000 } }) + "\n",
  );
  await until(() => proc.stderr().includes("ACK:stored"), "post-wake send/ack succeeded");

  proc.channel.end();
  const exit = await proc.waitExit(1_500);
  assert.equal(exit.code, 0);
});

test("Issue #29: telegram plugin aborts stalled getUpdates long-poll immediately on system.wake", async () => {
  const http = await import("node:http");
  let pollCount = 0;
  let stalledRes = null;
  let firstPollStarted = false;

  const server = http.createServer((req, res) => {
    if (req.url?.endsWith("/getUpdates")) {
      pollCount += 1;
      if (pollCount === 1) {
        firstPollStarted = true;
        stalledRes = res;
        // Hold poll #1 open forever to simulate a half-open socket across laptop sleep.
        return;
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(
        JSON.stringify({
          ok: true,
          result:
            pollCount === 2
              ? [
                  {
                    update_id: 9001,
                    message: {
                      message_id: 77,
                      date: Math.floor(Date.now() / 1000),
                      chat: { id: 4242, type: "private" },
                      from: { id: 999, username: "alice", first_name: "Alice" },
                      text: "arrived-after-telegram-wake",
                    },
                  },
                ]
              : [],
        }),
      );
      return;
    }
    res.writeHead(404);
    res.end();
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  cleanups.push(
    () =>
      new Promise((resolve) => {
        try {
          stalledRes?.destroy();
        } catch {}
        server.closeAllConnections?.();
        server.close(() => resolve());
      }),
  );
  const { port } = server.address();

  const child = spawn(process.execPath, [TELEGRAM_SCRIPT], {
    env: {
      PATH: process.env.PATH,
      HOME: process.env.HOME,
      HYPHAE_FD: "3",
      HYPHAE_PLUGIN: "telegram",
      TELEGRAM_BOT_TOKEN: "123456:test-wake-token",
      TELEGRAM_ALLOWED_USERS: "999",
      TELEGRAM_TARGET: "ops",
      TELEGRAM_API_BASE: `http://127.0.0.1:${port}`,
    },
    stdio: ["ignore", "ignore", "pipe", "pipe"],
  });
  const channel = child.stdio[3];
  const events = [];
  let exitInfo = null;
  child.on("exit", (code, signal) => {
    exitInfo = { code, signal };
  });
  channel.on("error", () => {});
  createInterface({ input: channel }).on("line", (line) => {
    if (!line.trim()) return;
    const msg = JSON.parse(line);
    if (msg.method === "hyphae/publish") {
      events.push(msg.params.event);
      channel.write(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { status: "stored" } }) + "\n");
    }
  });
  channel.write(JSON.stringify({ jsonrpc: "2.0", method: "hyphae/hello", params: { protocol: 2, plugin: "telegram", targets: ["ops"] } }) + "\n");
  cleanups.push(
    () =>
      new Promise((resolve) => {
        try {
          channel.destroy();
        } catch {}
        if (exitInfo !== null) return resolve();
        child.once("exit", () => resolve());
        child.kill("SIGKILL");
      }),
  );

  await until(() => firstPollStarted, "first telegram getUpdates poll stalled");
  assert.equal(events.length, 0);

  const t0 = Date.now();
  channel.write(
    JSON.stringify({ jsonrpc: "2.0", method: "system.wake", params: { sleptMs: 300_000 } }) + "\n",
  );
  await until(() => events.length >= 1, "telegram post-wake event", 1_500);
  const elapsed = Date.now() - t0;
  assert.ok(elapsed < 1_000, `telegram wake abort took ${elapsed}ms, expected <1000ms`);
  assert.equal(events[0].data.text, "arrived-after-telegram-wake");
  assert.ok(pollCount >= 2);
});

// Minimal RFC 6455 text frame encoder (server -> client, unmasked).
function wsTextFrame(str) {
  const payload = Buffer.from(str, "utf8");
  if (payload.length < 126) {
    return Buffer.concat([Buffer.from([0x81, payload.length]), payload]);
  }
  const hdr = Buffer.alloc(4);
  hdr[0] = 0x81;
  hdr[1] = 126;
  hdr.writeUInt16BE(payload.length, 2);
  return Buffer.concat([hdr, payload]);
}

test("Issue #29: slack plugin aborts stalled Socket Mode WebSocket immediately on system.wake", async () => {
  let openCalls = 0;
  let wsConns = 0;
  const openSockets = new Set();
  let firstWsOpen = false;

  const server = http.createServer((req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    if (req.url?.endsWith("/auth.test")) {
      res.end(JSON.stringify({ ok: true, user_id: "UBOT1", team_id: "TWAKE" }));
      return;
    }
    if (req.url?.endsWith("/apps.connections.open")) {
      openCalls += 1;
      const { port } = server.address();
      res.end(JSON.stringify({ ok: true, url: `ws://127.0.0.1:${port}/ws?n=${openCalls}` }));
      return;
    }
    res.end(JSON.stringify({ ok: false, error: "not_found" }));
  });

  server.on("upgrade", (req, socket) => {
    const key = req.headers["sec-websocket-key"];
    const accept = createHash("sha1")
      .update(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")
      .digest("base64");
    socket.write(
      "HTTP/1.1 101 Switching Protocols\r\n" +
        "Upgrade: websocket\r\n" +
        "Connection: Upgrade\r\n" +
        `Sec-WebSocket-Accept: ${accept}\r\n\r\n`,
    );
    socket.on("error", () => {});
    openSockets.add(socket);
    socket.on("close", () => openSockets.delete(socket));
    wsConns += 1;
    if (wsConns === 1) {
      // Hold WebSocket #1 open silently (never reply to close frames either!) to simulate half-open socket.
      firstWsOpen = true;
    } else if (wsConns === 2) {
      // On reconnected WebSocket #2 after wake, push a Slack DM event!
      const envelope = {
        envelope_id: "env-wake-1",
        type: "events_api",
        payload: {
          event: {
            type: "message",
            channel_type: "im",
            user: "UALICE",
            channel: "DWAKE1",
            ts: "1700000001.000100",
            text: "arrived-after-slack-wake",
          },
        },
      };
      socket.write(wsTextFrame(JSON.stringify(envelope)));
    }
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  cleanups.push(
    () =>
      new Promise((resolve) => {
        for (const s of openSockets) {
          try {
            s.destroy();
          } catch {}
        }
        openSockets.clear();
        server.closeAllConnections?.();
        server.close(() => resolve());
      }),
  );
  const { port } = server.address();

  const child = spawn(process.execPath, [SLACK_SCRIPT], {
    env: {
      PATH: process.env.PATH,
      HOME: process.env.HOME,
      HYPHAE_FD: "3",
      HYPHAE_PLUGIN: "slack",
      SLACK_APP_TOKEN: "xapp-test-wake-token",
      SLACK_BOT_TOKEN: "xoxb-test-wake-token",
      SLACK_ALLOWED_USERS: "UALICE",
      SLACK_TARGET: "ops",
      SLACK_API_BASE: `http://127.0.0.1:${port}`,
    },
    stdio: ["ignore", "ignore", "pipe", "pipe"],
  });
  const channel = child.stdio[3];
  const events = [];
  let exitInfo = null;
  child.on("exit", (code, signal) => {
    exitInfo = { code, signal };
  });
  channel.on("error", () => {});
  createInterface({ input: channel }).on("line", (line) => {
    if (!line.trim()) return;
    const msg = JSON.parse(line);
    if (msg.method === "hyphae/publish") {
      events.push(msg.params.event);
      channel.write(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { status: "stored" } }) + "\n");
    }
  });
  channel.write(JSON.stringify({ jsonrpc: "2.0", method: "hyphae/hello", params: { protocol: 2, plugin: "slack", targets: ["ops"] } }) + "\n");
  cleanups.push(
    () =>
      new Promise((resolve) => {
        try {
          channel.destroy();
        } catch {}
        if (exitInfo !== null) return resolve();
        child.once("exit", () => resolve());
        child.kill("SIGKILL");
      }),
  );

  await until(() => firstWsOpen, "first slack Socket Mode WS connected");
  assert.equal(events.length, 0);

  const t0 = Date.now();
  channel.write(
    JSON.stringify({ jsonrpc: "2.0", method: "system.wake", params: { sleptMs: 600_000 } }) + "\n",
  );
  await until(() => events.length >= 1, "slack post-wake event", 1_500);
  const elapsed = Date.now() - t0;
  assert.ok(elapsed < 1_000, `slack wake recycle took ${elapsed}ms, expected <1000ms`);
  assert.equal(events[0].data.text, "arrived-after-slack-wake");
  assert.ok(wsConns >= 2);
});

async function startSlackFixture(env, { updateErrors = [], publishErrors = [], roots = {} } = {}) {
  const updates = [];
  const history = [];
  const events = [];
  const posts = [];
  const responses = new Map();
  let socket;
  let requestId = 0;
  const server = http.createServer(async (req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    const apiResponses = {
      "/auth.test": { ok: true, user_id: "UBOT", team_id: "TDEMO" },
      "/apps.connections.open": { ok: true, url: `ws://127.0.0.1:${server.address().port}/ws` },
    };
    if (req.url === "/conversations.history") {
      const body = [];
      for await (const chunk of req) body.push(chunk);
      const query = Object.fromEntries(new URLSearchParams(Buffer.concat(body).toString()));
      history.push(query);
      res.end(JSON.stringify(roots[query.channel + ":" + query.oldest] ?? { ok: false, error: "missing_scope" }));
      return;
    }
    if (req.url === "/chat.update") {
      const body = [];
      for await (const chunk of req) body.push(chunk);
      updates.push(JSON.parse(Buffer.concat(body).toString()));
      res.end(JSON.stringify(updateErrors.shift() ?? { ok: true }));
      return;
    }
    if (req.url === "/chat.postMessage") {
      const body = [];
      for await (const chunk of req) body.push(chunk);
      posts.push(JSON.parse(Buffer.concat(body).toString()));
      res.end(JSON.stringify({ ok: true, ts: "99.01" }));
      return;
    }
    res.end(JSON.stringify(apiResponses[req.url] ?? { ok: false, error: "not_found" }));
  });
  server.on("upgrade", (req, connection) => {
    socket = connection;
    socket.on("error", () => {});
    const accept = createHash("sha1")
      .update(req.headers["sec-websocket-key"] + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")
      .digest("base64");
    socket.write(
      "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
        `Sec-WebSocket-Accept: ${accept}\r\n\r\n`,
    );
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  cleanups.push(() => new Promise((resolve) => {
    socket?.destroy();
    server.closeAllConnections?.();
    server.close(resolve);
  }));

  const child = spawnFd3Script("await import(process.env.SLACK_SCRIPT_URL)", {
    plugin: "slack",
    env: {
      SLACK_SCRIPT_URL: pathToFileURL(SLACK_SCRIPT).href,
      SLACK_APP_TOKEN: "xapp-fixture",
      SLACK_BOT_TOKEN: "xoxb-fixture",
      SLACK_API_BASE: `http://127.0.0.1:${server.address().port}`,
      ...env,
    },
  });
  const send = (msg) => child.channel.write(JSON.stringify({ jsonrpc: "2.0", ...msg }) + "\n");
  createInterface({ input: child.channel }).on("line", (line) => {
    const msg = JSON.parse(line);
    if (msg.method === "hyphae/publish") {
      events.push(msg.params.event);
      const error = publishErrors.shift();
      if (error) send({ id: msg.id, error });
      else send({ id: msg.id, result: { status: "stored" } });
    } else if (msg.id !== undefined) {
      responses.set(msg.id, msg);
    }
  });
  await until(() => socket, "Slack Socket Mode fixture connected");

  return {
    events, posts, updates, history, stderr: child.stderr,
    async stop() { child.child.kill("SIGTERM"); await child.waitExit(); },
    envelope(envelope) { socket.write(wsTextFrame(JSON.stringify(envelope))); },
    deliveryFailed(reason) {
      send({ method: "hyphae/deliveryFailed", params: { target: "ops", reason } });
    },
    deliver(...items) {
      socket.write(Buffer.concat(items.map((event) => wsTextFrame(JSON.stringify({
        type: "events_api",
        payload: { event },
      })))));
    },
    async post(params) {
      const id = ++requestId;
      send({ id, method: "hyphae/post", params: { target: "ops", params } });
      return until(() => responses.get(id), `Slack post result ${id}`);
    },
  };
}

function slackEvent(user, channel, ts, type = "message") {
  return { type, user, channel, ts, text: ts, channel_type: channel.startsWith("D") ? "im" : "channel" };
}

test("Slack records an external bot choice before forwarding, then retries the pending publish", async () => {
  const dir = mkdtempSync(join(tmpdir(), "hyp-slack-action-"));
  cleanups.push(() => rmSync(dir, { recursive: true, force: true }));
  const file = join(dir, "allowlist.json");
  writeFileSync(file, JSON.stringify({ owner: { id: "UALICE", name: "Demo owner" }, allowed: [], channels: ["COPS"] }));
  const env = { HYPHAE_STATE_DIR: dir, SLACK_ALLOWLIST_FILE: file };
  let slack = await startSlackFixture(env, {
    updateErrors: [{ ok: false, error: "rate_limited" }],
    publishErrors: [{ code: -32001, message: "fixture failure" }],
  });
  const button = { type: "button", action_id: "slot_a", value: "tue-10", text: { type: "plain_text", text: "Tue 10:00" } };
  const payload = {
    type: "block_actions", team: { id: "TDEMO" }, user: { id: "UALICE" },
    channel: { id: "COPS" }, container: { type: "message", channel_id: "COPS", message_ts: "100.01" },
    message: { user: "UBOT", ts: "100.01", text: "Pick a time", thread_ts: "99.01",
      blocks: [{ type: "section", text: { type: "plain_text", text: "Pick a time" }, accessory: button },
        { type: "actions", block_id: "choices", elements: [button] }] },
    actions: [{ ...button, text: undefined, action_ts: "101.01", block_id: "choices" }],
    response_url: "https://example.invalid/PRIVATE",
  };
  function click(overrides = {}) {
    slack.envelope({ type: "interactive", envelope_id: "test", payload: { ...payload, ...overrides } });
  }
  click({ team: { id: "TOTHER" } });
  click({ message: { ...payload.message, user: "UOTHERBOT" } });
  click({ user: { id: "UBOB" } });
  click({ channel: { id: "COTHER" } });
  click({ actions: [{ ...payload.actions[0], action_id: "forged" }] });
  click();
  await until(() => slack.stderr().includes("unacknowledged"), "Slack update failure");
  assert.equal(slack.events.length, 0);
  assert.equal(slack.updates.length, 1);
  click();
  await until(() => slack.stderr().split("unacknowledged").length === 3, "mesh delivery failed after update");
  // A different control with the same Slack timestamp cannot finish a prior winner’s pending publish.
  const otherButton = { ...button, value: "other" };
  click({ message: { ...payload.message, blocks: [{ type: "actions", block_id: "choices", elements: [otherButton] }] },
    actions: [{ ...payload.actions[0], value: "other" }] });
  await slack.post({ text: "fixture barrier", channel: "COPS" });
  assert.equal(slack.events.length, 1);
  const first = slack;
  await first.stop();
  slack = await startSlackFixture(env);
  click();
  await until(() => slack.events.length === 1, "retry pending publish after process restart");
  click({ actions: [{ ...payload.actions[0], action_ts: "101.02" }] });
  await slack.post({ text: "fixture barrier", channel: "COPS" });
  assert.equal(first.updates.length, 2);
  assert.equal(slack.updates.length, 0);
  assert.equal(slack.events.length, 1);
  assert.equal(slack.events[0].id, first.events[0].id);
  assert.equal(slack.events[0].data.role, "owner");
  assert.equal(slack.events[0].data.from_name, "Demo owner");
  assert.equal(slack.events[0].data.text, "[clicked] Tue 10:00 (action_id=slot_a, value=tue-10)");
  assert.equal(slack.events[0].data.via, "action");
  assert.equal(slack.events[0].data.thread_ts, "99.01");
  assert.doesNotMatch(JSON.stringify([slack.events, slack.updates, slack.stderr()]), /PRIVATE/);
  assert.deepEqual(first.updates[1], { channel: "COPS", ts: "100.01", text: "Pick a time", blocks: [
    { type: "section", text: { type: "plain_text", text: "Pick a time" } },
    { type: "context", elements: [{ type: "mrkdwn", text: ":white_check_mark: *Tue 10:00*, chosen by <@UALICE>" }] },
  ] });
});

test("Slack handles external section selects and acknowledges URL buttons without recording them", async () => {
  const slack = await startSlackFixture({ SLACK_ALLOWED_USERS: "UALICE" });
  const selected = { value: "slot-a", text: { type: "plain_text", text: "Slot <A>" } };
  const select = { type: "static_select", action_id: "q1", options: [selected] };
  const link = { type: "button", action_id: "visit", url: "https://example.invalid/path" };
  function click(element, data, stamp) {
    slack.envelope({ type: "interactive", envelope_id: stamp, payload: {
      type: "block_actions", team: { id: "TDEMO" }, user: { id: "UALICE" }, channel: { id: "DDEMO" },
      container: { type: "message", channel_id: "DDEMO", message_ts: "10.1" },
      message: { user: "UBOT", ts: "10.1", text: "Choose", blocks: [
        { type: "section", block_id: "choices", text: { type: "plain_text", text: "Choose" }, accessory: element },
      ] },
      actions: [{ type: element.type, action_id: element.action_id, block_id: "choices", action_ts: stamp, ...data }],
    } });
  }
  click(link, {}, "11.1");
  click(select, { selected_option: selected }, "12.1");
  click(select, { selected_option: selected }, "13.1");
  await until(() => slack.events.length > 0, "section select");
  await slack.post({ text: "fixture barrier", channel: "DDEMO" });
  assert.equal(slack.events.length, 1);
  assert.equal(slack.events[0].data.text, "[clicked] Slot <A> (action_id=q1, value=slot-a)");
  assert.equal(slack.events[0].data.thread_ts, "-");
  assert.equal(slack.updates.length, 1);
  assert.equal(slack.updates[0].blocks[1].elements[0].text, ":white_check_mark: *Slot &lt;A&gt;*, chosen by <@UALICE>");
});

test("Slack persists external same-bot threads and verifies allowed replies to unknown roots", async () => {
  const dir = mkdtempSync(join(tmpdir(), "hyp-slack-threads-"));
  cleanups.push(() => rmSync(dir, { recursive: true, force: true }));
  const env = { HYPHAE_STATE_DIR: dir, SLACK_ALLOWED_USERS: "UALICE", SLACK_ALLOWED_CHANNELS: "COPS,CWATCH",
    SLACK_TOP_LEVEL_CHANNELS: "CWATCH,CDENIED" };
  const first = await startSlackFixture(env);
  first.deliver(
    { ...slackEvent("UBOT", "COPS", "10.1"), bot_id: "BSAME", subtype: "bot_message" },
    { ...slackEvent("UBOT", "COPS", "10.2"), thread_ts: "9.1", bot_id: "BSAME" },
    slackEvent("UALICE", "COPS", "11.1", "app_mention"),
  );
  await until(() => first.events.length === 1, "own bot posts are tracked silently");
  await first.stop();
  const slack = await startSlackFixture(env, { roots: {
    "COPS:8.1": { ok: true, messages: [{ user: "UBOT", ts: "8.1" }] },
    "COPS:7.1": { ok: true, messages: [{ user: "UOTHER", ts: "7.1" }] },
    "COPS:6.1": { ok: true, messages: [{ user: "UBOT", ts: "6.2" }] },
  } });
  const reply = (ts, thread_ts, user = "UALICE", channel = "COPS") => ({ ...slackEvent(user, channel, ts), thread_ts });
  slack.deliver(reply("20.1", "10.1"), reply("20.2", "9.1"), reply("20.3", "11.1"),
    reply("20.4", "8.1"), reply("20.5", "7.1"), reply("20.6", "6.1"), reply("20.7", "5.1"),
    reply("20.8", "4.1", "UDENIED"), reply("20.9", "3.1", "UALICE", "CDENIED"),
    slackEvent("UALICE", "COPS", "21.1"), slackEvent("UALICE", "CDENIED", "21.2"),
    slackEvent("UALICE", "CWATCH", "21.3"), slackEvent("UALICE", "CWATCH", "21.3", "app_mention"),
    slackEvent("UALICE", "COPS", "21.4"), slackEvent("UALICE", "COPS", "21.4", "app_mention"));
  await until(() => slack.history.length === 4 && slack.events.length === 6, "thread and channel routing");
  assert.deepEqual(slack.events.map((e) => [e.data.ts, e.data.via]).sort(), [
    ["20.1", "thread"], ["20.2", "thread"], ["20.3", "thread"], ["20.4", "thread"],
    ["21.3", "channel"], ["21.4", "mention"],
  ]);
  for (const query of slack.history) {
    assert.deepEqual(query, { channel: "COPS", oldest: query.oldest, latest: query.oldest, inclusive: "true", limit: "1" });
  }
  assert.deepEqual(slack.history.map((q) => q.oldest).sort(), ["5.1", "6.1", "7.1", "8.1"]);
});

test("Slack reports a successful outbound post even if saving the thread fails", async () => {
  const dir = mkdtempSync(join(tmpdir(), "hyp-slack-storage-"));
  cleanups.push(() => rmSync(dir, { recursive: true, force: true }));
  const file = join(dir, "not-a-directory");
  writeFileSync(file, "fixture");
  const slack = await startSlackFixture({ SLACK_ALLOWED_CHANNELS: "COPS", HYPHAE_STATE_DIR: file });
  const response = await slack.post({ text: "fixture", channel: "COPS" });
  assert.equal(response.result.ts, "99.01");
  assert.equal(slack.posts.length, 1);
  await until(() => slack.stderr().includes("message was posted but thread membership could not be saved"), "storage diagnostic");
});

test("Slack redacts known secrets before publication and diagnostics when enabled", async () => {
  const fakeSecrets = [
    "xoxb-" + "0".repeat(24),
    "xapp-" + "0".repeat(24),
    "ghp_" + "0".repeat(36),
    "github_pat_" + "0".repeat(60),
    "AKIA" + "A".repeat(16),
    "ASIA" + "A".repeat(16),
    "AIza" + "_".repeat(34) + "-",
    "ya29." + "0".repeat(24),
    "sk-" + "0".repeat(24),
    "sk-ant-" + "0".repeat(24),
    "sk-proj-" + "0".repeat(24),
    "eyJhbGciOiJub25lIn0.eyJzdWIiOiJkZW1vIn0.fixture",
    "-----BEGIN PRIVATE KEY-----\nsynthetic body\n-----END PRIVATE KEY-----",
  ];
  const privateKey = JSON.stringify({ private_key: 'synthetic "escaped" key\nbody' });
  const slack = await startSlackFixture({ SLACK_ALLOWED_USERS: "UALLOWED", SLACK_REDACT: "1" });
  slack.deliver(
    { ...slackEvent("UALLOWED", "DPRIVATE", "5.01"), text: `prefix | ${[...fakeSecrets, privateKey].join(" | ")} | suffix` },
    { ...slackEvent("UALLOWED", "DPRIVATE", fakeSecrets[2]), text: "invalid timestamp" },
    { ...slackEvent("UALLOWED", "DPRIVATE", "5.02"), text: `${"a".repeat(3990)} ${fakeSecrets[2]}` },
    { ...slackEvent("UALLOWED", "DPRIVATE", "5.03"), text: "normal message" },
  );
  slack.deliveryFailed(`transient failure ${fakeSecrets[2]}`);
  await until(() => slack.events.some(({ data }) => data.ts === "5.03"), "Slack redacted fixture");
  await until(() => slack.stderr().includes("transient failure [REDACTED]"), "Slack redacted diagnostic");
  assert.deepEqual(slack.events.map(({ data }) => data.ts), ["5.01", "5.02", "5.03"]);
  const [sensitive, long, clean] = slack.events;
  assert.equal(sensitive.id, "DPRIVATE-5.01");
  assert.equal(sensitive.subject, "DPRIVATE/5.01");
  assert.equal(sensitive.data.user, "UALLOWED");
  assert.equal(sensitive.data.secret_removed, true);
  assert.equal(sensitive.data.text,
    `prefix | ${fakeSecrets.map(() => "[REDACTED]").join(" | ")} | {"private_key":"[REDACTED]"} | suffix`);
  assert.equal(long.data.text, `${"a".repeat(3990)} [REDACTED`);
  assert.equal(long.data.secret_removed, true);
  assert.equal(clean.data.text, "normal message");
  assert.equal(clean.data.secret_removed, undefined);
  assert.ok(!slack.stderr().includes(fakeSecrets[2]));

  const optOut = await startSlackFixture({ SLACK_ALLOWED_USERS: "UALLOWED", SLACK_REDACT: "0" });
  optOut.deliver({ ...slackEvent("UALLOWED", "DPRIVATE", "5.04"), text: fakeSecrets[2] });
  await until(() => optOut.events.length === 1, "Slack unchanged by default");
  assert.equal(optOut.events[0].data.text, fakeSecrets[2]);
  assert.equal(optOut.events[0].data.secret_removed, undefined);
});

test("Slack redacts verified choices in forwarded action data and updated message text", async () => {
  const slack = await startSlackFixture({ SLACK_ALLOWED_USERS: "UALICE", SLACK_REDACT: "1" });
  const actionId = "ghp_" + "0".repeat(36);
  const blockId = "xapp-" + "0".repeat(24);
  const value = "sk-proj-" + "0".repeat(24);
  const label = "Option " + "xoxb-" + "0".repeat(24);
  const text = "Choose a slot " + actionId;
  const selected = { value, text: { type: "plain_text", text: label } };
  const elements = [
    { type: "button", action_id: actionId, ...selected },
    { type: "static_select", action_id: actionId, options: [selected] },
  ];
  for (const [index, element] of elements.entries()) {
    const ts = `201.0${index + 1}`;
    slack.envelope({
      type: "interactive", envelope_id: `action-${index}`, payload: {
        type: "block_actions", team: { id: "TDEMO" }, user: { id: "UALICE" },
        channel: { id: "COPS" }, container: { type: "message", channel_id: "COPS", message_ts: ts },
        message: { user: "UBOT", ts, text,
          blocks: [{ type: "section", block_id: blockId, text: { type: "plain_text", text } },
            { type: "actions", block_id: blockId + "choice", elements: [element] }] },
        actions: [{ type: element.type, action_id: actionId, action_ts: "202.01", block_id: blockId + "choice",
          ...(element.type === "button" ? selected : { selected_option: selected }) }],
      },
    });
  }
  await until(() => slack.events.length === 2, "Slack redacted button and select");
  assert.equal(slack.updates.length, 2);
  for (const event of slack.events) {
    assert.match(event.id, /^choice-COPS-201\.0[12]-202\.01$/);
    assert.equal(event.data.user, "UALICE");
    assert.equal(event.data.action_id, "[REDACTED]");
    assert.equal(event.data.value, "[REDACTED]");
    assert.equal(event.data.label, "Option [REDACTED]");
    assert.equal(event.data.text, "[clicked] Option [REDACTED] (action_id=[REDACTED], value=[REDACTED])");
    assert.equal(event.data.secret_removed, true);
  }
  for (const update of slack.updates) {
    assert.equal(update.text, "Choose a slot [REDACTED]");
    assert.equal(update.blocks[0].block_id, "[REDACTED]");
    assert.equal(update.blocks[0].text.text, "Choose a slot [REDACTED]");
    assert.equal(update.blocks[1].elements[0].text, ":white_check_mark: *Option [REDACTED]*, chosen by <@UALICE>");
    assert.equal(update.secret_removed, undefined);
  }
  const emitted = JSON.stringify([slack.events, slack.updates, slack.stderr()]);
  for (const secret of [actionId, blockId, value, label]) assert.ok(!emitted.includes(secret));
});

test("Slack secret redaction handles projected interaction text and structured values", () => {
  const dummyValue = "xoxp-" + "0".repeat(24);
  const data = {
    text: `Label (choose): ${dummyValue}`,
    action_id: "choose",
    block_id: "block",
    selected_option: { text: { text: "Label" }, value: dummyValue },
    metadata: [{ private_key: "synthetic unprefixed value" }],
  };
  assert.deepEqual(redactSlackInboundData(data), {
    text: "Label (choose): [REDACTED]",
    action_id: "choose",
    block_id: "block",
    selected_option: { text: { text: "Label" }, value: "[REDACTED]" },
    metadata: [{ private_key: "[REDACTED]" }],
    secret_removed: true,
  });
  assert.equal(data.selected_option.value, dummyValue);
  assert.deepEqual(redactSlackInboundData({ text: '{"private_key":"unfinished fixture' }), {
    text: '{"private_key":"[REDACTED]"',
    secret_removed: true,
  });
});

test("Slack env sender policy admits DMs independently of channel restrictions", async () => {
  const slack = await startSlackFixture({
    SLACK_ALLOWED_USERS: "UALLOWED",
    SLACK_ALLOWED_CHANNELS: "COPEN,DEXPLICIT",
  });
  slack.deliver(
    slackEvent("UUNKNOWN", "DEXPLICIT", "1.01"),
    slackEvent("UALLOWED", "CBLOCKED", "1.02", "app_mention"),
    slackEvent("UUNKNOWN", "COPEN", "1.03", "app_mention"),
    slackEvent("UALLOWED", "DPRIVATE", "1.04"),
    slackEvent("UALLOWED", "COPEN", "1.05", "app_mention"),
  );
  await until(() => slack.events.some(({ data }) => data.ts === "1.05"), "Slack allowlisted mention");
  assert.deepEqual(slack.events.map(({ data }) => data.ts), ["1.04", "1.05"]);
  assert.equal(slack.events[0].type, "com.slack.message.im");
  assert.equal(slack.events[0].data.role, undefined);
  assert.equal(slack.events[0].data.from_name, undefined);
  assert.equal((await slack.post({ channel: "DPRIVATE", replyTo: "1.04", text: "reply" })).result?.ok, true);
  assert.ok((await slack.post({ channel: "DUNSEEN", text: "denied" })).error);
  assert.ok((await slack.post({ channel: "CBLOCKED", text: "denied" })).error);
  assert.deepEqual(slack.posts, [{ channel: "DPRIVATE", thread_ts: "1.04", text: "reply" }]);
});

test("Slack channel-only env policy still admits explicitly listed DM channels only", async () => {
  const slack = await startSlackFixture({ SLACK_ALLOWED_CHANNELS: "COPEN,DEXPLICIT" });
  slack.deliver(
    slackEvent("UUNLISTED", "DPRIVATE", "2.01"),
    slackEvent("UUNLISTED", "DEXPLICIT", "2.02"),
    slackEvent("UUNLISTED", "COPEN", "2.03", "app_mention"),
  );
  await until(() => slack.events.some(({ data }) => data.ts === "2.03"), "Slack channel-only mention");
  assert.deepEqual(slack.events.map(({ data }) => data.ts), ["2.02", "2.03"]);
  assert.ok((await slack.post({ channel: "DPRIVATE", text: "denied" })).error);
});

test("Slack file allowlist intersects env constraints and reloads roles and routes", async () => {
  const dir = mkdtempSync(join(tmpdir(), "hyp-slack-policy-"));
  cleanups.push(() => rmSync(dir, { recursive: true, force: true }));
  const file = join(dir, "allowlist.json");
  const owner = { id: "UOWNER", name: "Demo Owner" };
  const member = { id: "UALLOWED", name: "Demo Member" };
  const write = (allowed, channels = ["COPEN", "CFILEONLY"]) =>
    writeFileSync(file, JSON.stringify({ owner, allowed, channels }));
  write([member, { id: "UEXTRA", name: "Extra Member" }]);
  const slack = await startSlackFixture({
    SLACK_ALLOWLIST_FILE: file,
    SLACK_ALLOWED_USERS: "UOWNER,UALLOWED,UNEW",
    SLACK_ALLOWED_CHANNELS: "COPEN,CENVONLY",
    SLACK_ALLOW_ALL: "1",
  });
  slack.deliver(
    slackEvent("UOWNER", "DOWNER", "3.01"),
    slackEvent("UALLOWED", "DMEMBER", "3.02"),
    slackEvent("UEXTRA", "DEXTRA", "3.03"),
    slackEvent("UNEW", "DNEW", "3.04"),
    slackEvent("UOWNER", "CENVONLY", "3.05", "app_mention"),
    slackEvent("UOWNER", "CFILEONLY", "3.06", "app_mention"),
    slackEvent("UALLOWED", "COPEN", "3.07", "app_mention"),
  );
  await until(() => slack.events.some(({ data }) => data.ts === "3.07"), "Slack file-allowlisted mention");
  assert.deepEqual(slack.events.map(({ data }) => [data.ts, data.role, data.from_name]), [
    ["3.01", "owner", "Demo Owner"],
    ["3.02", "allowed", "Demo Member"],
    ["3.07", "allowed", "Demo Member"],
  ]);

  write([{ id: "UNEW", name: "New Member" }], ["CENVONLY"]);
  slack.deliver(
    slackEvent("UALLOWED", "DMEMBER", "3.08"),
    slackEvent("UOWNER", "COPEN", "3.09", "app_mention"),
    slackEvent("UNEW", "DNEW", "3.10"),
  );
  await until(() => slack.events.some(({ data }) => data.ts === "3.10"), "Slack reloaded sender");
  assert.deepEqual(slack.events.slice(3).map(({ data }) => [data.ts, data.role, data.from_name]), [
    ["3.10", "allowed", "New Member"],
  ]);
  assert.ok((await slack.post({ channel: "DMEMBER", text: "denied" })).error);
  assert.ok((await slack.post({ channel: "COPEN", text: "denied" })).error);
  assert.equal((await slack.post({ channel: "DNEW", text: "reply" })).result?.ok, true);

  writeFileSync(file, "{invalid");
  slack.deliver(slackEvent("UOWNER", "DOWNER", "3.11"));
  await until(() => slack.stderr().includes("slack handle error: SLACK_ALLOWLIST_FILE"), "Slack rejection at reload");
  assert.ok((await slack.post({ channel: "DOWNER", text: "denied" })).error);
  assert.equal(slack.events.length, 4);
  write([]);
  slack.deliver(slackEvent("UOWNER", "DOWNER", "3.11"));
  await until(() => slack.events.length === 5, "Slack recovers after allowlist repair");
  assert.equal(slack.events[4].data.ts, "3.11");
  assert.deepEqual(slack.posts, [{ channel: "DNEW", text: "reply" }]);
});

test("Slack file-only policy accepts the owner when no channels are listed", async () => {
  const dir = mkdtempSync(join(tmpdir(), "hyp-slack-owner-policy-"));
  cleanups.push(() => rmSync(dir, { recursive: true, force: true }));
  const file = join(dir, "allowlist.json");
  writeFileSync(file, JSON.stringify({
    owner: { id: "UOWNER", name: "Demo Owner" },
    allowed: [],
    channels: [],
  }));
  const slack = await startSlackFixture({ SLACK_ALLOWLIST_FILE: file });
  slack.deliver(
    slackEvent("UUNKNOWN", "DOTHER", "4.01"),
    slackEvent("UOWNER", "CUNLISTED", "4.02", "app_mention"),
    slackEvent("UOWNER", "DOWNER", "4.03"),
  );
  await until(() => slack.events.some(({ data }) => data.ts === "4.03"), "Slack owner DM");
  assert.deepEqual(slack.events.map(({ data }) => [data.ts, data.role]), [["4.03", "owner"]]);
  assert.equal((await slack.post({ text: "only destination" })).result?.ok, true);
  assert.deepEqual(slack.posts, [{ channel: "DOWNER", text: "only destination" }]);
});

test("Slack refuses startup with a missing or structurally invalid configured allowlist", async () => {
  const dir = mkdtempSync(join(tmpdir(), "hyp-slack-invalid-policy-"));
  cleanups.push(() => rmSync(dir, { recursive: true, force: true }));
  const bad = join(dir, "bad.json");
  writeFileSync(bad, JSON.stringify({ owner: { id: "UOWNER" }, allowed: [], channels: [] }));
  for (const file of [bad, join(dir, "missing.json")]) {
    const slack = spawnFd3Script("await import(process.env.SLACK_SCRIPT_URL)", {
      plugin: "slack",
      env: {
        SLACK_SCRIPT_URL: pathToFileURL(SLACK_SCRIPT).href,
        SLACK_APP_TOKEN: "xapp-fixture",
        SLACK_BOT_TOKEN: "xoxb-fixture",
        SLACK_ALLOWLIST_FILE: file,
        SLACK_ALLOW_ALL: "1",
      },
    });
    assert.equal((await slack.waitExit()).code, 1);
    assert.match(slack.stderr(), /SLACK_ALLOWLIST_FILE/);
  }
});
