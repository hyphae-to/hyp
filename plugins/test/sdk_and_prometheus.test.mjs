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
import { createHmac } from "node:crypto";
import net from "node:net";
import { dirname, join } from "node:path";
import { createInterface } from "node:readline";
import { after, test } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

const PLUGINS_DIR = join(dirname(fileURLToPath(import.meta.url)), "..");
const SDK_URL = pathToFileURL(join(PLUGINS_DIR, "sdk", "client.mjs")).href;
const PROMETHEUS_SCRIPT = join(PLUGINS_DIR, "prometheus", "index.mjs");
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
    channel.write(JSON.stringify({ type: "hello", protocol: 1, plugin, targets }) + "\n");
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
    if (msg.type !== "event") return;
    events.push({ to: msg.to, event: msg.event });
    channel.write(JSON.stringify({ type: "ack", status: "stored", id: msg.event.id }) + "\n");
  });
  channel.write(JSON.stringify({ type: "hello", protocol: 1, plugin: "prometheus", targets }) + "\n");

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
  channel.write(JSON.stringify({ type: "hello", protocol: 1, plugin: "prometheus", targets: ["alerts"] }) + "\n");
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
  channel.write(JSON.stringify({ type: "hello", protocol: 1, plugin: "telegram", targets: ["ops"] }) + "\n");
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
      socket.write(JSON.stringify({ type: "hello", protocol: 1, plugin: "tcp-demo", targets: ["ops"] }) + "\n");
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
