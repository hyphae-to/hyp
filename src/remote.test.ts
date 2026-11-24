import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { startDaemon } from "./daemon.ts";
import { loadConfig } from "./config.ts";
import {
  decodeInvite,
  detectExposedTailscaleUrl,
  encodeInvite,
  exposeTailscale,
  probeRouter,
  unexposeTailscale,
  type ExecRunner,
} from "./remote.ts";
import { runOnboard } from "./setup.ts";
import { RouterCore } from "./core/router/core.ts";
import { serveRouter } from "./core/router/server.ts";

test("invite encode/decode round-trips and enforces HTTPS/loopback origins", () => {
  const code = encodeInvite({
    connectorId: "bogdan@solace",
    router: "https://hyphae.tail1234.ts.net/",
    token: "t3c_secret123",
  });
  assert.ok(code.startsWith("am1_"));
  const decoded = decodeInvite(code);
  assert.deepEqual(decoded, {
    v: 1,
    connectorId: "bogdan@solace",
    router: "https://hyphae.tail1234.ts.net",
    token: "t3c_secret123",
  });

  // Non-loopback plain HTTP must be rejected
  assert.throws(() => encodeInvite({ connectorId: "a@b", router: "http://example.com:8790", token: "tok" }), /HTTPS origin/);
  assert.throws(() => decodeInvite("invalid"), /am1_/);
});

test("exposeTailscale supports Tailscale Services (--service) and node-scoped Serve without Funnel", () => {
  const executed: string[][] = [];
  const fakeStatus = JSON.stringify({
    BackendState: "Running",
    MagicDNSSuffix: "tail9999.ts.net",
    Self: { DNSName: "macbook.tail9999.ts.net." },
  });
  const fakeServeStatus = JSON.stringify({
    Services: {
      "svc:hyphae": {
        Web: {
          "hyphae.tail9999.ts.net:443": {
            Handlers: { "/": { Proxy: "http://127.0.0.1:8790" } },
          },
        },
      },
    },
  });
  const exec: ExecRunner = (bin, args) => {
    executed.push([bin, ...args]);
    if (args[0] === "status") return fakeStatus;
    if (args[0] === "serve" && args[1] === "status") return fakeServeStatus;
    return "";
  };

  // Service mode (TailVIP at https://hyphae.tail9999.ts.net)
  const svc = exposeTailscale({ service: "hyphae", localPort: 8790, exec });
  assert.equal(svc.mode, "service");
  assert.equal(svc.url, "https://hyphae.tail9999.ts.net");
  assert.deepEqual(svc.command, ["tailscale", "serve", "--bg", "--yes", "--service=svc:hyphae", "--https=443", "http://127.0.0.1:8790"]);
  assert.equal(svc.applied, true);

  // Dry run does not invoke `tailscale serve`
  executed.length = 0;
  const dry = exposeTailscale({ localPort: 8790, dryRun: true, exec });
  assert.equal(dry.mode, "node");
  assert.equal(dry.url, "https://macbook.tail9999.ts.net:8790");
  assert.equal(dry.applied, false);
  assert.equal(executed.length, 1); // only `tailscale status --json`

  // Auto-detect exposed service URL
  assert.equal(detectExposedTailscaleUrl(8790, exec), "https://hyphae.tail9999.ts.net");

  // Unexpose service cleanly
  const unexposed = unexposeTailscale({ service: "svc:hyphae", exec });
  assert.deepEqual(unexposed, ["tailscale", "serve", "clear", "svc:hyphae"]);
});

test("remote onboard via --join invite verifies live router auth, writes 0600 token, and connects", async () => {
  const dir = mkdtempSync(join(tmpdir(), "am-rem-"));
  const routerCore = new RouterCore({ dbPath: join(dir, "router.sqlite") });
  const token = routerCore.addConnector("bogdan@remote-box");
  const router = await serveRouter({ core: routerCore, host: "127.0.0.1", port: 0 });

  try {
    // Bad token fails pre-flight before writing any config
    const badProbe = await probeRouter(router.url, "wrong-token");
    assert.equal(badProbe.ok, false);
    assert.equal(badProbe.status, 401);

    const badInvite = encodeInvite({ connectorId: "bogdan@remote-box", router: router.url, token: "wrong-token" });
    await assert.rejects(
      runOnboard({
        configPath: join(dir, "client", "connector.json"),
        inviteCode: badInvite,
        homeDir: join(dir, "home"),
        harnesses: [],
        startDaemon: false,
      }),
      /Authentication refused/,
    );

    // Valid invite passes pre-flight, stores 0600 token, and connects daemon cleanly
    const invite = encodeInvite({ connectorId: "bogdan@remote-box", router: router.url, token });
    const configPath = join(dir, "client", "connector.json");
    const onboarded = await runOnboard({
      configPath,
      inviteCode: invite,
      homeDir: join(dir, "home"),
      harnesses: [],
      startDaemon: false,
    });
    assert.equal(onboarded.connectorId, "bogdan@remote-box");
    assert.equal(onboarded.localRouter, false);
    assert.equal(onboarded.remoteVerified, true);

    const tokenPath = join(dir, "client", "tokens", "primary.token");
    assert.equal(statSync(tokenPath).mode & 0o077, 0);
    assert.equal(readFileSync(tokenPath, "utf8").trim(), token);

    const daemon = await startDaemon(loadConfig(configPath), { quiet: true });
    try {
      daemon.state.register("claude:remote-1", { kind: "claude" });
      const res = await daemon.connector.call("claude:remote-1", "hyp_join", { handle: "worker" });
      assert.deepEqual(res, { address: "bogdan@remote-box/worker" });
    } finally {
      await daemon.stop();
    }
  } finally {
    await router.close();
    routerCore.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
