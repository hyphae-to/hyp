import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { discoverRemoteMachines, onboardRemoteOverSsh, probeRemoteHost, type LocalEnvironment } from "../../src/discover.ts";
import { daemonRpc } from "../../src/hooks.ts";
import { encodeInvite } from "../../src/remote.ts";
import { freePort, McpClient, MeshTopology, waitFor } from "./harness/topology.ts";
import { createVirtualSshHost, startChaosProxy, startTlsReverseProxy } from "./shims/multihost.ts";

const CLI_SCRIPT = join(process.cwd(), "src", "cli.ts");
const CLEAN_PATH = `${dirname(process.execPath)}:/usr/bin:/bin`;

function isolatedEnv(homeDir: string, xdgConfigHome: string, extra: Record<string, string> = {}): NodeJS.ProcessEnv {
  return {
    HOME: homeDir,
    XDG_CONFIG_HOME: xdgConfigHome,
    PATH: CLEAN_PATH,
    USER: process.env.USER ?? "testuser",
    TERM: "dumb",
    ...extra,
  };
}

function runCli(
  args: readonly string[],
  opts: { env: NodeJS.ProcessEnv; stdin?: string; timeoutMs?: number },
): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI_SCRIPT, ...args], {
      env: opts.env,
      stdio: [opts.stdin !== undefined ? "pipe" : "ignore", "pipe", "pipe"],
    });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    child.stdout?.on("data", (d: Buffer) => out.push(d));
    child.stderr?.on("data", (d: Buffer) => err.push(d));

    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error(`CLI timed out: hyp ${args.join(" ")}`));
    }, opts.timeoutMs ?? 12_000).unref();

    child.once("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.once("exit", (code) => {
      clearTimeout(timer);
      resolve({
        code,
        stdout: Buffer.concat(out).toString("utf8"),
        stderr: Buffer.concat(err).toString("utf8"),
      });
    });

    if (opts.stdin !== undefined) {
      child.stdin?.end(opts.stdin);
    }
  });
}

async function stopChild(proc: ChildProcess | undefined): Promise<void> {
  if (!proc || proc.exitCode !== null) return;
  await new Promise<void>((resolve) => {
    const timer = setTimeout(() => {
      if (proc.exitCode === null) proc.kill("SIGKILL");
      resolve();
    }, 3_000).unref();
    proc.once("exit", () => {
      clearTimeout(timer);
      resolve();
    });
    proc.kill("SIGTERM");
  });
}

test(
  "real CLI onboarding, setup all/project/service, skill install, doctor transitions, and 0600 secret lifecycle",
  { timeout: 30_000 },
  async () => {
    const root = mkdtempSync(join(tmpdir(), "hi-"));
    const homeDir = join(root, "h");
    const xdgConfig = join(root, "c");
    const projDir = join(root, "p");
    mkdirSync(homeDir, { recursive: true, mode: 0o700 });
    mkdirSync(xdgConfig, { recursive: true, mode: 0o700 });
    mkdirSync(projDir, { recursive: true, mode: 0o700 });

    const env = isolatedEnv(homeDir, xdgConfig);
    let daemonProc: ChildProcess | undefined;

    try {
      const port = await freePort();

      // 1. Real CLI `onboard --yes --id dev@box1 --port <free> --no-start`
      const onboard = await runCli(
        ["onboard", "--yes", "--id", "dev@box1", "--port", String(port), "--no-start"],
        { env },
      );
      assert.equal(onboard.code, 0, `onboard failed: ${onboard.stderr}`);
      assert.match(onboard.stdout, /COMMAND: onboard/);
      assert.match(onboard.stdout, /STATUS: ok/);
      assert.match(onboard.stdout, /dev@box1/);
      assert.match(onboard.stdout, /embedded local (?:router|Node)/i);

      const configDir = join(xdgConfig, "hyphae");
      const configPath = join(configDir, "connector.json");
      const routerDbPath = join(configDir, "router", "router.sqlite");
      const tokenPath = join(configDir, "router", "connector.token");
      const socketPath = join(configDir, "state", "connector.sock");

      assert.ok(existsSync(configPath), "connector.json should exist");
      assert.equal(statSync(configPath).mode & 0o777, 0o600, "connector.json must be 0600");
      assert.ok(existsSync(routerDbPath), "embedded router SQLite DB should exist");
      assert.ok(existsSync(tokenPath), "connector token file should exist");
      assert.equal(statSync(tokenPath).mode & 0o777, 0o600, "connector token must be 0600");

      const cfgJson = JSON.parse(readFileSync(configPath, "utf8")) as {
        connectorId: string;
        localRouter?: { port: number; db: string };
        routers: Array<{ name: string; url: string; tokenFile: string }>;
      };
      assert.equal(cfgJson.connectorId, "dev@box1");
      assert.equal(cfgJson.localRouter?.port, port);
      assert.equal(cfgJson.routers[0]?.url, `http://127.0.0.1:${port}`);

      // 2. Real CLI `setup all --scope user` + idempotency check
      const setupAll1 = await runCli(["setup", "all", "--scope", "user"], { env });
      assert.equal(setupAll1.code, 0, `setup all failed: ${setupAll1.stderr}`);

      const expectedUserFiles = [
        join(homeDir, ".gemini", "config", "plugins", "hyphae", "plugin.json"),
        join(homeDir, ".gemini", "config", "plugins", "hyphae", "mcp_config.json"),
        join(homeDir, ".gemini", "config", "plugins", "hyphae", "hooks.json"),
        join(homeDir, ".gemini", "config", "plugins", "hyphae", "sidecars", "daemon", "sidecar.json"),
        join(homeDir, ".gemini", "config", "plugins", "hyphae", "rules", "AGENTS.md"),
        join(homeDir, ".gemini", "config", "plugins", "hyphae", "skills", "hyphae", "SKILL.md"),
        join(homeDir, ".claude.json"),
        join(homeDir, ".claude", "settings.json"),
        join(homeDir, ".codex", "config.toml"),
        join(homeDir, ".codex", "hooks.json"),
        join(homeDir, ".cursor", "mcp.json"),
        join(homeDir, ".cursor", "hooks.json"),
        join(homeDir, ".config", "opencode", "opencode.json"),
        join(homeDir, ".config", "opencode", "plugins", "hyphae.ts"),
        join(homeDir, ".gemini", "settings.json"),
        join(homeDir, ".openclaw", "openclaw.json"),
        join(homeDir, ".openclaw", "skills", "hyphae", "SKILL.md"),
      ];
      for (const file of expectedUserFiles) {
        assert.ok(existsSync(file), `expected setup file to exist: ${file}`);
      }

      // Run `setup all --scope user` a second time and confirm idempotency (no duplicated entries).
      const setupAll2 = await runCli(["setup", "all", "--scope", "user"], { env });
      assert.equal(setupAll2.code, 0, `second setup all failed: ${setupAll2.stderr}`);
      const codexToml = readFileSync(join(homeDir, ".codex", "config.toml"), "utf8");
      assert.equal(codexToml.match(/\[mcp_servers\.hyphae\]/g)?.length, 1, "Codex TOML block should not duplicate");
      const claudeSettings = JSON.parse(readFileSync(join(homeDir, ".claude", "settings.json"), "utf8")) as {
        hooks: { PreToolUse: unknown[]; PostToolUse: unknown[]; Stop: unknown[] };
      };
      assert.equal(claudeSettings.hooks.PreToolUse.length, 1, "Claude PreToolUse hook should not duplicate");
      assert.equal(claudeSettings.hooks.PostToolUse.length, 1, "Claude PostToolUse hook should not duplicate");
      assert.equal(claudeSettings.hooks.Stop.length, 1, "Claude Stop hook should not duplicate");

      // 3. Project-scoped setup (`setup claude --scope project --dir <proj>`)
      const setupProj = await runCli(["setup", "claude", "--scope", "project", "--dir", projDir], { env });
      assert.equal(setupProj.code, 0, `project setup failed: ${setupProj.stderr}`);
      assert.ok(existsSync(join(projDir, ".mcp.json")));
      assert.ok(existsSync(join(projDir, ".claude", "settings.json")));
      assert.match(readFileSync(join(projDir, ".mcp.json"), "utf8"), /"hyphae"/);

      // 4. Service setup (preview + isolated `--install`)
      const svcPreview = await runCli(["setup", "service"], { env });
      assert.equal(svcPreview.code, 0, `setup service preview failed: ${svcPreview.stderr}`);
      assert.match(svcPreview.stdout, /pass --install to write/i);
      assert.match(svcPreview.stdout, new RegExp(configPath.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));

      const svcInstall = await runCli(["setup", "service", "--install"], { env });
      assert.equal(svcInstall.code, 0, `setup service --install failed: ${svcInstall.stderr}`);
      const expectedServiceFile = process.platform === "darwin"
        ? join(homeDir, "Library", "LaunchAgents", "dev.hyphae.daemon.plist")
        : join(homeDir, ".config", "systemd", "user", "hyphae.service");
      assert.ok(existsSync(expectedServiceFile), `expected service file at ${expectedServiceFile}`);

      // 5. Canonical skill installation (`skill install all`)
      const skillRes = await runCli(["skill", "install", "all"], { env });
      assert.equal(skillRes.code, 0, `skill install all failed: ${skillRes.stderr}`);
      for (const skillFile of [
        join(homeDir, ".gemini", "config", "plugins", "hyphae", "skills", "hyphae", "SKILL.md"),
        join(homeDir, ".claude", "skills", "hyphae", "SKILL.md"),
        join(homeDir, ".codex", "skills", "hyphae", "SKILL.md"),
        join(homeDir, ".cursor", "rules", "hyphae-skill.mdc"),
        join(homeDir, ".openclaw", "skills", "hyphae", "SKILL.md"),
      ]) {
        assert.ok(existsSync(skillFile), `expected installed skill file: ${skillFile}`);
      }

      // 6. `hyp doctor` BEFORE daemon starts -> fails `daemon` check with fix hint
      const docBefore = await runCli(["doctor"], { env });
      assert.equal(docBefore.code, 1, "doctor should fail before daemon starts");
      assert.match(docBefore.stdout, /\[OK\]\s+node\b/);
      assert.match(docBefore.stdout, /\[OK\]\s+config\b/);
      assert.match(docBefore.stdout, /\[FAIL\]\s+daemon\s+Not reachable/);
      assert.match(docBefore.stdout, /fix: Run `hyp onboard` or `hyp daemon`/);

      // 7. Start real daemon subprocess -> `hyp doctor` goes ALL GREEN
      daemonProc = spawn(process.execPath, [CLI_SCRIPT, "daemon", configPath], {
        env,
        stdio: ["ignore", "pipe", "pipe"],
      });
      await waitFor(
        async () => {
          const status = await daemonRpc(socketPath, { type: "daemon.status" }, 500);
          return status.ok ? status : null;
        },
        { timeoutMs: 8_000, label: "real hyp daemon startup" },
      );

      const docAfter = await runCli(["doctor"], { env });
      assert.equal(docAfter.code, 0, `doctor should be all green once daemon runs:\n${docAfter.stdout}\n${docAfter.stderr}`);
      assert.doesNotMatch(docAfter.stdout, /\[FAIL\]/);
      assert.match(docAfter.stdout, /\[OK\]\s+daemon\s+Running at/);
      assert.match(docAfter.stdout, /\[OK\]\s+router:primary\b/);
      assert.match(docAfter.stdout, /\[OK\]\s+antigravity\b/);
      assert.match(docAfter.stdout, /\[OK\]\s+claude\b/);
      assert.match(docAfter.stdout, /\[OK\]\s+codex\b/);
      assert.match(docAfter.stdout, /\[OK\]\s+cursor\b/);
      assert.match(docAfter.stdout, /\[OK\]\s+opencode\b/);
      assert.match(docAfter.stdout, /\[OK\]\s+gemini\b/);
      assert.match(docAfter.stdout, /\[OK\]\s+openclaw\b/);

      await stopChild(daemonProc);
      daemonProc = undefined;

      // 8. Real CLI secrets lifecycle (`set`, `list`, `check`, `rm`) — secret value never printed
      const secretValue = "sk-live-hyphae-never-print-918273645";
      const secretSet = await runCli(["secret", "set", "api-key"], { env, stdin: secretValue + "\n" });
      assert.equal(secretSet.code, 0, `secret set failed: ${secretSet.stderr}`);
      assert.match(secretSet.stdout, /Saved secret 'api-key'/i);
      assert.ok(!secretSet.stdout.includes(secretValue) && !secretSet.stderr.includes(secretValue), "secret set must never echo value");

      const secretPath = join(configDir, "secrets", "api-key.secret");
      assert.ok(existsSync(secretPath));
      assert.equal(statSync(secretPath).mode & 0o777, 0o600, "secret file must be 0600");

      const secretList = await runCli(["secret", "list"], { env });
      assert.equal(secretList.code, 0, `secret list failed: ${secretList.stderr}`);
      assert.match(secretList.stdout, /api-key/);
      assert.match(secretList.stdout, /OK/);
      assert.ok(!secretList.stdout.includes(secretValue) && !secretList.stderr.includes(secretValue), "secret list must never print value");

      // Add a `{ secret: "api-key" }` ref to connector.json and verify `hyp secret check`
      const cfgWithSecretRef = {
        ...JSON.parse(readFileSync(configPath, "utf8")),
        plugins: [
          {
            name: "demo",
            builtin: "webhook",
            env: { DEMO_API_KEY: { secret: "api-key" } },
            targets: [{ name: "t1", handle: "dev" }],
          },
        ],
      };
      writeFileSync(configPath, JSON.stringify(cfgWithSecretRef, null, 2) + "\n", { mode: 0o600 });

      const secretCheckOk = await runCli(["secret", "check"], { env });
      assert.equal(secretCheckOk.code, 0, `secret check failed: ${secretCheckOk.stdout} ${secretCheckOk.stderr}`);
      assert.match(secretCheckOk.stdout, /\[OK\]\s+api-key/);
      assert.match(secretCheckOk.stdout, /plugin:demo -> DEMO_API_KEY/);
      assert.ok(!secretCheckOk.stdout.includes(secretValue) && !secretCheckOk.stderr.includes(secretValue));

      const secretRm = await runCli(["secret", "rm", "api-key"], { env });
      assert.equal(secretRm.code, 0, `secret rm failed: ${secretRm.stderr}`);
      assert.match(secretRm.stdout, /Removed secret 'api-key'/i);
      assert.ok(!existsSync(secretPath), "secret file should be deleted");
      assert.ok(!secretRm.stdout.includes(secretValue) && !secretRm.stderr.includes(secretValue));

      const secretCheckMissing = await runCli(["secret", "check"], { env });
      assert.equal(secretCheckMissing.code, 1, "secret check should fail after secret removal");
      assert.match(secretCheckMissing.stdout, /\[FAIL\]\s+api-key/);
      assert.ok(!secretCheckMissing.stdout.includes(secretValue) && !secretCheckMissing.stderr.includes(secretValue));
    } finally {
      await stopChild(daemonProc);
      rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
    }
  },
);

test(
  "remote --join onboarding & --replace migration over real TLS reverse proxy (HTTPS + SSE)",
  { timeout: 30_000 },
  async () => {
    const topo = new MeshTopology("hi-");
    let bobDaemon: ChildProcess | undefined;
    let bobMcp: McpClient | undefined;

    try {
      const teamRouter = await topo.addRouter({ name: "team" });
      const tlsProxy = await startTlsReverseProxy(teamRouter.url);
      topo.track(() => tlsProxy.close());

      // Peer connector on the same Team Router so we can exchange real messages over TLS
      const alice = await topo.addConnector({
        connectorId: "alice@hq",
        links: [{ name: "primary", router: teamRouter }],
      });
      alice.daemon.state.register("claude:alice-1", { kind: "claude" });
      await alice.daemon.connector.call("claude:alice-1", "hyp_join", { handle: "hq" });

      // Provision remote connector `bob@tlsbox` and encode an `https://` invite
      const bobToken = teamRouter.addConnector("bob@tlsbox");
      const bobInvite = encodeInvite({
        connectorId: "bob@tlsbox",
        router: tlsProxy.url,
        token: bobToken,
      });

      const bobHome = topo.subDir("bh");
      const bobXdg = topo.subDir("bc");
      const bobEnv = isolatedEnv(bobHome, bobXdg, { NODE_EXTRA_CA_CERTS: tlsProxy.caCertPath });

      // 1. Run real CLI `onboard --join --no-start` over HTTPS with NODE_EXTRA_CA_CERTS
      const joinRes = await runCli(["onboard", "--join", "--no-start"], {
        env: bobEnv,
        stdin: bobInvite + "\n",
      });
      assert.equal(joinRes.code, 0, `TLS --join onboard failed:\n${joinRes.stdout}\n${joinRes.stderr}`);
      assert.match(joinRes.stdout, /bob@tlsbox/);
      assert.match(joinRes.stdout, /\(remote verified\)/);

      const bobCfgDir = join(bobXdg, "hyphae");
      const bobCfgPath = join(bobCfgDir, "connector.json");
      const bobTokenPath = join(bobCfgDir, "tokens", "primary.token");
      const bobSocketPath = join(bobCfgDir, "state", "connector.sock");

      assert.ok(existsSync(bobTokenPath), "tokens/primary.token should be written");
      assert.equal(statSync(bobTokenPath).mode & 0o777, 0o600, "tokens/primary.token must be 0600");
      assert.equal(statSync(bobCfgPath).mode & 0o777, 0o600, "connector.json must be 0600");
      const bobCfg = JSON.parse(readFileSync(bobCfgPath, "utf8")) as {
        connectorId: string;
        localRouter?: unknown;
        routers: Array<{ name: string; url: string; tokenFile: string }>;
      };
      assert.equal(bobCfg.connectorId, "bob@tlsbox");
      assert.equal(bobCfg.localRouter, undefined, "remote join must not configure localRouter");
      assert.equal(bobCfg.routers[0]?.url, tlsProxy.url);

      // 2. Start real child `hyp daemon` with NODE_EXTRA_CA_CERTS
      bobDaemon = spawn(process.execPath, [CLI_SCRIPT, "daemon", bobCfgPath], {
        env: bobEnv,
        stdio: ["ignore", "pipe", "pipe"],
      });
      await waitFor(
        async () => {
          const res = await daemonRpc(bobSocketPath, { type: "daemon.status" }, 500);
          return res.ok ? res : null;
        },
        { timeoutMs: 8_000, label: "Bob TLS daemon startup" },
      );

      // 3. Verify `hyp doctor` reports `router:primary` reachable over HTTPS
      const doctorRes = await runCli(["doctor"], { env: bobEnv });
      assert.match(doctorRes.stdout, /\[OK\]\s+config\s+bob@tlsbox/);
      assert.match(doctorRes.stdout, /\[OK\]\s+daemon\s+Running at/);
      assert.match(
        doctorRes.stdout,
        new RegExp(`\\[OK\\]\\s+router:primary\\s+${tlsProxy.url.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")} reachable`),
      );

      // 4. Exchange bidirectional messages over the TLS-proxied router (testing HTTPS + SSE streaming)
      bobMcp = new McpClient(bobSocketPath, ["--ephemeral"], bobEnv);
      await bobMcp.initialize();
      const joinTool = await bobMcp.callTool("hyp_join", { handle: "worker" });
      assert.equal(joinTool.isError, false, `Bob hyp_join failed: ${joinTool.text}`);
      assert.equal((joinTool.json() as { address: string }).address, "bob@tlsbox/worker");

      // Wait until Alice sees Bob online on the Team Router
      await waitFor(
        async () => {
          const res = (await alice.daemon.connector.call("claude:alice-1", "hyp_peers", {})) as {
            peers: Array<{ address: string; online: boolean }>;
          };
          return res.peers.find((p) => p.address === "bob@tlsbox/worker" && p.online) ?? null;
        },
        { label: "Bob online via TLS proxy" },
      );

      // Bob -> Alice over HTTPS
      const sendTool = await bobMcp.callTool("hyp_send", {
        to: "alice@hq/hq",
        text: "hello-over-real-tls",
      });
      assert.equal(sendTool.isError, false, `Bob hyp_send failed: ${sendTool.text}`);
      const aliceItems = await waitFor(
        () => {
          const drained = alice.daemon.connector.drainMailbox("claude:alice-1", 5);
          return drained.length > 0 ? drained : null;
        },
        { label: "Alice receiving Bob's HTTPS message" },
      );
      assert.match(aliceItems[0].text, /bob@tlsbox\/worker/);
      assert.match(aliceItems[0].text, /hello-over-real-tls/);

      // Alice -> Bob over HTTPS SSE `/v1/inbox`
      await alice.daemon.connector.call("claude:alice-1", "hyp_send", {
        to: "bob@tlsbox/worker",
        text: "reply-over-tls-sse-stream",
      });
      const bobInbox = await waitFor(
        async () => {
          const res = await bobMcp!.callTool("hyp_inbox", { acknowledgeAll: true });
          const parsed = res.json() as { items: Array<{ text: string }> };
          return parsed.items.length > 0 ? parsed.items : null;
        },
        { label: "Bob receiving Alice's reply via TLS SSE stream" },
      );
      assert.match(bobInbox[0].text, /alice@hq\/hq/);
      assert.match(bobInbox[0].text, /reply-over-tls-sse-stream/);

      await bobMcp.close();
      bobMcp = undefined;
      await stopChild(bobDaemon);
      bobDaemon = undefined;

      // 5. Test `--replace` migration from a local-router config to the remote TLS router
      const migHome = topo.subDir("mh");
      const migXdg = topo.subDir("mc");
      const migEnv = isolatedEnv(migHome, migXdg, { NODE_EXTRA_CA_CERTS: tlsProxy.caCertPath });
      const localPort = await freePort();

      const localOnboard = await runCli(
        ["onboard", "--yes", "--id", "mig@box", "--port", String(localPort), "--no-start"],
        { env: migEnv },
      );
      assert.equal(localOnboard.code, 0, `initial local onboard failed: ${localOnboard.stderr}`);

      const migCfgPath = join(migXdg, "hyphae", "connector.json");
      const beforeMig = JSON.parse(readFileSync(migCfgPath, "utf8")) as {
        localRouter?: { port: number };
        routers: Array<{ url: string }>;
      };
      assert.equal(beforeMig.localRouter?.port, localPort);
      assert.equal(beforeMig.routers[0]?.url, `http://127.0.0.1:${localPort}`);

      const migToken = teamRouter.addConnector("mig@box");
      const migInvite = encodeInvite({
        connectorId: "mig@box",
        router: tlsProxy.url,
        token: migToken,
      });

      const replaceRes = await runCli(["onboard", "--join", "--replace", "--no-start"], {
        env: migEnv,
        stdin: migInvite + "\n",
      });
      assert.equal(replaceRes.code, 0, `--replace migration failed:\n${replaceRes.stdout}\n${replaceRes.stderr}`);
      assert.match(replaceRes.stdout, /\(remote verified\)/);

      const afterMig = JSON.parse(readFileSync(migCfgPath, "utf8")) as {
        connectorId: string;
        localRouter?: unknown;
        routers: Array<{ name: string; url: string; tokenFile: string }>;
      };
      assert.equal(afterMig.connectorId, "mig@box");
      assert.equal(afterMig.localRouter, undefined, "--replace should remove localRouter");
      assert.equal(afterMig.routers[0]?.url, tlsProxy.url);
      assert.equal(afterMig.routers[0]?.tokenFile, "tokens/primary.token");
      assert.equal(statSync(join(migXdg, "hyphae", "tokens", "primary.token")).mode & 0o777, 0o600);
    } finally {
      if (bobMcp) await bobMcp.close().catch(() => {});
      await stopChild(bobDaemon);
      await topo.cleanup();
    }
  },
);

test(
  "virtual remote SSH host discovery, probeRemoteHost, and onboardRemoteOverSsh (token piped via stdin, never in argv)",
  { timeout: 30_000 },
  async () => {
    const topo = new MeshTopology("hi-");
    const originalPath = process.env.PATH;

    try {
      const teamRouter = await topo.addRouter({ name: "team" });

      // Fake local ~/.ssh/config
      const localHome = topo.subDir("lh");
      mkdirSync(join(localHome, ".ssh"), { recursive: true, mode: 0o700 });
      writeFileSync(
        join(localHome, ".ssh", "config"),
        [
          "Host prod-box",
          "  HostName 10.20.30.40",
          "  User deploy",
          "",
          "Host github.com",
          "  HostName github.com",
          "",
          "Host *.internal",
          "  User ops",
          "",
        ].join("\n"),
        "utf8",
      );

      // Fake remote host with `.claude` and `.codex` harness directories
      const remoteHome = topo.subDir("rh");
      const remoteXdg = topo.subDir("rx");
      mkdirSync(join(remoteHome, ".claude"), { recursive: true, mode: 0o700 });
      mkdirSync(join(remoteHome, ".codex"), { recursive: true, mode: 0o700 });

      const virtualSsh = createVirtualSshHost({
        rootDir: topo.subDir("vssh"),
        hostAlias: "prod-box",
        remoteHome,
        remoteXdgConfig: remoteXdg,
        hypPath: CLI_SCRIPT,
      });
      topo.track(() => virtualSsh.cleanup());

      // 1. Verify `discoverRemoteMachines` finds `prod-box` and skips `github.com` / wildcards
      const cleanLocalEnv: LocalEnvironment = {
        antigravity: false,
        claude: false,
        codex: false,
        cursor: false,
        opencode: false,
        gemini: false,
        openclaw: false,
        tailscale: false,
        herdr: { installed: false, inTerminal: false, machines: [] },
        t3: { installed: false, meshConfigured: false, plugins: [] },
      };
      const discovered = discoverRemoteMachines(localHome, cleanLocalEnv);
      assert.deepEqual(
        discovered.map((m) => ({ host: m.host, sources: m.sources })),
        [{ host: "prod-box", sources: ["ssh-config"] }],
      );

      // 2. Prepend isolated virtual `ssh` binDir to PATH (restored in `finally`)
      process.env.PATH = `${virtualSsh.binDir}:${originalPath ?? ""}`;

      const probe = await probeRemoteHost(discovered[0]);
      assert.equal(probe.sshReachable, true, `probeRemoteHost failed: ${probe.error}`);
      assert.equal(probe.hasHyphae, true, "remote should detect hyp in PATH");
      assert.match(probe.nodeVersion ?? "", /^v\d+\./);
      assert.deepEqual([...probe.harnesses].sort(), ["claude", "codex"]);

      // Also verify an unknown host fails gracefully
      const missingProbe = await probeRemoteHost({ host: "nonexistent-box", sources: ["ssh-config"] });
      assert.equal(missingProbe.sshReachable, false);

      // 3. Onboard the virtual remote host via `onboardRemoteOverSsh`
      const remoteToken = teamRouter.addConnector("deploy@prod-box");
      const inviteCode = encodeInvite({
        connectorId: "deploy@prod-box",
        router: teamRouter.url,
        token: remoteToken,
      });

      const onboardRes = await onboardRemoteOverSsh({
        host: "prod-box",
        inviteCode,
      });
      assert.equal(onboardRes.ok, true, `onboardRemoteOverSsh failed:\nSTDOUT:\n${onboardRes.stdout}\nSTDERR:\n${onboardRes.stderr}`);
      assert.match(onboardRes.stdout, /COMMAND: onboard/);
      assert.match(onboardRes.stdout, /STATUS: ok/);
      assert.match(onboardRes.stdout, /deploy@prod-box/);

      // 4. Verify the invite code and raw token NEVER appeared in any `ssh` argv
      const invocations = virtualSsh.readInvocations();
      assert.ok(invocations.length >= 2, `expected at least 2 ssh invocations, saw ${invocations.length}`);
      for (const inv of invocations) {
        const joined = inv.argv.join(" ");
        assert.ok(!joined.includes(inviteCode), "invite code must NEVER appear in ssh argv");
        assert.ok(!joined.includes(remoteToken), "raw connector token must NEVER appear in ssh argv");
      }

      // 5. Verify remote config, 0600 token, and auto-configured harnesses were written in remote dirs
      const remoteCfgPath = join(remoteXdg, "hyphae", "connector.json");
      const remoteTokenPath = join(remoteXdg, "hyphae", "tokens", "primary.token");
      assert.ok(existsSync(remoteCfgPath), "remote connector.json should exist");
      assert.equal(statSync(remoteCfgPath).mode & 0o777, 0o600, "remote connector.json must be 0600");
      assert.ok(existsSync(remoteTokenPath), "remote primary.token should exist");
      assert.equal(statSync(remoteTokenPath).mode & 0o777, 0o600, "remote primary.token must be 0600");
      assert.equal(readFileSync(remoteTokenPath, "utf8").trim(), remoteToken);

      const remoteCfg = JSON.parse(readFileSync(remoteCfgPath, "utf8")) as {
        connectorId: string;
        routers: Array<{ name: string; url: string; tokenFile: string }>;
      };
      assert.equal(remoteCfg.connectorId, "deploy@prod-box");
      assert.equal(remoteCfg.routers[0]?.url, teamRouter.url);

      // Auto-detected remote harnesses `.claude` and `.codex` were configured inside `remoteHome`
      assert.ok(existsSync(join(remoteHome, ".claude", "settings.json")));
      assert.ok(existsSync(join(remoteHome, ".codex", "hooks.json")));
    } finally {
      process.env.PATH = originalPath;
      await topo.cleanup();
    }
  },
);

test(
  "single-host network partition via ChaosProxy: isolated peer drops offline, healthy peers keep messaging, buffered messages deliver on heal",
  { timeout: 30_000 },
  async () => {
    const topo = new MeshTopology("hi-");

    try {
      const teamRouter = await topo.addRouter({ name: "team" });
      const chaosProxy = await startChaosProxy(teamRouter.url);
      topo.track(() => chaosProxy.close());

      // Wrap teamRouter so `jack@prod` routes exclusively through `chaosProxy`
      const proxiedRouter = {
        ...teamRouter,
        get url() { return chaosProxy.url; },
        addConnector: (connectorId: string) => teamRouter.addConnector(connectorId),
      };

      const alex = await topo.addConnector({
        connectorId: "alex@laptop",
        links: [{ name: "primary", router: teamRouter }],
      });
      const alice = await topo.addConnector({
        connectorId: "alice@laptop",
        links: [{ name: "primary", router: teamRouter }],
      });
      const jack = await topo.addConnector({
        connectorId: "jack@prod",
        links: [{ name: "primary", router: proxiedRouter }],
      });

      alex.daemon.state.register("claude:alex-1", { kind: "claude" });
      alice.daemon.state.register("antigravity:alice-1", { kind: "antigravity" });
      jack.daemon.state.register("codex:jack-1", { kind: "codex" });

      await alex.daemon.connector.call("claude:alex-1", "hyp_join", { handle: "dev" });
      await alice.daemon.connector.call("antigravity:alice-1", "hyp_join", { handle: "ops" });
      await jack.daemon.connector.call("codex:jack-1", "hyp_join", { handle: "prod" });

      const getPeers = async () =>
        (await alex.daemon.connector.call("claude:alex-1", "hyp_peers", {})) as {
          peers: Array<{ address: string; online: boolean }>;
        };

      // 1. Wait until all 3 peers are online and verify baseline messaging across ChaosProxy
      await waitFor(
        async () => {
          const { peers } = await getPeers();
          const allOnline = ["alex@laptop/dev", "alice@laptop/ops", "jack@prod/prod"].every((addr) =>
            peers.some((p) => p.address === addr && p.online),
          );
          return allOnline ? peers : null;
        },
        { label: "all 3 peers online before partition" },
      );

      await alex.daemon.connector.call("claude:alex-1", "hyp_send", {
        to: "jack@prod/prod",
        text: "baseline-before-partition",
      });
      const baselineItems = await waitFor(
        () => {
          const drained = jack.daemon.connector.drainMailbox("codex:jack-1", 5);
          return drained.length > 0 ? drained : null;
        },
        { label: "Jack receiving baseline message" },
      );
      assert.match(baselineItems[0].text, /baseline-before-partition/);

      // 2. Sever ONLY jack@prod's link while the Team Router stays alive
      chaosProxy.sever();
      assert.equal(chaosProxy.isSevered(), true);

      // Verify jack@prod goes offline while alex@laptop and alice@laptop stay online
      await waitFor(
        async () => {
          const { peers } = await getPeers();
          const jackPeer = peers.find((p) => p.address === "jack@prod/prod");
          const alexPeer = peers.find((p) => p.address === "alex@laptop/dev");
          const alicePeer = peers.find((p) => p.address === "alice@laptop/ops");
          return jackPeer?.online === false && alexPeer?.online === true && alicePeer?.online === true ? peers : null;
        },
        { label: "jack@prod marked offline while alex & alice stay online" },
      );

      // 3. Healthy peers continue exchanging messages uninterrupted during Jack's partition
      await alex.daemon.connector.call("claude:alex-1", "hyp_send", {
        to: "alice@laptop/ops",
        text: "healthy-peer-message-during-partition",
      });
      const aliceItems = await waitFor(
        () => {
          const drained = alice.daemon.connector.drainMailbox("antigravity:alice-1", 5);
          return drained.length > 0 ? drained : null;
        },
        { label: "Alice receiving message during Jack's partition" },
      );
      assert.match(aliceItems[0].text, /healthy-peer-message-during-partition/);

      // 4. Send a message from alex@laptop to partitioned jack@prod (buffered durably on router)
      const bufferedSend = (await alex.daemon.connector.call("claude:alex-1", "hyp_send", {
        to: "jack@prod/prod",
        text: "buffered-while-partitioned-payload",
      })) as { status: string };
      assert.equal(bufferedSend.status, "stored");
      assert.equal(jack.daemon.state.pendingCount("codex:jack-1"), 0, "Jack must not receive message while severed");

      // 5. Heal the partition -> Jack auto-reconnects and receives the buffered message
      chaosProxy.heal();
      assert.equal(chaosProxy.isSevered(), false);

      await waitFor(
        async () => {
          const { peers } = await getPeers();
          return peers.find((p) => p.address === "jack@prod/prod" && p.online) ?? null;
        },
        { timeoutMs: 8_000, label: "jack@prod auto-reconnecting after heal" },
      );

      const recoveredItems = await waitFor(
        () => {
          const drained = jack.daemon.connector.drainMailbox("codex:jack-1", 5);
          return drained.length > 0 ? drained : null;
        },
        { timeoutMs: 8_000, label: "Jack receiving buffered message after heal" },
      );
      assert.match(recoveredItems[0].text, /alex@laptop\/dev/);
      assert.match(recoveredItems[0].text, /buffered-while-partitioned-payload/);

      // 6. Verify ChaosProxy artificial latency mode still delivers messages cleanly
      chaosProxy.setLatencyMs(40);
      await alex.daemon.connector.call("claude:alex-1", "hyp_send", {
        to: "jack@prod/prod",
        text: "post-heal-with-latency",
      });
      const latencyItems = await waitFor(
        () => {
          const drained = jack.daemon.connector.drainMailbox("codex:jack-1", 5);
          return drained.length > 0 ? drained : null;
        },
        { label: "Jack receiving message under 40ms simulated latency" },
      );
      assert.match(latencyItems[0].text, /post-heal-with-latency/);
    } finally {
      await topo.cleanup();
    }
  },
);
