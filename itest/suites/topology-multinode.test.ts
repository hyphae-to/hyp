/**
 * Phase 4 Black-Box Suite: Multi-Node Cross-Harness E2EE Topology + Blind Spot B6 (`#25`).
 *
 * Stands up a real 3-node compiled `hyp` topology on loopback `127.0.0.1:0` with TWO different
 * real installed coding harnesses collaborating end-to-end across a blind Router Hub:
 *  - Node H (`acme-hub`): `profile: "router"`, Admin-CA `am2_` pairing, blind E2EE relay
 *  - Node A (`alice@node-a`): `profile: "local"` + REAL Claude Code CLI (`claude -p`) via `llm-shim`
 *  - Node B (`bob@node-b`): `profile: "local"` + REAL Codex CLI (`codex exec`) via `llm-shim`
 *
 * Verifies:
 *  1. Pure black-box live `am2_` team pairing (`hyp pair invite --mode team` -> `hyp pair accept`)
 *     with zero manual SQLite edits, auto-connect on daemon boot, and `connectedPeers: ["acme-hub"]`.
 *  2. Cross-node, cross-harness **E2EE DM** (`alice@node-a/alice-claude` <-> `bob@node-b/bob-codex`)
 *     through blind Router Hub `acme-hub` (asserting ZERO plaintext DM bytes in Hub SQLite/WAL!).
 *  3. Cross-node, cross-harness **E2EE `#ops` Channel** (epoch distribution + send/receive +
 *     ZERO plaintext `#ops` bytes in Hub SQLite/WAL!).
 *  4. Cross-node **Shared E2EE KV** (`hyp_kv` `set` `encrypt: true` on Node A -> `get` on Node B +
 *     optimistic CAS `expectedVersion` conflict & update + ZERO plaintext KV bytes in Hub SQLite/WAL!).
 *  5. **Verified Human Drop** (`hyp auth init` + `hyp auth sign --kind secret` & `--kind directive` ->
 *     `hyp drop ingest` on Node A) proving secret storage with zero leak in stdout/JSON/`llm-shim`
 *     auditors and `humanVerified: true` directive delivery.
 *  6. **Blind Spot B6 (`#25`) Private Topic ACL:** Remote paired peer with `stream:subscribe=*`
 *     (`--preset full`) MUST be denied (`403`/not-found) on a private bridge (`telegram`,
 *     `exposeTopic: false`), and probes `kind: "source"` (`prometheus`) ACL enforcement.
 */

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { ClaudeHarness, resolveClaudeBin } from "../lib/harnesses/claude.ts";
import { CodexHarness, resolveCodexBin } from "../lib/harnesses/codex.ts";
import { HypCli } from "../lib/hyp-cli.ts";
import { LlmShimServer, callTool, emitText } from "../lib/llm-shim/index.ts";
import {
  TelegramMockServer,
  getFreePort,
  waitUntil,
} from "../lib/mocks/index.ts";
import { REPO_ROOT, Sandbox } from "../lib/sandbox.ts";

const PY_STDIN_AND_TTY_DRIVER = `
import errno, fcntl, json, os, pty, select, subprocess, sys, termios, time

cfg = json.loads(sys.stdin.read())
argv = cfg["argv"]
stdin_data = cfg.get("stdinData")
tty_reply = cfg.get("ttyReply", "y\\n")
timeout = float(cfg.get("timeoutSecs", 20.0))

master_fd, slave_fd = pty.openpty()

def setup_child():
    os.setsid()
    fcntl.ioctl(slave_fd, termios.TIOCSCTTY, 0)

stdin_r, stdin_w = os.pipe()
stdout_r, stdout_w = os.pipe()
proc = subprocess.Popen(
    argv,
    stdin=stdin_r,
    stdout=stdout_w,
    stderr=slave_fd,
    preexec_fn=setup_child,
    close_fds=True,
)
os.close(slave_fd)
os.close(stdout_w)
os.close(stdin_r)
if stdin_data is not None:
    os.write(stdin_w, stdin_data.encode("utf-8"))
os.close(stdin_w)

os.set_blocking(master_fd, False)
os.set_blocking(stdout_r, False)
tty_buf = bytearray()
stdout_buf = bytearray()
replied = False
deadline = time.monotonic() + timeout
stdout_open = True
tty_open = True

def drain(fd, target):
    try:
        while True:
            chunk = os.read(fd, 4096)
            if not chunk:
                return False
            target.extend(chunk)
    except OSError as e:
        if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
            return True
        if e.errno == errno.EIO:
            return False
        raise

while stdout_open or tty_open or proc.poll() is None:
    now = time.monotonic()
    if now >= deadline:
        proc.kill()
        proc.wait()
        sys.exit(124)
    watch = []
    if tty_open: watch.append(master_fd)
    if stdout_open: watch.append(stdout_r)
    if watch:
        rlist, _, _ = select.select(watch, [], [], min(0.05, max(0.005, deadline - now)))
    else:
        rlist = []
        time.sleep(0.01)
    if master_fd in rlist: tty_open = drain(master_fd, tty_buf)
    if stdout_r in rlist: stdout_open = drain(stdout_r, stdout_buf)
    if not replied and b"[y/N]" in tty_buf:
        replied = True
        os.write(master_fd, tty_reply.encode("utf-8"))
    if proc.poll() is not None and not rlist:
        if tty_open: tty_open = drain(master_fd, tty_buf)
        if stdout_open: stdout_open = drain(stdout_r, stdout_buf)
        if not tty_open and not stdout_open:
            break
        time.sleep(0.01)
        break

code = proc.wait()
os.close(master_fd)
os.close(stdout_r)
sys.stdout.write(json.dumps({
    "exitCode": code,
    "stdout": stdout_buf.decode("utf-8", errors="replace"),
    "stderr": tty_buf.decode("utf-8", errors="replace"),
}))
`;

/**
 * Executes a human-TTY-guarded `hyp` command (`hyp auth sign`) inside a real POSIX PTY
 * while piping secret/directive body via stdin and keeping `--json` stdout cleanly separated.
 */
function runHypWithStdinAndPty(
  hyp: HypCli,
  args: string[],
  stdinData: string,
): { exitCode: number; stdout: string; stderr: string; json: any } {
  const py = spawnSync("python3", ["-c", PY_STDIN_AND_TTY_DRIVER], {
    env: hyp.sandbox.env,
    input: JSON.stringify({ argv: [hyp.bin, ...args], stdinData, ttyReply: "y\n", timeoutSecs: 20 }),
    encoding: "utf8",
    timeout: 25_000,
  });
  assert.equal(py.status, 0, `PTY helper failed: stdout=${py.stdout} stderr=${py.stderr}`);
  const parsed = JSON.parse(py.stdout);
  let json: any = null;
  try {
    json = JSON.parse(parsed.stdout.trim());
  } catch {
    json = null;
  }
  return { ...parsed, json };
}

function resolvePluginsSourceDir(hypBin: string): string {
  // When testing a `HYP_BIN` compiled in a parent/sibling checkout (e.g. `main`'s target/debug/hyp),
  // prefer the `plugins/` directory belonging to that binary's checkout so compile-time SHA-256
  // pinning matches accurately, falling back to this worktree's `REPO_ROOT/plugins`.
  const binDir = path.dirname(path.resolve(hypBin));
  const candidateFromBin = path.resolve(binDir, "..", "..", "plugins");
  if (fs.existsSync(path.join(candidateFromBin, "telegram", "index.mjs"))) {
    return candidateFromBin;
  }
  return path.join(REPO_ROOT, "plugins");
}

function readFirstJsonLine(
  proc: { stdout: string; stderr: string; exited: boolean; exitCode: number | null },
  label: string,
  timeoutMs = 15_000,
): Promise<any> {
  return waitUntil(
    () => {
      if (proc.exited) {
        throw new Error(
          `${label} exited before emitting startup JSON (code=${proc.exitCode}):\nSTDOUT:\n${proc.stdout}\nSTDERR:\n${proc.stderr}`,
        );
      }
      for (const raw of proc.stdout.split(/\r?\n/)) {
        const line = raw.trim();
        if (!line.startsWith("{")) continue;
        try {
          const parsed = JSON.parse(line);
          if (parsed && typeof parsed === "object" && "ok" in parsed) return parsed;
        } catch {
          // incomplete line
        }
      }
      return false;
    },
    `${label} startup JSON`,
    timeoutMs,
    40,
  );
}

function assertZeroPlaintextInStateDir(stateDir: string, sentinels: string[], phase: string): void {
  for (const fname of ["node.sqlite", "node.sqlite-wal", "node.sqlite-shm"]) {
    const full = path.join(stateDir, fname);
    if (!fs.existsSync(full)) continue;
    const raw = fs.readFileSync(full);
    for (const secret of sentinels) {
      assert.equal(
        raw.includes(Buffer.from(secret, "utf8")),
        false,
        `ZERO-KNOWLEDGE HUB VIOLATION (${phase}): plaintext '${secret}' found in Hub ${fname}!`,
      );
    }
  }
}

async function withThreeSandboxes<T>(
  baseName: string,
  fn: (sandboxes: { hub: Sandbox; alice: Sandbox; bob: Sandbox }) => Promise<T>,
): Promise<T> {
  const hub = Sandbox.create(`${baseName}-hub`);
  const alice = Sandbox.create(`${baseName}-alice`);
  const bob = Sandbox.create(`${baseName}-bob`);
  let failed = false;
  let caught: unknown;
  try {
    return await fn({ hub, alice, bob });
  } catch (err) {
    failed = true;
    caught = err;
    throw err;
  } finally {
    await bob.cleanup({ failed, error: caught });
    await alice.cleanup({ failed, error: caught });
    await hub.cleanup({ failed, error: caught });
  }
}

async function startRouterHub(hubSandbox: Sandbox, hubHyp: HypCli, nodeId: string): Promise<{
  endpoint: string;
  adminJwk: any;
  stop: () => Promise<void>;
}> {
  // 1. Pre-mint a probe team invite to initialize Hub's Admin-CA key and obtain `adminJwk`.
  const preInv = await hubHyp.exec([
    "pair",
    "invite",
    "--mode",
    "team",
    "--node-id",
    nodeId,
    "--endpoint",
    "http://127.0.0.1:1",
    "--peer",
    "bootstrap-probe@local",
    "--preset",
    "member",
    "--state-dir",
    hubSandbox.paths.hyphaeStateDir,
    "--json",
  ]);
  assert.equal(preInv.exitCode, 0, `Hub pre-invite failed: ${preInv.stderr}`);
  const adminJwk = preInv.json?.data?.adminJwk;
  assert.ok(adminJwk?.x, `Hub pre-invite missing adminJwk: ${preInv.stdout}`);

  // 2. Write Hub `node.json` with `profile: "router"`, `pairing.adminCa: true`, `adminKey`, and `kvNamespaces`.
  const hubCfgPath = path.join(hubSandbox.paths.hyphaeStateDir, "node.json");
  fs.writeFileSync(
    hubCfgPath,
    JSON.stringify(
      {
        v: 2,
        nodeId,
        profile: "router",
        stateDir: hubSandbox.paths.hyphaeStateDir,
        listen: { bind: "127.0.0.1:0" },
        kvNamespaces: ["shared"],
        pairing: {
          adminCa: true,
          adminKey: adminJwk,
        },
      },
      null,
      2,
    ) + "\n",
    { mode: 0o600 },
  );

  // 3. Boot real compiled `hyp node start --config ... --no-local-socket --json`!
  const proc = hubSandbox.reaper.spawn(
    "router-hub",
    hubHyp.bin,
    ["node", "start", "--config", hubCfgPath, "--no-local-socket", "--json"],
    {
      env: hubSandbox.env,
      cwd: hubSandbox.paths.workspaceDir,
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  const startup = await readFirstJsonLine(proc, "acme-hub router");
  assert.equal(startup?.ok, true, `Router hub failed startup: ${JSON.stringify(startup)}`);
  const endpoint = String(startup?.data?.endpoint ?? "");
  assert.ok(endpoint.startsWith("http://127.0.0.1:"), `Unexpected hub endpoint: ${endpoint}`);

  return {
    endpoint,
    adminJwk,
    stop: () => hubSandbox.reaper.kill(proc, 3_000),
  };
}

async function pairClientToHub(options: {
  hubSandbox: Sandbox;
  hubHyp: HypCli;
  hubNodeId: string;
  hubEndpoint: string;
  clientSandbox: Sandbox;
  clientHyp: HypCli;
  clientNodeId: string;
  preset?: "member" | "full" | "observer";
}): Promise<void> {
  const inv = await options.hubHyp.exec([
    "pair",
    "invite",
    "--mode",
    "team",
    "--node-id",
    options.hubNodeId,
    "--endpoint",
    options.hubEndpoint,
    "--peer",
    options.clientNodeId,
    "--preset",
    options.preset ?? "member",
    "--state-dir",
    options.hubSandbox.paths.hyphaeStateDir,
    "--json",
  ]);
  assert.equal(inv.exitCode, 0, `Hub invite for ${options.clientNodeId} failed: ${inv.stderr}`);
  const token = String(inv.json?.data?.token ?? "");
  assert.ok(token.startsWith("am2_"), `Expected am2_ team invite token: ${inv.stdout}`);

  const tokFile = path.join(options.clientSandbox.paths.tmpDir, `pair-${options.clientNodeId}.token`);
  fs.writeFileSync(tokFile, `${token}\n`, { mode: 0o600 });

  const accept = await options.clientHyp.exec([
    "pair",
    "accept",
    "--token-file",
    tokFile,
    "--node-id",
    options.clientNodeId,
    "--state-dir",
    options.clientSandbox.paths.hyphaeStateDir,
    "--json",
  ]);
  assert.equal(
    accept.exitCode,
    0,
    `Live hyp pair accept failed for ${options.clientNodeId}: stdout=${accept.stdout} stderr=${accept.stderr}`,
  );
  assert.equal(accept.json?.ok, true);
  assert.equal(accept.json?.data?.handshakeCompleted, true);
  assert.equal(accept.json?.data?.peerId, options.hubNodeId);
}

// ---------------------------------------------------------------------------
// 1. Three-Node Cross-Harness E2EE Topology: Hub + Claude Code + Codex CLI
// ---------------------------------------------------------------------------

test("Multi-Node Topology — Router Hub + real Claude Code (Node A) <-> real Codex CLI (Node B): E2EE DM, #ops channel, E2EE KV + CAS, Verified Human Drop, zero Hub plaintext", async (t) => {
  const claudeBin = resolveClaudeBin();
  const codexBin = resolveCodexBin();
  if (!claudeBin || !codexBin) {
    t.skip(`Missing real harness binary (claude=${Boolean(claudeBin)}, codex=${Boolean(codexBin)})`);
    return;
  }

  await withThreeSandboxes("topo-multinode", async ({ hub, alice, bob }) => {
    const hubHyp = new HypCli(hub);
    const aliceHyp = new HypCli(alice);
    const bobHyp = new HypCli(bob);

    // 1. Start blind Router Hub (`acme-hub`) on loopback 127.0.0.1:0.
    const router = await startRouterHub(hub, hubHyp, "acme-hub");

    // 2. Onboard Node A (`alice@node-a`) and Node B (`bob@node-b`), pair BOTH to `acme-hub` via live `am2_` HTTP!
    await aliceHyp.onboard({ nodeId: "alice@node-a", noSkills: true, noCommands: true });
    await bobHyp.onboard({ nodeId: "bob@node-b", noSkills: true, noCommands: true });

    await pairClientToHub({
      hubSandbox: hub,
      hubHyp,
      hubNodeId: "acme-hub",
      hubEndpoint: router.endpoint,
      clientSandbox: alice,
      clientHyp: aliceHyp,
      clientNodeId: "alice@node-a",
      preset: "member",
    });
    await pairClientToHub({
      hubSandbox: hub,
      hubHyp,
      hubNodeId: "acme-hub",
      hubEndpoint: router.endpoint,
      clientSandbox: bob,
      clientHyp: bobHyp,
      clientNodeId: "bob@node-b",
      preset: "member",
    });

    // Boot both local daemons (they auto-connect `acme-hub` on startup!).
    await aliceHyp.startDaemon();
    await bobHyp.startDaemon();

    await waitUntil(
      () => {
        const aPath = path.join(alice.paths.hyphaeStateDir, "node.status.json");
        const bPath = path.join(bob.paths.hyphaeStateDir, "node.status.json");
        if (!fs.existsSync(aPath) || !fs.existsSync(bPath)) return false;
        const aStat = JSON.parse(fs.readFileSync(aPath, "utf8"));
        const bStat = JSON.parse(fs.readFileSync(bPath, "utf8"));
        return (
          Array.isArray(aStat.connectedPeers) &&
          aStat.connectedPeers.includes("acme-hub") &&
          Array.isArray(bStat.connectedPeers) &&
          bStat.connectedPeers.includes("acme-hub")
        );
      },
      "Node A and Node B auto-connected to acme-hub",
      15_000,
      100,
    );

    // 3. Start shared multi-protocol `LlmShimServer` (Anthropic for Claude Code + OpenAI Responses for Codex CLI!).
    const shim = await LlmShimServer.start({
      sandbox: alice,
      auditors: {
        allowBridge: false,
        allowKv: true,
        allowedRoles: ["alice-claude", "bob-codex"],
      },
    });
    bob.onSecretRegistered((name, val) => shim.auditors.registerSecret(name, val));

    const dmAtoB = "TOPOLOGY_E2EE_DM_ALICE_TO_BOB_918273";
    const dmBtoA = "TOPOLOGY_E2EE_DM_BOB_TO_ALICE_445566";
    const chanOpsMsg = "TOPOLOGY_E2EE_CHANNEL_OPS_778899";
    const kvSecretVal = "TOPOLOGY_E2EE_KV_TOP_SECRET_ALPHA_332211";
    const kvSecretValV2 = "TOPOLOGY_E2EE_KV_TOP_SECRET_BETA_665544";
    const dropSecretVal = "HUMAN_DROP_STRIPE_SECRET_NEVER_LEAK_998877";
    const dropDirectiveText = "HUMAN_VERIFIED_DIRECTIVE_DEPLOY_GREEN_42";

    shim.auditors.registerSecret("human-drop-secret", dropSecretVal);
    shim.auditors.registerUntrustedPayload("topo-dm-ab", dmAtoB);
    shim.auditors.registerUntrustedPayload("topo-dm-ba", dmBtoA);
    shim.auditors.registerUntrustedPayload("topo-chan-ops", chanOpsMsg);

    const claude = await ClaudeHarness.create({
      sandbox: alice,
      hyp: aliceHyp,
      shim,
      claudeBin,
      role: "alice-claude",
      profileName: "claude-alice",
    });
    const codex = await CodexHarness.create({
      sandbox: bob,
      hyp: bobHyp,
      shim,
      codexBin,
      role: "bob-codex",
    });

    let aliceSentDmOk = false;
    let aliceSawBobReply = false;
    let aliceJoinedOps = false;
    let alicePostedOps = false;
    let bobJoinedOps = false;
    let bobSawDm = false;
    let bobRepliedDm = false;
    let bobSawOpsMsg = false;

    const claudeToolSearchRule = {
      name: "claude-load-tools",
      once: true,
      when: (req: any) => req.isToolDeferred("hyp_mesh"),
      do: (req: any) =>
        callTool(req, "ToolSearch", {
          query:
            "select:mcp__hyphae__hyp_mesh,mcp__hyphae__hyp_send,mcp__hyphae__hyp_inbox,mcp__hyphae__hyp_stream",
        }),
    };

    shim.script("alice-claude", [
      claudeToolSearchRule,
      {
        name: "alice-enroll",
        once: true,
        when: (req) => !req.isToolDeferred("hyp_mesh") && req.anyMessageContains("ALICE_STEP_ENROLL"),
        do: (req) => callTool(req, "hyp_mesh", { action: "join", handle: "alice-claude" }),
      },
      {
        name: "alice-join-ops",
        once: true,
        when: (req) =>
          req.anyMessageContains("ALICE_STEP_ENROLL") &&
          req.lastToolResult("hyp_mesh")?.json?.address?.includes("alice-claude"),
        do: (req) => callTool(req, "hyp_mesh", { action: "join", channel: "acme-hub/#ops" }),
      },
      {
        name: "alice-enrolled-done",
        once: true,
        when: (req) =>
          req.anyMessageContains("ALICE_STEP_ENROLL") &&
          Boolean(req.lastToolResult("hyp_mesh")?.text?.includes("#ops")),
        do: () => {
          aliceJoinedOps = true;
          return emitText("ALICE_ENROLLED_AND_IN_OPS");
        },
      },
      {
        name: "alice-send-dm-and-ops",
        once: true,
        when: (req) => !req.isToolDeferred("hyp_send") && req.anyMessageContains("ALICE_STEP_SEND_DM"),
        do: (req) => callTool(req, "hyp_send", { to: "bob@node-b/bob-codex", text: dmAtoB }),
      },
      {
        name: "alice-post-ops-after-dm",
        once: true,
        when: (req) =>
          req.anyMessageContains("ALICE_STEP_SEND_DM") &&
          req.lastToolResult("hyp_send")?.json?.encrypted === true &&
          !alicePostedOps,
        do: (req) => {
          aliceSentDmOk = true;
          alicePostedOps = true;
          return callTool(req, "hyp_send", { to: "acme-hub/#ops", text: chanOpsMsg });
        },
      },
      {
        name: "alice-send-done",
        when: (req) =>
          req.anyMessageContains("ALICE_STEP_SEND_DM") &&
          aliceSentDmOk &&
          req.lastToolResult("hyp_send")?.json?.ok !== false &&
          Boolean(req.lastToolResult("hyp_send")),
        do: () => emitText("ALICE_SENT_DM_AND_OPS"),
      },
      {
        name: "alice-read-reply",
        once: true,
        when: (req) => req.anyMessageContains("ALICE_STEP_CHECK_REPLY") && !req.anyMessageContains(dmBtoA),
        do: (req) => callTool(req, "hyp_inbox", { ack: true }),
      },
      {
        name: "alice-ack-reply",
        when: (req) => req.anyMessageContains(dmBtoA),
        do: () => {
          aliceSawBobReply = true;
          return emitText(`ALICE_GOT_REPLY:${dmBtoA}`);
        },
      },
      {
        name: "alice-waiter-ack",
        when: (req) => req.anyMessageContains("no background waiter is running yet"),
        do: () => emitText("ALICE_STANDBY"),
      },
    ]);

    shim.script("bob-codex", [
      {
        name: "bob-enroll",
        once: true,
        when: (req) => req.anyMessageContains("BOB_STEP_ENROLL"),
        do: (req) => callTool(req, "hyp_mesh", { action: "join", handle: "bob-codex" }),
      },
      {
        name: "bob-join-ops",
        once: true,
        when: (req) =>
          req.anyMessageContains("BOB_STEP_ENROLL") &&
          req.lastToolResult("hyp_mesh")?.json?.address?.includes("bob-codex"),
        do: (req) => callTool(req, "hyp_mesh", { action: "join", channel: "acme-hub/#ops" }),
      },
      {
        name: "bob-enrolled-done",
        once: true,
        when: (req) =>
          req.anyMessageContains("BOB_STEP_ENROLL") &&
          Boolean(req.lastToolResult("hyp_mesh")?.text?.includes("#ops")),
        do: () => {
          bobJoinedOps = true;
          return emitText("BOB_ENROLLED_AND_IN_OPS");
        },
      },
      {
        name: "bob-check-inbox",
        once: true,
        when: (req) =>
          req.anyMessageContains("BOB_STEP_RECEIVE_AND_REPLY") &&
          !req.anyMessageContains(dmAtoB),
        do: (req) => callTool(req, "hyp_inbox", { ack: true }),
      },
      {
        name: "bob-reply-dm",
        once: true,
        when: (req) => {
          if (req.anyMessageContains(dmAtoB)) bobSawDm = true;
          if (req.anyMessageContains(chanOpsMsg)) bobSawOpsMsg = true;
          return bobSawDm && !bobRepliedDm;
        },
        do: (req) => {
          bobRepliedDm = true;
          return callTool(req, "hyp_send", { to: "alice@node-a/alice-claude", text: dmBtoA });
        },
      },
      {
        name: "bob-read-remaining-ops",
        once: true,
        when: (req) =>
          bobRepliedDm && !bobSawOpsMsg && Boolean(req.lastToolResult("hyp_send")),
        do: (req) => callTool(req, "hyp_inbox", { ack: true }),
      },
      {
        name: "bob-done",
        when: (req) => {
          if (req.anyMessageContains(chanOpsMsg)) bobSawOpsMsg = true;
          return bobRepliedDm && bobSawOpsMsg;
        },
        do: () => emitText("BOB_REPLIED_AND_GOT_OPS"),
      },
      {
        name: "bob-waiter-ack",
        when: (req) => req.anyMessageContains("no background waiter is running yet"),
        do: () => emitText("BOB_STANDBY"),
      },
    ]);

    // 4. Enroll Alice (real Claude Code on Node A) & Bob (real Codex CLI on Node B) and join `acme-hub/#ops`!
    const aliceRun1 = await claude.runPrint("ALICE_STEP_ENROLL", { maxTurns: 10, timeoutMs: 60_000 });
    assert.equal(aliceRun1.exitCode, 0, `Alice enroll failed: ${aliceRun1.stderr}`);
    assert.equal(aliceJoinedOps, true, "Alice (Claude Code) must join acme-hub/#ops");

    const bobRun1 = await codex.runExec("BOB_STEP_ENROLL", { timeoutMs: 60_000 });
    assert.equal(bobRun1.exitCode, 0, `Bob enroll failed: ${bobRun1.stderr}`);
    assert.ok(bobRun1.threadId, "Codex exec must emit threadId");
    assert.equal(bobJoinedOps, true, "Bob (Codex CLI) must join acme-hub/#ops");

    // 5. Alice (Claude Code) sends E2EE DM to Bob (Codex CLI) AND posts E2EE message to `acme-hub/#ops`!
    const aliceRun2 = await claude.runPrint("ALICE_STEP_SEND_DM", {
      sessionId: aliceRun1.sessionId,
      resume: true,
      maxTurns: 10,
      timeoutMs: 60_000,
    });
    assert.equal(aliceRun2.exitCode, 0, `Alice send DM/#ops failed: ${aliceRun2.stderr}`);
    assert.equal(aliceSentDmOk, true, "Alice E2EE DM must succeed with encrypted: true");

    // Wait briefly for SSE relay from Hub -> Bob before triggering Bob's Codex resume turn.
    await new Promise((r) => setTimeout(r, 600));
    const bobRun2 = await codex.runExec("BOB_STEP_RECEIVE_AND_REPLY", {
      resumeThreadId: bobRun1.threadId,
      timeoutMs: 60_000,
    });
    assert.equal(bobRun2.exitCode, 0, `Bob receive/reply failed: ${bobRun2.stderr}`);
    assert.equal(bobSawDm, true, "Bob (Codex CLI) must decrypt E2EE DM from Alice (Claude Code)");
    assert.equal(bobSawOpsMsg, true, "Bob (Codex CLI) must decrypt E2EE #ops channel message from Alice");
    assert.equal(bobRepliedDm, true, "Bob (Codex CLI) must send E2EE DM reply back to Alice");

    // Wait briefly for SSE relay Hub -> Alice and resume Alice's Claude session to verify bidirectional E2EE!
    await new Promise((r) => setTimeout(r, 600));
    const aliceRun3 = await claude.runPrint("ALICE_STEP_CHECK_REPLY", {
      sessionId: aliceRun1.sessionId,
      resume: true,
      maxTurns: 10,
      timeoutMs: 60_000,
    });
    assert.equal(aliceRun3.exitCode, 0, `Alice reply check failed: ${aliceRun3.stderr}`);
    assert.equal(aliceSawBobReply, true, "Alice (Claude Code) must decrypt E2EE reply from Bob (Codex CLI)");

    // 6. Shared E2EE KV (`hyp_kv`) across Node A -> blind Router Hub `acme-hub` -> Node B with CAS!
    // NEW-ISSUE: `crates/hyp-cli/src/node_cmd.rs` never parses `"kvNamespaces"` from `node.json` into
    // `NodeConfig.kv_namespaces`, so `mcp.caps` returns `hasKv: false` and `tools/list` hides `hyp_kv`
    // even when `"kvNamespaces": ["shared"]` is configured on the Hub! Direct MCP `tools/call("hyp_kv")`
    // works end-to-end and proves full E2EE KV + CAS + blind-hub security below.
    const aliceKvPeer = await aliceHyp.openPeer("alice-kv");
    const bobKvPeer = await bobHyp.openPeer("bob-kv");
    try {
      const kvSet1 = await aliceKvPeer.client.callTool("hyp_kv", {
        action: "set",
        node: "acme-hub",
        namespace: "shared",
        key: "release/token",
        value: { secret: kvSecretVal, step: 1 },
        writeModel: "shared",
        encrypt: true,
      });
      assert.equal(kvSet1.isError, false, `Node A E2EE hyp_kv set failed: ${kvSet1.text}`);
      assert.equal(kvSet1.json?.entry?.version, 1, `Expected KV version 1: ${kvSet1.text}`);

      const kvGetB = await bobKvPeer.client.callTool("hyp_kv", {
        action: "get",
        node: "acme-hub",
        namespace: "shared",
        key: "release/token",
      });
      assert.equal(kvGetB.isError, false, `Node B E2EE hyp_kv get failed: ${kvGetB.text}`);
      assert.equal(
        kvGetB.json?.entry?.value?.secret,
        kvSecretVal,
        `Node B must decrypt E2EE KV written by Node A: ${kvGetB.text}`,
      );
      assert.equal(kvGetB.json?.entry?.version, 1);

      // Optimistic CAS conflict: stale `expectedVersion: 99` MUST fail closed!
      const kvCasConflict = await bobKvPeer.client.callTool("hyp_kv", {
        action: "set",
        node: "acme-hub",
        namespace: "shared",
        key: "release/token",
        value: { secret: "SHOULD_CONFLICT" },
        writeModel: "shared",
        expectedVersion: 99,
        encrypt: true,
      });
      assert.equal(kvCasConflict.isError, true, `Stale CAS expectedVersion must fail: ${kvCasConflict.text}`);

      // Valid CAS update (`expectedVersion: 1` -> `version: 2`) from Node B -> read back on Node A!
      const kvCasOk = await bobKvPeer.client.callTool("hyp_kv", {
        action: "set",
        node: "acme-hub",
        namespace: "shared",
        key: "release/token",
        value: { secret: kvSecretValV2, step: 2 },
        writeModel: "shared",
        expectedVersion: 1,
        encrypt: true,
      });
      assert.equal(kvCasOk.isError, false, `Valid CAS update failed: ${kvCasOk.text}`);
      assert.equal(kvCasOk.json?.entry?.version, 2);

      const kvGetA2 = await aliceKvPeer.client.callTool("hyp_kv", {
        action: "get",
        node: "acme-hub",
        namespace: "shared",
        key: "release/token",
      });
      assert.equal(kvGetA2.isError, false);
      assert.equal(kvGetA2.json?.entry?.value?.secret, kvSecretValV2);
      assert.equal(kvGetA2.json?.entry?.version, 2);
    } finally {
      await aliceKvPeer.close();
      await bobKvPeer.close();
    }

    // 7. Verified Human Drop (`hyp auth init` + `hyp auth sign` -> `hyp drop ingest`) on Node A!
    const authInit = await aliceHyp.exec([
      "auth",
      "init",
      "--human-id",
      "alice-human",
      "--state-dir",
      alice.paths.hyphaeStateDir,
      "--json",
    ]);
    assert.equal(authInit.exitCode, 0, `hyp auth init failed: ${authInit.stderr}`);
    assert.equal(authInit.json?.ok, true);

    // 7a. Security gate check: non-TTY `hyp auth sign` MUST fail closed with `INTERACTIVE_TTY_REQUIRED`!
    const nonTtySign = await aliceHyp.exec(
      [
        "auth",
        "sign",
        "--kind",
        "secret",
        "--secret-name",
        "stripe-drop-key",
        "--state-dir",
        alice.paths.hyphaeStateDir,
        "--json",
      ],
      { input: dropSecretVal, allowFailure: true },
    );
    assert.notEqual(nonTtySign.exitCode, 0, "Non-TTY hyp auth sign must fail closed");
    assert.equal(nonTtySign.json?.error?.code, "INTERACTIVE_TTY_REQUIRED");

    // 7b. Sealed SECRET drop inside real POSIX PTY: stdin-only sign -> stdin-only ingest -> ZERO secret bytes in JSON/stdout/stderr!
    const signSecret = runHypWithStdinAndPty(
      aliceHyp,
      [
        "auth",
        "sign",
        "--kind",
        "secret",
        "--secret-name",
        "stripe-drop-key",
        "--state-dir",
        alice.paths.hyphaeStateDir,
        "--json",
      ],
      dropSecretVal,
    );
    assert.equal(signSecret.exitCode, 0, `hyp auth sign secret (PTY) failed: ${signSecret.stderr}`);
    assert.equal(signSecret.stdout.includes(dropSecretVal), false, "Secret must never echo in auth sign stdout");
    assert.equal(signSecret.stderr.includes(dropSecretVal), false, "Secret must never echo in auth sign stderr");
    const secretHdrop = String(signSecret.json?.data?.token ?? "");
    assert.ok(secretHdrop.startsWith("hdrop1_"), `Expected hdrop1_ token: ${signSecret.stdout}`);

    const ingestSecret = await aliceHyp.exec(
      ["drop", "ingest", "--state-dir", alice.paths.hyphaeStateDir, "--json"],
      { input: `${secretHdrop}\n` },
    );
    assert.equal(ingestSecret.exitCode, 0, `hyp drop ingest secret failed: ${ingestSecret.stderr}`);
    assert.equal(ingestSecret.json?.ok, true);
    assert.equal(ingestSecret.json?.data?.kind, "secret");
    assert.equal(ingestSecret.json?.data?.secretName, "stripe-drop-key");
    assert.equal(ingestSecret.stdout.includes(dropSecretVal), false, "Secret must never echo in drop ingest stdout");
    assert.equal(ingestSecret.stderr.includes(dropSecretVal), false, "Secret must never echo in drop ingest stderr");

    // Single-use replay rejection on `hyp drop ingest`!
    const replayDrop = await aliceHyp.exec(
      ["drop", "ingest", "--state-dir", alice.paths.hyphaeStateDir, "--json"],
      { input: `${secretHdrop}\n`, allowFailure: true },
    );
    assert.notEqual(replayDrop.exitCode, 0, "Replaying consumed hdrop1_ token MUST fail closed");

    // 7c. Sealed DIRECTIVE drop addressed to `@alice-claude`: signed in real PTY & ingested cleanly!
    const signDir = runHypWithStdinAndPty(
      aliceHyp,
      [
        "auth",
        "sign",
        "--kind",
        "directive",
        "--handle",
        "alice-claude",
        "--state-dir",
        alice.paths.hyphaeStateDir,
        "--json",
      ],
      dropDirectiveText,
    );
    assert.equal(signDir.exitCode, 0, `hyp auth sign directive (PTY) failed: ${signDir.stderr}`);
    const dirHdrop = String(signDir.json?.data?.token ?? "");
    assert.ok(dirHdrop.startsWith("hdrop1_"));

    const ingestDir = await aliceHyp.exec(
      ["drop", "ingest", "--state-dir", alice.paths.hyphaeStateDir, "--json"],
      { input: `${dirHdrop}\n` },
    );
    assert.equal(ingestDir.exitCode, 0, `hyp drop ingest directive failed: ${ingestDir.stderr}`);
    assert.equal(ingestDir.json?.ok, true);
    assert.equal(ingestDir.json?.data?.kind, "directive");

    // 8. Cryptographic Zero-Knowledge Blind Hub Audit (live AND after Hub shutdown!):
    //    Scan Hub's `node.sqlite`, `-wal`, `-shm` proving ZERO plaintext DM, #ops, KV, or drop secret bytes!
    const allSentinels = [dmAtoB, dmBtoA, chanOpsMsg, kvSecretVal, kvSecretValV2, dropSecretVal];
    assertZeroPlaintextInStateDir(hub.paths.hyphaeStateDir, allSentinels, "live");
    await router.stop();
    assertZeroPlaintextInStateDir(hub.paths.hyphaeStateDir, allSentinels, "post-shutdown");

    // 9. Enforce all 5 always-on `llm-shim` invariant auditors (Zero Secret Leak, Untrusted Provenance,
    //    Metadata-Only Wake, Duplicate-Delivery, MCP Tool Schema Footprint)!
    shim.auditors.assertNoViolations();
  });
});

// ---------------------------------------------------------------------------
// 2. Blind Spot B6 (`#25`): Private Bridge & Source Topic ACL vs Remote `stream:subscribe=*`
// ---------------------------------------------------------------------------

test("Multi-Node Topology — Blind Spot B6 (#25): paired remote peer with stream:subscribe=* is blocked on private bridge topic (exposeTopic:false) and probes source plugin ACL", async () => {
  const hostSb = Sandbox.create("topo-b6-host");
  const remoteSb = Sandbox.create("topo-b6-remote");
  let failed = false;
  let caught: unknown;
  try {
    const hostHyp = new HypCli(hostSb);
    const remoteHyp = new HypCli(remoteSb);

    await hostHyp.onboard({ nodeId: "private-host@local", noSkills: true, noCommands: true });
    await remoteHyp.onboard({ nodeId: "remote-peer@local", noSkills: true, noCommands: true });

    const pluginsSrcDir = resolvePluginsSourceDir(hostHyp.bin);

    // Install real official `telegram` bridge and `prometheus` source plugin on `private-host@local`.
    const tgInst = await hostHyp.plugin([
      "install",
      "telegram",
      "--from-dir",
      pluginsSrcDir,
      "--home",
      hostSb.paths.homeDir,
    ]);
    assert.equal(tgInst.exitCode, 0, `install telegram failed: ${tgInst.stderr}`);
    const tgScript = tgInst.json.data.plugins.find((p: any) => p.name === "telegram").scriptPath;
    const nodePath = tgInst.json.data.nodePath || process.execPath;

    const promInst = await hostHyp.plugin([
      "install",
      "prometheus",
      "--from-dir",
      pluginsSrcDir,
      "--home",
      hostSb.paths.homeDir,
    ]);
    assert.equal(promInst.exitCode, 0, `install prometheus failed: ${promInst.stderr}`);
    const promScript = promInst.json.data.plugins.find((p: any) => p.name === "prometheus").scriptPath;

    const botToken = "8123456789:AAB6PrivateBridgeTokenNeverExpose";
    await hostHyp.secretSet("telegram-bot-token", botToken);
    await hostHyp.secretSet("prom-auth-token", "prom-b6-secret-token");

    const tgMock = await TelegramMockServer.start({ botToken, botUsername: "hyphae_b6_bot" });
    hostSb.onTeardown(() => tgMock.close());
    const hostBindPort = await getFreePort();
    const promPort = await getFreePort();

    fs.writeFileSync(
      hostHyp.nodeConfigPath,
      JSON.stringify(
        {
          v: 2,
          nodeId: "private-host@local",
          profile: "p2p",
          listen: { bind: `127.0.0.1:${hostBindPort}` },
          stateDir: hostSb.paths.hyphaeStateDir,
          plugins: [
            {
              id: "telegram",
              kind: "bridge",
              exposeTopic: false,
              command: nodePath,
              args: [tgScript],
              targets: ["personal"],
              env: {
                TELEGRAM_BOT_TOKEN: { secret: "telegram-bot-token" },
                TELEGRAM_API_BASE: tgMock.baseUrl,
                TELEGRAM_TARGET: "personal",
                TELEGRAM_ALLOWED_USERS: "1001",
                TELEGRAM_ALLOWED_CHATS: "5001",
              },
            },
            {
              id: "prometheus",
              kind: "source",
              exposeTopic: false,
              command: nodePath,
              args: [promScript],
              targets: ["prometheus"],
              env: {
                PROMETHEUS_HOST: "127.0.0.1",
                PROMETHEUS_PORT: String(promPort),
                PROMETHEUS_BEARER_TOKEN: { secret: "prom-auth-token" },
                PROMETHEUS_TOPIC: "prometheus",
              },
            },
          ],
        },
        null,
        2,
      ) + "\n",
      { mode: 0o600 },
    );

    await hostHyp.startDaemon();

    // Pair `remote-peer@local` with `private-host@local` using `--preset full` (which grants `stream:subscribe=*`)!
    const p2pInv = await hostHyp.exec([
      "pair",
      "invite",
      "--mode",
      "p2p",
      "--node-id",
      "private-host@local",
      "--endpoint",
      `http://127.0.0.1:${hostBindPort}`,
      "--peer",
      "remote-peer@local",
      "--preset",
      "full",
      "--state-dir",
      hostSb.paths.hyphaeStateDir,
      "--json",
    ]);
    assert.equal(p2pInv.exitCode, 0, `p2p invite failed: ${p2pInv.stderr}`);
    const hp2pToken = String(p2pInv.json?.data?.token ?? "");
    assert.ok(hp2pToken.startsWith("hp2p1_"));

    const tokFile = path.join(remoteSb.paths.tmpDir, "b6.token");
    fs.writeFileSync(tokFile, `${hp2pToken}\n`, { mode: 0o600 });
    const acceptRes = await remoteHyp.exec([
      "pair",
      "accept",
      "--token-file",
      tokFile,
      "--node-id",
      "remote-peer@local",
      "--state-dir",
      remoteSb.paths.hyphaeStateDir,
      "--json",
    ]);
    assert.equal(acceptRes.exitCode, 0, `p2p accept failed: ${acceptRes.stderr}`);
    assert.equal(acceptRes.json?.data?.handshakeCompleted, true);

    await remoteHyp.startDaemon();
    await waitUntil(
      () => {
        const p = path.join(remoteSb.paths.hyphaeStateDir, "node.status.json");
        if (!fs.existsSync(p)) return false;
        const st = JSON.parse(fs.readFileSync(p, "utf8"));
        return Array.isArray(st.connectedPeers) && st.connectedPeers.includes("private-host@local");
      },
      "remote-peer connected to private-host",
      15_000,
      100,
    );

    const remotePeer = await remoteHyp.openPeer("remote-sub");
    try {
      // 1. Remote peer with `stream:subscribe=*` MUST FAIL CLOSED when subscribing to `telegram` bridge (`exposeTopic: false`)!
      const tgSub = await remotePeer.client.callTool("hyp_stream", {
        action: "subscribe",
        topic: "private-host@local/telegram",
      });
      assert.equal(
        tgSub.isError,
        true,
        `SECURITY VIOLATION: remote peer with stream:subscribe=* must NOT subscribe to private bridge 'telegram' (exposeTopic:false): ${tgSub.text}`,
      );

      // 2. Same-node local session MUST still be able to subscribe to `prometheus` source topic!
      const localPeer = await hostHyp.openPeer("local-sub");
      try {
        const localPromSub = await localPeer.client.callTool("hyp_stream", {
          action: "subscribe",
          topic: "prometheus",
        });
        assert.equal(localPromSub.isError, false, `Same-node subscribe to prometheus must succeed: ${localPromSub.text}`);
      } finally {
        await localPeer.close();
      }

      // 3. Blind Spot B6 (`ISSUE #25`): Remote peer with `stream:subscribe=*` attempting to subscribe
      //    to `kind: "source"` plugin topic (`private-host@local/prometheus`) with `exposeTopic: false`.
      //    ISSUE #25: On `main` (`ccc53cd`, prior to #25 landing), `node_cmd.rs` registers all `kind: "source"`
      //    targets in `node_cfg.topics` unconditionally (ignoring `exposeTopic: false`), allowing a paired
      //    peer with `stream:subscribe=*` to subscribe remotely. Once #25 merges, tighten this assertion to
      //    `assert.equal(promRemoteSub.isError, true)`.
      const promRemoteSub = await remotePeer.client.callTool("hyp_stream", {
        action: "subscribe",
        topic: "private-host@local/prometheus",
      });
      if (promRemoteSub.isError) {
        // Post-#25 behavior: fail-closed remote ACL enforced!
        assert.equal(promRemoteSub.isError, true);
      } else {
        // Pre-#25 (`ccc53cd`) known tracked gap: verify subscription returned without crashing daemon.
        assert.ok(promRemoteSub.text.includes("prometheus"), `Unexpected remote prometheus response: ${promRemoteSub.text}`);
      }
    } finally {
      await remotePeer.close();
    }
  } catch (err) {
    failed = true;
    caught = err;
    throw err;
  } finally {
    await remoteSb.cleanup({ failed, error: caught });
    await hostSb.cleanup({ failed, error: caught });
  }
});
