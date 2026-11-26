/**
 * Cross-Language Verified Human Drops E2E Interop Test (JS `site/drop/crypto.js` <-> Rust `hyp` CLI).
 *
 * Proves bit-for-bit interoperability across:
 *   1. `NodeCertV1` (`hcert1_`): Rust signs -> JS verifies, AND JS signs -> Rust `hyp auth add` verifies
 *   2. `human.draft.v1` (`encDraft`): Rust `hyp drop create --draft` seals -> JS `openHumanDraft` opens
 *   3. `human.drop.v1` (`hdrop1_`) DIRECTIVE: JS `sealHumanDrop` seals -> Rust `hyp drop ingest` opens & verifies
 *      + single-use replay rejection
 *   4. `human.drop.v1` (`hdrop1_`) SECRET: JS `sealHumanDrop` seals -> Rust `hyp drop ingest` opens & stores
 *      into isolated file SecretStore with zero plaintext leakage in stdout/stderr/JSON
 *   5. Mutated-input fail-closed check: 1-bit flip in JS-sealed HPKE ciphertext rejected by Rust `hyp drop ingest`
 *   6. Frame-busting defense (`isEmbeddedInFrame` in `site/drop/drop.js`)
 *
 * Run via:
 *   cargo build -p hyp-cli --offline --locked && node --test site/drop/cross_lang_interop.test.mjs
 */

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { after, before, describe, test } from "node:test";
import { fileURLToPath } from "node:url";

import {
  base64urlDecode,
  base64urlEncode,
  decodeHcert1,
  decodeHdrop1,
  decodeHjoin1,
  decodeHpub1,
  derivePrfEd25519Seed,
  derivePrfX25519Keypair,
  ed25519KeypairFromSeed,
  encodeHdrop1,
  encodeHjoin1,
  encodeHpub1,
  openHumanDraft,
  randomBytes,
  sealHumanDrop,
  signHumanInviteClaim,
  signNodeCert,
  verifyHumanInvite,
  verifyNodeCert,
} from "./crypto.js";

import { isEmbeddedInFrame, parseFragmentString } from "./drop.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, "../..");

function resolveHypBinary() {
  const exe = process.platform === "win32" ? "hyp.exe" : "hyp";
  const candidates = [
    process.env.HYPHAE_BIN,
    join(repoRoot, "target", "debug", exe),
    join(repoRoot, "target", "release", exe),
  ].filter(Boolean);
  for (const cand of candidates) {
    if (existsSync(cand)) {
      return cand;
    }
  }
  throw new Error(
    `Could not locate compiled hyp binary (checked: ${candidates.join(", ")}). ` +
      "Build it first with `cargo build -p hyp-cli --offline --locked` or set HYPHAE_BIN.",
  );
}

function runHyp(hypBin, env, args, stdinText = undefined) {
  const res = spawnSync(hypBin, args, {
    env,
    input: stdinText,
    encoding: "utf8",
    timeout: 20_000,
  });
  if (res.error) {
    throw res.error;
  }
  return res;
}

const PY_PTY_DRIVER = `
import errno, fcntl, json, os, pty, select, subprocess, sys, termios, time

cfg = json.loads(sys.stdin.read())
argv = cfg["argv"]
stdin_data = cfg.get("stdinData")
tty_reply = cfg.get("ttyReply")
timeout = float(cfg.get("timeoutSecs", 20.0))

master_fd, slave_fd = pty.openpty()

def setup_child():
    os.setsid()
    fcntl.ioctl(slave_fd, termios.TIOCSCTTY, 0)

stdin_pipe_r = None
stdin_pipe_w = None
if stdin_data is not None:
    stdin_pipe_r, stdin_pipe_w = os.pipe()
    child_stdin = stdin_pipe_r
else:
    child_stdin = slave_fd

stdout_r, stdout_w = os.pipe()

proc = subprocess.Popen(
    argv,
    stdin=child_stdin,
    stdout=stdout_w,
    stderr=slave_fd,
    preexec_fn=setup_child,
    close_fds=True,
)
os.close(slave_fd)
os.close(stdout_w)
if stdin_pipe_r is not None:
    os.close(stdin_pipe_r)
if stdin_pipe_w is not None:
    raw = stdin_data.encode("utf-8")
    view = memoryview(raw)
    while view:
        written = os.write(stdin_pipe_w, view)
        view = view[written:]
    os.close(stdin_pipe_w)

os.set_blocking(master_fd, False)
os.set_blocking(stdout_r, False)

tty_buf = bytearray()
stdout_buf = bytearray()
replied = False
deadline = time.monotonic() + timeout
stdout_open = True
tty_open = True

def drain_fd(fd, target):
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
        sys.stderr.write(
            f"PTY driver timed out after {timeout}s; tty={tty_buf.decode('utf-8', 'replace')!r}\\n"
        )
        sys.exit(124)

    watch = []
    if tty_open:
        watch.append(master_fd)
    if stdout_open:
        watch.append(stdout_r)

    if watch:
        rlist, _, _ = select.select(watch, [], [], min(0.05, max(0.005, deadline - now)))
    else:
        rlist = []
        time.sleep(0.01)

    if master_fd in rlist:
        tty_open = drain_fd(master_fd, tty_buf)
    if stdout_r in rlist:
        stdout_open = drain_fd(stdout_r, stdout_buf)

    if not replied and b"[y/N]:" in tty_buf:
        replied = True
        if tty_reply is not None:
            os.write(master_fd, tty_reply.encode("utf-8"))
        else:
            os.write(master_fd, b"\\x04")

    if proc.poll() is not None and not rlist:
        if tty_open:
            tty_open = drain_fd(master_fd, tty_buf)
        if stdout_open:
            stdout_open = drain_fd(stdout_r, stdout_buf)
        if not tty_open and not stdout_open:
            break
        time.sleep(0.01)
        if tty_open:
            tty_open = drain_fd(master_fd, tty_buf)
        if stdout_open:
            stdout_open = drain_fd(stdout_r, stdout_buf)
        break

exit_code = proc.wait()
os.close(master_fd)
os.close(stdout_r)
sys.stdout.write(json.dumps({
    "code": exit_code,
    "stdout": stdout_buf.decode("utf-8", errors="replace"),
    "tty": tty_buf.decode("utf-8", errors="replace"),
}))
`;

/**
 * Drives a security-sensitive `hyp` subcommand (such as `hyp auth add`, guarded by `#10`/`H1`
 * interactive TTY confirmation) inside a real POSIX PTY via Python 3 stdlib `pty`, piping
 * `stdinText` to stdin while answering `[y/N]:` on the controlling `/dev/tty` and keeping
 * `--json` stdout cleanly separated.
 */
function runHypInPty(hypBin, env, args, stdinText = undefined, ttyReply = "y\n") {
  const payload = JSON.stringify({
    argv: [hypBin, ...args],
    stdinData: stdinText ?? null,
    ttyReply: ttyReply ?? null,
    timeoutSecs: 20.0,
  });
  const pyRes = spawnSync("python3", ["-c", PY_PTY_DRIVER], {
    env,
    input: payload,
    encoding: "utf8",
    timeout: 25_000,
  });
  if (pyRes.error) {
    throw pyRes.error;
  }
  assert.equal(
    pyRes.status,
    0,
    `POSIX PTY driver failed (exit=${pyRes.status}):\nstdout=${pyRes.stdout}\nstderr=${pyRes.stderr}`,
  );
  const parsed = JSON.parse(pyRes.stdout);
  return {
    status: parsed.code,
    stdout: parsed.stdout,
    stderr: parsed.tty,
  };
}

function parseJsonStdout(res, label) {
  assert.equal(
    res.status,
    0,
    `${label} failed (exit=${res.status}):\nstdout=${res.stdout}\nstderr=${res.stderr}`,
  );
  let parsed;
  try {
    parsed = JSON.parse(res.stdout);
  } catch (err) {
    assert.fail(`${label} emitted invalid JSON (${err.message}):\n${res.stdout}`);
  }
  assert.equal(parsed.ok, true, `${label} returned ok=false:\n${res.stdout}`);
  return parsed;
}

describe("Cross-language Verified Human Drops interop (JS <-> Rust hyp CLI)", () => {
  let tmpRoot;
  let homeDir;
  let stateDir;
  let configPath;
  let hypBin;
  let isoEnv;

  let nodeId;
  let nodeSigningJwk;
  let nodeEncJwk;
  let humanId;
  let humanPrfSalt;
  let humanEdSeed;
  let humanEdKp;
  let humanEncKp;
  let jsSignedHcert1;

  before(async () => {
    hypBin = resolveHypBinary();
    tmpRoot = mkdtempSync(join(tmpdir(), "hyphae-cross-lang-drop-"));
    homeDir = join(tmpRoot, "home");
    stateDir = join(tmpRoot, "state");
    configPath = join(tmpRoot, "node.json");
    mkdirSync(homeDir, { recursive: true });
    mkdirSync(stateDir, { recursive: true });

    nodeId = "interop@testbox";
    writeFileSync(configPath, JSON.stringify({ v: 2, nodeId }, null, 2) + "\n", "utf8");

    isoEnv = {
      PATH: process.env.PATH ?? "",
      HOME: homeDir,
      USERPROFILE: homeDir,
      XDG_CONFIG_HOME: join(homeDir, ".config"),
      XDG_STATE_HOME: join(homeDir, ".local", "state"),
      HYPHAE_SECRET_BACKEND: "file",
    };

    // 1. Initialize Rust node keys & local admin cert via `hyp auth init`.
    const initRes = runHyp(hypBin, isoEnv, [
      "auth",
      "init",
      "--human-id",
      "local-admin",
      "--state-dir",
      stateDir,
      "--config",
      configPath,
      "--json",
    ]);
    const initJson = parseJsonStdout(initRes, "hyp auth init");
    assert.equal(initJson.data.nodeId, nodeId);
    assert.equal(typeof initJson.data.nodeCert, "string");
    assert.ok(initJson.data.nodeCert.startsWith("hcert1_"));

    // Verify JS can decode & cryptographically verify the Rust-signed NodeCertV1!
    const rustSignedCert = decodeHcert1(initJson.data.nodeCert);
    const rustCertPayload = JSON.parse(rustSignedCert.payload);
    nodeSigningJwk = rustCertPayload.signingJwk;
    nodeEncJwk = rustCertPayload.encryptionJwk;

    const rustCertCheck = await verifyNodeCert(
      initJson.data.nodeCert,
      initJson.data.publicJwk,
      nodeId,
      nodeEncJwk,
      Date.now(),
    );
    assert.equal(
      rustCertCheck.ok,
      true,
      `JS verifyNodeCert must accept Rust-signed NodeCertV1: ${JSON.stringify(rustCertCheck)}`,
    );

    // 2. Derive a simulated WebAuthn Passkey+PRF authority in JS and sign a JS NodeCertV1 (`hcert1_`).
    humanId = "alice@phone";
    humanPrfSalt = base64urlEncode(randomBytes(16));
    const fakePrfOut = randomBytes(32);
    humanEdSeed = await derivePrfEd25519Seed(fakePrfOut, humanId, 1);
    humanEdKp = await ed25519KeypairFromSeed(humanEdSeed);
    humanEncKp = await derivePrfX25519Keypair(fakePrfOut, humanId, 1);

    const nowMs = Date.now();
    const jsCert = await signNodeCert(
      {
        nodeId,
        signingJwk: nodeSigningJwk,
        encryptionJwk: nodeEncJwk,
        humanId,
        humanKid: humanEdKp.kid,
        authEpoch: 1,
        issuedAt: new Date(nowMs).toISOString(),
        expiresAt: new Date(nowMs + 365 * 24 * 60 * 60 * 1000).toISOString(),
      },
      humanEdSeed,
    );
    jsSignedHcert1 = jsCert.hcert1;

    // 3. Enroll JS-derived Passkey bundle (including JS-signed hcert1_ and X25519 encJwk) into Rust!
    const enrollmentBundle = {
      v: 1,
      humanId,
      kid: humanEdKp.kid,
      authEpoch: 1,
      prfSalt: humanPrfSalt,
      jwk: humanEdKp.publicJwk,
      encJwk: humanEncKp.publicJwk,
      encKid: humanEncKp.kid,
      nodeCert: jsSignedHcert1,
    };
    const addArgs = [
      "auth",
      "add",
      "--human-id",
      humanId,
      "--label",
      "js-passkey-interop",
      "--role",
      "signer",
      "--state-dir",
      stateDir,
      "--config",
      configPath,
      "--json",
    ];
    // Confirm non-TTY invocation fails closed (`#10`/`H1`), then enroll via real POSIX PTY.
    const nonTtyRes = runHyp(hypBin, isoEnv, addArgs, JSON.stringify(enrollmentBundle));
    assert.equal(nonTtyRes.status, 2, "non-TTY hyp auth add must fail closed with INTERACTIVE_TTY_REQUIRED");
    assert.equal(JSON.parse(nonTtyRes.stdout).error.code, "INTERACTIVE_TTY_REQUIRED");

    const addRes = runHypInPty(hypBin, isoEnv, addArgs, JSON.stringify(enrollmentBundle), "y\n");
    const addJson = parseJsonStdout(addRes, "hyp auth add (JS Passkey bundle + hcert1_)");
    assert.equal(addJson.data.kid, humanEdKp.kid);
    assert.equal(addJson.data.encKid, humanEncKp.kid);
    assert.equal(addJson.data.nodeCertStored, true);
  });

  after(() => {
    if (tmpRoot && existsSync(tmpRoot)) {
      rmSync(tmpRoot, { recursive: true, force: true });
    }
  });

  test("Rust `hyp drop create --draft` seals encDraft + hcert1_ that JS parses, verifies, and opens", async () => {
    const draftText = "Deploy canary v2.5.0 to staging\nCheck p99 latency before promoting.";
    const draftContext = "All CI checks green on main";

    const createRes = runHyp(hypBin, isoEnv, [
      "drop",
      "create",
      "--kind",
      "directive",
      "--offline",
      "--draft",
      draftText,
      "--context",
      draftContext,
      "--state-dir",
      stateDir,
      "--config",
      configPath,
      "--json",
    ]);
    const createJson = parseJsonStdout(createRes, "hyp drop create --draft");
    assert.equal(createJson.data.hasNodeCert, true);
    assert.equal(createJson.data.hasEncDraft, true);

    const hashIdx = createJson.data.url.indexOf("#");
    assert.ok(hashIdx >= 0, "drop URL must contain #fragment");
    const parsed = parseFragmentString(createJson.data.url.slice(hashIdx));
    assert.equal(parsed.mode, "drop");
    assert.equal(parsed.fragment.nodeId, nodeId);
    assert.deepEqual(parsed.fragment.encJwk, nodeEncJwk);
    assert.ok(parsed.fragment.encDraft, "fragment must carry HPKE-encrypted encDraft");
    assert.ok(!createJson.data.url.includes("canary"), "draft text must never appear in URL");

    // Verify JS verifies the nodeCert returned in the invite fragment.
    const certCheck = await verifyNodeCert(
      parsed.fragment.nodeCert,
      humanEdKp.publicKeyBytes,
      parsed.fragment.nodeId,
      parsed.fragment.encJwk,
      Date.now(),
    );
    assert.equal(certCheck.ok, true, `nodeCert check failed: ${JSON.stringify(certCheck)}`);

    // Verify JS opens the Rust-sealed HPKE encDraft!
    const openedDraft = await openHumanDraft({
      encDraft: parsed.fragment.encDraft,
      recipientPriv32: humanEncKp.privateKeyBytes,
      expectedNodeId: parsed.fragment.nodeId,
    });
    assert.equal(openedDraft.nodeId, nodeId);
    assert.equal(openedDraft.text, draftText);
    assert.equal(openedDraft.context, draftContext);
  });

  test("JS seals `hdrop1_` directive -> Rust `hyp drop ingest` opens, verifies & enforces replay guard", async () => {
    const nowMs = Date.now();
    const directiveBody = "Approve production rollout v2.5.0 on interop@testbox — verified via JS WebCrypto.";

    const sealed = await sealHumanDrop({
      claim: {
        v: 1,
        kind: "directive",
        humanId,
        authEpoch: 1,
        issuedAt: new Date(nowMs).toISOString(),
        expiresAt: new Date(nowMs + 5 * 60 * 1000).toISOString(),
        dropId: "",
        audience: { nodeId },
        body: directiveBody,
      },
      humanSeed32: humanEdSeed,
      recipientEncJwk: nodeEncJwk,
    });

    assert.ok(sealed.hdrop1.startsWith("hdrop1_"));
    assert.ok(!sealed.hdrop1.includes("rollout"), "hdrop1_ ciphertext must be opaque");

    const ingestRes = runHyp(
      hypBin,
      isoEnv,
      ["drop", "ingest", "--state-dir", stateDir, "--config", configPath, "--json"],
      sealed.hdrop1,
    );
    const ingestJson = parseJsonStdout(ingestRes, "hyp drop ingest (JS-sealed directive)");
    assert.equal(ingestJson.data.kind, "directive");
    assert.equal(ingestJson.data.humanId, humanId);
    assert.equal(ingestJson.data.kid, humanEdKp.kid);
    assert.equal(ingestJson.data.claimId, sealed.claim.claimId);
    assert.ok(ingestJson.data.mailboxReceipt, "directive must be persisted to local mailbox");
    assert.ok(Number.isInteger(ingestJson.data.auditSeq), "directive must record gate_audit sequence");

    // Replaying the exact same single-use hdrop1_ token MUST fail closed!
    const replayRes = runHyp(
      hypBin,
      isoEnv,
      ["drop", "ingest", "--state-dir", stateDir, "--config", configPath, "--json"],
      sealed.hdrop1,
    );
    assert.notEqual(replayRes.status, 0, "replayed hdrop1_ directive must be rejected");
    const replayJson = JSON.parse(replayRes.stdout);
    assert.equal(replayJson.ok, false);
    assert.match(replayJson.error.message, /replay/i);
  });

  test("JS seals `hdrop1_` secret -> Rust `hyp drop ingest` decrypts, stores securely & never leaks plaintext", async () => {
    const nowMs = Date.now();
    const secretName = "cross-lang-api-key";
    const secretValue = "sk_live_cross_lang_interop_secret_987654321";

    const sealed = await sealHumanDrop({
      claim: {
        v: 1,
        kind: "secret",
        humanId,
        authEpoch: 1,
        issuedAt: new Date(nowMs).toISOString(),
        expiresAt: new Date(nowMs + 5 * 60 * 1000).toISOString(),
        dropId: "",
        audience: { nodeId },
        secretSpec: { name: secretName, overwrite: false },
        body: secretValue,
      },
      humanSeed32: humanEdSeed,
      recipientEncJwk: nodeEncJwk,
    });

    assert.ok(sealed.hdrop1.startsWith("hdrop1_"));
    assert.ok(!sealed.hdrop1.includes(secretName), "hdrop1_ must not leak secretName");
    assert.ok(!sealed.hdrop1.includes(secretValue), "hdrop1_ must not leak secret value");

    const ingestRes = runHyp(
      hypBin,
      isoEnv,
      ["drop", "ingest", "--state-dir", stateDir, "--config", configPath, "--json"],
      sealed.hdrop1,
    );
    const ingestJson = parseJsonStdout(ingestRes, "hyp drop ingest (JS-sealed secret)");
    assert.equal(ingestJson.data.kind, "secret");
    assert.equal(ingestJson.data.secretName, secretName);
    assert.equal(ingestJson.data.humanId, humanId);
    assert.equal(ingestJson.data.kid, humanEdKp.kid);
    assert.equal(ingestJson.data.claimId, sealed.claim.claimId);

    // Zero plaintext leakage on stdout or stderr!
    assert.ok(!ingestRes.stdout.includes(secretValue), "stdout must NEVER contain secret value");
    assert.ok(!ingestRes.stderr.includes(secretValue), "stderr must NEVER contain secret value");

    // Verify stored secret metadata & bit-exact decrypted bytes in isolated file SecretStore.
    const listRes = runHyp(hypBin, isoEnv, ["secret", "list", "--state-dir", stateDir, "--json"]);
    const listJson = parseJsonStdout(listRes, "hyp secret list");
    const entry = listJson.data.secrets.find((s) => s.name === secretName);
    assert.ok(entry, `expected '${secretName}' in hyp secret list`);
    assert.equal(entry.backend, "file");
    assert.ok(entry.bytes >= Buffer.byteLength(secretValue, "utf8"));
    assert.equal(readFileSync(entry.location, "utf8").replace(/\r?\n$/, ""), secretValue);
  });

  test("1-bit ciphertext mutation in JS-sealed `hdrop1_` fails closed in Rust `hyp drop ingest`", async () => {
    const nowMs = Date.now();
    const sealed = await sealHumanDrop({
      claim: {
        v: 1,
        kind: "directive",
        humanId,
        authEpoch: 1,
        issuedAt: new Date(nowMs).toISOString(),
        expiresAt: new Date(nowMs + 5 * 60 * 1000).toISOString(),
        dropId: "",
        audience: { nodeId },
        body: "Mutated ciphertext must never ingest.",
      },
      humanSeed32: humanEdSeed,
      recipientEncJwk: nodeEncJwk,
    });

    const env = decodeHdrop1(sealed.hdrop1);
    const badCt = base64urlDecode(env.ct);
    badCt[badCt.length - 1] ^= 0x01;
    const tamperedToken = encodeHdrop1({ ...env, ct: base64urlEncode(badCt) });

    const res = runHyp(
      hypBin,
      isoEnv,
      ["drop", "ingest", "--state-dir", stateDir, "--config", configPath, "--json"],
      tamperedToken,
    );
    assert.notEqual(res.status, 0, "1-bit flipped HPKE ciphertext MUST fail closed");
    const parsed = JSON.parse(res.stdout);
    assert.equal(parsed.ok, false);
  });

  test("frame-busting detector (`isEmbeddedInFrame`) blocks framed contexts and fails closed on SecurityError", () => {
    const topWin = {};
    topWin.top = topWin;
    topWin.self = topWin;
    assert.equal(isEmbeddedInFrame(topWin), false);

    const framedWin = { top: topWin, self: {} };
    assert.equal(isEmbeddedInFrame(framedWin), true);

    const crossOriginFrame = {
      self: {},
      get top() {
        throw new Error("Blocked a frame with origin from accessing a cross-origin frame");
      },
    };
    assert.equal(isEmbeddedInFrame(crossOriginFrame), true);
  });

  test("Delegated Human-Cert Admission cross-language parity: Rust `hyp auth invite`/`whoami` <-> JS `verifyHumanInvite`/`decodeHpub1`/`encodeHpub1` <-> Rust `hyp auth admit` & `hyp join --stdin`", async () => {
    const hubDir = join(tmpRoot, "delegated-hub");
    const hubState = join(hubDir, "state");
    const hubCfgPath = join(hubDir, "node.json");
    mkdirSync(hubState, { recursive: true });
    writeFileSync(
      hubCfgPath,
      JSON.stringify({
        v: 2,
        nodeId: "interop-hub",
        profile: "router",
        stateDir: hubState,
        listen: { publicUrl: "http://127.0.0.1:1" },
      }),
    );

    // 1. Rust `hyp auth invite` mints `hjoin1_` -> JS `verifyHumanInvite` verifies bit-for-bit!
    const invRes = runHyp(hypBin, isoEnv, [
      "auth",
      "invite",
      "philip",
      "--hub",
      "interop-hub",
      "--endpoint",
      "http://127.0.0.1:1",
      "--node-prefix",
      "philip@*",
      "--max-devices",
      "7",
      "--state-dir",
      hubState,
      "--config",
      hubCfgPath,
      "--json",
    ]);
    const invJson = parseJsonStdout(invRes, "hyp auth invite");
    const hjoin1 = invJson.data.token;
    assert.ok(hjoin1.startsWith("hjoin1_"));
    assert.equal(invJson.data.joinUrl, `https://hyphae.to/join#${hjoin1}`);

    const verified = await verifyHumanInvite(hjoin1);
    assert.equal(verified.ok, true, `JS verifyHumanInvite failed: ${verified.message}`);
    assert.equal(verified.invite.hubNodeId, "interop-hub");
    assert.equal(verified.invite.humanId, "philip");
    assert.equal(verified.invite.nodePrefix, "philip@*");
    assert.equal(verified.invite.maxDevices, 7);

    // 1b. 1-bit signature mutation in Rust-minted `hjoin1_` fails closed in JS!
    const rawEnv = decodeHjoin1(hjoin1);
    const badSigBytes = base64urlDecode(rawEnv.sig);
    badSigBytes[badSigBytes.length - 1] ^= 0x01;
    const tamperedHjoin1 = encodeHjoin1({ ...rawEnv, sig: base64urlEncode(badSigBytes) });
    const badRes = await verifyHumanInvite(tamperedHjoin1);
    assert.equal(badRes.ok, false);
    assert.equal(badRes.reason, "invalid_signature");

    // 2. Rust `hyp auth whoami` emits `hpub1_` -> JS `decodeHpub1` decodes bit-for-bit!
    const whoRes = runHyp(hypBin, isoEnv, [
      "auth",
      "whoami",
      "--state-dir",
      stateDir,
      "--config",
      configPath,
      "--json",
    ]);
    const whoJson = parseJsonStdout(whoRes, "hyp auth whoami");
    const rustHpub1 = whoJson.data.hpub1;
    assert.ok(rustHpub1.startsWith("hpub1_"));
    const decodedRustCard = decodeHpub1(rustHpub1);
    assert.equal(decodedRustCard.humanId, humanId);
    assert.equal(decodedRustCard.signingJwk.crv, "Ed25519");

    // 3. JS `encodeHpub1` -> Rust `hyp auth admit --id` accepts and enrolls!
    const jsPrf = randomBytes(32);
    const jsEdSeed = await derivePrfEd25519Seed(jsPrf, "philip", 1);
    const jsEdKp = await ed25519KeypairFromSeed(jsEdSeed);
    const jsEncKp = await derivePrfX25519Keypair(jsPrf, "philip", 1);
    const jsHpub1 = encodeHpub1({
      v: 1,
      humanId: "philip",
      signingJwk: jsEdKp.publicJwk,
      encJwk: jsEncKp.publicJwk,
    });
    const admitRes = runHyp(hypBin, isoEnv, [
      "auth",
      "admit",
      "philip",
      "--id",
      jsHpub1,
      "--node-prefix",
      "philip@*",
      "--max-devices",
      "4",
      "--state-dir",
      hubState,
      "--config",
      hubCfgPath,
      "--json",
    ]);
    const admitJson = parseJsonStdout(admitRes, "hyp auth admit (JS hpub1_)");
    assert.equal(admitJson.data.humanId, "philip");
    assert.equal(admitJson.data.kid, jsEdKp.kid);
    assert.equal(admitJson.data.nodePrefix, "philip@*");
    assert.equal(admitJson.data.maxDevices, 4);

    // 4. JS `signHumanInviteClaim` + `signNodeCert` -> Rust `hyp join --stdin` verifies ALL
    //    cryptographic signatures (fails only at unreachable HTTPS hub network step, NEVER crypto!).
    const devDir = join(tmpRoot, "delegated-dev");
    const devState = join(devDir, "state");
    const devCfg = join(devDir, "node.json");
    mkdirSync(devState, { recursive: true });
    const cardRes = runHyp(hypBin, isoEnv, [
      "join",
      "--remote",
      "--print-card",
      "--node-id",
      "philip@interop-box",
      "--state-dir",
      devState,
      "--config",
      devCfg,
      "--json",
    ]);
    const cardJson = parseJsonStdout(cardRes, "hyp join --remote --print-card");
    const devCard = cardJson.data.deviceCard;
    const nowMs = Date.now();
    const claimRes = await signHumanInviteClaim(
      {
        inviteId: verified.invite.inviteId,
        hubNodeId: verified.invite.hubNodeId,
        humanId: "philip",
        signingJwk: jsEdKp.publicJwk,
        encJwk: jsEncKp.publicJwk,
        prfSalt: "interop-salt",
        timestamp: new Date(nowMs).toISOString(),
      },
      jsEdSeed,
    );
    const certRes = await signNodeCert(
      {
        nodeId: devCard.nodeId,
        signingJwk: devCard.ed25519Jwk,
        encryptionJwk: devCard.x25519Jwk,
        humanId: "philip",
        humanKid: jsEdKp.kid,
        authEpoch: 1,
        issuedAt: new Date(nowMs).toISOString(),
        expiresAt: new Date(nowMs + 86_400_000).toISOString(),
      },
      jsEdSeed,
    );

    const bundle = {
      hjoin1,
      humanClaim: claimRes.claim,
      humanClaimSig: claimRes.sig,
      humanAuthority: {
        humanId: "philip",
        signingJwk: jsEdKp.publicJwk,
        encJwk: jsEncKp.publicJwk,
        prfSalt: "interop-salt",
        authEpoch: 1,
        label: "js-passkey",
      },
      nodeCert: certRes.hcert1,
      hubNodeId: verified.invite.hubNodeId,
      hubEndpoint: verified.invite.hubEndpoint,
    };

    // Valid JS signatures pass Rust crypto validation and reach `CLAIM_FAILED` (offline loopback port)
    const joinRes = runHyp(
      hypBin,
      isoEnv,
      [
        "join",
        "--stdin",
        "--no-setup",
        "--node-id",
        "philip@interop-box",
        "--state-dir",
        devState,
        "--config",
        devCfg,
        "--json",
      ],
      JSON.stringify(bundle),
    );
    const joinErrJson = JSON.parse(joinRes.stdout);
    assert.equal(
      joinErrJson.error.code,
      "CLAIM_FAILED",
      `expected Rust crypto validation to pass and reach CLAIM_FAILED, got: ${joinRes.stdout}`,
    );

    // 1-bit flip in JS `humanClaimSig` fails immediately at `INVALID_HANDOFF` before any network call!
    const badClaimSigBytes = base64urlDecode(claimRes.sig);
    badClaimSigBytes[0] ^= 0x01;
    const badBundle = { ...bundle, humanClaimSig: base64urlEncode(badClaimSigBytes) };
    const badJoinRes = runHyp(
      hypBin,
      isoEnv,
      [
        "join",
        "--stdin",
        "--no-setup",
        "--node-id",
        "philip@interop-box",
        "--state-dir",
        devState,
        "--config",
        devCfg,
        "--json",
      ],
      JSON.stringify(badBundle),
    );
    const badJoinJson = JSON.parse(badJoinRes.stdout);
    assert.equal(
      badJoinJson.error.code,
      "INVALID_HANDOFF",
      `expected tampered humanClaimSig to fail closed at INVALID_HANDOFF, got: ${badJoinRes.stdout}`,
    );
  });

  test("Non-authoritative `secretExists` hint interop: Rust `hyp drop create` <-> JS `parseFragmentString` & fail-closed UI markup", () => {
    // 1. Secret absent -> `secretExists: false` in CLI JSON & parsed JS fragment.
    const absentRes = runHyp(hypBin, isoEnv, [
      "drop",
      "create",
      "--kind",
      "secret",
      "--secret-name",
      "cross-lang-missing-secret",
      "--offline",
      "--state-dir",
      stateDir,
      "--config",
      configPath,
      "--json",
    ]);
    const absentJson = parseJsonStdout(absentRes, "hyp drop create (secret absent)");
    assert.equal(absentJson.data.secretExists, false);
    const absentParsed = parseFragmentString(
      absentJson.data.url.slice(absentJson.data.url.indexOf("#")),
    );
    assert.equal(absentParsed.mode, "drop");
    assert.equal(absentParsed.fragment.secretName, "cross-lang-missing-secret");
    assert.equal(absentParsed.fragment.secretExists, false);

    // 2. Secret already exists (`cross-lang-api-key` stored earlier) -> `secretExists: true`!
    const presentRes = runHyp(hypBin, isoEnv, [
      "drop",
      "create",
      "--kind",
      "secret",
      "--secret-name",
      "cross-lang-api-key",
      "--offline",
      "--state-dir",
      stateDir,
      "--config",
      configPath,
      "--json",
    ]);
    const presentJson = parseJsonStdout(presentRes, "hyp drop create (secret present)");
    assert.equal(presentJson.data.secretExists, true);
    assert.ok(
      !presentRes.stdout.includes("sk_live_cross_lang_interop_secret_987654321"),
      "secretExists check must NEVER leak secret bytes",
    );
    const presentParsed = parseFragmentString(
      presentJson.data.url.slice(presentJson.data.url.indexOf("#")),
    );
    assert.equal(presentParsed.mode, "drop");
    assert.equal(presentParsed.fragment.secretName, "cross-lang-api-key");
    assert.equal(presentParsed.fragment.secretExists, true);

    // 3. Mutated nearby fragments: directive or non-boolean `secretExists` MUST parse as false!
    const encodeFrag = (obj) => `#drop=${base64urlEncode(new TextEncoder().encode(JSON.stringify(obj)))}`;
    const baseFrag = {
      v: 1,
      nodeId,
      encJwk: nodeEncJwk,
    };
    const dirWithHint = parseFragmentString(
      encodeFrag({ ...baseFrag, kind: "directive", secretExists: true }),
    );
    assert.equal(dirWithHint.fragment.secretExists, false);

    const strBoolHint = parseFragmentString(
      encodeFrag({ ...baseFrag, kind: "secret", secretName: "k", secretExists: "true" }),
    );
    assert.equal(strBoolHint.fragment.secretExists, false);

    // 4. H15 markup invariant: `#chkOverwriteSecret` is never checked by default and `#secretExistsHint` exists.
    const indexHtml = readFileSync(join(__dirname, "index.html"), "utf8");
    assert.ok(indexHtml.includes('id="secretExistsHint"'), "index.html must include #secretExistsHint");
    assert.ok(
      /<input\s+id="chkOverwriteSecret"\s+type="checkbox"\s+disabled\s*\/>/.test(indexHtml),
      "#chkOverwriteSecret must remain unchecked by default (H15)",
    );
  });
});
