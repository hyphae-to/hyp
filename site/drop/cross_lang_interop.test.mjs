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
import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
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
  toCanonicalJson,
  validateApprovalAction,
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

    // Helper: spawn an async `hyp` command, wait for a stderr marker line, run callback, and collect exit + JSON stdout.
    function driveAsyncHyp(args, marker, onMarker, stdinText) {
      return new Promise((resolvePromise, rejectPromise) => {
        const child = spawn(hypBin, args, {
          env: { ...isoEnv, HYPHAE_NO_OPEN: "1" },
          stdio: ["pipe", "pipe", "pipe"],
        });
        child.stdin.end(stdinText ?? "");
        let stdoutBuf = "";
        let stderrBuf = "";
        let lineBuf = "";
        let triggered = false;
        const timer = setTimeout(() => {
          child.kill("SIGKILL");
          rejectPromise(new Error(`Timed out driving hyp ${args.join(" ")}; stderr=${stderrBuf}`));
        }, 20_000);

        child.stdout.setEncoding("utf8");
        child.stdout.on("data", (chunk) => {
          stdoutBuf += chunk;
        });
        child.stderr.setEncoding("utf8");
        child.stderr.on("data", (chunk) => {
          stderrBuf += chunk;
          lineBuf += chunk;
          let nl;
          while ((nl = lineBuf.indexOf("\n")) >= 0) {
            const line = lineBuf.slice(0, nl);
            lineBuf = lineBuf.slice(nl + 1);
            if (!triggered && line.includes(marker)) {
              triggered = true;
              Promise.resolve(onMarker(line)).catch((err) => {
                clearTimeout(timer);
                child.kill("SIGKILL");
                rejectPromise(err);
              });
            }
          }
        });
        child.on("error", (err) => {
          clearTimeout(timer);
          rejectPromise(err);
        });
        child.on("close", (code) => {
          clearTimeout(timer);
          resolvePromise({ code, stdout: stdoutBuf, stderr: stderrBuf });
        });
      });
    }

  async function seedExistingAdmin(state, config) {
    if (!existsSync(join(state, "node.sqlite"))) {
      parseJsonStdout(runHyp(hypBin, isoEnv, ["auth", "init", "--human-id", "fixture-local", "--state-dir", state, "--config", config, "--json"]), "legacy installation fixture");
    }
    const id = "fixture-passkey-admin";
    const prf = randomBytes(32);
    const seed = await derivePrfEd25519Seed(prf, id, 1);
    const key = await ed25519KeypairFromSeed(seed);
    const enc = await derivePrfX25519Keypair(prf, id, 1);
    const db = new DatabaseSync(join(state, "node.sqlite"));
    try {
      db.prepare("INSERT INTO human_authorities (human_id,kid,label,role,jwk_json,enc_jwk_json,prf_salt,auth_epoch,status,created_at) VALUES (?,?,?,'admin',?,?,?,1,'active',?)")
        .run(id, key.kid, "existing-passkey-fixture", JSON.stringify(key.publicJwk), JSON.stringify(enc.publicJwk), "existing-passkey-fixture", Date.now() - 1);
    } finally {db.close();}
    return {id, seed};
  }

  async function approveOperation(args, signer, stdinText) {
    const result = await driveAsyncHyp([...args, "--local", "--no-open"], "Hyphae Passkey approval URL: ", async (line) => {
      const url = line.split("Hyphae Passkey approval URL: ")[1].trim();
      const {fragment} = parseFragmentString(url.slice(url.indexOf("#")));
      const sealed = await sealHumanDrop({claim: {
        v: 1, kind: "approval", humanId: signer.id, authEpoch: 1,
        issuedAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 300_000).toISOString(),
        dropId: fragment.dropId, audience: {nodeId: fragment.nodeId}, body: toCanonicalJson(fragment.approval),
      }, humanSeed32: signer.seed, recipientEncJwk: fragment.encJwk});
      const response = await fetch(`${fragment.relay}/v1/drops/${fragment.dropId}`, {method:"POST",
        headers: {"Content-Type":"text/plain", Origin:"https://hyphae.to", "X-Hyphae-Drop-Cap":fragment.postCap}, body:sealed.hdrop1});
      assert.equal(response.status, 201, await response.text());
    }, stdinText);
    return {status:result.code, stdout:result.stdout, stderr:result.stderr};
  }

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
    // Initial local-key fixtures cannot enroll through a TTY fallback.
    const nonTtyRes = runHyp(hypBin, isoEnv, addArgs, JSON.stringify(enrollmentBundle));
    assert.equal(nonTtyRes.status, 1);
    assert.equal(JSON.parse(nonTtyRes.stdout).error.code, "PASSKEY_AUTHORITY_REQUIRED");
    const approvingAdmin = await seedExistingAdmin(stateDir, configPath);
    const addRes = await approveOperation(addArgs, approvingAdmin, JSON.stringify(enrollmentBundle));
    const addJson = parseJsonStdout(addRes, "live hyp auth add (JS Passkey bundle + hcert1_)");
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
    const hubAdmin = await seedExistingAdmin(hubState, hubCfgPath);
    const admitRes = await approveOperation([
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
    ], hubAdmin);
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

  test("Live per-operation Passkey policy approval E2E cross-language interop (Rust hyp <-> JS crypto.js & drop.js)", async () => {
    const pkRoot = join(tmpRoot, "passkey-gate-interop");
    const pkState = join(pkRoot, "state");
    const pkCfgPath = join(pkRoot, "node.json");
    mkdirSync(pkState, { recursive: true });
    const pkNodeId = "passkey-interop@box";
    writeFileSync(pkCfgPath, JSON.stringify({ v: 2, nodeId: pkNodeId }, null, 2) + "\n", "utf8");

    const pkHumanId = "bogdan@passkey";
    const pkPrfOut = randomBytes(32);
    const pkEdSeed = await derivePrfEd25519Seed(pkPrfOut, pkHumanId, 1);
    const pkEdKp = await ed25519KeypairFromSeed(pkEdSeed);
    const pkEncKp = await derivePrfX25519Keypair(pkPrfOut, pkHumanId, 1);

    // 1. Enroll Passkey Admin via `hyp auth init --web` -> JS verifies #enroll= & signs NodeCertV1!
    const enrollRes = await driveAsyncHyp(
      [
        "auth",
        "init",
        "--web",
        "--human-id",
        pkHumanId,
        "--label",
        "js-passkey-admin",
        "--no-open",
        "--port",
        "0",
        "--timeout",
        "15",
        "--state-dir",
        pkState,
        "--config",
        pkCfgPath,
        "--json",
      ],
      "#enroll=",
      async (line) => {
        const hashIdx = line.indexOf("#enroll=");
        const parsed = parseFragmentString(line.slice(hashIdx).trim());
        assert.equal(parsed.mode, "enroll");
        assert.equal(parsed.payload.nodeId, pkNodeId);
        const nowMs = Date.now();
        const cert = await signNodeCert(
          {
            nodeId: parsed.payload.nodeId,
            signingJwk: parsed.payload.nodeSignJwk,
            encryptionJwk: parsed.payload.nodeEncJwk,
            humanId: pkHumanId,
            humanKid: pkEdKp.kid,
            authEpoch: 1,
            issuedAt: new Date(nowMs).toISOString(),
            expiresAt: new Date(nowMs + 365 * 86_400_000).toISOString(),
          },
          pkEdSeed,
        );
        const resp = await fetch(parsed.payload.callbackUrl, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Origin: "https://hyphae.to",
            "X-Hyphae-CSRF": parsed.payload.csrfToken,
          },
          body: JSON.stringify({
            v: 1,
            humanId: pkHumanId,
            kid: pkEdKp.kid,
            jwk: pkEdKp.publicJwk,
            encJwk: pkEncKp.publicJwk,
            nodeCert: cert.hcert1,
            label: "js-passkey-admin",
            credentialId: "cred-js-interop",
          }),
        });
        assert.equal(resp.status, 200);
      },
    );
    const enrollJson = parseJsonStdout(
      { status: enrollRes.code, stdout: enrollRes.stdout, stderr: enrollRes.stderr },
      "hyp auth init --web (JS Passkey Admin)",
    );
    assert.equal(enrollJson.data.webEnrolled.role, "admin");
    assert.equal(enrollJson.data.passkeyBacked, true);
    assert.equal(enrollJson.data.secretName, null);

    // 2. Stage a filter with a secret ref canary, then run `hyp gate apply --local --no-open`!
    const gateInitRes = runHyp(hypBin, isoEnv, [
      "gate",
      "propose",
      "--adapter",
      "anthropic",
      "--id",
      "js-interop-filter-99",
      "--secret",
      "js-interop-secret-ref",
      "--state-dir",
      pkState,
      "--config",
      pkCfgPath,
      "--json",
    ]);
    parseJsonStdout(gateInitRes, "hyp gate init");

    let lockedAction = null;
    const lockRes = await driveAsyncHyp(
      [
        "gate",
        "apply",
        "--local",
        "--no-open",
        "--state-dir",
        pkState,
        "--config",
        pkCfgPath,
        "--json",
      ],
      "Hyphae Passkey approval URL: ",
      async (line) => {
        const url = line.split("Hyphae Passkey approval URL: ")[1].trim();
        // G7: Zero plaintext filter ID or secret ref in URL!
        assert.ok(!url.includes("js-interop-filter-99"), "filter ID must not leak in URL");
        assert.ok(!url.includes("js-interop-secret-ref"), "secret ref must not leak in URL");

        const parsed = parseFragmentString(url.slice(url.indexOf("#")));
        assert.equal(parsed.mode, "drop");
        assert.equal(parsed.fragment.kind, "approval");
        // The link carries the exact action to sign; the policy is named by hash only.
        const opened = parsed.fragment.approval;
        assert.deepEqual(validateApprovalAction(opened), opened);
        assert.equal(opened.action, "gate.apply");
        assert.equal(opened.locked, true);
        assert.match(opened.policySha256, /^[0-9a-f]{64}$/);
        assert.equal(opened.summary, undefined);
        lockedAction = opened;

        // JS signs & HPKE-seals the `kind: "approval"` drop and POSTs to Rust loopback relay!
        const nowMs = Date.now();
        const sealed = await sealHumanDrop({
          claim: {
            v: 1,
            kind: "approval",
            humanId: pkHumanId,
            authEpoch: 1,
            issuedAt: new Date(nowMs).toISOString(),
            expiresAt: new Date(nowMs + 5 * 60 * 1000).toISOString(),
            dropId: parsed.fragment.dropId,
            audience: { nodeId: pkNodeId },
            body: toCanonicalJson(opened),
          },
          humanSeed32: pkEdSeed,
          recipientEncJwk: parsed.fragment.encJwk,
        });

        const postResp = await fetch(`${parsed.fragment.relay}/v1/drops/${parsed.fragment.dropId}`, {
          method: "POST",
          headers: {
            "Content-Type": "text/plain; charset=utf-8",
            Origin: "https://hyphae.to",
            "X-Hyphae-Drop-Cap": parsed.fragment.postCap,
          },
          body: sealed.hdrop1,
        });
        assert.equal(postResp.status, 201, `expected HTTP 201, got ${postResp.status}: ${await postResp.text()}`);
      },
    );
    const lockJson = parseJsonStdout(
      { status: lockRes.code, stdout: lockRes.stdout, stderr: lockRes.stderr },
      "hyp gate apply (JS Passkey approval)",
    );
    assert.equal(lockJson.data.gatePolicySig, "OK");
    assert.ok(lockedAction);

    // 3. Verify `hyp doctor --json` passes `OK`, then delete `"gate"` from `node.json` and confirm fail-closed!
    const docOk = parseJsonStdout(
      runHyp(hypBin, isoEnv, ["doctor", "--state-dir", pkState, "--config", pkCfgPath, "--json"]),
      "hyp doctor (locked OK)",
    );
    assert.equal(docOk.data.gate.gatePolicySig, "OK");
    assert.equal(docOk.data.gate.tampered, false);

    const lockedCfgRaw = readFileSync(pkCfgPath, "utf8");
    const deletedGateCfg = JSON.parse(lockedCfgRaw);
    delete deletedGateCfg.gate;
    writeFileSync(pkCfgPath, JSON.stringify(deletedGateCfg, null, 2) + "\n", "utf8");

    const docTampered = runHyp(hypBin, isoEnv, [
      "doctor",
      "--state-dir",
      pkState,
      "--config",
      pkCfgPath,
      "--json",
    ]);
    assert.equal(docTampered.status, 1);
    const docTamperedJson = JSON.parse(docTampered.stdout);
    assert.equal(docTamperedJson.data.gate.gatePolicySig, "FAIL");
    assert.equal(docTamperedJson.data.gate.tampered, true);

    // Restore node.json and verify JS `parseFragmentString` fails closed on a missing action,
    // unsigned extra text, and an action aimed at another node.
    writeFileSync(pkCfgPath, lockedCfgRaw, "utf8");
    const encodeFrag = (obj) => `#drop=${base64urlEncode(new TextEncoder().encode(JSON.stringify(obj)))}`;
    const approvalFrag = (approval) =>
      encodeFrag({ v: 1, nodeId: pkNodeId, encJwk: nodeEncJwk, kind: "approval", approval });
    assert.throws(() => parseFragmentString(approvalFrag(undefined)), /approval action/i);
    assert.throws(
      () => parseFragmentString(approvalFrag({ ...lockedAction, summary: ["SPOOF"] })),
      /Unknown approval action field: summary/,
    );
    assert.throws(
      () => parseFragmentString(approvalFrag({ ...lockedAction, nodeId: "other@local" })),
      /different node/,
    );
    assert.equal(parseFragmentString(approvalFrag(lockedAction)).fragment.approval.action, "gate.apply");

    // 4. Rust `hyp gate apply --local --no-open` <-> JS signs `gate.unlock`!
    const unlockRes = await driveAsyncHyp(
      [
        "gate",
        "apply",
        "--local",
        "--no-open",
        "--state-dir",
        pkState,
        "--config",
        pkCfgPath,
        "--json",
      ],
      "Hyphae Passkey approval URL: ",
      async (line) => {
        const url = line.split("Hyphae Passkey approval URL: ")[1].trim();
        const parsed = parseFragmentString(url.slice(url.indexOf("#")));
        const opened = parsed.fragment.approval;
        assert.equal(opened.action, "gate.apply");
        assert.equal(opened.locked, true);
        assert.notEqual(opened.nonce, lockedAction.nonce);

        const nowMs = Date.now();
        const sealed = await sealHumanDrop({
          claim: {
            v: 1,
            kind: "approval",
            humanId: pkHumanId,
            authEpoch: 1,
            issuedAt: new Date(nowMs).toISOString(),
            expiresAt: new Date(nowMs + 5 * 60 * 1000).toISOString(),
            dropId: parsed.fragment.dropId,
            audience: { nodeId: pkNodeId },
            body: toCanonicalJson(opened),
          },
          humanSeed32: pkEdSeed,
          recipientEncJwk: parsed.fragment.encJwk,
        });
        const postResp = await fetch(`${parsed.fragment.relay}/v1/drops/${parsed.fragment.dropId}`, {
          method: "POST",
          headers: {
            "Content-Type": "text/plain; charset=utf-8",
            Origin: "https://hyphae.to",
            "X-Hyphae-Drop-Cap": parsed.fragment.postCap,
          },
          body: sealed.hdrop1,
        });
        assert.equal(postResp.status, 201);
      },
    );
    const unlockJson = parseJsonStdout(
      { status: unlockRes.code, stdout: unlockRes.stdout, stderr: unlockRes.stderr },
      "hyp gate apply (JS Passkey approval)",
    );
    assert.equal(unlockJson.data.approved, true);

    const docUnlocked = parseJsonStdout(
      runHyp(hypBin, isoEnv, ["doctor", "--state-dir", pkState, "--config", pkCfgPath, "--json"]),
      "hyp doctor (unlocked)",
    );
    assert.equal(docUnlocked.data.gate.gatePolicySig, "OK");
    assert.equal(docUnlocked.data.gate.tampered, false);

    // 5. Approval UI markup invariant: `#approvalReviewGroup` & `#approvalConfirmCheck` exist and unchecked by default.
    const indexHtml = readFileSync(join(__dirname, "index.html"), "utf8");
    assert.ok(indexHtml.includes('id="approvalReviewGroup"'));
    assert.ok(/<input\s+id="approvalConfirmCheck"\s+type="checkbox"\s*\/>/.test(indexHtml));
  });
});
