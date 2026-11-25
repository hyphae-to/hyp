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
  derivePrfEd25519Seed,
  derivePrfX25519Keypair,
  ed25519KeypairFromSeed,
  encodeHdrop1,
  openHumanDraft,
  randomBytes,
  sealHumanDrop,
  signNodeCert,
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
    const addRes = runHyp(
      hypBin,
      isoEnv,
      [
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
      ],
      JSON.stringify(enrollmentBundle),
    );
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
});
