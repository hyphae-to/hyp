/**
 * Differential & Mutated-Input Verification Suite for `site/drop/crypto.js` & `site/drop/drop.js`.
 *
 * Verifies bit-for-bit parity with Rust `hyp-crypto`:
 * - RFC 8785 JCS edge cases (matching `crates/hyp-crypto/src/jcs.rs`)
 * - Strict unpadded base64url (RFC 4648 §5)
 * - Power-of-2 bucket padding (`256 B .. 32 KiB`, 2B u16 BE prefix, matching `e2ee.rs`)
 * - Frozen golden Ed25519/X25519 keys, JWK thumbprints, fingerprints, small-order points & HPKE vectors
 *   loaded directly from `crates/hyp-crypto/tests/fixtures/v1_crypto_vectors.json`
 * - Official RFC 9180 Appendix A.1.1 HPKE known-answer vector
 * - Differential native WebCrypto vs. pure-JS BigInt fallback parity (Ed25519 + X25519)
 * - WebAuthn PRF -> HKDF-SHA256 -> Ed25519 seed derivation
 * - `NodeCertV1` (`hcert1_`) verification & tamper rejection
 * - Full `sealHumanDrop` -> `openHumanDrop` (`directive` + `secret`) & `hdrop1_` roundtrip + bit-flips
 * - Reserved system-secret denylist & secret name validator
 * - `drop.js` fragment parser security invariants (ignores `proposedText`, rejects insecure relays)
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  AEAD_AES_128_GCM,
  base64urlDecode,
  base64urlEncode,
  bucketSizeFor,
  decodeHdrop1,
  derivePrfEd25519Seed,
  ed25519KeypairFromSeed,
  ed25519Sign,
  ed25519Verify,
  encodeHdrop1,
  hexDecode,
  hexEncode,
  hpkeDeriveKeyPairX25519,
  hpkeOpenBase,
  hpkeSealBase,
  HUMAN_DROP_SUITE,
  isReservedSecretName,
  isSmallOrderEd25519Point,
  jwkThumbprint,
  MAX_PADDED_PLAINTEXT,
  openHumanDrop,
  padBucket,
  prfEvalInput,
  randomBytes,
  sasFingerprint,
  sealHumanDrop,
  signNodeCert,
  toCanonicalJson,
  unpadBucket,
  utf8Bytes,
  validateSecretName,
  verifyNodeCert,
  x25519DeriveSharedSecret,
  x25519PublicFromPrivate,
  _ed25519SignPure,
  _ed25519VerifyPure,
  _x25519DhPure,
  _x25519PublicFromPrivatePure,
} from "../site/drop/crypto.js";

import {
  isAllowedRelayUrl,
  isLoopbackCallbackUrl,
  parseFragmentString,
} from "../site/drop/drop.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, "..");

let passed = 0;

async function test(name, fn) {
  await fn();
  passed += 1;
  console.log(`  PASS  ${name}`);
}

console.log("Running Hyphae Verified Human Drops WebCrypto & Parity Suite...");

// ----------------------------------------------------------------------------
// 1. Strict Base64url (RFC 4648 §5)
// ----------------------------------------------------------------------------
await test("base64url strict unpadded roundtrip & malformed input rejection", async () => {
  for (let len = 0; len <= 65; len++) {
    const raw = randomBytes(len);
    const enc = base64urlEncode(raw);
    assert.ok(!enc.includes("="), "must be unpadded");
    assert.ok(!enc.includes("+") && !enc.includes("/"), "must be url-safe");
    assert.deepEqual(base64urlDecode(enc), raw);
  }
  assert.throws(() => base64urlDecode("abc="), /Invalid base64url/);
  assert.throws(() => base64urlDecode("a"), /Invalid unpadded base64url length/);
  assert.throws(() => base64urlDecode("ab+c"), /Invalid base64url/);
  assert.throws(() => base64urlDecode("ab/c"), /Invalid base64url/);
  assert.throws(() => base64urlDecode("AB"), /Non-canonical trailing bits/);
  assert.throws(() => base64urlDecode("AAB"), /Non-canonical trailing bits/);
});

// ----------------------------------------------------------------------------
// 2. RFC 8785 JCS (Exact Parity with `crates/hyp-crypto/src/jcs.rs`)
// ----------------------------------------------------------------------------
await test("RFC 8785 JCS UTF-16 sorting, number normalization & control escapes", async () => {
  const val1 = {
    "\ue000": "pua",
    "\u{1f600}": "emoji",
    b: 2,
    a: 1,
    "\r": "cr",
    omitted: undefined,
  };
  assert.equal(
    toCanonicalJson(val1),
    '{"\\r":"cr","a":1,"b":2,"\u{1f600}":"emoji","\ue000":"pua"}'
  );

  const val2 = {
    neg_zero: -0.0,
    small: 1e-7,
    fixed_small: 1e-6,
    big_int: 1e20,
    sci_big: 1e21,
    ctrl: "\u0000\u0008\u000c\n\r\t\"\\/",
  };
  assert.equal(
    toCanonicalJson(val2),
    '{"big_int":100000000000000000000,"ctrl":"\\u0000\\b\\f\\n\\r\\t\\"\\\\/","fixed_small":0.000001,"neg_zero":0,"sci_big":1e+21,"small":1e-7}'
  );

  assert.throws(() => toCanonicalJson({ x: NaN }), /Non-finite/);
  assert.throws(() => toCanonicalJson({ x: Infinity }), /Non-finite/);
  assert.throws(() => toCanonicalJson({ x: -Infinity }), /Non-finite/);
});

// ----------------------------------------------------------------------------
// 3. Bucket Padding (Exact Parity with `crates/hyp-crypto/src/e2ee.rs`)
// ----------------------------------------------------------------------------
await test("padBucket/unpadBucket exact 2B u16 BE layout & mutated-input fail-closed", async () => {
  assert.equal(bucketSizeFor(0), 256);
  assert.equal(bucketSizeFor(254), 256);
  assert.equal(bucketSizeFor(255), 512);
  assert.equal(bucketSizeFor(510), 512);
  assert.equal(bucketSizeFor(511), 1024);
  assert.equal(bucketSizeFor(MAX_PADDED_PLAINTEXT), 32768);
  assert.throws(() => bucketSizeFor(MAX_PADDED_PLAINTEXT + 1), /exceeds maximum/);

  for (const len of [0, 1, 17, 254, 255, 510, 511, 4094, 4095, MAX_PADDED_PLAINTEXT]) {
    const pt = randomBytes(len);
    const padded = padBucket(pt);
    assert.equal(padded.length, bucketSizeFor(len));
    // Verify exact 2-byte big-endian length header
    assert.equal((padded[0] << 8) | padded[1], len);
    // Verify trailing zeros
    for (let i = 2 + len; i < padded.length; i++) {
      assert.equal(padded[i], 0);
    }
    assert.deepEqual(unpadBucket(padded), pt);
  }

  // Mutated padded buffers MUST fail closed
  const valid = padBucket(utf8Bytes("hyphae-bucket"));
  const badTrail = new Uint8Array(valid);
  badTrail[badTrail.length - 1] = 1;
  assert.throws(() => unpadBucket(badTrail), /Non-zero trailing/);

  const nonMinimal = new Uint8Array(512);
  nonMinimal[0] = 0;
  nonMinimal[1] = 10;
  assert.throws(() => unpadBucket(nonMinimal), /Corrupt bucket padding/);

  assert.throws(() => unpadBucket(new Uint8Array(300)), /Invalid padded bucket length/);
  assert.throws(() => unpadBucket(new Uint8Array(128)), /Invalid padded bucket length/);
  assert.throws(() => unpadBucket(new Uint8Array(65536)), /Invalid padded bucket length/);
});

// ----------------------------------------------------------------------------
// 4. Frozen Rust Golden Vectors (`v1_crypto_vectors.json`) Interop
// ----------------------------------------------------------------------------
await test("frozen Rust golden keys, JWK thumbprints, fingerprints, small-order & HPKE vectors", async () => {
  const fixturePath = resolve(repoRoot, "crates/hyp-crypto/tests/fixtures/v1_crypto_vectors.json");
  const fixture = JSON.parse(readFileSync(fixturePath, "utf8"));

  const xPrivByName = new Map();

  for (const k of fixture.keys) {
    const seed = hexDecode(k.seedHex);
    if (k.keyType === "ed25519") {
      const kp = await ed25519KeypairFromSeed(seed);
      assert.equal(base64urlEncode(kp.publicKeyBytes), k.rawPubB64, `Ed25519 pub ${k.name}`);
      assert.deepEqual(kp.publicJwk, k.jwk, `Ed25519 jwk ${k.name}`);
      assert.equal(kp.kid, k.jwkThumbprint, `Ed25519 kid ${k.name}`);
      assert.equal(await jwkThumbprint(k.jwk), k.jwkThumbprint);
      const sas = await sasFingerprint(k.jwk);
      assert.equal(sas.hex, k.fingerprint, `Ed25519 fingerprint ${k.name}`);
    } else if (k.keyType === "x25519") {
      const pub = await x25519PublicFromPrivate(seed);
      assert.equal(base64urlEncode(pub), k.rawPubB64, `X25519 pub ${k.name}`);
      assert.equal(await jwkThumbprint(k.jwk), k.jwkThumbprint, `X25519 kid ${k.name}`);
      const sas = await sasFingerprint(k.jwk);
      assert.equal(sas.hex, k.fingerprint, `X25519 fingerprint ${k.name}`);
      xPrivByName.set(k.name, seed);
    }
  }

  for (const check of fixture.smallOrderChecks) {
    assert.equal(
      isSmallOrderEd25519Point(hexDecode(check.pointHex)),
      check.isSmallOrder,
      `small-order check ${check.pointHex}`
    );
  }

  assert.equal(fixture.hpkeVectors.length, 3);
  for (const vec of fixture.hpkeVectors) {
    const recipientPriv = xPrivByName.get(vec.recipientKeyName);
    const enc = hexDecode(vec.encHex);
    const info = hexDecode(vec.infoHex);
    const aad = hexDecode(vec.aadHex);
    const ct = hexDecode(vec.ciphertextHex);
    const expectedPt = base64urlDecode(vec.plaintextB64);

    const opened = await hpkeOpenBase(recipientPriv, enc, info, aad, ct);
    assert.deepEqual(opened, expectedPt, `HPKE golden open ${vec.name}`);

    // Mutated copies MUST fail closed
    const badCt = new Uint8Array(ct);
    badCt[badCt.length - 1] ^= 0x01;
    await assert.rejects(() => hpkeOpenBase(recipientPriv, enc, info, aad, badCt));

    const badEnc = new Uint8Array(enc);
    badEnc[0] ^= 0x01;
    await assert.rejects(() => hpkeOpenBase(recipientPriv, badEnc, info, aad, ct));

    await assert.rejects(() =>
      hpkeOpenBase(recipientPriv, enc, utf8Bytes("wrong-info"), aad, ct)
    );
    await assert.rejects(() =>
      hpkeOpenBase(recipientPriv, enc, info, utf8Bytes("wrong-aad"), ct)
    );
  }
});

// ----------------------------------------------------------------------------
// 5. Official RFC 9180 Appendix A.1.1 Known-Answer Vector
// ----------------------------------------------------------------------------
await test("RFC 9180 Appendix A.1.1 exact known-answer HPKE vector", async () => {
  const info = hexDecode("4f6465206f6e2061204772656369616e2055726e");
  const ikmE = hexDecode("7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234");
  const expectedSkE = "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736";
  const expectedPkE = "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431";

  const ikmR = hexDecode("6db9df30aa07dd42ee5e8181afdb977e538f5e1fec8a06223f33f7013e525037");
  const expectedSkR = "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8";
  const expectedPkR = "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d";

  const kpE = await hpkeDeriveKeyPairX25519(ikmE);
  assert.equal(hexEncode(kpE.sk), expectedSkE);
  assert.equal(hexEncode(kpE.pk), expectedPkE);

  const kpR = await hpkeDeriveKeyPairX25519(ikmR);
  assert.equal(hexEncode(kpR.sk), expectedSkR);
  assert.equal(hexEncode(kpR.pk), expectedPkR);

  const pt = hexDecode("4265617574792069732074727574682c20747275746820626561757479");
  const aad0 = hexDecode("436f756e742d30");
  const expectedCt0 =
    "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a";

  const { enc, ciphertext } = await hpkeSealBase(kpR.pk, info, aad0, pt, {
    aeadId: AEAD_AES_128_GCM,
    ephemeralIkm: ikmE,
  });
  assert.equal(hexEncode(enc), expectedPkE);
  assert.equal(hexEncode(ciphertext), expectedCt0);

  const opened = await hpkeOpenBase(kpR.sk, enc, info, aad0, ciphertext, {
    aeadId: AEAD_AES_128_GCM,
  });
  assert.deepEqual(opened, pt);
});

// ----------------------------------------------------------------------------
// 6. Differential Native WebCrypto vs. Pure-JS Curve25519 Fallback Parity
// ----------------------------------------------------------------------------
await test("differential native WebCrypto vs pure-JS fallback (Ed25519 + X25519)", async () => {
  for (let i = 0; i < 4; i++) {
    const edSeed = randomBytes(32);
    const msg = utf8Bytes(`differential-test-${i}`);
    const kp = await ed25519KeypairFromSeed(edSeed);

    const sigNative = await ed25519Sign(edSeed, msg);
    const sigPure = await _ed25519SignPure(edSeed, msg);
    assert.deepEqual(sigPure, sigNative, "Ed25519 signatures must be deterministic and bit-exact");
    assert.equal(await ed25519Verify(kp.publicKeyBytes, msg, sigPure), true);
    assert.equal(await _ed25519VerifyPure(kp.publicKeyBytes, msg, sigNative), true);

    const badSig = new Uint8Array(sigNative);
    badSig[63] ^= 0x01;
    assert.equal(await ed25519Verify(kp.publicKeyBytes, msg, badSig), false);
    assert.equal(await _ed25519VerifyPure(kp.publicKeyBytes, msg, badSig), false);

    const xPrivA = randomBytes(32);
    const xPrivB = randomBytes(32);
    const xPubANative = await x25519PublicFromPrivate(xPrivA);
    const xPubAPure = _x25519PublicFromPrivatePure(xPrivA);
    assert.deepEqual(xPubAPure, xPubANative, "X25519 public derivation parity");

    const xPubB = await x25519PublicFromPrivate(xPrivB);
    const dhNative = await x25519DeriveSharedSecret(xPrivA, xPubB);
    const dhPure = _x25519DhPure(xPrivA, xPubB);
    assert.deepEqual(dhPure, dhNative, "X25519 DH shared secret parity");
  }

  // Low-order X25519 point rejected by both native and pure paths
  const priv = randomBytes(32);
  await assert.rejects(() => x25519DeriveSharedSecret(priv, new Uint8Array(32)));
  assert.throws(() => _x25519DhPure(priv, new Uint8Array(32)));
});

// ----------------------------------------------------------------------------
// 7. WebAuthn PRF -> HKDF-SHA256 -> Ed25519 Seed Derivation
// ----------------------------------------------------------------------------
await test("prfEvalInput & derivePrfEd25519Seed determinism and domain separation", async () => {
  const input1 = await prfEvalInput("bogdan", "salt-alpha-123456");
  const input2 = await prfEvalInput("bogdan", "salt-alpha-123456");
  const inputOtherSalt = await prfEvalInput("bogdan", "salt-beta-123456");
  const inputOtherHuman = await prfEvalInput("alice", "salt-alpha-123456");
  assert.equal(input1.length, 32);
  assert.deepEqual(input1, input2);
  assert.notDeepEqual(input1, inputOtherSalt);
  assert.notDeepEqual(input1, inputOtherHuman);

  const prfOut = hexDecode("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
  const seedE1 = await derivePrfEd25519Seed(prfOut, "bogdan", 1);
  const seedE1Again = await derivePrfEd25519Seed(prfOut, "bogdan", 1);
  const seedE2 = await derivePrfEd25519Seed(prfOut, "bogdan", 2);
  const seedOtherHuman = await derivePrfEd25519Seed(prfOut, "alice", 1);
  const seedHighEpoch = await derivePrfEd25519Seed(prfOut, "bogdan", 0x100000007n);

  assert.equal(seedE1.length, 32);
  assert.deepEqual(seedE1, seedE1Again);
  assert.notDeepEqual(seedE1, seedE2);
  assert.notDeepEqual(seedE1, seedOtherHuman);
  assert.notDeepEqual(seedE1, seedHighEpoch);

  const mutatedPrf = new Uint8Array(prfOut);
  mutatedPrf[31] ^= 0x01;
  const seedMutated = await derivePrfEd25519Seed(mutatedPrf, "bogdan", 1);
  assert.notDeepEqual(seedE1, seedMutated);
});

// ----------------------------------------------------------------------------
// 8. NodeCertV1 (`hcert1_`) Verify + Tamper Rejection
// ----------------------------------------------------------------------------
await test("NodeCertV1 hcert1_ verification & fail-closed tamper/phishing rejection", async () => {
  const humanSeed = randomBytes(32);
  const wrongHumanSeed = randomBytes(32);
  const humanKp = await ed25519KeypairFromSeed(humanSeed);
  const wrongHumanKp = await ed25519KeypairFromSeed(wrongHumanSeed);

  const nodeEncPriv = randomBytes(32);
  const nodeEncPub = await x25519PublicFromPrivate(nodeEncPriv);
  const nodeEncJwk = { kty: "OKP", crv: "X25519", x: base64urlEncode(nodeEncPub) };

  const attackerEncPub = await x25519PublicFromPrivate(randomBytes(32));
  const attackerEncJwk = { kty: "OKP", crv: "X25519", x: base64urlEncode(attackerEncPub) };

  const nodeSignKp = await ed25519KeypairFromSeed(randomBytes(32));
  const nowMs = Date.parse("2026-11-24T21:05:00Z");

  const { signed, hcert1 } = await signNodeCert(
    {
      humanId: "bogdan",
      authEpoch: 1,
      nodeId: "prod@eu-1",
      encryptionJwk: nodeEncJwk,
      signingJwk: nodeSignKp.publicJwk,
      issuedAt: "2026-11-24T21:00:00Z",
      expiresAt: "2027-11-24T00:00:00Z",
    },
    humanSeed
  );

  // Valid armored hcert1_ and object both verify
  const ok1 = await verifyNodeCert(hcert1, humanKp.publicKeyBytes, "prod@eu-1", nodeEncJwk, nowMs);
  assert.equal(ok1.ok, true);
  assert.equal(ok1.cert.nodeId, "prod@eu-1");

  const ok2 = await verifyNodeCert(signed, humanKp.publicJwk, "prod@eu-1", nodeEncJwk, nowMs);
  assert.equal(ok2.ok, true);

  // Phishing: substituted target X25519 key fails closed
  const badKey = await verifyNodeCert(hcert1, humanKp.publicKeyBytes, "prod@eu-1", attackerEncJwk, nowMs);
  assert.equal(badKey.ok, false);
  assert.equal(badKey.reason, "encryption_key_mismatch");

  // Wrong nodeId fails closed
  const badNode = await verifyNodeCert(hcert1, humanKp.publicKeyBytes, "staging@eu-1", nodeEncJwk, nowMs);
  assert.equal(badNode.ok, false);
  assert.equal(badNode.reason, "node_id_mismatch");

  // Wrong human authority key fails closed
  const badAuth = await verifyNodeCert(hcert1, wrongHumanKp.publicKeyBytes, "prod@eu-1", nodeEncJwk, nowMs);
  assert.equal(badAuth.ok, false);
  assert.equal(badAuth.reason, "invalid_signature");

  // 1-bit flip in signature fails closed
  const sigBytes = base64urlDecode(signed.sig);
  sigBytes[10] ^= 0x01;
  const badSig = await verifyNodeCert(
    { payload: signed.payload, sig: base64urlEncode(sigBytes) },
    humanKp.publicKeyBytes,
    "prod@eu-1",
    nodeEncJwk,
    nowMs
  );
  assert.equal(badSig.ok, false);
  assert.equal(badSig.reason, "invalid_signature");

  // Expired certificate fails closed
  const expired = await verifyNodeCert(
    hcert1,
    humanKp.publicKeyBytes,
    "prod@eu-1",
    nodeEncJwk,
    Date.parse("2028-01-01T00:00:00Z")
  );
  assert.equal(expired.ok, false);
  assert.equal(expired.reason, "cert_expired");

  // Not yet valid (beyond 60s skew) fails closed
  const future = await verifyNodeCert(
    hcert1,
    humanKp.publicKeyBytes,
    "prod@eu-1",
    nodeEncJwk,
    Date.parse("2026-11-24T20:55:00Z")
  );
  assert.equal(future.ok, false);
  assert.equal(future.reason, "cert_not_yet_valid");

  // Missing cert fails closed
  const missing = await verifyNodeCert(null, humanKp.publicKeyBytes, "prod@eu-1", nodeEncJwk, nowMs);
  assert.equal(missing.ok, false);
  assert.equal(missing.reason, "missing_cert");
});

// ----------------------------------------------------------------------------
// 9. Full `sealHumanDrop` -> `openHumanDrop` & `hdrop1_` Roundtrip + Mutations
// ----------------------------------------------------------------------------
await test("sealHumanDrop -> openHumanDrop (directive & secret) + hdrop1_ + bit-flip fail-closed", async () => {
  const humanSeed = randomBytes(32);
  const wrongHumanSeed = randomBytes(32);
  const humanKp = await ed25519KeypairFromSeed(humanSeed);
  const wrongHumanKp = await ed25519KeypairFromSeed(wrongHumanSeed);

  const targetPriv = randomBytes(32);
  const wrongTargetPriv = randomBytes(32);
  const targetPub = await x25519PublicFromPrivate(targetPriv);
  const targetEncJwk = { kty: "OKP", crv: "X25519", x: base64urlEncode(targetPub) };

  // A) Directive drop
  const dirDropId = base64urlEncode(randomBytes(16));
  const dirSealed = await sealHumanDrop({
    claim: {
      v: 1,
      kind: "directive",
      humanId: "bogdan",
      authEpoch: 1,
      issuedAt: "2026-11-24T21:00:00Z",
      expiresAt: "2026-11-24T21:10:00Z",
      dropId: dirDropId,
      audience: { nodeId: "prod@eu-1", handle: "ops" },
      body: "Roll back checkout-api on prod@eu-1 to v2.4.0",
    },
    humanSeed32: humanSeed,
    recipientEncJwk: targetEncJwk,
  });

  // Outer envelope MUST be strictly opaque (zero identity/kind/body/secretName leakage!)
  assert.deepEqual(Object.keys(dirSealed.envelope).sort(), ["ct", "dropId", "enc", "suite", "v"]);
  assert.equal(dirSealed.envelope.v, 1);
  assert.equal(dirSealed.envelope.suite, HUMAN_DROP_SUITE);
  assert.equal(dirSealed.envelope.dropId, dirDropId);
  assert.ok(dirSealed.hdrop1.startsWith("hdrop1_"));
  assert.deepEqual(decodeHdrop1(dirSealed.hdrop1), dirSealed.envelope);
  assert.equal(encodeHdrop1(dirSealed.envelope), dirSealed.hdrop1);

  const dirOpened = await openHumanDrop({
    envelopeOrToken: dirSealed.hdrop1,
    recipientPriv32: targetPriv,
    expectedHumanPub32: humanKp.publicKeyBytes,
  });
  assert.equal(dirOpened.claim.kind, "directive");
  assert.equal(dirOpened.claim.body, "Roll back checkout-api on prod@eu-1 to v2.4.0");
  assert.equal(dirOpened.claim.audience.nodeId, "prod@eu-1");
  assert.equal(dirOpened.claim.audience.handle, "ops");
  assert.equal(dirOpened.claim.secretSpec, undefined);

  // B) Secret drop
  const secSealed = await sealHumanDrop({
    claim: {
      v: 1,
      kind: "secret",
      humanId: "bogdan",
      authEpoch: 2,
      issuedAt: "2026-11-24T21:00:00Z",
      expiresAt: "2026-11-24T21:05:00Z",
      dropId: "", // offline mode
      audience: { nodeId: "prod@eu-1", handle: "ops" },
      secretSpec: { name: "stripe-prod-key", overwrite: false },
      body: "hyphae_zk_test_value_999",
    },
    humanSeed32: humanSeed,
    recipientEncJwk: targetEncJwk,
  });

  // Verify zero secret leakage in armored token string
  assert.ok(!secSealed.hdrop1.includes("stripe-prod-key"));
  assert.ok(!secSealed.hdrop1.includes("hyphae_zk_"));

  const secOpened = await openHumanDrop({
    envelopeOrToken: secSealed.envelope,
    recipientPriv32: targetPriv,
    expectedHumanPub32: humanKp.publicJwk,
  });
  assert.equal(secOpened.claim.kind, "secret");
  assert.equal(secOpened.claim.secretSpec.name, "stripe-prod-key");
  assert.equal(secOpened.claim.secretSpec.overwrite, false);
  assert.equal(secOpened.claim.body, "hyphae_zk_test_value_999");

  // Mutated envelopes MUST fail closed
  const badEnc = base64urlDecode(dirSealed.envelope.enc);
  badEnc[5] ^= 0x01;
  await assert.rejects(() =>
    openHumanDrop({
      envelopeOrToken: { ...dirSealed.envelope, enc: base64urlEncode(badEnc) },
      recipientPriv32: targetPriv,
      expectedHumanPub32: humanKp.publicKeyBytes,
    })
  );

  const badCt = base64urlDecode(dirSealed.envelope.ct);
  badCt[badCt.length - 1] ^= 0x01;
  await assert.rejects(() =>
    openHumanDrop({
      envelopeOrToken: { ...dirSealed.envelope, ct: base64urlEncode(badCt) },
      recipientPriv32: targetPriv,
      expectedHumanPub32: humanKp.publicKeyBytes,
    })
  );

  // Outer dropId tamper fails HPKE info/AAD authentication
  await assert.rejects(() =>
    openHumanDrop({
      envelopeOrToken: { ...dirSealed.envelope, dropId: "tampered-drop-id" },
      recipientPriv32: targetPriv,
      expectedHumanPub32: humanKp.publicKeyBytes,
    })
  );

  // Wrong recipient private key fails
  await assert.rejects(() =>
    openHumanDrop({
      envelopeOrToken: dirSealed.envelope,
      recipientPriv32: wrongTargetPriv,
      expectedHumanPub32: humanKp.publicKeyBytes,
    })
  );

  // Wrong human authority public key fails inner Ed25519 signature check
  await assert.rejects(() =>
    openHumanDrop({
      envelopeOrToken: dirSealed.envelope,
      recipientPriv32: targetPriv,
      expectedHumanPub32: wrongHumanKp.publicKeyBytes,
    })
  );

  assert.throws(() => decodeHdrop1("hdrop2_abc"), /Invalid hdrop1_ prefix/);
});

// ----------------------------------------------------------------------------
// 10. Reserved Secret Name Guard, SAS Fingerprint & Fragment Parser Security
// ----------------------------------------------------------------------------
await test("reserved secret-name denylist, SAS fingerprint & fragment parser security", async () => {
  for (const okName of ["stripe-prod-key", "openai.api_key", "db_pass-1", "a"]) {
    assert.equal(validateSecretName(okName).ok, true, `valid secret name ${okName}`);
    assert.equal(isReservedSecretName(okName), false, `non-reserved secret name ${okName}`);
  }

  for (const badName of ["", "../etc", "UPPERCASE", "-leading", "a..b", "a".repeat(65)]) {
    assert.equal(validateSecretName(badName).ok, false, `invalid secret name ${badName}`);
  }

  const reservedNames = [
    "node-sign-deadbeef1234",
    "node-enc-deadbeef1234",
    "id-sign-0123456789ab",
    "id-enc-0123456789ab",
    "admin-ca-primary",
    "gate-policy-hmac-key",
    "human-admin-abcdef012345",
    "human-authority-root",
    "auth-token-main",
  ];
  const humanSeed = randomBytes(32);
  const encPub = await x25519PublicFromPrivate(randomBytes(32));
  const encJwk = { kty: "OKP", crv: "X25519", x: base64urlEncode(encPub) };

  for (const name of reservedNames) {
    assert.equal(isReservedSecretName(name), true, `reserved ${name}`);
    await assert.rejects(
      () =>
        sealHumanDrop({
          claim: {
            v: 1,
            kind: "secret",
            humanId: "bogdan",
            authEpoch: 1,
            issuedAt: "2026-11-24T21:00:00Z",
            expiresAt: "2026-11-24T21:05:00Z",
            dropId: "",
            audience: { nodeId: "prod@eu-1" },
            secretSpec: { name, overwrite: true },
            body: "should-be-blocked",
          },
          humanSeed32: humanSeed,
          recipientEncJwk: encJwk,
        }),
      /Reserved system secret name blocked/
    );
  }

  // SAS fingerprint structure, 256-word coverage & sensitivity
  const cryptoSrc = readFileSync(resolve(repoRoot, "site/drop/crypto.js"), "utf8");
  const wlMatch = cryptoSrc.match(/const SAS_WORDLIST = \[([\s\S]*?)\];/);
  assert.ok(wlMatch, "SAS_WORDLIST found");
  const wlWords = wlMatch[1].match(/"[^"]+"/g).map((w) => w.slice(1, -1));
  assert.equal(wlWords.length, 256, "SAS_WORDLIST must have exactly 256 entries");
  assert.equal(new Set(wlWords).size, 256, "SAS_WORDLIST entries must be unique");

  const sas1 = await sasFingerprint(encJwk);
  assert.match(sas1.hex, /^[0-9a-f]{16}$/);
  assert.match(sas1.formatted, /^[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}$/);
  assert.equal(sas1.words.length, 4);
  for (const w of sas1.words) assert.ok(typeof w === "string" && w.length > 0);
  const flipped = new Uint8Array(encPub);
  flipped[0] ^= 0x01;
  const sas2 = await sasFingerprint(flipped);
  assert.notEqual(sas1.hex, sas2.hex);

  // Fragment parser: strips proposedText/body, validates relay URL scheme
  assert.deepEqual(parseFragmentString(""), { mode: "landing" });
  const inviteWithSmuggledPrefill = {
    v: 1,
    dropId: "abc123",
    relay: "https://public.hyphae.to/",
    postCap: "hdcap1_test",
    nodeId: "prod@eu-1",
    handle: "ops",
    encJwk,
    kind: "directive",
    proposedText: "rm -rf / # smuggled prefill MUST be ignored!",
    body: "smuggled body MUST be ignored!",
    expiresAt: "2026-11-24T21:10:00Z",
  };
  const fragHash = "#" + base64urlEncode(utf8Bytes(toCanonicalJson(inviteWithSmuggledPrefill)));
  const parsed = parseFragmentString(fragHash);
  assert.equal(parsed.mode, "drop");
  assert.equal(parsed.fragment.relay, "https://public.hyphae.to");
  assert.equal("proposedText" in parsed.fragment, false);
  assert.equal("body" in parsed.fragment, false);

  // Reject insecure remote http:// relay and non-loopback enroll callback
  assert.equal(isAllowedRelayUrl("https://public.hyphae.to"), true);
  assert.equal(isAllowedRelayUrl("http://127.0.0.1:8787"), true);
  assert.equal(isAllowedRelayUrl("http://evil.example.com"), false);
  assert.equal(isAllowedRelayUrl("javascript:alert(1)"), false);
  assert.equal(isLoopbackCallbackUrl("http://127.0.0.1:41234/enroll"), true);
  assert.equal(isLoopbackCallbackUrl("https://evil.example.com/steal"), false);
});

console.log(`\nAll ${passed} test groups passed!`);
