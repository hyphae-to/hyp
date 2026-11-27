/**
 * Unit & adversarial tests for the static `https://hyphae.to/join` portal (`site/join/join.js`)
 * and delegated human admission crypto primitives in `site/drop/crypto.js`.
 *
 * Run via:
 *   node --test site/join/join.test.mjs
 */

import assert from "node:assert/strict";
import { describe, test } from "node:test";

import {
  HUMAN_INVITE_DOMAIN,
  base64urlDecode,
  base64urlEncode,
  decodeHjoin1,
  decodeHpub1,
  derivePrfX25519Keypair,
  ed25519KeypairFromSeed,
  ed25519Sign,
  encodeHjoin1,
  encodeHpub1,
  isAllowedHubEndpoint,
  isForbiddenDelegatedScope,
  isValidNodePrefix,
  matchesNodePrefix,
  randomBytes,
  signHumanInviteClaim,
  toCanonicalJson,
  utf8Bytes,
  validateDelegatedScopes,
  verifyHumanInvite,
} from "../drop/crypto.js";

import {
  buildAgentPrompts,
  formatCountdown,
  formatSixDigitCodeInput,
  isEmbeddedInFrame,
  parseJoinFragment,
} from "./join.js";

async function signTestHjoin1(payloadObj, adminSeed32) {
  const adminKp = await ed25519KeypairFromSeed(adminSeed32);
  const payload = toCanonicalJson(payloadObj);
  const sigBytes = await ed25519Sign(adminSeed32, utf8Bytes(HUMAN_INVITE_DOMAIN + payload));
  const signed = {
    payload,
    sig: base64urlEncode(sigBytes),
    adminJwk: adminKp.publicJwk,
  };
  return { token: encodeHjoin1(signed), signed, adminKp };
}

describe("site/join portal helpers & delegated admission crypto", () => {
  test("parseJoinFragment handles landing, #hjoin1_, #invite=, #certify=, and rejects garbage", () => {
    assert.deepEqual(parseJoinFragment(""), { mode: "landing" });
    assert.deepEqual(parseJoinFragment("#"), { mode: "landing" });
    assert.deepEqual(parseJoinFragment("#hjoin1_abc123"), {
      mode: "invite",
      hjoin1: "hjoin1_abc123",
    });
    assert.deepEqual(parseJoinFragment("https://hyphae.to/join#hjoin1_xyz"), {
      mode: "invite",
      hjoin1: "hjoin1_xyz",
    });
    assert.deepEqual(parseJoinFragment("#invite=hjoin1_foo"), {
      mode: "invite",
      hjoin1: "hjoin1_foo",
    });

    const certObj = {
      hubNodeId: "acme-team",
      hubEndpoint: "https://hub.acme.example",
      humanId: "philip",
      nodePrefix: "philip@*",
    };
    const certFrag = `#certify=${base64urlEncode(utf8Bytes(JSON.stringify(certObj)))}`;
    assert.deepEqual(parseJoinFragment(certFrag), { mode: "certify", certify: certObj });

    // Reject javascript: or non-loopback http:// endpoints in #certify=
    const badCert = base64urlEncode(
      utf8Bytes(JSON.stringify({ ...certObj, hubEndpoint: "javascript:alert(1)" })),
    );
    assert.throws(() => parseJoinFragment(`#certify=${badCert}`));
    assert.throws(() => parseJoinFragment("#am2_wrong_prefix"));
    assert.throws(() => parseJoinFragment("#invite=not_hjoin"));
  });

  test("buildAgentPrompts, formatSixDigitCodeInput, formatCountdown, and frame-busting", () => {
    const prompts = buildAgentPrompts("acme-team");
    assert.match(prompts.existing, /hyp join/);
    assert.match(prompts.existing, /acme-team/);
    assert.match(prompts.fresh, /https:\/\/hyphae\.to\/install\.sh/);
    assert.match(prompts.remoteFinish, /hyp join --stdin/);

    assert.equal(formatSixDigitCodeInput("482917"), "482-917");
    assert.equal(formatSixDigitCodeInput("48a2-91x7999"), "482-917");
    assert.equal(formatSixDigitCodeInput("48"), "48");

    assert.equal(formatCountdown(0), "EXPIRED");
    assert.equal(formatCountdown(-500), "EXPIRED");
    assert.equal(formatCountdown(90_000), "1m 30s");

    const topWin = {};
    topWin.top = topWin;
    topWin.self = topWin;
    assert.equal(isEmbeddedInFrame(topWin), false);
    assert.equal(isEmbeddedInFrame({ top: topWin, self: {} }), true);
    assert.equal(
      isEmbeddedInFrame({
        self: {},
        get top() {
          throw new Error("SecurityError");
        },
      }),
      true,
    );
  });

  test("nodePrefix, scope, and endpoint fail-closed validators", () => {
    assert.equal(isValidNodePrefix("philip@*"), true);
    assert.equal(isValidNodePrefix("philip@macbook"), true);
    assert.equal(isValidNodePrefix("philip@dev-*"), true);
    assert.equal(isValidNodePrefix("*"), false);
    assert.equal(isValidNodePrefix("**"), false);
    assert.equal(isValidNodePrefix("phi*lip@mac"), false);
    assert.equal(isValidNodePrefix("philip@../bad"), false);
    assert.equal(isValidNodePrefix("local"), false);

    assert.equal(matchesNodePrefix("philip@*", "philip@macbook"), true);
    assert.equal(matchesNodePrefix("philip@*", "alice@macbook"), false);
    assert.equal(matchesNodePrefix("philip@dev-*", "philip@dev-01"), true);
    assert.equal(matchesNodePrefix("philip@dev-*", "philip@prod-01"), false);
    assert.equal(matchesNodePrefix("*", "philip@macbook"), false);

    assert.equal(isForbiddenDelegatedScope("*"), true);
    assert.equal(isForbiddenDelegatedScope("bridge:post=slack:ops"), true);
    assert.equal(isForbiddenDelegatedScope("forward:via=hub"), true);
    assert.equal(isForbiddenDelegatedScope("dm:send"), false);
    assert.equal(validateDelegatedScopes(["dm:send", "*"]).ok, false);
    assert.equal(validateDelegatedScopes(["bridge:post=slack:ops"]).ok, false);
    assert.equal(validateDelegatedScopes(["forward:via=hub"]).ok, false);
    assert.equal(validateDelegatedScopes([]).ok, false);
    assert.equal(validateDelegatedScopes(["dm:send", "kv:read=shared/*"]).ok, true);

    assert.equal(isAllowedHubEndpoint("https://hub.acme.example"), true);
    assert.equal(isAllowedHubEndpoint("http://127.0.0.1:47899"), true);
    assert.equal(isAllowedHubEndpoint("http://localhost:8080"), true);
    assert.equal(isAllowedHubEndpoint("http://hub.acme.example"), false);
    assert.equal(isAllowedHubEndpoint("javascript:alert(1)"), false);
  });

  test("verifyHumanInvite accepts valid hjoin1_ and rejects mutated signatures, expired, and forbidden scopes", async () => {
    const adminSeed = randomBytes(32);
    const otherSeed = randomBytes(32);
    const otherKp = await ed25519KeypairFromSeed(otherSeed);
    const nowMs = Date.now();

    const basePayload = {
      v: 1,
      inviteId: "550e8400-e29b-41d4-a716-446655440000",
      hubNodeId: "acme-team",
      hubEndpoint: "https://hub.acme.example",
      hubFingerprint: "0123456789abcdef",
      humanId: "philip",
      nodePrefix: "philip@*",
      scopes: ["dm:send", "dm:receive", "kv:read=shared/*", "kv:write=shared/*"],
      maxDevices: 10,
      issuedAt: new Date(nowMs).toISOString(),
      expiresAt: new Date(nowMs + 3600_000).toISOString(),
    };

    const { token, signed, adminKp } = await signTestHjoin1(basePayload, adminSeed);
    const verified = await verifyHumanInvite(token, adminKp.publicJwk, nowMs + 1000);
    assert.equal(verified.ok, true);
    assert.equal(verified.invite.humanId, "philip");
    assert.equal(verified.invite.hubNodeId, "acme-team");
    assert.equal(verified.adminJwk.x, adminKp.publicJwk.x);

    // Wrong pinned admin key fails closed
    const wrongAdmin = await verifyHumanInvite(token, otherKp.publicJwk, nowMs + 1000);
    assert.equal(wrongAdmin.ok, false);
    assert.equal(wrongAdmin.reason, "admin_key_mismatch");

    // 1-bit signature tamper fails closed
    const badSigBytes = base64urlDecode(signed.sig);
    badSigBytes[0] ^= 0x01;
    const tampered = encodeHjoin1({ ...signed, sig: base64urlEncode(badSigBytes) });
    const tamperedRes = await verifyHumanInvite(tampered, null, nowMs + 1000);
    assert.equal(tamperedRes.ok, false);
    assert.equal(tamperedRes.reason, "invalid_signature");

    // Expired invite fails closed
    const expiredRes = await verifyHumanInvite(token, null, nowMs + 3600_000 + 120_000);
    assert.equal(expiredRes.ok, false);

    // Forbidden scope signed by admin STILL fails closed!
    const badScope = await signTestHjoin1(
      { ...basePayload, scopes: ["dm:send", "bridge:post=slack:ops"] },
      adminSeed,
    );
    const badScopeRes = await verifyHumanInvite(badScope.token, null, nowMs + 1000);
    assert.equal(badScopeRes.ok, false);

    // Bare `*` nodePrefix fails closed!
    const badPrefix = await signTestHjoin1({ ...basePayload, nodePrefix: "*" }, adminSeed);
    const badPrefixRes = await verifyHumanInvite(badPrefix.token, null, nowMs + 1000);
    assert.equal(badPrefixRes.ok, false);

    // `hpub1_` roundtrip + `signHumanInviteClaim` sanity check
    const humanSeed = randomBytes(32);
    const humanEd = await ed25519KeypairFromSeed(humanSeed);
    const humanX = await derivePrfX25519Keypair(randomBytes(32), "philip", 1);
    const hpub1 = encodeHpub1({
      v: 1,
      humanId: "philip",
      signingJwk: humanEd.publicJwk,
      encJwk: humanX.publicJwk,
    });
    const decodedCard = decodeHpub1(hpub1);
    assert.equal(decodedCard.humanId, "philip");
    assert.equal(decodedCard.signingJwk.x, humanEd.publicJwk.x);
    assert.equal(decodedCard.encJwk.x, humanX.publicJwk.x);

    const claimRes = await signHumanInviteClaim(
      {
        inviteId: basePayload.inviteId,
        hubNodeId: basePayload.hubNodeId,
        humanId: "philip",
        signingJwk: humanEd.publicJwk,
        encJwk: humanX.publicJwk,
        prfSalt: "salt-123",
        timestamp: new Date(nowMs).toISOString(),
      },
      humanSeed,
    );
    assert.equal(typeof claimRes.sig, "string");
    assert.ok(claimRes.sig.length > 40);
    assert.equal(decodeHjoin1(token).adminJwk.x, adminKp.publicJwk.x);
  });
});

test("shared Passkey flow preserves relying-party labels, PRF fallback, and byte formats", async (t) => {
  const { createPasskeyOperations } = await import("../passkey.js");
  const oldWindow = Object.getOwnPropertyDescriptor(globalThis, "window");
  const oldNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  t.after(() => {
    if (oldWindow) Object.defineProperty(globalThis, "window", oldWindow);
    else delete globalThis.window;
    if (oldNavigator) Object.defineProperty(globalThis, "navigator", oldNavigator);
  });
  const attempts = [];
  const prf = new Uint8Array(32).fill(27);
  const rawId = Uint8Array.of(1, 2, 3);
  let serialized = false;
  const passkey = (first) => ({
    rawId,
    getClientExtensionResults: () => ({ prf: { enabled: true, results: { first } } }),
  });
  Object.defineProperty(globalThis, "window", {
    configurable: true,
    value: { PublicKeyCredential: true, location: { hostname: "hyphae.to" } },
  });
  Object.defineProperty(globalThis, "navigator", {
    configurable: true,
    value: {
      credentials: {
        async create({ publicKey }) {
          attempts.push(publicKey);
          return passkey(undefined);
        },
        async get({ publicKey }) {
          attempts.push(publicKey);
          return passkey(serialized ? Object.fromEntries(prf.entries()) : prf);
        },
      },
    },
  });
  const join = createPasskeyOperations({ rpName: "Hyphae Authority", missingPrfMessage: "Join PRF missing" });
  const drop = createPasskeyOperations({
    rpName: "Hyphae Verified Drops",
    missingPrfMessage: "Drop PRF missing",
    allowSerializedBytes: true,
  });
  const salt = base64urlEncode(new Uint8Array(16));
  const joined = await join.enrollPasskeyWithPrf("alice", salt);
  assert.deepEqual(joined.prfOut, prf);
  assert.equal(joined.credentialId, base64urlEncode(rawId));
  assert.deepEqual(attempts[0].rp, { name: "Hyphae Authority", id: "hyphae.to" });
  assert.deepEqual(attempts[1].allowCredentials[0].id, rawId);
  assert.deepEqual(attempts[0].extensions, attempts[1].extensions);
  assert.equal(attempts[1].userVerification, "required");

  serialized = true;
  await assert.rejects(join.evaluatePasskeyPrf("alice", salt), /Join PRF missing/);
  const enrolled = await drop.enrollPasskeyWithPrf("alice", salt);
  assert.deepEqual(enrolled.prfOut, prf);
  assert.equal(enrolled.rpId, "hyphae.to");
  assert.deepEqual(attempts[3].rp, { name: "Hyphae Verified Drops", id: "hyphae.to" });
});
