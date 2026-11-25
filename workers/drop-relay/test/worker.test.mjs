/**
 * Comprehensive zero-dependency Node 24 test suite for `workers/drop-relay/src/index.mjs`.
 *
 * Uses an in-memory mock `DurableObjectNamespace` executing the REAL `DropSlotDO` class
 * so every HTTP/SSE route, capability token, Ed25519 signature, CORS/PNA policy, rate limit,
 * pre-body rejection, late-subscriber SSE catch-up, and RAM buffer zeroization is verified
 * end-to-end without external dependencies or network sockets.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import {
  DropSlotDO,
  DROP_CAP_PREFIX,
  DROP_CAP_DOMAIN,
  DROP_CAP_HEADER,
  PUBLIC_KEY_HEADER,
  DROP_CAP_ROLE_POST,
  DROP_CAP_ROLE_SUB,
  DROP_CAP_RAW_LEN,
  DROP_CAP_ENCODED_LEN,
  DROP_ID_LEN,
  HTTP_AUTH_DOMAIN_PREFIX,
  HTTP_AUTH_SKEW_MS,
  base64UrlEncode,
  base64UrlDecodeStrict,
  sha256Hex,
  buildHttpAuthSigningInput,
  createCapability,
  verifyCapability,
  verifyHyphaeEd25519Request,
  createWorkerApp,
} from "../src/index.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const INDEX_PATH = join(__dirname, "../src/index.mjs");

const TEST_HMAC_KEY = "hyphae-test-hmac-secret-key-0123456789abcdef";
const TEST_HMAC_KEY_PREV = "hyphae-prev-hmac-secret-key-fedcba9876543210";
const BASE_NOW_MS = 1_750_000_000_000;

// ============================================================================
// Test Helpers: Mock DurableObjectNamespace, Ed25519 Signer, SSE Reader
// ============================================================================

/**
 * In-memory mock `DurableObjectNamespace` executing the real `DropSlotDO` class.
 * Deliberately provides a `ctx` whose `storage` getter throws if ever accessed,
 * proving at runtime that `DropSlotDO` is 100% RAM-only.
 */
function createMockDurableObjectNamespace({ now, keepaliveMs = 25_000 } = {}) {
  /** @type {Map<string, DropSlotDO>} */
  const instances = new Map();
  let envRef = null;

  const forbiddenCtx = {
    get storage() {
      throw new Error("VIOLATION: DropSlotDO must NEVER access ctx.storage!");
    },
  };

  return {
    instances,
    bindEnv(env) {
      envRef = env;
    },
    idFromName(name) {
      return { name: String(name), toString: () => String(name) };
    },
    get(id) {
      const key = typeof id === "string" ? id : id.name;
      let instance = instances.get(key);
      if (!instance) {
        instance = new DropSlotDO(forbiddenCtx, envRef ?? {}, { now, keepaliveMs });
        instances.set(key, instance);
      }
      return {
        fetch: (input, init) => {
          const req = input instanceof Request ? input : new Request(input, init);
          return instance.fetch(req);
        },
      };
    },
  };
}

/**
 * Generates a fresh Ed25519 keypair via native WebCrypto and exports raw 32-byte pubkey.
 */
async function generateEd25519Identity(nodeId) {
  const keyPair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const rawPub = new Uint8Array(await crypto.subtle.exportKey("raw", keyPair.publicKey));
  const pubB64 = base64UrlEncode(rawPub);
  const jwk = { kty: "OKP", crv: "Ed25519", x: pubB64 };

  /**
   * Signs an HTTP request using the exact Hyphae v2 `Hyphae-Ed25519` wire protocol
   * (`crates/hyp-node/src/engine/peer_link.rs` + `crates/hyp-crypto/src/keys.rs`).
   */
  async function signHeaders({
    method,
    pathAndQuery,
    bodyBytes = new Uint8Array(0),
    ts = BASE_NOW_MS,
    nonce = base64UrlEncode(crypto.getRandomValues(new Uint8Array(12))),
    nodeOverride = nodeId,
    includePublicKeyHeader = false,
    publicKeyFormat = "raw",
    useNodeIdParam = false,
  }) {
    const bodySha = await sha256Hex(bodyBytes);
    const signingInput = buildHttpAuthSigningInput(
      method.toUpperCase(),
      pathAndQuery,
      ts,
      nonce,
      bodySha
    );
    const prefix = new TextEncoder().encode(HTTP_AUTH_DOMAIN_PREFIX);
    const domainMsg = new Uint8Array(prefix.byteLength + signingInput.byteLength);
    domainMsg.set(prefix, 0);
    domainMsg.set(signingInput, prefix.byteLength);
    const sigRaw = new Uint8Array(
      await crypto.subtle.sign({ name: "Ed25519" }, keyPair.privateKey, domainMsg)
    );
    const sigB64 = base64UrlEncode(sigRaw);
    const paramName = useNodeIdParam ? "nodeId" : "node";
    const headers = {
      Authorization: `Hyphae-Ed25519 ${paramName}="${nodeOverride}",ts="${ts}",nonce="${nonce}",sig="${sigB64}"`,
      "X-Hyphae-Node": nodeOverride,
    };
    if (includePublicKeyHeader) {
      headers[PUBLIC_KEY_HEADER] =
        publicKeyFormat === "jwk" ? JSON.stringify(jwk) : pubB64;
    }
    return headers;
  }

  return { nodeId, keyPair, rawPub, pubB64, jwk, signHeaders };
}

/**
 * Helper to create a test harness with deterministic clock and real `DropSlotDO`.
 */
function createTestHarness(envOverrides = {}, { initialNowMs = BASE_NOW_MS, keepaliveMs = 25_000 } = {}) {
  let nowMs = initialNowMs;
  const now = () => nowMs;
  const setNow = (nextMs) => {
    nowMs = nextMs;
  };
  const advanceMs = (deltaMs) => {
    nowMs += deltaMs;
  };

  const dropSlotNs = createMockDurableObjectNamespace({ now, keepaliveMs });
  const env = {
    DROP_AUTH_MODE: "private",
    DROP_CAP_HMAC_KEY: TEST_HMAC_KEY,
    ALLOWED_ORIGINS: "https://hyphae.to",
    ALLOW_PRIVATE_NETWORK: "true",
    MAX_PAYLOAD_BYTES: "65536",
    MAX_TTL_SECONDS: "900",
    DEFAULT_TTL_SECONDS: "600",
    MAX_ITEMS_PER_DROP: "16",
    MAX_SSE_STREAMS_PER_DROP: "2",
    DROP_SLOT: dropSlotNs,
    ...envOverrides,
  };
  dropSlotNs.bindEnv(env);
  const app = createWorkerApp({ now });

  return {
    app,
    env,
    dropSlotNs,
    now,
    setNow,
    advanceMs,
    fetch: (pathOrUrl, init) => {
      const url = pathOrUrl.startsWith("http")
        ? pathOrUrl
        : `https://drop.hyphae.test${pathOrUrl}`;
      return app.fetch(new Request(url, init), env, {});
    },
  };
}

/**
 * Incrementally reads SSE text chunks from a `Response` until `predicate(accumulated)` holds.
 */
async function readSseUntil(reader, state, predicate, timeoutMs = 2_000) {
  const decoder = new TextDecoder();
  const deadline = Date.now() + timeoutMs;
  while (!predicate(state.buf)) {
    const remaining = deadline - Date.now();
    if (remaining <= 0) {
      throw new Error(`Timed out waiting for SSE predicate. Accumulated:\n${state.buf}`);
    }
    let timer = null;
    const result = await Promise.race([
      reader.read(),
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error("SSE chunk read timeout")), remaining);
      }),
    ]).finally(() => {
      if (timer !== null) clearTimeout(timer);
    });
    if (result.done) {
      state.done = true;
      break;
    }
    state.buf += decoder.decode(result.value, { stream: true });
  }
  return state.buf;
}

// ============================================================================
// 1. Stateless `hdcap1_` Capabilities (Layout, Roles, Rotation, Tampering)
// ============================================================================

test("hdcap1_ exact length (62 chars), binary layout, Rust domain vector, roles, rotation, and 1-bit tamper rejection", async () => {
  const dropId = "abcdefghijklmnopqrstuv"; // 22 chars
  const expiresAtMs = BASE_NOW_MS + 600_000;

  const postCap = await createCapability({
    dropId,
    role: DROP_CAP_ROLE_POST,
    expiresAtMs,
    hmacKey: TEST_HMAC_KEY,
  });
  const subCap = await createCapability({
    dropId,
    role: DROP_CAP_ROLE_SUB,
    expiresAtMs,
    hmacKey: TEST_HMAC_KEY,
  });

  // Exact prefix & length: 7 ("hdcap1_") + 55 (base64url_nopad(41)) = 62 chars
  assert.equal(postCap.startsWith(DROP_CAP_PREFIX), true);
  assert.equal(subCap.startsWith(DROP_CAP_PREFIX), true);
  assert.equal(postCap.length, DROP_CAP_PREFIX.length + DROP_CAP_ENCODED_LEN);
  assert.equal(postCap.length, 62);
  assert.equal(subCap.length, 62);

  // Verify exact binary layout: role[1] || exp_ms_be[8] || mac[32]
  const rawPost = base64UrlDecodeStrict(postCap.slice(DROP_CAP_PREFIX.length));
  assert.ok(rawPost);
  assert.equal(rawPost.length, DROP_CAP_RAW_LEN);
  assert.equal(rawPost[0], DROP_CAP_ROLE_POST);
  const decodedExp = new DataView(rawPost.buffer, rawPost.byteOffset + 1, 8).getBigInt64(0, false);
  assert.equal(Number(decodedExp), expiresAtMs);

  // Differential check against independent WebCrypto HMAC over Rust's exact domain string:
  // "hyphae/v2/human-drop-cap\npost\n<drop_id>\n<exp_ms_be[8]>"
  const expBe = new Uint8Array(8);
  new DataView(expBe.buffer).setBigInt64(0, BigInt(expiresAtMs), false);
  const prefixBytes = new TextEncoder().encode(`${DROP_CAP_DOMAIN}post\n${dropId}\n`);
  const expectedInput = new Uint8Array(prefixBytes.length + 8);
  expectedInput.set(prefixBytes, 0);
  expectedInput.set(expBe, prefixBytes.length);
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(TEST_HMAC_KEY),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const expectedMac = new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, expectedInput));
  assert.deepEqual(rawPost.subarray(9, 41), expectedMac);

  // Valid verification
  const okPost = await verifyCapability({
    dropId,
    token: postCap,
    expectedRole: DROP_CAP_ROLE_POST,
    hmacKey: TEST_HMAC_KEY,
    nowMs: BASE_NOW_MS,
  });
  assert.deepEqual(okPost, { ok: true, expiresAtMs });

  const okSub = await verifyCapability({
    dropId,
    token: subCap,
    expectedRole: DROP_CAP_ROLE_SUB,
    hmacKey: TEST_HMAC_KEY,
    nowMs: BASE_NOW_MS,
  });
  assert.deepEqual(okSub, { ok: true, expiresAtMs });

  // Role separation: postCap rejected as Sub, subCap rejected as Post
  const wrongRole1 = await verifyCapability({
    dropId,
    token: postCap,
    expectedRole: DROP_CAP_ROLE_SUB,
    hmacKey: TEST_HMAC_KEY,
    nowMs: BASE_NOW_MS,
  });
  assert.equal(wrongRole1.ok, false);
  assert.equal(wrongRole1.problem.status, 401);

  const wrongRole2 = await verifyCapability({
    dropId,
    token: subCap,
    expectedRole: DROP_CAP_ROLE_POST,
    hmacKey: TEST_HMAC_KEY,
    nowMs: BASE_NOW_MS,
  });
  assert.equal(wrongRole2.ok, false);
  assert.equal(wrongRole2.problem.status, 401);

  // Cross-dropId rejection
  const wrongDrop = await verifyCapability({
    dropId: "zzzzzzzzzzzzzzzzzzzzzz",
    token: postCap,
    expectedRole: DROP_CAP_ROLE_POST,
    hmacKey: TEST_HMAC_KEY,
    nowMs: BASE_NOW_MS,
  });
  assert.equal(wrongDrop.ok, false);
  assert.equal(wrongDrop.problem.status, 401);

  // Expiry boundary (nowMs === expiresAtMs -> 410 Gone)
  const expiredRes = await verifyCapability({
    dropId,
    token: postCap,
    expectedRole: DROP_CAP_ROLE_POST,
    hmacKey: TEST_HMAC_KEY,
    nowMs: expiresAtMs,
  });
  assert.equal(expiredRes.ok, false);
  assert.equal(expiredRes.problem.status, 410);
  assert.equal(expiredRes.problem.error, "drop_expired");

  // Key rotation via DROP_CAP_HMAC_KEY_PREV
  const prevCap = await createCapability({
    dropId,
    role: DROP_CAP_ROLE_POST,
    expiresAtMs,
    hmacKey: TEST_HMAC_KEY_PREV,
  });
  const withoutPrev = await verifyCapability({
    dropId,
    token: prevCap,
    expectedRole: DROP_CAP_ROLE_POST,
    hmacKey: TEST_HMAC_KEY,
    nowMs: BASE_NOW_MS,
  });
  assert.equal(withoutPrev.ok, false);
  assert.equal(withoutPrev.problem.status, 401);

  const withPrev = await verifyCapability({
    dropId,
    token: prevCap,
    expectedRole: DROP_CAP_ROLE_POST,
    hmacKey: TEST_HMAC_KEY,
    prevHmacKey: TEST_HMAC_KEY_PREV,
    nowMs: BASE_NOW_MS,
  });
  assert.deepEqual(withPrev, { ok: true, expiresAtMs });

  // 1-bit tamper rejection across every byte of the 41-byte binary token (role, exp, and MAC)
  for (let byteIdx = 0; byteIdx < DROP_CAP_RAW_LEN; byteIdx += 1) {
    const mutated = new Uint8Array(rawPost);
    mutated[byteIdx] ^= 0x01;
    const tamperedToken = `${DROP_CAP_PREFIX}${base64UrlEncode(mutated)}`;
    const tamperedRes = await verifyCapability({
      dropId,
      token: tamperedToken,
      expectedRole: DROP_CAP_ROLE_POST,
      hmacKey: TEST_HMAC_KEY,
      nowMs: BASE_NOW_MS,
    });
    assert.equal(
      tamperedRes.ok,
      false,
      `1-bit flip at byte ${byteIdx} must be rejected`
    );
    assert.equal(tamperedRes.problem.status, 401);
  }
});

// ============================================================================
// 2. Private Mode (Allowlist, 403 Non-Allowlisted, 401 Bad Sig / Skew / Replay)
// ============================================================================

test("private mode: allowlisted Ed25519 node succeeds (201), unlisted node fails closed (403), bad sig fails closed (401)", async () => {
  const alice = await generateEd25519Identity("alice@macbook");
  const bob = await generateEd25519Identity("bob@laptop");
  const mallory = await generateEd25519Identity("mallory@rogue");

  const harness = createTestHarness({
    DROP_AUTH_MODE: "private",
    ALLOWED_NODE_KEYS: JSON.stringify({
      "alice@macbook": alice.pubB64,
      "bob@laptop": bob.jwk, // OKP JWK value also accepted in JSON map
    }),
  });

  // Allowlisted Alice creates a drop -> 201
  const reqBody = new TextEncoder().encode(JSON.stringify({ ttlSeconds: 300, maxItems: 4 }));
  const aliceHeaders = await alice.signHeaders({
    method: "POST",
    pathAndQuery: "/v1/drops",
    bodyBytes: reqBody,
  });
  const resp1 = await harness.fetch("/v1/drops", {
    method: "POST",
    headers: { "Content-Type": "application/json", ...aliceHeaders },
    body: reqBody,
  });
  assert.equal(resp1.status, 201);
  const created = await resp1.json();
  assert.equal(created.dropId.length, DROP_ID_LEN);
  assert.equal(created.postCap.length, 62);
  assert.equal(created.subCap.length, 62);
  assert.equal(created.maxPayloadBytes, 65536);
  assert.equal(created.maxItems, 4);
  assert.equal(created.expiresAtMs, BASE_NOW_MS + 300_000);

  // Replay of the exact same nonce fails closed with 401
  const replayResp = await harness.fetch("/v1/drops", {
    method: "POST",
    headers: { "Content-Type": "application/json", ...aliceHeaders },
    body: reqBody,
  });
  assert.equal(replayResp.status, 401);
  const replayProblem = await replayResp.json();
  assert.equal(replayProblem.error, "drop_unauthorized");

  // Allowlisted Bob (via JWK entry in ALLOWED_NODE_KEYS) succeeds -> 201
  const bobHeaders = await bob.signHeaders({
    method: "POST",
    pathAndQuery: "/v1/drops",
    bodyBytes: new Uint8Array(0),
  });
  const bobResp = await harness.fetch("/v1/drops", {
    method: "POST",
    headers: bobHeaders,
  });
  assert.equal(bobResp.status, 201);

  // Non-allowlisted valid Ed25519 node (Mallory) fails closed -> 403 Forbidden
  const malloryHeaders = await mallory.signHeaders({
    method: "POST",
    pathAndQuery: "/v1/drops",
    bodyBytes: reqBody,
  });
  const malloryResp = await harness.fetch("/v1/drops", {
    method: "POST",
    headers: { "Content-Type": "application/json", ...malloryHeaders },
    body: reqBody,
  });
  assert.equal(malloryResp.status, 403);
  const malloryProblem = await malloryResp.json();
  assert.equal(malloryProblem.error, "drop_forbidden");

  // Bad signature claiming Alice's nodeId (signed with Mallory's private key) -> 401 Unauthorized
  const forgedHeaders = await mallory.signHeaders({
    method: "POST",
    pathAndQuery: "/v1/drops",
    bodyBytes: reqBody,
    nodeOverride: "alice@macbook",
  });
  const forgedResp = await harness.fetch("/v1/drops", {
    method: "POST",
    headers: { "Content-Type": "application/json", ...forgedHeaders },
    body: reqBody,
  });
  assert.equal(forgedResp.status, 401);
  const forgedProblem = await forgedResp.json();
  assert.equal(forgedProblem.error, "drop_unauthorized");

  // Timestamp outside ±5 min skew window -> 401 Unauthorized
  const staleHeaders = await alice.signHeaders({
    method: "POST",
    pathAndQuery: "/v1/drops",
    bodyBytes: reqBody,
    ts: BASE_NOW_MS - HTTP_AUTH_SKEW_MS - 1,
  });
  const staleResp = await harness.fetch("/v1/drops", {
    method: "POST",
    headers: { "Content-Type": "application/json", ...staleHeaders },
    body: reqBody,
  });
  assert.equal(staleResp.status, 401);

  // Pair-list format `nodeId=b64url,nodeId2=b64url` also works
  const pairHarness = createTestHarness({
    DROP_AUTH_MODE: "private",
    ALLOWED_NODE_KEYS: `alice@macbook=${alice.pubB64},bob@laptop=${bob.pubB64}`,
  });
  const alicePairHeaders = await alice.signHeaders({
    method: "POST",
    pathAndQuery: "/v1/drops",
    bodyBytes: new Uint8Array(0),
    useNodeIdParam: true, // Verify nodeId= compatibility alongside canonical node=
  });
  const pairResp = await pairHarness.fetch("/v1/drops", {
    method: "POST",
    headers: alicePairHeaders,
  });
  assert.equal(pairResp.status, 201);

  // Default mode (unset DROP_AUTH_MODE) and unset ALLOWED_NODE_KEYS fails closed -> 403
  const defaultClosed = createTestHarness({
    DROP_AUTH_MODE: undefined,
    ALLOWED_NODE_KEYS: undefined,
  });
  const closedHeaders = await alice.signHeaders({
    method: "POST",
    pathAndQuery: "/v1/drops",
    bodyBytes: new Uint8Array(0),
  });
  const closedResp = await defaultClosed.fetch("/v1/drops", {
    method: "POST",
    headers: closedHeaders,
  });
  assert.equal(closedResp.status, 403);

  // Missing / short DROP_CAP_HMAC_KEY fails closed -> 500
  const noKeyHarness = createTestHarness({ DROP_CAP_HMAC_KEY: "too-short" });
  const noKeyResp = await noKeyHarness.fetch("/v1/drops", {
    method: "POST",
    headers: closedHeaders,
  });
  assert.equal(noKeyResp.status, 500);
});

// ============================================================================
// 3. Open Mode (Self-Signed Ed25519 + X-Hyphae-Public-Key, Small-Order & Quotas)
// ============================================================================

test("open mode: raw & JWK X-Hyphae-Public-Key succeed (201), mismatch/missing/small-order rejected (401), quotas enforced (429)", async () => {
  const alice = await generateEd25519Identity("alice@macbook");
  const mallory = await generateEd25519Identity("mallory@rogue");

  const harness = createTestHarness({
    DROP_AUTH_MODE: "open",
    CREATES_PER_HOUR_PER_NODE: "2",
    CREATES_PER_HOUR_PER_IP: "3",
  });

  // 1) Raw 43-char base64url X-Hyphae-Public-Key succeeds -> 201
  const rawHeaders = await alice.signHeaders({
    method: "POST",
    pathAndQuery: "/v1/drops",
    includePublicKeyHeader: true,
    publicKeyFormat: "raw",
  });
  const r1 = await harness.fetch("/v1/drops", {
    method: "POST",
    headers: { ...rawHeaders, "CF-Connecting-IP": "198.51.100.10" },
  });
  assert.equal(r1.status, 201);
  const slot1 = await r1.json();

  // 2) JSON OKP JWK X-Hyphae-Public-Key succeeds -> 201
  const jwkHeaders = await alice.signHeaders({
    method: "POST",
    pathAndQuery: "/v1/drops",
    includePublicKeyHeader: true,
    publicKeyFormat: "jwk",
  });
  const r2 = await harness.fetch("/v1/drops", {
    method: "POST",
    headers: { ...jwkHeaders, "CF-Connecting-IP": "198.51.100.10" },
  });
  assert.equal(r2.status, 201);

  // 3) Per-pubkey creation limit (2/hr) triggers 429 even if caller changes nodeId!
  const renamedAliceHeaders = await alice.signHeaders({
    method: "POST",
    pathAndQuery: "/v1/drops",
    nodeOverride: "alice-alias@macbook",
    includePublicKeyHeader: true,
  });
  const r3 = await harness.fetch("/v1/drops", {
    method: "POST",
    headers: { ...renamedAliceHeaders, "CF-Connecting-IP": "198.51.100.10" },
  });
  assert.equal(r3.status, 429);
  assert.ok(Number(r3.headers.get("Retry-After")) >= 1);
  const r3Problem = await r3.json();
  assert.equal(r3Problem.error, "drop_rate_limited");

  // 4) Per-IP creation limit (3/hr): 3rd creation from different pubkey succeeds, 4th gets 429
  const bob = await generateEd25519Identity("bob@laptop");
  const bobHeaders1 = await bob.signHeaders({
    method: "POST",
    pathAndQuery: "/v1/drops",
    includePublicKeyHeader: true,
  });
  const r4 = await harness.fetch("/v1/drops", {
    method: "POST",
    headers: { ...bobHeaders1, "CF-Connecting-IP": "198.51.100.10" },
  });
  assert.equal(r4.status, 201);

  const bobHeaders2 = await bob.signHeaders({
    method: "POST",
    pathAndQuery: "/v1/drops",
    includePublicKeyHeader: true,
  });
  const r5 = await harness.fetch("/v1/drops", {
    method: "POST",
    headers: { ...bobHeaders2, "CF-Connecting-IP": "198.51.100.10" },
  });
  assert.equal(r5.status, 429);

  // 5) Mismatched key/signature (signed by Mallory, header claims Alice's pubkey) -> 401
  const mismatchHeaders = await mallory.signHeaders({
    method: "POST",
    pathAndQuery: "/v1/drops",
  });
  mismatchHeaders[PUBLIC_KEY_HEADER] = alice.pubB64;
  const rMismatch = await harness.fetch("/v1/drops", {
    method: "POST",
    headers: mismatchHeaders,
  });
  assert.equal(rMismatch.status, 401);

  // 6) Missing Authorization header -> 401
  const rNoAuth = await harness.fetch("/v1/drops", {
    method: "POST",
    headers: { [PUBLIC_KEY_HEADER]: alice.pubB64 },
  });
  assert.equal(rNoAuth.status, 401);

  // 7) Missing X-Hyphae-Public-Key header -> 401
  const noPubHeaders = await mallory.signHeaders({
    method: "POST",
    pathAndQuery: "/v1/drops",
    includePublicKeyHeader: false,
  });
  const rNoPub = await harness.fetch("/v1/drops", {
    method: "POST",
    headers: noPubHeaders,
  });
  assert.equal(rNoPub.status, 401);

  // 8) All-zero small-order Ed25519 public key rejected -> 401
  const allZeroPub = base64UrlEncode(new Uint8Array(32));
  const zeroKeyHeaders = await mallory.signHeaders({
    method: "POST",
    pathAndQuery: "/v1/drops",
  });
  zeroKeyHeaders[PUBLIC_KEY_HEADER] = allZeroPub;
  const rZero = await harness.fetch("/v1/drops", {
    method: "POST",
    headers: zeroKeyHeaders,
  });
  assert.equal(rZero.status, 401);

  // 9) Impersonation defense: Mallory cannot access Alice's slot /stream even if claiming node="alice@macbook"
  const impersonateStreamHeaders = await mallory.signHeaders({
    method: "GET",
    pathAndQuery: `/v1/drops/${slot1.dropId}/stream`,
    nodeOverride: "alice@macbook",
    includePublicKeyHeader: true,
  });
  const rImpersonate = await harness.fetch(`/v1/drops/${slot1.dropId}/stream`, {
    method: "GET",
    headers: impersonateStreamHeaders,
  });
  assert.equal(rImpersonate.status, 401);

  // 10) Direct verifyHyphaeEd25519Request export sanity check
  const directReq = new Request("https://drop.hyphae.test/v1/drops", {
    method: "POST",
    headers: await mallory.signHeaders({
      method: "POST",
      pathAndQuery: "/v1/drops",
      includePublicKeyHeader: true,
    }),
  });
  const directVerified = await verifyHyphaeEd25519Request(directReq, {
    mode: "open",
    nowMs: BASE_NOW_MS,
  });
  assert.equal(directVerified.ok, true);
  assert.equal(directVerified.nodeId, "mallory@rogue");
  assert.equal(directVerified.pubKeyB64, mallory.pubB64);
});

// ============================================================================
// 4. Strict CORS + Chrome Private Network Access (PNA)
// ============================================================================

test("strict CORS & Chrome PNA: allowed origin succeeds, disallowed/null/wildcard origins receive no ACAO", async () => {
  // Even if misconfigured with "*" and "null", the worker MUST ignore them fail-closed.
  const harness = createTestHarness({
    ALLOWED_ORIGINS: "*, null, https://hyphae.to, javascript:alert(1)",
    ALLOW_PRIVATE_NETWORK: "true",
  });

  // Allowed origin preflight on /v1/drops/{id}
  const okPreflight = await harness.fetch("/v1/drops/abcdefghijklmnopqrstuv", {
    method: "OPTIONS",
    headers: {
      Origin: "https://hyphae.to",
      "Access-Control-Request-Method": "POST",
      "Access-Control-Request-Private-Network": "true",
    },
  });
  assert.equal(okPreflight.status, 204);
  assert.equal(okPreflight.headers.get("Access-Control-Allow-Origin"), "https://hyphae.to");
  assert.equal(okPreflight.headers.get("Access-Control-Allow-Private-Network"), "true");
  assert.equal(okPreflight.headers.get("Vary"), "Origin");
  assert.equal(okPreflight.headers.get("Access-Control-Allow-Methods"), "GET, POST, OPTIONS");
  assert.ok(
    okPreflight.headers.get("Access-Control-Allow-Headers")?.includes("X-Hyphae-Drop-Cap")
  );
  assert.ok(
    okPreflight.headers.get("Access-Control-Allow-Headers")?.includes("Last-Event-ID")
  );

  // Allowed origin preflight on /v1/drops
  const okRootPreflight = await harness.fetch("/v1/drops", {
    method: "OPTIONS",
    headers: { Origin: "https://hyphae.to" },
  });
  assert.equal(okRootPreflight.status, 204);
  assert.equal(okRootPreflight.headers.get("Access-Control-Allow-Origin"), "https://hyphae.to");

  // Disallowed evil origin -> NO Access-Control-Allow-Origin, NO PNA
  for (const badOrigin of ["https://evil.example", "null", "*", "http://hyphae.to"]) {
    const badResp = await harness.fetch("/v1/drops/abcdefghijklmnopqrstuv", {
      method: "OPTIONS",
      headers: { Origin: badOrigin },
    });
    assert.equal(badResp.status, 204);
    assert.equal(badResp.headers.get("Access-Control-Allow-Origin"), null);
    assert.equal(badResp.headers.get("Access-Control-Allow-Private-Network"), null);
    assert.equal(badResp.headers.get("Vary"), "Origin");
  }

  // Error responses on POST /v1/drops/{id} ALSO attach strict CORS headers for allowed origin
  const errWithAllowedOrigin = await harness.fetch("/v1/drops/abcdefghijklmnopqrstuv", {
    method: "POST",
    headers: { Origin: "https://hyphae.to", [DROP_CAP_HEADER]: "hdcap1_invalid" },
  });
  assert.equal(errWithAllowedOrigin.status, 401);
  assert.equal(
    errWithAllowedOrigin.headers.get("Access-Control-Allow-Origin"),
    "https://hyphae.to"
  );
  assert.equal(errWithAllowedOrigin.headers.get("Access-Control-Allow-Private-Network"), "true");

  const errWithEvilOrigin = await harness.fetch("/v1/drops/abcdefghijklmnopqrstuv", {
    method: "POST",
    headers: { Origin: "https://evil.example", [DROP_CAP_HEADER]: "hdcap1_invalid" },
  });
  assert.equal(errWithEvilOrigin.status, 401);
  assert.equal(errWithEvilOrigin.headers.get("Access-Control-Allow-Origin"), null);
});

// ============================================================================
// 5. Pre-Body Capability Verification & Payload Ceiling Enforcement
// ============================================================================

test("invalid X-Hyphae-Drop-Cap and oversized Content-Length rejected BEFORE body consumption", async () => {
  const alice = await generateEd25519Identity("alice@macbook");
  const harness = createTestHarness({
    DROP_AUTH_MODE: "private",
    ALLOWED_NODE_KEYS: JSON.stringify({ "alice@macbook": alice.pubB64 }),
    MAX_PAYLOAD_BYTES: "128",
  });

  const createHeaders = await alice.signHeaders({
    method: "POST",
    pathAndQuery: "/v1/drops",
  });
  const createResp = await harness.fetch("/v1/drops", {
    method: "POST",
    headers: createHeaders,
  });
  assert.equal(createResp.status, 201);
  const { dropId, postCap, subCap } = await createResp.json();

  function makeTrapStream() {
    let pulled = false;
    const stream = new ReadableStream(
      {
        pull(controller) {
          pulled = true;
          controller.enqueue(new Uint8Array(64).fill(0x41));
          controller.close();
        },
      },
      { highWaterMark: 0 }
    );
    return { stream, wasPulled: () => pulled };
  }

  // Invalid cap token -> 401 BEFORE body is pulled!
  const trap1 = makeTrapStream();
  const reqInvalid = new Request(`https://drop.hyphae.test/v1/drops/${dropId}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      [DROP_CAP_HEADER]: "hdcap1_invalid_capability_token",
    },
    body: trap1.stream,
    duplex: "half",
  });
  const rInvalid = await harness.app.fetch(reqInvalid, harness.env, {});
  assert.equal(rInvalid.status, 401);
  assert.equal(reqInvalid.bodyUsed, false, "Request.bodyUsed must remain false on invalid cap");
  assert.equal(trap1.wasPulled(), false, "request body must NOT be read on invalid capability");

  // Wrong-role subCap on POST /v1/drops/{id} -> 401 BEFORE body is pulled!
  const trap2 = makeTrapStream();
  const reqWrongRole = new Request(`https://drop.hyphae.test/v1/drops/${dropId}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      [DROP_CAP_HEADER]: subCap,
    },
    body: trap2.stream,
    duplex: "half",
  });
  const rWrongRole = await harness.app.fetch(reqWrongRole, harness.env, {});
  assert.equal(rWrongRole.status, 401);
  assert.equal(reqWrongRole.bodyUsed, false);
  assert.equal(trap2.wasPulled(), false, "request body must NOT be read on wrong capability role");

  // Missing X-Hyphae-Drop-Cap -> 401 BEFORE body is pulled!
  const trap3 = makeTrapStream();
  const reqMissing = new Request(`https://drop.hyphae.test/v1/drops/${dropId}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: trap3.stream,
    duplex: "half",
  });
  const rMissing = await harness.app.fetch(reqMissing, harness.env, {});
  assert.equal(rMissing.status, 401);
  assert.equal(reqMissing.bodyUsed, false);
  assert.equal(trap3.wasPulled(), false, "request body must NOT be read when capability is missing");

  // Oversized Content-Length with valid postCap -> 413 BEFORE body is pulled!
  const trap4 = makeTrapStream();
  const reqOversizedHeader = new Request(`https://drop.hyphae.test/v1/drops/${dropId}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/octet-stream",
      "Content-Length": "999999",
      [DROP_CAP_HEADER]: postCap,
    },
    body: trap4.stream,
    duplex: "half",
  });
  const rOversizedHeader = await harness.app.fetch(reqOversizedHeader, harness.env, {});
  assert.equal(rOversizedHeader.status, 413);
  assert.equal(reqOversizedHeader.bodyUsed, false);
  assert.equal(
    trap4.wasPulled(),
    false,
    "request body must NOT be read when Content-Length exceeds maxPayloadBytes"
  );
  const problem413 = await rOversizedHeader.json();
  assert.equal(problem413.error, "drop_payload_too_large");
  assert.equal(problem413.maxPayloadBytes, 128);

  // Positive control: valid postCap DOES pull the stream and accept the payload (201)
  const trapValid = makeTrapStream();
  const rValid = await harness.fetch(`/v1/drops/${dropId}`, {
    method: "POST",
    headers: { "Content-Type": "application/octet-stream", [DROP_CAP_HEADER]: postCap },
    body: trapValid.stream,
    duplex: "half",
  });
  assert.equal(rValid.status, 201);
  assert.equal(trapValid.wasPulled(), true);

  // Streaming oversized payload (no Content-Length) -> 413
  const bigStream = new ReadableStream({
    start(controller) {
      controller.enqueue(new Uint8Array(80).fill(0x55));
      controller.enqueue(new Uint8Array(80).fill(0x66));
      controller.close();
    },
  });
  const rOversizedStream = await harness.fetch(`/v1/drops/${dropId}`, {
    method: "POST",
    headers: { [DROP_CAP_HEADER]: postCap },
    body: bigStream,
    duplex: "half",
  });
  assert.equal(rOversizedStream.status, 413);

  // Empty body -> 400
  const rEmpty = await harness.fetch(`/v1/drops/${dropId}`, {
    method: "POST",
    headers: { [DROP_CAP_HEADER]: postCap },
    body: new Uint8Array(0),
  });
  assert.equal(rEmpty.status, 400);
});

// ============================================================================
// 6. Full E2E: Create -> Post -> Late-Sub Catch-Up + Live SSE -> Burn Zeroize
// ============================================================================

test("E2E flow: POST /v1/drops -> POST ciphertext -> late-subscriber catch-up + live SSE push -> ack burn zeroizes RAM & closes slot", async () => {
  const alice = await generateEd25519Identity("alice@macbook");
  const harness = createTestHarness(
    {
      DROP_AUTH_MODE: "private",
      ALLOWED_NODE_KEYS: JSON.stringify({ "alice@macbook": alice.pubB64 }),
      MAX_SSE_STREAMS_PER_DROP: "2",
    },
    { keepaliveMs: 60 }
  );

  // 1) Allocate slot with burnAfterRead=true, maxItems=2
  const createBody = new TextEncoder().encode(
    JSON.stringify({ ttlSeconds: 600, maxItems: 2, burnAfterRead: true })
  );
  const createHeaders = await alice.signHeaders({
    method: "POST",
    pathAndQuery: "/v1/drops",
    bodyBytes: createBody,
  });
  const createResp = await harness.fetch("/v1/drops", {
    method: "POST",
    headers: { "Content-Type": "application/json", ...createHeaders },
    body: createBody,
  });
  assert.equal(createResp.status, 201);
  const { dropId, postCap, subCap, expiresAtMs } = await createResp.json();

  // Verify postCap is rejected on /stream and /ack
  const badStream = await harness.fetch(`/v1/drops/${dropId}/stream`, {
    method: "GET",
    headers: { [DROP_CAP_HEADER]: postCap },
  });
  assert.equal(badStream.status, 401);

  const badAck = await harness.fetch(`/v1/drops/${dropId}/ack`, {
    method: "POST",
    headers: { "Content-Type": "application/json", [DROP_CAP_HEADER]: postCap },
    body: JSON.stringify({ seq: 1, burn: true }),
  });
  assert.equal(badAck.status, 401);

  // 2) Post item #1 BEFORE any subscriber connects (tests late-subscriber catch-up!)
  const envelope1 = JSON.stringify({ v: 1, ct: "ciphertext-item-one" });
  const post1 = await harness.fetch(`/v1/drops/${dropId}`, {
    method: "POST",
    headers: {
      Origin: "https://hyphae.to",
      "Content-Type": "application/json",
      [DROP_CAP_HEADER]: postCap,
    },
    body: envelope1,
  });
  assert.equal(post1.status, 201);
  assert.equal(post1.headers.get("Access-Control-Allow-Origin"), "https://hyphae.to");
  assert.deepEqual(await post1.json(), { seq: 1, expiresAtMs });

  // Capture direct reference to the Uint8Array stored in DropSlotDO RAM!
  const doInstance = harness.dropSlotNs.instances.get(dropId);
  assert.ok(doInstance && doInstance.slot);
  const storedPayload1 = doInstance.slot.items[0].payload;
  assert.equal(storedPayload1.some((b) => b !== 0), true);

  // 3) Connect late subscriber #1 via subCap -> must receive `: connected` + catch-up item #1
  const sseResp1 = await harness.fetch(`/v1/drops/${dropId}/stream`, {
    method: "GET",
    headers: { [DROP_CAP_HEADER]: subCap },
  });
  assert.equal(sseResp1.status, 200);
  assert.equal(sseResp1.headers.get("Content-Type"), "text/event-stream; charset=utf-8");
  assert.equal(sseResp1.headers.get("Cache-Control"), "no-store");
  assert.equal(sseResp1.headers.get("X-Accel-Buffering"), "no");

  const reader1 = sseResp1.body.getReader();
  const sseState1 = { buf: "", done: false };
  await readSseUntil(reader1, sseState1, (s) => s.includes("ciphertext-item-one"));
  assert.ok(sseState1.buf.includes(": connected\n\n"));
  assert.ok(sseState1.buf.includes(`id: 1\nevent: drop\ndata: ${envelope1}\n\n`));

  // Also verify keepalive frame arrives automatically
  await readSseUntil(reader1, sseState1, (s) => s.includes(": keepalive\n\n"));

  // 4) Connect subscriber #2 via creator Hyphae-Ed25519 auth with Last-Event-ID: 1
  const creatorStreamHeaders = await alice.signHeaders({
    method: "GET",
    pathAndQuery: `/v1/drops/${dropId}/stream`,
  });
  const sseResp2 = await harness.fetch(`/v1/drops/${dropId}/stream`, {
    method: "GET",
    headers: { ...creatorStreamHeaders, "Last-Event-ID": "1" },
  });
  assert.equal(sseResp2.status, 200);
  const reader2 = sseResp2.body.getReader();
  const sseState2 = { buf: "", done: false };
  await readSseUntil(reader2, sseState2, (s) => s.includes(": connected\n\n"));

  // 5) 3rd concurrent subscriber rejected with 429 (maxSseStreamsPerDrop = 2)
  const sseResp3 = await harness.fetch(`/v1/drops/${dropId}/stream`, {
    method: "GET",
    headers: { [DROP_CAP_HEADER]: subCap },
  });
  assert.equal(sseResp3.status, 429);
  assert.equal(sseResp3.headers.get("Retry-After"), "5");

  // 6) Live push: post item #2 -> BOTH open SSE streams receive seq=2 live!
  const envelope2 = JSON.stringify({ v: 1, ct: "ciphertext-item-two" });
  const post2 = await harness.fetch(`/v1/drops/${dropId}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", [DROP_CAP_HEADER]: postCap },
    body: envelope2,
  });
  assert.equal(post2.status, 201);
  assert.deepEqual(await post2.json(), { seq: 2, expiresAtMs });

  const storedPayload2 = doInstance.slot.items[1].payload;
  assert.equal(storedPayload2.some((b) => b !== 0), true);

  // Item #3 exceeds maxItems=2 -> 409 Conflict (`drop_full`)
  const post3 = await harness.fetch(`/v1/drops/${dropId}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", [DROP_CAP_HEADER]: postCap },
    body: JSON.stringify({ v: 1, ct: "overflow" }),
  });
  assert.equal(post3.status, 409);
  const fullProblem = await post3.json();
  assert.equal(fullProblem.error, "drop_full");
  assert.equal(fullProblem.maxItems, 2);

  await readSseUntil(reader1, sseState1, (s) => s.includes("ciphertext-item-two"));
  await readSseUntil(reader2, sseState2, (s) => s.includes("ciphertext-item-two"));
  // Subscriber #2 had Last-Event-ID: 1, so it MUST NOT have received item #1!
  assert.equal(sseState2.buf.includes("ciphertext-item-one"), false);
  assert.ok(sseState2.buf.includes(`id: 2\nevent: drop\ndata: ${envelope2}\n\n`));

  // 7) Partial burn: ack seq=1 burn=true -> item #1 zeroized, item #2 still live, slotClosed=false
  const ack1 = await harness.fetch(`/v1/drops/${dropId}/ack`, {
    method: "POST",
    headers: { "Content-Type": "application/json", [DROP_CAP_HEADER]: subCap },
    body: JSON.stringify({ seq: 1, burn: true }),
  });
  assert.equal(ack1.status, 200);
  assert.deepEqual(await ack1.json(), {
    ackedSeq: 1,
    burnedItems: 1,
    burnedBytes: new TextEncoder().encode(envelope1).byteLength,
    remainingItems: 1,
    slotClosed: false,
  });
  assert.equal(
    storedPayload1.every((b) => b === 0),
    true,
    "burned item #1 Uint8Array must be zeroized in RAM"
  );
  assert.equal(
    storedPayload2.some((b) => b !== 0),
    true,
    "unburned item #2 must remain intact"
  );

  // 8) Final burn via creator Hyphae-Ed25519 auth: ack seq=2 burn=true -> zeroized & slotClosed=true!
  const ack2Body = new TextEncoder().encode(JSON.stringify({ seq: 2, burn: true }));
  const ack2Headers = await alice.signHeaders({
    method: "POST",
    pathAndQuery: `/v1/drops/${dropId}/ack`,
    bodyBytes: ack2Body,
  });
  const ack2 = await harness.fetch(`/v1/drops/${dropId}/ack`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...ack2Headers },
    body: ack2Body,
  });
  assert.equal(ack2.status, 200);
  assert.deepEqual(await ack2.json(), {
    ackedSeq: 2,
    burnedItems: 1,
    burnedBytes: new TextEncoder().encode(envelope2).byteLength,
    remainingItems: 0,
    slotClosed: true,
  });
  assert.equal(
    storedPayload2.every((b) => b === 0),
    true,
    "burned item #2 Uint8Array must be zeroized in RAM"
  );
  assert.equal(doInstance.slot, null, "slot must be cleared from DO RAM after burn-after-read close");
  assert.equal(doInstance.subscribers.size, 0, "all SSE subscribers must be closed and removed");

  // Drain/close SSE readers cleanly (stream ends because slot closed)
  await readSseUntil(reader1, sseState1, () => sseState1.done);
  await readSseUntil(reader2, sseState2, () => sseState2.done);
  assert.equal(sseState1.done, true);
  assert.equal(sseState2.done, true);

  // Subsequent POST to burned-closed slot returns 404 Not Found
  const postAfterClose = await harness.fetch(`/v1/drops/${dropId}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", [DROP_CAP_HEADER]: postCap },
    body: envelope1,
  });
  assert.equal(postAfterClose.status, 404);
});

// ============================================================================
// 7. TTL Expiry Zeroization & `?after=` Cursor + Non-UTF-8 Binary Base64url SSE
// ============================================================================

test("TTL expiry zeroizes RAM buffers (410) and binary non-UTF-8 payloads stream as base64url with ?after= catch-up", async () => {
  const alice = await generateEd25519Identity("alice@macbook");
  const harness = createTestHarness({
    DROP_AUTH_MODE: "open",
  });

  // TTL > 900 is hard-clamped to 900 seconds
  const createBody = new TextEncoder().encode(JSON.stringify({ ttlSeconds: 99_999, maxItems: 3 }));
  const createHeaders = await alice.signHeaders({
    method: "POST",
    pathAndQuery: "/v1/drops",
    bodyBytes: createBody,
    includePublicKeyHeader: true,
  });
  const createResp = await harness.fetch("/v1/drops", {
    method: "POST",
    headers: { "Content-Type": "application/json", ...createHeaders },
    body: createBody,
  });
  assert.equal(createResp.status, 201);
  const { dropId, postCap, subCap, expiresAtMs } = await createResp.json();
  assert.equal(expiresAtMs, BASE_NOW_MS + 900_000, "TTL must be clamped to hard 900s cap");

  // Post item #1 (UTF-8) and item #2 (non-UTF-8 raw binary bytes)
  const r1 = await harness.fetch(`/v1/drops/${dropId}`, {
    method: "POST",
    headers: { [DROP_CAP_HEADER]: postCap },
    body: "plain-utf8-ciphertext",
  });
  assert.equal(r1.status, 201);

  const rawBinary = new Uint8Array([0xff, 0xfe, 0x00, 0xab, 0xcd, 0xef]);
  const r2 = await harness.fetch(`/v1/drops/${dropId}`, {
    method: "POST",
    headers: { [DROP_CAP_HEADER]: postCap },
    body: rawBinary,
  });
  assert.equal(r2.status, 201);

  const doInstance = harness.dropSlotNs.instances.get(dropId);
  const storedBin = doInstance.slot.items[1].payload;
  assert.deepEqual(storedBin, rawBinary);

  // Open-mode creator auth WITHOUT X-Hyphae-Public-Key on /stream?after=1 verifies against pinned slot key!
  const deferredHeaders = await alice.signHeaders({
    method: "GET",
    pathAndQuery: `/v1/drops/${dropId}/stream?after=1`,
    includePublicKeyHeader: false,
  });
  const streamResp = await harness.fetch(`/v1/drops/${dropId}/stream?after=1`, {
    method: "GET",
    headers: deferredHeaders,
  });
  assert.equal(streamResp.status, 200);
  const reader = streamResp.body.getReader();
  const state = { buf: "", done: false };
  const expectedB64 = base64UrlEncode(rawBinary);
  await readSseUntil(reader, state, (s) => s.includes(expectedB64));
  assert.equal(state.buf.includes("plain-utf8-ciphertext"), false);
  assert.ok(state.buf.includes(`id: 2\nevent: drop\ndata: ${expectedB64}\n\n`));
  await reader.cancel();

  // Advance clock past TTL -> slot expires and zeroizes buffered bytes in RAM!
  harness.advanceMs(900_000);
  const afterExpiry = await harness.fetch(`/v1/drops/${dropId}`, {
    method: "POST",
    headers: { [DROP_CAP_HEADER]: postCap },
    body: "too-late",
  });
  assert.equal(afterExpiry.status, 410);
  assert.equal((await afterExpiry.json()).error, "drop_expired");

  // Also trigger DO-side expiry sweep via /ack with valid creator auth (still returns 410 and zeroizes)
  const freshAckHeaders = await alice.signHeaders({
    method: "POST",
    pathAndQuery: `/v1/drops/${dropId}/ack`,
    bodyBytes: new TextEncoder().encode(JSON.stringify({ seq: 2, burn: false })),
    ts: harness.now(),
    includePublicKeyHeader: true,
  });
  const ackExpired = await harness.fetch(`/v1/drops/${dropId}/ack`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...freshAckHeaders },
    body: JSON.stringify({ seq: 2, burn: false }),
  });
  assert.equal(ackExpired.status, 410);
  assert.equal(
    storedBin.every((b) => b === 0),
    true,
    "expired slot buffers must be zeroized in RAM"
  );
  assert.equal(doInstance.slot, null);
  assert.ok(subCap.startsWith(DROP_CAP_PREFIX));
});

// ============================================================================
// 8. Aggregate-Only GET /v1/health & Static Privacy Invariants
// ============================================================================

test("GET /v1/health returns aggregate-only JSON with zero drop IDs, IPs, or secrets", async () => {
  const alice = await generateEd25519Identity("alice@macbook");
  const harness = createTestHarness({
    DROP_AUTH_MODE: "private",
    ALLOWED_NODE_KEYS: JSON.stringify({ "alice@macbook": alice.pubB64 }),
    ALLOWED_ORIGINS: "https://hyphae.to, https://staging.hyphae.to",
  });

  // Create an active drop first to confirm health NEVER leaks its dropId, caps, IP, or keys
  const createHeaders = await alice.signHeaders({
    method: "POST",
    pathAndQuery: "/v1/drops",
  });
  const createdResp = await harness.fetch("/v1/drops", {
    method: "POST",
    headers: { ...createHeaders, "CF-Connecting-IP": "203.0.113.42" },
  });
  assert.equal(createdResp.status, 201);
  const created = await createdResp.json();

  const healthResp = await harness.fetch("/v1/health", { method: "GET" });
  assert.equal(healthResp.status, 200);
  assert.equal(healthResp.headers.get("Cache-Control"), "no-store");
  const rawText = await healthResp.text();
  const health = JSON.parse(rawText);

  assert.deepEqual(health, {
    ok: true,
    runtime: "cloudflare-workers",
    mode: "private",
    dropRelay: {
      enabled: true,
      maxPayloadBytes: 65536,
      maxTtlSeconds: 900,
      allowedOriginsCount: 2,
    },
  });

  // Strictly zero sensitive values in health body
  assert.equal(rawText.includes(created.dropId), false);
  assert.equal(rawText.includes(created.postCap), false);
  assert.equal(rawText.includes(created.subCap), false);
  assert.equal(rawText.includes(alice.pubB64), false);
  assert.equal(rawText.includes("alice@macbook"), false);
  assert.equal(rawText.includes("203.0.113.42"), false);
  assert.equal(rawText.includes(TEST_HMAC_KEY), false);

  // Clean up any open expiry timer on the created DO
  harness.dropSlotNs.instances.get(created.dropId)?._destroySlot({ markExpired: false });
});

test("HTTP-level HMAC key rotation (DROP_CAP_HMAC_KEY_PREV) & query-string signature binding", async () => {
  const alice = await generateEd25519Identity("alice@macbook");
  const harness = createTestHarness({
    DROP_AUTH_MODE: "private",
    ALLOWED_NODE_KEYS: JSON.stringify({ "alice@macbook": alice.pubB64 }),
    DROP_CAP_HMAC_KEY: TEST_HMAC_KEY_PREV,
  });

  // Create drop under old HMAC key
  const createHeaders = await alice.signHeaders({
    method: "POST",
    pathAndQuery: "/v1/drops",
  });
  const createResp = await harness.fetch("/v1/drops", {
    method: "POST",
    headers: createHeaders,
  });
  assert.equal(createResp.status, 201);
  const { dropId, postCap, subCap } = await createResp.json();

  // Rotate Worker env: new primary key + old key in DROP_CAP_HMAC_KEY_PREV
  harness.env.DROP_CAP_HMAC_KEY = TEST_HMAC_KEY;
  harness.env.DROP_CAP_HMAC_KEY_PREV = TEST_HMAC_KEY_PREV;

  // In-flight postCap, subCap /stream, and subCap /ack all continue working seamlessly!
  const postResp = await harness.fetch(`/v1/drops/${dropId}`, {
    method: "POST",
    headers: { [DROP_CAP_HEADER]: postCap },
    body: JSON.stringify({ rotated: true }),
  });
  assert.equal(postResp.status, 201);

  const streamResp = await harness.fetch(`/v1/drops/${dropId}/stream`, {
    method: "GET",
    headers: { [DROP_CAP_HEADER]: subCap },
  });
  assert.equal(streamResp.status, 200);
  const reader = streamResp.body.getReader();
  const sseState = { buf: "", done: false };
  await readSseUntil(reader, sseState, (s) => s.includes('"rotated":true'));
  await reader.cancel();

  // Tampering query string on a signed Hyphae-Ed25519 GET /stream request MUST fail closed (401)
  const signedForAfter0 = await alice.signHeaders({
    method: "GET",
    pathAndQuery: `/v1/drops/${dropId}/stream?after=0`,
  });
  const tamperedQueryResp = await harness.fetch(`/v1/drops/${dropId}/stream?after=1`, {
    method: "GET",
    headers: signedForAfter0,
  });
  assert.equal(tamperedQueryResp.status, 401);

  const ackResp = await harness.fetch(`/v1/drops/${dropId}/ack`, {
    method: "POST",
    headers: { "Content-Type": "application/json", [DROP_CAP_HEADER]: subCap },
    body: JSON.stringify({ seq: 1, burn: true }),
  });
  assert.equal(ackResp.status, 200);
  assert.equal((await ackResp.json()).burnedItems, 1);

  // Removing DROP_CAP_HMAC_KEY_PREV invalidates old capabilities immediately
  delete harness.env.DROP_CAP_HMAC_KEY_PREV;
  const retiredResp = await harness.fetch(`/v1/drops/${dropId}`, {
    method: "POST",
    headers: { [DROP_CAP_HEADER]: postCap },
    body: JSON.stringify({ afterRetire: true }),
  });
  assert.equal(retiredResp.status, 401);

  harness.dropSlotNs.instances.get(dropId)?._destroySlot({ markExpired: false });
});

test("static invariants: src/index.mjs never accesses DO storage and never calls console.*", () => {
  const source = readFileSync(INDEX_PATH, "utf8");
  // Strip block comments and line comments before checking code invariants
  const codeOnly = source
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/\/\/.*$/gm, "");
  assert.equal(
    /\.storage\b/.test(codeOnly),
    false,
    "DropSlotDO must NEVER reference .storage (strictly RAM-only)"
  );
  assert.equal(
    /\bconsole\s*\.\s*(log|info|debug|warn|error|trace)\b/.test(codeOnly),
    false,
    "Worker must NEVER log via console.* to avoid leaking drop metadata"
  );
});
