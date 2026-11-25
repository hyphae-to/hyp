/**
 * Hyphae v2 Blind Ephemeral Drop Relay — Cloudflare Workers + RAM-only Durable Object.
 *
 * Wire-compatible with `crates/hyp-node/src/engine/drop_relay.rs`,
 * `crates/hyp-node/src/engine/peer_link.rs`, `crates/hyp-node/src/engine/server.rs`,
 * and `site/drop/drop.js`:
 *
 * - RAM-only `DropSlotDO`: NEVER touches Durable Object persistent storage. Every
 *   opaque ciphertext `Uint8Array` lives strictly in volatile isolate RAM and is
 *   zeroized via `.fill(0)` on burn, TTL expiration, or slot close.
 * - Zero sensitive logging: never logs `dropId`, client IPs, capability tokens,
 *   public keys, or payload bytes.
 * - Stateless HMAC-SHA256 capabilities (`hdcap1_`): constant-time verified BEFORE
 *   reading request body bytes on `POST /v1/drops/{id}`, with zero-downtime key
 *   rotation via `DROP_CAP_HMAC_KEY_PREV`.
 * - Dual auth modes (`DROP_AUTH_MODE`):
 *   - `"private"` (default, fail-closed): allowlist of Ed25519 node public keys in
 *     `ALLOWED_NODE_KEYS` (JSON map or comma/newline `nodeId=b64url` pairs).
 *   - `"open"` (public relay e.g. `drop.hyphae.to`): self-authenticated Ed25519
 *     requests carrying `X-Hyphae-Public-Key` (raw 43-char base64url or OKP JWK),
 *     protected by per-IP and per-pubkey sliding-window creation quotas.
 * - Fail-closed CORS + Chrome Private Network Access (PNA): strict explicit
 *   origin allowlist (never `"*"` or `"null"`).
 */

/** @type {"hdcap1_"} */
export const DROP_CAP_PREFIX = "hdcap1_";
export const DROP_CAP_DOMAIN = "hyphae/v2/human-drop-cap\n";
export const DROP_CAP_HEADER = "X-Hyphae-Drop-Cap";
export const PUBLIC_KEY_HEADER = "X-Hyphae-Public-Key";
export const DROP_CAP_ROLE_POST = 1;
export const DROP_CAP_ROLE_SUB = 2;
export const DROP_ID_BYTES = 16;
export const DROP_ID_LEN = 22;
export const DROP_CAP_RAW_LEN = 41; // role[1] || exp_ms_be[8] || mac[32]
export const DROP_CAP_ENCODED_LEN = 55; // base64url_nopad(41 bytes)
export const HTTP_AUTH_DOMAIN_PREFIX = "hyphae/v2/http-auth\n";
export const HTTP_AUTH_SKEW_MS = 5 * 60 * 1000;
export const HARD_MAX_TTL_SECONDS = 900;
export const DEFAULT_TTL_SECONDS = 600;
export const DEFAULT_MAX_PAYLOAD_BYTES = 65_536;
export const DEFAULT_MAX_ITEMS_PER_DROP = 16;
export const DEFAULT_MAX_SSE_STREAMS_PER_DROP = 2;
export const DEFAULT_ALLOWED_ORIGIN = "https://hyphae.to";
export const DROP_SSE_KEEPALIVE_MS = 25_000;
export const CREATE_RATE_WINDOW_MS = 3_600_000;
export const DEFAULT_CREATES_PER_HOUR_PER_NODE = 10;
export const DEFAULT_CREATES_PER_HOUR_PER_IP = 20;

const MAX_CONTROL_BODY_BYTES = 16_384;
const MAX_CREATOR_NODE_ID_LEN = 256;
const MAX_NONCE_LEN = 128;
const MIN_HMAC_KEY_BYTES = 32;
const RATE_TABLE_PRUNE_THRESHOLD = 4_096;
const MAX_HTTP_AUTH_NONCES = 16_384;
const MAX_TIMEOUT_MS = 2_147_483_647;
const PROBLEM_TYPE_BASE = "https://hyphae.to/errors/";
const CONTENT_TYPE_PROBLEM_JSON = "application/problem+json";

const TEXT_ENCODER = new TextEncoder();
const UTF8_DECODER_FATAL = new TextDecoder("utf-8", { fatal: true });
const DROP_CAP_DOMAIN_BYTES = TEXT_ENCODER.encode(DROP_CAP_DOMAIN);
const HTTP_AUTH_DOMAIN_BYTES = TEXT_ENCODER.encode(HTTP_AUTH_DOMAIN_PREFIX);
const EMPTY_BYTES = new Uint8Array(0);

/** `p = 2^255 - 19` in little-endian bytes (matches `crates/hyp-crypto/src/keys.rs`). */
const ED25519_P_LE = new Uint8Array([
  0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
]);

/** Canonical little-endian y-coordinates (mod p) of the eight small-order Ed25519 points. */
const SMALL_ORDER_ED25519_Y_LE = [
  // 0
  new Uint8Array(32),
  // 1
  new Uint8Array([
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  ]),
  // p - 1
  new Uint8Array([
    0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
  ]),
  // 0x05fc536d880238b13933c6d305acdfd5f098eff289f4c345b027b2c28f95e826 (LE)
  new Uint8Array([
    0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0,
    0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0,
    0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39,
    0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05,
  ]),
  // 0x7a03ac9277fdc74ec6cc392cfa53202a0f67100d760b3cba4fd84d3d706a17c7 (LE)
  new Uint8Array([
    0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f,
    0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f,
    0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6,
    0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a,
  ]),
];

// ============================================================================
// Encoding, Constant-Time Comparison & Ed25519 Validation Helpers
// ============================================================================

/**
 * Encodes bytes as unpadded RFC 4648 base64url.
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function base64UrlEncode(bytes) {
  let binary = "";
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    const slice = bytes.subarray(i, Math.min(i + chunkSize, bytes.length));
    binary += String.fromCharCode(...slice);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

/**
 * Strictly decodes unpadded RFC 4648 base64url, rejecting non-canonical encodings.
 * @param {string} input
 * @returns {Uint8Array | null}
 */
export function base64UrlDecodeStrict(input) {
  if (typeof input !== "string" || input.length === 0) return null;
  if (input.length % 4 === 1) return null;
  if (!/^[A-Za-z0-9_-]+$/.test(input)) return null;
  const padded = input.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((input.length + 3) % 4);
  let binary;
  try {
    binary = atob(padded);
  } catch {
    return null;
  }
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    out[i] = binary.charCodeAt(i);
  }
  // Enforce canonical base64url (no non-zero unused trailing bits).
  if (base64UrlEncode(out) !== input) {
    out.fill(0);
    return null;
  }
  return out;
}

/**
 * Constant-time equality over two byte arrays.
 * @param {Uint8Array} a
 * @param {Uint8Array} b
 * @returns {boolean}
 */
export function timingSafeEqualBytes(a, b) {
  const maxLen = Math.max(a.length, b.length);
  let diff = a.length ^ b.length;
  for (let i = 0; i < maxLen; i += 1) {
    const av = i < a.length ? a[i] : 0;
    const bv = i < b.length ? b[i] : 0;
    diff |= av ^ bv;
  }
  return diff === 0;
}

/**
 * Lowercase hex SHA-256 digest of raw bytes.
 * @param {Uint8Array} bytes
 * @returns {Promise<string>}
 */
export async function sha256Hex(bytes) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  let hex = "";
  for (let i = 0; i < digest.length; i += 1) {
    hex += digest[i].toString(16).padStart(2, "0");
  }
  return hex;
}

/**
 * Concatenates multiple `Uint8Array` chunks into a single buffer.
 * @param {Uint8Array[]} parts
 * @returns {Uint8Array}
 */
function concatBytes(parts) {
  let total = 0;
  for (const p of parts) total += p.byteLength;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.byteLength;
  }
  return out;
}

/**
 * Returns `true` if `dropId` is a valid 22-char unpadded base64url 128-bit ID.
 * @param {string} dropId
 * @returns {boolean}
 */
export function isValidDropId(dropId) {
  return (
    typeof dropId === "string" &&
    dropId.length === DROP_ID_LEN &&
    /^[A-Za-z0-9_-]{22}$/.test(dropId)
  );
}

/**
 * Generates a fresh 128-bit CSPRNG `dropId` (22 unpadded base64url chars).
 * @returns {string}
 */
export function generateDropId() {
  const bytes = new Uint8Array(DROP_ID_BYTES);
  crypto.getRandomValues(bytes);
  const id = base64UrlEncode(bytes);
  bytes.fill(0);
  return id;
}

/**
 * Returns `true` if `bytes` encodes a small-order Ed25519 point (including all-zero).
 * @param {Uint8Array} bytes
 * @returns {boolean}
 */
export function isSmallOrderEd25519Point(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 32) return true;
  const y = new Uint8Array(bytes);
  y[31] &= 0x7f;

  let allFf = true;
  for (let i = 1; i < 31; i += 1) {
    if (y[i] !== 0xff) {
      allFf = false;
      break;
    }
  }
  if (y[31] === 0x7f && allFf && y[0] >= 0xed) {
    const reduced = y[0] - 0xed;
    y.fill(0);
    y[0] = reduced;
  }

  for (const blocked of SMALL_ORDER_ED25519_Y_LE) {
    if (timingSafeEqualBytes(y, blocked)) {
      return true;
    }
  }
  return false;
}

/**
 * Returns `true` if `bytes` has a non-canonical Ed25519 y-coordinate (`y >= 2^255 - 19`).
 * @param {Uint8Array} bytes
 * @returns {boolean}
 */
export function isNonCanonicalEd25519Y(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 32) return true;
  for (let i = 31; i >= 0; i -= 1) {
    const b = i === 31 ? bytes[i] & 0x7f : bytes[i];
    if (b > ED25519_P_LE[i]) return true;
    if (b < ED25519_P_LE[i]) return false;
  }
  return true; // y == p is non-canonical
}

/**
 * Parses and validates an Ed25519 public key from:
 * - raw 43-char unpadded base64url string,
 * - JSON OKP JWK string or object `{"kty":"OKP","crv":"Ed25519","x":"..."}`, or
 * - raw 32-byte `Uint8Array`.
 *
 * Rejects small-order (including all-zero) and non-canonical points.
 * @param {string | Uint8Array | { kty?: string, crv?: string, x?: string }} input
 * @returns {{ bytes: Uint8Array, b64: string } | null}
 */
export function parseEd25519PublicKey(input) {
  /** @type {Uint8Array | null} */
  let raw = null;
  if (input instanceof Uint8Array) {
    if (input.length !== 32) return null;
    raw = new Uint8Array(input);
  } else if (typeof input === "string") {
    const trimmed = input.trim();
    if (!trimmed) return null;
    if (trimmed.startsWith("{")) {
      let jwk;
      try {
        jwk = JSON.parse(trimmed);
      } catch {
        return null;
      }
      return parseEd25519PublicKey(jwk);
    }
    if (trimmed.length !== 43) return null;
    raw = base64UrlDecodeStrict(trimmed);
  } else if (input && typeof input === "object" && !Array.isArray(input)) {
    if (input.kty !== "OKP" || input.crv !== "Ed25519" || typeof input.x !== "string") {
      return null;
    }
    const xTrimmed = input.x.trim();
    if (xTrimmed.length !== 43) return null;
    raw = base64UrlDecodeStrict(xTrimmed);
  } else {
    return null;
  }

  if (!raw || raw.length !== 32) return null;
  if (isSmallOrderEd25519Point(raw) || isNonCanonicalEd25519Y(raw)) {
    return null;
  }
  return { bytes: raw, b64: base64UrlEncode(raw) };
}

// ============================================================================
// RFC 9457 Problem Details Helpers
// ============================================================================

/**
 * @typedef {Object} ProblemSpec
 * @property {number} status
 * @property {string} error
 * @property {string} slug
 * @property {string} title
 * @property {string} detail
 * @property {Record<string, unknown>} [extensions]
 * @property {number} [retryAfterSeconds]
 */

/**
 * Builds an RFC 9457 `application/problem+json` response matching Hyphae v2.
 * @param {ProblemSpec} spec
 * @param {HeadersInit} [extraHeaders]
 * @returns {Response}
 */
function problemResponse(spec, extraHeaders) {
  /** @type {Record<string, unknown>} */
  const body = {
    type: `${PROBLEM_TYPE_BASE}${spec.slug}`,
    title: spec.title,
    status: spec.status,
    detail: spec.detail,
    error: spec.error,
    ...(spec.extensions || {}),
  };
  const headers = new Headers(extraHeaders);
  headers.set("Content-Type", CONTENT_TYPE_PROBLEM_JSON);
  headers.set("Cache-Control", "no-store");
  if (typeof spec.retryAfterSeconds === "number" && Number.isFinite(spec.retryAfterSeconds)) {
    headers.set("Retry-After", String(Math.max(1, Math.ceil(spec.retryAfterSeconds))));
  }
  return new Response(JSON.stringify(body), { status: spec.status, headers });
}

/**
 * Builds a `no-store` JSON response.
 * @param {number} status
 * @param {unknown} payload
 * @param {HeadersInit} [extraHeaders]
 * @returns {Response}
 */
function jsonResponse(status, payload, extraHeaders) {
  const headers = new Headers(extraHeaders);
  headers.set("Content-Type", "application/json");
  headers.set("Cache-Control", "no-store");
  return new Response(JSON.stringify(payload), { status, headers });
}

/** @returns {ProblemSpec} */
function errBadRequest(detail) {
  return {
    status: 400,
    error: "drop_bad_request",
    slug: "drop-bad-request",
    title: "Bad Drop Request",
    detail,
  };
}

/** @returns {ProblemSpec} */
function errUnauthorized(detail) {
  return {
    status: 401,
    error: "drop_unauthorized",
    slug: "drop-unauthorized",
    title: "Unauthorized Drop Request",
    detail,
  };
}

/** @returns {ProblemSpec} */
function errForbidden(detail) {
  return {
    status: 403,
    error: "drop_forbidden",
    slug: "drop-forbidden",
    title: "Forbidden Drop Request",
    detail,
  };
}

/** @returns {ProblemSpec} */
function errNotFound(detail = "drop slot not found") {
  return {
    status: 404,
    error: "drop_not_found",
    slug: "drop-not-found",
    title: "Drop Not Found",
    detail,
  };
}

/** @returns {ProblemSpec} */
function errDropFull(maxItems) {
  return {
    status: 409,
    error: "drop_full",
    slug: "drop-full",
    title: "Drop Slot Full",
    detail: `drop slot is full (max ${maxItems} items)`,
    extensions: { maxItems },
  };
}

/** @returns {ProblemSpec} */
function errExpired(detail = "drop slot or capability has expired") {
  return {
    status: 410,
    error: "drop_expired",
    slug: "drop-expired",
    title: "Drop Expired",
    detail,
  };
}

/** @returns {ProblemSpec} */
function errPayloadTooLarge(size, maxBytes) {
  return {
    status: 413,
    error: "drop_payload_too_large",
    slug: "drop-payload-too-large",
    title: "Drop Payload Too Large",
    detail: `drop payload (${size} bytes) exceeds limit of ${maxBytes} bytes`,
    extensions: { payloadBytes: size, maxPayloadBytes: maxBytes },
  };
}

/** @returns {ProblemSpec} */
function errRateLimited(reason, retryAfterSeconds) {
  const retry = Math.max(1, Math.ceil(retryAfterSeconds));
  return {
    status: 429,
    error: "drop_rate_limited",
    slug: "drop-rate-limited",
    title: "Drop Relay Rate Limited",
    detail: reason,
    extensions: { retryAfterSeconds: retry },
    retryAfterSeconds: retry,
  };
}

/** @returns {ProblemSpec} */
function errInternal(detail) {
  return {
    status: 500,
    error: "drop_internal_error",
    slug: "drop-internal-error",
    title: "Drop Relay Internal Error",
    detail,
  };
}

// ============================================================================
// Stateless `hdcap1_` HMAC-SHA256 Capabilities
// ============================================================================

/**
 * Normalizes HMAC key material from `Uint8Array` or `string` (>= 32 bytes required).
 * @param {string | Uint8Array | undefined | null} key
 * @returns {Uint8Array | null}
 */
function parseHmacKeyMaterial(key) {
  if (key instanceof Uint8Array) {
    return key.byteLength >= MIN_HMAC_KEY_BYTES ? key : null;
  }
  if (typeof key === "string") {
    const trimmed = key.trim();
    if (!trimmed) return null;
    const bytes = TEXT_ENCODER.encode(trimmed);
    return bytes.byteLength >= MIN_HMAC_KEY_BYTES ? bytes : null;
  }
  return null;
}

/**
 * Maps a numeric `DropCapRole` to its canonical MAC label (`"post"` | `"sub"`).
 * @param {number} role
 * @returns {"post" | "sub" | null}
 */
function roleToMacLabel(role) {
  if (role === DROP_CAP_ROLE_POST) return "post";
  if (role === DROP_CAP_ROLE_SUB) return "sub";
  return null;
}

/**
 * Builds the exact MAC signing input matching Rust `build_cap_mac_input`:
 * `"hyphae/v2/human-drop-cap\n" || ("post" | "sub") || "\n" || drop_id || "\n" || exp_ms_be[8]`
 * @param {number} role
 * @param {string} dropId
 * @param {Uint8Array} expMsBe
 * @returns {Uint8Array}
 */
function buildCapMacInput(role, dropId, expMsBe) {
  const label = roleToMacLabel(role);
  if (!label) {
    throw new Error("Invalid capability role");
  }
  const middle = TEXT_ENCODER.encode(`${label}\n${dropId}\n`);
  return concatBytes([DROP_CAP_DOMAIN_BYTES, middle, expMsBe]);
}

/**
 * Computes 32-byte HMAC-SHA256 over `msg` using `keyBytes`.
 * @param {Uint8Array} keyBytes
 * @param {Uint8Array} msg
 * @returns {Promise<Uint8Array>}
 */
async function hmacSha256(keyBytes, msg) {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  return new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, msg));
}

/**
 * Mints a stateless `hdcap1_` HMAC-SHA256 capability token (exact 62 chars: `7 + 55`).
 * Binary payload: `role_byte[1] || exp_ms_be[8] || mac[32]`.
 *
 * @param {{ dropId: string, role: 1 | 2, expiresAtMs: number, hmacKey: string | Uint8Array }} params
 * @returns {Promise<string>}
 */
export async function createCapability({ dropId, role, expiresAtMs, hmacKey }) {
  if (!isValidDropId(dropId)) {
    throw new Error("Invalid dropId format");
  }
  if (!roleToMacLabel(role)) {
    throw new Error("Invalid capability role");
  }
  if (typeof expiresAtMs !== "number" || !Number.isSafeInteger(expiresAtMs)) {
    throw new Error("Invalid expiresAtMs");
  }
  const keyBytes = parseHmacKeyMaterial(hmacKey);
  if (!keyBytes) {
    throw new Error(`DROP_CAP_HMAC_KEY must be at least ${MIN_HMAC_KEY_BYTES} bytes`);
  }

  const expBytes = new Uint8Array(8);
  new DataView(expBytes.buffer).setBigInt64(0, BigInt(expiresAtMs), false);
  const macInput = buildCapMacInput(role, dropId, expBytes);
  const mac = await hmacSha256(keyBytes, macInput);

  const raw = new Uint8Array(DROP_CAP_RAW_LEN);
  try {
    raw[0] = role;
    raw.set(expBytes, 1);
    raw.set(mac, 9);
    return `${DROP_CAP_PREFIX}${base64UrlEncode(raw)}`;
  } finally {
    raw.fill(0);
    mac.fill(0);
  }
}

/**
 * Constant-time stateless verification of an `hdcap1_` capability token.
 * Supports optional previous key (`prevHmacKey`) for zero-downtime key rotation.
 *
 * @param {{
 *   dropId: string,
 *   token: string,
 *   expectedRole: 1 | 2,
 *   hmacKey: string | Uint8Array | undefined | null,
 *   prevHmacKey?: string | Uint8Array | undefined | null,
 *   nowMs?: number
 * }} params
 * @returns {Promise<{ ok: true, expiresAtMs: number } | { ok: false, problem: ProblemSpec }>}
 */
export async function verifyCapability({
  dropId,
  token,
  expectedRole,
  hmacKey,
  prevHmacKey = null,
  nowMs = Date.now(),
}) {
  if (!isValidDropId(dropId)) {
    return { ok: false, problem: errUnauthorized("invalid drop_id format") };
  }
  const currentKey = parseHmacKeyMaterial(hmacKey);
  if (!currentKey) {
    return {
      ok: false,
      problem: errInternal("relay HMAC capability key is not configured"),
    };
  }
  const previousKey = parseHmacKeyMaterial(prevHmacKey);

  if (typeof token !== "string" || !token.startsWith(DROP_CAP_PREFIX)) {
    return { ok: false, problem: errUnauthorized("missing hdcap1_ token prefix") };
  }
  const encoded = token.slice(DROP_CAP_PREFIX.length);
  if (encoded.length !== DROP_CAP_ENCODED_LEN) {
    return { ok: false, problem: errUnauthorized("invalid drop capability token length") };
  }
  const raw = base64UrlDecodeStrict(encoded);
  if (!raw || raw.length !== DROP_CAP_RAW_LEN) {
    if (raw) raw.fill(0);
    return { ok: false, problem: errUnauthorized("malformed drop capability encoding") };
  }

  try {
    const tokenRole = raw[0];
    if (!roleToMacLabel(tokenRole)) {
      return { ok: false, problem: errUnauthorized("unknown drop capability role") };
    }
    if (tokenRole !== expectedRole) {
      return { ok: false, problem: errUnauthorized("drop capability role mismatch") };
    }

    const expBytes = raw.subarray(1, 9);
    const expBig = new DataView(
      expBytes.buffer,
      expBytes.byteOffset,
      expBytes.byteLength
    ).getBigInt64(0, false);
    const tag = raw.subarray(9, 41);
    const macInput = buildCapMacInput(tokenRole, dropId, expBytes);

    const expectedCur = await hmacSha256(currentKey, macInput);
    let verified = timingSafeEqualBytes(expectedCur, tag);
    expectedCur.fill(0);

    if (!verified && previousKey) {
      const expectedPrev = await hmacSha256(previousKey, macInput);
      verified = timingSafeEqualBytes(expectedPrev, tag);
      expectedPrev.fill(0);
    }

    if (!verified) {
      return { ok: false, problem: errUnauthorized("invalid drop capability signature") };
    }

    const expMs = Number(expBig);
    if (!Number.isSafeInteger(expMs) || nowMs >= expMs) {
      return { ok: false, problem: errExpired() };
    }

    return { ok: true, expiresAtMs: expMs };
  } finally {
    raw.fill(0);
  }
}

// ============================================================================
// `Hyphae-Ed25519` HTTP Authentication (Dual Mode: "private" | "open")
// ============================================================================

/**
 * Formats the exact Hyphae v2 Ed25519 HTTP auth signing input
 * (`crates/hyp-node/src/engine/peer_link.rs::http_auth_signing_input`).
 *
 * @param {string} method
 * @param {string} pathAndQuery
 * @param {number} tsMs
 * @param {string} nonce
 * @param {string} bodySha256Hex
 * @returns {Uint8Array}
 */
export function buildHttpAuthSigningInput(method, pathAndQuery, tsMs, nonce, bodySha256Hex) {
  return TEXT_ENCODER.encode(`${method}\n${pathAndQuery}\n${tsMs}\n${nonce}\n${bodySha256Hex}`);
}

/**
 * Parses `Authorization: Hyphae-Ed25519 node="...",ts="...",nonce="...",sig="..."`
 * (also accepts `nodeId="..."` if `node` is omitted, matching Rust `parse_auth_kv`).
 *
 * @param {string | null} authHeader
 * @returns {{ ok: true, nodeId: string, ts: number, nonce: string, sigBytes: Uint8Array } | { ok: false, detail: string }}
 */
export function parseHyphaeEd25519Header(authHeader) {
  if (!authHeader || typeof authHeader !== "string") {
    return { ok: false, detail: "missing Authorization header" };
  }
  const trimmed = authHeader.trim();
  if (!trimmed.startsWith("Hyphae-Ed25519 ")) {
    return { ok: false, detail: "unsupported Authorization scheme (expected Hyphae-Ed25519)" };
  }
  const rest = trimmed.slice("Hyphae-Ed25519 ".length);
  /** @type {Map<string, string>} */
  const params = new Map();
  for (const part of rest.split(",")) {
    const p = part.trim();
    if (!p) continue;
    const eq = p.indexOf("=");
    if (eq === -1) continue;
    const key = p.slice(0, eq).trim();
    let val = p.slice(eq + 1).trim();
    if (val.length >= 2 && val.startsWith('"') && val.endsWith('"')) {
      val = val.slice(1, -1);
    }
    if (key) params.set(key, val);
  }

  const nodeParam = params.get("node");
  const nodeIdParam = params.get("nodeId");
  if (nodeParam !== undefined && nodeIdParam !== undefined && nodeParam !== nodeIdParam) {
    return { ok: false, detail: "conflicting node and nodeId parameters in Ed25519 auth" };
  }
  const nodeId = (nodeParam ?? nodeIdParam ?? "").trim();
  if (!nodeId || nodeId.length > MAX_CREATOR_NODE_ID_LEN || /[\x00-\x1f\x7f]/.test(nodeId)) {
    return { ok: false, detail: "missing or invalid node in Ed25519 auth" };
  }

  const tsStr = params.get("ts");
  if (!tsStr || !/^-?\d+$/.test(tsStr)) {
    return { ok: false, detail: "missing or invalid ts in Ed25519 auth" };
  }
  const ts = Number(tsStr);
  if (!Number.isSafeInteger(ts)) {
    return { ok: false, detail: "out-of-range ts in Ed25519 auth" };
  }

  const nonce = params.get("nonce") ?? "";
  if (!nonce || nonce.length > MAX_NONCE_LEN || /[\x00-\x1f\x7f]/.test(nonce)) {
    return { ok: false, detail: "missing or invalid nonce in Ed25519 auth" };
  }

  const sigStr = params.get("sig") ?? "";
  if (!sigStr) {
    return { ok: false, detail: "missing sig in Ed25519 auth" };
  }
  const sigBytes = base64UrlDecodeStrict(sigStr);
  if (!sigBytes || sigBytes.length !== 64) {
    return { ok: false, detail: "invalid Ed25519 signature encoding" };
  }

  return { ok: true, nodeId, ts, nonce, sigBytes };
}

/**
 * Verifies a domain-separated Hyphae v2 Ed25519 signature over `"hyphae/v2/http-auth\n" || input`.
 *
 * @param {{
 *   pubKeyBytes: Uint8Array,
 *   method: string,
 *   pathAndQuery: string,
 *   ts: number,
 *   nonce: string,
 *   bodySha256Hex: string,
 *   sigBytes: Uint8Array
 * }} params
 * @returns {Promise<boolean>}
 */
export async function verifyEd25519HttpSignature({
  pubKeyBytes,
  method,
  pathAndQuery,
  ts,
  nonce,
  bodySha256Hex,
  sigBytes,
}) {
  if (!(pubKeyBytes instanceof Uint8Array) || pubKeyBytes.length !== 32) return false;
  if (isSmallOrderEd25519Point(pubKeyBytes) || isNonCanonicalEd25519Y(pubKeyBytes)) {
    return false;
  }
  if (!(sigBytes instanceof Uint8Array) || sigBytes.length !== 64) return false;
  const sigR = sigBytes.subarray(0, 32);
  if (isSmallOrderEd25519Point(sigR) || isNonCanonicalEd25519Y(sigR)) {
    return false;
  }

  let cryptoKey;
  try {
    cryptoKey = await crypto.subtle.importKey(
      "raw",
      pubKeyBytes,
      { name: "Ed25519" },
      false,
      ["verify"]
    );
  } catch {
    return false;
  }

  const signingInput = buildHttpAuthSigningInput(method, pathAndQuery, ts, nonce, bodySha256Hex);
  const domainMsg = concatBytes([HTTP_AUTH_DOMAIN_BYTES, signingInput]);
  try {
    return await crypto.subtle.verify({ name: "Ed25519" }, cryptoKey, sigBytes, domainMsg);
  } catch {
    return false;
  }
}

/**
 * Parses `env.ALLOWED_NODE_KEYS` into a `Map<nodeId, { bytes: Uint8Array, b64: string }>`.
 * Accepts:
 * - JSON map: `{"alice@macbook": "<43-char-b64url-pubkey>"}` (values may also be OKP JWKs)
 * - Pair list: `alice@macbook=<b64url>,bob@laptop=<b64url>` (comma or newline separated)
 * - Pre-parsed `Map` or plain `Object` (in unit tests)
 *
 * @param {string | Map<string, string | Uint8Array | object> | Record<string, string | Uint8Array | object> | undefined | null} raw
 * @returns {{ ok: true, keys: Map<string, { bytes: Uint8Array, b64: string }> } | { ok: false, detail: string }}
 */
export function parseAllowedNodeKeys(raw) {
  /** @type {Map<string, { bytes: Uint8Array, b64: string }>} */
  const keys = new Map();
  if (raw === undefined || raw === null) {
    return { ok: true, keys };
  }

  if (raw instanceof Map) {
    for (const [nodeId, keyVal] of raw.entries()) {
      const id = String(nodeId).trim();
      const parsed = parseEd25519PublicKey(keyVal);
      if (id && parsed) keys.set(id, parsed);
    }
    return { ok: true, keys };
  }

  if (typeof raw === "object" && !Array.isArray(raw)) {
    for (const [nodeId, keyVal] of Object.entries(raw)) {
      const id = nodeId.trim();
      const parsed = parseEd25519PublicKey(keyVal);
      if (id && parsed) keys.set(id, parsed);
    }
    return { ok: true, keys };
  }

  if (typeof raw !== "string") {
    return { ok: false, detail: "ALLOWED_NODE_KEYS has unsupported type" };
  }

  const trimmed = raw.trim();
  if (!trimmed) {
    return { ok: true, keys };
  }

  if (trimmed.startsWith("{")) {
    let parsedObj;
    try {
      parsedObj = JSON.parse(trimmed);
    } catch {
      return { ok: false, detail: "ALLOWED_NODE_KEYS is malformed JSON" };
    }
    if (!parsedObj || typeof parsedObj !== "object" || Array.isArray(parsedObj)) {
      return { ok: false, detail: "ALLOWED_NODE_KEYS JSON must be an object mapping nodeId -> pubkey" };
    }
    for (const [nodeId, keyVal] of Object.entries(parsedObj)) {
      const id = nodeId.trim();
      const parsed = parseEd25519PublicKey(keyVal);
      if (!id || !parsed) {
        return { ok: false, detail: "ALLOWED_NODE_KEYS contains an invalid Ed25519 public key" };
      }
      keys.set(id, parsed);
    }
    return { ok: true, keys };
  }

  // Pair list format: nodeId=b64url,nodeId2=b64url (or newline-separated)
  for (const entry of trimmed.split(/[,\n]+/)) {
    const part = entry.trim();
    if (!part) continue;
    const eq = part.indexOf("=");
    if (eq === -1) {
      return { ok: false, detail: "ALLOWED_NODE_KEYS pair entry is missing '='" };
    }
    const id = part.slice(0, eq).trim();
    const keyVal = part.slice(eq + 1).trim();
    const parsed = parseEd25519PublicKey(keyVal);
    if (!id || !parsed) {
      return { ok: false, detail: "ALLOWED_NODE_KEYS contains an invalid Ed25519 public key" };
    }
    keys.set(id, parsed);
  }
  return { ok: true, keys };
}

/**
 * Records `(nodeId, nonce)` in a bounded in-RAM replay cache; returns `false` on replay.
 * @param {Map<string, number>} nonceCache
 * @param {string} nodeId
 * @param {string} nonce
 * @param {number} ts
 * @param {number} nowMs
 * @returns {boolean}
 */
function checkAndRecordNonce(nonceCache, nodeId, nonce, ts, nowMs) {
  const key = `${nodeId}\0${nonce}`;
  const existingExp = nonceCache.get(key);
  if (existingExp !== undefined && existingExp >= nowMs) {
    return false;
  }
  if (nonceCache.size >= MAX_HTTP_AUTH_NONCES) {
    for (const [k, exp] of nonceCache.entries()) {
      if (exp < nowMs) nonceCache.delete(k);
    }
    if (nonceCache.size >= MAX_HTTP_AUTH_NONCES) {
      const evictCount = Math.max(1, Math.floor(MAX_HTTP_AUTH_NONCES / 8));
      let removed = 0;
      for (const k of nonceCache.keys()) {
        nonceCache.delete(k);
        removed += 1;
        if (removed >= evictCount) break;
      }
    }
  }
  nonceCache.set(key, ts + HTTP_AUTH_SKEW_MS);
  return true;
}

/**
 * Verifies an incoming `Hyphae-Ed25519` authenticated HTTP request in either
 * `"private"` (allowlist) or `"open"` (self-signed `X-Hyphae-Public-Key`) mode.
 *
 * @param {Request} request
 * @param {{
 *   mode?: "private" | "open",
 *   allowedNodeKeys?: string | Map<string, unknown> | Record<string, unknown> | null,
 *   bodyBytes?: Uint8Array,
 *   nowMs?: number,
 *   nonceCache?: Map<string, number> | null,
 *   allowDeferredOpenPubKey?: boolean
 * }} [options]
 * @returns {Promise<
 *   | { ok: true, nodeId: string, pubKeyB64: string, deferred: false }
 *   | { ok: true, nodeId: string, pubKeyB64: null, deferred: true, parsed: { nodeId: string, ts: number, nonce: string, sigBytes: Uint8Array }, bodySha256Hex: string }
 *   | { ok: false, problem: ProblemSpec }
 * >}
 */
export async function verifyHyphaeEd25519Request(request, options = {}) {
  const mode = options.mode ?? "private";
  const nowMs = options.nowMs ?? Date.now();
  const parsed = parseHyphaeEd25519Header(request.headers.get("Authorization"));
  if (!parsed.ok) {
    return { ok: false, problem: errUnauthorized(parsed.detail) };
  }

  if (Math.abs(nowMs - parsed.ts) > HTTP_AUTH_SKEW_MS) {
    return {
      ok: false,
      problem: errUnauthorized("Ed25519 auth timestamp outside allowed skew window"),
    };
  }

  const url = new URL(request.url);
  const pathAndQuery = `${url.pathname}${url.search}`;
  const method = request.method.toUpperCase();

  let bodyBytes = options.bodyBytes;
  if (bodyBytes === undefined) {
    if (method === "GET" || method === "HEAD" || method === "OPTIONS") {
      bodyBytes = EMPTY_BYTES;
    } else {
      bodyBytes = new Uint8Array(await request.clone().arrayBuffer());
    }
  }
  const bodySha256Hex = await sha256Hex(bodyBytes);

  /** @type {{ bytes: Uint8Array, b64: string } | null} */
  let pubKey = null;

  if (mode === "private") {
    const allowlist = parseAllowedNodeKeys(options.allowedNodeKeys);
    if (!allowlist.ok) {
      return { ok: false, problem: errInternal(allowlist.detail) };
    }
    const allowedKey = allowlist.keys.get(parsed.nodeId);
    if (!allowedKey) {
      return {
        ok: false,
        problem: errForbidden("node is not allowlisted on this private drop relay"),
      };
    }
    pubKey = allowedKey;
  } else if (mode === "open") {
    const rawPubHeader = request.headers.get(PUBLIC_KEY_HEADER);
    if (!rawPubHeader || !rawPubHeader.trim()) {
      if (options.allowDeferredOpenPubKey) {
        return {
          ok: true,
          nodeId: parsed.nodeId,
          pubKeyB64: null,
          deferred: true,
          parsed,
          bodySha256Hex,
        };
      }
      return {
        ok: false,
        problem: errUnauthorized(`missing ${PUBLIC_KEY_HEADER} header in open mode`),
      };
    }
    pubKey = parseEd25519PublicKey(rawPubHeader);
    if (!pubKey) {
      return {
        ok: false,
        problem: errUnauthorized(`invalid or small-order Ed25519 key in ${PUBLIC_KEY_HEADER}`),
      };
    }
  } else {
    return {
      ok: false,
      problem: errInternal("invalid DROP_AUTH_MODE configuration"),
    };
  }

  const valid = await verifyEd25519HttpSignature({
    pubKeyBytes: pubKey.bytes,
    method,
    pathAndQuery,
    ts: parsed.ts,
    nonce: parsed.nonce,
    bodySha256Hex,
    sigBytes: parsed.sigBytes,
  });
  if (!valid) {
    return { ok: false, problem: errUnauthorized("Ed25519 auth signature invalid") };
  }

  if (options.nonceCache) {
    const fresh = checkAndRecordNonce(
      options.nonceCache,
      parsed.nodeId,
      parsed.nonce,
      parsed.ts,
      nowMs
    );
    if (!fresh) {
      return { ok: false, problem: errUnauthorized("replayed request nonce") };
    }
  }

  return { ok: true, nodeId: parsed.nodeId, pubKeyB64: pubKey.b64, deferred: false };
}

// ============================================================================
// Strict CORS & Chrome PNA Helpers
// ============================================================================

/**
 * Parses explicit CORS origins (`env.ALLOWED_ORIGINS`), rejecting `"*"`, `"null"`,
 * non-http(s) schemes, and control characters.
 *
 * @param {string | string[] | undefined | null} raw
 * @returns {string[]}
 */
export function parseAllowedOrigins(raw) {
  const entries =
    raw === undefined || raw === null
      ? [DEFAULT_ALLOWED_ORIGIN]
      : Array.isArray(raw)
        ? raw
        : String(raw).split(",");

  /** @type {string[]} */
  const out = [];
  for (const item of entries) {
    const candidate = String(item).trim().replace(/\/+$/g, "");
    if (
      !candidate ||
      candidate === "*" ||
      candidate.toLowerCase() === "null" ||
      /[\x00-\x20\x7f]/.test(candidate) ||
      (!candidate.startsWith("https://") && !candidate.startsWith("http://"))
    ) {
      continue;
    }
    if (!out.includes(candidate)) {
      out.push(candidate);
    }
  }
  return out;
}

/**
 * Strict exact-match origin lookup. Never echoes `"*"` or `"null"`.
 * @param {string | null} reqOrigin
 * @param {string[]} allowedOrigins
 * @returns {string | null}
 */
function matchAllowedOrigin(reqOrigin, allowedOrigins) {
  if (!reqOrigin || typeof reqOrigin !== "string") return null;
  const trimmed = reqOrigin.trim();
  if (
    !trimmed ||
    trimmed === "*" ||
    trimmed.toLowerCase() === "null" ||
    /[\x00-\x20\x7f]/.test(trimmed)
  ) {
    return null;
  }
  return allowedOrigins.includes(trimmed) ? trimmed : null;
}

/**
 * Applies fail-closed CORS + optional Chrome PNA headers.
 * Always emits `Vary: Origin`.
 *
 * @param {Headers} headers
 * @param {string | null} reqOrigin
 * @param {string[]} allowedOrigins
 * @param {boolean} allowPrivateNetwork
 * @returns {boolean}
 */
function applyCorsHeaders(headers, reqOrigin, allowedOrigins, allowPrivateNetwork) {
  headers.set("Vary", "Origin");
  const matched = matchAllowedOrigin(reqOrigin, allowedOrigins);
  if (!matched) return false;
  headers.set("Access-Control-Allow-Origin", matched);
  if (allowPrivateNetwork) {
    headers.set("Access-Control-Allow-Private-Network", "true");
  }
  return true;
}

// ============================================================================
// Config, Rate Limiting, Bounded Body Read & SSE Formatting
// ============================================================================

/**
 * Parses a positive bounded integer env var with fallback.
 * @param {unknown} value
 * @param {number} fallback
 * @param {number} min
 * @param {number} max
 * @returns {number}
 */
function parseBoundedInt(value, fallback, min, max) {
  if (value === undefined || value === null || value === "") return fallback;
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  const intVal = Math.trunc(parsed);
  return Math.min(max, Math.max(min, intVal));
}

/**
 * Resolves validated worker configuration from `env`.
 * Defaults to fail-closed `"private"` mode.
 * @param {Record<string, unknown>} env
 */
function resolveConfig(env) {
  const rawMode =
    env && typeof env.DROP_AUTH_MODE === "string" && env.DROP_AUTH_MODE.trim()
      ? env.DROP_AUTH_MODE.trim().toLowerCase()
      : "private";
  const validMode = rawMode === "private" || rawMode === "open" ? rawMode : null;
  const maxTtlSeconds = parseBoundedInt(
    env?.MAX_TTL_SECONDS,
    HARD_MAX_TTL_SECONDS,
    1,
    HARD_MAX_TTL_SECONDS
  );
  const defaultTtlSeconds = parseBoundedInt(
    env?.DEFAULT_TTL_SECONDS,
    DEFAULT_TTL_SECONDS,
    1,
    maxTtlSeconds
  );
  const maxPayloadBytes = parseBoundedInt(
    env?.MAX_PAYLOAD_BYTES,
    DEFAULT_MAX_PAYLOAD_BYTES,
    1,
    10 * 1024 * 1024
  );
  const maxItemsPerDrop = parseBoundedInt(
    env?.MAX_ITEMS_PER_DROP,
    DEFAULT_MAX_ITEMS_PER_DROP,
    1,
    DEFAULT_MAX_ITEMS_PER_DROP
  );
  const maxSseStreamsPerDrop = parseBoundedInt(
    env?.MAX_SSE_STREAMS_PER_DROP,
    DEFAULT_MAX_SSE_STREAMS_PER_DROP,
    1,
    16
  );
  const createsPerHourPerNode = parseBoundedInt(
    env?.CREATES_PER_HOUR_PER_NODE,
    DEFAULT_CREATES_PER_HOUR_PER_NODE,
    0,
    10_000
  );
  const createsPerHourPerIp = parseBoundedInt(
    env?.CREATES_PER_HOUR_PER_IP,
    DEFAULT_CREATES_PER_HOUR_PER_IP,
    0,
    10_000
  );
  const allowedOrigins = parseAllowedOrigins(env?.ALLOWED_ORIGINS);
  const rawPna = env?.ALLOW_PRIVATE_NETWORK;
  const allowPrivateNetwork =
    rawPna === undefined || rawPna === null
      ? true
      : String(rawPna).trim().toLowerCase() !== "false";

  return {
    mode: validMode,
    maxTtlSeconds,
    defaultTtlSeconds,
    maxPayloadBytes,
    maxItemsPerDrop,
    maxSseStreamsPerDrop,
    createsPerHourPerNode,
    createsPerHourPerIp,
    allowedOrigins,
    allowPrivateNetwork,
  };
}

/**
 * Sliding-window hourly rate limiter (pure volatile RAM).
 */
class SlidingWindowLimiter {
  constructor() {
    /** @type {Map<string, number[]>} */
    this.windows = new Map();
  }

  /**
   * Checks whether `key` is within `limit` events per hour as of `nowMs` (without recording yet).
   * @param {string} key
   * @param {number} limit
   * @param {number} nowMs
   * @returns {{ ok: true } | { ok: false, retryAfterSeconds: number }}
   */
  check(key, limit, nowMs) {
    if (limit <= 0) {
      return { ok: false, retryAfterSeconds: 3600 };
    }
    const cutoff = nowMs - CREATE_RATE_WINDOW_MS;
    const list = this.windows.get(key);
    if (!list) return { ok: true };
    while (list.length > 0 && list[0] <= cutoff) {
      list.shift();
    }
    if (list.length === 0) {
      this.windows.delete(key);
      return { ok: true };
    }
    if (list.length >= limit) {
      const retryMs = list[0] + CREATE_RATE_WINDOW_MS - nowMs;
      return { ok: false, retryAfterSeconds: Math.max(1, Math.ceil(retryMs / 1000)) };
    }
    return { ok: true };
  }

  /**
   * Records a creation timestamp for `key` and bounds table cardinality.
   * @param {string} key
   * @param {number} nowMs
   */
  record(key, nowMs) {
    const cutoff = nowMs - CREATE_RATE_WINDOW_MS;
    if (this.windows.size > RATE_TABLE_PRUNE_THRESHOLD) {
      for (const [k, arr] of this.windows.entries()) {
        while (arr.length > 0 && arr[0] <= cutoff) arr.shift();
        if (arr.length === 0) this.windows.delete(k);
      }
    }
    let list = this.windows.get(key);
    if (!list) {
      list = [];
      this.windows.set(key, list);
    }
    list.push(nowMs);
  }
}

/**
 * Reads an HTTP request body with a hard byte ceiling (`maxBytes`).
 * Checks `Content-Length` BEFORE touching `request.body`, and enforces a streaming cap.
 *
 * @param {Request} request
 * @param {number} maxBytes
 * @returns {Promise<{ ok: true, bytes: Uint8Array } | { ok: false, problem: ProblemSpec }>}
 */
async function readBoundedBody(request, maxBytes) {
  const clHeader = request.headers.get("Content-Length");
  if (clHeader !== null && clHeader.trim() !== "") {
    if (!/^\d+$/.test(clHeader.trim())) {
      return { ok: false, problem: errBadRequest("invalid Content-Length header") };
    }
    const declared = Number(clHeader.trim());
    if (!Number.isSafeInteger(declared) || declared > maxBytes) {
      return { ok: false, problem: errPayloadTooLarge(declared, maxBytes) };
    }
  }

  if (!request.body) {
    return { ok: true, bytes: new Uint8Array(0) };
  }

  const reader = request.body.getReader();
  /** @type {Uint8Array[]} */
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value || value.byteLength === 0) continue;
      const nextTotal = total + value.byteLength;
      if (nextTotal > maxBytes) {
        for (const c of chunks) c.fill(0);
        chunks.length = 0;
        await reader.cancel().catch(() => {});
        return { ok: false, problem: errPayloadTooLarge(nextTotal, maxBytes) };
      }
      chunks.push(value);
      total = nextTotal;
    }
  } finally {
    try {
      reader.releaseLock();
    } catch {
      // Ignore already released lock.
    }
  }

  if (total === 0) {
    return { ok: true, bytes: new Uint8Array(0) };
  }
  const combined = concatBytes(chunks);
  for (const c of chunks) c.fill(0);
  return { ok: true, bytes: combined };
}

/**
 * Formats a buffered drop item into a WHATWG SSE event frame matching `DropItem::to_sse_event`.
 * Valid UTF-8 without NUL bytes is emitted directly; arbitrary binary falls back to base64url.
 *
 * @param {{ seq: number, payload: Uint8Array }} item
 * @returns {string}
 */
function formatSseDropEvent(item) {
  let data;
  try {
    const decoded = UTF8_DECODER_FATAL.decode(item.payload);
    data = decoded.includes("\0") ? base64UrlEncode(item.payload) : decoded;
  } catch {
    data = base64UrlEncode(item.payload);
  }

  let out = `id: ${item.seq}\nevent: drop\n`;
  if (data.length === 0) {
    out += "data:\n\n";
    return out;
  }
  const lines = data.split("\n");
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i].endsWith("\r") ? lines[i].slice(0, -1) : lines[i];
    out += `data: ${line}\n`;
  }
  out += "\n";
  return out;
}

/**
 * Safely decodes a URL path segment; returns `null` on malformed percent-encoding.
 * @param {string} raw
 * @returns {string | null}
 */
function safeDecodeSegment(raw) {
  try {
    return decodeURIComponent(raw);
  } catch {
    return null;
  }
}

/**
 * Extracts normalized client IP for volatile in-RAM sliding-window rate limiting only.
 * Never logged or persisted.
 * @param {Request} request
 * @returns {string}
 */
function extractClientIp(request) {
  const cfIp = request.headers.get("CF-Connecting-IP");
  if (cfIp && cfIp.trim()) return cfIp.trim();
  const realIp = request.headers.get("X-Real-IP");
  if (realIp && realIp.trim()) return realIp.trim();
  return "unknown";
}

// ============================================================================
// RAM-Only Durable Object (`DropSlotDO`) — ZERO Persistent Storage Calls!
// ============================================================================

/**
 * RAM-only Durable Object storing one ephemeral blind drop slot.
 *
 * Strictly volatile: NEVER reads or writes Durable Object persistent storage.
 * Every buffered ciphertext `Uint8Array` is zeroized via `.fill(0)` on burn,
 * TTL expiry, or slot close.
 */
export class DropSlotDO {
  /**
   * @param {unknown} ctx
   * @param {Record<string, unknown>} env
   * @param {{ now?: () => number, keepaliveMs?: number }} [options]
   */
  constructor(ctx, env, options = {}) {
    this.ctx = ctx;
    this.env = env;
    this._now = options.now ?? (() => Date.now());
    this._keepaliveMs = options.keepaliveMs ?? DROP_SSE_KEEPALIVE_MS;

    /**
     * Volatile in-RAM drop slot state (null when uninitialized, expired, or burned closed).
     * @type {{
     *   dropId: string,
     *   creatorNodeId: string,
     *   creatorPubKeyB64: string,
     *   expiresAtMs: number,
     *   maxItems: number,
     *   maxPayloadBytes: number,
     *   maxSseStreamsPerDrop: number,
     *   burnAfterRead: boolean,
     *   nextSeq: number,
     *   highestAckedSeq: number,
     *   bufferedBytes: number,
     *   items: Array<{ seq: number, payload: Uint8Array, receivedAtMs: number }>
     * } | null}
     */
    this.slot = null;

    /** @type {boolean} */
    this.expired = false;

    /**
     * Active SSE subscriber handles.
     * @type {Set<{
     *   writer: WritableStreamDefaultWriter<Uint8Array>,
     *   lastSentSeq: number,
     *   queue: Promise<void>,
     *   keepaliveTimer: ReturnType<typeof setInterval> | null,
     *   closed: boolean
     * }>}
     */
    this.subscribers = new Set();

    /** @type {ReturnType<typeof setTimeout> | null} */
    this.expiryTimer = null;

    /** @type {Map<string, number>} */
    this._deferredNonceCache = new Map();
  }

  /**
   * Zeroizes every buffered ciphertext buffer in RAM and clears slot references.
   * @param {{ markExpired: boolean }} opts
   */
  _destroySlot({ markExpired }) {
    if (this.expiryTimer !== null) {
      clearTimeout(this.expiryTimer);
      this.expiryTimer = null;
    }
    if (this.slot) {
      for (const item of this.slot.items) {
        item.payload.fill(0);
      }
      this.slot.items.length = 0;
      this.slot.bufferedBytes = 0;
      this.slot = null;
    }
    if (markExpired) {
      this.expired = true;
    }
    // Close all active SSE streams cleanly after flushing pending writes.
    for (const sub of Array.from(this.subscribers)) {
      this._closeSubscriber(sub);
    }
  }

  /**
   * Schedules an in-RAM TTL sweep timer (no persistent DO alarm!).
   * @param {number} expiresAtMs
   */
  _armExpiryTimer(expiresAtMs) {
    if (this.expiryTimer !== null) {
      clearTimeout(this.expiryTimer);
      this.expiryTimer = null;
    }
    const remaining = Math.max(1, Math.min(MAX_TIMEOUT_MS, expiresAtMs - this._now()));
    this.expiryTimer = setTimeout(() => {
      this.expiryTimer = null;
      if (this.slot && this._now() >= this.slot.expiresAtMs) {
        this._destroySlot({ markExpired: true });
      } else if (this.slot) {
        this._armExpiryTimer(this.slot.expiresAtMs);
      }
    }, remaining);
    if (typeof this.expiryTimer?.unref === "function") {
      this.expiryTimer.unref();
    }
  }

  /**
   * Checks whether `this.slot` is currently live; sweeps and zeroizes if expired.
   * @returns {{ ok: true, slot: NonNullable<DropSlotDO["slot"]> } | { ok: false, problem: ProblemSpec }}
   */
  _requireActiveSlot() {
    if (!this.slot) {
      return { ok: false, problem: this.expired ? errExpired() : errNotFound() };
    }
    if (this._now() >= this.slot.expiresAtMs) {
      this._destroySlot({ markExpired: true });
      return { ok: false, problem: errExpired() };
    }
    return { ok: true, slot: this.slot };
  }

  /**
   * Enqueues an SSE text frame onto a subscriber's ordered writer chain.
   * @param {{
   *   writer: WritableStreamDefaultWriter<Uint8Array>,
   *   lastSentSeq: number,
   *   queue: Promise<void>,
   *   keepaliveTimer: ReturnType<typeof setInterval> | null,
   *   closed: boolean
   * }} sub
   * @param {string} text
   * @param {number | null} [seq]
   */
  _enqueueWrite(sub, text, seq = null) {
    if (sub.closed) return;
    if (seq !== null) {
      if (seq <= sub.lastSentSeq) return;
      sub.lastSentSeq = seq;
    }
    const bytes = TEXT_ENCODER.encode(text);
    sub.queue = sub.queue
      .then(() => {
        if (sub.closed) return;
        return sub.writer.write(bytes);
      })
      .catch(() => {
        this._removeSubscriber(sub);
      });
  }

  /**
   * Removes a disconnected subscriber and clears its keepalive timer.
   * @param {{
   *   writer: WritableStreamDefaultWriter<Uint8Array>,
   *   lastSentSeq: number,
   *   queue: Promise<void>,
   *   keepaliveTimer: ReturnType<typeof setInterval> | null,
   *   closed: boolean
   * }} sub
   */
  _removeSubscriber(sub) {
    if (sub.closed) return;
    sub.closed = true;
    if (sub.keepaliveTimer !== null) {
      clearInterval(sub.keepaliveTimer);
      sub.keepaliveTimer = null;
    }
    this.subscribers.delete(sub);
  }

  /**
   * Gracefully flushes pending frames and closes an SSE subscriber stream.
   * @param {{
   *   writer: WritableStreamDefaultWriter<Uint8Array>,
   *   lastSentSeq: number,
   *   queue: Promise<void>,
   *   keepaliveTimer: ReturnType<typeof setInterval> | null,
   *   closed: boolean
   * }} sub
   */
  _closeSubscriber(sub) {
    if (sub.closed) return;
    sub.closed = true;
    if (sub.keepaliveTimer !== null) {
      clearInterval(sub.keepaliveTimer);
      sub.keepaliveTimer = null;
    }
    this.subscribers.delete(sub);
    sub.queue
      .then(() => sub.writer.close())
      .catch(() => {});
  }

  /**
   * Verifies caller authorization on `/stream` and `/ack` inside the DO.
   * @param {Request} request
   * @param {NonNullable<DropSlotDO["slot"]>} slot
   * @returns {Promise<{ ok: true } | { ok: false, problem: ProblemSpec }>}
   */
  async _authorizeSubscriberOrCreator(request, slot) {
    const authMode = request.headers.get("X-Drop-Auth");
    if (authMode === "subcap") {
      return { ok: true };
    }
    if (authMode === "creator") {
      const callerNode = (request.headers.get("X-Drop-Creator-Node") ?? "").trim();
      const callerPub = (request.headers.get("X-Drop-Creator-PubKey") ?? "").trim();
      if (!callerNode || callerNode !== slot.creatorNodeId) {
        return {
          ok: false,
          problem: errUnauthorized("caller node is not the creator of this drop"),
        };
      }
      if (!callerPub || callerPub !== slot.creatorPubKeyB64) {
        return {
          ok: false,
          problem: errUnauthorized("caller public key does not match drop creator"),
        };
      }
      return { ok: true };
    }
    if (authMode === "creator-deferred") {
      const origAuth = request.headers.get("X-Drop-Orig-Auth");
      const origMethod = request.headers.get("X-Drop-Orig-Method") ?? "";
      const origPathAndQuery = request.headers.get("X-Drop-Orig-Path") ?? "";
      const origBodySha = request.headers.get("X-Drop-Orig-Body-Sha256") ?? "";
      const parsed = parseHyphaeEd25519Header(origAuth);
      if (!parsed.ok) {
        return { ok: false, problem: errUnauthorized(parsed.detail) };
      }
      const nowMs = this._now();
      if (Math.abs(nowMs - parsed.ts) > HTTP_AUTH_SKEW_MS) {
        return {
          ok: false,
          problem: errUnauthorized("Ed25519 auth timestamp outside allowed skew window"),
        };
      }
      if (parsed.nodeId !== slot.creatorNodeId) {
        return {
          ok: false,
          problem: errUnauthorized("caller node is not the creator of this drop"),
        };
      }
      const pinnedKey = parseEd25519PublicKey(slot.creatorPubKeyB64);
      if (!pinnedKey) {
        return { ok: false, problem: errInternal("corrupted slot creator public key") };
      }
      const sigOk = await verifyEd25519HttpSignature({
        pubKeyBytes: pinnedKey.bytes,
        method: origMethod,
        pathAndQuery: origPathAndQuery,
        ts: parsed.ts,
        nonce: parsed.nonce,
        bodySha256Hex: origBodySha,
        sigBytes: parsed.sigBytes,
      });
      if (!sigOk) {
        return { ok: false, problem: errUnauthorized("Ed25519 auth signature invalid") };
      }
      const fresh = checkAndRecordNonce(
        this._deferredNonceCache,
        parsed.nodeId,
        parsed.nonce,
        parsed.ts,
        nowMs
      );
      if (!fresh) {
        return { ok: false, problem: errUnauthorized("replayed request nonce") };
      }
      return { ok: true };
    }
    return { ok: false, problem: errUnauthorized("missing drop subscriber authentication") };
  }

  /**
   * Internal Durable Object fetch handler.
   * @param {Request} request
   * @returns {Promise<Response>}
   */
  async fetch(request) {
    const url = new URL(request.url);
    const method = request.method.toUpperCase();

    // POST /init — initialize slot in volatile RAM
    if (method === "POST" && url.pathname === "/init") {
      let initData;
      try {
        initData = await request.json();
      } catch {
        return problemResponse(errBadRequest("invalid slot init payload"));
      }
      if (
        !initData ||
        !isValidDropId(initData.dropId) ||
        typeof initData.creatorNodeId !== "string" ||
        !initData.creatorNodeId.trim() ||
        typeof initData.creatorPubKeyB64 !== "string" ||
        !initData.creatorPubKeyB64.trim() ||
        typeof initData.expiresAtMs !== "number" ||
        !Number.isSafeInteger(initData.expiresAtMs)
      ) {
        return problemResponse(errBadRequest("missing required slot init fields"));
      }

      // Zeroize any prior slot state before initializing.
      this._destroySlot({ markExpired: false });
      this.expired = false;

      const maxItems = parseBoundedInt(
        initData.maxItems,
        DEFAULT_MAX_ITEMS_PER_DROP,
        1,
        DEFAULT_MAX_ITEMS_PER_DROP
      );
      const maxPayloadBytes = parseBoundedInt(
        initData.maxPayloadBytes,
        DEFAULT_MAX_PAYLOAD_BYTES,
        1,
        10 * 1024 * 1024
      );
      const maxSseStreamsPerDrop = parseBoundedInt(
        initData.maxSseStreamsPerDrop,
        DEFAULT_MAX_SSE_STREAMS_PER_DROP,
        1,
        16
      );

      this.slot = {
        dropId: initData.dropId,
        creatorNodeId: initData.creatorNodeId.trim(),
        creatorPubKeyB64: initData.creatorPubKeyB64.trim(),
        expiresAtMs: initData.expiresAtMs,
        maxItems,
        maxPayloadBytes,
        maxSseStreamsPerDrop,
        burnAfterRead: Boolean(initData.burnAfterRead),
        nextSeq: 1,
        highestAckedSeq: 0,
        bufferedBytes: 0,
        items: [],
      };
      this._armExpiryTimer(this.slot.expiresAtMs);
      return jsonResponse(201, { ok: true, expiresAtMs: this.slot.expiresAtMs });
    }

    // POST /post — append opaque ciphertext bytes into RAM FIFO and wake SSE streams
    if (method === "POST" && url.pathname === "/post") {
      const active = this._requireActiveSlot();
      if (!active.ok) return problemResponse(active.problem);
      const slot = active.slot;

      if (slot.nextSeq > slot.maxItems || slot.items.length >= slot.maxItems) {
        return problemResponse(errDropFull(slot.maxItems));
      }

      const bodyRes = await readBoundedBody(request, slot.maxPayloadBytes);
      if (!bodyRes.ok) return problemResponse(bodyRes.problem);
      const payload = bodyRes.bytes;

      if (payload.byteLength === 0) {
        return problemResponse(errBadRequest("drop payload must not be empty"));
      }

      // Re-check slot state after async body read in case TTL elapsed or slot filled concurrently.
      const recheck = this._requireActiveSlot();
      if (!recheck.ok) {
        payload.fill(0);
        return problemResponse(recheck.problem);
      }
      if (slot.nextSeq > slot.maxItems || slot.items.length >= slot.maxItems) {
        payload.fill(0);
        return problemResponse(errDropFull(slot.maxItems));
      }

      const seq = slot.nextSeq;
      slot.nextSeq += 1;
      const item = {
        seq,
        payload,
        receivedAtMs: this._now(),
      };
      slot.items.push(item);
      slot.bufferedBytes += payload.byteLength;

      const sseFrame = formatSseDropEvent(item);
      for (const sub of this.subscribers) {
        this._enqueueWrite(sub, sseFrame, seq);
      }

      return jsonResponse(201, {
        seq,
        expiresAtMs: slot.expiresAtMs,
      });
    }

    // GET /stream — atomic late-subscriber catch-up + live SSE stream with 25s keepalives
    if (method === "GET" && url.pathname === "/stream") {
      const active = this._requireActiveSlot();
      if (!active.ok) return problemResponse(active.problem);
      const slot = active.slot;

      const authRes = await this._authorizeSubscriberOrCreator(request, slot);
      if (!authRes.ok) return problemResponse(authRes.problem);

      // Re-check expiry after any async Ed25519 verification.
      const recheck = this._requireActiveSlot();
      if (!recheck.ok) return problemResponse(recheck.problem);

      const rawAfter = url.searchParams.get("after");
      let afterSeq = 0;
      if (rawAfter !== null && rawAfter.trim() !== "") {
        if (!/^\d+$/.test(rawAfter.trim())) {
          return problemResponse(errBadRequest(`invalid Last-Event-ID cursor '${rawAfter}'`));
        }
        afterSeq = Number(rawAfter.trim());
        if (!Number.isSafeInteger(afterSeq)) {
          return problemResponse(errBadRequest(`invalid Last-Event-ID cursor '${rawAfter}'`));
        }
      }

      if (this.subscribers.size >= slot.maxSseStreamsPerDrop) {
        return problemResponse(
          errRateLimited(
            `per-drop SSE stream limit (${slot.maxSseStreamsPerDrop}) reached`,
            5
          )
        );
      }

      const { readable, writable } = new TransformStream();
      const writer = writable.getWriter();

      const subscriber = {
        writer,
        lastSentSeq: afterSeq,
        queue: Promise.resolve(),
        keepaliveTimer: null,
        closed: false,
      };

      // Register synchronously BEFORE enqueuing backlog so zero live posts can slip through.
      this.subscribers.add(subscriber);
      this._enqueueWrite(subscriber, ": connected\n\n");

      for (const item of slot.items) {
        if (item.seq > afterSeq) {
          this._enqueueWrite(subscriber, formatSseDropEvent(item), item.seq);
        }
      }

      subscriber.keepaliveTimer = setInterval(() => {
        if (subscriber.closed) return;
        if (!this.slot || this._now() >= this.slot.expiresAtMs) {
          this._destroySlot({ markExpired: true });
          return;
        }
        this._enqueueWrite(subscriber, ": keepalive\n\n");
      }, this._keepaliveMs);
      if (typeof subscriber.keepaliveTimer?.unref === "function") {
        subscriber.keepaliveTimer.unref();
      }

      writer.closed.then(
        () => this._removeSubscriber(subscriber),
        () => this._removeSubscriber(subscriber)
      );

      return new Response(readable, {
        status: 200,
        headers: {
          "Content-Type": "text/event-stream; charset=utf-8",
          "Cache-Control": "no-store",
          "X-Accel-Buffering": "no",
        },
      });
    }

    // POST /ack — acknowledge & optionally burn/zeroize items up to `seq`
    if (method === "POST" && url.pathname === "/ack") {
      const active = this._requireActiveSlot();
      if (!active.ok) return problemResponse(active.problem);
      const slot = active.slot;

      const authRes = await this._authorizeSubscriberOrCreator(request, slot);
      if (!authRes.ok) return problemResponse(authRes.problem);

      const recheck = this._requireActiveSlot();
      if (!recheck.ok) return problemResponse(recheck.problem);

      let ackBody;
      try {
        ackBody = await request.json();
      } catch {
        return problemResponse(errBadRequest("invalid JSON in ack request"));
      }
      if (
        !ackBody ||
        typeof ackBody !== "object" ||
        typeof ackBody.seq !== "number" ||
        !Number.isSafeInteger(ackBody.seq) ||
        ackBody.seq < 0
      ) {
        return problemResponse(errBadRequest("ack request requires non-negative integer 'seq'"));
      }
      if (ackBody.burn !== undefined && typeof ackBody.burn !== "boolean") {
        return problemResponse(errBadRequest("ack 'burn' must be a boolean"));
      }

      const seq = ackBody.seq;
      const burn = Boolean(ackBody.burn);
      const maxPostedSeq = Math.max(0, slot.nextSeq - 1);
      const effectiveSeq = Math.min(seq, maxPostedSeq);
      if (effectiveSeq > slot.highestAckedSeq) {
        slot.highestAckedSeq = effectiveSeq;
      }

      let burnedItems = 0;
      let burnedBytes = 0;
      if (burn && seq > 0) {
        while (slot.items.length > 0 && slot.items[0].seq <= seq) {
          const removed = slot.items.shift();
          if (removed) {
            const len = removed.payload.byteLength;
            removed.payload.fill(0);
            burnedItems += 1;
            burnedBytes += len;
            slot.bufferedBytes = Math.max(0, slot.bufferedBytes - len);
          }
        }
      }

      const remainingItems = slot.items.length;
      const shouldClose =
        burn && slot.burnAfterRead && remainingItems === 0 && effectiveSeq > 0;
      if (shouldClose) {
        this._destroySlot({ markExpired: false });
      }

      return jsonResponse(200, {
        ackedSeq: effectiveSeq,
        burnedItems,
        burnedBytes,
        remainingItems,
        slotClosed: shouldClose,
      });
    }

    return problemResponse(errNotFound("unknown internal drop slot route"));
  }
}

// ============================================================================
// Cloudflare Worker Entrypoint Factory (`createWorkerApp` & `default`)
// ============================================================================

/**
 * Creates a self-contained Cloudflare Worker app with isolated in-RAM rate limiters,
 * replay cache, and optional injectable clock (for deterministic testing).
 *
 * @param {{ now?: () => number }} [options]
 * @returns {{ fetch(request: Request, env: Record<string, unknown>, ctx?: unknown): Promise<Response> }}
 */
export function createWorkerApp(options = {}) {
  const getNow = options.now ?? (() => Date.now());
  const creatorLimiter = new SlidingWindowLimiter();
  const ipLimiter = new SlidingWindowLimiter();
  /** @type {Map<string, number>} */
  const nonceCache = new Map();

  return {
    /**
     * Cloudflare Workers HTTP entrypoint.
     * @param {Request} request
     * @param {Record<string, unknown>} env
     * @param {unknown} [_ctx]
     * @returns {Promise<Response>}
     */
    async fetch(request, env, _ctx) {
      const cfg = resolveConfig(env ?? {});
      if (!cfg.mode) {
        return problemResponse(
          errInternal("invalid DROP_AUTH_MODE (expected 'private' or 'open')")
        );
      }

      const url = new URL(request.url);
      const path = url.pathname;
      const method = request.method.toUpperCase();
      const reqOrigin = request.headers.get("Origin");
      const nowMs = getNow();

      // ------------------------------------------------------------------
      // GET /v1/health — aggregate-only status (ZERO drop IDs / IPs / keys)
      // ------------------------------------------------------------------
      if (path === "/v1/health") {
        if (method !== "GET") {
          return problemResponse(
            {
              status: 405,
              error: "drop_method_not_allowed",
              slug: "drop-method-not-allowed",
              title: "Method Not Allowed",
              detail: "GET is required for /v1/health",
            },
            { Allow: "GET" }
          );
        }
        return jsonResponse(200, {
          ok: true,
          runtime: "cloudflare-workers",
          mode: cfg.mode,
          dropRelay: {
            enabled: true,
            maxPayloadBytes: cfg.maxPayloadBytes,
            maxTtlSeconds: cfg.maxTtlSeconds,
            allowedOriginsCount: cfg.allowedOrigins.length,
          },
        });
      }

      if (path !== "/v1/drops" && !path.startsWith("/v1/drops/")) {
        return problemResponse(errNotFound(`route '${method} ${path}' not found`));
      }

      // ------------------------------------------------------------------
      // OPTIONS /v1/drops & OPTIONS /v1/drops/* — strict CORS + Chrome PNA
      // ------------------------------------------------------------------
      if (method === "OPTIONS") {
        const headers = new Headers({
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, X-Hyphae-Drop-Cap, Last-Event-ID",
          "Access-Control-Max-Age": "600",
        });
        applyCorsHeaders(headers, reqOrigin, cfg.allowedOrigins, cfg.allowPrivateNetwork);
        return new Response(null, { status: 204, headers });
      }

      // Fail closed if HMAC secret or Durable Object binding is missing/invalid.
      const hmacKey = parseHmacKeyMaterial(env?.DROP_CAP_HMAC_KEY);
      if (!hmacKey) {
        const corsHeaders = new Headers();
        if (path.startsWith("/v1/drops/") && !path.endsWith("/stream") && !path.endsWith("/ack")) {
          applyCorsHeaders(corsHeaders, reqOrigin, cfg.allowedOrigins, cfg.allowPrivateNetwork);
        }
        return problemResponse(
          errInternal("DROP_CAP_HMAC_KEY is not configured or shorter than 32 bytes"),
          corsHeaders
        );
      }
      const prevHmacKey = parseHmacKeyMaterial(env?.DROP_CAP_HMAC_KEY_PREV);

      const dropSlotNs = env?.DROP_SLOT;
      if (!dropSlotNs || typeof dropSlotNs.idFromName !== "function") {
        return problemResponse(errInternal("DROP_SLOT Durable Object binding is not configured"));
      }

      // ------------------------------------------------------------------
      // POST /v1/drops — authenticated slot allocation
      // ------------------------------------------------------------------
      if (path === "/v1/drops") {
        if (method !== "POST") {
          return problemResponse(
            {
              status: 405,
              error: "drop_method_not_allowed",
              slug: "drop-method-not-allowed",
              title: "Method Not Allowed",
              detail: "POST is required for /v1/drops",
            },
            { Allow: "POST, OPTIONS" }
          );
        }

        const bodyRes = await readBoundedBody(request, MAX_CONTROL_BODY_BYTES);
        if (!bodyRes.ok) return problemResponse(bodyRes.problem);
        const bodyBytes = bodyRes.bytes;

        const authRes = await verifyHyphaeEd25519Request(request, {
          mode: cfg.mode,
          allowedNodeKeys: env?.ALLOWED_NODE_KEYS,
          bodyBytes,
          nowMs,
          nonceCache,
        });
        if (!authRes.ok) {
          return problemResponse(authRes.problem);
        }

        /** @type {{ ttlSeconds?: unknown, maxItems?: unknown, targetNodeId?: unknown, burnAfterRead?: unknown }} */
        let createReq = {};
        if (bodyBytes.byteLength > 0) {
          try {
            const parsedJson = JSON.parse(UTF8_DECODER_FATAL.decode(bodyBytes));
            if (!parsedJson || typeof parsedJson !== "object" || Array.isArray(parsedJson)) {
              return problemResponse(errBadRequest("request body must be a JSON object"));
            }
            createReq = parsedJson;
          } catch {
            return problemResponse(errBadRequest("invalid JSON in POST /v1/drops body"));
          }
        }

        // Validate & clamp ttlSeconds (1..=maxTtlSeconds, default defaultTtlSeconds)
        let ttlSeconds = cfg.defaultTtlSeconds;
        if (createReq.ttlSeconds !== undefined && createReq.ttlSeconds !== null) {
          if (
            typeof createReq.ttlSeconds !== "number" ||
            !Number.isFinite(createReq.ttlSeconds) ||
            createReq.ttlSeconds < 0
          ) {
            return problemResponse(errBadRequest("ttlSeconds must be a non-negative number"));
          }
          ttlSeconds = Math.min(cfg.maxTtlSeconds, Math.max(1, Math.trunc(createReq.ttlSeconds)));
        }

        // Validate & clamp maxItems (1..=maxItemsPerDrop)
        let maxItems = cfg.maxItemsPerDrop;
        if (createReq.maxItems !== undefined && createReq.maxItems !== null) {
          if (
            typeof createReq.maxItems !== "number" ||
            !Number.isFinite(createReq.maxItems) ||
            createReq.maxItems < 0
          ) {
            return problemResponse(errBadRequest("maxItems must be a non-negative number"));
          }
          maxItems = Math.min(cfg.maxItemsPerDrop, Math.max(1, Math.trunc(createReq.maxItems)));
        }

        if (
          createReq.burnAfterRead !== undefined &&
          typeof createReq.burnAfterRead !== "boolean"
        ) {
          return problemResponse(errBadRequest("burnAfterRead must be a boolean"));
        }
        const burnAfterRead = Boolean(createReq.burnAfterRead);

        // Enforce per-creator (pubkey in open mode, nodeId in private mode) & per-IP rate limits.
        const creatorRateKey =
          cfg.mode === "open" ? `pk:${authRes.pubKeyB64}` : `node:${authRes.nodeId}`;
        const creatorQuota = creatorLimiter.check(creatorRateKey, cfg.createsPerHourPerNode, nowMs);
        if (!creatorQuota.ok) {
          return problemResponse(
            errRateLimited(
              `per-creator hourly drop creation limit (${cfg.createsPerHourPerNode}/hr) exceeded`,
              creatorQuota.retryAfterSeconds
            )
          );
        }

        const clientIp = extractClientIp(request);
        const ipQuota = ipLimiter.check(clientIp, cfg.createsPerHourPerIp, nowMs);
        if (!ipQuota.ok) {
          return problemResponse(
            errRateLimited(
              `per-IP hourly drop creation limit (${cfg.createsPerHourPerIp}/hr) exceeded`,
              ipQuota.retryAfterSeconds
            )
          );
        }

        const dropId = generateDropId();
        const expiresAtMs = nowMs + ttlSeconds * 1000;
        const postCap = await createCapability({
          dropId,
          role: DROP_CAP_ROLE_POST,
          expiresAtMs,
          hmacKey,
        });
        const subCap = await createCapability({
          dropId,
          role: DROP_CAP_ROLE_SUB,
          expiresAtMs,
          hmacKey,
        });

        const stub = dropSlotNs.get(dropSlotNs.idFromName(dropId));
        const initResp = await stub.fetch("https://drop-slot.internal/init", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            dropId,
            creatorNodeId: authRes.nodeId,
            creatorPubKeyB64: authRes.pubKeyB64,
            expiresAtMs,
            maxItems,
            maxPayloadBytes: cfg.maxPayloadBytes,
            maxSseStreamsPerDrop: cfg.maxSseStreamsPerDrop,
            burnAfterRead,
          }),
        });
        if (!initResp.ok) {
          return initResp;
        }

        creatorLimiter.record(creatorRateKey, nowMs);
        ipLimiter.record(clientIp, nowMs);

        return jsonResponse(201, {
          dropId,
          expiresAtMs,
          postCap,
          subCap,
          maxPayloadBytes: cfg.maxPayloadBytes,
          maxItems,
        });
      }

      const rest = path.slice("/v1/drops/".length);

      // ------------------------------------------------------------------
      // GET /v1/drops/{id}/stream — SSE catch-up & live push
      // ------------------------------------------------------------------
      if (rest.endsWith("/stream")) {
        const rawId = rest.slice(0, -"/stream".length);
        if (!rawId || rawId.includes("/")) {
          return problemResponse(errNotFound(`route '${method} ${path}' not found`));
        }
        if (method !== "GET") {
          return problemResponse(
            {
              status: 405,
              error: "drop_method_not_allowed",
              slug: "drop-method-not-allowed",
              title: "Method Not Allowed",
              detail: "GET is required for /v1/drops/{id}/stream",
            },
            { Allow: "GET, OPTIONS" }
          );
        }

        const dropId = safeDecodeSegment(rawId);
        if (!dropId || !isValidDropId(dropId)) {
          return problemResponse(errUnauthorized("invalid drop_id format"));
        }

        const rawCursor =
          request.headers.get("Last-Event-ID")?.trim() ||
          url.searchParams.get("after")?.trim() ||
          "";
        if (rawCursor && (!/^\d+$/.test(rawCursor) || !Number.isSafeInteger(Number(rawCursor)))) {
          return problemResponse(errBadRequest(`invalid Last-Event-ID cursor '${rawCursor}'`));
        }

        const forwardHeaders = new Headers();
        const capHeader = request.headers.get(DROP_CAP_HEADER)?.trim() || "";
        if (capHeader) {
          const capRes = await verifyCapability({
            dropId,
            token: capHeader,
            expectedRole: DROP_CAP_ROLE_SUB,
            hmacKey,
            prevHmacKey,
            nowMs,
          });
          if (!capRes.ok) return problemResponse(capRes.problem);
          forwardHeaders.set("X-Drop-Auth", "subcap");
        } else {
          const authRes = await verifyHyphaeEd25519Request(request, {
            mode: cfg.mode,
            allowedNodeKeys: env?.ALLOWED_NODE_KEYS,
            bodyBytes: EMPTY_BYTES,
            nowMs,
            nonceCache,
            allowDeferredOpenPubKey: true,
          });
          if (!authRes.ok) return problemResponse(authRes.problem);

          if (authRes.deferred) {
            forwardHeaders.set("X-Drop-Auth", "creator-deferred");
            forwardHeaders.set("X-Drop-Orig-Auth", request.headers.get("Authorization") ?? "");
            forwardHeaders.set("X-Drop-Orig-Method", "GET");
            forwardHeaders.set("X-Drop-Orig-Path", `${url.pathname}${url.search}`);
            forwardHeaders.set("X-Drop-Orig-Body-Sha256", authRes.bodySha256Hex);
          } else {
            forwardHeaders.set("X-Drop-Auth", "creator");
            forwardHeaders.set("X-Drop-Creator-Node", authRes.nodeId);
            forwardHeaders.set("X-Drop-Creator-PubKey", authRes.pubKeyB64);
          }
        }

        const stub = dropSlotNs.get(dropSlotNs.idFromName(dropId));
        const doUrl = rawCursor
          ? `https://drop-slot.internal/stream?after=${encodeURIComponent(rawCursor)}`
          : "https://drop-slot.internal/stream";
        return stub.fetch(doUrl, { method: "GET", headers: forwardHeaders });
      }

      // ------------------------------------------------------------------
      // POST /v1/drops/{id}/ack — acknowledge & burn/zeroize RAM buffers
      // ------------------------------------------------------------------
      if (rest.endsWith("/ack")) {
        const rawId = rest.slice(0, -"/ack".length);
        if (!rawId || rawId.includes("/")) {
          return problemResponse(errNotFound(`route '${method} ${path}' not found`));
        }
        if (method !== "POST") {
          return problemResponse(
            {
              status: 405,
              error: "drop_method_not_allowed",
              slug: "drop-method-not-allowed",
              title: "Method Not Allowed",
              detail: "POST is required for /v1/drops/{id}/ack",
            },
            { Allow: "POST, OPTIONS" }
          );
        }

        const dropId = safeDecodeSegment(rawId);
        if (!dropId || !isValidDropId(dropId)) {
          return problemResponse(errUnauthorized("invalid drop_id format"));
        }

        const capHeader = request.headers.get(DROP_CAP_HEADER)?.trim() || "";
        const forwardHeaders = new Headers({ "Content-Type": "application/json" });

        // Verify subCap BEFORE reading body when capability auth is used!
        if (capHeader) {
          const capRes = await verifyCapability({
            dropId,
            token: capHeader,
            expectedRole: DROP_CAP_ROLE_SUB,
            hmacKey,
            prevHmacKey,
            nowMs,
          });
          if (!capRes.ok) return problemResponse(capRes.problem);
          forwardHeaders.set("X-Drop-Auth", "subcap");
        }

        const bodyRes = await readBoundedBody(request, MAX_CONTROL_BODY_BYTES);
        if (!bodyRes.ok) return problemResponse(bodyRes.problem);
        const bodyBytes = bodyRes.bytes;

        if (!capHeader) {
          const authRes = await verifyHyphaeEd25519Request(request, {
            mode: cfg.mode,
            allowedNodeKeys: env?.ALLOWED_NODE_KEYS,
            bodyBytes,
            nowMs,
            nonceCache,
            allowDeferredOpenPubKey: true,
          });
          if (!authRes.ok) return problemResponse(authRes.problem);

          if (authRes.deferred) {
            forwardHeaders.set("X-Drop-Auth", "creator-deferred");
            forwardHeaders.set("X-Drop-Orig-Auth", request.headers.get("Authorization") ?? "");
            forwardHeaders.set("X-Drop-Orig-Method", "POST");
            forwardHeaders.set("X-Drop-Orig-Path", `${url.pathname}${url.search}`);
            forwardHeaders.set("X-Drop-Orig-Body-Sha256", authRes.bodySha256Hex);
          } else {
            forwardHeaders.set("X-Drop-Auth", "creator");
            forwardHeaders.set("X-Drop-Creator-Node", authRes.nodeId);
            forwardHeaders.set("X-Drop-Creator-PubKey", authRes.pubKeyB64);
          }
        }

        const stub = dropSlotNs.get(dropSlotNs.idFromName(dropId));
        return stub.fetch("https://drop-slot.internal/ack", {
          method: "POST",
          headers: forwardHeaders,
          body: bodyBytes,
        });
      }

      // ------------------------------------------------------------------
      // POST /v1/drops/{id} — browser/client opaque ciphertext submission
      // ------------------------------------------------------------------
      if (rest && !rest.includes("/")) {
        const corsHeaders = new Headers();
        applyCorsHeaders(corsHeaders, reqOrigin, cfg.allowedOrigins, cfg.allowPrivateNetwork);

        if (method !== "POST") {
          corsHeaders.set("Allow", "POST, OPTIONS");
          return problemResponse(
            {
              status: 405,
              error: "drop_method_not_allowed",
              slug: "drop-method-not-allowed",
              title: "Method Not Allowed",
              detail: "POST is required for /v1/drops/{id}",
            },
            corsHeaders
          );
        }

        const dropId = safeDecodeSegment(rest);
        if (!dropId || !isValidDropId(dropId)) {
          return problemResponse(errUnauthorized("invalid drop_id format"), corsHeaders);
        }

        const capHeader = request.headers.get(DROP_CAP_HEADER)?.trim() || "";
        if (!capHeader) {
          return problemResponse(
            errUnauthorized(`missing ${DROP_CAP_HEADER} header`),
            corsHeaders
          );
        }

        // CRITICAL: constant-time stateless capability verification BEFORE reading request body!
        const capRes = await verifyCapability({
          dropId,
          token: capHeader,
          expectedRole: DROP_CAP_ROLE_POST,
          hmacKey,
          prevHmacKey,
          nowMs,
        });
        if (!capRes.ok) {
          return problemResponse(capRes.problem, corsHeaders);
        }

        // Enforce Content-Length + streaming byte cap <= maxPayloadBytes.
        const bodyRes = await readBoundedBody(request, cfg.maxPayloadBytes);
        if (!bodyRes.ok) {
          return problemResponse(bodyRes.problem, corsHeaders);
        }
        const payloadBytes = bodyRes.bytes;
        if (payloadBytes.byteLength === 0) {
          return problemResponse(errBadRequest("drop payload must not be empty"), corsHeaders);
        }

        try {
          const stub = dropSlotNs.get(dropSlotNs.idFromName(dropId));
          const doResp = await stub.fetch("https://drop-slot.internal/post", {
            method: "POST",
            headers: { "Content-Type": "application/octet-stream" },
            body: payloadBytes,
          });
          const mergedHeaders = new Headers(doResp.headers);
          applyCorsHeaders(mergedHeaders, reqOrigin, cfg.allowedOrigins, cfg.allowPrivateNetwork);
          mergedHeaders.set("Cache-Control", "no-store");
          return new Response(doResp.body, {
            status: doResp.status,
            headers: mergedHeaders,
          });
        } finally {
          // Zeroize temporary Worker isolate copy immediately after forwarding to DO.
          payloadBytes.fill(0);
        }
      }

      return problemResponse(errNotFound(`route '${method} ${path}' not found`));
    },
  };
}

const defaultWorker = createWorkerApp();
export default defaultWorker;
