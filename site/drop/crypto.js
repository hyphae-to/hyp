/**
 * Hyphae v2 Verified Human Drops — Zero-Dependency WebCrypto Suite
 *
 * Bit-for-bit parity with Rust `hyp-crypto`:
 * - RFC 4648 §5 strict unpadded base64url
 * - RFC 8785 JSON Canonicalization Scheme (JCS)
 * - Power-of-2 bucket padding (`256 B .. 32 KiB`, 2-byte u16 BE length prefix)
 * - RFC 8032 Ed25519 signing & strict verification (WebCrypto + pure-JS fallback)
 * - RFC 7748 X25519 key agreement (WebCrypto + pure-JS fallback)
 * - RFC 9180 HPKE Base Mode (`DHKEM(X25519, HKDF-SHA256)`, `HKDF-SHA256`, `AES-256-GCM`)
 * - WebAuthn Passkey+PRF -> HKDF-SHA256 -> Ed25519 key derivation
 * - RFC 7638 OKP JWK thumbprints (`kid`) & human-verifiable SAS fingerprints
 * - `NodeCertV1` (`hcert1_`) verification & `HumanDropEnvelopeV1` (`hdrop1_`) sealing/opening
 * - Reserved system-secret name denylist & secret-name validator
 *
 * Works natively in modern browsers (Safari 18+, Chrome, Edge, Firefox) and Node 24+.
 */

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", { fatal: true });

// ============================================================================
// Protocol Constants (Exact Match with `hyp-crypto` & RFC-human-authority-mvp)
// ============================================================================

export const HUMAN_CLAIM_DOMAIN = "hyphae/v2/human-claim\n";
export const HUMAN_NODE_CERT_DOMAIN = "hyphae/v2/human-node-cert\n";
export const HUMAN_REVOCATION_DOMAIN = "hyphae/v2/human-revocation\n";
export const HUMAN_PRF_INPUT_PREFIX = "hyphae/v2/human-prf-input\n";
export const HUMAN_PRF_ED25519_SALT = "hyphae/v2/human-prf-ed25519";
export const HUMAN_PRF_X25519_SALT = "hyphae/v2/human-prf-x25519";
export const HUMAN_DROP_SUITE = "human.drop.v1";
export const HUMAN_DRAFT_SUITE = "human.draft.v1";
export const HUMAN_DRAFT_INFO_PREFIX = "hyphae/v2/human-draft\n";
export const MAX_HUMAN_DRAFT_CHARS = 512;
export const MAX_HUMAN_DRAFT_CONTEXT_CHARS = 160;

export const HDROP1_PREFIX = "hdrop1_";
export const HCERT1_PREFIX = "hcert1_";

export const MIN_PADDING_BUCKET = 256;
export const MAX_PADDING_BUCKET = 32 * 1024;
export const MAX_PADDED_PLAINTEXT = MAX_PADDING_BUCKET - 2;

export const MAX_CLOCK_SKEW_MS = 60_000;

export const AEAD_AES_128_GCM = 0x0001;
export const AEAD_AES_256_GCM = 0x0002;

const HPKE_V1 = utf8Bytes("HPKE-v1");
const KEM_SUITE_ID = new Uint8Array([0x4b, 0x45, 0x4d, 0x00, 0x20]); // "KEM" || 0x0020

// RFC 8410 PKCS#8 v1 DER prefixes (16 bytes) for raw 32-byte private keys.
const ED25519_PKCS8_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
  0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);

const X25519_PKCS8_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
  0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
]);

// Reserved Hyphae internal secret prefixes (exact match with Rust denylist).
export const RESERVED_SECRET_PREFIXES = Object.freeze([
  "node-sign-",
  "node-enc-",
  "id-sign-",
  "id-enc-",
  "admin-ca-",
  "gate-policy-",
  "human-admin-",
  "human-authority-",
  "auth-token-",
]);

const RESERVED_SECRET_EXACT = new Set([
  "admin-ca",
  "gate-policy",
  "gate-policy-hmac-key",
  "human-admin",
  "human-authority",
  "auth-token",
]);

// ============================================================================
// Byte & Random Utilities
// ============================================================================

function getCrypto() {
  const c = globalThis.crypto;
  if (!c || !c.subtle) {
    throw new Error("WebCrypto API (crypto.subtle) is unavailable in this environment");
  }
  return c;
}

export function utf8Bytes(str) {
  return textEncoder.encode(str);
}

export function utf8String(bytes) {
  return textDecoder.decode(bytes);
}

export function concatBytes(...parts) {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

export function randomBytes(len) {
  const out = new Uint8Array(len);
  getCrypto().getRandomValues(out);
  return out;
}

export function zeroize(buf) {
  if (buf instanceof Uint8Array) {
    buf.fill(0);
  }
}

export function constantTimeEqual(a, b) {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array) || a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

export function hexEncode(bytes) {
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i].toString(16).padStart(2, "0");
  }
  return out;
}

export function hexDecode(hex) {
  if (typeof hex !== "string" || hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) {
    throw new Error("Invalid hex string");
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

// ============================================================================
// Strict Unpadded Base64url (RFC 4648 §5)
// ============================================================================

const B64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const B64URL_DECODE = new Int8Array(128).fill(-1);
for (let i = 0; i < B64URL_ALPHABET.length; i++) {
  B64URL_DECODE[B64URL_ALPHABET.charCodeAt(i)] = i;
}

export function base64urlEncode(input) {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  const len = bytes.length;
  if (len === 0) return "";
  let out = "";
  let i = 0;
  for (; i + 2 < len; i += 3) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    out +=
      B64URL_ALPHABET[(n >>> 18) & 63] +
      B64URL_ALPHABET[(n >>> 12) & 63] +
      B64URL_ALPHABET[(n >>> 6) & 63] +
      B64URL_ALPHABET[n & 63];
  }
  const rem = len - i;
  if (rem === 1) {
    const n = bytes[i];
    out += B64URL_ALPHABET[(n >>> 2) & 63] + B64URL_ALPHABET[(n << 4) & 63];
  } else if (rem === 2) {
    const n = (bytes[i] << 8) | bytes[i + 1];
    out +=
      B64URL_ALPHABET[(n >>> 10) & 63] +
      B64URL_ALPHABET[(n >>> 4) & 63] +
      B64URL_ALPHABET[(n << 2) & 63];
  }
  return out;
}

export function base64urlDecode(str) {
  if (typeof str !== "string") {
    throw new Error("base64url input must be a string");
  }
  const len = str.length;
  if (len === 0) return new Uint8Array(0);
  const rem = len & 3;
  if (rem === 1) {
    throw new Error("Invalid unpadded base64url length");
  }
  const fullGroups = len >>> 2;
  const outLen = fullGroups * 3 + (rem === 2 ? 1 : rem === 3 ? 2 : 0);
  const out = new Uint8Array(outLen);

  let pos = 0;
  let o = 0;
  for (let g = 0; g < fullGroups; g++) {
    const c0 = str.charCodeAt(pos++);
    const c1 = str.charCodeAt(pos++);
    const c2 = str.charCodeAt(pos++);
    const c3 = str.charCodeAt(pos++);
    if ((c0 | c1 | c2 | c3) > 127) throw new Error("Invalid base64url character");
    const v0 = B64URL_DECODE[c0];
    const v1 = B64URL_DECODE[c1];
    const v2 = B64URL_DECODE[c2];
    const v3 = B64URL_DECODE[c3];
    if ((v0 | v1 | v2 | v3) < 0) throw new Error("Invalid base64url character");
    const n = (v0 << 18) | (v1 << 12) | (v2 << 6) | v3;
    out[o++] = (n >>> 16) & 0xff;
    out[o++] = (n >>> 8) & 0xff;
    out[o++] = n & 0xff;
  }

  if (rem === 2) {
    const c0 = str.charCodeAt(pos++);
    const c1 = str.charCodeAt(pos++);
    if ((c0 | c1) > 127) throw new Error("Invalid base64url character");
    const v0 = B64URL_DECODE[c0];
    const v1 = B64URL_DECODE[c1];
    if ((v0 | v1) < 0) throw new Error("Invalid base64url character");
    if ((v1 & 0x0f) !== 0) {
      throw new Error("Non-canonical trailing bits in base64url");
    }
    out[o] = (v0 << 2) | (v1 >>> 4);
  } else if (rem === 3) {
    const c0 = str.charCodeAt(pos++);
    const c1 = str.charCodeAt(pos++);
    const c2 = str.charCodeAt(pos++);
    if ((c0 | c1 | c2) > 127) throw new Error("Invalid base64url character");
    const v0 = B64URL_DECODE[c0];
    const v1 = B64URL_DECODE[c1];
    const v2 = B64URL_DECODE[c2];
    if ((v0 | v1 | v2) < 0) throw new Error("Invalid base64url character");
    if ((v2 & 0x03) !== 0) {
      throw new Error("Non-canonical trailing bits in base64url");
    }
    out[o++] = (v0 << 2) | (v1 >>> 4);
    out[o] = ((v1 & 0x0f) << 4) | (v2 >>> 2);
  }
  return out;
}

// ============================================================================
// Strict RFC 8785 JSON Canonicalization Scheme (JCS)
// ============================================================================

function escapeJcsString(s) {
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    if (code === 0x22) out += '\\"';
    else if (code === 0x5c) out += "\\\\";
    else if (code === 0x08) out += "\\b";
    else if (code === 0x0c) out += "\\f";
    else if (code === 0x0a) out += "\\n";
    else if (code === 0x0d) out += "\\r";
    else if (code === 0x09) out += "\\t";
    else if (code < 0x20) out += "\\u" + code.toString(16).padStart(4, "0");
    else out += s[i];
  }
  out += '"';
  return out;
}

function serializeJcs(value) {
  if (value === null) return "null";
  if (typeof value === "object" && typeof value.toJSON === "function") {
    value = value.toJSON();
    if (value === null) return "null";
  }
  const t = typeof value;
  if (t === "boolean") return value ? "true" : "false";
  if (t === "number") {
    if (!Number.isFinite(value)) {
      throw new Error("Non-finite JSON number is not valid in RFC 8785 JCS");
    }
    if (value === 0) return "0"; // normalizes -0 to "0"
    // ES6 Number::toString is normative RFC 8785 §3.2.2.3.
    return String(value);
  }
  if (t === "string") return escapeJcsString(value);
  if (Array.isArray(value)) {
    const parts = new Array(value.length);
    for (let i = 0; i < value.length; i++) {
      const item = value[i];
      parts[i] = item === undefined || typeof item === "function" || typeof item === "symbol"
        ? "null"
        : serializeJcs(item);
    }
    return "[" + parts.join(",") + "]";
  }
  if (t === "object") {
    // RFC 8785 §3.2.3: lexicographical sort by UTF-16 code units.
    // JS `<` compares strings lexicographically by UTF-16 code units.
    const keys = Object.keys(value).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    const parts = [];
    for (const k of keys) {
      const v = value[k];
      if (v === undefined || typeof v === "function" || typeof v === "symbol") continue;
      parts.push(escapeJcsString(k) + ":" + serializeJcs(v));
    }
    return "{" + parts.join(",") + "}";
  }
  throw new Error(`Unsupported value type in RFC 8785 JCS: ${t}`);
}

export function toCanonicalJson(value) {
  return serializeJcs(value);
}

// ============================================================================
// Power-of-2 Bucket Padding (Exact Match with `hyp-crypto::e2ee::pad_bucket`)
// ============================================================================

export function bucketSizeFor(plaintextLen) {
  if (!Number.isInteger(plaintextLen) || plaintextLen < 0 || plaintextLen > MAX_PADDED_PLAINTEXT) {
    throw new Error(
      `plaintext length ${plaintextLen} exceeds maximum padded size ${MAX_PADDED_PLAINTEXT}`
    );
  }
  const needed = plaintextLen + 2;
  let bucket = MIN_PADDING_BUCKET;
  while (bucket < needed) {
    bucket <<= 1;
  }
  return bucket;
}

/**
 * Pads `plaintext` into `[2B u16 BE len][plaintext][0x00 ...]`
 * at the minimal power-of-2 bucket in `256..=32768`.
 */
export function padBucket(plaintext) {
  const pt = plaintext instanceof Uint8Array ? plaintext : new Uint8Array(plaintext);
  const bucket = bucketSizeFor(pt.length);
  const out = new Uint8Array(bucket);
  out[0] = (pt.length >>> 8) & 0xff;
  out[1] = pt.length & 0xff;
  out.set(pt, 2);
  return out;
}

/**
 * Validates and strips power-of-2 bucket padding, failing closed on non-bucket lengths,
 * non-minimal buckets, or non-zero trailing bytes.
 */
export function unpadBucket(padded) {
  const buf = padded instanceof Uint8Array ? padded : new Uint8Array(padded);
  const len = buf.length;
  if (len < MIN_PADDING_BUCKET || len > MAX_PADDING_BUCKET || (len & (len - 1)) !== 0) {
    throw new Error(`Invalid padded bucket length ${len}`);
  }
  const ptLen = (buf[0] << 8) | buf[1];
  const expectedBucket = bucketSizeFor(ptLen);
  if (expectedBucket !== len || 2 + ptLen > len) {
    throw new Error("Corrupt bucket padding length prefix");
  }
  let nonZero = 0;
  for (let i = 2 + ptLen; i < len; i++) {
    nonZero |= buf[i];
  }
  if (nonZero !== 0) {
    throw new Error("Non-zero trailing padding bytes");
  }
  return buf.slice(2, 2 + ptLen);
}

// ============================================================================
// Small-Order & Canonical Point Validation (Exact Match with `hyp-crypto`)
// ============================================================================

const ED25519_P_LE = new Uint8Array([
  0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
]);

const SMALL_ORDER_ED25519_Y_LE = [
  new Uint8Array(32),
  new Uint8Array([1, ...new Array(31).fill(0)]),
  new Uint8Array([
    0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
  ]),
  new Uint8Array([
    0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0,
    0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05,
  ]),
  new Uint8Array([
    0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f,
    0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a,
  ]),
];

const LOW_ORDER_X25519_POINTS = [
  new Uint8Array(32),
  new Uint8Array([1, ...new Array(31).fill(0)]),
  new Uint8Array([
    0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a,
    0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00,
  ]),
  new Uint8Array([
    0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b,
    0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57,
  ]),
  new Uint8Array([
    0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
  ]),
  new Uint8Array([
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
  ]),
  new Uint8Array([
    0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
  ]),
];

export function isSmallOrderEd25519Point(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 32) return true;
  let y = new Uint8Array(bytes);
  y[31] &= 0x7f;

  let allFf = true;
  for (let i = 1; i < 31; i++) {
    if (y[i] !== 0xff) {
      allFf = false;
      break;
    }
  }
  if (y[31] === 0x7f && allFf && y[0] >= 0xed) {
    const reduced = y[0] - 0xed;
    y = new Uint8Array(32);
    y[0] = reduced;
  }

  for (const cand of SMALL_ORDER_ED25519_Y_LE) {
    if (constantTimeEqual(y, cand)) return true;
  }
  return false;
}

export function isNonCanonicalEd25519Y(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 32) return true;
  for (let i = 31; i >= 0; i--) {
    const b = i === 31 ? bytes[i] & 0x7f : bytes[i];
    if (b > ED25519_P_LE[i]) return true;
    if (b < ED25519_P_LE[i]) return false;
  }
  return true; // y == p is non-canonical
}

export function isLowOrderX25519Point(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 32) return true;
  const masked = new Uint8Array(bytes);
  masked[31] &= 0x7f;
  let hit = 0;
  for (const cand of LOW_ORDER_X25519_POINTS) {
    let diff = 0;
    for (let i = 0; i < 32; i++) diff |= masked[i] ^ cand[i];
    hit |= ((diff - 1) >>> 31) & 1;
  }
  return hit !== 0;
}

// ============================================================================
// Pure-JS BigInt Curve25519 Fallback (Used only if WebCrypto lacks OKP curves)
// ============================================================================

const FP = (1n << 255n) - 19n;
const ED_L = (1n << 252n) + 27742317777372353535851937790883648493n;
const ED_D = 37095705934669439343138083508754565189542113879843219016388785533085940283555n;
const ED_I = 19681161376707505956807079304988542015446066515923890162744021073123829784752n;
const ED_BX = 15112221349535400772501151409588531511454012693041857206046113283949847762202n;
const ED_BY = 46316835694926478169428394003475163141307993866256225615783033603165251855960n;
const ED_BASE = [ED_BX, ED_BY, 1n, (ED_BX * ED_BY) % FP];
const ED_IDENTITY = [0n, 1n, 1n, 0n];

function fpMod(a) {
  const r = a % FP;
  return r >= 0n ? r : r + FP;
}

function fpPow(base, exp) {
  let result = 1n;
  let b = fpMod(base);
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % FP;
    b = (b * b) % FP;
    e >>= 1n;
  }
  return result;
}

function fpInv(a) {
  return fpPow(a, FP - 2n);
}

function bytesToLeBigInt(bytes) {
  let n = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    n = (n << 8n) | BigInt(bytes[i]);
  }
  return n;
}

function bigIntToLe32(n) {
  const out = new Uint8Array(32);
  let v = n;
  for (let i = 0; i < 32; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

function x25519ScalarMultPure(scalar32, u32) {
  const k = new Uint8Array(scalar32);
  k[0] &= 248;
  k[31] &= 127;
  k[31] |= 64;
  const kBig = bytesToLeBigInt(k);
  zeroize(k);

  const uCopy = new Uint8Array(u32);
  uCopy[31] &= 127;
  const x1 = bytesToLeBigInt(uCopy) % FP;

  let x2 = 1n;
  let z2 = 0n;
  let x3 = x1;
  let z3 = 1n;
  let swap = 0n;

  for (let t = 254n; t >= 0n; t--) {
    const kt = (kBig >> t) & 1n;
    swap ^= kt;
    if (swap) {
      [x2, x3] = [x3, x2];
      [z2, z3] = [z3, z2];
    }
    swap = kt;

    const A = fpMod(x2 + z2);
    const AA = fpMod(A * A);
    const B = fpMod(x2 - z2);
    const BB = fpMod(B * B);
    const E = fpMod(AA - BB);
    const C = fpMod(x3 + z3);
    const D = fpMod(x3 - z3);
    const DA = fpMod(D * A);
    const CB = fpMod(C * B);
    x3 = fpMod((DA + CB) * (DA + CB));
    z3 = fpMod(x1 * fpMod((DA - CB) * (DA - CB)));
    x2 = fpMod(AA * BB);
    z2 = fpMod(E * fpMod(AA + 121665n * E));
  }
  if (swap) {
    [x2, x3] = [x3, x2];
    [z2, z3] = [z3, z2];
  }
  return bigIntToLe32(fpMod(x2 * fpInv(z2)));
}

function edAdd(P, Q) {
  const [X1, Y1, Z1, T1] = P;
  const [X2, Y2, Z2, T2] = Q;
  const A = fpMod((Y1 - X1) * (Y2 - X2));
  const B = fpMod((Y1 + X1) * (Y2 + X2));
  const C = fpMod(2n * ED_D * T1 * T2);
  const D = fpMod(2n * Z1 * Z2);
  const E = fpMod(B - A);
  const F = fpMod(D - C);
  const G = fpMod(D + C);
  const H = fpMod(B + A);
  return [fpMod(E * F), fpMod(G * H), fpMod(F * G), fpMod(E * H)];
}

function edDouble(P) {
  const [X1, Y1, Z1] = P;
  const A = fpMod(X1 * X1);
  const B = fpMod(Y1 * Y1);
  const C = fpMod(2n * Z1 * Z1);
  const H = fpMod(A + B);
  const E = fpMod(H - fpMod((X1 + Y1) * (X1 + Y1)));
  const G = fpMod(A - B);
  const F = fpMod(C + G);
  return [fpMod(E * F), fpMod(G * H), fpMod(F * G), fpMod(E * H)];
}

function edMul(P, scalar) {
  let Q = ED_IDENTITY;
  let R = P;
  let k = scalar;
  while (k > 0n) {
    if (k & 1n) Q = edAdd(Q, R);
    R = edDouble(R);
    k >>= 1n;
  }
  return Q;
}

function edEncodePoint(P) {
  const zInv = fpInv(P[2]);
  const x = fpMod(P[0] * zInv);
  const y = fpMod(P[1] * zInv);
  const out = bigIntToLe32(y);
  if (x & 1n) out[31] |= 0x80;
  return out;
}

function edDecodePoint(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 32) return null;
  if (isNonCanonicalEd25519Y(bytes)) return null;
  const sign = BigInt((bytes[31] >>> 7) & 1);
  const yBytes = new Uint8Array(bytes);
  yBytes[31] &= 0x7f;
  const y = bytesToLeBigInt(yBytes);
  const y2 = fpMod(y * y);
  const u = fpMod(y2 - 1n);
  const v = fpMod(ED_D * y2 + 1n);
  const v3 = fpMod(v * v * v);
  const v7 = fpMod(v3 * v3 * v);
  let x = fpMod(u * v3 * fpPow(fpMod(u * v7), (FP - 5n) / 8n));
  const vx2 = fpMod(v * x * x);
  if (vx2 !== u) {
    if (vx2 === fpMod(-u)) {
      x = fpMod(x * ED_I);
    } else {
      return null;
    }
  }
  if (x === 0n && sign === 1n) return null;
  if ((x & 1n) !== sign) x = fpMod(-x);
  return [x, y, 1n, fpMod(x * y)];
}

async function sha512(bytes) {
  const digest = await getCrypto().subtle.digest("SHA-512", bytes);
  return new Uint8Array(digest);
}

async function ed25519ExpandSeedPure(seed32) {
  const h = await sha512(seed32);
  const aBytes = h.slice(0, 32);
  aBytes[0] &= 248;
  aBytes[31] &= 127;
  aBytes[31] |= 64;
  const a = bytesToLeBigInt(aBytes);
  const prefix = h.slice(32, 64);
  const pub = edEncodePoint(edMul(ED_BASE, a));
  zeroize(h);
  zeroize(aBytes);
  return { a, prefix, publicKeyBytes: pub };
}

export async function _ed25519SignPure(seed32, msg) {
  const { a, prefix, publicKeyBytes } = await ed25519ExpandSeedPure(seed32);
  const rHash = await sha512(concatBytes(prefix, msg));
  zeroize(prefix);
  const r = bytesToLeBigInt(rHash) % ED_L;
  zeroize(rHash);
  const R = edEncodePoint(edMul(ED_BASE, r));
  const kHash = await sha512(concatBytes(R, publicKeyBytes, msg));
  const k = bytesToLeBigInt(kHash) % ED_L;
  const S = (r + k * a) % ED_L;
  const sig = new Uint8Array(64);
  sig.set(R, 0);
  sig.set(bigIntToLe32(S), 32);
  return sig;
}

export async function _ed25519VerifyPure(pub32, msg, sig64) {
  if (!(pub32 instanceof Uint8Array) || pub32.length !== 32) return false;
  if (!(sig64 instanceof Uint8Array) || sig64.length !== 64) return false;
  if (isSmallOrderEd25519Point(pub32) || isNonCanonicalEd25519Y(pub32)) return false;
  const Rbytes = sig64.subarray(0, 32);
  const Sbytes = sig64.subarray(32, 64);
  if (isSmallOrderEd25519Point(Rbytes) || isNonCanonicalEd25519Y(Rbytes)) return false;
  const S = bytesToLeBigInt(Sbytes);
  if (S >= ED_L) return false;
  const A = edDecodePoint(pub32);
  const R = edDecodePoint(Rbytes);
  if (!A || !R) return false;
  const kHash = await sha512(concatBytes(Rbytes, pub32, msg));
  const k = bytesToLeBigInt(kHash) % ED_L;
  const lhs = edEncodePoint(edMul(ED_BASE, S));
  const rhs = edEncodePoint(edAdd(R, edMul(A, k)));
  return constantTimeEqual(lhs, rhs);
}

export function _x25519PublicFromPrivatePure(priv32) {
  const base = new Uint8Array(32);
  base[0] = 9;
  return x25519ScalarMultPure(priv32, base);
}

export function _x25519DhPure(priv32, pub32) {
  if (isLowOrderX25519Point(pub32)) {
    throw new Error("Low-order X25519 public key rejected");
  }
  const shared = x25519ScalarMultPure(priv32, pub32);
  let orAcc = 0;
  for (let i = 0; i < 32; i++) orAcc |= shared[i];
  if (orAcc === 0) {
    zeroize(shared);
    throw new Error("All-zero X25519 shared secret rejected");
  }
  return shared;
}

// ============================================================================
// SHA-256, HMAC-SHA256 & HKDF-SHA256 (WebCrypto)
// ============================================================================

export async function sha256(bytes) {
  const data = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  const digest = await getCrypto().subtle.digest("SHA-256", data);
  return new Uint8Array(digest);
}

export async function hmacSha256(keyBytes, data) {
  const subtle = getCrypto().subtle;
  // WebCrypto rejects 0-length HMAC keys; RFC 2104 pads short keys with 0x00 to block size.
  const effectiveKey = keyBytes.length > 0 ? keyBytes : new Uint8Array(32);
  const cryptoKey = await subtle.importKey(
    "raw",
    effectiveKey,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const mac = await subtle.sign("HMAC", cryptoKey, data);
  return new Uint8Array(mac);
}

export async function hkdfExpandSha256(prk, info, length) {
  if (!Number.isInteger(length) || length < 0 || length > 255 * 32) {
    throw new Error(`Invalid HKDF-Expand length ${length}`);
  }
  if (length === 0) return new Uint8Array(0);
  const n = Math.ceil(length / 32);
  const okm = new Uint8Array(n * 32);
  let prev = new Uint8Array(0);
  for (let i = 1; i <= n; i++) {
    const input = new Uint8Array(prev.length + info.length + 1);
    input.set(prev, 0);
    input.set(info, prev.length);
    input[input.length - 1] = i;
    prev = await hmacSha256(prk, input);
    okm.set(prev, (i - 1) * 32);
  }
  const out = okm.slice(0, length);
  zeroize(okm);
  return out;
}

export async function hkdfSha256(salt, ikm, info, length) {
  const prk = await hmacSha256(salt, ikm);
  try {
    return await hkdfExpandSha256(prk, info, length);
  } finally {
    zeroize(prk);
  }
}

// ============================================================================
// Ed25519 (WebCrypto Native Primary + Pure-JS Fallback)
// ============================================================================

function wrapPkcs8(prefix, key32) {
  if (!(key32 instanceof Uint8Array) || key32.length !== 32) {
    throw new Error("Expected 32-byte private key");
  }
  const der = new Uint8Array(48);
  der.set(prefix, 0);
  der.set(key32, 16);
  return der;
}

export async function ed25519KeypairFromSeed(seed32) {
  if (!(seed32 instanceof Uint8Array) || seed32.length !== 32) {
    throw new Error("Ed25519 seed must be 32 bytes");
  }
  const subtle = getCrypto().subtle;
  const der = wrapPkcs8(ED25519_PKCS8_PREFIX, seed32);
  try {
    const privateKey = await subtle.importKey("pkcs8", der, { name: "Ed25519" }, true, ["sign"]);
    const jwk = await subtle.exportKey("jwk", privateKey);
    if (!jwk || typeof jwk.x !== "string") {
      throw new Error("WebCrypto Ed25519 JWK export missing public coordinate x");
    }
    const publicKeyBytes = base64urlDecode(jwk.x);
    const publicJwk = { kty: "OKP", crv: "Ed25519", x: jwk.x };
    const kid = await jwkThumbprint(publicJwk);
    return { publicKeyBytes, publicJwk, kid };
  } catch {
    const { publicKeyBytes } = await ed25519ExpandSeedPure(seed32);
    const publicJwk = { kty: "OKP", crv: "Ed25519", x: base64urlEncode(publicKeyBytes) };
    const kid = await jwkThumbprint(publicJwk);
    return { publicKeyBytes, publicJwk, kid };
  } finally {
    zeroize(der);
  }
}

export async function ed25519Sign(seed32, msg) {
  if (!(seed32 instanceof Uint8Array) || seed32.length !== 32) {
    throw new Error("Ed25519 seed must be 32 bytes");
  }
  const data = msg instanceof Uint8Array ? msg : utf8Bytes(String(msg));
  const subtle = getCrypto().subtle;
  const der = wrapPkcs8(ED25519_PKCS8_PREFIX, seed32);
  try {
    const privateKey = await subtle.importKey("pkcs8", der, { name: "Ed25519" }, false, ["sign"]);
    const sig = await subtle.sign("Ed25519", privateKey, data);
    return new Uint8Array(sig);
  } catch {
    return _ed25519SignPure(seed32, data);
  } finally {
    zeroize(der);
  }
}

export async function ed25519Verify(pub32, msg, sig64) {
  if (!(pub32 instanceof Uint8Array) || pub32.length !== 32) return false;
  if (!(sig64 instanceof Uint8Array) || sig64.length !== 64) return false;
  // Fail closed on small-order or non-canonical public key / signature R component.
  if (isSmallOrderEd25519Point(pub32) || isNonCanonicalEd25519Y(pub32)) return false;
  const rBytes = sig64.subarray(0, 32);
  if (isSmallOrderEd25519Point(rBytes) || isNonCanonicalEd25519Y(rBytes)) return false;

  const data = msg instanceof Uint8Array ? msg : utf8Bytes(String(msg));
  const subtle = getCrypto().subtle;
  try {
    const publicKey = await subtle.importKey("raw", pub32, { name: "Ed25519" }, false, ["verify"]);
    return await subtle.verify("Ed25519", publicKey, sig64, data);
  } catch {
    return _ed25519VerifyPure(pub32, data, sig64);
  }
}

// ============================================================================
// X25519 (WebCrypto Native Primary + Pure-JS Fallback)
// ============================================================================

export async function x25519PublicFromPrivate(priv32) {
  if (!(priv32 instanceof Uint8Array) || priv32.length !== 32) {
    throw new Error("X25519 private key must be 32 bytes");
  }
  const subtle = getCrypto().subtle;
  const der = wrapPkcs8(X25519_PKCS8_PREFIX, priv32);
  try {
    const privKey = await subtle.importKey("pkcs8", der, { name: "X25519" }, true, ["deriveBits"]);
    const jwk = await subtle.exportKey("jwk", privKey);
    if (!jwk || typeof jwk.x !== "string") {
      throw new Error("WebCrypto X25519 JWK export missing public coordinate x");
    }
    const pub = base64urlDecode(jwk.x);
    if (isLowOrderX25519Point(pub)) {
      throw new Error("Derived low-order X25519 public key");
    }
    return pub;
  } catch {
    const pub = _x25519PublicFromPrivatePure(priv32);
    if (isLowOrderX25519Point(pub)) {
      throw new Error("Derived low-order X25519 public key");
    }
    return pub;
  } finally {
    zeroize(der);
  }
}

export async function x25519DeriveSharedSecret(priv32, pub32) {
  if (!(priv32 instanceof Uint8Array) || priv32.length !== 32) {
    throw new Error("X25519 private key must be 32 bytes");
  }
  if (!(pub32 instanceof Uint8Array) || pub32.length !== 32) {
    throw new Error("X25519 public key must be 32 bytes");
  }
  if (isLowOrderX25519Point(pub32)) {
    throw new Error("Low-order X25519 public key rejected");
  }
  const subtle = getCrypto().subtle;
  const der = wrapPkcs8(X25519_PKCS8_PREFIX, priv32);
  let shared;
  try {
    const privKey = await subtle.importKey("pkcs8", der, { name: "X25519" }, false, ["deriveBits"]);
    const pubKey = await subtle.importKey("raw", pub32, { name: "X25519" }, false, []);
    const bits = await subtle.deriveBits({ name: "X25519", public: pubKey }, privKey, 256);
    shared = new Uint8Array(bits);
  } catch {
    shared = _x25519DhPure(priv32, pub32);
  } finally {
    zeroize(der);
  }
  let orAcc = 0;
  for (let i = 0; i < 32; i++) orAcc |= shared[i];
  if (orAcc === 0) {
    zeroize(shared);
    throw new Error("All-zero X25519 shared secret rejected");
  }
  return shared;
}

// ============================================================================
// RFC 9180 HPKE Base Mode (Bit-Exact Parity with `crates/hyp-crypto/src/hpke.rs`)
// ============================================================================

function hpkeSuiteIdForAead(aeadId) {
  if (aeadId !== AEAD_AES_128_GCM && aeadId !== AEAD_AES_256_GCM) {
    throw new Error(`Unsupported HPKE AEAD ID: 0x${aeadId.toString(16)}`);
  }
  return new Uint8Array([
    0x48, 0x50, 0x4b, 0x45, // "HPKE"
    0x00, 0x20,             // KEM: DHKEM(X25519, HKDF-SHA256)
    0x00, 0x01,             // KDF: HKDF-SHA256
    (aeadId >>> 8) & 0xff,
    aeadId & 0xff,
  ]);
}

function aeadKeyLen(aeadId) {
  return aeadId === AEAD_AES_128_GCM ? 16 : 32;
}

async function labeledExtract(suiteId, salt, labelBytes, ikm) {
  const labeledIkm = concatBytes(HPKE_V1, suiteId, labelBytes, ikm);
  try {
    return await hmacSha256(salt, labeledIkm);
  } finally {
    zeroize(labeledIkm);
  }
}

async function labeledExpand(suiteId, prk, labelBytes, info, len) {
  if (len < 0 || len > 0xffff || len > 255 * 32) {
    throw new Error(`Invalid HPKE LabeledExpand length ${len}`);
  }
  const lenBe = new Uint8Array([(len >>> 8) & 0xff, len & 0xff]);
  const labeledInfo = concatBytes(lenBe, HPKE_V1, suiteId, labelBytes, info);
  return hkdfExpandSha256(prk, labeledInfo, len);
}

/**
 * RFC 9180 §7.1.3 `DeriveKeyPair(ikm)` for `DHKEM(X25519, HKDF-SHA256)`.
 */
export async function hpkeDeriveKeyPairX25519(ikm) {
  const empty = new Uint8Array(0);
  const dkpPrk = await labeledExtract(KEM_SUITE_ID, empty, utf8Bytes("dkp_prk"), ikm);
  try {
    const sk = await labeledExpand(KEM_SUITE_ID, dkpPrk, utf8Bytes("sk"), empty, 32);
    const pk = await x25519PublicFromPrivate(sk);
    return { sk, pk };
  } finally {
    zeroize(dkpPrk);
  }
}

async function hpkeExtractAndExpand(dh, enc, pkR) {
  const empty = new Uint8Array(0);
  const eaePrk = await labeledExtract(KEM_SUITE_ID, empty, utf8Bytes("eae_prk"), dh);
  try {
    const kemContext = concatBytes(enc, pkR);
    return await labeledExpand(KEM_SUITE_ID, eaePrk, utf8Bytes("shared_secret"), kemContext, 32);
  } finally {
    zeroize(eaePrk);
  }
}

async function hpkeKeyScheduleBase(aeadId, sharedSecret, info) {
  const empty = new Uint8Array(0);
  const suiteId = hpkeSuiteIdForAead(aeadId);

  const pskIdHash = await labeledExtract(suiteId, empty, utf8Bytes("psk_id_hash"), empty);
  const infoHash = await labeledExtract(suiteId, empty, utf8Bytes("info_hash"), info);

  const ksContext = new Uint8Array(65);
  ksContext[0] = 0x00; // MODE_BASE
  ksContext.set(pskIdHash, 1);
  ksContext.set(infoHash, 33);

  const secret = await labeledExtract(suiteId, sharedSecret, utf8Bytes("secret"), empty);
  try {
    const key = await labeledExpand(suiteId, secret, utf8Bytes("key"), ksContext, aeadKeyLen(aeadId));
    const baseNonce = await labeledExpand(suiteId, secret, utf8Bytes("base_nonce"), ksContext, 12);
    const exporterSecret = await labeledExpand(suiteId, secret, utf8Bytes("exp"), ksContext, 32);
    return { key, baseNonce, exporterSecret };
  } finally {
    zeroize(secret);
  }
}

/**
 * Single-shot RFC 9180 HPKE Base Mode seal.
 * Defaults to Hyphae v2 suite: `DHKEM(X25519, HKDF-SHA256)` + `HKDF-SHA256` + `AES-256-GCM`.
 */
export async function hpkeSealBase(recipientPub32, info, aad, plaintext, options = {}) {
  const aeadId = options.aeadId ?? AEAD_AES_256_GCM;
  const infoBytes = info instanceof Uint8Array ? info : utf8Bytes(info);
  const aadBytes = aad instanceof Uint8Array ? aad : utf8Bytes(aad);
  const ptBytes = plaintext instanceof Uint8Array ? plaintext : new Uint8Array(plaintext);

  if (!(recipientPub32 instanceof Uint8Array) || recipientPub32.length !== 32) {
    throw new Error("Recipient X25519 public key must be 32 bytes");
  }
  if (isLowOrderX25519Point(recipientPub32)) {
    throw new Error("Low-order recipient X25519 public key rejected");
  }

  let ephSk;
  let enc;
  if (options.ephemeralPriv32) {
    ephSk = new Uint8Array(options.ephemeralPriv32);
    enc = await x25519PublicFromPrivate(ephSk);
  } else if (options.ephemeralIkm) {
    const derived = await hpkeDeriveKeyPairX25519(options.ephemeralIkm);
    ephSk = derived.sk;
    enc = derived.pk;
  } else {
    ephSk = randomBytes(32);
    enc = await x25519PublicFromPrivate(ephSk);
  }

  let dh;
  let sharedSecret;
  let ks;
  try {
    dh = await x25519DeriveSharedSecret(ephSk, recipientPub32);
    sharedSecret = await hpkeExtractAndExpand(dh, enc, recipientPub32);
    ks = await hpkeKeyScheduleBase(aeadId, sharedSecret, infoBytes);

    const subtle = getCrypto().subtle;
    const aesKey = await subtle.importKey("raw", ks.key, { name: "AES-GCM" }, false, ["encrypt"]);
    const ctBuf = await subtle.encrypt(
      { name: "AES-GCM", iv: ks.baseNonce, additionalData: aadBytes, tagLength: 128 },
      aesKey,
      ptBytes
    );
    return { enc, ciphertext: new Uint8Array(ctBuf) };
  } finally {
    zeroize(ephSk);
    if (dh) zeroize(dh);
    if (sharedSecret) zeroize(sharedSecret);
    if (ks) {
      zeroize(ks.key);
      zeroize(ks.baseNonce);
      zeroize(ks.exporterSecret);
    }
  }
}

/**
 * Single-shot RFC 9180 HPKE Base Mode open.
 */
export async function hpkeOpenBase(recipientPriv32, enc32, info, aad, ciphertext, options = {}) {
  const aeadId = options.aeadId ?? AEAD_AES_256_GCM;
  const infoBytes = info instanceof Uint8Array ? info : utf8Bytes(info);
  const aadBytes = aad instanceof Uint8Array ? aad : utf8Bytes(aad);
  const ctBytes = ciphertext instanceof Uint8Array ? ciphertext : new Uint8Array(ciphertext);

  if (!(recipientPriv32 instanceof Uint8Array) || recipientPriv32.length !== 32) {
    throw new Error("Recipient X25519 private key must be 32 bytes");
  }
  if (!(enc32 instanceof Uint8Array) || enc32.length !== 32) {
    throw new Error("HPKE enc must be 32 bytes");
  }
  if (isLowOrderX25519Point(enc32)) {
    throw new Error("Low-order HPKE enc key rejected");
  }
  if (ctBytes.length < 16) {
    throw new Error("Ciphertext shorter than AES-GCM authentication tag");
  }

  let dh;
  let sharedSecret;
  let ks;
  try {
    const pkR = await x25519PublicFromPrivate(recipientPriv32);
    dh = await x25519DeriveSharedSecret(recipientPriv32, enc32);
    sharedSecret = await hpkeExtractAndExpand(dh, enc32, pkR);
    ks = await hpkeKeyScheduleBase(aeadId, sharedSecret, infoBytes);

    const subtle = getCrypto().subtle;
    const aesKey = await subtle.importKey("raw", ks.key, { name: "AES-GCM" }, false, ["decrypt"]);
    const ptBuf = await subtle.decrypt(
      { name: "AES-GCM", iv: ks.baseNonce, additionalData: aadBytes, tagLength: 128 },
      aesKey,
      ctBytes
    );
    return new Uint8Array(ptBuf);
  } finally {
    if (dh) zeroize(dh);
    if (sharedSecret) zeroize(sharedSecret);
    if (ks) {
      zeroize(ks.key);
      zeroize(ks.baseNonce);
      zeroize(ks.exporterSecret);
    }
  }
}

// ============================================================================
// WebAuthn Passkey + PRF -> Ed25519 & Companion X25519 Seed Derivation
// ============================================================================

const NODE_ID_RE = /^[a-z0-9][a-z0-9@._-]{0,63}$/;

export function isValidNodeId(id) {
  return typeof id === "string" && NODE_ID_RE.test(id);
}

function buildPrfHkdfInfo(humanId, authEpoch, requirePositiveEpoch = false) {
  if (typeof humanId !== "string" || humanId.length === 0) {
    throw new Error("humanId must be a non-empty string");
  }
  if (requirePositiveEpoch && !isValidNodeId(humanId)) {
    throw new Error(`Invalid humanId: ${humanId}`);
  }
  const epochBig = typeof authEpoch === "bigint" ? authEpoch : BigInt(authEpoch);
  const minEpoch = requirePositiveEpoch ? 1n : 0n;
  if (epochBig < minEpoch || epochBig > 0xffffffffffffffffn) {
    throw new Error(`authEpoch out of u64 range: ${authEpoch}`);
  }
  const epochBe = new Uint8Array(8);
  new DataView(epochBe.buffer).setBigUint64(0, epochBig, false);
  return concatBytes(utf8Bytes(humanId), new Uint8Array([0x0a]), epochBe);
}

/**
 * Computes `SHA-256("hyphae/v2/human-prf-input\n" || humanId || "\n" || prfSalt)`.
 */
export async function prfEvalInput(humanId, prfSalt) {
  if (typeof humanId !== "string" || humanId.length === 0) {
    throw new Error("humanId must be a non-empty string");
  }
  if (typeof prfSalt !== "string" || prfSalt.length === 0) {
    throw new Error("prfSalt must be a non-empty string");
  }
  return sha256(utf8Bytes(`${HUMAN_PRF_INPUT_PREFIX}${humanId}\n${prfSalt}`));
}

/**
 * Derives the 32-byte Ed25519 seed from a WebAuthn PRF 32-byte output:
 * `HKDF-SHA256(salt = "hyphae/v2/human-prf-ed25519", ikm = prfOutput32, info = utf8(humanId) || 0x0a || u64_be(authEpoch), L = 32)`
 */
export async function derivePrfEd25519Seed(prfOutput32, humanId, authEpoch) {
  const ikm = prfOutput32 instanceof Uint8Array ? prfOutput32 : new Uint8Array(prfOutput32);
  if (ikm.length !== 32) {
    throw new Error(`Expected 32-byte PRF output, got ${ikm.length} bytes`);
  }
  const salt = utf8Bytes(HUMAN_PRF_ED25519_SALT);
  const info = buildPrfHkdfInfo(humanId, authEpoch, false);
  return hkdfSha256(salt, ikm, info, 32);
}

/**
 * Derives the companion 32-byte X25519 seed from a WebAuthn PRF 32-byte output:
 * `HKDF-SHA256(salt = "hyphae/v2/human-prf-x25519", ikm = prfOutput32, info = utf8(humanId) || 0x0a || u64_be(authEpoch), L = 32)`
 * Matches Rust `hyp_crypto::human::derive_prf_x25519_keypair` bit-for-bit.
 */
export async function derivePrfX25519Seed(prfOutput32, humanId, authEpoch = 1) {
  const ikm = prfOutput32 instanceof Uint8Array ? prfOutput32 : new Uint8Array(prfOutput32);
  if (ikm.length !== 32) {
    throw new Error(`Expected 32-byte PRF output, got ${ikm.length} bytes`);
  }
  const salt = utf8Bytes(HUMAN_PRF_X25519_SALT);
  const info = buildPrfHkdfInfo(humanId, authEpoch, true);
  return hkdfSha256(salt, ikm, info, 32);
}

/**
 * Derives an OKP/X25519 keypair + RFC 7638 thumbprint (`kid`) from a 32-byte private seed.
 */
export async function x25519KeypairFromSeed(seed32) {
  if (!(seed32 instanceof Uint8Array) || seed32.length !== 32) {
    throw new Error("X25519 seed must be 32 bytes");
  }
  const privateKeyBytes = new Uint8Array(seed32);
  const publicKeyBytes = await x25519PublicFromPrivate(privateKeyBytes);
  const publicJwk = {
    kty: "OKP",
    crv: "X25519",
    x: base64urlEncode(publicKeyBytes),
  };
  const kid = await jwkThumbprint(publicJwk);
  return { privateKeyBytes, publicKeyBytes, publicJwk, kid };
}

/**
 * Deterministically derives the companion Passkey-PRF X25519 keypair for encrypted directive drafts.
 */
export async function derivePrfX25519Keypair(prfOutput32, humanId, authEpoch = 1) {
  const seed32 = await derivePrfX25519Seed(prfOutput32, humanId, authEpoch);
  try {
    return await x25519KeypairFromSeed(seed32);
  } finally {
    zeroize(seed32);
  }
}

// ============================================================================
// RFC 7638 OKP JWK Thumbprint (`kid`) & Human-Verifiable SAS Fingerprint
// ============================================================================

export function decodeOkpJwkBytes(jwk, expectedCrv = null) {
  if (!jwk || typeof jwk !== "object") {
    throw new Error("JWK must be an object");
  }
  if (jwk.kty !== "OKP") {
    throw new Error(`Expected JWK kty "OKP", got ${JSON.stringify(jwk.kty)}`);
  }
  if (jwk.crv !== "Ed25519" && jwk.crv !== "X25519") {
    throw new Error(`Unsupported OKP crv ${JSON.stringify(jwk.crv)}`);
  }
  if (expectedCrv && jwk.crv !== expectedCrv) {
    throw new Error(`Expected OKP/${expectedCrv} JWK, got OKP/${jwk.crv}`);
  }
  if (typeof jwk.x !== "string" || jwk.x.length !== 43) {
    throw new Error("Expected 43-character unpadded base64url 32-byte key in JWK.x");
  }
  const raw = base64urlDecode(jwk.x);
  if (raw.length !== 32) {
    throw new Error("Decoded JWK.x must be 32 bytes");
  }
  if (jwk.crv === "X25519" && isLowOrderX25519Point(raw)) {
    throw new Error("Low-order X25519 public key in JWK rejected");
  }
  if (jwk.crv === "Ed25519" && (isSmallOrderEd25519Point(raw) || isNonCanonicalEd25519Y(raw))) {
    throw new Error("Small-order or non-canonical Ed25519 public key in JWK rejected");
  }
  return raw;
}

/**
 * Computes RFC 7638 SHA-256 JWK Thumbprint for an OKP (`Ed25519` or `X25519`) public key.
 * Exact match with `hyp_crypto::keys::OkpJwk::thumbprint`.
 */
export async function jwkThumbprint(jwk) {
  decodeOkpJwkBytes(jwk);
  const canonical = `{"crv":"${jwk.crv}","kty":"OKP","x":"${jwk.x}"}`;
  const digest = await sha256(utf8Bytes(canonical));
  return base64urlEncode(digest);
}

// 256-word high-distinction phonetic/botanical wordlist for 4-word visual SAS checks.
const SAS_WORDLIST = [
  "acorn","agate","alder","amber","anise","apple","arbor","aspen","aster","atlas","azure","badge",
  "basil","bayou","beach","birch","bison","blade","bloom","bluff","board","bough","brass","breeze",
  "briar","brine","brook","brush","cabin","cairn","camel","canal","caper","cedar","chalk","charm",
  "chasm","chime","cider","cinder","citrus","cliff","cloak","cloud","clover","coast","cobra","cocoa",
  "comet","coral","crane","creek","crest","crisp","crown","crust","cumin","cypress","daisy","delta",
  "depot","dingo","diver","dowel","draft","drake","drift","druid","dunes","eagle","earth","ebony",
  "eddy","egret","elder","ember","epoch","fable","falcon","fauna","fennel","ferns","fiber","field",
  "finch","fjord","flame","flank","flint","flora","flute","focus","forge","forum","foxes","frame",
  "frost","fungi","gable","gale","garnet","gavel","gecko","glade","gleam","glint","globe","glyph",
  "goose","gorse","grain","grape","graph","gravel","grove","guide","gully","harbor","hazel","heath",
  "hedge","helix","heron","hinge","holly","honey","horizon","hound","humus","hypha","ibis","icicle",
  "index","indigo","inlet","irony","ivory","jacks","jasper","jewel","joust","juniper","kayak","keel",
  "kelp","kestrel","khaki","kiln","knoll","koala","krill","larch","latch","laurel","ledge","lemon",
  "lemur","lilac","linen","links","llama","loam","lodge","lotus","lunar","lupin","lynx","macaw",
  "magma","maize","manta","maple","marsh","mason","meadow","melon","merlin","mesa","metro","mica",
  "midge","millet","miner","mirth","mocha","modal","moose","morel","mossy","mound","mulch","myrrh",
  "nacre","nectar","nerve","newt","nexus","noble","north","notch","nutmeg","oaken","oasis","oaten",
  "ochre","olive","omega","onion","onyx","opal","orbit","orchid","osier","otter","ounce","ovule",
  "oxide","ozone","palms","panda","panel","pansy","papaw","patch","pause","peach","pearl","pebble",
  "pecan","pedal","peony","perch","petal","phase","phlox","piano","picea","pinto","piper","pithy",
  "pixel","plaid","plank","plant","plaza","plumb","plume","poise","polar","pollen","poppy","porch",
  "prism","probe","prose","prune",
];

/**
 * Computes Hyphae's 16-hex SHA-256 fingerprint (matching `hyp_crypto::keys::fingerprint_bytes`)
 * paired with a 4-word human-verifiable SAS phrase.
 */
export async function sasFingerprint(encJwkOrBytes) {
  let raw;
  if (encJwkOrBytes instanceof Uint8Array) {
    if (encJwkOrBytes.length !== 32) {
      throw new Error("Expected 32-byte key for SAS fingerprint");
    }
    raw = encJwkOrBytes;
  } else {
    raw = decodeOkpJwkBytes(encJwkOrBytes);
  }
  const digest = await sha256(raw);
  const hex = hexEncode(digest.subarray(0, 8));
  const formatted = `${hex.slice(0, 4)}-${hex.slice(4, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}`;
  const words = [
    SAS_WORDLIST[digest[0]],
    SAS_WORDLIST[digest[1]],
    SAS_WORDLIST[digest[2]],
    SAS_WORDLIST[digest[3]],
  ];
  return {
    hex,
    formatted,
    words,
    phrase: words.join(" · "),
  };
}

// ============================================================================
// Secret Name Validation & Reserved System-Key Denylist
// ============================================================================

const SECRET_NAME_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;

export function validateSecretName(name) {
  if (typeof name !== "string" || name.length === 0 || name.length > 64) {
    return { ok: false, reason: "invalid_secret_name", message: "Secret name must be 1..64 characters" };
  }
  if (!SECRET_NAME_RE.test(name)) {
    return {
      ok: false,
      reason: "invalid_secret_name",
      message: "Secret name must match /^[a-z0-9][a-z0-9._-]{0,63}$/",
    };
  }
  if (name.includes("..")) {
    return { ok: false, reason: "invalid_secret_name", message: "Secret name must not contain '..'" };
  }
  return { ok: true };
}

export function isReservedSecretName(name) {
  if (typeof name !== "string") return true;
  const lower = name.trim().toLowerCase();
  if (RESERVED_SECRET_EXACT.has(lower)) return true;
  return RESERVED_SECRET_PREFIXES.some((prefix) => lower.startsWith(prefix));
}

// ============================================================================
// Node Certificate (`NodeCertV1` / `hcert1_`) Sign & Fail-Closed Verify
// ============================================================================

export function encodeHcert1(signedCert) {
  return HCERT1_PREFIX + base64urlEncode(utf8Bytes(toCanonicalJson(signedCert)));
}

export function decodeHcert1(token) {
  if (typeof token !== "string" || !token.startsWith(HCERT1_PREFIX)) {
    throw new Error("Invalid hcert1_ prefix");
  }
  const jsonBytes = base64urlDecode(token.slice(HCERT1_PREFIX.length));
  const parsed = JSON.parse(utf8String(jsonBytes));
  if (!parsed || typeof parsed.payload !== "string" || typeof parsed.sig !== "string") {
    throw new Error("Malformed hcert1_ SignedPayload");
  }
  return parsed;
}

export async function signNodeCert(certPayload, humanSeed32) {
  const { publicJwk, kid } = await ed25519KeypairFromSeed(humanSeed32);
  const fullPayload = {
    v: 1,
    ...certPayload,
    humanKid: certPayload.humanKid ?? kid,
  };
  if (fullPayload.humanKid !== kid) {
    throw new Error("certPayload.humanKid does not match signing seed");
  }
  const payload = toCanonicalJson(fullPayload);
  const sigBytes = await ed25519Sign(humanSeed32, utf8Bytes(HUMAN_NODE_CERT_DOMAIN + payload));
  const signed = { payload, sig: base64urlEncode(sigBytes) };
  return { signed, hcert1: encodeHcert1(signed), humanJwk: publicJwk, humanKid: kid };
}

/**
 * Verifies a `NodeCertV1` (`hcert1_` string or `{ payload, sig }` object) against
 * the derived human Ed25519 public key, expected `nodeId`, expected X25519 `encJwk`, and time.
 * Always fails closed returning `{ ok: false, reason, message }`.
 */
export async function verifyNodeCert(
  hcert1OrObj,
  humanPub32OrJwk,
  expectedNodeId,
  expectedEncJwk,
  nowMs = Date.now()
) {
  try {
    if (!hcert1OrObj) {
      return { ok: false, reason: "missing_cert", message: "No node certificate present in drop link" };
    }
    let signed;
    if (typeof hcert1OrObj === "string") {
      signed = decodeHcert1(hcert1OrObj);
    } else if (
      typeof hcert1OrObj === "object" &&
      typeof hcert1OrObj.payload === "string" &&
      typeof hcert1OrObj.sig === "string"
    ) {
      signed = hcert1OrObj;
    } else {
      return { ok: false, reason: "malformed_cert", message: "Malformed node certificate structure" };
    }

    const humanPub32 =
      humanPub32OrJwk instanceof Uint8Array
        ? humanPub32OrJwk
        : decodeOkpJwkBytes(humanPub32OrJwk, "Ed25519");

    if (humanPub32.length !== 32 || isSmallOrderEd25519Point(humanPub32)) {
      return { ok: false, reason: "invalid_human_key", message: "Invalid human verification public key" };
    }

    const sigBytes = base64urlDecode(signed.sig);
    const sigOk = await ed25519Verify(
      humanPub32,
      utf8Bytes(HUMAN_NODE_CERT_DOMAIN + signed.payload),
      sigBytes
    );
    if (!sigOk) {
      return {
        ok: false,
        reason: "invalid_signature",
        message: "Node certificate signature did not verify against your Passkey authority",
      };
    }

    const cert = JSON.parse(signed.payload);
    if (!cert || typeof cert !== "object" || cert.v !== 1) {
      return { ok: false, reason: "unsupported_version", message: "Unsupported node certificate version" };
    }

    const expectedHumanKid = await jwkThumbprint({
      kty: "OKP",
      crv: "Ed25519",
      x: base64urlEncode(humanPub32),
    });
    if (cert.humanKid !== expectedHumanKid) {
      return {
        ok: false,
        reason: "human_kid_mismatch",
        message: "Node certificate humanKid does not match derived Passkey identity",
      };
    }

    if (!Number.isInteger(cert.authEpoch) || cert.authEpoch < 1) {
      return { ok: false, reason: "invalid_auth_epoch", message: "Node certificate authEpoch is invalid" };
    }

    if (typeof expectedNodeId !== "string" || expectedNodeId.length === 0 || cert.nodeId !== expectedNodeId) {
      return {
        ok: false,
        reason: "node_id_mismatch",
        message: `Node certificate bound to "${cert.nodeId}", expected "${expectedNodeId}"`,
      };
    }

    const expectedEncRaw = decodeOkpJwkBytes(expectedEncJwk, "X25519");
    const certEncRaw = decodeOkpJwkBytes(cert.encryptionJwk, "X25519");
    if (!constantTimeEqual(expectedEncRaw, certEncRaw)) {
      return {
        ok: false,
        reason: "encryption_key_mismatch",
        message: "Node certificate X25519 encryption key does NOT match the drop link key",
      };
    }

    if (cert.signingJwk) {
      // Validate signingJwk shape if included.
      decodeOkpJwkBytes(cert.signingJwk, "Ed25519");
    }

    const issuedAtMs = Date.parse(cert.issuedAt);
    const expiresAtMs = Date.parse(cert.expiresAt);
    if (!Number.isFinite(issuedAtMs) || !Number.isFinite(expiresAtMs) || expiresAtMs <= issuedAtMs) {
      return { ok: false, reason: "invalid_timestamps", message: "Node certificate timestamps are invalid" };
    }
    if (nowMs < issuedAtMs - MAX_CLOCK_SKEW_MS) {
      return { ok: false, reason: "cert_not_yet_valid", message: "Node certificate is not yet valid" };
    }
    if (nowMs > expiresAtMs) {
      return { ok: false, reason: "cert_expired", message: "Node certificate has expired" };
    }

    return { ok: true, cert };
  } catch (err) {
    return {
      ok: false,
      reason: "verify_error",
      message: err instanceof Error ? err.message : "Node certificate verification failed",
    };
  }
}

// ============================================================================
// Human Drop Sealing & Opening (`human.drop.v1` / `hdrop1_`)
// ============================================================================

export function humanDropHpkeInfo(recipientEncKid, dropId) {
  return utf8Bytes(`hyphae/v2/human-drop\n1\n${recipientEncKid}\n${dropId}`);
}

export function humanDropHpkeAad(recipientEncKid, dropId) {
  return utf8Bytes(`hyphae/v2/human-drop-aad\n${HUMAN_DROP_SUITE}\n${recipientEncKid}\n${dropId}`);
}

export function encodeHdrop1(envelope) {
  return HDROP1_PREFIX + base64urlEncode(utf8Bytes(toCanonicalJson(envelope)));
}

export function decodeHdrop1(token) {
  if (typeof token !== "string" || !token.startsWith(HDROP1_PREFIX)) {
    throw new Error("Invalid hdrop1_ prefix");
  }
  const bytes = base64urlDecode(token.slice(HDROP1_PREFIX.length));
  const envelope = JSON.parse(utf8String(bytes));
  if (!envelope || typeof envelope !== "object") {
    throw new Error("Malformed hdrop1_ envelope");
  }
  return envelope;
}

/**
 * Signs `HumanClaimV1` under `"hyphae/v2/human-claim\n"`, pads via `padBucket`,
 * and seals via RFC 9180 HPKE (`AES-256-GCM`) to `recipientEncJwk`.
 *
 * Returns `{ envelope, hdrop1, claim }` where `envelope` is completely opaque
 * (`{ v: 1, suite: "human.drop.v1", dropId, enc, ct }`).
 */
export async function sealHumanDrop({ claim, humanSeed32, recipientEncJwk, hpkeOptions = {} }) {
  if (!claim || typeof claim !== "object") {
    throw new Error("claim object is required");
  }
  if (!(humanSeed32 instanceof Uint8Array) || humanSeed32.length !== 32) {
    throw new Error("humanSeed32 must be a 32-byte Uint8Array");
  }

  const recipientPub32 = decodeOkpJwkBytes(recipientEncJwk, "X25519");
  const recipientEncKid = await jwkThumbprint(recipientEncJwk);
  const { kid: derivedHumanKid } = await ed25519KeypairFromSeed(humanSeed32);

  if (claim.v !== undefined && claim.v !== 1) {
    throw new Error(`Unsupported HumanClaimV1 version: ${claim.v}`);
  }
  if (claim.kind !== "directive" && claim.kind !== "secret") {
    throw new Error(`Unsupported claim kind: ${claim.kind}`);
  }
  if (typeof claim.humanId !== "string" || claim.humanId.length === 0) {
    throw new Error("claim.humanId is required");
  }
  if (claim.humanKid && claim.humanKid !== derivedHumanKid) {
    throw new Error("claim.humanKid does not match derived human Ed25519 key");
  }
  if (!Number.isInteger(claim.authEpoch) || claim.authEpoch < 1) {
    throw new Error("claim.authEpoch must be an integer >= 1");
  }
  if (typeof claim.body !== "string" || claim.body.length === 0) {
    throw new Error("claim.body must be a non-empty string");
  }
  if (!claim.audience || typeof claim.audience.nodeId !== "string" || claim.audience.nodeId.length === 0) {
    throw new Error("claim.audience.nodeId is required");
  }
  if (claim.audience.nodeEncKid && claim.audience.nodeEncKid !== recipientEncKid) {
    throw new Error("claim.audience.nodeEncKid does not match recipientEncJwk thumbprint");
  }

  const dropId = typeof claim.dropId === "string" ? claim.dropId : "";
  const claimId =
    typeof claim.claimId === "string" && claim.claimId.length > 0
      ? claim.claimId
      : base64urlEncode(randomBytes(16));

  const audience = {
    nodeId: claim.audience.nodeId,
    nodeEncKid: recipientEncKid,
  };
  if (typeof claim.audience.handle === "string" && claim.audience.handle.length > 0) {
    audience.handle = claim.audience.handle;
  }

  const normalizedClaim = {
    v: 1,
    kind: claim.kind,
    claimId,
    humanId: claim.humanId,
    humanKid: derivedHumanKid,
    authEpoch: claim.authEpoch,
    issuedAt: claim.issuedAt,
    expiresAt: claim.expiresAt,
    dropId,
    audience,
    body: claim.body,
  };

  if (claim.kind === "secret") {
    if (!claim.secretSpec || typeof claim.secretSpec !== "object") {
      throw new Error("claim.secretSpec is required for secret drops");
    }
    const nameCheck = validateSecretName(claim.secretSpec.name);
    if (!nameCheck.ok) {
      throw new Error(nameCheck.message);
    }
    if (isReservedSecretName(claim.secretSpec.name)) {
      throw new Error(`Reserved system secret name blocked: ${claim.secretSpec.name}`);
    }
    normalizedClaim.secretSpec = {
      name: claim.secretSpec.name,
      overwrite: Boolean(claim.secretSpec.overwrite),
    };
  }

  const payloadJson = toCanonicalJson(normalizedClaim);
  const sigBytes = await ed25519Sign(humanSeed32, utf8Bytes(HUMAN_CLAIM_DOMAIN + payloadJson));
  const signedPayload = {
    payload: payloadJson,
    sig: base64urlEncode(sigBytes),
  };

  const signedBytes = utf8Bytes(toCanonicalJson(signedPayload));
  let padded;
  try {
    padded = padBucket(signedBytes);
    const info = humanDropHpkeInfo(recipientEncKid, dropId);
    const aad = humanDropHpkeAad(recipientEncKid, dropId);
    const { enc, ciphertext } = await hpkeSealBase(recipientPub32, info, aad, padded, hpkeOptions);

    const envelope = {
      v: 1,
      suite: HUMAN_DROP_SUITE,
      dropId,
      enc: base64urlEncode(enc),
      ct: base64urlEncode(ciphertext),
    };
    const hdrop1 = encodeHdrop1(envelope);
    return { envelope, hdrop1, claim: normalizedClaim };
  } finally {
    zeroize(signedBytes);
    if (padded) zeroize(padded);
  }
}

/**
 * Opens and verifies an opaque `HumanDropEnvelopeV1` (or `hdrop1_` armored string)
 * using the target node's X25519 private key and expected human Ed25519 public key.
 */
export async function openHumanDrop({ envelopeOrToken, recipientPriv32, expectedHumanPub32 }) {
  const envelope =
    typeof envelopeOrToken === "string" ? decodeHdrop1(envelopeOrToken) : envelopeOrToken;

  if (!envelope || typeof envelope !== "object") {
    throw new Error("Invalid HumanDropEnvelopeV1");
  }
  if (envelope.v !== 1 || envelope.suite !== HUMAN_DROP_SUITE) {
    throw new Error(`Unsupported drop envelope v=${envelope.v} suite=${envelope.suite}`);
  }
  if (typeof envelope.dropId !== "string") {
    throw new Error("Envelope dropId must be a string");
  }
  const encBytes = base64urlDecode(envelope.enc);
  if (encBytes.length !== 32) {
    throw new Error("Envelope enc must be 32 bytes");
  }
  const ctBytes = base64urlDecode(envelope.ct);

  const recipientPub32 = await x25519PublicFromPrivate(recipientPriv32);
  const recipientEncKid = await jwkThumbprint({
    kty: "OKP",
    crv: "X25519",
    x: base64urlEncode(recipientPub32),
  });

  const info = humanDropHpkeInfo(recipientEncKid, envelope.dropId);
  const aad = humanDropHpkeAad(recipientEncKid, envelope.dropId);
  const padded = await hpkeOpenBase(recipientPriv32, encBytes, info, aad, ctBytes);
  let unpadded;
  try {
    unpadded = unpadBucket(padded);
    const signed = JSON.parse(utf8String(unpadded));
    if (!signed || typeof signed.payload !== "string" || typeof signed.sig !== "string") {
      throw new Error("Malformed inner SignedPayload");
    }

    const humanPub32 =
      expectedHumanPub32 instanceof Uint8Array
        ? expectedHumanPub32
        : decodeOkpJwkBytes(expectedHumanPub32, "Ed25519");

    const sigBytes = base64urlDecode(signed.sig);
    const sigOk = await ed25519Verify(
      humanPub32,
      utf8Bytes(HUMAN_CLAIM_DOMAIN + signed.payload),
      sigBytes
    );
    if (!sigOk) {
      throw new Error("Inner HumanClaimV1 Ed25519 signature verification failed");
    }

    const claim = JSON.parse(signed.payload);
    if (!claim || claim.v !== 1) {
      throw new Error("Unsupported inner HumanClaimV1 version");
    }
    if (claim.dropId !== envelope.dropId) {
      throw new Error("Inner claim dropId does not match outer envelope dropId");
    }
    if (!claim.audience || claim.audience.nodeEncKid !== recipientEncKid) {
      throw new Error("Inner claim audience.nodeEncKid does not match recipient key");
    }
    const expectedHumanKid = await jwkThumbprint({
      kty: "OKP",
      crv: "Ed25519",
      x: base64urlEncode(humanPub32),
    });
    if (claim.humanKid !== expectedHumanKid) {
      throw new Error("Inner claim humanKid does not match verifying human key");
    }
    return { claim, signed };
  } finally {
    zeroize(padded);
    if (unpadded) zeroize(unpadded);
  }
}

// ============================================================================
// Encrypted Directive Draft Prefill (`human.draft.v1`) & BiDi/Control Guard
// ============================================================================

/**
 * Validates human-reviewable directive draft text (or optional context):
 * - Rejects non-string, empty/whitespace-only, and Unicode code-point count > `maxChars`.
 * - Rejects C0/C1 control characters (allowing only `\t` and `\n`), unpaired UTF-16 surrogates,
 *   and BiDi / invisible formatting characters (`\u061C`, `\u200B-\u200F`, `\u2028-\u202F`,
 *   `\u2060-\u206F`, `\uFEFF`).
 */
export function validateDraftText(text, maxChars = MAX_HUMAN_DRAFT_CHARS) {
  if (typeof text !== "string") {
    throw new Error("Draft text must be a string");
  }
  if (!Number.isInteger(maxChars) || maxChars < 1) {
    throw new Error(`Invalid maxChars limit: ${maxChars}`);
  }
  if (text.trim().length === 0) {
    throw new Error("Draft text must not be empty or whitespace-only");
  }
  let count = 0;
  for (const ch of text) {
    count += 1;
    if (count > maxChars) {
      throw new Error(`Draft text exceeds maximum length of ${maxChars} characters`);
    }
    const cp = ch.codePointAt(0);
    // Reject C0 controls except \t (0x09) and \n (0x0A), plus DEL & C1 controls (0x7F..=0x9F).
    if (
      cp <= 0x08 ||
      cp === 0x0b ||
      cp === 0x0c ||
      cp === 0x0d ||
      (cp >= 0x0e && cp <= 0x1f) ||
      (cp >= 0x7f && cp <= 0x9f)
    ) {
      throw new Error(
        `Draft text contains disallowed control character U+${cp.toString(16).toUpperCase().padStart(4, "0")}`
      );
    }
    // Reject BiDi controls & invisible formatting characters.
    if (
      cp === 0x061c ||
      (cp >= 0x200b && cp <= 0x200f) ||
      (cp >= 0x2028 && cp <= 0x202f) ||
      (cp >= 0x2060 && cp <= 0x206f) ||
      cp === 0xfeff
    ) {
      throw new Error(
        `Draft text contains disallowed BiDi/invisible character U+${cp.toString(16).toUpperCase().padStart(4, "0")}`
      );
    }
    // Reject unpaired UTF-16 surrogates.
    if (cp >= 0xd800 && cp <= 0xdfff) {
      throw new Error("Draft text contains unpaired UTF-16 surrogate");
    }
  }
  return text;
}

export function humanDraftHpkeInfo(nodeId, recipientKid) {
  return utf8Bytes(`${HUMAN_DRAFT_INFO_PREFIX}${nodeId}\n${recipientKid}`);
}

export function humanDraftHpkeAad(nodeId, recipientKid) {
  return utf8Bytes(
    toCanonicalJson({
      v: 1,
      suite: HUMAN_DRAFT_SUITE,
      nodeId,
      recipientKid,
    })
  );
}

/**
 * Seals an untrusted agent-proposed directive draft (`human.draft.v1`) to the human's
 * Passkey-PRF derived X25519 encryption key via power-of-2 bucket padding + RFC 9180 HPKE.
 *
 * Returns `{ v: 1, suite: "human.draft.v1", recipientKid, enc, ct }`.
 */
export async function sealHumanDraft({ payload, recipientEncJwk, hpkeOptions = {} }) {
  if (!payload || typeof payload !== "object") {
    throw new Error("Draft payload object is required");
  }
  if (payload.v !== 1) {
    throw new Error(`Unsupported HumanDraftPayloadV1 version: ${payload.v}`);
  }
  if (!isValidNodeId(payload.nodeId)) {
    throw new Error(`Invalid draft nodeId: ${payload.nodeId}`);
  }
  validateDraftText(payload.text, MAX_HUMAN_DRAFT_CHARS);

  const normalizedPayload = {
    v: 1,
    nodeId: payload.nodeId,
    text: payload.text,
    createdAt: payload.createdAt,
  };
  if (payload.context !== undefined && payload.context !== null) {
    validateDraftText(payload.context, MAX_HUMAN_DRAFT_CONTEXT_CHARS);
    normalizedPayload.context = payload.context;
  }
  if (
    typeof normalizedPayload.createdAt !== "string" ||
    normalizedPayload.createdAt.trim().length === 0 ||
    !Number.isFinite(Date.parse(normalizedPayload.createdAt))
  ) {
    throw new Error("Draft payload createdAt must be a valid RFC 3339 timestamp");
  }

  const recipientPub32 = decodeOkpJwkBytes(recipientEncJwk, "X25519");
  const recipientKid = await jwkThumbprint(recipientEncJwk);

  const info = humanDraftHpkeInfo(normalizedPayload.nodeId, recipientKid);
  const aad = humanDraftHpkeAad(normalizedPayload.nodeId, recipientKid);

  const plainBytes = utf8Bytes(toCanonicalJson(normalizedPayload));
  let padded;
  try {
    padded = padBucket(plainBytes);
    const { enc, ciphertext } = await hpkeSealBase(recipientPub32, info, aad, padded, hpkeOptions);
    return {
      v: 1,
      suite: HUMAN_DRAFT_SUITE,
      recipientKid,
      enc: base64urlEncode(enc),
      ct: base64urlEncode(ciphertext),
    };
  } finally {
    zeroize(plainBytes);
    if (padded) zeroize(padded);
  }
}

/**
 * Opens and strictly validates a sealed `human.draft.v1` encrypted directive draft
 * using the human's Passkey-PRF derived X25519 private key. Always fails closed.
 */
export async function openHumanDraft({ encDraft, recipientPriv32, expectedNodeId }) {
  if (!encDraft || typeof encDraft !== "object") {
    throw new Error("Encrypted draft object is required");
  }
  if (encDraft.v !== 1 || encDraft.suite !== HUMAN_DRAFT_SUITE) {
    throw new Error(`Unsupported draft envelope v=${encDraft.v} suite=${encDraft.suite}`);
  }
  if (typeof encDraft.recipientKid !== "string" || encDraft.recipientKid.length === 0) {
    throw new Error("Encrypted draft missing recipientKid");
  }
  if (!isValidNodeId(expectedNodeId)) {
    throw new Error(`Invalid expectedNodeId: ${expectedNodeId}`);
  }
  const encBytes = base64urlDecode(encDraft.enc);
  if (encBytes.length !== 32) {
    throw new Error("Encrypted draft enc must be 32 bytes");
  }
  const ctBytes = base64urlDecode(encDraft.ct);
  if (ctBytes.length < 16) {
    throw new Error("Encrypted draft ciphertext shorter than AES-GCM tag");
  }

  const recipientPub32 = await x25519PublicFromPrivate(recipientPriv32);
  const recipientKid = await jwkThumbprint({
    kty: "OKP",
    crv: "X25519",
    x: base64urlEncode(recipientPub32),
  });
  if (encDraft.recipientKid !== recipientKid) {
    throw new Error("Encrypted draft recipientKid does not match Passkey encryption key");
  }

  const info = humanDraftHpkeInfo(expectedNodeId, recipientKid);
  const aad = humanDraftHpkeAad(expectedNodeId, recipientKid);

  const padded = await hpkeOpenBase(recipientPriv32, encBytes, info, aad, ctBytes);
  let unpadded;
  try {
    unpadded = unpadBucket(padded);
    const payload = JSON.parse(utf8String(unpadded));
    if (!payload || typeof payload !== "object") {
      throw new Error("Malformed decrypted draft payload");
    }
    if (payload.v !== 1) {
      throw new Error(`Unsupported decrypted draft payload version: ${payload.v}`);
    }
    if (payload.nodeId !== expectedNodeId) {
      throw new Error("Decrypted draft nodeId does not match expected target node");
    }
    if (
      typeof payload.createdAt !== "string" ||
      payload.createdAt.trim().length === 0 ||
      !Number.isFinite(Date.parse(payload.createdAt))
    ) {
      throw new Error("Decrypted draft createdAt is not a valid timestamp");
    }
    validateDraftText(payload.text, MAX_HUMAN_DRAFT_CHARS);

    const out = {
      v: 1,
      nodeId: payload.nodeId,
      text: payload.text,
      createdAt: payload.createdAt,
    };
    if (payload.context !== undefined && payload.context !== null) {
      validateDraftText(payload.context, MAX_HUMAN_DRAFT_CONTEXT_CHARS);
      out.context = payload.context;
    }
    return out;
  } finally {
    zeroize(padded);
    if (unpadded) zeroize(unpadded);
  }
}
