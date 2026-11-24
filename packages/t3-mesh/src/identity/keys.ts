// Keys and signatures (SPEC.md section 14.1). Ed25519 for signing, X25519 for encryption; public
// keys travel as raw 32-byte keys in base64url, private keys are stored as PKCS#8 DER.
// Node builtins only, so the router can use it.
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify,
  type KeyObject,
} from "node:crypto";

export type KeyType = "ed25519" | "x25519";

const JWK_CURVE: Readonly<Record<KeyType, string>> = { ed25519: "Ed25519", x25519: "X25519" };
/** PKCS#8 DER prefix for a raw 32-byte private key (RFC 8410). */
const PKCS8_PREFIX: Readonly<Record<KeyType, string>> = {
  ed25519: "302e020100300506032b657004220420",
  x25519: "302e020100300506032b656e04220420",
};

const RAW_KEY = /^[A-Za-z0-9_-]{43}$/;

export const isRawKey = (value: string): boolean => RAW_KEY.test(value) && Buffer.from(value, "base64url").length === 32;

/** The raw public key (base64url) of a public or private key. */
export function rawPublicKey(key: KeyObject): string {
  const jwk = (key.type === "private" ? createPublicKey(key) : key).export({ format: "jwk" });
  if (typeof jwk.x !== "string") throw new Error("not an OKP key");
  return jwk.x;
}

export function publicKeyFromRaw(raw: string, type: KeyType): KeyObject {
  if (!isRawKey(raw)) throw new Error("a public key must be 32 bytes in base64url");
  return createPublicKey({ key: { kty: "OKP", crv: JWK_CURVE[type], x: raw }, format: "jwk" });
}

/** A private key from its 32 raw bytes (for Ed25519, the seed). */
export function privateKeyFromSeed(seed: Buffer, type: KeyType): KeyObject {
  if (seed.length !== 32) throw new Error("a private key seed must be 32 bytes");
  return createPrivateKey({
    key: Buffer.concat([Buffer.from(PKCS8_PREFIX[type], "hex"), seed]),
    format: "der",
    type: "pkcs8",
  });
}

export const generatePrivateKey = (type: KeyType): KeyObject =>
  type === "ed25519" ? generateKeyPairSync("ed25519").privateKey : generateKeyPairSync("x25519").privateKey;

export const exportPrivateKey = (key: KeyObject): string => key.export({ format: "der", type: "pkcs8" }).toString("base64url");

export function importPrivateKey(value: string, type: KeyType): KeyObject {
  const key = createPrivateKey({ key: Buffer.from(value, "base64url"), format: "der", type: "pkcs8" });
  if (key.asymmetricKeyType !== type) throw new Error(`expected an ${type} private key, got ${key.asymmetricKeyType}`);
  return key;
}

const ED25519_P = (1n << 255n) - 19n;
/** y-coordinates of the eight small-order Ed25519 points (libsodium's blocklist), modulo p. */
const SMALL_ORDER_Y = new Set([
  0n,
  1n,
  ED25519_P - 1n,
  BigInt("0x05fc536d880238b13933c6d305acdfd5f098eff289f4c345b027b2c28f95e826"),
  BigInt("0x7a03ac9277fdc74ec6cc392cfa53202a0f67100d760b3cba4fd84d3d706a17c7"),
]);

/**
 * Whether a raw Ed25519 public key (base64url) encodes a small-order point, in any encoding (sign bit
 * and non-canonical y included). Such a key verifies forged signatures under some libraries, so a
 * pinned verifier must refuse it rather than rely on its backend.
 */
export function isSmallOrderKey(raw: string): boolean {
  return isSmallOrderPoint(Buffer.from(raw, "base64url"));
}

/** Whether 32 bytes encode a small-order Ed25519 point (a public key, or a signature's R). */
export function isSmallOrderPoint(bytes: Uint8Array): boolean {
  if (bytes.length !== 32) return true;
  let y = 0n;
  for (let i = 31; i >= 0; i -= 1) y = (y << 8n) | BigInt(bytes[i] ?? 0);
  y &= (1n << 255n) - 1n;
  return SMALL_ORDER_Y.has(y % ED25519_P);
}

/** First 8 bytes of the SHA-256 of the raw public key, in hex. */
export const fingerprint = (raw: string): string =>
  createHash("sha256").update(Buffer.from(raw, "base64url")).digest("hex").slice(0, 16);

/** A JSON payload as the exact string that was signed, and its signature. */
export interface Signed {
  readonly payload: string;
  readonly sig: string;
}

/** `attestation`: a role decision for the bayfold work-record writer (src/attest.ts). */
export type SignatureKind = "grant" | "binding" | "binding-self" | "revocation" | "transfer" | "attestation";

const signedBytes = (kind: SignatureKind, payload: string): Buffer => Buffer.from(`t3-mesh/v1/${kind}\n${payload}`, "utf8");

export const signPayload = (kind: SignatureKind, payload: string, key: KeyObject): string =>
  sign(null, signedBytes(kind, payload), key).toString("base64url");

export function signValue(kind: SignatureKind, value: unknown, key: KeyObject): Signed {
  const payload = JSON.stringify(value);
  return { payload, sig: signPayload(kind, payload, key) };
}

/** Whether `sig` is `key`'s signature of the raw `payload` bytes as `kind`. Never throws. */
export function verifyBytes(kind: SignatureKind, payload: Uint8Array, sig: Uint8Array, key: KeyObject): boolean {
  try {
    return verify(null, Buffer.concat([Buffer.from(`t3-mesh/v1/${kind}\n`, "utf8"), payload]), key, sig);
  } catch {
    return false;
  }
}

/** Whether `sig` is `key`'s signature of `payload` as `kind`. Never throws. */
export function verifyPayload(kind: SignatureKind, payload: string, sig: string, key: KeyObject): boolean {
  try {
    return verify(null, signedBytes(kind, payload), key, Buffer.from(sig, "base64url"));
  } catch {
    return false;
  }
}
