// Sealed transfers (SPEC.md section 15.1): signed by the sender's Ed25519 key, encrypted to the
// recipient's X25519 key with an ephemeral key, AES-256-GCM. Node builtins only (the router reads
// headers too).
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  diffieHellman,
  hkdfSync,
  randomBytes,
  type KeyObject,
} from "node:crypto";
import * as Schema from "effect/Schema";
import { isConnectorId, isHandle } from "../address.ts";
import { generatePrivateKey, isRawKey, publicKeyFromRaw, rawPublicKey, signValue, verifyPayload, type Signed } from "../identity/keys.ts";

export const TRANSFER_TYPES = ["files", "fork", "fork.result"] as const;
export type TransferType = (typeof TRANSFER_TYPES)[number];
export const MAX_TRANSFER_TTL_MS = 24 * 60 * 60 * 1000;

const HeaderPayload = Schema.Struct({
  v: Schema.Literal(1),
  id: Schema.String,
  type: Schema.Literals(TRANSFER_TYPES),
  from: Schema.String,
  to: Schema.String,
  toHandle: Schema.NullOr(Schema.String),
  createdAt: Schema.String,
  expiresAt: Schema.String,
  size: Schema.Number,
  sha256: Schema.String,
  nonce: Schema.String,
  ephemeralKey: Schema.String,
});
export type TransferHeader = typeof HeaderPayload.Type;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const TAG_BYTES = 16;

/** The header in a signed envelope, if it is well formed (the signature is not checked here). */
export function readHeader(signed: Signed): TransferHeader | null {
  let header: TransferHeader;
  try {
    const decoded = Schema.decodeUnknownOption(HeaderPayload)(JSON.parse(signed.payload));
    if (decoded._tag === "None") return null;
    header = decoded.value;
  } catch {
    return null;
  }
  const created = Date.parse(header.createdAt);
  const expires = Date.parse(header.expiresAt);
  const ok =
    UUID.test(header.id) &&
    isConnectorId(header.from) &&
    isConnectorId(header.to) &&
    (header.toHandle === null || isHandle(header.toHandle)) &&
    (header.type === "files") === (header.toHandle !== null) &&
    !Number.isNaN(created) &&
    !Number.isNaN(expires) &&
    expires > created &&
    expires - created <= MAX_TRANSFER_TTL_MS &&
    Number.isSafeInteger(header.size) &&
    header.size > TAG_BYTES &&
    /^[0-9a-f]{64}$/.test(header.sha256) &&
    Buffer.from(header.nonce, "base64url").length === 12 &&
    isRawKey(header.ephemeralKey);
  return ok ? header : null;
}

export const verifyHeader = (signed: Signed, senderSigningKey: KeyObject): boolean =>
  verifyPayload("transfer", signed.payload, signed.sig, senderSigningKey);

const aad = (header: Pick<TransferHeader, "id" | "type" | "from" | "to">): Buffer =>
  Buffer.from(`${header.id}\n${header.type}\n${header.from}\n${header.to}`, "utf8");

function contentKey(shared: Buffer, ephemeralPublic: string, recipientPublic: string, id: string): Buffer {
  const salt = Buffer.concat([Buffer.from(ephemeralPublic, "base64url"), Buffer.from(recipientPublic, "base64url")]);
  return Buffer.from(hkdfSync("sha256", shared, salt, `t3-mesh/v1/transfer\n${id}`, 32));
}

export interface SealInput {
  readonly id: string;
  readonly type: TransferType;
  readonly from: string;
  readonly to: string;
  readonly toHandle: string | null;
  readonly ttlMs: number;
}

export interface Sealed {
  readonly header: Signed;
  readonly ciphertext: Buffer;
}

export function seal(input: SealInput, plaintext: Buffer, senderSigning: KeyObject, recipientEncryptionKey: string, now = new Date()): Sealed {
  const ephemeral = generatePrivateKey("x25519");
  const ephemeralPublic = rawPublicKey(ephemeral);
  const shared = diffieHellman({ privateKey: ephemeral, publicKey: publicKeyFromRaw(recipientEncryptionKey, "x25519") });
  const key = contentKey(shared, ephemeralPublic, recipientEncryptionKey, input.id);
  const nonce = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(aad(input));
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
  const header: TransferHeader = {
    v: 1,
    id: input.id,
    type: input.type,
    from: input.from,
    to: input.to,
    toHandle: input.toHandle,
    createdAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + Math.min(input.ttlMs, MAX_TRANSFER_TTL_MS)).toISOString(),
    size: ciphertext.length,
    sha256: createHash("sha256").update(ciphertext).digest("hex"),
    nonce: nonce.toString("base64url"),
    ephemeralKey: ephemeralPublic,
  };
  return { header: signValue("transfer", header, senderSigning), ciphertext };
}

export class OpenError extends Error {
  readonly reason: "corrupt" | "bad_signature";
  constructor(reason: "corrupt" | "bad_signature", message: string) {
    super(message);
    this.reason = reason;
  }
}

/** Checks the sender's signature and the ciphertext, then decrypts with this connector's key. */
export function open(signed: Signed, ciphertext: Buffer, senderSigningKey: KeyObject, recipientEncryption: KeyObject): { header: TransferHeader; plaintext: Buffer } {
  const header = readHeader(signed);
  if (header === null) throw new OpenError("corrupt", "malformed transfer header");
  if (!verifyHeader(signed, senderSigningKey)) throw new OpenError("bad_signature", "the header is not signed by the sender's key");
  if (ciphertext.length !== header.size || createHash("sha256").update(ciphertext).digest("hex") !== header.sha256) {
    throw new OpenError("corrupt", "the ciphertext does not match the header");
  }
  const recipientPublic = rawPublicKey(recipientEncryption);
  const shared = diffieHellman({ privateKey: recipientEncryption, publicKey: publicKeyFromRaw(header.ephemeralKey, "x25519") });
  const decipher = createDecipheriv("aes-256-gcm", contentKey(shared, header.ephemeralKey, recipientPublic, header.id), Buffer.from(header.nonce, "base64url"));
  decipher.setAAD(aad(header));
  decipher.setAuthTag(ciphertext.subarray(ciphertext.length - TAG_BYTES));
  try {
    return { header, plaintext: Buffer.concat([decipher.update(ciphertext.subarray(0, ciphertext.length - TAG_BYTES)), decipher.final()]) };
  } catch {
    throw new OpenError("corrupt", "decryption failed (not sealed to this connector, or altered)");
  }
}
