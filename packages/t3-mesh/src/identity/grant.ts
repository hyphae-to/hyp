// Grants, bindings, entries, revocations and pairing codes (SPEC.md sections 14.2-14.3).
import { hkdfSync, randomBytes, randomUUID, type KeyObject } from "node:crypto";
import * as Schema from "effect/Schema";
import { isConnectorId } from "../address.ts";
import { expandScopes } from "./scopes.ts";
import {
  fingerprint,
  isRawKey,
  privateKeyFromSeed,
  publicKeyFromRaw,
  rawPublicKey,
  signValue,
  verifyPayload,
  type Signed,
} from "./keys.ts";

export const SignedSchema = Schema.Struct({ payload: Schema.String, sig: Schema.String });

const GrantPayload = Schema.Struct({
  v: Schema.Literal(1),
  id: Schema.String,
  connectorId: Schema.String,
  scopes: Schema.Array(Schema.String),
  pairingKey: Schema.String,
  issuedAt: Schema.String,
  pairBy: Schema.String,
});
export type Grant = typeof GrantPayload.Type;

const BindingPayload = Schema.Struct({
  v: Schema.Literal(1),
  grantId: Schema.String,
  connectorId: Schema.String,
  signingKey: Schema.String,
  encryptionKey: Schema.String,
  boundAt: Schema.String,
});
export type Binding = typeof BindingPayload.Type;

const RevocationPayload = Schema.Struct({
  v: Schema.Literal(1),
  connectorId: Schema.String,
  grantId: Schema.String,
  revokedAt: Schema.String,
});
export type Revocation = typeof RevocationPayload.Type;

export const SignedBindingSchema = Schema.Struct({
  payload: Schema.String,
  pairingSig: Schema.String,
  selfSig: Schema.String,
});
export type SignedBinding = typeof SignedBindingSchema.Type;

export const EntrySchema = Schema.Struct({ grant: SignedSchema, binding: SignedBindingSchema });
export type Entry = typeof EntrySchema.Type;

/** A connector as a valid entry describes it. */
export interface Identity {
  readonly connectorId: string;
  readonly grantId: string;
  readonly issuedAt: string;
  readonly scopes: readonly string[];
  readonly signingKey: string;
  readonly encryptionKey: string;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const isTime = (value: string): boolean => !Number.isNaN(Date.parse(value));

function decodeJson<A>(schema: Schema.Codec<A>, text: string): A | null {
  try {
    const decoded = Schema.decodeUnknownOption(schema)(JSON.parse(text));
    return decoded._tag === "Some" ? decoded.value : null;
  } catch {
    return null;
  }
}

const decodeGrant = (payload: string): Grant | null => {
  const grant = decodeJson(GrantPayload, payload);
  return grant !== null &&
    UUID.test(grant.id) &&
    isConnectorId(grant.connectorId) &&
    isRawKey(grant.pairingKey) &&
    isTime(grant.issuedAt) &&
    isTime(grant.pairBy)
    ? grant
    : null;
};

const decodeBinding = (payload: string): Binding | null => {
  const binding = decodeJson(BindingPayload, payload);
  return binding !== null &&
    isRawKey(binding.signingKey) &&
    isRawKey(binding.encryptionKey) &&
    isTime(binding.boundAt)
    ? binding
    : null;
};

/** The grant, if `signed` is one the admin key signed. */
export function openGrant(signed: Signed, adminKey: KeyObject): Grant | null {
  return verifyPayload("grant", signed.payload, signed.sig, adminKey) ? decodeGrant(signed.payload) : null;
}

export function openRevocation(signed: Signed, adminKey: KeyObject): Revocation | null {
  if (!verifyPayload("revocation", signed.payload, signed.sig, adminKey)) return null;
  const revocation = decodeJson(RevocationPayload, signed.payload);
  return revocation !== null && isConnectorId(revocation.connectorId) && UUID.test(revocation.grantId) ? revocation : null;
}

/** The identity an entry describes, or why it is not valid. */
export function verifyEntry(entry: Entry, adminKey: KeyObject): { ok: true; identity: Identity } | { ok: false; reason: string } {
  const grant = openGrant(entry.grant, adminKey);
  if (grant === null) return { ok: false, reason: "grant signature does not check against the admin key" };
  const binding = decodeBinding(entry.binding.payload);
  if (binding === null) return { ok: false, reason: "binding is malformed" };
  if (binding.grantId !== grant.id || binding.connectorId !== grant.connectorId) {
    return { ok: false, reason: "binding is for another grant" };
  }
  if (!verifyPayload("binding", entry.binding.payload, entry.binding.pairingSig, publicKeyFromRaw(grant.pairingKey, "ed25519"))) {
    return { ok: false, reason: "binding was not signed with the pairing key" };
  }
  if (!verifyPayload("binding-self", entry.binding.payload, entry.binding.selfSig, publicKeyFromRaw(binding.signingKey, "ed25519"))) {
    return { ok: false, reason: "binding was not signed with its own signing key" };
  }
  if (Date.parse(binding.boundAt) > Date.parse(grant.pairBy)) return { ok: false, reason: "bound after the pairing window" };
  return {
    ok: true,
    identity: {
      connectorId: grant.connectorId,
      grantId: grant.id,
      issuedAt: grant.issuedAt,
      scopes: grant.scopes,
      signingKey: binding.signingKey,
      encryptionKey: binding.encryptionKey,
    },
  };
}

// ---- pairing codes ----

const CODE_PREFIX = "t3mp1_";
const SECRET_BYTES = 20;

export interface PairingCode {
  readonly grantId: string;
  readonly secret: Buffer;
  /** Fingerprint of the admin key that signed the grant. */
  readonly adminFingerprint: string;
}

const uuidBytes = (id: string): Buffer => Buffer.from(id.replaceAll("-", ""), "hex");
const uuidFromBytes = (bytes: Buffer): string => {
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
};

export const formatPairingCode = (code: PairingCode): string =>
  CODE_PREFIX +
  Buffer.concat([uuidBytes(code.grantId), code.secret, Buffer.from(code.adminFingerprint, "hex")]).toString("base64url");

export function parsePairingCode(text: string): PairingCode | null {
  const trimmed = text.trim();
  if (!trimmed.startsWith(CODE_PREFIX)) return null;
  const bytes = Buffer.from(trimmed.slice(CODE_PREFIX.length), "base64url");
  if (bytes.length !== 16 + SECRET_BYTES + 8) return null;
  return {
    grantId: uuidFromBytes(bytes.subarray(0, 16)),
    secret: bytes.subarray(16, 16 + SECRET_BYTES),
    adminFingerprint: bytes.subarray(16 + SECRET_BYTES).toString("hex"),
  };
}

/** The Ed25519 key a pairing code stands for. */
export const pairingKey = (secret: Buffer, grantId: string): KeyObject =>
  privateKeyFromSeed(Buffer.from(hkdfSync("sha256", secret, "t3-mesh pairing v1", grantId, 32)), "ed25519");

// ---- signing (admin and connector side) ----

export interface IssuedGrant {
  readonly grant: Grant;
  readonly signed: Signed;
  readonly code: string;
}

/** Signs a grant for `connectorId` (scopes expanded and checked here, so a grant never lists shorthand) and makes its pairing code. */
export function issueGrant(
  adminKey: KeyObject,
  connectorId: string,
  scopes: readonly string[],
  ttlMs: number,
  now = new Date(),
): IssuedGrant {
  if (!isConnectorId(connectorId)) throw new Error(`invalid connector id ${connectorId}`);
  const id = randomUUID();
  const secret = randomBytes(SECRET_BYTES);
  const grant: Grant = {
    v: 1,
    id,
    connectorId,
    scopes: expandScopes(scopes),
    pairingKey: rawPublicKey(pairingKey(secret, id)),
    issuedAt: now.toISOString(),
    pairBy: new Date(now.getTime() + ttlMs).toISOString(),
  };
  return {
    grant,
    signed: signValue("grant", grant, adminKey),
    code: formatPairingCode({ grantId: id, secret, adminFingerprint: fingerprint(rawPublicKey(adminKey)) }),
  };
}

/** The binding a pairing connector sends: its new public keys, signed with the pairing key and its signing key. */
export function signBinding(
  grant: Grant,
  code: PairingCode,
  signingKey: KeyObject,
  encryptionKey: KeyObject,
  now = new Date(),
): SignedBinding {
  const binding: Binding = {
    v: 1,
    grantId: grant.id,
    connectorId: grant.connectorId,
    signingKey: rawPublicKey(signingKey),
    encryptionKey: rawPublicKey(encryptionKey),
    boundAt: now.toISOString(),
  };
  const pairing = signValue("binding", binding, pairingKey(code.secret, grant.id));
  return {
    payload: pairing.payload,
    pairingSig: pairing.sig,
    selfSig: signValue("binding-self", binding, signingKey).sig,
  };
}

export function signRevocation(adminKey: KeyObject, connectorId: string, grantId: string, now = new Date()): Signed {
  const revocation: Revocation = { v: 1, connectorId, grantId, revokedAt: now.toISOString() };
  return signValue("revocation", revocation, adminKey);
}
