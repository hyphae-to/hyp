import { createHash, type KeyObject } from "node:crypto";
import {
  exportPrivateKey,
  fingerprint,
  generatePrivateKey,
  importPrivateKey,
  isRawKey,
  isSmallOrderKey,
  publicKeyFromRaw,
  rawPublicKey,
  signValue,
  verifyPayload,
  type Signed,
} from "./core/identity/keys.ts";
import { object } from "./protocol.ts";
import { readSecret, writeSecretDetailed } from "./secrets.ts";

export interface ConnectorKeys {
  readonly signingKey: KeyObject;
  readonly encryptionKey: KeyObject;
  readonly signingPublic: string;
  readonly encryptionPublic: string;
  readonly fingerprint: string;
}

export interface KeyRegistrationPayload {
  readonly v: 1;
  readonly connectorId: string;
  readonly signingKey: string;
  readonly encryptionKey: string;
}

export interface KeyRegistration {
  readonly signingKey: string;
  readonly encryptionKey: string;
  readonly proof: Signed;
}

export type KeyRegistrationVerification =
  | { readonly ok: true; readonly signingKey: string; readonly encryptionKey: string; readonly proof: Signed }
  | { readonly ok: false; readonly message: string };

/** Deterministic secret names scoped per connector so multi-connector setups never collide. */
export function connectorKeySecretNames(connectorId: string): { readonly signing: string; readonly encryption: string } {
  const hash = createHash("sha256").update(connectorId).digest("hex").slice(0, 12);
  return {
    signing: `id-sign-${hash}`,
    encryption: `id-enc-${hash}`,
  };
}

function isMissingSecretError(error: unknown, name: string): boolean {
  return error instanceof Error && error.message.startsWith(`Missing secret "${name}"`);
}

function isAllZeroKey(raw: string): boolean {
  return Buffer.from(raw, "base64url").every((byte) => byte === 0);
}

function toConnectorKeys(signingKey: KeyObject, encryptionKey: KeyObject): ConnectorKeys {
  const signingPublic = rawPublicKey(signingKey);
  const encryptionPublic = rawPublicKey(encryptionKey);
  return {
    signingKey,
    encryptionKey,
    signingPublic,
    encryptionPublic,
    fingerprint: fingerprint(signingPublic),
  };
}

/** Creates an in-memory keypair without touching the secret store (for synthetic non-filesystem tests). */
export function createEphemeralConnectorKeys(): ConnectorKeys {
  return toConnectorKeys(generatePrivateKey("ed25519"), generatePrivateKey("x25519"));
}

/**
 * Loads or generates this connector's persistent Ed25519 signing key and X25519 encryption key
 * via the Hyphae secret store (OS Keychain / Linux Secret Service / private local file store).
 * Private keys are never written into `connector.json` or exposed in prompts.
 */
export function loadOrCreateConnectorKeys(configDir: string, connectorId: string): ConnectorKeys {
  const names = connectorKeySecretNames(connectorId);

  let signingKey: KeyObject;
  try {
    signingKey = importPrivateKey(readSecret(names.signing, configDir), "ed25519");
  } catch (error) {
    if (!isMissingSecretError(error, names.signing)) throw error;
    signingKey = generatePrivateKey("ed25519");
    writeSecretDetailed(names.signing, exportPrivateKey(signingKey), configDir);
  }

  let encryptionKey: KeyObject;
  try {
    encryptionKey = importPrivateKey(readSecret(names.encryption, configDir), "x25519");
  } catch (error) {
    if (!isMissingSecretError(error, names.encryption)) throw error;
    encryptionKey = generatePrivateKey("x25519");
    writeSecretDetailed(names.encryption, exportPrivateKey(encryptionKey), configDir);
  }

  return toConnectorKeys(signingKey, encryptionKey);
}

/** Creates a self-signed key registration proving possession of `keys.signingKey` for `connectorId`. */
export function createKeyRegistration(connectorId: string, keys: ConnectorKeys): KeyRegistration {
  const payload: KeyRegistrationPayload = {
    v: 1,
    connectorId,
    signingKey: keys.signingPublic,
    encryptionKey: keys.encryptionPublic,
  };
  return {
    signingKey: keys.signingPublic,
    encryptionKey: keys.encryptionPublic,
    proof: signValue("key-reg", payload, keys.signingKey),
  };
}

/** Verifies a key registration payload and self-signature against `connectorId`. */
export function verifyKeyRegistration(connectorId: string, reg: unknown): KeyRegistrationVerification {
  if (!object(reg)) return { ok: false, message: "expected key registration object" };
  const { signingKey, encryptionKey, proof } = reg;
  if (typeof signingKey !== "string" || typeof encryptionKey !== "string") {
    return { ok: false, message: "expected signingKey and encryptionKey strings" };
  }
  if (!isRawKey(signingKey) || isSmallOrderKey(signingKey)) {
    return { ok: false, message: "invalid Ed25519 signingKey" };
  }
  if (!isRawKey(encryptionKey) || isAllZeroKey(encryptionKey)) {
    return { ok: false, message: "invalid X25519 encryptionKey" };
  }
  if (!object(proof) || typeof proof.payload !== "string" || typeof proof.sig !== "string") {
    return { ok: false, message: "expected proof {payload, sig}" };
  }
  let signingPub: KeyObject;
  try {
    signingPub = publicKeyFromRaw(signingKey, "ed25519");
    publicKeyFromRaw(encryptionKey, "x25519");
  } catch {
    return { ok: false, message: "invalid public key encoding" };
  }
  if (!verifyPayload("key-reg", proof.payload, proof.sig, signingPub)) {
    return { ok: false, message: "key registration signature is invalid" };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(proof.payload);
  } catch {
    return { ok: false, message: "key registration proof payload is not valid JSON" };
  }
  if (
    !object(parsed) ||
    parsed.v !== 1 ||
    parsed.connectorId !== connectorId ||
    parsed.signingKey !== signingKey ||
    parsed.encryptionKey !== encryptionKey
  ) {
    return { ok: false, message: "key registration payload does not match connector and keys" };
  }
  return {
    ok: true,
    signingKey,
    encryptionKey,
    proof: { payload: proof.payload, sig: proof.sig },
  };
}
