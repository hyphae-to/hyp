// The connector's side of pairing (SPEC.md section 14.3) and its key file.
import type { KeyObject } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import * as Schema from "effect/Schema";
import { readPrivateFile } from "../privateFile.ts";
import { SignedSchema, openGrant, parsePairingCode, signBinding, verifyEntry } from "./grant.ts";
import { exportPrivateKey, fingerprint, generatePrivateKey, importPrivateKey, isRawKey, publicKeyFromRaw } from "./keys.ts";

const KeysFile = Schema.Struct({ v: Schema.Literal(1), signing: Schema.String, encryption: Schema.String });

export interface ConnectorKeys {
  readonly signing: KeyObject;
  readonly encryption: KeyObject;
}

export function readKeys(path: string): ConnectorKeys {
  const file = Schema.decodeUnknownSync(KeysFile)(JSON.parse(readPrivateFile(path)));
  return { signing: importPrivateKey(file.signing, "ed25519"), encryption: importPrivateKey(file.encryption, "x25519") };
}

/** Writes new keys; refuses to replace a key file (pairing again keeps the same keys). */
export function writeKeys(path: string, keys: ConnectorKeys): void {
  const file: typeof KeysFile.Type = { v: 1, signing: exportPrivateKey(keys.signing), encryption: exportPrivateKey(keys.encryption) };
  writeFileSync(path, JSON.stringify(file) + "\n", { mode: 0o600, flag: "wx" });
}

export const generateKeys = (): ConnectorKeys => ({
  signing: generatePrivateKey("ed25519"),
  encryption: generatePrivateKey("x25519"),
});

/** The existing keys at `path`, or new ones (not yet written). */
export const keysFor = (path: string): { readonly keys: ConnectorKeys; readonly created: boolean } =>
  existsSync(path) ? { keys: readKeys(path), created: false } : { keys: generateKeys(), created: true };

const PendingGrant = Schema.Struct({ grant: SignedSchema, adminKey: Schema.String });
const Paired = Schema.Struct({ connectorId: Schema.String, token: Schema.String, scopes: Schema.Array(Schema.String) });
const ErrorBody = Schema.Struct({ error: Schema.String, message: Schema.String });

export class PairingFailed extends Error {}

async function readBody(response: Response, what: string): Promise<unknown> {
  const body: unknown = await response.json().catch(() => null);
  if (response.ok) return body;
  const error = Schema.decodeUnknownOption(ErrorBody)(body);
  throw new PairingFailed(
    error._tag === "Some" ? `${what}: ${error.value.error}: ${error.value.message}` : `${what}: HTTP ${response.status}`,
  );
}

export interface PairResult {
  readonly connectorId: string;
  readonly token: string;
  readonly scopes: readonly string[];
  readonly adminKey: string;
}

/**
 * Pairs with the router using a code from `t3-mesh admin pair`: checks the grant against the admin
 * key the code names, binds `keys` to it, and returns the router token.
 */
export async function pairWithRouter(
  routerUrl: string,
  codeText: string,
  keys: ConnectorKeys,
  expectedConnectorId?: string,
): Promise<PairResult> {
  const code = parsePairingCode(codeText);
  if (code === null) throw new PairingFailed("not a pairing code (it starts with t3mp1_)");
  const base = new URL(routerUrl).origin;
  const pending = Schema.decodeUnknownSync(PendingGrant)(
    await readBody(await fetch(`${base}/v1/pairing/${code.grantId}`, { signal: AbortSignal.timeout(15_000) }), "fetching the grant"),
  );
  // The admin key comes from the router; the code says which one it must be.
  if (!isRawKey(pending.adminKey) || fingerprint(pending.adminKey) !== code.adminFingerprint) {
    throw new PairingFailed("the router's admin key is not the one this code was issued with");
  }
  const adminKey = publicKeyFromRaw(pending.adminKey, "ed25519");
  const grant = openGrant(pending.grant, adminKey);
  if (grant === null || grant.id !== code.grantId) throw new PairingFailed("the grant does not check against the admin key");
  // Checked before binding: a binding uses the grant up, even for the wrong connector.
  if (expectedConnectorId !== undefined && grant.connectorId !== expectedConnectorId) {
    throw new PairingFailed(`the code is for ${grant.connectorId}, but this connector is ${expectedConnectorId}`);
  }
  const binding = signBinding(grant, code, keys.signing, keys.encryption);
  if (!verifyEntry({ grant: pending.grant, binding }, adminKey).ok) {
    throw new PairingFailed("this code does not match the grant (wrong or mistyped code)");
  }
  const paired = Schema.decodeUnknownSync(Paired)(
    await readBody(
      await fetch(`${base}/v1/pairing/${code.grantId}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ binding }),
        signal: AbortSignal.timeout(15_000),
      }),
      "pairing",
    ),
  );
  if (paired.connectorId !== grant.connectorId) throw new PairingFailed("the router paired a different connector id");
  return { connectorId: paired.connectorId, token: paired.token, scopes: grant.scopes, adminKey: pending.adminKey };
}

export const readCodeFromStdin = (): string => readFileSync(0, "utf8").trim();
