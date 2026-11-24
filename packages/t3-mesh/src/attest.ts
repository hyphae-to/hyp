// Role-decision attestations for the bayfold work-record writer (docs/builder-subscriptions.md E6).
//
// The writer (monorepo tools/work_records.py, slice A) accepts a role's decision only from a verified
// origin (`Trust.<role>_origins`). A dedicated GitHub identity is one kind; this is the other: the
// connector, which already verifies which T3 thread is calling it (SPEC.md section 3), signs with its
// paired Ed25519 identity key that a thread configured for a role asked to attest one exact request.
// The writer's MeshAttestationOrigin checks the signature against the connector's pinned public key,
// the thread, and that record ID, envelope digest and work match the request it is deciding.
//
// It proves which thread asked, not that the decision is wise. It adds no record kind and no store:
// the line travels in the request comment, next to the request's own JSON block. Nothing is attested
// unless the operator configured the role's threads; an unconfigured connector refuses.
import type { KeyObject } from "node:crypto";
import * as Schema from "effect/Schema";
import { isWorkReference, scanJson } from "./github/records.ts";
import { isSmallOrderKey, isSmallOrderPoint, rawPublicKey, signPayload, verifyBytes } from "./identity/keys.ts";

export const ATTEST_PREFIX = "bayfold-attest: v1";
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const ROLE = /^[a-z][a-z_]{0,31}$/;
const B64URL = /^[A-Za-z0-9_-]+$/;
const ATTEST_MARK = "bayfold-attest:";
const EDGE = /^[ \t\r]+|[ \t\r]+$/g;
/** The signer's format (Date.toISOString), the only one accepted. */
const ISSUED_AT = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/;
const PAYLOAD_KEYS = ["connector", "envelope_sha256", "issuedAt", "kind", "record_id", "role", "threadId", "v", "work"].join();
const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
/** Longest payload field: about twice a real payload's, and too short for nesting that can exhaust a parser. */
export const MAX_PAYLOAD_CHARS = 1024;

/** The threads configured for `role`; own properties only, so "constructor" and the like have none. */
export function attestThreads(roles: Readonly<Record<string, readonly string[]>>, role: string): readonly string[] {
  return Object.hasOwn(roles, role) ? (roles[role] ?? []) : [];
}

/** What the connector signs: everything the writer needs to bind the attestation to one request. */
export const AttestationPayload = Schema.Struct({
  v: Schema.Literal(1),
  kind: Schema.Literal("bayfold-decision"),
  role: Schema.String,
  connector: Schema.String,
  threadId: Schema.String,
  record_id: Schema.String,
  /** monorepo work_records.envelope_digest(env): SHA-256 of the canonical envelope. */
  envelope_sha256: Schema.String,
  work: Schema.String,
  issuedAt: Schema.String,
});
export type AttestationPayload = typeof AttestationPayload.Type;
const decodePayload = Schema.decodeUnknownOption(AttestationPayload);

export type AttestInput = Pick<AttestationPayload, "role" | "record_id" | "envelope_sha256" | "work">;

/** Why the inputs cannot be attested, or null. */
export function checkAttestInput(input: AttestInput): string | null {
  if (!ROLE.test(input.role)) return "role must be lowercase, e.g. lead";
  if (!UUID.test(input.record_id)) return "recordId must be a lowercase UUID";
  if (!SHA256.test(input.envelope_sha256)) return "envelopeSha256 must be 64 lowercase hex characters";
  // The receiver's bound: only work E routes is attested, and the payload stays within A's string limits.
  if (!isWorkReference(input.work)) return "work must be owner/repo#issue within GitHub's limits (owner 39, repository 100, issue 9 digits)";
  return null;
}

/**
 * The line to append to the request comment: `bayfold-attest: v1 <payload> <signature>`, both
 * base64url. The payload is the exact JSON that was signed as SignatureKind `attestation`, i.e. the
 * bytes `t3-mesh/v1/attestation\n<payload JSON>`.
 */
export function attestationLine(payload: AttestationPayload, key: KeyObject): string {
  const json = JSON.stringify(payload);
  return `${ATTEST_PREFIX} ${Buffer.from(json, "utf8").toString("base64url")} ${signPayload("attestation", json, key)}`;
}

/** Whether a payload fits the verifiers' MAX_PAYLOAD_CHARS once encoded; the signer refuses one that does not. */
export const payloadFits = (payload: AttestationPayload): boolean =>
  Buffer.from(JSON.stringify(payload), "utf8").toString("base64url").length <= MAX_PAYLOAD_CHARS;

export type Verified =
  | { readonly ok: true; readonly payload: AttestationPayload }
  | { readonly ok: false; readonly reason: string };

/** The bytes of canonical unpadded base64url text, or null: one encoding per value. */
export function canonicalBase64url(text: string): Buffer | null {
  if (!B64URL.test(text) || text.length % 4 === 1) return null;
  const bytes = Buffer.from(text, "base64url");
  return bytes.toString("base64url") === text ? bytes : null;
}

const refuse = (reason: string): Verified => ({ ok: false, reason });

/**
 * The payload of the one well-formed attestation line in `body` signed by `key`. This is the wire
 * format the writer's Python Origin (docs/reference/mesh_attestation_origin.py, read_attestation)
 * implements too; src/fixtures/attestation-vector.json pins their agreement case by case:
 * - lines split on "\n" and trimmed of spaces, tabs and "\r"; exactly one starts `bayfold-attest:`
 *   and it is exactly `bayfold-attest: v1 <payload> <signature>`, single spaces;
 * - both fields canonical unpadded base64url, the payload field at most MAX_PAYLOAD_CHARS; the
 *   signature is 64 bytes, over the raw payload bytes, by a key that is not of small order, with an
 *   R that is not of small order;
 * - the payload is strict UTF-8 JSON, an object with exactly the payload keys, no duplicates, `v`
 *   the integer 1 (not 1.0 or true), every other value a string, `issuedAt` in the signer's format
 *   with a year from 0001 (Python's datetime has no year 0).
 */
export function readAttestation(body: string, key: KeyObject): Verified {
  const lines = body
    .split("\n")
    .map((line) => line.replace(EDGE, ""))
    .filter((line) => line.startsWith(ATTEST_MARK));
  if (lines.length !== 1) return refuse(`expected exactly one attestation line, found ${lines.length}`);
  const parts = (lines[0] ?? "").split(" ");
  if (parts.length !== 4 || `${parts[0]} ${parts[1]}` !== ATTEST_PREFIX) return refuse("malformed attestation line");
  if ((parts[2] ?? "").length > MAX_PAYLOAD_CHARS) return refuse("malformed attestation line");
  const payloadBytes = canonicalBase64url(parts[2] ?? "");
  const signature = canonicalBase64url(parts[3] ?? "");
  if (payloadBytes === null || signature === null || signature.length !== 64) return refuse("malformed attestation line");
  if (isSmallOrderKey(rawPublicKey(key))) return refuse("the pinned key is of small order");
  // A small-order R verifies under some backends (OpenSSL 4) and not others (Node's 3.5): refuse it.
  if (isSmallOrderPoint(signature.subarray(0, 32))) return refuse("signature does not verify with the pinned connector key");
  if (!verifyBytes("attestation", payloadBytes, signature, key)) return refuse("signature does not verify with the pinned connector key");
  let json: string;
  let parsed: unknown;
  try {
    json = utf8.decode(payloadBytes);
    parsed = JSON.parse(json);
  } catch {
    return refuse("attestation payload is not UTF-8 JSON");
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return refuse("not a v1 bayfold decision attestation");
  const scan = scanJson(json);
  if (scan.duplicate || Object.keys(parsed).sort().join() !== PAYLOAD_KEYS || scan.topLevel.get("v") !== "1") {
    return refuse("not a v1 bayfold decision attestation");
  }
  const decoded = decodePayload(parsed);
  if (decoded._tag === "None") return refuse("not a v1 bayfold decision attestation");
  const issued = Date.parse(decoded.value.issuedAt);
  if (
    !ISSUED_AT.test(decoded.value.issuedAt) ||
    decoded.value.issuedAt.startsWith("0000") ||
    !Number.isFinite(issued) ||
    new Date(issued).toISOString() !== decoded.value.issuedAt
  ) {
    return refuse("attestation time is not a timestamp");
  }
  return { ok: true, payload: decoded.value };
}

/**
 * Reference verification of what a comment body alone can show: the one well-formed line
 * (readAttestation), signed by `key`, bound to this request and a configured thread. The writer's
 * Origin also checks what needs the issue: freshness against the comment's server time, an unedited
 * comment, the first request comment carrying the record, and no founder revocation of it.
 */
export function verifyAttestation(
  body: string,
  key: KeyObject,
  expect: { readonly role: string; readonly connector: string; readonly threadIds: readonly string[] } & Omit<AttestInput, "role">,
): Verified {
  const read = readAttestation(body, key);
  if (!read.ok) return read;
  const { payload } = read;
  if (payload.role !== expect.role) return refuse(`attested role ${payload.role}, not ${expect.role}`);
  if (payload.connector !== expect.connector) return refuse("attested by another connector");
  if (!expect.threadIds.includes(payload.threadId)) return refuse(`thread ${payload.threadId} is not a configured ${expect.role} thread`);
  if (payload.record_id !== expect.record_id) return refuse("attests another record");
  if (payload.envelope_sha256 !== expect.envelope_sha256) return refuse("attests other content");
  if (payload.work !== expect.work) return refuse("attests another work item");
  return { ok: true, payload };
}
