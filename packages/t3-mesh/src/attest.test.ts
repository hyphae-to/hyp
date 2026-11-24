import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, sign } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { ATTEST_PREFIX, attestationLine, attestThreads, checkAttestInput, MAX_PAYLOAD_CHARS, payloadFits, verifyAttestation, type AttestationPayload } from "./attest.ts";
import { isSmallOrderKey, privateKeyFromSeed, publicKeyFromRaw, rawPublicKey } from "./identity/keys.ts";
import { recordKeys } from "./github/records.ts";

// Role-decision attestations (docs/builder-subscriptions.md E6). The request and its envelope digest
// come from slice A's real tools/work_records.py (render() and envelope_digest() at 4e9c83b508), and
// the key from a fixed seed, so src/fixtures/attestation-vector.json is reproducible and the writer's
// Python Origin can be tested on the same bytes.

const REQUEST_BODY = "Work request: work.assigned on bayfold/monorepo#4045, operation 11111111, step 1.\n\n<!-- bayfold-request:v1 -->\n```json\n{\n  \"kind\": \"work.assigned\",\n  \"operation_id\": \"11111111-1111-4111-8111-111111111111\",\n  \"payload\": {\n    \"owner\": \"builder-4045\",\n    \"prs\": [\n      5001\n    ],\n    \"task_generation\": 2\n  },\n  \"previous_record_id\": null,\n  \"record_id\": \"22222222-2222-4222-8222-222222222222\",\n  \"schema\": 1,\n  \"sequence\": 1,\n  \"work\": \"bayfold/monorepo#4045\"\n}\n```\n\n<!-- agent:builder-4045 -->\n";
const DIGEST = "22f5fe4599a2363234dff7bf7399f07f40875c0de62f2f829383ed84beacb225";
const RECORD = "22222222-2222-4222-8222-222222222222";
const WORK = "bayfold/monorepo#4045";
const seed = createHash("sha256").update("t3-mesh attestation test vector v1").digest();
const key = privateKeyFromSeed(seed, "ed25519");
const publicKey = publicKeyFromRaw(rawPublicKey(key), "ed25519");
const payload: AttestationPayload = {
  v: 1,
  kind: "bayfold-decision",
  role: "lead",
  connector: "bogdan@solace",
  threadId: "bb2681a8-8183-4fe2-921f-96ab9e53de21",
  record_id: RECORD,
  envelope_sha256: DIGEST,
  work: WORK,
  issuedAt: "2026-11-09T20:30:00.000Z",
};
const expect = { role: "lead", connector: "bogdan@solace", threadIds: [payload.threadId], record_id: RECORD, envelope_sha256: DIGEST, work: WORK };


/**
 * An Ed25519 signature with R = the identity point, which only the key holder can make: S = k·a mod L,
 * where k = SHA-512(R ‖ A ‖ M). It satisfies [S]B = R + [k]A, so backends that accept a small-order R
 * verify it (OpenSSL 4 does, Node's OpenSSL 3.5 does not). Both verifiers must refuse it.
 */
function identityRSignature(payloadBytes: Buffer): string {
  const L = (1n << 252n) + 27742317777372353535851937790883648493n;
  const fromLe = (bytes: Uint8Array): bigint => bytes.reduceRight((acc, byte) => (acc << 8n) | BigInt(byte), 0n);
  const toLe = (n: bigint): Buffer => Buffer.from(Array.from({ length: 32 }, (_, i) => Number((n >> BigInt(8 * i)) & 0xffn)));
  const scalar = Buffer.from(createHash("sha512").update(seed).digest().subarray(0, 32));
  scalar[0] = (scalar[0] ?? 0) & 248;
  scalar[31] = ((scalar[31] ?? 0) & 127) | 64;
  const r = Buffer.alloc(32);
  r[0] = 1;
  const message = Buffer.concat([Buffer.from("t3-mesh/v1/attestation\n"), payloadBytes]);
  const k = fromLe(createHash("sha512").update(Buffer.concat([r, Buffer.from(rawPublicKey(key), "base64url"), message])).digest()) % L;
  return Buffer.concat([r, toLe((k * fromLe(scalar)) % L)]).toString("base64url");
}

/**
 * Wire-format cases both verifiers must agree on (src/attest.ts and the writer's Python Origin),
 * each a full request comment and the verdict. Signed with the test key where a signature is
 * needed, so they reach the payload checks; deterministic, since Ed25519 is.
 */
interface SharedCase {
  readonly name: string;
  readonly body: string;
  readonly verdict: "verified" | "refused";
}
function sharedCases(): SharedCase[] {
  const line = attestationLine(payload, key);
  const [, , encoded = "", sig = ""] = line.split(" ");
  const signed = (bytes: Buffer) =>
    `${ATTEST_PREFIX} ${bytes.toString("base64url")} ${sign(null, Buffer.concat([Buffer.from("t3-mesh/v1/attestation\n"), bytes]), key).toString("base64url")}`;
  const text = (json: string) => signed(Buffer.from(json, "utf8"));
  const json = JSON.stringify(payload);
  const { work: _work, ...missing } = payload;
  // The signature's last character carries 4 unused bits: setting one gives the same bytes, non-canonically.
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  const loose = sig.slice(0, -1) + (alphabet[alphabet.indexOf(sig.at(-1) ?? "A") ^ 1] ?? "");
  const body = (attest: string, crlf = false) => {
    const text = `${REQUEST_BODY}${attest}\n`;
    return crlf ? text.replaceAll("\n", "\r\n") : text;
  };
  const refused = (name: string, attest: string): SharedCase => ({ name, body: body(attest), verdict: "refused" });
  return [
    { name: "valid", body: body(line), verdict: "verified" },
    { name: "valid, CRLF line endings", body: body(line, true), verdict: "verified" },
    { name: "valid, indented with a tab", body: body(`\t${line}`), verdict: "verified" },
    refused("payload encoding of impossible length (A)", `${ATTEST_PREFIX} A AA`),
    refused("padded payload encoding", `${ATTEST_PREFIX} ${encoded}= ${sig}`),
    refused("non-canonical signature encoding of the same bytes", `${ATTEST_PREFIX} ${encoded} ${loose}`),
    refused("signature of the wrong length", `${ATTEST_PREFIX} ${encoded} ${sig.slice(0, 84)}`),
    refused("two spaces", `${ATTEST_PREFIX}  ${encoded} ${sig}`),
    refused("tab separator", `${ATTEST_PREFIX}\t${encoded} ${sig}`),
    refused("version 2", `bayfold-attest: v2 ${encoded} ${sig}`),
    refused("a fifth field", `${line} x`),
    refused("two attestation lines", `${line}\n${line}`),
    refused("signed: not JSON", text("not json")),
    refused("signed: a JSON array", text(JSON.stringify([payload]))),
    refused("signed: invalid UTF-8", signed(Buffer.concat([Buffer.from([0xff]), Buffer.from(json)]))),
    refused("signed: UTF-8 byte order mark", signed(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(json)]))),
    refused("signed: UTF-16 JSON", signed(Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(json, "utf16le")]))),
    refused("signed: v is true", text(JSON.stringify({ ...payload, v: true }))),
    refused("signed: v is 1.0", text(json.replace('"v":1,', '"v":1.0,'))),
    refused("signed: NaN", text(json.replace('"v":1,', '"v":NaN,'))),
    refused("signed: duplicate threadId, the configured one last", text(json.replace('"threadId":', '"threadId":"other","threadId":'))),
    refused("signed: an extra key", text(JSON.stringify({ ...payload, note: "x" }))),
    refused("signed: a missing key", text(JSON.stringify(missing))),
    refused("signed: threadId is a list", text(JSON.stringify({ ...payload, threadId: [payload.threadId] }))),
    refused("signed: another kind", text(JSON.stringify({ ...payload, kind: "bayfold-other" }))),
    refused("signed: issuedAt without a zone", text(JSON.stringify({ ...payload, issuedAt: "2026-11-09T20:30:00" }))),
    refused("signed: issuedAt with an offset", text(JSON.stringify({ ...payload, issuedAt: "2026-11-09T20:30:00.000+00:00" }))),
    refused("signed: impossible issuedAt", text(JSON.stringify({ ...payload, issuedAt: "2026-02-30T20:30:00.000Z" }))),
    refused("signed: issuedAt in year 0000", text(JSON.stringify({ ...payload, issuedAt: "0000-01-01T00:00:00.000Z" }))),
    refused("signed: deeply nested payload", signed(Buffer.from("[".repeat(9998) + "]".repeat(9998)))),
    refused(`signed: payload field over ${MAX_PAYLOAD_CHARS} characters`, text(JSON.stringify({ ...payload, threadId: "t".repeat(MAX_PAYLOAD_CHARS) }))),
    refused("signed by the key holder with a small-order (identity) R", `${ATTEST_PREFIX} ${encoded} ${identityRSignature(Buffer.from(json))}`),
  ];
}

/** Small-order Ed25519 public keys in canonical, sign-bit and non-canonical encodings (libsodium's blocklist). */
const SMALL_ORDER_KEYS = [
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0100000000000000000000000000000000000000000000000000000000000000",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
  "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
].map((hex) => Buffer.from(hex, "hex").toString("base64url"));

/** The whole vector file, every field of which the Python self-test may read. */
function buildVector(): unknown {
  return {
    about:
      "t3-mesh role-decision attestation test vector (docs/builder-subscriptions.md E6). Test key from a fixed seed; never trust it. " +
      "`cases` are full request comments (comment created 2026-11-09T20:31:00Z, never edited) with the verdict both verifiers must give; " +
      "`smallOrderKeys` must be refused as pinned keys.",
    seed: "sha256('t3-mesh attestation test vector v1')",
    publicKey: rawPublicKey(key),
    signedBytesPrefix: "t3-mesh/v1/attestation\n",
    payload,
    line: attestationLine(payload, key),
    request: { record_id: RECORD, work: WORK, envelope_sha256: DIGEST, comment_body: `${REQUEST_BODY}${attestationLine(payload, key)}\n` },
    cases: sharedCases(),
    smallOrderKeys: SMALL_ORDER_KEYS,
  };
}

test("the whole vector is current, and its shared cases verify as stated", () => {
  const vector = JSON.parse(readFileSync(new URL("./fixtures/attestation-vector.json", import.meta.url), "utf8")) as { cases: SharedCase[] };
  assert.deepEqual(vector, buildVector(), "regenerate: T3_MESH_WRITE_VECTOR=1 node --test src/attest.test.ts");
  for (const { name, body, verdict } of vector.cases) {
    const result = verifyAttestation(body, publicKey, expect);
    assert.equal(result.ok ? "verified" : "refused", verdict, `${name}: ${result.ok ? "verified" : result.reason}`);
  }
});

test("a small-order pinned key is refused in every encoding", () => {
  const body = `${REQUEST_BODY}${attestationLine(payload, key)}\n`;
  for (const raw of SMALL_ORDER_KEYS) {
    assert.ok(isSmallOrderKey(raw), raw);
    // Node may not even import some encodings as keys; where it does, verification refuses.
    let weak: ReturnType<typeof publicKeyFromRaw> | null = null;
    try {
      weak = publicKeyFromRaw(raw, "ed25519");
    } catch {
      continue;
    }
    const result = verifyAttestation(body, weak, expect);
    assert.equal(result.ok, false, raw);
  }
  assert.equal(isSmallOrderKey(rawPublicKey(key)), false);
});

test("roles are looked up as own properties only", () => {
  const roles = { lead: ["t-lead"] };
  assert.deepEqual(attestThreads(roles, "lead"), ["t-lead"]);
  for (const role of ["constructor", "tostring", "valueof", "hasownproperty", "queue"]) assert.deepEqual(attestThreads(roles, role), []);
});

test("an attestation appended to slice A's request verifies, bound to that exact request", () => {
  const line = attestationLine(payload, key);
  const body = `${REQUEST_BODY}${line}\n`;
  assert.deepEqual(verifyAttestation(body, publicKey, expect), { ok: true, payload });
  // Ed25519 is deterministic: the vector reproduces exactly.
  const vector = JSON.parse(readFileSync(new URL("./fixtures/attestation-vector.json", import.meta.url), "utf8")) as {
    publicKey: string;
    line: string;
    signedBytesPrefix: string;
  };
  assert.equal(vector.publicKey, rawPublicKey(key));
  assert.equal(vector.line, line);
  assert.equal(vector.signedBytesPrefix, "t3-mesh/v1/attestation\n");
});

test("anything not bound to this request, thread, role, connector or key is refused", () => {
  const line = attestationLine(payload, key);
  const body = `${REQUEST_BODY}${line}\n`;
  const reason = (b: string, e = expect, k = publicKey) => {
    const verdict = verifyAttestation(b, k, e);
    return verdict.ok ? "ok" : verdict.reason;
  };
  assert.match(reason(body, { ...expect, envelope_sha256: "0".repeat(64) }), /other content/);
  assert.match(reason(body, { ...expect, record_id: "33333333-3333-4333-8333-333333333333" }), /another record/);
  assert.match(reason(body, { ...expect, work: "bayfold/monorepo#1" }), /another work/);
  assert.match(reason(body, { ...expect, role: "queue" }), /role lead/);
  assert.match(reason(body, { ...expect, connector: "ops@solace" }), /another connector/);
  assert.match(reason(body, { ...expect, threadIds: ["someone-else"] }), /not a configured lead thread/);
  const other = publicKeyFromRaw(rawPublicKey(privateKeyFromSeed(createHash("sha256").update("other").digest(), "ed25519")), "ed25519");
  assert.match(reason(body, expect, other), /signature/);
  // Tampering with the payload (claiming another thread) breaks the signature.
  const forged = Buffer.from(JSON.stringify({ ...payload, threadId: "x" })).toString("base64url");
  const parts = line.split(" ");
  assert.match(reason(`${REQUEST_BODY}${[parts[0], parts[1], forged, parts[3]].join(" ")}\n`), /signature/);
  // No line, two lines, malformed line.
  assert.match(reason(REQUEST_BODY), /exactly one/);
  assert.match(reason(`${body}${line}\n`), /exactly one/);
  assert.match(reason(`${REQUEST_BODY}bayfold-attest: v1 ???\n`), /malformed/);
});

test("the signer refuses a payload the verifiers would refuse for length", () => {
  assert.equal(payloadFits(payload), true);
  assert.equal(payloadFits({ ...payload, threadId: "t".repeat(800) }), false);
});

test("inputs are checked before anything is signed", () => {
  const ok = { role: "lead", record_id: RECORD, envelope_sha256: DIGEST, work: WORK };
  assert.equal(checkAttestInput(ok), null);
  assert.notEqual(checkAttestInput({ ...ok, record_id: "2222222A-2222-4222-8222-22222222222B" }), null, "uppercase UUID");
  assert.notEqual(checkAttestInput({ ...ok, envelope_sha256: "sha256:" + DIGEST }), null);
  assert.notEqual(checkAttestInput({ ...ok, work: "monorepo#1" }), null);
  assert.notEqual(checkAttestInput({ ...ok, role: "Lead" }), null);
});

test("only work E routes is signable: the largest GitHub reference signs and verifies, a longer one is refused before signing", () => {
  const ok = { role: "lead", record_id: RECORD, envelope_sha256: DIGEST, work: WORK };
  /** The request comment with `work` in its envelope, as the receiver sees it. */
  const requestFor = (work: string) => REQUEST_BODY.replaceAll(WORK, work);

  // Owner 39, repository 100, issue 9 digits: 150 characters, under A's 200-character string bound.
  const largest = `${"o".repeat(39)}/${"r".repeat(100)}#999999999`;
  assert.equal(largest.length, 150);
  assert.equal(checkAttestInput({ ...ok, work: largest }), null);
  assert.equal(recordKeys(requestFor(largest)).record_work, largest, "the receiver routes it");
  const signed: AttestationPayload = { ...payload, work: largest };
  assert.equal(payloadFits(signed), true);
  const body = `${requestFor(largest)}${attestationLine(signed, key)}\n`;
  assert.deepEqual(verifyAttestation(body, publicKey, { ...expect, work: largest }), { ok: true, payload: signed });

  const overBound: Array<[string, string]> = [
    ["owner of 40 characters", `${"o".repeat(40)}/r#1`],
    ["repository of 101 characters", `o/${"r".repeat(101)}#1`],
    ["issue number of 10 digits", "o/r#1234567890"],
    ["over A's 200-character string bound", `o/${"r".repeat(300)}#1`],
  ];
  for (const [name, work] of overBound) {
    // The payload still fits, so before this check nothing stopped the connector from signing it.
    assert.equal(payloadFits({ ...payload, work }), true, `${name}: fits the payload limit`);
    assert.match(checkAttestInput({ ...ok, work }) ?? "", /within GitHub's limits/, `${name}: refused`);
    assert.equal(recordKeys(requestFor(work)).record_work, null, `${name}: the receiver does not route it either`);
  }
});

// Regenerate the vector: T3_MESH_WRITE_VECTOR=1 node --test src/attest.test.ts
if (process.env["T3_MESH_WRITE_VECTOR"] === "1") {
  writeFileSync(new URL("./fixtures/attestation-vector.json", import.meta.url), `${JSON.stringify(buildVector(), null, 2)}\n`);
}
