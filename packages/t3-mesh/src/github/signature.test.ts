import { test } from "node:test";
import assert from "node:assert/strict";
import { signatureHeader, verifySignature } from "./signature.ts";

const secret = "It's a Secret to Everybody";
const body = Buffer.from("Hello, World!");

test("matches GitHub's documented test vector", () => {
  // https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries#testing-the-webhook-payload-validation
  const expected = "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17";
  assert.equal(signatureHeader(secret, body), expected);
  assert.equal(verifySignature(secret, body, expected), true);
});

test("rejects missing, malformed and wrong signatures", () => {
  const good = signatureHeader(secret, body);
  const hex = good.slice("sha256=".length);
  const cases: Array<[string, string | string[] | undefined]> = [
    ["missing", undefined],
    ["empty", ""],
    ["sha1", `sha1=${hex.slice(0, 40)}`],
    ["no prefix", hex],
    ["uppercase prefix", `SHA256=${hex}`],
    ["uppercase hex", `sha256=${hex.toUpperCase()}`],
    ["truncated", good.slice(0, -2)],
    ["extended", `${good}00`],
    ["not hex", `sha256=${"z".repeat(64)}`],
    ["whitespace", ` ${good}`],
    ["two values joined", `${good}, ${good}`],
    ["array", [good, good]],
    ["other secret", signatureHeader("another secret", body)],
    ["other body", signatureHeader(secret, Buffer.from("Hello, World! "))],
  ];
  for (const [name, header] of cases) assert.equal(verifySignature(secret, body, header), false, name);
});

test("an empty secret never verifies", () => {
  assert.equal(verifySignature("", body, signatureHeader("", body)), false);
});

test("checks the exact bytes, not re-serialized JSON", () => {
  const raw = Buffer.from('{"a": 1}');
  const header = signatureHeader(secret, raw);
  assert.equal(verifySignature(secret, raw, header), true);
  assert.equal(verifySignature(secret, Buffer.from(JSON.stringify(JSON.parse(raw.toString()))), header), false);
});
