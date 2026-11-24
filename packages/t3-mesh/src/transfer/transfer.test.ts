import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { test } from "node:test";
import { generatePrivateKey, publicKeyFromRaw, rawPublicKey, signValue } from "../identity/keys.ts";
import { PackError, compressPack, decodePack, decompressPack, encodePack, pathProblem } from "./pack.ts";
import { OpenError, open, readHeader, seal } from "./seal.ts";

test("packs round-trip and are checked on decode", () => {
  const pack = { meta: { note: "hi" }, files: [{ path: "a/b.txt", data: Buffer.from("one") }, { path: "c", data: Buffer.alloc(0) }] };
  const decoded = decodePack(encodePack(pack));
  assert.deepEqual(decoded.meta, { note: "hi" });
  assert.deepEqual(decoded.files.map((file) => [file.path, file.data.toString()]), [["a/b.txt", "one"], ["c", ""]]);

  const bytes = encodePack(pack);
  const flipped = Buffer.from(bytes);
  flipped[flipped.length - 1] = (flipped[flipped.length - 1] ?? 0) ^ 1;
  assert.throws(() => decodePack(flipped), /checksum/);
  assert.throws(() => decodePack(Buffer.concat([bytes, Buffer.from("x")])), /trailing/);
  assert.throws(() => decodePack(Buffer.from("nope")), PackError);
});

test("pack paths cannot escape or collide", () => {
  for (const bad of ["../x", "a/../b", "/abs", "a//b", "a/./b", "a\\b", "a\0b", ""]) assert.notEqual(pathProblem(bad), null, bad);
  assert.equal(pathProblem("dir/file.txt"), null);
  assert.throws(() => encodePack({ meta: null, files: [{ path: "a", data: Buffer.from("") }, { path: "a/b", data: Buffer.from("") }] }), /both a file and a directory/);
  assert.throws(() => encodePack({ meta: null, files: [{ path: "a", data: Buffer.from("") }, { path: "a", data: Buffer.from("") }] }), /twice/);
});

function parties() {
  const sender = generatePrivateKey("ed25519");
  const recipient = generatePrivateKey("x25519");
  return { sender, recipient, input: { id: randomUUID(), type: "files" as const, from: "a@host", to: "b@host", toHandle: "beta", ttlMs: 60_000 } };
}

test("a sealed transfer opens only for its recipient, from its sender", () => {
  const { sender, recipient, input } = parties();
  const sealed = seal(input, Buffer.from("secret"), sender, rawPublicKey(recipient));
  const senderPublic = publicKeyFromRaw(rawPublicKey(sender), "ed25519");
  const opened = open(sealed.header, sealed.ciphertext, senderPublic, recipient);
  assert.equal(opened.plaintext.toString(), "secret");
  assert.equal(opened.header.toHandle, "beta");

  assert.throws(() => open(sealed.header, sealed.ciphertext, senderPublic, generatePrivateKey("x25519")), (error) => error instanceof OpenError && error.reason === "corrupt");
  const other = publicKeyFromRaw(rawPublicKey(generatePrivateKey("ed25519")), "ed25519");
  assert.throws(() => open(sealed.header, sealed.ciphertext, other, recipient), (error) => error instanceof OpenError && error.reason === "bad_signature");
});

test("altering the ciphertext or re-addressing the header is detected", () => {
  const { sender, recipient, input } = parties();
  const sealed = seal(input, Buffer.from("secret"), sender, rawPublicKey(recipient));
  const senderPublic = publicKeyFromRaw(rawPublicKey(sender), "ed25519");
  const altered = Buffer.from(sealed.ciphertext);
  altered[0] = (altered[0] ?? 0) ^ 1;
  assert.throws(() => open(sealed.header, altered, senderPublic, recipient), /does not match/);

  // A router re-signing a re-addressed header cannot use the sender's key; one keeping the
  // signature cannot change the payload.
  const header = readHeader(sealed.header);
  assert.ok(header !== null);
  const readdressed = { payload: JSON.stringify({ ...header, to: "c@host" }), sig: sealed.header.sig };
  assert.throws(() => open(readdressed, sealed.ciphertext, senderPublic, recipient), /not signed/);
  const forged = signValue("transfer", { ...header, to: "c@host" }, generatePrivateKey("ed25519"));
  assert.throws(() => open(forged, sealed.ciphertext, senderPublic, recipient), /not signed/);
});

test("packs are compressed for transfer and decompress back, with a cap on the output", async () => {
  const transcript = Buffer.from(Array.from({ length: 20_000 }, (_, i) => JSON.stringify({ type: "assistant", uuid: `u${i}`, text: "the same words again and again" })).join("\n"));
  const pack = { meta: { kind: "fork" }, files: [{ path: "session.jsonl", data: transcript }] };
  const compressed = await compressPack(pack);
  assert.ok(compressed.length * 5 < transcript.length, `${compressed.length} vs ${transcript.length}`);
  const back = await decompressPack(compressed);
  assert.deepEqual(back.meta, { kind: "fork" });
  assert.ok(back.files[0]?.data.equals(transcript));
  // An uncompressed pack (from a connector before compression) still decodes.
  assert.equal((await decompressPack(encodePack(pack))).files.length, 1);
  // A pack that decompresses past the cap is refused without being held whole.
  await assert.rejects(decompressPack(compressed, 1024), /decompresses past the size limit/);
  await assert.rejects(decompressPack(Buffer.concat([compressed.subarray(0, 8), Buffer.from("garbage")])), /does not decompress/);
});
