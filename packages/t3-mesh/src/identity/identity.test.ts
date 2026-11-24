import assert from "node:assert/strict";
import { test } from "node:test";
import {
  issueGrant,
  openGrant,
  openRevocation,
  pairingKey,
  parsePairingCode,
  signBinding,
  signRevocation,
  verifyEntry,
  type Entry,
} from "./grant.ts";
import { fingerprint, generatePrivateKey, rawPublicKey, signValue } from "./keys.ts";
import { ScopeError, ScopeSet, expandScopes, lowerMode } from "./scopes.ts";

test("expandScopes expands shorthand into the explicit list", () => {
  assert.deepEqual(expandScopes(["*"]), [
    "messages:send",
    "messages:receive",
    "events:subscribe",
    "files:send",
    "files:receive",
    "forks:send",
    "forks:receive/full-access",
  ]);
  assert.deepEqual(expandScopes(["messages:*", "forks:receive/approval-required", "files:send=b@x,a@x"]), [
    "messages:send",
    "messages:receive",
    "files:send=a@x,b@x",
    "forks:receive/approval-required",
  ]);
  assert.deepEqual(expandScopes(["forks:*", "forks:send"]), ["forks:send", "forks:receive/full-access"]);
});

test("expandScopes refuses unknown scopes and two forms of one scope", () => {
  assert.throws(() => expandScopes(["forks:*", "forks:send=a@x"]), ScopeError);
  assert.throws(() => expandScopes(["forks:receive"]), /needs a mode/);
  assert.throws(() => expandScopes(["forks:receive/everything"]), /unknown mode/);
  assert.throws(() => expandScopes(["files:receive=a@x"]), /only send scopes/);
  assert.throws(() => expandScopes(["messages:shout"]), /unknown scope/);
  assert.throws(() => expandScopes([]), /at least one/);
});

test("ScopeSet answers what a grant allows", () => {
  const scopes = new ScopeSet(["messages:send", "forks:send=bogdan@solace", "forks:receive/auto", "files:receive", "later:thing"]);
  assert.equal(scopes.has("messages:send"), true);
  assert.equal(scopes.has("messages:receive"), false);
  assert.equal(scopes.maySend("forks", "bogdan@solace"), true);
  assert.equal(scopes.maySend("forks", "ops@solace"), false);
  assert.equal(scopes.maySend("files", "bogdan@solace"), false);
  assert.equal(scopes.forkCeiling(), "auto");
  assert.equal(new ScopeSet([]).forkCeiling(), null);
  assert.equal(lowerMode("full-access", "approval-required"), "approval-required");
  assert.equal(lowerMode("auto", "full-access"), "auto");
});

function pairedEntry(): { entry: Entry; admin: ReturnType<typeof generatePrivateKey>; code: string } {
  const admin = generatePrivateKey("ed25519");
  const issued = issueGrant(admin, "bogdan@solace", ["messages:send"], 600_000);
  const code = parsePairingCode(issued.code);
  assert.ok(code !== null);
  const binding = signBinding(issued.grant, code, generatePrivateKey("ed25519"), generatePrivateKey("x25519"));
  return { entry: { grant: issued.signed, binding }, admin, code: issued.code };
}

test("a paired entry verifies and describes the connector", () => {
  const { entry, admin, code } = pairedEntry();
  const parsed = parsePairingCode(code);
  assert.ok(parsed !== null);
  assert.equal(parsed.adminFingerprint, fingerprint(rawPublicKey(admin)));
  const verified = verifyEntry(entry, admin);
  assert.ok(verified.ok);
  assert.equal(verified.identity.connectorId, "bogdan@solace");
  assert.deepEqual(verified.identity.scopes, ["messages:send"]);
  assert.equal(verified.identity.grantId, parsed.grantId);
});

test("entries a router could forge do not verify", () => {
  const { entry, admin } = pairedEntry();
  const otherAdmin = generatePrivateKey("ed25519");
  assert.equal(verifyEntry(entry, otherAdmin).ok, false);

  // Widened scopes: the grant payload no longer matches its signature.
  const grant = openGrant(entry.grant, admin);
  assert.ok(grant !== null);
  const widened = { ...entry, grant: { ...entry.grant, payload: JSON.stringify({ ...grant, scopes: ["forks:send"] }) } };
  assert.equal(verifyEntry(widened, admin).ok, false);

  // Swapped keys: a binding the router made without the pairing code.
  const routerKey = generatePrivateKey("ed25519");
  const forged = signValue(
    "binding",
    { ...JSON.parse(entry.binding.payload), signingKey: rawPublicKey(routerKey) },
    routerKey,
  );
  const swapped = {
    ...entry,
    binding: { payload: forged.payload, pairingSig: forged.sig, selfSig: signValue("binding-self", JSON.parse(forged.payload), routerKey).sig },
  };
  assert.equal(verifyEntry(swapped, admin).ok, false);
});

test("only the code holder can sign a binding", () => {
  const admin = generatePrivateKey("ed25519");
  const issued = issueGrant(admin, "bogdan@solace", ["messages:send"], 600_000);
  const code = parsePairingCode(issued.code);
  assert.ok(code !== null);
  assert.equal(rawPublicKey(pairingKey(code.secret, issued.grant.id)), issued.grant.pairingKey);
  const wrong = { ...code, secret: Buffer.alloc(20, 1) };
  const binding = signBinding(issued.grant, wrong, generatePrivateKey("ed25519"), generatePrivateKey("x25519"));
  assert.equal(verifyEntry({ grant: issued.signed, binding }, admin).ok, false);
});

test("a binding after the pairing window does not verify", () => {
  const admin = generatePrivateKey("ed25519");
  const issued = issueGrant(admin, "bogdan@solace", ["messages:send"], 1_000, new Date("2026-11-06T10:00:00Z"));
  const code = parsePairingCode(issued.code);
  assert.ok(code !== null);
  const late = signBinding(issued.grant, code, generatePrivateKey("ed25519"), generatePrivateKey("x25519"), new Date("2026-11-06T10:00:02Z"));
  assert.deepEqual(verifyEntry({ grant: issued.signed, binding: late }, admin), { ok: false, reason: "bound after the pairing window" });
});

test("revocations open only with the admin key", () => {
  const admin = generatePrivateKey("ed25519");
  const signed = signRevocation(admin, "bogdan@solace", "6f1c0a52-8a3e-4f43-9b51-1d2f3e4a5b6c");
  assert.equal(openRevocation(signed, admin)?.connectorId, "bogdan@solace");
  assert.equal(openRevocation(signed, generatePrivateKey("ed25519")), null);
});

test("pairing codes round-trip and reject garbage", () => {
  const { code } = pairedEntry();
  assert.ok(code.startsWith("t3mp1_"));
  assert.equal(parsePairingCode(`${code}\n`)?.secret.length, 20);
  assert.equal(parsePairingCode("t3mp1_short"), null);
  assert.equal(parsePairingCode("nope"), null);
});
