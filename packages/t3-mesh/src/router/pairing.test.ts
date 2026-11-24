import assert from "node:assert/strict";
import { test } from "node:test";
import { issueGrant, signRevocation } from "../identity/grant.ts";
import { generatePrivateKey, rawPublicKey } from "../identity/keys.ts";
import { PairingFailed, generateKeys, pairWithRouter } from "../identity/pairClient.ts";
import { HttpRouterLink } from "./client.ts";
import { RouterCore } from "./core.ts";
import { serveRouter } from "./server.ts";

async function withRouter(
  run: (env: { url: string; core: RouterCore; admin: ReturnType<typeof generatePrivateKey> }) => Promise<void>,
  options: { requirePairing?: boolean } = {},
): Promise<void> {
  const admin = generatePrivateKey("ed25519");
  const core = new RouterCore({ dbPath: ":memory:", adminKey: rawPublicKey(admin), requirePairing: options.requirePairing ?? false });
  const router = await serveRouter({ core, host: "127.0.0.1", port: 0 });
  try {
    await run({ url: router.url, core, admin });
  } finally {
    await router.close();
    core.close();
  }
}

const post = (url: string, body: unknown) =>
  fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });

test("a connector pairs with a code, gets a token and its grant's scopes", async () => {
  await withRouter(async ({ url, core, admin }) => {
    const issued = issueGrant(admin, "b@host", ["messages:receive"], 600_000);
    assert.equal((await post(`${url}/v1/grants`, issued.signed)).status, 200);
    const paired = await pairWithRouter(url, issued.code, generateKeys());
    assert.equal(paired.connectorId, "b@host");
    assert.equal(paired.adminKey, rawPublicKey(admin));
    assert.equal(core.authenticate(paired.token), "b@host");

    // b may receive but not send; an unpaired connector keeps the old defaults.
    const a = new HttpRouterLink(url, core.addConnector("a@host"));
    const b = new HttpRouterLink(url, paired.token);
    await a.setHandles(["alpha"]);
    await b.setHandles(["beta"]);
    assert.deepEqual(await a.send({ id: "m1", fromHandle: "alpha", to: "b@host/beta", text: "hi", origin: null }), {
      ok: true,
      status: "stored",
    });
    const refused = await b.send({ id: "m2", fromHandle: "beta", to: "a@host/alpha", text: "hi", origin: null });
    assert.equal(refused.ok ? "stored" : refused.error, "not_granted");
    const subscribed = await b.setSubscriptions([{ id: "8b0f6c1e-5d2a-4f7e-9c3b-2a1d0e9f8c7b", topic: "github", filters: [], coalesceSeconds: 30 }]);
    assert.equal(subscribed.ok ? "ok" : subscribed.error, "not_granted");

    // The code is used up.
    await assert.rejects(pairWithRouter(url, issued.code, generateKeys()), /already_paired/);

    const directory = core.pairing.directory();
    assert.ok(directory.ok);
    assert.equal(directory.value.entries.length, 1);
  });
});

test("pairing again supersedes the old token and scopes; revoking cuts the connector off", async () => {
  await withRouter(async ({ url, core, admin }) => {
    const first = issueGrant(admin, "b@host", ["messages:receive"], 600_000, new Date(Date.now() - 1000));
    await post(`${url}/v1/grants`, first.signed);
    const keys = generateKeys();
    const one = await pairWithRouter(url, first.code, keys);
    const second = issueGrant(admin, "b@host", ["messages:*"], 600_000);
    await post(`${url}/v1/grants`, second.signed);
    const two = await pairWithRouter(url, second.code, keys);
    assert.equal(core.authenticate(one.token), null);
    assert.equal(core.authenticate(two.token), "b@host");
    assert.equal(core.scopesOf("b@host").has("messages:send"), true);

    const response = await post(`${url}/v1/revocations`, signRevocation(admin, "b@host", second.grant.id));
    assert.equal(response.status, 200);
    assert.equal(core.authenticate(two.token), null);
  });
});

test("the router refuses grants and revocations not signed by its admin key", async () => {
  await withRouter(async ({ url }) => {
    const stranger = generatePrivateKey("ed25519");
    const issued = issueGrant(stranger, "b@host", ["*"], 600_000);
    assert.equal((await post(`${url}/v1/grants`, issued.signed)).status, 401);
    assert.equal((await post(`${url}/v1/revocations`, signRevocation(stranger, "b@host", issued.grant.id))).status, 401);
    // The code names the stranger's key, so even a router serving that grant would not be believed.
    await assert.rejects(pairWithRouter(url, issued.code, generateKeys()), PairingFailed);
  });
});

test("an expired pairing window and a wrong code are refused", async () => {
  await withRouter(async ({ url, admin }) => {
    const issued = issueGrant(admin, "b@host", ["messages:send"], 600_000);
    await post(`${url}/v1/grants`, issued.signed);
    const mangled = `${issued.code.slice(0, 30)}${issued.code[30] === "A" ? "B" : "A"}${issued.code.slice(31)}`;
    await assert.rejects(pairWithRouter(url, mangled, generateKeys()), PairingFailed);

    const late = issueGrant(admin, "c@host", ["messages:send"], 1, new Date(Date.now() - 10_000));
    assert.equal((await post(`${url}/v1/grants`, late.signed)).status, 410);
  });
});

test("--require-pairing refuses unpaired tokens", async () => {
  await withRouter(
    async ({ core }) => {
      const token = core.addConnector("old@host");
      assert.equal(core.authenticate(token), null);
    },
    { requirePairing: true },
  );
});

test("the router refuses a transfer over its limit from the header, before reading the body", async () => {
  const { seal } = await import("../transfer/seal.ts");
  const { randomUUID } = await import("node:crypto");
  const admin = generatePrivateKey("ed25519");
  const core = new RouterCore({
    dbPath: ":memory:",
    adminKey: rawPublicKey(admin),
    transferLimits: { maxBytes: 1024, maxPendingBytesPerRecipient: 4096, maxPendingPerRecipient: 20, holdRetryMs: 30_000 },
  });
  const router = await serveRouter({ core, host: "127.0.0.1", port: 0 });
  try {
    const keysA = generateKeys();
    const keysB = generateKeys();
    for (const [id, keys, scopes] of [["a@host", keysA, ["files:send"]], ["b@host", keysB, ["files:receive"]]] as const) {
      const issued = issueGrant(admin, id, [...scopes], 600_000);
      await post(`${router.url}/v1/grants`, issued.signed);
      await pairWithRouter(router.url, issued.code, keys);
    }
    const b = core.pairing.identity("b@host");
    assert.ok(b !== undefined);
    const sealed = seal({ id: randomUUID(), type: "files", from: "a@host", to: "b@host", toHandle: "beta", ttlMs: 60_000 }, Buffer.alloc(4000, 7), keysA.signing, b.encryptionKey);
    const checked = core.transfers.check("a@host", JSON.parse(sealed.header.payload).id, sealed.header);
    assert.equal(checked.ok ? "ok" : checked.error, "too_large");
  } finally {
    await router.close();
    core.close();
  }
});
