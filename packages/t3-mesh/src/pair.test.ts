import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, realpathSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { loadConfig } from "./config.ts";
import { issueGrant } from "./identity/grant.ts";
import { generatePrivateKey, rawPublicKey } from "./identity/keys.ts";
import { readKeys } from "./identity/pairClient.ts";
import { pairConnector } from "./pair.ts";
import { RouterCore } from "./router/core.ts";
import { serveRouter } from "./router/server.ts";

test("pairing an existing connector swaps its router token and adds the admin key, keeping the rest", async () => {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "t3-mesh-pair-")));
  const admin = generatePrivateKey("ed25519");
  const core = new RouterCore({ dbPath: ":memory:", adminKey: rawPublicKey(admin) });
  const router = await serveRouter({ core, host: "127.0.0.1", port: 0 });
  try {
    const oldToken = core.addConnector("b@host");
    writeFileSync(join(dir, "router.token"), `${oldToken}\n`, { mode: 0o600 });
    const original = {
      connectorId: "b@host",
      t3: { url: "http://127.0.0.1:3773", home: dir },
      router: { mode: "http", url: router.url, tokenFile: "router.token" },
      delivery: "queue",
    };
    writeFileSync(join(dir, "config.json"), JSON.stringify(original), { mode: 0o600 });

    const wrong = issueGrant(admin, "c@host", ["messages:*"], 600_000);
    await fetch(`${router.url}/v1/grants`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(wrong.signed) });
    await assert.rejects(pairConnector(join(dir, "config.json"), wrong.code), /the code is for c@host/);
    // Refused before binding: the grant is still unused and no c@host identity exists.
    assert.equal(core.pairing.identity("c@host"), undefined);
    assert.equal(core.pairing.pendingGrant(wrong.grant.id).ok, true);

    const issued = issueGrant(admin, "b@host", ["messages:*", "files:receive"], 600_000);
    await fetch(`${router.url}/v1/grants`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(issued.signed) });
    const paired = await pairConnector(join(dir, "config.json"), issued.code);
    assert.deepEqual(paired.scopes, ["messages:send", "messages:receive", "files:receive"]);

    const config = loadConfig(join(dir, "config.json"));
    assert.equal(config.delivery, "queue");
    assert.equal(config.identity?.adminKey, rawPublicKey(admin));
    assert.equal(core.authenticate(oldToken), null);
    assert.equal(core.authenticate(config.router.mode === "http" ? config.router.token : ""), "b@host");
    assert.equal(statSync(join(dir, "keys.json")).mode & 0o777, 0o600);
    readKeys(join(dir, "keys.json"));
    assert.equal(JSON.parse(readFileSync(join(dir, "config.json"), "utf8")).router.tokenFile, "router.token");
  } finally {
    await router.close();
    core.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
