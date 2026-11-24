import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import type { ConnectorConfig } from "./config.ts";
import { issueGrant } from "./identity/grant.ts";
import { generatePrivateKey, rawPublicKey } from "./identity/keys.ts";
import { generateKeys, pairWithRouter, writeKeys } from "./identity/pairClient.ts";
import type { ToolResponse } from "./ipc.ts";
import { HttpRouterLink } from "./router/client.ts";
import { RouterCore } from "./router/core.ts";
import { serveRouter } from "./router/server.ts";
import type { InboundOutcome, InboundTransfer } from "./router/types.ts";
import { DEFAULT_POLICY } from "./t3/threadState.ts";
import { Transfers } from "./transfers.ts";

const waitFor = async (condition: () => boolean, timeoutMs = 5000) => {
  const deadline = Date.now() + timeoutMs;
  while (!condition()) {
    if (Date.now() > deadline) throw new Error("timed out");
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
};

const configFor = (dir: string, connectorId: string, adminKey: string, accept: readonly string[] | null = null): ConnectorConfig => ({
  stateDir: dir,
  connectorId,
  t3Url: "http://127.0.0.1:1",
  t3Home: dir,
  t3Bin: undefined,
  t3TokenPath: join(dir, "t3-token.json"),
  router: { mode: "loopback" },
  delivery: "steer",
  policy: DEFAULT_POLICY,
  socketPath: join(dir, "daemon.sock"),
  statePath: join(dir, "state.json"),
  plugins: [],
  localDbPath: join(dir, "local.db"),
  identity: { adminKey, keysPath: join(dir, "keys.json") },
  accept: { files: accept, forks: null },
  attestRoles: {},
  statusPath: null,
});

const resultOf = (response: ToolResponse): unknown => {
  if (!response.ok) assert.fail(`${response.error.code}: ${response.error.message}`);
  return response.result;
};

async function mesh(scopes: { a: string[]; b: string[] }, acceptB: readonly string[] | null = null) {
  const base = realpathSync(mkdtempSync(join(tmpdir(), "t3-mesh-transfers-")));
  const admin = generatePrivateKey("ed25519");
  const core = new RouterCore({ dbPath: ":memory:", adminKey: rawPublicKey(admin) });
  const router = await serveRouter({ core, host: "127.0.0.1", port: 0 });
  const connector = async (id: string, granted: string[], accept: readonly string[] | null) => {
    const dir = join(base, id);
    mkdirSync(dir, { mode: 0o700 });
    const issued = issueGrant(admin, id, granted, 600_000);
    await fetch(`${router.url}/v1/grants`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(issued.signed) });
    const keys = generateKeys();
    writeKeys(join(dir, "keys.json"), keys);
    const paired = await pairWithRouter(router.url, issued.code, keys);
    const link = new HttpRouterLink(router.url, paired.token);
    const transfers = Transfers.open(configFor(dir, id, rawPublicKey(admin), accept), link);
    assert.ok(transfers !== null);
    await transfers.refresh();
    return { dir, link, transfers };
  };
  const a = await connector("a@host", scopes.a, null);
  const b = await connector("b@host", scopes.b, acceptB);
  await a.transfers.refresh();
  return {
    base,
    a,
    b,
    core,
    close: async () => {
      await a.link.stop();
      await b.link.stop();
      await router.close();
      core.close();
      rmSync(base, { recursive: true, force: true });
    },
  };
}

/** Starts b receiving: transfers go through Transfers.receive, turns are captured instead of dispatched. */
function receiveOn(b: Awaited<ReturnType<typeof mesh>>["b"]) {
  const turns: Array<{ threadId: string; text: string }> = [];
  const outcomes: InboundOutcome[] = [];
  b.link.start(async (item) => {
    if (item.kind !== "transfer") return { kind: "rejected", reason: "unexpected" };
    const transfer: InboundTransfer = item;
    const outcome = await b.transfers.receive(transfer, (handle) => (handle === "beta" ? "thread-b" : undefined), async (threadId, _prefix, _id, text) => {
      turns.push({ threadId, text });
      return { kind: "delivered" };
    });
    outcomes.push(outcome);
    return outcome;
  });
  return { turns, outcomes };
}

test("files go from one paired connector to another, sealed, and land in the quarantine directory", async () => {
  const env = await mesh({ a: ["files:send"], b: ["files:receive"] });
  try {
    const work = join(env.a.dir, "work");
    mkdirSync(work);
    writeFileSync(join(work, "notes.md"), "hello from a");
    const sent = resultOf(await env.a.transfers.sendFiles("alpha", work, { to: "b@host/beta", paths: ["notes.md"], note: "for the migration" }));
    assert.equal((sent as { files: number }).files, 1);

    const { turns, outcomes } = receiveOn(env.b);
    await waitFor(() => turns.length === 1);
    const transferId = (sent as { transferId: string }).transferId;
    const dir = join(env.b.dir, "received", transferId);
    assert.equal(readFileSync(join(dir, "notes.md"), "utf8"), "hello from a");
    assert.equal(turns[0]?.threadId, "thread-b");
    assert.ok(turns[0]?.text.startsWith(`mesh files from a@host/alpha · 1 file, 12 B · saved in ${dir}`));
    assert.ok(turns[0]?.text.includes("for the migration"));
    assert.deepEqual(outcomes, [{ kind: "delivered" }]);
  } finally {
    await env.close();
  }
});

test("scopes are checked on both sides before anything is sent", async () => {
  const env = await mesh({ a: ["files:send=c@host"], b: ["files:receive"] });
  try {
    writeFileSync(join(env.a.dir, "x.txt"), "x");
    const refused = await env.a.transfers.sendFiles("alpha", env.a.dir, { to: "b@host/beta", paths: ["x.txt"] });
    assert.equal(refused.ok ? "ok" : refused.error.code, "not_granted");
  } finally {
    await env.close();
  }
  const noReceive = await mesh({ a: ["files:send"], b: ["messages:receive"] });
  try {
    writeFileSync(join(noReceive.a.dir, "x.txt"), "x");
    const refused = await noReceive.a.transfers.sendFiles("alpha", noReceive.a.dir, { to: "b@host/beta", paths: ["x.txt"] });
    assert.equal(refused.ok ? "ok" : refused.error.code, "not_granted");
  } finally {
    await noReceive.close();
  }
});

test("a receiver's accept list narrows its scopes", async () => {
  const env = await mesh({ a: ["files:send"], b: ["files:receive"] }, ["someone@else"]);
  try {
    writeFileSync(join(env.a.dir, "x.txt"), "x");
    resultOf(await env.a.transfers.sendFiles("alpha", env.a.dir, { to: "b@host/beta", paths: ["x.txt"] }));
    const { turns, outcomes } = receiveOn(env.b);
    await waitFor(() => outcomes.length === 1);
    assert.deepEqual(outcomes, [{ kind: "rejected", reason: "not_accepted" }]);
    assert.equal(turns.length, 0);
  } finally {
    await env.close();
  }
});
