import { test } from "node:test";
import assert from "node:assert/strict";
import { execFile, spawn } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { parseListen, parseTopicFlags, RouterUsageError } from "./commands.ts";
import { RouterCore } from "./core.ts";
import { serveRouter } from "./server.ts";

test("parses repeated --topic name=publisher[,publisher]", () => {
  assert.deepEqual(
    parseTopicFlags(["github=github-hub@bayfold-co-ops", "ci=a@host,b@host", "github=other@host"]),
    new Map([
      ["github", ["github-hub@bayfold-co-ops", "other@host"]],
      ["ci", ["a@host", "b@host"]],
    ]),
  );
  assert.deepEqual(parseTopicFlags([]), new Map());
});

test("refuses topics without publishers and bad names", () => {
  for (const flag of ["github", "github=", "Git Hub=a@host", "github=Bad Id"]) {
    assert.throws(() => parseTopicFlags([flag]), RouterUsageError, flag);
  }
});

test("add-publisher and add-connector work against a serving router, waiting out its write lock", async () => {
  const dir = mkdtempSync(join(tmpdir(), "t3-mesh-cli-"));
  const dbPath = join(dir, "router.db");
  const hub = "github-hub@bayfold-co-ops";
  const core = new RouterCore({ dbPath, topics: new Map([["github", [hub]]]) });
  const router = await serveRouter({ core, host: "127.0.0.1", port: 0 });
  const cli = (...args: string[]) =>
    promisify(execFile)(process.execPath, [new URL("./main.ts", import.meta.url).pathname, ...args]);
  // Another process holds the write lock for a while into each command, as a router transaction would.
  const holdLock = () =>
    new Promise<void>((resolve, reject) => {
      const script =
        `const db = new (require("node:sqlite").DatabaseSync)(${JSON.stringify(dbPath)});` +
        `db.exec("PRAGMA busy_timeout = 5000; BEGIN IMMEDIATE"); process.stdout.write("locked");` +
        `Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 500); db.exec("COMMIT");`;
      const child = spawn(process.execPath, ["-e", script], { stdio: ["ignore", "pipe", "inherit"] });
      child.stdout.once("data", () => resolve());
      child.once("exit", (code) => (code === 0 ? resolve() : reject(new Error(`lock holder exited ${code}`))));
    });
  try {
    await holdLock();
    await cli("add-publisher", hub, "--topic", "github", "--db", dbPath, "--token-out", join(dir, "publisher.token"));
    await holdLock();
    await cli("add-connector", "b@host", "--db", dbPath, "--token-out", join(dir, "connector.token"));

    // The live router accepts both new tokens without a restart.
    const token = (name: string) => readFileSync(join(dir, name), "utf8").trim();
    const published = await fetch(`${router.url}/v1/events?topic=github`, {
      method: "POST",
      headers: { authorization: `Bearer ${token("publisher.token")}`, "content-type": "application/json" },
      body: JSON.stringify({
        specversion: "1.0",
        id: "d1",
        source: "github.com/bayfold/infra",
        type: "com.github.ping",
        datacontenttype: "application/json",
        data: {},
      }),
    });
    assert.equal(published.status, 202);
    const peers = await fetch(`${router.url}/v1/peers`, { headers: { authorization: `Bearer ${token("connector.token")}` } });
    assert.equal(peers.status, 200);

    await holdLock();
    await cli("revoke-publisher", hub, "--db", dbPath);
    await holdLock();
    await cli("revoke-connector", "b@host", "--db", dbPath);
    assert.equal(core.events.authenticatePublisher(token("publisher.token")), null);
    assert.equal(core.authenticate(token("connector.token")), null);
  } finally {
    await router.close();
    core.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("parses --listen host:port", () => {
  assert.deepEqual(parseListen("127.0.0.1:8792"), { host: "127.0.0.1", port: 8792 });
  assert.deepEqual(parseListen("[::1]:8792"), { host: "::1", port: 8792 });
  for (const value of ["8792", ":8792", "127.0.0.1:", "127.0.0.1:x", "127.0.0.1:70000"]) {
    assert.throws(() => parseListen(value), RouterUsageError, value);
  }
});

test("processes starting together on a fresh database migrate it once", async () => {
  const cli = (...args: string[]) =>
    promisify(execFile)(process.execPath, [new URL("./main.ts", import.meta.url).pathname, ...args]);
  // Each round: one fresh database, several admin commands started at the same moment (as a router
  // and its token unit can be after an upgrade). Every one must succeed.
  for (let round = 0; round < 5; round++) {
    const dir = mkdtempSync(join(tmpdir(), "t3-mesh-migrate-"));
    const dbPath = join(dir, "router.db");
    try {
      await Promise.all(
        ["a", "b", "c", "d"].map((name) =>
          cli("add-connector", `${name}@host`, "--db", dbPath, "--token-out", join(dir, `${name}.token`)),
        ),
      );
      const core = new RouterCore({ dbPath });
      core.close();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }
});
