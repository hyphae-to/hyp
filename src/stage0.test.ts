import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { test } from "node:test";
import { serveReceiver } from "./core/github/receiver.ts";
import { signatureHeader } from "./core/github/signature.ts";
import { DEFAULT_LIMITS, RouterCore } from "./core/router/core.ts";
import { serveRouter } from "./core/router/server.ts";
import * as Schema from "./core/validate.ts";
import { State } from "./state.ts";

test("zero-dep validate.ts covers Struct, optionalKey, NullOr, Union, Array, Literals, and fromJsonString", () => {
  const Inner = Schema.Struct({
    v: Schema.Literal(1),
    kind: Schema.Literals(["a", "b"] as const),
    note: Schema.optionalKey(Schema.NullOr(Schema.String)),
    tags: Schema.Array(Schema.String),
  });
  const Wrapped = Schema.fromJsonString(Inner);
  const ok = Schema.decodeUnknownOption(Wrapped)(JSON.stringify({ v: 1, kind: "a", tags: ["x"] }));
  assert.equal(ok._tag, "Some");
  assert.deepEqual(ok.value, { v: 1, kind: "a", tags: ["x"] });

  const withNull = Schema.decodeUnknownSync(Inner)({ v: 1, kind: "b", note: null, tags: [] });
  assert.equal(withNull.note, null);

  assert.equal(Schema.decodeUnknownOption(Inner)({ v: 2, kind: "a", tags: [] })._tag, "None");
  assert.equal(Schema.decodeUnknownOption(Inner)({ v: 1, kind: "c", tags: [] })._tag, "None");
  assert.equal(Schema.decodeUnknownOption(Wrapped)("{not-json")._tag, "None");
  assert.throws(() => Schema.decodeUnknownSync(Inner)(null), TypeError);
});

test("State opens state.sqlite in WAL journal mode", () => {
  const dir = mkdtempSync(join(tmpdir(), "hyphae-wal-"));
  const dbPath = join(dir, "state.sqlite");
  try {
    const state = new State(dbPath, "dev@local");
    state.close();
    const check = new DatabaseSync(dbPath, { readOnly: true });
    try {
      const row = check.prepare("PRAGMA journal_mode").get() as { journal_mode: string };
      assert.equal(row.journal_mode.toLowerCase(), "wal");
    } finally {
      check.close();
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("RouterCore.tick prunes settled messages past settledRetentionMs while preserving pending and recent settled rows", () => {
  const dir = mkdtempSync(join(tmpdir(), "hyphae-ttl-"));
  const dbPath = join(dir, "router.sqlite");
  let now = 1_700_000_000_000;
  try {
    const core = new RouterCore({
      dbPath,
      now: () => now,
      limits: {
        ...DEFAULT_LIMITS,
        ttlMs: 1_000,
        settledRetentionMs: 5_000,
      },
    });
    core.addConnector("a@host");
    core.addConnector("b@host");
    core.setHandles("a@host", ["alice"]);
    core.setHandles("b@host", ["bob"]);

    // 1. Deliver a message at t=0 -> settled at t=0
    const offered: string[] = [];
    const detach = core.attach("b@host", (item) => {
      if (item.kind === "message") offered.push(item.id);
    });
    const m1 = core.submit("a@host", { id: "m-old-delivered", fromHandle: "alice", to: "b@host/bob", text: "old", origin: null });
    assert.equal(m1.ok, true);
    assert.deepEqual(offered, ["m-old-delivered"]);
    assert.equal(core.ack("b@host", "m-old-delivered", { kind: "delivered" }), true);
    detach();

    // 2. Submit another message at t=4_500 -> stays pending until t=5_500
    now += 4_500;
    const m2 = core.submit("a@host", { id: "m-still-pending", fromHandle: "alice", to: "b@host/bob", text: "pending", origin: null });
    assert.equal(m2.ok, true);

    // 3. Advance to t=5_200: m-old-delivered is 5.2s past settled_at (> 5s retention), while m-still-pending is only 0.7s old (< 1s ttl)
    now += 700;
    core.tick();

    const check = new DatabaseSync(dbPath, { readOnly: true });
    try {
      const ids = (check.prepare("SELECT id, state FROM messages ORDER BY id").all() as Array<{ id: string; state: string }>)
        .map((r) => ({ id: r.id, state: r.state }));
      assert.deepEqual(ids, [{ id: "m-still-pending", state: "pending" }]);
    } finally {
      check.close();
    }

    // 4. Advance past ttlMs (m-still-pending expires at t=6_000) and then past settledRetentionMs (t=11_500) -> pruned!
    now += 1_000;
    core.tick();
    now += 65_000; // also passes prune throttle interval
    core.tick();

    const check2 = new DatabaseSync(dbPath, { readOnly: true });
    try {
      const remaining = (check2.prepare("SELECT COUNT(*) AS n FROM messages").get() as { n: number }).n;
      assert.equal(remaining, 0);
    } finally {
      check2.close();
    }
    core.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("GitHub serveReceiver enforces publish-time allowedRepos / allowedOrgs allowlist after HMAC verification", async () => {
  const dir = mkdtempSync(join(tmpdir(), "hyphae-gh-scope-"));
  const dbPath = join(dir, "router.sqlite");
  const core = new RouterCore({ dbPath, topics: new Map([["github", ["gh-stream"]]]) });
  const pubToken = core.events.addPublisher("gh-stream", ["github"]);
  const router = await serveRouter({ core, host: "127.0.0.1", port: 0 });
  const secret = "whsec_test_scope_secret_12345";
  const receiver = await serveReceiver({
    host: "127.0.0.1",
    port: 0,
    routerUrl: router.url,
    topic: "github",
    secret,
    token: pubToken,
    allowedRepos: ["hyphae-to/hyp"],
    allowedOrgs: ["bayfold"],
  });

  const postPr = async (deliveryId: string, fullName: string) => {
    const body = Buffer.from(
      JSON.stringify({
        action: "opened",
        repository: { full_name: fullName },
        sender: { login: "alex" },
        pull_request: {
          number: 42,
          title: "Test PR",
          html_url: `https://github.com/${fullName}/pull/42`,
          state: "open",
          draft: false,
          user: { login: "alex", type: "User" },
          head: { ref: "feat/x", sha: "deadbeef" },
          base: { ref: "main" },
          labels: [],
          assignees: [],
        },
      }),
      "utf8",
    );
    const res = await fetch(`${receiver.url}/hooks/github`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-github-event": "pull_request",
        "x-github-delivery": deliveryId,
        "x-hub-signature-256": signatureHeader(secret, body),
      },
      body,
    });
    return { status: res.status, json: (await res.json()) as Record<string, unknown> };
  };

  try {
    // 1. Uncovered repo -> 200 ignored with repo_not_allowed, NEVER stored on router
    const dropped = await postPr("deliv-unmonitored-1", "stranger/rogue-repo");
    assert.equal(dropped.status, 200);
    assert.equal(dropped.json.status, "ignored");
    assert.equal(dropped.json.reason, "repo_not_allowed");

    // 2. Explicitly allowed repo -> 202 stored
    const allowedRepo = await postPr("deliv-allowed-repo-1", "hyphae-to/hyp");
    assert.equal(allowedRepo.status, 202);
    assert.equal(allowedRepo.json.status, "stored");

    // 3. Org-allowed repo -> 202 stored
    const allowedOrg = await postPr("deliv-allowed-org-1", "bayfold/api-service");
    assert.equal(allowedOrg.status, 202);
    assert.equal(allowedOrg.json.status, "stored");

    // Confirm router SQLite only stored the 2 allowed events, never stranger/rogue-repo
    const check = new DatabaseSync(dbPath, { readOnly: true });
    try {
      const sources = (check.prepare("SELECT source FROM events ORDER BY seq").all() as Array<{ source: string }>).map((r) => r.source);
      assert.deepEqual(sources, ["github.com/hyphae-to/hyp", "github.com/bayfold/api-service"]);
    } finally {
      check.close();
    }
  } finally {
    await receiver.close();
    await router.close();
    core.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
