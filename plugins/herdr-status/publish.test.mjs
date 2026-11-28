import assert from "node:assert/strict";
import test from "node:test";
import { parseBinding, projectTerminal, publishStatus } from "./publish.mjs";

function harness() {
  const rows = new Map();
  const events = [];
  let time = 10_000;
  const kv = (binding) => ({
    async get(ns) {
      return rows.get(`${ns}/${binding.key}`) ?? null;
    },
    async set(ns, value, expectedVersion) {
      const id = `${ns}/${binding.key}`;
      const existing = rows.get(id);
      assert.equal(existing?.version ?? 0, expectedVersion);
      const entry = { writeModel: "owner", version: expectedVersion + 1, value };
      rows.set(id, entry);
      events.push({ ns, key: binding.key, value });
      return entry;
    },
  });
  return {
    kv, events, now: () => time, advance: (ms) => { time += ms; },
  };
}

const binding = (key, terminal, created = "100") => parseBinding([key, terminal, created, "/test-state"]);
const terminal = (id, state, kind) => ({
  address: id, created_ms: 100, state: "live",
  argv: ["PRIVATE_ARG"], cwd: "/PRIVATE_PATH", title: "PRIVATE_TITLE",
  status: { state, kind, app: "PRIVATE_APP", msg: "PRIVATE_PROMPT" },
});
const snapshot = (seq, term) => ({ seq, terminals: [term] });
const event = (seq, id, type, data) => ({ method: "event", params: { seq, terminal: id, type, data } });

test("two pinned builders publish only transitions on their exact status keys", async () => {
  const h = harness();
  const a = binding("builder-a", "t1");
  const b = binding("builder-b", "t2");
  const firstTerminal = terminal("t1", "working");
  async function* first() {
    yield snapshot(1, firstTerminal);
    yield event(2, "t1", "status", { status: { state: "working", msg: "PRIVATE_CHANGED" } });
    h.advance(30_000);
    yield { method: "heartbeat", params: { seq: 2 } };
    yield event(3, "t2", "status", { status: { state: "error" } });
    yield event(4, "t1", "status", { status: { state: "blocked", kind: "question" } });
    yield event(5, "t1", "status", { status: { state: "working" } });
    yield event(6, "t1", "lost", {});
    yield event(7, "t1", "restarted", firstTerminal);
    yield { method: "missed", params: snapshot(9, terminal("t1", "done")) };
    yield event(8, "t1", "status", { status: { state: "error" } });
    yield event(10, "t1", "finished", { exit_code: 0 });
  }
  async function* second() {
    yield snapshot(1, terminal("t2", "idle"));
    yield event(2, "t2", "status", { status: { state: "blocked", kind: "permission" } });
  }
  await publishStatus(a, first(), h.kv(a), h.now);
  await publishStatus(b, second(), h.kv(b), h.now);
  const filtered = (key) => h.events
    .filter((ev) => ev.ns === "herdr-status" && ev.key === key)
    .map(({ value }) => [value.state, value.kind]);
  assert.deepEqual(filtered("builder-a"), [
    ["working", undefined], ["blocked", "question"], ["working", undefined], ["unknown", undefined],
    ["working", undefined], ["done", undefined], ["finished", undefined],
  ]);
  assert.deepEqual(filtered("builder-b"), [["idle", undefined], ["blocked", "permission"]]);
  assert.doesNotMatch(JSON.stringify(h.events), /PRIVATE|t1|t2/);
  assert.equal((await h.kv(a).get("herdr-status-lease")).value.validUntil, 0);
  assert.equal((await h.kv(b).get("herdr-status-lease")).value.validUntil, 0);
  assert.equal(h.events.filter((ev) => ev.ns === "herdr-status-lease" && ev.key === a.key).length, 9);
});

test("restart bootstrap deduplicates and recycled terminals cannot claim a status key", async () => {
  const h = harness();
  const a = binding("builder-a", "t1");
  const kv = h.kv(a);
  const frames = [snapshot(0, terminal("t1", "working"))];
  await publishStatus(a, frames, kv, h.now);
  await publishStatus(a, frames, kv, h.now);
  assert.equal((await kv.get("herdr-status")).version, 1);
  await assert.rejects(publishStatus(binding("builder-a", "t1", "101"), frames, kv, h.now),
    /already belongs/);
  await assert.rejects(publishStatus(a, [snapshot(0, { ...terminal("t1", "working"), created_ms: 101 })],
    kv, h.now), /identity changed/);
  assert.deepEqual(projectTerminal(terminal("t1", "private-freeform-status"), a), { state: "unknown" });
  assert.deepEqual(projectTerminal(terminal("t1", "blocked", "private-kind"), a), { state: "blocked" });
});

test("a duplicate publisher cannot claim a live key, and stale leases are bounded", async () => {
  const h = harness();
  const a = binding("builder-a", "t1");
  const kv = h.kv(a);
  const frames = [snapshot(0, terminal("t1", "working"))];
  async function* stream() {
    yield frames[0];
    const lease = await kv.get("herdr-status-lease");
    assert.equal(lease.value.validUntil, h.now() + 75_000);
    assert.equal(lease.value.statusVersion, (await kv.get("herdr-status")).version);
    await assert.rejects(publishStatus(a, frames, kv, h.now), /active publisher/);
    h.advance(75_000);
    yield { method: "heartbeat" };
  }
  await assert.rejects(publishStatus(a, stream(), kv, h.now), /lease expired/);
  assert.equal((await kv.get("herdr-status")).version, 1);
  assert.equal((await kv.get("herdr-status-lease")).value.validUntil, 0);
});
