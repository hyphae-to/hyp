import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { PluginConfig } from "../config.ts";
import type { ToolResponse } from "../ipc.ts";
import { EnrollmentStore } from "../store.ts";
import { PluginTargets } from "./targets.ts";

const BOOTSTRAP = "thread-moneypenny";
const plugins: PluginConfig[] = [
  {
    name: "slack",
    exec: "/bin/true",
    args: [],
    env: {},
    cwd: "/",
    targets: [{ name: "moneypenny", threadId: BOOTSTRAP, coalesceSeconds: 5, maxWaitSeconds: 30, wakesPerHour: 120 }],
  },
];
/** Threads in the fake shell cache; anything else is unknown, and "archived" is archived. */
const live = new Set([BOOTSTRAP, "thread-a", "thread-b"]);
const isLive = (threadId: string) => live.has(threadId);

const withStore = (body: (store: EnrollmentStore, path: string) => void) => {
  const dir = mkdtempSync(join(tmpdir(), "t3-mesh-targets-"));
  try {
    body(EnrollmentStore.load(join(dir, "state.json")), join(dir, "state.json"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
};
const code = (response: ToolResponse) => (response.ok ? "ok" : response.error.code);
const handoff = (targets: PluginTargets, caller: string, threadId: string, target = "moneypenny") =>
  targets.handoff(caller, { plugin: "slack", target, threadId }, isLive);

test("the holder hands off, the new holder can hand on, and the old one no longer can", () => {
  withStore((store) => {
    const targets = new PluginTargets(plugins, store);
    assert.equal(targets.threadOf("slack", "moneypenny"), BOOTSTRAP);
    assert.deepEqual(handoff(targets, BOOTSTRAP, "thread-a"), {
      ok: true,
      result: { plugin: "slack", target: "moneypenny", threadId: "thread-a" },
    });
    assert.equal(targets.threadOf("slack", "moneypenny"), "thread-a");
    assert.equal(code(handoff(targets, "thread-a", "thread-b")), "ok");
    assert.equal(code(handoff(targets, "thread-a", "thread-a")), "not_target_holder");
    assert.equal(targets.threadOf("slack", "moneypenny"), "thread-b");
  });
});

test("the configured thread can always reclaim its target", () => {
  withStore((store) => {
    const targets = new PluginTargets(plugins, store);
    handoff(targets, BOOTSTRAP, "thread-a");
    handoff(targets, "thread-a", "thread-b");
    assert.equal(code(handoff(targets, BOOTSTRAP, BOOTSTRAP)), "ok");
    assert.equal(targets.threadOf("slack", "moneypenny"), BOOTSTRAP);
  });
});

test("other threads, unknown targets and dead or archived threads are refused", () => {
  withStore((store) => {
    const targets = new PluginTargets(plugins, store);
    assert.equal(code(handoff(targets, "thread-a", "thread-a")), "not_target_holder");
    assert.equal(code(handoff(targets, BOOTSTRAP, "thread-a", "nobody")), "unknown_target");
    assert.equal(code(targets.handoff(BOOTSTRAP, { plugin: "github", target: "moneypenny", threadId: "thread-a" }, isLive)), "unknown_target");
    assert.equal(code(handoff(targets, BOOTSTRAP, "archived")), "unknown_thread");
    assert.equal(code(targets.handoff(BOOTSTRAP, { plugin: "slack" }, isLive)), "invalid");
    assert.equal(targets.threadOf("slack", "moneypenny"), BOOTSTRAP);
  });
});

test("handoffs persist in state.json, and older state files still load", () => {
  withStore((store, path) => {
    handoff(new PluginTargets(plugins, store), BOOTSTRAP, "thread-a");
    const saved: unknown = JSON.parse(readFileSync(path, "utf8"));
    assert.ok(typeof saved === "object" && saved !== null && "pluginTargets" in saved);
    const reloaded = new PluginTargets(plugins, EnrollmentStore.load(path));
    assert.equal(reloaded.threadOf("slack", "moneypenny"), "thread-a");

    writeFileSync(path, JSON.stringify({ version: 1, enrollments: [] }));
    assert.equal(new PluginTargets(plugins, EnrollmentStore.load(path)).threadOf("slack", "moneypenny"), BOOTSTRAP);
  });
});

test("mesh_plugin_targets lists what the caller holds or bootstraps", () => {
  withStore((store) => {
    const targets = new PluginTargets(plugins, store);
    const entry = (threadId: string) => ({ ok: true, result: { targets: [{ plugin: "slack", target: "moneypenny", threadId }] } });
    assert.deepEqual(targets.list(BOOTSTRAP), entry(BOOTSTRAP));
    assert.deepEqual(targets.list("thread-a"), { ok: true, result: { targets: [] } });
    handoff(targets, BOOTSTRAP, "thread-a");
    assert.deepEqual(targets.list("thread-a"), entry("thread-a"));
    assert.deepEqual(targets.list(BOOTSTRAP), entry("thread-a"), "the configured thread still sees it");
    assert.deepEqual(targets.list("thread-b"), { ok: true, result: { targets: [] } });
  });
});

const withConfigured = (threadId: string): PluginConfig[] =>
  plugins.map((plugin) => ({ ...plugin, targets: plugin.targets.map((target) => ({ ...target, threadId })) }));

test("a handoff thread that is gone reverts the target to its configured thread", () => {
  withStore((store) => {
    const targets = new PluginTargets(plugins, store);
    handoff(targets, BOOTSTRAP, "thread-a");
    assert.deepEqual(targets.resolve("slack", "moneypenny", isLive), { ok: true, threadId: "thread-a" });
    const gone = (threadId: string) => threadId !== "thread-a" && isLive(threadId);
    assert.deepEqual(targets.resolve("slack", "moneypenny", gone), { ok: true, threadId: BOOTSTRAP });
    assert.equal(store.pluginTarget("slack", "moneypenny"), undefined, "the record is deleted");
    assert.deepEqual(targets.resolve("slack", "moneypenny", isLive), { ok: true, threadId: BOOTSTRAP }, "and stays reverted");
    assert.equal(targets.resolve("slack", "nobody", isLive), undefined);
  });
});

test("with the configured thread gone too, the target is unavailable rather than rejected", () => {
  withStore((store) => {
    const targets = new PluginTargets(plugins, store);
    handoff(targets, BOOTSTRAP, "thread-a");
    assert.deepEqual(targets.resolve("slack", "moneypenny", () => false), { ok: false, threadId: BOOTSTRAP });
    assert.equal(store.pluginTarget("slack", "moneypenny"), undefined);
  });
});

test("reconcile reverts handoffs to gone threads ahead of any delivery", () => {
  withStore((store) => {
    const targets = new PluginTargets(plugins, store);
    handoff(targets, BOOTSTRAP, "thread-a");
    targets.reconcile(isLive, true);
    assert.equal(targets.threadOf("slack", "moneypenny"), "thread-a", "kept while live");
    targets.reconcile((threadId) => threadId !== "thread-a", false);
    assert.equal(store.pluginTarget("slack", "moneypenny"), undefined);
    assert.equal(targets.threadOf("slack", "moneypenny"), BOOTSTRAP);
  });
});

test("handoffs made under another configured thread, or for unconfigured targets, are dropped", () => {
  withStore((store, path) => {
    handoff(new PluginTargets(plugins, store), BOOTSTRAP, "thread-a");
    assert.equal(store.pluginTarget("slack", "moneypenny")?.configuredThreadId, BOOTSTRAP);
    // config.json now names another thread for the target: the old handoff no longer applies.
    const moved = new PluginTargets(withConfigured("thread-b"), EnrollmentStore.load(path));
    assert.equal(moved.threadOf("slack", "moneypenny"), "thread-b");
    assert.equal(EnrollmentStore.load(path).pluginTarget("slack", "moneypenny"), undefined, "deleted from state.json");

    handoff(new PluginTargets(plugins, EnrollmentStore.load(path)), BOOTSTRAP, "thread-a");
    assert.equal(EnrollmentStore.load(path).pluginTarget("slack", "moneypenny")?.threadId, "thread-a");
    new PluginTargets([], EnrollmentStore.load(path));
    assert.equal(EnrollmentStore.load(path).pluginTarget("slack", "moneypenny"), undefined, "plugin no longer configured");
  });
});

test("handoff records without configuredThreadId are dropped on load", () => {
  withStore((_store, path) => {
    const record = { plugin: "slack", target: "moneypenny", threadId: "thread-a", setAt: "2026-10-08T00:00:00Z", setBy: BOOTSTRAP };
    writeFileSync(path, JSON.stringify({ version: 1, enrollments: [], pluginTargets: [record] }));
    const store = EnrollmentStore.load(path);
    assert.deepEqual(store.pluginTargets(), []);
    assert.equal(new PluginTargets(plugins, store).threadOf("slack", "moneypenny"), BOOTSTRAP);
  });
});

test("without plugins both tools answer no_plugins", () => {
  withStore((store) => {
    const targets = new PluginTargets([], store);
    assert.equal(code(targets.list(BOOTSTRAP)), "no_plugins");
    assert.equal(code(handoff(targets, BOOTSTRAP, "thread-a")), "no_plugins");
  });
});
