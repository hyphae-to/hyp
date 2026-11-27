// Zero-dependency Node 24 test suite for plugins/herdr-mod.
// Verifies terminal address parsing, state_dir resolution, session matching &
// anti-recycle pinning, pill formatting, anti-body-leakage invariants,
// quick-control argv generation, local watcher lifecycle, remote cache dedup,
// pill.js composition rendering, and Herdr mod quality gates.

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import moduleApi from "node:module";
import { fileURLToPath } from "node:url";

import {
  buildSessionControlArgs,
  createHyphaeClient,
  findLayoutNode,
  formatPillMetrics,
  formatRelativeAge,
  getEffectiveQuarantinedCount,
  parseSnapshotJson,
  parseTerminalAddress,
  qualifyChannelTarget,
  resolveSessionById,
  resolveSessionForTerminal,
  resolveUiStateCandidates,
  sanitizeUiText,
  stripControlChars,
  withAlpha,
} from "../mods/hyphae-pane/shared-client.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const MOD_ROOT = path.resolve(__dirname, "..");

test("parseTerminalAddress handles local, remote SSH, and empty inputs", () => {
  assert.deepEqual(parseTerminalAddress("t4g"), {
    machine: null,
    rawTid: "t4g",
    address: "t4g",
  });
  assert.deepEqual(parseTerminalAddress("maple-relay/t4g"), {
    machine: "maple-relay",
    rawTid: "t4g",
    address: "maple-relay/t4g",
  });
  assert.deepEqual(parseTerminalAddress("  cedar-desk/t12  "), {
    machine: "cedar-desk",
    rawTid: "t12",
    address: "cedar-desk/t12",
  });
  assert.deepEqual(parseTerminalAddress(""), {
    machine: null,
    rawTid: null,
    address: null,
  });
  assert.deepEqual(parseTerminalAddress(null), {
    machine: null,
    rawTid: null,
    address: null,
  });
});

test("resolveUiStateCandidates mirrors hyp-cli default and custom stateDir paths", () => {
  const def = resolveUiStateCandidates("/Users/alice", null);
  assert.deepEqual(def.dirs, [
    "/Users/alice/.config/hyphae/ui",
    "/Users/alice/.config/hyphae/state/ui",
  ]);
  assert.equal(def.files[0], "/Users/alice/.config/hyphae/ui/state.json");

  const customAbs = resolveUiStateCandidates(
    "/Users/alice",
    JSON.stringify({ stateDir: "/var/lib/hyphae" })
  );
  assert.equal(customAbs.dirs[0], "/var/lib/hyphae/ui");
  assert.equal(customAbs.dirs[1], "/Users/alice/.config/hyphae/ui");

  const customTilde = resolveUiStateCandidates(
    "/Users/alice",
    JSON.stringify({ stateDir: "~/custom-hyp" })
  );
  assert.equal(customTilde.dirs[0], "/Users/alice/custom-hyp/ui");

  const customRel = resolveUiStateCandidates(
    "/Users/alice",
    JSON.stringify({ stateDir: "state" })
  );
  assert.equal(customRel.dirs[0], "/Users/alice/.config/hyphae/state/ui");
  assert.equal(customRel.dirs[1], "/Users/alice/.config/hyphae/ui");
  assert.equal(customRel.dirs.length, 2);

  // Malformed node.json safely falls back to defaults.
  const malformed = resolveUiStateCandidates("/Users/alice", "{not json");
  assert.deepEqual(malformed.dirs, def.dirs);
});

test("resolveSessionForTerminal resolves byHerdrTerminal and rejects recycled created_ms", () => {
  const snapshot = {
    schemaVersion: 1,
    rev: 12,
    sessions: [
      {
        sessionId: "claude:old",
        harness: "claude",
        enrolled: true,
        handle: "old-agent",
        herdrTerminalId: "t4g",
        herdrCreatedMs: 1000,
        lastSeen: 1500,
        hasLiveTransport: false,
      },
      {
        sessionId: "codex:live",
        harness: "codex",
        enrolled: true,
        handle: "alice",
        herdrTerminalId: "t4g",
        herdrCreatedMs: 2000,
        lastSeen: 2500,
        hasLiveTransport: true,
      },
    ],
    byHerdrTerminal: {
      t4g: "claude:old",
    },
  };

  // Without created_ms, follows byHerdrTerminal.
  assert.equal(resolveSessionForTerminal(snapshot, "t4g")?.sessionId, "claude:old");

  // With new recycled terminal created_ms=2000, rejects stale claude:old and picks codex:live!
  assert.equal(resolveSessionForTerminal(snapshot, "t4g", 2000)?.sessionId, "codex:live");

  // With brand-new created_ms=3000 matching neither pinned session, returns null!
  assert.equal(resolveSessionForTerminal(snapshot, "t4g", 3000), null);

  assert.equal(resolveSessionById(snapshot, "codex:live")?.handle, "alice");
});

test("formatPillMetrics hides plain shells and formats enrolled, queued, focus, muted, and quarantined states", () => {
  // Unenrolled with 0 subs & 0 queued -> hidden (zero visual clutter)
  const plain = formatPillMetrics({
    enrolled: false,
    handle: null,
    counts: { subscriptions: 0, queued: 0, quarantined: 0 },
  });
  assert.equal(plain.visible, false);
  assert.equal(formatPillMetrics(null).visible, false);

  // Enrolled idle
  const idle = formatPillMetrics({
    enrolled: true,
    handle: "alice",
    focusMode: false,
    mutedAll: false,
    counts: { subscriptions: 3, queued: 0, quarantined: 0 },
  });
  assert.equal(idle.visible, true);
  assert.equal(idle.tone, "active");
  assert.equal(idle.compactLabel, "3s");
  assert.equal(idle.mediumLabel, "3s");
  assert.equal(idle.wideLabel, "@alice · 3 subs");
  assert.equal(idle.alertLabel, null);

  // Queued + Focus Mode
  const queuedFocus = formatPillMetrics({
    enrolled: true,
    handle: "alice",
    focusMode: true,
    mutedAll: false,
    counts: { subscriptions: 3, queued: 2, quarantined: 0 },
  });
  assert.equal(queuedFocus.visible, true);
  assert.equal(queuedFocus.tone, "queued");
  assert.equal(queuedFocus.chip, "focus");
  assert.equal(queuedFocus.compactLabel, "3·2");
  assert.equal(queuedFocus.mediumLabel, "focus · 3s · 2q");
  assert.equal(queuedFocus.wideLabel, "@alice · FOCUS · 3 subs · 2 queued");

  // Quarantined alert overrides tone and sets ⚠ N badge
  const quarantined = formatPillMetrics({
    enrolled: true,
    handle: "alice\u001b[31m\x07",
    focusMode: false,
    mutedAll: true,
    counts: { subscriptions: 1, queued: 0, quarantined: 2 },
  });
  assert.equal(quarantined.tone, "alert");
  assert.equal(quarantined.chip, "muted");
  assert.equal(quarantined.alertLabel, "⚠ 2");
  assert.equal(quarantined.handle, "alice");
  assert.ok(!quarantined.wideLabel.includes("\u001b"));

  // U3: daemon.quarantinedGlobal surfaces on the pill even when session.counts.quarantined === 0
  const globalQuarantined = formatPillMetrics(
    {
      enrolled: true,
      handle: "alice",
      counts: { subscriptions: 1, queued: 0, quarantined: 0 },
    },
    { quarantinedGlobal: 4 }
  );
  assert.equal(globalQuarantined.visible, true);
  assert.equal(globalQuarantined.quarantined, 4);
  assert.equal(globalQuarantined.tone, "alert");
  assert.equal(globalQuarantined.alertLabel, "⚠ 4");
  assert.equal(
    getEffectiveQuarantinedCount({ counts: { quarantined: 1 } }, { daemon: { quarantinedGlobal: 3 } }),
    3
  );
  assert.equal(
    getEffectiveQuarantinedCount({ counts: { quarantined: 5 } }, { daemon: { quarantinedGlobal: 2 } }),
    5
  );

  // U15: linked bridges surface in the Herdr pane pill across density modes
  const bridged = formatPillMetrics({
    enrolled: true,
    handle: "integration-tests",
    bridges: ["telegram:\u001b[31mpersonal\u001b[0m"],
    counts: { bridges: 1, subscriptions: 0, queued: 0, quarantined: 0 },
  });
  assert.equal(bridged.visible, true);
  assert.equal(bridged.bridges, 1);
  assert.equal(bridged.bridgeSummary, "telegram:personal");
  assert.equal(bridged.compactLabel, "telegram");
  assert.equal(bridged.mediumLabel, "telegram:personal");
  assert.equal(bridged.wideLabel, "@integration-tests · telegram:personal");
  assert.ok(!bridged.wideLabel.includes("\u001b"));

  const multiBridged = formatPillMetrics({
    enrolled: false,
    handle: null,
    bridges: ["telegram:personal", "slack:ops"],
    counts: { bridges: 2, subscriptions: 1, queued: 0, quarantined: 0 },
  });
  assert.equal(multiBridged.visible, true);
  assert.equal(multiBridged.bridgeSummary, "telegram:personal +1");
  assert.equal(multiBridged.compactLabel, "2b·1s");
  assert.equal(multiBridged.mediumLabel, "telegram:personal +1 · 1s");
  assert.equal(multiBridged.wideLabel, "telegram:personal +1 · 1 sub");
});

test("anti-body-leakage invariant: parseSnapshotJson strips body/text/payload/secret keys", () => {
  const dirty = JSON.stringify({
    ok: true,
    command: "inspect",
    data: {
      schemaVersion: 1,
      rev: 7,
      updatedAt: 1795588123456,
      daemon: {
        online: true,
        nodeId: "alice@mac",
        secret: "SUPER_SECRET_KEY",
      },
      sessions: [
        {
          sessionId: "claude:1",
          enrolled: true,
          handle: "alice",
          token: "hp2p1_never_leak",
          counts: { subscriptions: 1, queued: 1, quarantined: 0 },
          details: {
            queuedItems: [
              {
                receipt: "rcpt_1",
                kind: "message",
                source: "bob/rev",
                body: "SECRET_MESSAGE_BODY",
                text: "SECRET_TEXT",
                payload: { leak: true },
              },
            ],
          },
        },
      ],
      byHerdrTerminal: { t4g: "claude:1" },
    },
  });

  const snap = parseSnapshotJson(dirty);
  assert.ok(snap);
  const serialized = JSON.stringify(snap);
  for (const sentinel of [
    "SUPER_SECRET_KEY",
    "hp2p1_never_leak",
    "SECRET_MESSAGE_BODY",
    "SECRET_TEXT",
  ]) {
    assert.ok(!serialized.includes(sentinel), `Leaked sentinel: ${sentinel}`);
  }
  assert.equal(snap.sessions[0].details.queuedItems[0].source, "bob/rev");
});

test("sanitizeUiText, stripControlChars, and qualifyChannelTarget preserve long control values without truncation (U2 & U9)", () => {
  assert.equal(sanitizeUiText("\u001b[1;31malice\u001b[0m\r\n\t"), "alice");
  assert.equal(sanitizeUiText("\u001b]8;;https://evil.test\u0007click\u001b]8;;\u0007"), "click");
  assert.equal(withAlpha("#33aa66", "26"), "#33aa6626");
  assert.equal(withAlpha("#33aa6680", "26"), "#33aa6680");

  // Long patterns (>120 chars) keep full length under stripControlChars while stripping ANSI/BiDi
  const longPattern = `#very-long-channel-${"a".repeat(140)}`;
  assert.equal(stripControlChars(`\u001b[31m${longPattern}\u202e\u001b[0m`), longPattern);
  assert.ok(!stripControlChars(longPattern).includes("…"));
  assert.ok(sanitizeUiText(longPattern, 64).endsWith("…"));

  // U2: qualifyChannelTarget always qualifies local & remote channels without double-prefixing
  assert.equal(qualifyChannelTarget("alice@macbook", "#ops", "alice@macbook"), "alice@macbook/#ops");
  assert.equal(qualifyChannelTarget("local", "#ops", "alice@macbook"), "local/#ops");
  assert.equal(qualifyChannelTarget("", "#ops", "alice@macbook"), "alice@macbook/#ops");
  assert.equal(qualifyChannelTarget("", "#ops", ""), "local/#ops");
  assert.equal(qualifyChannelTarget("acme-hub", "#release", "alice@macbook"), "acme-hub/#release");
  assert.equal(qualifyChannelTarget("local", "acme-hub/#release", "alice@macbook"), "acme-hub/#release");
  assert.equal(qualifyChannelTarget("local", longPattern, "alice@macbook"), `local/${longPattern}`);
});

test("buildSessionControlArgs generates exact hyp session CLI argv", () => {
  assert.deepEqual(
    buildSessionControlArgs("focus", { rawTid: "t4g" }, { enabled: true }),
    ["session", "focus", "--herdr-terminal", "t4g", "on", "--json"]
  );
  assert.deepEqual(
    buildSessionControlArgs("mute", { rawTid: "t4g" }, { pattern: "*", scope: "session" }),
    ["session", "mute", "--herdr-terminal", "t4g", "--json", "*"]
  );
  assert.deepEqual(
    buildSessionControlArgs("unmute", { sessionId: "claude:abc" }, { pattern: "-weird", scope: "connector" }),
    ["session", "unmute", "--session", "claude:abc", "--scope", "connector", "--json", "--", "-weird"]
  );
  assert.deepEqual(
    buildSessionControlArgs("rule", { rawTid: "t4g" }, { target: "bob/rev", delivery: "interrupt" }),
    ["session", "rule", "--herdr-terminal", "t4g", "--json", "bob/rev", "interrupt"]
  );
  assert.deepEqual(
    buildSessionControlArgs("unsubscribe", { rawTid: "t4g" }, { id: "sub_01" }),
    ["session", "unsubscribe", "--herdr-terminal", "t4g", "--json", "sub_01"]
  );
  assert.deepEqual(
    buildSessionControlArgs("leave", { rawTid: "t4g" }, { channel: "#ops" }),
    ["session", "leave", "--herdr-terminal", "t4g", "--json", "#ops"]
  );
});

test("relative age formatting", () => {
  const now = 1_700_000_000_000;
  assert.equal(formatRelativeAge(now - 2000, now), "now");
  assert.equal(formatRelativeAge(now - 15_000, now), "15s");
  assert.equal(formatRelativeAge(now - 180_000, now), "3m");
});

test("createHyphaeClient cancels watchFolder cleanly on dispose and deduplicates remote fetches", async () => {
  let cancelled = 0;
  let resolveWatch;
  const watchPromise = new Promise((resolve) => {
    resolveWatch = resolve;
  });
  watchPromise.cancel = () => {
    cancelled += 1;
    resolveWatch([]);
  };

  const sharedStore = {};
  let execCalls = 0;
  let localPresent = true;
  const host = {
    home: () => "/Users/alice",
    readTextFile: async (p) => {
      if (localPresent && p.endsWith("/ui/state.json")) {
        return JSON.stringify({
          schemaVersion: 1,
          rev: 3,
          sessions: [{ sessionId: "claude:1", enrolled: true, handle: "alice", herdrTerminalId: "t4g" }],
          byHerdrTerminal: { t4g: "claude:1" },
        });
      }
      return null;
    },
    watchFolder: () => watchPromise,
    exec: async (_cmd, _args, opts) => {
      execCalls += 1;
      assert.equal(opts.on, "maple-relay");
      return {
        code: 0,
        stdout: JSON.stringify({
          ok: true,
          data: {
            schemaVersion: 1,
            rev: 9,
            sessions: [{ sessionId: "codex:r1", enrolled: true, handle: "remote-bob", herdrTerminalId: "t2" }],
            byHerdrTerminal: { t2: "codex:r1" },
          },
        }),
        stderr: "",
      };
    },
    shared: (k) => sharedStore[k],
    setShared: (k, v) => {
      sharedStore[k] = v;
    },
    terminals: () => [{ address: "t4g", created_ms: 100 }],
  };

  const pendingTasks = [];
  const fakeCx = {
    notify: () => {},
    spawn: (fn) => {
      pendingTasks.push(fn(fakeCx));
    },
  };

  const client = createHyphaeClient(host);
  client.ensureLocal(fakeCx);
  // Wait a microtask tick for loadLocalOnce() to populate localSnapshot.
  await new Promise((r) => setTimeout(r, 15));
  assert.equal(client.resolveTerminal("t4g").entry?.handle, "alice");

  // Trigger two concurrent remote refreshes -> must dedup to 1 exec call!
  client.ensureRemoteFresh("maple-relay", fakeCx, false);
  client.ensureRemoteFresh("maple-relay", fakeCx, false);
  await new Promise((r) => setTimeout(r, 15));
  assert.equal(execCalls, 1);
  assert.equal(client.resolveTerminal("maple-relay/t2").entry?.handle, "remote-bob");

  localPresent = false;
  await client.refreshNow(null, fakeCx);
  assert.equal(client.getSnapshot(), null);

  // Dispose must call watch.cancel() cleanly.
  client.dispose();
  await Promise.allSettled(pendingTasks);
  assert.equal(cancelled, 1);
});

test("U5: multiple pane clients sharing shared() deduplicate in-flight remote SSH fetches via hyphae.remoteInFlight", async () => {
  const sharedStore = {};
  let execCalls = 0;
  let resolveExec;
  const execPromise = new Promise((resolve) => {
    resolveExec = resolve;
  });

  const makeHost = () => ({
    home: () => "/Users/alice",
    readTextFile: async () => null,
    watchFolder: () => {
      const p = new Promise(() => {});
      p.cancel = () => {};
      return p;
    },
    exec: async (_cmd, _args, opts) => {
      execCalls += 1;
      assert.equal(opts.on, "maple-relay");
      return execPromise;
    },
    shared: (k) => sharedStore[k],
    setShared: (k, v) => {
      sharedStore[k] = v;
    },
    terminals: () => [],
  });

  const pendingTasks = [];
  const fakeCx = {
    notify: () => {},
    spawn: (fn) => {
      pendingTasks.push(fn(fakeCx));
    },
  };

  // Simulate 3 separate panes on SSH host `maple-relay` starting up simultaneously!
  const paneA = createHyphaeClient(makeHost());
  const paneB = createHyphaeClient(makeHost());
  const paneC = createHyphaeClient(makeHost());

  paneA.ensureRemoteFresh("maple-relay", fakeCx, false);
  // Lock MUST be written synchronously BEFORE exec completes so panes B & C dedup immediately!
  assert.equal(typeof sharedStore["hyphae.remoteInFlight"]?.["maple-relay"], "number");

  paneB.ensureRemoteFresh("maple-relay", fakeCx, false);
  paneC.ensureRemoteFresh("maple-relay", fakeCx, false);
  assert.equal(execCalls, 1, "3 panes on the same SSH host must share ONE in-flight exec");

  resolveExec({
    code: 0,
    stdout: JSON.stringify({
      ok: true,
      data: {
        schemaVersion: 1,
        rev: 15,
        daemon: { online: true, nodeId: "maple-relay", quarantinedGlobal: 0 },
        sessions: [{ sessionId: "claude:r1", enrolled: true, handle: "remote-alice", herdrTerminalId: "t2" }],
        byHerdrTerminal: { t2: "claude:r1" },
      },
    }),
    stderr: "",
  });
  await Promise.allSettled(pendingTasks);

  // Lock must be released after completion, and all panes resolve the shared cached snapshot.
  assert.equal(sharedStore["hyphae.remoteInFlight"]?.["maple-relay"], undefined);
  assert.equal(paneA.resolveTerminal("maple-relay/t2").entry?.handle, "remote-alice");
  assert.equal(paneB.resolveTerminal("maple-relay/t2").entry?.handle, "remote-alice");
  assert.equal(paneC.resolveTerminal("maple-relay/t2").entry?.handle, "remote-alice");

  // Stale in-flight lock older than TTL must automatically recover instead of deadlocking!
  sharedStore["hyphae.remoteCache"] = {};
  sharedStore["hyphae.remoteInFlight"] = { "maple-relay": Date.now() - 30_000 };
  paneB.ensureRemoteFresh("maple-relay", fakeCx, false);
  assert.equal(execCalls, 2, "expired stale in-flight lock must allow a fresh remote fetch");

  paneA.dispose();
  paneB.dispose();
  paneC.dispose();
});

test("pill.js renderHyphaePill integrates cleanly and dispatches dock vs overlay clicks", async () => {
  const calls = { setShared: [], run: [], openOverlay: [] };
  let mockLayout = {
    id: "root",
    children: [
      {
        id: "panel",
        hidden: true,
        children: [{ id: "panel-body", active: "files", children: [{ id: "files" }] }],
      },
    ],
  };

  // Register lightweight in-memory hooks for virtual Herdr modules in Node 24.
  const hooks = moduleApi.registerHooks({
    resolve(specifier, context, nextResolve) {
      if (specifier === "gpui-kit" || specifier === "gpui-base" || specifier === "herdr") {
        return { url: `hyphae-mock:${specifier}`, shortCircuit: true };
      }
      return nextResolve(specifier, context);
    },
    load(url, context, nextLoad) {
      if (url === "hyphae-mock:gpui-kit") {
        return {
          format: "module",
          shortCircuit: true,
          source: `
            function makeEl(tag, extra = {}) {
              const node = { tag, props: { ...extra }, children: [], handlers: {} };
              const proxy = new Proxy(node, {
                get(target, prop) {
                  if (prop in target) return target[prop];
                  if (prop === "when") return (cond, fn) => (cond ? fn(proxy) : proxy);
                  if (prop === "child") return (c) => { target.children.push(c); return proxy; };
                  if (prop === "children") return (arr) => { target.children.push(...arr); return proxy; };
                  if (prop === "on_click") return (fn) => { target.handlers.click = fn; return proxy; };
                  if (prop === "on_mouse_down") return (_b, fn) => { target.handlers.mouseDown = fn; return proxy; };
                  return (...args) => { target.props[prop] = args; return proxy; };
                }
              });
              return proxy;
            }
            export const div = () => makeEl("div");
            export const svg = (p) => makeEl("svg", { path: p });
            export const image = (p) => makeEl("image", { path: p });
          `,
        };
      }
      if (url === "hyphae-mock:gpui-base") {
        return {
          format: "module",
          shortCircuit: true,
          source: `
            import { div } from "gpui-kit";
            export const h_flex = () => div();
          `,
        };
      }
      if (url === "hyphae-mock:herdr") {
        return {
          format: "module",
          shortCircuit: true,
          source: `
            export const layout = () => globalThis.__hyphaeTestMock.getLayout();
            export const run = (cmd, args) => globalThis.__hyphaeTestMock.calls.run.push({ cmd, args });
            export const openOverlay = (spec) => globalThis.__hyphaeTestMock.calls.openOverlay.push(spec);
            export const setShared = (k, v) => globalThis.__hyphaeTestMock.calls.setShared.push({ k, v });
          `,
        };
      }
      return nextLoad(url, context);
    },
  });

  globalThis.__hyphaeTestMock = {
    getLayout: () => mockLayout,
    calls,
  };

  try {
    const pillMod = await import("../mods/hyphae-pane/pill.js");
    const theme = {
      foreground: "#ffffff",
      muted: "#aaaaaa",
      dim: "#777777",
      border: "#333333",
      hover: "#222222",
      raised: "#1a1a1a",
      surface: "#111111",
      accent: "#5599ff",
      done: "#44bb77",
      blocked: "#ee9933",
      ansi1: "#ee4444",
      ansi2: "#44bb77",
      ansi3: "#ee9933",
    };

    // Unenrolled empty -> returns null
    const hidden = pillMod.renderHyphaePill({
      theme,
      paneId: "p1",
      terminal: "t4g",
      entry: { enrolled: false, counts: { subscriptions: 0, queued: 0, quarantined: 0 } },
    });
    assert.equal(hidden, null);

    // Enrolled queued -> returns pill element and opens floating overlay when layout has no hyphae block
    const el = pillMod.renderHyphaePill({
      theme,
      paneId: "p1",
      terminal: "maple-relay/t4g",
      entry: {
        sessionId: "claude:1",
        enrolled: true,
        handle: "alice",
        focusMode: true,
        counts: { subscriptions: 3, queued: 2, quarantined: 0 },
      },
      compact: true,
    });
    assert.ok(el);
    let stopped = false;
    el.handlers.click({}, { stop_propagation: () => { stopped = true; } });
    assert.equal(stopped, true);
    assert.equal(calls.setShared[0].k, "hyphae.selected");
    assert.equal(calls.setShared[0].v.machine, "maple-relay");
    assert.equal(calls.setShared[0].v.rawTid, "t4g");
    assert.equal(calls.openOverlay.length, 1);
    assert.equal(calls.openOverlay[0].mod, "hyphae-panel");
    assert.equal(calls.run.length, 0);

    // When active layout has a `hyphae` child in `panel-body`, clicking selects & shows dock panel instead!
    mockLayout.children[0].children[0].children.push({ id: "hyphae" });
    el.handlers.click({}, { stop_propagation: () => {} });
    assert.equal(calls.run.length, 2);
    assert.deepEqual(calls.run[0], { cmd: "layout.select", args: { stack: "panel-body", child: "hyphae" } });
    assert.deepEqual(calls.run[1], { cmd: "layout.show", args: { id: "panel" } });
  } finally {
    delete globalThis.__hyphaeTestMock;
    hooks.deregister();
  }
});

test("static Herdr mod quality gates & file parity", () => {
  const paneClient = fs.readFileSync(path.join(MOD_ROOT, "mods/hyphae-pane/shared-client.js"), "utf8");
  const panelClient = fs.readFileSync(path.join(MOD_ROOT, "mods/hyphae-panel/shared-client.js"), "utf8");
  assert.equal(paneClient, panelClient, "shared-client.js must stay byte-identical across both mods");

  const paneSvg = fs.readFileSync(path.join(MOD_ROOT, "mods/hyphae-pane/hyphae.svg"), "utf8");
  const panelSvg = fs.readFileSync(path.join(MOD_ROOT, "mods/hyphae-panel/hyphae.svg"), "utf8");
  assert.equal(paneSvg, panelSvg, "hyphae.svg must stay byte-identical across both mods");

  const jsFiles = [
    "mods/hyphae-pane/shared-client.js",
    "mods/hyphae-pane/pill.js",
    "mods/hyphae-pane/main.js",
    "mods/hyphae-panel/shared-client.js",
    "mods/hyphae-panel/main.js",
  ];
  for (const rel of jsFiles) {
    const src = fs.readFileSync(path.join(MOD_ROOT, rel), "utf8");
    assert.ok(!/\bsetTimeout\s*\(/.test(src), `${rel} must never call setTimeout`);
    assert.ok(!/\bsetInterval\s*\(/.test(src), `${rel} must never call setInterval`);
    assert.ok(!/from\s+["']\.\.\//.test(src), `${rel} must not use ../ imports (Herdr per-mod sandbox)`);
  }

  for (const modMain of ["mods/hyphae-pane/main.js", "mods/hyphae-panel/main.js"]) {
    const src = fs.readFileSync(path.join(MOD_ROOT, modMain), "utf8");
    assert.ok(src.includes("if (checking()) return;"), `${modMain} must guard init() with if (checking()) return;`);
    assert.ok(src.includes("async close("), `${modMain} must implement async close(cx)`);
    assert.ok(src.includes("this.client.dispose()"), `${modMain} must dispose watchFolder handle in close()`);
  }

  // U2 & U9 static guard: hyphae-panel must qualify leave channels & avoid truncated display values in actions
  const panelSrc = fs.readFileSync(path.join(MOD_ROOT, "mods/hyphae-panel/main.js"), "utf8");
  assert.ok(panelSrc.includes("qualifyChannelTarget("), "hyphae-panel must qualify channel targets before leave");
  assert.ok(panelSrc.includes("rawPattern || pattern"), "hyphae-panel must pass untruncated rawPattern to unmute");
  assert.ok(panelSrc.includes("rawSource || source"), "hyphae-panel must pass untruncated rawSource to mute");
  assert.ok(panelSrc.includes("rawRuleTarget || ruleTarget"), "hyphae-panel must pass untruncated rawRuleTarget to rule");

  // Validate JSON metadata files
  const keys = JSON.parse(fs.readFileSync(path.join(MOD_ROOT, "keys.json"), "utf8"));
  assert.equal(keys.global["cmd-shift-h"], "mod.open:hyphae-panel");
  const paneMod = JSON.parse(fs.readFileSync(path.join(MOD_ROOT, "mods/hyphae-pane/mod.json"), "utf8"));
  assert.equal(paneMod.place, "none");
  const panelMod = JSON.parse(fs.readFileSync(path.join(MOD_ROOT, "mods/hyphae-panel/mod.json"), "utf8"));
  assert.equal(panelMod.focusable, true);
  assert.equal(panelMod.overlay.kind, "window");

  assert.equal(findLayoutNode({ id: "root", children: [{ id: "hyphae" }] }, "hyphae")?.id, "hyphae");
});

test("KV snapshots and cursor navigation keep values behind an explicit preview", async () => {
  const { KvBrowser, buildKvCommandArgs, parseKvInspection } = await import("../mods/hyphae-panel/kv-view.js");
  const key = "-draft/alpha\u202e";
  const entry = { key, version: 2, updatedBy: "alice", updatedAt: 2, expiresAt: null, sizeBytes: 24, value: "NOT_METADATA" };
  const raw = { namespaces: [{ name: "shared", originNode: "laptop", entryCount: 1, entries: [entry] }] };
  const snapshot = parseSnapshotJson(JSON.stringify({ kv: raw }));
  assert.equal(snapshot.kv.namespaces[0].entries[0].key, key);
  assert.ok(!JSON.stringify(snapshot).includes("NOT_METADATA"));
  assert.match(formatPillMetrics({ enrolled: true, unreadBreakdown: { kv: 2 } }).wideLabel, /2 KV/);
  assert.equal(buildKvCommandArgs("preview", { originNode: "laptop", namespace: "shared", key: "bad\nkey" }), null);
  const previewArgs = (key) => buildKvCommandArgs("preview", { originNode: "laptop", namespace: "shared", key });
  assert.equal(previewArgs("nested/./key"), null);
  assert.equal(previewArgs("é".repeat(129)), null);
  assert.equal(previewArgs("folder\\key").at(-1), "--key=folder\\key");
  assert.equal(previewArgs("é".repeat(128)).at(-1), "--key=" + "é".repeat(128));

  const browser = new KvBrowser();
  const calls = [];
  const run = async (args) => {
    calls.push(args);
    if (args[1] === "keys") return { entries: [entry], nextAfter: key };
    return { text: "\u001b[31mvisible\u202e\n" + "x".repeat(5000), version: 2 };
  };
  await browser.open(parseKvInspection(raw).namespaces[0], run);
  assert.equal(browser.preview, null);
  assert.deepEqual(calls[0], ["kv", "keys", "--node=laptop", "--ns=shared", "--json"]);
  await browser.turnPage(true, run);
  assert.equal(calls[1].at(-1), "--after=" + key);
  await browser.show(key, run, sanitizeUiText);
  assert.deepEqual(calls[2], ["kv", "preview", "--node=laptop", "--ns=shared", "--json", "--key=" + key]);
  assert.ok(browser.preview.text.startsWith("visible\n"));
  assert.ok(browser.preview.text.length <= 4096);
  assert.equal(browser.preview.truncated, true);
  assert.ok(!browser.preview.text.includes("\u001b"));
  assert.ok(!browser.preview.text.includes("\u202e"));
  let finishPreview;
  const pending = browser.show(key, () => new Promise((resolve) => { finishPreview = resolve; }), sanitizeUiText);
  browser.reset();
  finishPreview({ text: "late preview" });
  await pending;
  assert.equal(browser.preview, null);
});

test("snapshot clients agree on metadata, envelope failures, and path precedence", async () => {
  const claude = await import("../../claude-code/hooks/state.ts");
  const opencode = await import("../../opencode/tui.mjs");
  const record = {
    rev: 5,
    daemon: { nodeId: "laptop", online: true, body: "private daemon text" },
    sessions: [
      {
        sessionId: "claude:test",
        enrolled: true,
        handle: "alice",
        details: {
          queuedItems: [{ kind: "event", source: "topic", data: "private event data" }],
        },
      },
    ],
  };
  const projection = (snapshot) => ({
    rev: snapshot.rev,
    nodeId: snapshot.daemon.nodeId,
    sessions: snapshot.sessions.map(({ sessionId, handle }) => [sessionId, handle]),
  });
  const expected = { rev: 5, nodeId: "laptop", sessions: [["claude:test", "alice"]] };
  for (const parse of [parseSnapshotJson, claude.parseSnapshotJson, opencode.parseSnapshotJson]) {
    for (const shape of [record, { ok: true, data: record }, { ok: true, result: record }]) {
      const snapshot = parse(JSON.stringify(shape));
      assert.deepEqual(projection(snapshot), expected);
      assert.doesNotMatch(JSON.stringify(snapshot), /private (?:daemon|event)/);
    }
    assert.equal(parse('{"ok":false}'), null);
    assert.equal(parse("[]"), null);
  }
  const config = '{"stateDir":"./custom"}';
  const home = "/Users/alice";
  const paths = resolveUiStateCandidates(home, config);
  assert.deepEqual(claude.resolveUiStateCandidates(home, null, config), paths);
  assert.deepEqual(opencode.resolveUiStateCandidates(home, null, config), paths);
});
