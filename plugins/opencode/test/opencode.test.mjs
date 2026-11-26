import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFile } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

import tuiPlugin, {
  sanitizeUiText,
  stripMetadataOnly,
  resolveUiStateCandidates,
  parseSnapshotJson,
  resolveActiveOpencodeSession,
  getQuarantinedCount,
  formatStatusLine,
  formatSidebarLines,
  createHyphaeTuiController,
} from "../tui.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PLUGIN_DIR = path.resolve(__dirname, "..");

function sampleSnapshot(overrides = {}) {
  return {
    schemaVersion: 1,
    rev: 7,
    updatedAt: 1_795_588_123_456,
    daemon: {
      online: true,
      pid: 4242,
      nodeId: "alice@macbook",
      version: "0.6.1",
      profile: "local",
      peersOnline: 2,
      quarantinedGlobal: 0,
    },
    sessions: [
      {
        sessionId: "opencode:ses-123",
        harness: "opencode",
        enrolled: true,
        handle: "coder",
        address: "alice@macbook/coder",
        lastSeen: 1_795_588_120_000,
        transportKind: "waiter",
        hasLiveTransport: true,
        deliveryMode: "notify",
        focusMode: true,
        focusAllowInterruptVips: true,
        mutedAll: false,
        bridges: ["telegram:ops"],
        counts: {
          subscriptions: 3,
          bridges: 1,
          queued: 2,
          unnotified: 1,
          quarantined: 0,
          mutedRules: 1,
          mutedArchived: 0,
          channels: 2,
          wakeups: 1,
        },
        unreadBreakdown: {
          messages: 1,
          events: 1,
          plugins: 0,
          transfers: 0,
          kv: 0,
          sources: ["bob@laptop/reviewer", "github.pr"],
        },
        details: {
          bridges: [
            {
              plugin: "telegram",
              target: "ops",
              label: "telegram:ops",
              role: "primary",
            },
          ],
          subscriptions: [
            {
              id: "sub_1",
              key: "prs",
              originNode: "local",
              topic: "github.pr",
              mode: "queue",
              coalesceSeconds: 15,
              filterSummary: "type=pr.opened",
            },
          ],
          queuedItems: [
            {
              receipt: "rcpt_1",
              kind: "message",
              source: "bob@laptop/reviewer",
              originNode: "bob@laptop",
              receivedAt: 1_795_588_100_000,
              notified: false,
              urgency: "notify",
            },
          ],
          mutes: [
            {
              pattern: "#noisy-ci",
              scope: "session",
              mutedAt: 1_795_587_000_000,
            },
          ],
          rules: [{ target: "bob@laptop/reviewer", delivery: "interrupt" }],
          channels: ["#ops", "#release"],
          channelEntries: [
            { hostNode: "local", channel: "#ops", mode: "open" },
          ],
          wakeups: [
            {
              id: "wk_1",
              label: "check-ci",
              triggerKind: "timer",
              nextFireAt: 1_795_589_000_000,
              urgency: "queue",
              state: "active",
            },
          ],
        },
      },
    ],
    ...overrides,
  };
}

// ============================================================================
// 1. Security Sanitization & Metadata-Only Stripping (McKeeman Levels 1–3)
// ============================================================================

test("sanitizeUiText strips OSC, CSI, DCS, C0/C1, zero-width, and BiDi characters", () => {
  const hostile =
    "\u001b]0;pwned\u0007\u001b]8;;https://evil.example\u001b\\link\u001b[31;1m" +
    "ali\u202ece\u2066\u2069\u200b\ufeff\u061c\u001bPbad\u001b\\\x00\x07\r\n\x7f\u009bOK";
  assert.equal(sanitizeUiText(hostile), "linkaliceOK");
  assert.equal(sanitizeUiText(null), "");
  assert.equal(sanitizeUiText(undefined), "");
  assert.equal(sanitizeUiText("abcdefghij", 5), "abcd…");
});

test("stripMetadataOnly recursively removes all forbidden body/secret/quarantine fields", () => {
  const contaminated = {
    schemaVersion: 1,
    body: "SECRET_BODY",
    text: "SECRET_TEXT",
    note: "SECRET_NOTE",
    payload: { nested: "SECRET_PAYLOAD" },
    data: { event: "SECRET_DATA" },
    content: "SECRET_CONTENT",
    message: "SECRET_MESSAGE",
    raw: "SECRET_RAW",
    ciphertext: "SECRET_CIPHER",
    plaintext: "SECRET_PLAIN",
    secret: "hp2p1_never_leak",
    token: "am2_never_leak",
    quarantinedText: "BAD_TEXT",
    quarantinedItems: [{ source: "evil" }],
    sessions: [
      {
        sessionId: "opencode:s1",
        handle: "safe",
        body: "NESTED_BODY",
        details: {
          queuedItems: [
            {
              receipt: "r1",
              source: "peer/a",
              text: "LEAKED_DM",
              payload: "LEAKED_EVENT",
            },
          ],
        },
      },
    ],
  };

  const cleaned = stripMetadataOnly(contaminated);
  const serialized = JSON.stringify(cleaned);
  for (const forbidden of [
    "SECRET_BODY",
    "SECRET_TEXT",
    "SECRET_NOTE",
    "SECRET_PAYLOAD",
    "SECRET_DATA",
    "SECRET_CONTENT",
    "SECRET_MESSAGE",
    "SECRET_RAW",
    "SECRET_CIPHER",
    "SECRET_PLAIN",
    "hp2p1_never_leak",
    "am2_never_leak",
    "BAD_TEXT",
    "NESTED_BODY",
    "LEAKED_DM",
    "LEAKED_EVENT",
  ]) {
    assert.ok(!serialized.includes(forbidden), `leaked forbidden string: ${forbidden}`);
  }
  assert.equal(cleaned.sessions[0].handle, "safe");
  assert.equal(cleaned.sessions[0].details.queuedItems[0].receipt, "r1");
});

test("parseSnapshotJson sanitizes untrusted metadata, handles envelopes, and fails safe on corrupt input", () => {
  const dirty = sampleSnapshot();
  dirty.sessions[0].handle = "\u001b[31malice\u202e\u0007";
  dirty.sessions[0].details.queuedItems[0].text = "MUST_BE_STRIPPED";
  dirty.sessions[0].details.queuedItems[0].source = "\u001b]0;evil\u0007bob/ops";
  dirty.sessions[0].details.channels = ["#ops\u200b\u001b[1m"];

  const snap = parseSnapshotJson(JSON.stringify(dirty));
  assert.ok(snap);
  assert.equal(snap.sessions[0].handle, "alice");
  assert.equal(snap.sessions[0].details.queuedItems[0].source, "bob/ops");
  assert.equal(snap.sessions[0].details.channels[0], "#ops");
  assert.ok(!JSON.stringify(snap).includes("MUST_BE_STRIPPED"));

  // CLI `--json` envelope `{ ok: true, data: ... }`
  const enveloped = parseSnapshotJson(
    JSON.stringify({ ok: true, command: "inspect", data: dirty }),
  );
  assert.ok(enveloped);
  assert.equal(enveloped.sessions[0].sessionId, "opencode:ses-123");
  assert.ok(!JSON.stringify(enveloped).includes("MUST_BE_STRIPPED"));

  // Error envelope and malformed JSON fail safe to null.
  assert.equal(parseSnapshotJson(JSON.stringify({ ok: false, error: "offline" })), null);
  assert.equal(parseSnapshotJson(""), null);
  assert.equal(parseSnapshotJson("{truncated"), null);
  assert.equal(parseSnapshotJson("null"), null);
  assert.equal(parseSnapshotJson("[]"), null);
});

// ============================================================================
// 2. State Candidate Precedence, Session Resolution & Formatting
// ============================================================================

test("resolveUiStateCandidates honors env > node.json stateDir > defaults without duplicates", () => {
  const { dirs, files } = resolveUiStateCandidates(
    "/Users/alice/",
    "~/custom-env-state",
    JSON.stringify({ stateDir: "./rel-state" }),
  );
  assert.deepEqual(dirs, [
    "/Users/alice/custom-env-state/ui",
    "/Users/alice/.config/hyphae/rel-state/ui",
    "/Users/alice/.config/hyphae/ui",
    "/Users/alice/.config/hyphae/state/ui",
  ]);
  assert.equal(files[0], "/Users/alice/custom-env-state/ui/state.json");

  // Malformed node.json degrades cleanly.
  const fallback = resolveUiStateCandidates("/Users/alice", null, "{bad-json");
  assert.deepEqual(fallback.dirs, [
    "/Users/alice/.config/hyphae/ui",
    "/Users/alice/.config/hyphae/state/ui",
  ]);
});

test("resolveActiveOpencodeSession matches direct, root ancestor, env, and none cleanly", () => {
  const snap = parseSnapshotJson(JSON.stringify(sampleSnapshot()));
  assert.ok(snap);

  const direct = resolveActiveOpencodeSession(snap, "ses-123");
  assert.equal(direct.matchedBy, "opencode");
  assert.equal(direct.active?.handle, "coder");

  const subtask = resolveActiveOpencodeSession(snap, "child-999", "ses-123");
  assert.equal(subtask.matchedBy, "opencode-root");
  assert.equal(subtask.active?.sessionId, "opencode:ses-123");

  const envMatch = resolveActiveOpencodeSession(
    snap,
    "unknown-ses",
    null,
    "opencode:ses-123",
  );
  assert.equal(envMatch.matchedBy, "env");
  assert.equal(envMatch.active?.sessionId, "opencode:ses-123");

  const none = resolveActiveOpencodeSession(snap, "other-ses");
  assert.equal(none.matchedBy, "none");
  assert.equal(none.active, null);
});

test("formatStatusLine and formatSidebarLines enforce zero-clutter and quarantine human-CLI boundary", () => {
  const snap = parseSnapshotJson(JSON.stringify(sampleSnapshot()));
  const active = snap.sessions[0];

  const status = formatStatusLine(snap, active, 0);
  assert.equal(
    status,
    "⟁ @coder · telegram:ops · 3 subs · 2 queued · FOCUS · 1 muted",
  );

  const sidebar = formatSidebarLines(snap, active, 0);
  assert.ok(sidebar.some((l) => l.includes("alice@macbook/coder · FOCUS")));
  assert.ok(sidebar.some((l) => l.includes("3 subs · 2 queued")));
  assert.ok(sidebar.some((l) => l.includes("bob@laptop/reviewer")));
  assert.ok(sidebar.some((l) => l.includes("#ops #release")));

  // Unenrolled with zero activity & zero quarantine -> undefined (zero clutter)
  assert.equal(formatStatusLine(snap, null, 0), undefined);

  // Quarantine takes priority even when session is unenrolled; never leaks payload.
  const qSnap = parseSnapshotJson(
    JSON.stringify(
      sampleSnapshot({
        daemon: {
          online: true,
          pid: 1,
          nodeId: "alice@macbook",
          version: "0.6.1",
          profile: "local",
          peersOnline: 0,
          quarantinedGlobal: 2,
        },
      }),
    ),
  );
  const qCount = getQuarantinedCount(qSnap, null);
  assert.equal(qCount, 2);
  assert.equal(
    formatStatusLine(qSnap, null, qCount),
    "⚠ hyphae: 2 held · run `hyp gate review`",
  );
  const qSidebar = formatSidebarLines(qSnap, null, qCount);
  assert.ok(qSidebar[0].includes("hyp gate review"));
});

// ============================================================================
// 3. Zero-Polling Watcher & OpenCode v2 / v1 TUI Loader Compatibility
// ============================================================================

test("plugins/opencode/tui.mjs is strictly zero-polling (zero setInterval)", () => {
  const src = fs.readFileSync(path.join(PLUGIN_DIR, "tui.mjs"), "utf8");
  assert.ok(
    !/\bsetInterval\s*\(/.test(src),
    "tui.mjs must never use setInterval (zero-polling invariant)",
  );
  assert.equal(tuiPlugin.id, "hyphae.opencode.tui");
  assert.equal(typeof tuiPlugin.setup, "function");
  assert.equal(typeof tuiPlugin.tui, "function");
});

test("createHyphaeTuiController reacts to atomic ui/state.json writes via fs.watch and disposes cleanly", async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "hyp-opencode-tui-"));
  const uiDir = path.join(tmp, ".config", "hyphae", "ui");
  fs.mkdirSync(uiDir, { recursive: true });
  const statePath = path.join(uiDir, "state.json");

  // fs.watch can return before macOS starts delivering directory events.
  // Confirm readiness with an unrelated file before testing a single atomic rename.
  const probeName = ".watch-ready";
  let watcherReady = false;
  const updates = [];
  const controller = createHyphaeTuiController({
    watch: (dir, options, listener) =>
      fs.watch(dir, options, (event, name) => {
        if (name === probeName) watcherReady = true;
        listener(event, name);
      }),
    homeDir: tmp,
    env: {},
    getSessionInfo: () => ({ sessionID: "ses-123", rootSessionID: "ses-123" }),
    onUpdate: (st) => updates.push(st),
  });

  try {
    assert.equal(controller.getState().snapshot, null);
    assert.equal(controller.getState().statusLine, undefined);

    const readyDeadline = Date.now() + 10_000;
    while (!watcherReady && Date.now() < readyDeadline) {
      fs.appendFileSync(path.join(uiDir, probeName), ".");
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    assert.ok(watcherReady, "fs.watch must receive events in the UI directory");

    // Atomic temp + rename mimicking LocalDaemon's debounced UI projector.
    const tmpFile = path.join(uiDir, "state.json.tmp");
    fs.writeFileSync(tmpFile, JSON.stringify(sampleSnapshot()), "utf8");
    fs.renameSync(tmpFile, statePath);

    // Wait reactively (bounded timeout) for fs.watch debounce delivery.
    const deadline = Date.now() + 10_000;
    while (Date.now() < deadline && !controller.getState().active) {
      await new Promise((r) => setTimeout(r, 25));
    }

    assert.ok(controller.getState().active, "watcher must pick up atomic state.json update");
    assert.equal(controller.getState().active.handle, "coder");
    assert.ok(controller.getState().statusLine?.includes("@coder"));
    assert.ok(updates.length >= 2);
  } finally {
    controller.dispose();
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("default export supports both OpenCode v2 setup(api) and v1 tui(api) slots and clean teardown", async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "hyp-opencode-v1v2-"));
  const uiDir = path.join(tmp, "ui");
  fs.mkdirSync(uiDir, { recursive: true });
  fs.writeFileSync(path.join(uiDir, "state.json"), JSON.stringify(sampleSnapshot()), "utf8");

  const prevStateDir = process.env.HYPHAE_STATE_DIR;
  process.env.HYPHAE_STATE_DIR = tmp;

  try {
    // OpenCode v2 mock API
    let registeredSlot = null;
    let slotDisposed = false;
    let listener = null;
    let listenerDisposed = false;
    let routeSessionID = "ses-123";

    const v2Api = {
      ui: {
        router: {
          current: () => ({ type: "session", sessionID: routeSessionID }),
        },
        slot: (name, def) => {
          registeredSlot = { name, def };
          return () => {
            slotDisposed = true;
          };
        },
      },
      data: {
        session: {
          get: (id) =>
            id === "subtask-1"
              ? { id, parentID: "ses-123" }
              : { id, parentID: null },
        },
        listen: (cb) => {
          listener = cb;
          return () => {
            listenerDisposed = true;
          };
        },
      },
    };

    const disposeV2 = tuiPlugin.setup(v2Api);
    assert.equal(registeredSlot?.name, "sidebar.content");
    assert.equal(registeredSlot?.def?.id, "hyphae-status");
    const rendered1 = registeredSlot.def.render();
    assert.ok(rendered1.statusLine.includes("@coder"));

    // Route switches to child subtask -> resolves parent `ses-123` via api.data.session.get!
    routeSessionID = "subtask-1";
    listener();
    const renderedSub = registeredSlot.def.render();
    assert.ok(renderedSub.statusLine.includes("@coder"));

    // Route switches to unrelated session -> zero-clutter undefined statusLine
    routeSessionID = "unrelated-ses";
    listener();
    assert.equal(registeredSlot.def.render().statusLine, undefined);

    disposeV2();
    assert.equal(slotDisposed, true);
    assert.equal(listenerDisposed, true);

    // OpenCode v1 mock API
    let v1Slot = null;
    let v1OnDispose = null;
    const v1Api = {
      route: { current: { name: "session", params: { sessionID: "ses-123" } } },
      state: { session: { get: (id) => ({ id, parentID: null }) } },
      slots: {
        register: (entry) => {
          v1Slot = entry;
        },
      },
      lifecycle: {
        onDispose: (fn) => {
          v1OnDispose = fn;
        },
      },
    };

    await tuiPlugin.tui(v1Api);
    assert.equal(v1Slot?.slot, "sidebar_content");
    assert.ok(v1Slot.render().statusLine.includes("@coder"));
    assert.equal(typeof v1OnDispose, "function");
    v1OnDispose();
  } finally {
    if (prevStateDir === undefined) delete process.env.HYPHAE_STATE_DIR;
    else process.env.HYPHAE_STATE_DIR = prevStateDir;
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

// ============================================================================
// 4. Real OpenCode Lifecycle Hook Plugin (`plugins/opencode/hyphae.ts`) Tests
// ============================================================================

test("plugins/opencode/hyphae.ts wires pre-tool-use, post-tool-use, and session.idle safely", async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "hyp-opencode-hooks-"));
  const logFile = path.join(tmp, "calls.ndjson");
  const modeFile = path.join(tmp, "mode.json");
  const fakeHyp = path.join(tmp, "fake-hyp.mjs");

  // Fake `hyp` executable recording exact argv + stdin JSON and returning programmable responses.
  fs.writeFileSync(
    fakeHyp,
    `#!${process.execPath}
import fs from "node:fs";
const chunks = [];
for await (const chunk of process.stdin) chunks.push(chunk);
const stdinText = Buffer.concat(chunks).toString("utf8");
const payload = stdinText.trim() ? JSON.parse(stdinText) : {};
const argv = process.argv.slice(2);
fs.appendFileSync(${JSON.stringify(logFile)}, JSON.stringify({ argv, payload }) + "\\n");
const mode = JSON.parse(fs.readFileSync(${JSON.stringify(modeFile)}, "utf8"));
const event = argv[2];
const reply = mode[event];
if (reply === "__FAIL__") {
  process.exit(1);
}
if (reply === "__CORRUPT__") {
  process.stdout.write("{not-valid-json");
  process.exit(0);
}
process.stdout.write(JSON.stringify(reply ?? {}) + "\\n");
`,
    { mode: 0o755 },
  );

  const setMode = (obj) => fs.writeFileSync(modeFile, JSON.stringify(obj), "utf8");
  const readCalls = () =>
    fs.existsSync(logFile)
      ? fs
          .readFileSync(logFile, "utf8")
          .trim()
          .split("\n")
          .filter(Boolean)
          .map((l) => JSON.parse(l))
      : [];

  const prevBin = process.env.HYPHAE_BIN;
  const prevSock = process.env.HYPHAE_SOCKET;
  process.env.HYPHAE_BIN = fakeHyp;
  process.env.HYPHAE_SOCKET = "/tmp/test-opencode.sock";

  try {
    // Import fresh copy with cache-busting query so env overrides take effect.
    const modUrl = `${pathToFileURL(path.join(PLUGIN_DIR, "hyphae.ts")).href}?t=${Date.now()}`;
    const mod = await import(modUrl);

    // Ensure ONLY `HyphaePlugin` function and OpenCode v2 `default` definition `{ id, setup }`
    // are exported (no helper functions that v1 OpenCode might invoke!).
    const exportedFns = Object.entries(mod).filter(([, v]) => typeof v === "function");
    assert.equal(exportedFns.length, 1);
    assert.equal(exportedFns[0][0], "HyphaePlugin");
    assert.equal(typeof mod.default, "object");
    assert.equal(mod.default.id, "hyphae");
    assert.equal(typeof mod.default.setup, "function");

    // ------------------------------------------------------------------------
    // Part A: OpenCode v1 `HyphaePlugin` factory compatibility
    // ------------------------------------------------------------------------
    const promptCalls = [];
    const sessionObj = {
      tag: "bound-session",
      prompt(req) {
        // Verify `this` binding is preserved!
        assert.equal(this.tag, "bound-session");
        promptCalls.push(req);
        return Promise.resolve({ ok: true });
      },
    };
    const hooks = await mod.HyphaePlugin({
      directory: "/workspace/demo",
      client: { session: sessionObj },
    });

    // 4a. Non-Hyphae tools must NOT invoke pre-tool-use.
    setMode({ "pre-tool-use": { callToken: "tok_should_not_be_used" } });
    const bashOut = { args: { command: "ls" } };
    await hooks["tool.execute.before"](
      { sessionID: "ses-1", tool: "bash", callID: "c-bash" },
      bashOut,
    );
    assert.equal(bashOut.args._meshCall, undefined);
    assert.equal(readCalls().length, 0);

    // 4b. Hyphae MCP tool strips any untrusted `_meshCall`, invokes `hyp hook opencode pre-tool-use --socket ...`, and injects verified `_meshCall`.
    setMode({
      "pre-tool-use": {
        callToken: "tok_verified_1",
        sessionId: "opencode:ses-1",
        updatedInput: {
          extraFlag: true,
          __proto__: { polluted: true },
        },
      },
    });
    const meshOut = {
      args: { action: "join", handle: "opencode-worker", _meshCall: "ct_spoofed" },
    };
    await hooks["tool.execute.before"](
      { sessionID: "ses-1", tool: "hyphae_hyp_mesh", callID: "c-1" },
      meshOut,
    );
    assert.equal(meshOut.args._meshCall, "tok_verified_1");
    assert.equal(meshOut.args.extraFlag, true);
    assert.equal(({}).polluted, undefined);

    const call1 = readCalls().at(-1);
    assert.deepEqual(call1.argv, [
      "hook",
      "opencode",
      "pre-tool-use",
      "--socket",
      "/tmp/test-opencode.sock",
    ]);
    assert.equal(call1.payload.session_id, "ses-1");
    assert.equal(call1.payload.sessionID, "ses-1");
    assert.equal(call1.payload.tool_name, "hyphae_hyp_mesh");
    assert.equal(call1.payload.call_id, "c-1");
    assert.equal(call1.payload.cwd, "/workspace/demo");
    assert.deepEqual(call1.payload.tool_input, {
      action: "join",
      handle: "opencode-worker",
    });

    // 4c. Also matches bare `hyp_kv`, `hyp_bridge`, and `mcp__hyphae__hyp_send`.
    for (const toolName of ["hyp_kv", "hyp_bridge", "mcp__hyphae__hyp_send"]) {
      const out = { args: {} };
      setMode({ "pre-tool-use": { _meshCall: `tok_${toolName}` } });
      await hooks["tool.execute.before"](
        { sessionID: "ses-1", tool: toolName, callID: `c-${toolName}` },
        out,
      );
      assert.equal(out.args._meshCall, `tok_${toolName}`);
    }

    // 4d. `tool.execute.after` appends `additionalContext` to string, empty, and content-array
    //     outputs WITHOUT breaking non-string outputs!
    setMode({
      "post-tool-use": {
        additionalContext: "Incoming hyphae message(s):\n\nhello from alice",
      },
    });

    const strOut = { output: "command ok" };
    await hooks["tool.execute.after"](
      { sessionID: "ses-1", tool: "bash", callID: "c-after-1" },
      strOut,
    );
    assert.equal(
      strOut.output,
      "command ok\n\nIncoming hyphae message(s):\n\nhello from alice",
    );

    const arrOut = { output: [{ type: "text", text: "part1" }] };
    await hooks["tool.execute.after"](
      { sessionID: "ses-1", tool: "bash", callID: "c-after-2" },
      arrOut,
    );
    assert.equal(arrOut.output.length, 2);
    assert.deepEqual(arrOut.output[1], {
      type: "text",
      text: "Incoming hyphae message(s):\n\nhello from alice",
    });

    const objOut = { output: { exitCode: 0, count: 42 }, metadata: {} };
    await hooks["tool.execute.after"](
      { sessionID: "ses-1", tool: "custom", callID: "c-after-3" },
      objOut,
    );
    assert.deepEqual(objOut.output, { exitCode: 0, count: 42 });
    assert.equal(
      objOut.metadata.hyphaeAdditionalContext,
      "Incoming hyphae message(s):\n\nhello from alice",
    );

    const numOut = { output: 1234 };
    await hooks["tool.execute.after"](
      { sessionID: "ses-1", tool: "custom", callID: "c-after-4" },
      numOut,
    );
    assert.equal(numOut.output, 1234);

    // 4e. `event` (`session.idle`) calls `stop`, delivers `followupMessage`, and prevents reminder loops.
    setMode({
      stop: {
        followupMessage:
          "hyphae: Enrolled, but no background waiter is running yet. Run `hyp wait --session opencode:ses-1` in background, then end turn.",
      },
    });
    // Non-idle events ignored.
    await hooks.event({ event: { type: "session.created", properties: { sessionID: "ses-1" } } });
    assert.equal(promptCalls.length, 0);

    // First idle delivers reminder (`continuationActive: false`).
    await hooks.event({ event: { type: "session.idle", properties: { sessionID: "ses-1" } } });
    assert.equal(promptCalls.length, 1);
    assert.equal(promptCalls[0].path.id, "ses-1");
    assert.ok(promptCalls[0].body.parts[0].text.includes("hyp wait --session opencode:ses-1"));
    assert.equal(readCalls().at(-1).payload.continuationActive, false);

    // Consecutive idle passes `continuationActive: true` so `hyp hook` won't loop infinitely.
    setMode({ stop: {} });
    await hooks.event({ event: { type: "session.idle", properties: { sessionID: "ses-1" } } });
    assert.equal(readCalls().at(-1).payload.continuationActive, true);
    assert.equal(promptCalls.length, 1);

    // 4f. Fail-safe on hook failure, corrupt JSON, forged `_meshCall`, or missing client.session.prompt.
    setMode({ "pre-tool-use": "__FAIL__", "post-tool-use": "__CORRUPT__", stop: "__FAIL__" });
    const failOut = { args: { action: "status", _meshCall: "ct_forged_must_be_stripped" } };
    await hooks["tool.execute.before"](
      { sessionID: "ses-1", tool: "hyp_mesh", callID: "c-fail" },
      failOut,
    );
    assert.equal(failOut.args._meshCall, undefined);
    await hooks["tool.execute.after"](
      { sessionID: "ses-1", tool: "bash", callID: "c-corrupt" },
      { output: "ok" },
    );
    const noClientHooks = await mod.HyphaePlugin({});
    setMode({ stop: { followupMessage: "ignored without client" } });
    await noClientHooks.event({
      event: { type: "session.idle", properties: { sessionID: "ses-2" } },
    });

    // ------------------------------------------------------------------------
    // Part B: OpenCode v2 (`default.setup(api)`) with Code Mode & Async Event Stream
    // ------------------------------------------------------------------------
    const v2ToolHooks = new Map();
    const v2SessionHooks = new Map();
    const v2Prompts = [];
    let v2DisposedCount = 0;
    let v2SubscribedTypes = null;
    let v2EventResolve = null;
    const v2EventQueue = [];
    let v2EventClosed = false;

    const pushV2Event = (ev) => {
      if (v2EventResolve) {
        const r = v2EventResolve;
        v2EventResolve = null;
        r({ value: ev, done: false });
      } else {
        v2EventQueue.push(ev);
      }
    };

    const v2Api = {
      location: { directory: "/workspace/v2-demo" },
      tool: {
        async transform(cb) {
          cb({
            list: () => [
              { id: "hyphae_hyp_mesh", name: "hyp_mesh", options: { codemode: true, namespace: "hyphae" } },
              { id: "hyphae_hyp_inbox", name: "hyp_inbox", options: { codemode: true, namespace: "hyphae" } },
              { id: "opencode_models", name: "models", options: { codemode: true, namespace: "opencode" } },
              { id: "shell", name: "shell", options: {} },
            ],
          });
          return { dispose: () => { v2DisposedCount++; } };
        },
        async hook(name, fn) {
          v2ToolHooks.set(name, fn);
          return () => { v2DisposedCount++; };
        },
      },
      session: {
        tag: "v2-session-api",
        async hook(name, fn) {
          v2SessionHooks.set(name, fn);
          return { dispose: () => { v2DisposedCount++; } };
        },
        async prompt(req) {
          assert.equal(this.tag, "v2-session-api");
          v2Prompts.push(req);
          // Mirror real OpenCode v2: `api.session.prompt` invokes `session.hook("prompt")` synchronously!
          const promptHook = v2SessionHooks.get("prompt");
          if (promptHook) {
            await promptHook({
              sessionID: req.sessionID,
              prompt: { text: req.text, files: [] },
              delivery: "steer",
            });
          }
          return { id: "msg_plugin_1" };
        },
      },
      event: {
        subscribe(opts) {
          v2SubscribedTypes = opts?.types ?? null;
          return {
            [Symbol.asyncIterator]() {
              return {
                next() {
                  if (v2EventClosed) return Promise.resolve({ value: undefined, done: true });
                  if (v2EventQueue.length > 0) {
                    return Promise.resolve({ value: v2EventQueue.shift(), done: false });
                  }
                  return new Promise((resolve) => {
                    v2EventResolve = resolve;
                  });
                },
                return() {
                  v2EventClosed = true;
                  if (v2EventResolve) {
                    const r = v2EventResolve;
                    v2EventResolve = null;
                    r({ value: undefined, done: true });
                  }
                  return Promise.resolve({ value: undefined, done: true });
                },
              };
            },
          };
        },
      },
    };

    const disposeV2Plugin = await mod.default.setup(v2Api);
    assert.equal(typeof disposeV2Plugin, "function");
    assert.ok(v2ToolHooks.has("execute.before"));
    assert.ok(v2ToolHooks.has("execute.after"));
    assert.ok(v2SessionHooks.has("prompt"));
    assert.ok(Array.isArray(v2SubscribedTypes) && v2SubscribedTypes.includes("session.execution.succeeded"));

    // 4g. v2 `session.hook("prompt")` drains `pre-invocation` into `ev.prompt.text`.
    setMode({
      "pre-invocation": {
        additionalContext: "Incoming hyphae message(s):\n\nqueued before turn",
      },
    });
    const promptEv = {
      sessionID: "ses-v2-1",
      prompt: { text: "Check status", files: [] },
    };
    await v2SessionHooks.get("prompt")(promptEv);
    assert.equal(
      promptEv.prompt.text,
      "Check status\n\nIncoming hyphae message(s):\n\nqueued before turn",
    );

    // 4h. v2 Code Mode `execute` + inner `hyphae_hyp_mesh` + parallel direct `shell`:
    //     - `execute.before` injects `_meshCall` on `hyphae_hyp_mesh` and strips forged `_meshCall`.
    //     - `execute.after` skips draining on inner Code Mode `hyphae_hyp_mesh` (scrubbing `_meshCall`),
    //       drains on parallel direct `shell`, AND drains on outer `execute` into `ev.result.content`!
    const callsBeforeV2Exec = readCalls().length;
    setMode({
      "pre-tool-use": { callToken: "tok_v2_codemode_1" },
      "post-tool-use": { additionalContext: "Incoming hyphae message(s):\n\ninterrupt ping" },
    });

    const execBeforeEv = {
      tool: "execute",
      sessionID: "ses-v2-1",
      id: "call_exec_1",
      input: { code: "return await tools.hyphae.hyp_mesh({ action: 'join', handle: 'v2' });" },
    };
    await v2ToolHooks.get("execute.before")(execBeforeEv);
    assert.equal(readCalls().length, callsBeforeV2Exec, "outer execute must not call pre-tool-use");

    const innerMeshEv = {
      tool: "hyphae_hyp_mesh",
      sessionID: "ses-v2-1",
      id: "call_inner_mesh_1",
      input: { action: "join", handle: "v2", _meshCall: "ct_forged_inner" },
    };
    await v2ToolHooks.get("execute.before")(innerMeshEv);
    assert.equal(innerMeshEv.input._meshCall, "tok_v2_codemode_1");
    assert.equal(readCalls().at(-1).payload.tool_input._meshCall, undefined);
    assert.equal(readCalls().at(-1).payload.cwd, "/workspace/v2-demo");

    // Inner Code Mode `execute.after` MUST NOT drain (Code Mode drops inner content!) and MUST scrub `_meshCall`.
    const callsBeforeInnerAfter = readCalls().length;
    const innerAfterEv = {
      tool: "hyphae_hyp_mesh",
      sessionID: "ses-v2-1",
      id: "call_inner_mesh_1",
      input: innerMeshEv.input,
      status: "completed",
      result: { output: { ok: true }, content: [{ type: "text", text: "{\"ok\":true}" }] },
    };
    await v2ToolHooks.get("execute.after")(innerAfterEv);
    assert.equal(innerAfterEv.input._meshCall, undefined, "consumed _meshCall should be scrubbed");
    assert.equal(readCalls().length, callsBeforeInnerAfter, "inner Code Mode tool must not drain mailbox");
    assert.equal(innerAfterEv.result.content.length, 1);

    // Parallel direct `shell` finishing while `execute` is still active MUST STILL drain!
    const shellAfterEv = {
      tool: "shell",
      sessionID: "ses-v2-1",
      id: "call_sh_1",
      status: "completed",
      result: { output: "ok", content: [{ type: "text", text: "ok" }] },
    };
    await v2ToolHooks.get("execute.after")(shellAfterEv);
    assert.equal(shellAfterEv.result.content.length, 2);
    assert.ok(shellAfterEv.result.content[1].text.includes("interrupt ping"));

    // Outer `execute` finishing drains into `ev.result.content`!
    const execAfterEv = {
      tool: "execute",
      sessionID: "ses-v2-1",
      id: "call_exec_1",
      status: "completed",
      result: { output: { output: "{\"ok\":true}" }, content: [{ type: "text", text: "{\"ok\":true}" }] },
    };
    await v2ToolHooks.get("execute.after")(execAfterEv);
    assert.equal(execAfterEv.result.content.length, 2);
    assert.ok(execAfterEv.result.content[1].text.includes("interrupt ping"));

    // Zero-arg `hyphae_hyp_inbox` when daemon fails MUST strip any forged `_meshCall` and fail closed!
    setMode({ "pre-tool-use": "__FAIL__" });
    const forgedZeroEv = {
      tool: "hyphae_hyp_inbox",
      sessionID: "ses-v2-1",
      id: "call_inbox_fail",
      input: { _meshCall: "ct_forged_v2" },
    };
    await v2ToolHooks.get("execute.before")(forgedZeroEv);
    assert.equal(forgedZeroEv.input._meshCall, undefined);

    // 4i. v2 `event.subscribe` (`session.execution.succeeded`) triggers `stop`, sends waiter reminder
    //     via `api.session.prompt({ sessionID, text })`, preserves `idleReminderSent` across the
    //     resulting `session.hook("prompt")`, and suppresses consecutive reminder loop!
    setMode({
      stop: {
        followupMessage:
          "hyphae: Enrolled, but no background waiter is running yet. Run `hyp wait --session opencode:ses-v2-1` in background, then end turn.",
      },
      "pre-invocation": {
        additionalContext: "SHOULD_NOT_BE_CALLED_FOR_PLUGIN_PROMPT",
      },
    });
    pushV2Event({
      type: "session.execution.succeeded",
      data: { sessionID: "ses-v2-1" },
    });
    const waitDeadline = Date.now() + 2_000;
    while (Date.now() < waitDeadline && v2Prompts.length < 1) {
      await new Promise((r) => setTimeout(r, 15));
    }
    assert.equal(v2Prompts.length, 1);
    assert.equal(v2Prompts[0].sessionID, "ses-v2-1");
    assert.ok(v2Prompts[0].text.includes("hyp wait --session opencode:ses-v2-1"));
    assert.equal(readCalls().at(-1).argv[2], "stop", "plugin prompt must not trigger pre-invocation");
    assert.equal(readCalls().at(-1).payload.continuationActive, false);

    // Second consecutive `session.execution.succeeded` must pass `continuationActive: true`!
    const callsBeforeIdle2 = readCalls().length;
    setMode({ stop: {} });
    pushV2Event({
      type: "session.execution.succeeded",
      data: { sessionID: "ses-v2-1" },
    });
    const waitDeadline2 = Date.now() + 2_000;
    while (Date.now() < waitDeadline2 && readCalls().length <= callsBeforeIdle2) {
      await new Promise((r) => setTimeout(r, 15));
    }
    assert.equal(readCalls().at(-1).argv[2], "stop");
    assert.equal(readCalls().at(-1).payload.continuationActive, true);
    assert.equal(v2Prompts.length, 1);

    // Dispose cleans up all hooks and event iterator.
    disposeV2Plugin();
    assert.equal(v2EventClosed, true);
    assert.equal(v2DisposedCount, 4);
  } finally {
    if (prevBin === undefined) delete process.env.HYPHAE_BIN;
    else process.env.HYPHAE_BIN = prevBin;
    if (prevSock === undefined) delete process.env.HYPHAE_SOCKET;
    else process.env.HYPHAE_SOCKET = prevSock;
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("plugins/opencode/hyphae.ts skips TurnEnd stop drain in one-shot `opencode run --standalone` (#43) while preserving persistent serve & TUI", async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "hyp-opencode-standalone-"));
  const logFile = path.join(tmp, "calls.ndjson");
  const fakeHyp = path.join(tmp, "fake-hyp.mjs");

  fs.writeFileSync(
    fakeHyp,
    `#!${process.execPath}
import fs from "node:fs";
const chunks = [];
for await (const chunk of process.stdin) chunks.push(chunk);
const payload = Buffer.concat(chunks).toString("utf8").trim();
const argv = process.argv.slice(2);
const event = argv[2];
fs.appendFileSync(${JSON.stringify(logFile)}, JSON.stringify({ event, payload: payload ? JSON.parse(payload) : {} }) + "\\n");
if (event === "stop") {
  process.stdout.write(JSON.stringify({ followupMessage: "Incoming hyphae message(s):\\n\\nheld queue dm" }) + "\\n");
} else if (event === "pre-invocation") {
  process.stdout.write(JSON.stringify({ additionalContext: "Incoming hyphae message(s):\\n\\nheld queue dm" }) + "\\n");
} else {
  process.stdout.write("{}\\n");
}
`,
    { mode: 0o755 },
  );

  const readCalls = () =>
    fs.existsSync(logFile)
      ? fs
          .readFileSync(logFile, "utf8")
          .trim()
          .split("\n")
          .filter(Boolean)
          .map((l) => JSON.parse(l))
      : [];
  const clearCalls = () => {
    if (fs.existsSync(logFile)) fs.unlinkSync(logFile);
  };

  const prevBin = process.env.HYPHAE_BIN;
  const prevSock = process.env.HYPHAE_SOCKET;
  const prevStandaloneEnv = process.env.HYPHAE_OPENCODE_STANDALONE;
  const origArgv = [...process.argv];
  process.env.HYPHAE_BIN = fakeHyp;
  process.env.HYPHAE_SOCKET = "/tmp/test-opencode-43.sock";
  delete process.env.HYPHAE_OPENCODE_STANDALONE;

  const pluginHref = `${pathToFileURL(path.join(PLUGIN_DIR, "hyphae.ts")).href}?standalone=${Date.now()}`;

  const runV2Scenario = async (argvOverride, envOverride = undefined) => {
    clearCalls();
    process.argv = [...argvOverride];
    if (envOverride === undefined) delete process.env.HYPHAE_OPENCODE_STANDALONE;
    else process.env.HYPHAE_OPENCODE_STANDALONE = envOverride;

    const mod = await import(pluginHref);
    const prompts = [];
    const sessionHooks = new Map();
    let streamDoneResolve;
    const streamDone = new Promise((r) => {
      streamDoneResolve = r;
    });
    const events = [
      { type: "session.execution.succeeded", data: { sessionID: "ses-43" } },
    ];
    const dispose = await mod.default.setup({
      location: { directory: "/workspace/demo-43" },
      session: {
        async hook(name, fn) {
          sessionHooks.set(name, fn);
        },
        async prompt(req) {
          prompts.push(req);
        },
      },
      event: {
        subscribe() {
          let idx = 0;
          return {
            [Symbol.asyncIterator]() {
              return {
                async next() {
                  if (idx < events.length) return { value: events[idx++], done: false };
                  streamDoneResolve();
                  return { value: undefined, done: true };
                },
              };
            },
          };
        },
      },
    });
    await streamDone;
    // Allow microtasks/handleEvent to finish before inspecting calls.
    await new Promise((r) => setTimeout(r, 80));
    const stopCalls = readCalls().filter((c) => c.event === "stop");

    // Verify `session.hook("prompt")` (`pre-invocation`) STILL drains queued DMs in EVERY mode!
    const nextPromptEv = {
      sessionID: "ses-43",
      prompt: { text: "Resume session", files: [] },
    };
    await sessionHooks.get("prompt")(nextPromptEv);
    dispose();
    return { stopCalls, prompts, nextPromptText: nextPromptEv.prompt.text };
  };

  try {
    // 1. Persistent `opencode serve --hostname 127.0.0.1 --port 4096`: TurnEnd `stop` drains & prompts!
    const serveRes = await runV2Scenario([
      "bun",
      "/$bunfs/root/opencode",
      "serve",
      "--hostname",
      "127.0.0.1",
      "--port",
      "4096",
    ]);
    assert.equal(serveRes.stopCalls.length, 1, "persistent serve must call stop on TurnEnd");
    assert.equal(serveRes.prompts.length, 1, "persistent serve must dispatch followup prompt");
    assert.ok(serveRes.prompts[0].text.includes("held queue dm"));

    // 2. `opencode run --server http://127.0.0.1:4096`: persistent server attached -> drains & prompts!
    const serverRunRes = await runV2Scenario([
      "/usr/local/bin/opencode",
      "run",
      "--server",
      "http://127.0.0.1:4096",
      "--auto",
      "hello",
    ]);
    assert.equal(serverRunRes.stopCalls.length, 1);
    assert.equal(serverRunRes.prompts.length, 1);

    // 3. Interactive TUI `opencode --standalone` (no `run` subcommand): stays alive -> drains & prompts!
    const tuiStandaloneRes = await runV2Scenario([
      "/usr/local/bin/opencode",
      "--standalone",
      "/workspace/demo-43",
    ]);
    assert.equal(tuiStandaloneRes.stopCalls.length, 1);
    assert.equal(tuiStandaloneRes.prompts.length, 1);

    // 4. Direct one-shot `opencode run --standalone`: MUST skip TurnEnd `stop` & `api.session.prompt`,
    //    while `session.hook("prompt")` (`pre-invocation`) still drains cleanly on next turn!
    const directStandaloneRes = await runV2Scenario([
      "/usr/local/bin/opencode",
      "run",
      "--standalone",
      "--auto",
      "--format",
      "json",
      "do work",
    ]);
    assert.equal(
      directStandaloneRes.stopCalls.length,
      0,
      "one-shot `opencode run --standalone` must NOT drain via stop on TurnEnd",
    );
    assert.equal(directStandaloneRes.prompts.length, 0);
    assert.ok(
      directStandaloneRes.nextPromptText.includes("held queue dm"),
      "subsequent turn prompt hook must still drain held queue DM",
    );

    // 5. Global flag before subcommand (`opencode --standalone run "hi"`) also skips TurnEnd drain!
    const preFlagStandaloneRes = await runV2Scenario([
      "/usr/local/bin/opencode",
      "--standalone",
      "run",
      "do work",
    ]);
    assert.equal(preFlagStandaloneRes.stopCalls.length, 0);
    assert.equal(preFlagStandaloneRes.prompts.length, 0);

    // 6. Prompt text mentioning `--standalone` in non-standalone `opencode run` must NOT false-positive!
    const promptMentionsFlag = await runV2Scenario([
      "/usr/local/bin/opencode",
      "run",
      "explain --standalone flag",
    ]);
    assert.equal(promptMentionsFlag.stopCalls.length, 1);
    assert.equal(promptMentionsFlag.prompts.length, 1);

    // 7. Explicit env override `HYPHAE_OPENCODE_STANDALONE=1` / `=0` works deterministically.
    const envForceOn = await runV2Scenario(
      ["bun", "/$bunfs/root/opencode", "serve", "--port", "4096"],
      "1",
    );
    assert.equal(envForceOn.stopCalls.length, 0);
    assert.equal(envForceOn.prompts.length, 0);

    const envForceOff = await runV2Scenario(
      ["/usr/local/bin/opencode", "run", "--standalone", "do work"],
      "0",
    );
    assert.equal(envForceOff.stopCalls.length, 1);
    assert.equal(envForceOff.prompts.length, 1);

    // 8. Real OpenCode v2.3+ process tree (Unix): parent `... run --standalone` spawning child
    //    `serve --stdio --port 0` skips TurnEnd `stop`; parent `... --standalone` (TUI) keeps it!
    if (process.platform !== "win32") {
      const childRunner = path.join(tmp, "child-stdio-serve.mjs");
      const parentRunner = path.join(tmp, "parent-launcher.mjs");
      const pluginPathUrl = pathToFileURL(path.join(PLUGIN_DIR, "hyphae.ts")).href;

      fs.writeFileSync(
        childRunner,
        `import { pathToFileURL } from "node:url";
process.argv = ["bun", "/$bunfs/root/opencode", "serve", "--stdio", "--port", "0"];
const mod = await import(${JSON.stringify(pluginPathUrl)});
const prompts = [];
let doneResolve;
const done = new Promise((r) => { doneResolve = r; });
const dispose = await mod.default.setup({
  location: { directory: "/workspace/tree-test" },
  session: {
    async prompt(req) { prompts.push(req); },
  },
  event: {
    subscribe() {
      let sent = false;
      return {
        [Symbol.asyncIterator]() {
          return {
            async next() {
              if (!sent) {
                sent = true;
                return { value: { type: "session.execution.succeeded", data: { sessionID: "ses-tree" } }, done: false };
              }
              doneResolve();
              return { value: undefined, done: true };
            },
          };
        },
      };
    },
  },
});
await done;
await new Promise((r) => setTimeout(r, 80));
dispose();
process.stdout.write(JSON.stringify({ prompts }) + "\\n");
`,
        "utf8",
      );

      fs.writeFileSync(
        parentRunner,
        `import { execFileSync } from "node:child_process";
const out = execFileSync(process.execPath, [${JSON.stringify(childRunner)}], {
  encoding: "utf8",
  env: process.env,
});
process.stdout.write(out);
`,
        "utf8",
      );

      const execTree = (parentArgs) =>
        new Promise((resolve, reject) => {
          clearCalls();
          const env = { ...process.env };
          delete env.HYPHAE_OPENCODE_STANDALONE;
          execFile(process.execPath, [parentRunner, ...parentArgs], { env }, (err, stdout, stderr) => {
            if (err) reject(new Error(`parent tree failed: ${err.message}\nstderr=${stderr}`));
            else resolve(JSON.parse(stdout.trim()));
          });
        });

      const runChild = await execTree(["run", "--standalone", "--auto", "--format", "json", "hi"]);
      assert.equal(runChild.prompts.length, 0, "serve --stdio under `run --standalone` must skip stop drain");
      assert.equal(readCalls().filter((c) => c.event === "stop").length, 0);

      const tuiChild = await execTree(["--standalone", "/workspace/tree-test"]);
      assert.equal(tuiChild.prompts.length, 1, "serve --stdio under TUI `--standalone` must keep stop drain");
      assert.equal(readCalls().filter((c) => c.event === "stop").length, 1);
    }
  } finally {
    process.argv = origArgv;
    if (prevBin === undefined) delete process.env.HYPHAE_BIN;
    else process.env.HYPHAE_BIN = prevBin;
    if (prevSock === undefined) delete process.env.HYPHAE_SOCKET;
    else process.env.HYPHAE_SOCKET = prevSock;
    if (prevStandaloneEnv === undefined) delete process.env.HYPHAE_OPENCODE_STANDALONE;
    else process.env.HYPHAE_OPENCODE_STANDALONE = prevStandaloneEnv;
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
