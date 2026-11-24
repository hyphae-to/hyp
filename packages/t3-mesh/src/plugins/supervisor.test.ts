import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { PluginConfig } from "../config.ts";
import { LocalEvents } from "./store.ts";
import { pluginEnv, PluginProcess, type SupervisorOptions } from "./supervisor.ts";

const FIXTURE = new URL("./fixtures/plugin.ts", import.meta.url).pathname;

type Json = Readonly<Record<string, unknown>>;
const isRecord = (value: unknown): value is Json => typeof value === "object" && value !== null && !Array.isArray(value);

const cloudEvent = (id: string, data: Json = { text: "hi" }) => ({
  specversion: "1.0",
  id,
  source: "slack/T1/D1",
  type: "com.slack.message",
  datacontenttype: "application/json",
  data,
});
const eventLine = (to: string, event: unknown) => JSON.stringify({ type: "event", to, event });

/** Captures this process's JSON log lines (log() writes to stderr). */
function captureLogs(): { readonly lines: Json[]; readonly restore: () => void } {
  const lines: Json[] = [];
  const original = process.stderr.write;
  const capture = (chunk: string | Uint8Array): boolean => {
    for (const text of String(chunk).split("\n")) {
      if (!text.startsWith("{")) continue;
      try {
        const value: unknown = JSON.parse(text);
        if (isRecord(value)) lines.push(value);
      } catch {
        // not a log line
      }
    }
    return true;
  };
  process.stderr.write = capture as typeof process.stderr.write;
  return { lines, restore: () => (process.stderr.write = original) };
}

async function waitFor(check: () => boolean, what: string, timeoutMs = 8_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!check()) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}

function setup(
  env: Readonly<Record<string, string>>,
  options: SupervisorOptions = {},
  fields: (dir: string) => Partial<PluginConfig> = () => ({}),
) {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "t3-mesh-plugin-")));
  const record = join(dir, "record.jsonl");
  writeFileSync(record, "");
  const plugin: PluginConfig = {
    name: "slack",
    exec: process.execPath,
    args: [FIXTURE],
    env: { RECORD: record, CONFIGURED: "yes", ...env },
    cwd: dir,
    targets: [{ name: "moneypenny", threadId: "thread-1", coalesceSeconds: 5, maxWaitSeconds: 30, wakesPerHour: 120 }],
    ...fields(dir),
  };
  const events = new LocalEvents({ dbPath: ":memory:", plugins: [plugin] });
  const logs = captureLogs();
  const runner = new PluginProcess(plugin, (to, event) => events.publish("slack", to, event), {
    initialBackoffMs: 50,
    parentEnv: { PATH: process.env["PATH"], NOT_PASSED: "secret", DBUS_SESSION_BUS_ADDRESS: "unix:path=/run/bus" },
    ...options,
  });
  const recorded = (): Json[] =>
    readFileSync(record, "utf8")
      .split("\n")
      .filter((line) => line !== "")
      .flatMap((line) => {
        const value: unknown = JSON.parse(line);
        return isRecord(value) ? [value] : [];
      });
  const logged = (event: string) => logs.lines.filter((line) => line["event"] === event);
  const cleanup = async () => {
    await runner.stop();
    logs.restore();
    events.close();
    rmSync(dir, { recursive: true, force: true });
  };
  return { dir, runner, recorded, logged, cleanup, starts: () => recorded().filter((line) => "start" in line) };
}

test("passes only the minimal environment, the configured one and the channel variables", () => {
  const env = pluginEnv(
    { name: "slack", exec: "/bin/true", args: [], env: { KEY: "v", T3_MESH_FD: "9" }, cwd: "/", targets: [] },
    { HOME: "/home/b", PATH: "/bin", LANG: "C", XDG_RUNTIME_DIR: "/run/user/1", DBUS_SESSION_BUS_ADDRESS: "unix:x", SECRET: "s" },
  );
  assert.deepEqual(env, {
    HOME: "/home/b",
    PATH: "/bin",
    LANG: "C",
    XDG_RUNTIME_DIR: "/run/user/1",
    DBUS_SESSION_BUS_ADDRESS: "unix:x",
    KEY: "v",
    T3_MESH_FD: "3",
    T3_MESH_PLUGIN: "slack",
    T3_MESH_PROTOCOL: "1",
  });
});

test("hello first, an ack per event, and a resent event is a duplicate after a crash restart", async () => {
  const { dir, runner, recorded, logged, cleanup, starts } = setup({
    MODE: "crash-first",
    LINES: JSON.stringify([eventLine("moneypenny", cloudEvent("e1"))]),
  });
  try {
    runner.start();
    await waitFor(() => recorded().filter((line) => line["type"] === "ack").length === 2, "two acks");
    const sequence = recorded().map((line) =>
      "start" in line ? "start" : line["type"] === "ack" ? `ack:${String(line["status"])}` : String(line["type"]),
    );
    assert.deepEqual(sequence, ["start", "hello", "ack:stored", "start", "hello", "ack:duplicate"]);
    assert.deepEqual(recorded()[1], { type: "hello", protocol: 1, plugin: "slack", targets: ["moneypenny"] });
    assert.deepEqual(recorded()[2], { type: "ack", id: "e1", source: "slack/T1/D1", status: "stored" });
    assert.deepEqual(starts()[0], {
      start: 1,
      fd: "3",
      plugin: "slack",
      protocol: "1",
      configured: "yes",
      leaked: null,
      cwd: dir,
    });
    assert.equal(logged("plugin.started").length, 2);
    assert.deepEqual(
      logged("plugin.exited").map((line) => [line["code"], line["restartInMs"]]),
      [[1, 50]],
    );
    assert.deepEqual(
      logged("plugin.event_stored").map((line) => line["status"]),
      ["stored", "duplicate"],
    );
    assert.deepEqual(
      Object.keys(logged("plugin.event_stored")[0] ?? {}),
      ["at", "level", "event", "plugin", "target", "id", "source", "status"],
      "no event data",
    );
    assert.equal(logged("plugin.stdout")[0]?.["plugin"], "slack");
    assert.equal(logged("plugin.stdout")[0]?.["line"], "plugin says hi");
    const stderr = logged("plugin.stderr")[0];
    assert.equal(stderr?.["truncated"], true);
    assert.equal(String(stderr?.["line"]).length, 2048);
  } finally {
    await cleanup();
  }
});

test("every bad line gets a nack, with the limit named for too_large; none is a protocol violation", async () => {
  const { runner, recorded, logged, cleanup } = setup({
    LINES: JSON.stringify([
      "not json",
      JSON.stringify({ type: "request", id: "r1" }),
      eventLine("nobody", cloudEvent("e1")),
      eventLine("moneypenny", cloudEvent("e2", { text: "x".repeat(9000) })),
      eventLine("moneypenny", { ...cloudEvent("e3"), specversion: "0.3" }),
      JSON.stringify({ type: "event", event: cloudEvent("e4") }),
      eventLine("moneypenny", cloudEvent("e5")),
    ]),
  });
  try {
    runner.start();
    await waitFor(() => recorded().filter((line) => line["type"] === "ack" || line["type"] === "nack").length === 7, "replies");
    const replies = recorded().filter((line) => line["type"] === "nack" || line["type"] === "ack");
    assert.deepEqual(
      replies.map((line) => [line["type"], line["id"], line["error"] ?? line["status"]]),
      [
        ["nack", null, "invalid_event"],
        ["nack", null, "unsupported_type"],
        ["nack", "e1", "unknown_target"],
        ["nack", "e2", "too_large"],
        ["nack", "e3", "invalid_event"],
        ["nack", "e4", "invalid_event"],
        ["ack", "e5", "stored"],
      ],
    );
    assert.equal(replies[3]?.["message"], "data is 9011 bytes; limit 8192");
    assert.equal(replies[3]?.["source"], "slack/T1/D1");
    assert.equal(logged("plugin.exited").length, 0);
    assert.equal(logged("plugin.event_rejected").length, 6);
    assert.equal(logged("plugin.started").length, 1);
  } finally {
    await cleanup();
  }
});

test("restarts with backoff doubling up to the maximum", async () => {
  const { runner, logged, cleanup } = setup(
    { MODE: "exit-after", EXIT_AFTER_MS: "0" },
    { initialBackoffMs: 20, maxBackoffMs: 80 },
  );
  try {
    runner.start();
    await waitFor(() => logged("plugin.exited").length >= 5, "five exits");
    assert.deepEqual(
      logged("plugin.exited")
        .slice(0, 5)
        .map((line) => line["restartInMs"]),
      [20, 40, 80, 80, 80],
    );
  } finally {
    await cleanup();
  }
});

test("the backoff resets after enough uptime", async () => {
  const { runner, logged, cleanup } = setup(
    { MODE: "exit-after", EXIT_AFTER_MS: "300" },
    { initialBackoffMs: 20, resetAfterMs: 200 },
  );
  try {
    runner.start();
    await waitFor(() => logged("plugin.exited").length >= 3, "three exits");
    assert.deepEqual(
      logged("plugin.exited")
        .slice(0, 3)
        .map((line) => line["restartInMs"]),
      [20, 20, 20],
    );
  } finally {
    await cleanup();
  }
});

test("closing fd 3 gets the plugin stopped and restarted", async () => {
  const { runner, logged, cleanup, starts } = setup({ MODE: "close-fd3" });
  try {
    runner.start();
    await waitFor(() => starts().length >= 2, "a restart");
    assert.ok(logged("plugin.channel_closed").length >= 1);
    assert.equal(logged("plugin.exited")[0]?.["signal"], "SIGTERM");
  } finally {
    await cleanup();
  }
});

test("a line over 64 KiB is discarded with a too_large nack; the channel stays up", async () => {
  const { runner, recorded, logged, cleanup, starts } = setup({
    MODE: "flood",
    LINES: JSON.stringify([eventLine("moneypenny", cloudEvent("e1"))]),
  });
  try {
    runner.start();
    await waitFor(() => recorded().some((line) => line["type"] === "ack"), "the ack after the long line");
    const replies = recorded().filter((line) => line["type"] === "nack" || line["type"] === "ack");
    assert.deepEqual(replies, [
      {
        type: "nack",
        id: null,
        source: null,
        error: "too_large",
        message: "the line is over 65536 bytes; line limit 65536",
      },
      { type: "ack", id: "e1", source: "slack/T1/D1", status: "stored" },
    ]);
    assert.equal(starts().length, 1);
    assert.equal(logged("plugin.exited").length, 0);
  } finally {
    await cleanup();
  }
});

test("an escaped event line under 64 KiB is accepted when the event is within its limits", async () => {
  // Python's json.dumps with ensure_ascii=True writes each non-ASCII character as \uXXXX.
  const text = "\\u00e9".repeat(3000);
  const line = `{"type":"event","to":"moneypenny","event":${JSON.stringify(cloudEvent("e1")).replace('"hi"', `"${text}"`)}}`;
  assert.ok(Buffer.byteLength(line) > 16 * 1024);
  const { runner, recorded, cleanup } = setup({ LINES: JSON.stringify([line]) });
  try {
    runner.start();
    await waitFor(() => recorded().some((entry) => entry["type"] === "ack"), "the ack");
  } finally {
    await cleanup();
  }
});

test("a spawn that throws (cwd is a file) is retried with backoff", async () => {
  const { runner, logged, cleanup } = setup({}, { initialBackoffMs: 20, maxBackoffMs: 80 }, (dir) => ({
    cwd: join(dir, "record.jsonl"),
  }));
  try {
    runner.start();
    await waitFor(() => logged("plugin.exited").length >= 4, "four failed starts");
    assert.deepEqual(
      logged("plugin.exited")
        .slice(0, 4)
        .map((line) => line["restartInMs"]),
      [20, 40, 80, 80],
    );
    assert.match(String(logged("plugin.exited")[0]?.["error"]), /ENOTDIR/);
    assert.equal(logged("plugin.started").length, 0);
  } finally {
    await cleanup();
  }
});

test("stop sends SIGTERM, then SIGKILL after the kill timeout, and does not restart", async () => {
  const { runner, logged, cleanup, starts } = setup({ MODE: "ignore-term" }, { killTimeoutMs: 200 });
  try {
    runner.start();
    await waitFor(() => starts().length === 1 && runner.running, "the start");
    // Give the fixture time to install its SIGTERM handler.
    await new Promise((resolve) => setTimeout(resolve, 300));
    const stopping = Date.now();
    await runner.stop();
    assert.ok(Date.now() - stopping >= 150, "waited for the kill timeout");
    assert.equal(logged("plugin.exited")[0]?.["signal"], "SIGKILL");
    assert.equal(logged("plugin.exited")[0]?.["restartInMs"], null);
    await new Promise((resolve) => setTimeout(resolve, 200));
    assert.equal(starts().length, 1);
  } finally {
    await cleanup();
  }
});
