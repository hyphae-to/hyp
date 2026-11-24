import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { decodePlugins, loadConfig } from "./config.ts";

const STATE_DIR = "/home/b/.t3-mesh";
const plugin = (fields: Record<string, unknown> = {}) => ({
  name: "slack",
  exec: "/home/b/.pyenv/bin/python",
  args: ["-u", "/home/b/slack/bridge.py"],
  targets: [{ name: "moneypenny", threadId: "thread-1" }],
  ...fields,
});
const refusal = (plugins: unknown): string => {
  try {
    decodePlugins(plugins, STATE_DIR);
    return "accepted";
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  }
};

test("plugins get defaults: no args or env, cwd the state dir, and the target timings", () => {
  assert.deepEqual(decodePlugins([{ name: "slack", exec: "/bin/bridge", targets: [{ name: "m", threadId: "t" }] }], STATE_DIR), [
    {
      name: "slack",
      exec: "/bin/bridge",
      args: [],
      env: {},
      cwd: STATE_DIR,
      targets: [{ name: "m", threadId: "t", coalesceSeconds: 5, maxWaitSeconds: 30, wakesPerHour: 120 }],
    },
  ]);
  const [configured] = decodePlugins(
    [
      plugin({
        env: { SLACK_APP: "x" },
        cwd: "/home/b/slack",
        targets: [{ name: "moneypenny", threadId: "t", coalesceSeconds: 0, maxWaitSeconds: 3600, wakesPerHour: 1 }],
      }),
    ],
    STATE_DIR,
  );
  assert.equal(configured?.cwd, "/home/b/slack");
  assert.deepEqual(configured?.args, ["-u", "/home/b/slack/bridge.py"]);
  assert.deepEqual(configured?.targets[0], { name: "moneypenny", threadId: "t", coalesceSeconds: 0, maxWaitSeconds: 3600, wakesPerHour: 1 });
});

test("plugin config is checked", () => {
  assert.match(refusal([plugin({ name: "Slack" })]), /plugin name "Slack" must match/);
  assert.match(refusal([plugin({ name: "x".repeat(33) })]), /must match/);
  assert.match(refusal([plugin(), plugin()]), /plugin slack is configured twice/);
  assert.match(refusal([plugin({ exec: "bridge" })]), /plugins\.slack\.exec must be an absolute path/);
  assert.match(refusal([plugin({ cwd: "slack" })]), /plugins\.slack\.cwd must be an absolute path/);
  assert.match(refusal([plugin({ env: { "BAD-NAME": "x" } })]), /invalid variable name/);
  assert.match(refusal([plugin({ targets: [] })]), /at least one target/);
  assert.match(refusal([plugin({ targets: [{ name: "a b", threadId: "t" }] })]), /target name "a b" must match/);
  assert.match(
    refusal([plugin({ targets: [{ name: "m", threadId: "t" }, { name: "m", threadId: "u" }] })]),
    /target m is configured twice/,
  );
  assert.match(refusal([plugin({ targets: [{ name: "m", threadId: "" }] })]), /threadId is empty/);
  for (const [field, value] of [
    ["coalesceSeconds", 601],
    ["coalesceSeconds", -1],
    ["maxWaitSeconds", 0],
    ["maxWaitSeconds", 3601],
    ["wakesPerHour", 0],
    ["wakesPerHour", 1.5],
  ] as const) {
    assert.match(refusal([plugin({ targets: [{ name: "m", threadId: "t", [field]: value }] })]), new RegExp(`${field} must be an integer`));
  }
  assert.notEqual(refusal([plugin({ targets: [{ name: "m" }] })]), "accepted", "threadId is required");
  assert.notEqual(refusal([plugin({ args: "-u bridge.py" })]), "accepted", "args is an array, not a shell string");
  assert.equal(refusal([plugin({ name: "slack-2.b_c" })]), "accepted");
});

test("a config without plugins has none", () => {
  const dir = mkdtempSync(join(tmpdir(), "t3-mesh-config-"));
  try {
    chmodSync(dir, 0o700);
    const path = join(dir, "config.json");
    const base = { connectorId: "b@host", t3: { url: "http://127.0.0.1:3773", home: "/x" }, router: { mode: "loopback" } };
    writeFileSync(path, JSON.stringify(base));
    assert.deepEqual(loadConfig(path).plugins, []);
    writeFileSync(path, JSON.stringify({ ...base, plugins: [plugin()] }));
    const config = loadConfig(path);
    assert.equal(config.plugins[0]?.cwd, dir);
    assert.equal(config.localDbPath, join(dir, "local.db"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("event routers resolve origins and private token files relative to the state dir", () => {
  const dir = mkdtempSync(join(tmpdir(), "t3-mesh-event-config-"));
  try {
    chmodSync(dir, 0o700);
    const path = join(dir, "config.json");
    const base = { connectorId: "b@host", t3: { url: "http://127.0.0.1:3773", home: "/x" }, router: { mode: "loopback" } };
    writeFileSync(path, JSON.stringify(base));
    assert.deepEqual(loadConfig(path).eventRouters, []);
    writeFileSync(join(dir, "private.token"), "t3m_private\n", { mode: 0o600 });
    writeFileSync(join(dir, "personal.token"), "t3m_personal\n", { mode: 0o600 });
    writeFileSync(path, JSON.stringify({ ...base, eventRouters: [
      { name: "private", url: "http://127.0.0.1:8793/ignored", tokenFile: "private.token" },
      { name: "personal-2", url: "https://events.example/path", tokenFile: "personal.token" },
    ] }));
    assert.deepEqual(loadConfig(path).eventRouters, [
      { name: "private", url: "http://127.0.0.1:8793", token: "t3m_private" },
      { name: "personal-2", url: "https://events.example", token: "t3m_personal" },
    ]);
    chmodSync(join(dir, "private.token"), 0o644);
    assert.throws(() => loadConfig(path), /private|mode|600/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("event router names reject malformed, duplicate and reserved names before reading tokens", () => {
  const dir = mkdtempSync(join(tmpdir(), "t3-mesh-event-config-"));
  try {
    chmodSync(dir, 0o700);
    const path = join(dir, "config.json");
    const check = (names: string[]) => {
      writeFileSync(path, JSON.stringify({
        connectorId: "b@host", t3: { url: "http://127.0.0.1:3773", home: "/x" }, router: { mode: "loopback" },
        eventRouters: names.map((name) => ({ name, url: "http://127.0.0.1", tokenFile: "missing" })),
      }));
      return () => loadConfig(path);
    };
    for (const name of ["", "Private", "has.dot", "has_under", "-start", "x".repeat(33)]) {
      assert.throws(check([name]), /event router name .* must match/);
    }
    assert.throws(check(["private", "private"]), /event router private is configured twice/);
    assert.throws(check(["primary"]), /primary.*reserved/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("extra router origins must differ from primary and each other, ignoring URL paths", () => {
  const dir = mkdtempSync(join(tmpdir(), "t3-mesh-event-origin-"));
  try {
    const path = join(dir, "config.json");
    const primary = { mode: "http", url: "https://shared.example/primary", tokenFile: "missing" };
    const check = (urls: string[]) => {
      writeFileSync(path, JSON.stringify({ connectorId: "b@host", t3: { url: "http://127.0.0.1:3773", home: "/x" }, router: primary,
        eventRouters: urls.map((url, index) => ({ name: `private-${index}`, url, tokenFile: "missing" })),
      }));
      return () => loadConfig(path);
    };
    assert.throws(check(["https://shared.example:443/extra"]), /shares origin https:\/\/shared.example/);
    assert.throws(check(["http://127.0.0.1:8793/a", "http://127.0.0.1:8793/b"]), /shares origin http:\/\/127.0.0.1:8793/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("router aliases cannot share token-file paths or token contents", () => {
  const dir = mkdtempSync(join(tmpdir(), "t3-mesh-router-tokens-"));
  try {
    const path = join(dir, "config.json");
    writeFileSync(join(dir, "a.token"), "synthetic-token-a\n", { mode: 0o600 });
    writeFileSync(join(dir, "b.token"), "synthetic-token-a\n", { mode: 0o600 });
    const config = (files: string[], primary = true) => ({
      connectorId: "b@host", t3: { url: "http://127.0.0.1:3773", home: "/x" },
      router: primary ? { mode: "http", url: "http://127.0.0.1:8793", tokenFile: files[0] } : { mode: "loopback" },
      eventRouters: (primary ? files.slice(1) : files).map((tokenFile, index) => ({ name: `extra-${index}`, url: `http://localhost:${8793 + index}`, tokenFile })),
    });
    const check = (files: string[], primary = true) => { writeFileSync(path, JSON.stringify(config(files, primary))); return () => loadConfig(path); };
    assert.throws(check(["a.token", "./a.token"]), /shares a tokenFile path/);
    assert.throws(check(["a.token", "b.token"]), (error: unknown) =>
      error instanceof Error && /shares token contents/.test(error.message) && !error.message.includes("synthetic-token-a"));
    assert.throws(check(["a.token", "b.token"], false), /shares token contents/);
    writeFileSync(join(dir, "b.token"), "synthetic-token-b\n", { mode: 0o600 });
    assert.doesNotThrow(check(["a.token", "b.token"]), "different tokens on alias origins identify separate connectors");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("extra-router URLs require HTTPS outside the full loopback range", () => {
  const dir = mkdtempSync(join(tmpdir(), "t3-mesh-router-tls-"));
  try {
    writeFileSync(join(dir, "extra.token"), "synthetic-extra", { mode: 0o600 });
    const path = join(dir, "config.json");
    const check = (url: string) => {
      writeFileSync(path, JSON.stringify({ connectorId: "b@host", t3: { url: "http://127.0.0.1:3773", home: "/x" }, router: { mode: "loopback" },
        eventRouters: [{ name: "private", url, tokenFile: "extra.token" }],
      }));
      return () => loadConfig(path);
    };
    for (const host of ["127.0.0.1", "127.42.7.9", "127.255.255.255", "[::1]", "localhost"]) {
      assert.doesNotThrow(check(`http://${host}:8793`));
    }
    for (const url of ["http://events.example", "http://128.0.0.1", "http://192.168.1.1", "http://[::2]", "ftp://127.0.0.1"]) {
      assert.throws(check(url), /requires https outside loopback/);
    }
    assert.doesNotThrow(check("https://events.example"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
