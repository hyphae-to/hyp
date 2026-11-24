import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { PluginConfig } from "../config.ts";
import type { InboundEventBatch } from "../router/types.ts";
import { Plugins } from "./plugins.ts";

const FIXTURE = new URL("./fixtures/plugin.ts", import.meta.url).pathname;

type Json = Readonly<Record<string, unknown>>;
const isRecord = (value: unknown): value is Json => typeof value === "object" && value !== null && !Array.isArray(value);

async function waitFor(check: () => boolean, what: string): Promise<void> {
  const deadline = Date.now() + 8_000;
  while (!check()) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}

test("a target's backlog is reported to its plugin once a minute, and its clearing once", async () => {
  const dir = mkdtempSync(join(tmpdir(), "t3-mesh-plugins-"));
  const record = join(dir, "record.jsonl");
  writeFileSync(record, "");
  const event = {
    specversion: "1.0",
    id: "e1",
    source: "slack/T1",
    type: "com.slack.message",
    datacontenttype: "application/json",
    data: { text: "hi" },
  };
  const plugin: PluginConfig = {
    name: "slack",
    exec: process.execPath,
    args: [FIXTURE],
    env: { RECORD: record, LINES: JSON.stringify([JSON.stringify({ type: "event", to: "moneypenny", event })]) },
    cwd: dir,
    targets: [{ name: "moneypenny", threadId: "thread-1", coalesceSeconds: 0, maxWaitSeconds: 30, wakesPerHour: 120 }],
  };
  let now = 1_000_000;
  const plugins = new Plugins({
    dbPath: join(dir, "local.db"),
    plugins: [plugin],
    statusCheckMs: 60 * 60 * 1000,
    now: () => now,
  });
  const recorded = (type: string): Json[] =>
    readFileSync(record, "utf8")
      .split("\n")
      .filter((line) => line !== "")
      .flatMap((line) => {
        const value: unknown = JSON.parse(line);
        return isRecord(value) && value["type"] === type ? [value] : [];
      });
  const original = process.stderr.write;
  process.stderr.write = ((_chunk: string | Uint8Array) => true) as typeof process.stderr.write;
  try {
    plugins.start();
    await waitFor(() => recorded("ack").length === 1, "the ack");
    plugins.reportStatus();
    now += 61_000;
    plugins.reportStatus();
    now += 30_000;
    plugins.reportStatus();
    await waitFor(() => recorded("status").length === 1, "a status line");
    // The third report, 30 s after the second, must not have sent another.
    await new Promise((resolve) => setTimeout(resolve, 200));
    assert.deepEqual(recorded("status"), [
      { type: "status", target: "moneypenny", pending: 1, oldestAgeSeconds: 61, t3Connected: false },
    ]);

    const delivered: InboundEventBatch[] = [];
    plugins.attach(async (batch) => {
      delivered.push(batch);
      return { kind: "delivered" };
    });
    await waitFor(() => delivered.length === 1, "the delivery");
    await new Promise((resolve) => setImmediate(resolve));
    plugins.reportStatus();
    plugins.reportStatus();
    await waitFor(() => recorded("status").length === 2, "the cleared status");
    assert.deepEqual(recorded("status")[1], {
      type: "status",
      target: "moneypenny",
      pending: 0,
      oldestAgeSeconds: 0,
      t3Connected: true,
    });
    assert.deepEqual(plugins.route(delivered[0]?.subscriptionId ?? ""), { plugin: "slack", target: "moneypenny" });
  } finally {
    await plugins.stop();
    process.stderr.write = original;
    rmSync(dir, { recursive: true, force: true });
  }
});
