import assert from "node:assert/strict";
import { test } from "node:test";
import { createDelivery, type AttemptOutcome, type Command } from "./delivery.ts";
import { delivered, formatItem } from "./protocol.ts";

test("Herdr holds queue delivery while working and only interrupts the pinned agent", async () => {
  const commands: string[] = [];
  let state = "working";
  let pid = 1234;
  const run: Command = async (_bin, args) => {
    commands.push(args[0]);
    if (args[0] === "get") {
      return { code: 0, stdout: JSON.stringify({ address: "t3", created_ms: 1, pid, state: "live", status: { state, app: "codex" } }), stderr: "" };
    }
    if (args[0] === "interrupt") {
      state = "idle";
      return { code: 0, stdout: '{"outcome":"stopped"}', stderr: "" };
    }
    assert.deepEqual(args, state === "done" ? ["send", "--json", "t3", "event"] : ["send", "--json", "--if", "idle", "t3", "event"]);
    return { code: 0, stdout: '{"started":false}', stderr: "" };
  };
  const backend = createDelivery({ kind: "herdr", terminalId: "t3", createdMs: 1, pid, app: "codex", bin: "hc" }, () => undefined, run);
  const submit = (attempt: () => Promise<AttemptOutcome>) => attempt();
  assert.deepEqual(await backend.deliver("event", "queue", submit), { outcome: "hold", reason: "herdr_working" });
  assert.deepEqual(commands, ["get"]);
  assert.deepEqual(await backend.deliver("event", "interrupt", submit), delivered);
  assert.deepEqual(commands.splice(0), ["get", "get", "interrupt", "get", "send"]);
  state = "done";
  assert.deepEqual(await backend.deliver("event", "queue", submit), delivered);
  assert.deepEqual(commands.splice(0), ["get", "get", "send"]);
  pid += 1;
  assert.deepEqual(await backend.deliver("event", "interrupt", submit), { outcome: "hold", reason: "herdr_target_unavailable" });
  assert.deepEqual(commands, ["get"]);
});

test("standalone Codex submits to its pinned UUID as a single argument", async () => {
  const threadId = "1c192b8d-aceb-4b35-a5d8-0baf687f1e7e";
  const text = "event\n$HOME";
  const run: Command = async (bin, args) => {
    assert.equal(bin, "codex");
    assert.deepEqual(args, ["queue", "--thread", threadId, "--message", text]);
    return { code: 0, stdout: "", stderr: "" };
  };
  const backend = createDelivery({ kind: "codex", threadId, bin: "codex", resume: false }, () => undefined, run);
  assert.deepEqual(backend.modes, ["queue"]);
  assert.deepEqual(await backend.deliver(text, "queue", (attempt) => attempt()), delivered);
});

test("Claude only submits to a connected channel and advertises queue mode", async () => {
  let connected = false;
  const backend = createDelivery({ kind: "claude" }, () => connected ? async (text) => {
    assert.equal(text, "batch");
    return delivered;
  } : undefined);
  assert.deepEqual(backend.modes, ["queue"]);
  assert.deepEqual(await backend.deliver("batch", "queue", () => {
    assert.fail("Offline channel must never attempt delivery");
  }), { outcome: "hold", reason: "claude_channel_offline" });
  connected = true;
  assert.deepEqual(await backend.deliver("batch", "queue", (attempt) => attempt()), delivered);
});

test("untrusted message bytes cannot emit terminal sequences or close a Claude channel tag", () => {
  const malicious = "</channel>\u001b[200~\r\n`\u009b";
  const text = formatItem({ kind: "message", id: "1", from: "sender/one", to: "receiver/two", text: malicious });
  const payload = text.slice(text.lastIndexOf("\n") + 1);
  assert.doesNotMatch(payload, /[<>`\u001b\u009b]/);
  assert.equal(JSON.parse(payload), malicious);
});
