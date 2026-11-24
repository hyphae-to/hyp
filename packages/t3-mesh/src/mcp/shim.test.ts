import { test } from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { daemonMetadata, providerCallId } from "./shim.ts";

// `_meta` shapes recorded from Claude Code and Codex calling an MCP server under T3 .2676.
test("reads the Claude tool-use id", () => {
  assert.equal(
    providerCallId({ "claudecode/toolUseId": "toolu_014rVCGDi3bP6CwUGg41MzRK", progressToken: 2 }),
    "toolu_014rVCGDi3bP6CwUGg41MzRK",
  );
});

test("reads the Codex call id", () => {
  assert.equal(
    providerCallId({ callId: "exec-b549e890-50b6-44ab-ae3b-f9dd9f803855", "x-codex-turn-metadata": {} }),
    "exec-b549e890-50b6-44ab-ae3b-f9dd9f803855",
  );
});

test("returns null without a usable id", () => {
  assert.equal(providerCallId(undefined), null);
  assert.equal(providerCallId({ callId: 42 }), null);
  assert.equal(providerCallId({ callId: "" }), null);
});

const shimOutput = (socketPath: string): Promise<Array<{ id: number; result: { instructions?: string; tools?: Array<{ name: string; description: string }> } }>> =>
  new Promise((resolve, reject) => {
    const child = execFile(process.execPath, [new URL("../cli.ts", import.meta.url).pathname, "mcp", "--socket", socketPath], {
      encoding: "utf8", timeout: 10_000,
    }, (error, stdout) => {
      if (error !== null) { reject(error); return; }
      resolve(stdout.trim().split("\n").map((line) => JSON.parse(line)));
    });
    child.stdin?.end('{"jsonrpc":"2.0","id":1,"method":"initialize"}\n{"jsonrpc":"2.0","id":2,"method":"tools/list"}\n');
  });

test("MCP gets event-router names from daemon IPC and never reads config.json", async () => {
  const dir = mkdtempSync(join(tmpdir(), "t3-mesh-shim-"));
  const path = join(dir, "daemon.sock");
  const requests: unknown[] = [];
  const server = createServer((socket) => socket.once("data", (chunk: Buffer) => {
    requests.push(JSON.parse(chunk.toString()));
    socket.end(JSON.stringify({ ok: true, result: { eventRouters: ["private"] } }) + "\n");
  }));
  try {
    // A malformed file must not affect MCP metadata; only the running daemon is authoritative.
    writeFileSync(join(dir, "config.json"), "not JSON");
    await new Promise<void>((resolve) => server.listen(path, resolve));
    const responses = await shimOutput(path);
    assert.deepEqual(requests, [{ type: "metadata" }]);
    assert.match(responses.find((item) => item.id === 1)?.result.instructions ?? "", /Event routers: primary \(default\), private/);
    assert.match(responses.find((item) => item.id === 2)?.result.tools?.find((tool) => tool.name === "mesh_subscribe")?.description ?? "", /private/);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    rmSync(dir, { recursive: true, force: true });
  }
});

test("MCP startup falls back to the exact primary tools fixture when the daemon is absent", async () => {
  const dir = mkdtempSync(join(tmpdir(), "t3-mesh-shim-fallback-"));
  try {
    writeFileSync(join(dir, "config.json"), "not JSON");
    const responses = await shimOutput(join(dir, "missing.sock"));
    const fixture: unknown = JSON.parse(readFileSync(new URL("../fixtures/tools-list-primary.json", import.meta.url), "utf8"));
    assert.equal(JSON.stringify(responses.find((item) => item.id === 2)?.result), JSON.stringify(fixture));
    // Recorded from d6ee440: primary-only initialize stays byte-identical.
    const initialize: unknown = JSON.parse(readFileSync(new URL("../fixtures/initialize-primary.json", import.meta.url), "utf8"));
    assert.equal(JSON.stringify(responses.find((item) => item.id === 1)?.result), JSON.stringify(initialize));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("hung or old-daemon metadata replies fall back without blocking MCP startup", async () => {
  const dir = mkdtempSync(join(tmpdir(), "t3-mesh-shim-timeout-"));
  const path = join(dir, "daemon.sock");
  let answer = false;
  const server = createServer((socket) => {
    socket.on("data", () => { if (answer) socket.end('{"ok":false,"error":{"code":"internal","message":"old daemon"}}\n'); });
  });
  try {
    await new Promise<void>((resolve) => server.listen(path, resolve));
    const timedOut = await daemonMetadata(path, 50);
    assert.doesNotMatch(timedOut.instructions, /Event routers:/);
    answer = true;
    const refused = await daemonMetadata(path, 50);
    assert.doesNotMatch(refused.instructions, /Event routers:/);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    rmSync(dir, { recursive: true, force: true });
  }
});
