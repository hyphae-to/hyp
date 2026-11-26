import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import net from "node:net";
import { dirname, join } from "node:path";
import { createInterface } from "node:readline";
import { test } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

const sdkDir = join(dirname(fileURLToPath(import.meta.url)), "..", "sdk");
const event = { specversion: "1.0", id: "same-event", source: "sdk/parity", type: "sdk.test", data: {} };
const nodeCode = `
const { MeshPluginClient } = await import(process.env.SDK_URL);
const statuses = [];
const mesh = new MeshPluginClient({ handleFatalErrors:false, onStatus: msg => statuses.push(msg),
  onPost: async ({text,target}) => ({text,target}) });
await mesh.ready;
const values = await Promise.all([mesh.send("ops", ${JSON.stringify(event)}),mesh.send("ops", ${JSON.stringify(event)})]);
let error;
try { await mesh.send("bad", ${JSON.stringify(event)}); } catch (e) { error = {code:e.code,data:e.data}; }
console.log(JSON.stringify({values,error,statuses,tokenDeleted:!process.env.HYPHAE_PLUGIN_TOKEN}));
mesh.close();
`;
const pythonCode = `
import json, os, sys, threading
sys.path.insert(0, os.environ["SDK_DIR"])
from client import MeshPluginClient, PluginRpcError
statuses = []
client = MeshPluginClient(on_status=lambda msg:statuses.append(msg), on_post=lambda p:{"text":p["text"],"target":p["target"]})
values = [None, None]
def publish(i):
    values[i] = client.send("ops", json.loads(os.environ["TEST_EVENT"]), retry_unavailable=False)
threads = [threading.Thread(target=publish,args=(i,)) for i in range(2)]
for thread in threads:thread.start()
for thread in threads:thread.join()
error = None
try:client.send("bad", json.loads(os.environ["TEST_EVENT"]), retry_unavailable=False)
except PluginRpcError as e:error = {"code":e.code,"data":e.data}
print(json.dumps({"values":values,"error":error,"statuses":statuses,"tokenDeleted":"HYPHAE_PLUGIN_TOKEN" not in os.environ}),flush=True)
client.close()
`;

for (const runtime of ["node", "python"]) {
  test(`${runtime} v2 SDK: authenticated TCP, duplicate event IDs, out-of-order replies and interleaved post/status`, { timeout: 10_000 }, async (t) => {
    const executable = runtime === "node" ? process.execPath : "python3";
    if (runtime === "python" && spawnSync(executable, ["--version"]).error) return t.skip("python3 unavailable");
    const token = randomBytes(32).toString("hex");
    const sockets = new Set();
    const publishes = [];
    const postReplies = [];
    const protocolErrors = [];
    let release;
    const postSeen = new Promise(resolve => { release = resolve; });
    const server = net.createServer(socket => {
      sockets.add(socket);
      socket.on("error", () => {});
      const send = frame => socket.write(JSON.stringify(frame) + "\n");
      let authenticated = false;
      createInterface({ input: socket }).on("line", line => {
        try {
          const frame = JSON.parse(line);
          if (!authenticated) {
            assert.deepEqual(frame, { type: "auth", token });
            authenticated = true;
            send({ jsonrpc: "2.0", method: "hyphae/hello", params: { protocol: 2, plugin: "parity", targets: ["ops"] } });
            return;
          }
          assert.equal(frame.jsonrpc, "2.0");
          assert.equal(Object.hasOwn(frame, "type"), false);
          if (frame.method === "hyphae/publish") {
            if (frame.params.to === "bad") {
              send({ jsonrpc: "2.0", id: frame.id, error: { code: -32003, message: "unknown target", data: { target: "bad" } } });
              return;
            }
            publishes.push(frame);
            if (publishes.length === 2) {
              assert.notEqual(publishes[0].id, publishes[1].id);
              assert.equal(frame.params.event.id, publishes[0].params.event.id);
              send({ jsonrpc: "2.0", method: "hyphae/status", params: { target: "ops", pending: 2 } });
              send({ jsonrpc: "2.0", id: "host-post", method: "hyphae/post", params: { target: "ops", params: { text: "while-publishing" } } });
            }
          } else if (frame.id === "host-post") {
            postReplies.push(frame);
            send({ jsonrpc: "2.0", id: publishes[1].id, result: { status: "duplicate", ordinal: 2 } });
            send({ jsonrpc: "2.0", id: publishes[0].id, result: { status: "stored", ordinal: 1 } });
            release();
          } else throw new Error("unexpected protocol frame");
        } catch (error) { protocolErrors.push(error); socket.destroy(); }
      });
    });
    await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
    const child = spawn(executable, runtime === "node" ? ["--input-type=module", "-e", nodeCode] : ["-u", "-c", pythonCode], {
      env: { PATH: process.env.PATH, HOME: process.env.HOME, HYPHAE_PLUGIN_ADDR: `127.0.0.1:${server.address().port}`,
        HYPHAE_PLUGIN_TOKEN: token, SDK_URL: pathToFileURL(join(sdkDir, "client.mjs")).href, SDK_DIR: sdkDir, TEST_EVENT: JSON.stringify(event) },
      stdio: ["ignore", "pipe", "pipe"],
    });
    t.after(async () => {
      child.kill("SIGKILL");
      for (const socket of sockets) socket.destroy();
      await new Promise(resolve => server.close(resolve));
    });
    let stdout = "", stderr = "";
    child.stdout.on("data", data => { stdout += data; });
    child.stderr.on("data", data => { stderr += data; });
    const exit = await new Promise((resolve, reject) => { child.once("exit", resolve); child.once("error", reject); });
    assert.deepEqual(protocolErrors, []);
    assert.equal(exit, 0, stderr);
    await postSeen;
    assert.deepEqual(postReplies[0], { jsonrpc: "2.0", id: "host-post", result: { text: "while-publishing", target: "ops" } });
    const report = JSON.parse(stdout);
    assert.deepEqual(report.values.map(value => value.status).sort(), ["duplicate", "stored"]);
    if (runtime === "node") assert.deepEqual(report.values.map(value => value.ordinal), [1, 2]);
    assert.deepEqual(report.error, { code: -32003, data: { target: "bad" } });
    assert.deepEqual(report.statuses, [{ target: "ops", pending: 2 }]);
    assert.equal(report.tokenDeleted, true);
    assert.equal(stderr.includes(token), false);
  });
}

for (const runtime of ["node", "python"]) {
  for (const mode of ["v1-hello", "oversized", "partial-eof", "disconnect", "outbound-limit", "timeout", "invalid-result"]) {
    test(`${runtime} v2 SDK fails closed for ${mode} and releases pending calls`, { timeout: 5_000 }, async (t) => {
      const executable = runtime === "node" ? process.execPath : "python3";
      if (runtime === "python" && spawnSync(executable, ["--version"]).error) return t.skip("python3 unavailable");
      const token = randomBytes(32).toString("hex");
      const sockets = new Set();
      const errors = [];
      let published = 0;
      const server = net.createServer(socket => {
        sockets.add(socket);
        socket.on("error", () => {});
        let authenticated = false;
        createInterface({ input: socket }).on("line", line => {
          try {
            const frame = JSON.parse(line);
            if (!authenticated) {
              assert.deepEqual(frame, { type: "auth", token });
              authenticated = true;
              socket.write(JSON.stringify(mode === "v1-hello" ? { type: "hello", protocol: 1, targets: ["ops"] } :
                { jsonrpc: "2.0", method: "hyphae/hello", params: { protocol: 2, targets: ["ops"] } }) + "\n");
            } else {
              published++;
              assert.equal(frame.method, "hyphae/publish");
              if (mode === "timeout") return;
              if (mode === "invalid-result") socket.write(JSON.stringify({jsonrpc:"2.0",id:frame.id,result:null}) + "\n");
              else if (mode === "oversized") socket.write("x".repeat(65_537) + "\n");
              else if (mode === "partial-eof") socket.end('{"jsonrpc":"2.0"');
              else socket.destroy();
            }
          } catch (error) { errors.push(error); socket.destroy(); }
        });
      });
      await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
      const code = runtime === "node" ? `
const {MeshPluginClient} = await import(process.env.SDK_URL);
const mesh = new MeshPluginClient({handleFatalErrors:false,onError:()=>{}});
try {await mesh.ready;await mesh.send("ops",{...${JSON.stringify(event)},data:{body:process.env.MODE==="outbound-limit"?"x".repeat(70000):"ok"}},{timeoutMs:25});process.exitCode=2;}
catch {console.log("rejected");}finally{mesh.close();}
` : `
import os,sys
sys.path.insert(0,os.environ["SDK_DIR"])
from client import MeshPluginClient
try:
    client = MeshPluginClient()
    client.send("ops",{"specversion":"1.0","id":"pending","source":"test","type":"test","data":{"body":"x"*70000 if os.environ["MODE"]=="outbound-limit" else "ok"}},retry_unavailable=False,timeout=0.025)
    sys.exit(2)
except Exception:print("rejected",flush=True)
finally:
    if "client" in locals():client.close()
`;
      const child = spawn(executable, runtime === "node" ? ["--input-type=module", "-e", code] : ["-u", "-c", code], {
        env: { PATH: process.env.PATH, HOME: process.env.HOME, MODE: mode,
          HYPHAE_PLUGIN_ADDR: `127.0.0.1:${server.address().port}`, HYPHAE_PLUGIN_TOKEN: token,
          SDK_URL: pathToFileURL(join(sdkDir, "client.mjs")).href, SDK_DIR: sdkDir },
        stdio: ["ignore", "pipe", "pipe"],
      });
      t.after(async () => { child.kill("SIGKILL"); for (const socket of sockets) socket.destroy(); await new Promise(resolve => server.close(resolve)); });
      let stdout = "", stderr = "";
      child.stdout.on("data", data => { stdout += data; });
      child.stderr.on("data", data => { stderr += data; });
      const exit = await new Promise((resolve, reject) => {child.once("exit", resolve);child.once("error", reject);});
      assert.equal(exit, 0, stderr);
      assert.deepEqual(errors, []);
      assert.equal(stdout.trim(), "rejected");
      assert.equal(published, ["v1-hello", "outbound-limit"].includes(mode) ? 0 : 1);
      assert.equal(stderr.includes(token), false);
    });
  }
}
