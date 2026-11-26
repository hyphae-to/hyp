# Custom Plugin SDK (JSON-RPC 2.0 / Cross-Platform IPC)

Write custom chat bridges or event sources in any language that can read and write newline-delimited JSON (`<= 64 KiB` per line) over Hyphae's private subprocess IPC channel — supported natively on **macOS, Linux, and Windows**.

---

## 1. Supervisor Contract (`SubprocessSupervisor`)

- **Cross-platform transport:** Both transports carry the exact same NDJSON framing and protocol loop:
  - **macOS & Linux (`UnixFd3`):** Anonymous duplex Unix socketpair duped onto **fd 3** (`HYPHAE_FD=3`, `HYPHAE_PLUGIN=<id>`, `HYPHAE_PROTOCOL=2`). Exit cleanly with code `0` when fd 3 reaches EOF.
  - **Windows (`LoopbackTcp`):** Single-accept loopback-only TCP listener on `127.0.0.1:0` with a per-spawn 256-bit CSPRNG token passed in the scrubbed child env (`HYPHAE_PLUGIN_TRANSPORT=tcp`, `HYPHAE_PLUGIN_ADDR=127.0.0.1:<port>`, `HYPHAE_PLUGIN_TOKEN=<hex>`, `HYPHAE_PLUGIN=<id>`, `HYPHAE_PROTOCOL=2`). The child connects, sends one bounded (`<= 4 KiB`) auth line `{"type":"auth","token":"<hex>"}\n`, clears `HYPHAE_PLUGIN_TOKEN` from its environment, and exits cleanly with code `0` when the socket reaches EOF.
- **Scrubbed environment:** Inherits only safe OS runtime variables (`PATH`, `HOME`, `TMPDIR`, `LANG`, `XDG_RUNTIME_DIR`, `DBUS_SESSION_BUS_ADDRESS`, plus Windows OS/temp/profile paths on Windows) and entries explicitly listed in `plugins[].env` (resolved from `SecretStore` when using `{ "secret": "<name>" }`).
- **Framing & Resilience:** Strict 64 KiB `LineSplitter`, exponential restart backoff (`1s -> 60s`), clean shutdown, and a **`CrashLoopBackOff`** circuit breaker tripping after 5 consecutive rapid crashes.
- **Redacted stderr logs:** Captured into `<state_dir>/logs/plugin-<id>.log` (`0600`) with configured secret values and per-spawn loopback tokens automatically scrubbed to `[REDACTED]`.
- **Topic isolation:** Bridge topics stay local-only by default unless `"exposeTopic": true` is explicitly configured in `node.json`.

---

## 2. JSON-RPC 2.0 (`HYPHAE_PROTOCOL=2`)

- **`hyphae/hello`** *(notification, host -> plugin)*: `{ "protocol": 2, "plugin": "<id>", "targets": ["..."] }`
- **`hyphae/publish`** *(request, plugin -> host)*: `{ "to": "<target>", "event": <CloudEvent v1.0> }` -> result `{ "status": "stored" | "duplicate" }`
- **`hyphae/post`** *(request, host -> plugin)*: `{ "target": "<target>", "params": { "text": "...", "replyTo"?: "...", "reaction"?: "..." } }` -> JSON-RPC result `{ ... }`
- **`hyphae/status`** & **`hyphae/deliveryFailed`** *(notifications)*

---

## 3. Zero-Dependency v2 SDKs (Node & Python)

`SubprocessSupervisor` sends a JSON-RPC v2 `hyphae/hello` notification immediately after transport authentication. Protocol v1 frames are rejected; there is no grace timer, auto-detection, or fallback. Use [plugins/sdk/client.mjs](../../plugins/sdk/client.mjs) (Node 24+) or [plugins/sdk/client.py](../../plugins/sdk/client.py) (Python 3 stdlib) — both automatically handle Unix fd 3 and Windows authenticated loopback TCP with zero platform-specific code in your plugin:

```js
#!/usr/bin/env node
import { MeshPluginClient } from "./plugins/sdk/client.mjs";

const mesh = new MeshPluginClient();
const { targets } = await mesh.ready;

mesh.onPost(async ({ target, text, replyTo }) => {
  return { delivered: true, target };
});

await mesh.send(targets[0], {
  specversion: "1.0",
  id: crypto.randomUUID(),
  source: "my-plugin/local",
  type: "com.example.ping",
  datacontenttype: "application/json",
  data: { text: "hello from custom plugin" },
});
```

See [docs/plugins.md](../plugins.md) for wiring custom or official plugins in `node.json`.

Publish requests use unique RPC IDs independent of CloudEvent IDs, so concurrent duplicate events and out-of-order replies remain correlated. `send` returns the durable result and raises `PluginRpcError` for JSON-RPC failures: `-32001` too large, `-32002` invalid event, `-32003` unknown target, `-32004` ID conflict, and `-32005` temporarily unavailable. Node callers catch these errors; Python preserves its optional `retry_unavailable` behavior. Both SDKs dispatch posts and notifications while publish replies are pending, bound frames and pending work, and fail pending calls promptly on disconnect. `system.wake` remains a notification and never produces a reply.
