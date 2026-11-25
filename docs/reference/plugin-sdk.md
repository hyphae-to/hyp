# Custom Plugin SDK (JSON-RPC 2.0 / fd 3)

Write custom chat bridges or event sources in any language that can read and write newline-delimited JSON (`<= 64 KiB` per line) on **file descriptor 3** (supported on **macOS, Linux, and WSL**).

---

## 1. Supervisor Contract (`SubprocessSupervisor`)

- **Transport:** Anonymous duplex Unix socketpair duped onto **fd 3** (`HYPHAE_FD=3`, `HYPHAE_PLUGIN=<id>`, `HYPHAE_PROTOCOL=2`). Exit cleanly with code `0` when fd 3 reaches EOF.
- **Scrubbed environment:** Inherits only `PATH`, `HOME`, `TMPDIR`, `LANG`, `XDG_RUNTIME_DIR`, and `DBUS_SESSION_BUS_ADDRESS` plus entries explicitly listed in `plugins[].env` (resolved from `SecretStore` when using `{ "secret": "<name>" }`).
- **Framing & Resilience:** Strict 64 KiB `LineSplitter`, exponential restart backoff (`1s -> 60s`), clean `SIGTERM -> SIGKILL` shutdown, and a **`CrashLoopBackOff`** circuit breaker tripping after 5 consecutive rapid crashes.
- **Redacted stderr logs:** Captured into `<state_dir>/logs/plugin-<id>.log` (`0600`) with configured secret values automatically scrubbed to `[REDACTED]`.
- **Topic isolation:** Bridge topics stay local-only by default unless `"exposeTopic": true` is explicitly configured in `node.json`.

---

## 2. Option A: JSON-RPC 2.0 over fd 3 (`HYPHAE_PROTOCOL=2`, Recommended)

- **`hyphae/hello`** *(notification, host -> plugin)*: `{ "protocol": 2, "plugin": "<id>", "targets": ["..."] }`
- **`hyphae/publish`** *(request, plugin -> host)*: `{ "target": "<target>", "event": <CloudEvent v1.0> }` -> result `{ "status": "stored" | "duplicate" }`
- **`hyphae/post`** *(request, host -> plugin)*: `{ "target": "<target>", "params": { "text": "...", "replyTo"?: "...", "reaction"?: "..." } }` -> JSON-RPC result `{ ... }`
- **`hyphae/status`** & **`hyphae/deliveryFailed`** *(notifications)*

---

## 3. Option B: Zero-Dependency fd-3 v1 SDKs (Node & Python)

`SubprocessSupervisor` auto-detects legacy fd-3 v1 framing seamlessly. Use [plugins/sdk/client.mjs](../../plugins/sdk/client.mjs) (Node 24+) or [plugins/sdk/client.py](../../plugins/sdk/client.py) (Python 3 stdlib):

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
