# Router Data Streams, Connector Thread Bridges & Secrets

`hyphae` intentionally separates **Router Data Streams** (1-to-many pub/sub) from **Connector Thread Bridges** (1-to-1 thread-owned messaging), while letting both share the **same fd-3 plugin SDK** (`plugins/sdk/client.{mjs,py}`) and **private `0600` secrets store** (`~/.config/hyphae/secrets/`).

## Why Both Layers Exist

| Layer | Where it runs | Routing model | Where secrets live | Best for |
| --- | --- | --- | --- | --- |
| **Router Data Streams** (`localRouter.streams`) | Supervised on the **router host** (or external HTTP publisher posting to `POST /v1/events?topic=<name>`) | **1-to-many Pub/Sub** — any agent on any machine subscribes with CloudEvents filters (`hyp_subscribe`) | Router host's `~/.config/hyphae/secrets/` (`0600`) | **GitHub events** (`github-webhook`), **CI / Linear / Sentry / Stripe** webhooks (`webhook-stream`), **custom polling/streaming data source plugins** |
| **Connector Thread Bridges** (`plugins`) | Supervised on a **local connector daemon** (`hyp daemon`) | **1-to-1 Thread-Owned** — pinned to one local agent `handle` / `sessionId` with live `hyp_plugin_handoff` | Local machine's `~/.config/hyphae/secrets/` (`0600`) — never sent to a shared router | **Personal Slack / Telegram DM & mention bridges**, machine-local alerts, and **100% drop-in compatibility with existing `t3-mesh` plugins** |

### Interactive Setup & Built-In Guides

```sh
hyp plugin setup           # Interactive TUI for both Router Data Streams & Connector Bridges
hyp plugin list            # Inspect configured streams and bridges
hyp plugin guide           # List all built-in plugins & streams
hyp plugin guide slack     # Print step-by-step setup guide + agent usage for Slack
hyp plugin guide github-webhook
```

---

## 0. Private Secrets Management (`hyp secret`)

Never put raw API tokens or webhook secrets directly in `connector.json`. Store them in `~/.config/hyphae/secrets/<name>.secret` (strict `0600` inside `0700` directory):

```sh
hyp secret set slack-app-token      # hidden TTY prompt (or reads stdin)
hyp secret set github-webhook-secret
hyp secret list                     # lists names & 0600 status (never prints values)
hyp secret check                    # verifies every secret referenced in connector.json
hyp secret rm old-token
```

Reference secrets in any plugin or stream `env` block using:
- `{ "secret": "<name>" }` — resolves the `0600` secret and injects it **only** into that plugin/stream child process's environment.
- `{ "secretFile": "<name>" }` — validates permissions and passes the absolute `0600` file path (for plugins expecting `*_FILE`).

---

## 1. Router Data Streams (`localRouter.streams`)

Configure streams directly under `localRouter.streams` in `connector.json` (no manual `add-publisher` / `--topic` flags needed — `hyp daemon` registers topics, supervises each source, and fans out CloudEvents to matching `hyp_subscribe` filters across all connected harnesses and machines):

```json
{
  "localRouter": {
    "host": "127.0.0.1",
    "port": 8790,
    "db": "router/router.sqlite",
    "streams": [
      {
        "name": "github",
        "topic": "github",
        "builtin": "github-webhook",
        "env": {
          "GITHUB_WEBHOOK_PORT": "8791",
          "GITHUB_WEBHOOK_SECRET": { "secret": "github-webhook-secret" }
        }
      },
      {
        "name": "ci",
        "topic": "ci",
        "builtin": "webhook-stream",
        "env": {
          "WEBHOOK_PORT": "8792",
          "WEBHOOK_SECRET": { "secret": "ci-webhook-secret" }
        }
      },
      {
        "name": "my-custom-feed",
        "topic": "my-custom-feed",
        "exec": "/usr/bin/python3",
        "args": ["-u", "/path/to/my_source.py"],
        "env": {
          "API_KEY": { "secret": "my-feed-api-key" }
        }
      }
    ]
  }
}
```

Any agent on any connected machine can then subscribe with CloudEvents filters:

```json
hyp_subscribe({
  "key": "github:repo-prs",
  "topic": "github",
  "filters": [{ "prefix": { "subject": "myorg/myrepo" } }]
})
```

Custom router data sources use the **exact same fd-3 SDK** (`plugins/sdk/client.mjs` or `plugins/sdk/client.py`) — emitting `{"type":"event","to":"<topic>","event":<CloudEvent 1.0>}` publishes directly into the router's topic fan-out engine!

---

## 2. Universal Local Connector Bridges (Works Across All Harnesses)

`hyphae` reuses `t3-mesh`'s battle-tested fd-3 plugin supervisor, SQLite coalescing/retention store (`local.db`), wake caps, backlog status reporting, and CloudEvent validation—while routing targets to **any** harness session on the daemon.

- **100% drop-in compatible with existing `t3-mesh` plugins**: Any plugin built for `t3-mesh` (such as Python Slack Socket Mode bridges, Telegram long-polling connectors, `bf-ops-alerts`, or `scalable`) runs unmodified under `hyp daemon`.
- **Zero credentials shared**: Plugins hold their own secrets (e.g. `0600` files or `systemd-creds`), never see router tokens, and communicate solely over anonymous duplex fd 3 (`T3_MESH_FD=3` / `AGENTS_MESH_FD=3`).
- **Durable buffering & coalescing**: Events are persisted in `state/local.db` (24h retention, 100 pending batches per target, configurable `coalesceSeconds`, `maxWaitSeconds`, `wakesPerHour`). If the target agent hasn't joined yet, batches wait durably and flush automatically once the target session enrolls!

### Target addressing (all connector types)

Each plugin target in `~/.config/hyphae/connector.json` accepts one of:

| Field | Example | Behavior |
| --- | --- | --- |
| `handle` | `"pm"` | Routes to whichever enrolled session (Antigravity, Claude, Codex, Herdr) currently holds handle `pm`. Best for desktop workflows! |
| `sessionId` | `"antigravity:<uuid>"` / `"claude:<uuid>"` / `"codex:<uuid>"` | Pins delivery to one specific persistent conversation/session ID. |
| `threadId` | `"30227355-..."` | Matches exact `sessionId` or `<harness>:<threadId>` suffix (drop-in compatibility with `t3-mesh` configs). |

Agents can inspect targets they hold with **`hyp_plugin_targets`** and transfer ownership live to another session (even on a different harness!) with **`hyp_plugin_handoff`**:

```json
{ "plugin": "slack", "target": "pm", "handle": "codex-pm" }
```

---

## 2. Built-In Zero-Dependency Plugins (`plugins/`)

`hyphae` ships three ready-to-use Node 24 plugins with **zero external npm or Python dependencies**. Configure them in `connector.json` using `"builtin"`:

### A. Slack (`builtin: "slack"`) — Socket Mode DMs, `@mentions`, and thread follow-ups

```json
{
  "plugins": [
    {
      "name": "slack",
      "builtin": "slack",
      "env": {
        "SLACK_APP_TOKEN_FILE": "/Users/you/.config/hyphae/secrets/slack-app.token",
        "SLACK_BOT_TOKEN_FILE": "/Users/you/.config/hyphae/secrets/slack-bot.token",
        "SLACK_ALLOWED_USERS": "U01234567"
      },
      "targets": [
        { "name": "pm", "handle": "pm", "coalesceSeconds": 5, "maxWaitSeconds": 30, "wakesPerHour": 120 }
      ]
    }
  ]
}
```

- Uses Slack Socket Mode (`apps.connections.open` + Node 24 native `WebSocket`). No public URL or Funnel required.
- Optional env vars: `SLACK_TARGET`, `SLACK_ALLOWED_USERS` (comma-separated user IDs), `SLACK_ALLOWED_CHANNELS`.

### B. Telegram (`builtin: "telegram"`) — Bot API Long Polling

```json
{
  "plugins": [
    {
      "name": "telegram",
      "builtin": "telegram",
      "env": {
        "TELEGRAM_BOT_TOKEN_FILE": "/Users/you/.config/hyphae/secrets/telegram.token",
        "TELEGRAM_ALLOWED_USERS": "123456789",
        "TELEGRAM_STATE_FILE": "/Users/you/.config/hyphae/state/telegram-offset.json"
      },
      "targets": [
        { "name": "assistant", "handle": "assistant", "coalesceSeconds": 2, "maxWaitSeconds": 10, "wakesPerHour": 120 }
      ]
    }
  ]
}
```

- Persists Telegram `offset` safely only after durable `ack` from the connector's SQLite store.
- Optional env vars: `TELEGRAM_TARGET`, `TELEGRAM_ALLOWED_CHATS`, `TELEGRAM_ALLOWED_USERS`, `TELEGRAM_STATE_FILE`.

### C. Local Webhook (`builtin: "webhook"`) — Loopback / Tailnet HTTP → CloudEvent Bridge

```json
{
  "plugins": [
    {
      "name": "alerts",
      "builtin": "webhook",
      "env": {
        "WEBHOOK_PORT": "8795",
        "WEBHOOK_PATH": "/webhook",
        "WEBHOOK_SECRET_FILE": "/Users/you/.config/hyphae/secrets/webhook.secret",
        "WEBHOOK_SOURCE": "alerts/local",
        "WEBHOOK_EVENT_TYPE": "com.ops.alert"
      },
      "targets": [
        { "name": "ops", "handle": "ops", "coalesceSeconds": 30, "maxWaitSeconds": 120, "wakesPerHour": 30 }
      ]
    }
  ]
}
```

- Verifies `X-Webhook-Signature-256: sha256=<hex>` with constant-time HMAC when `WEBHOOK_SECRET_FILE` is set.

### D. Custom / Existing `t3-mesh` Plugins (`exec` + `args`)

Existing Python or binary plugins from `t3-mesh` (e.g. `bridge.py`, `alert_plugin.py`, `connector.py`) run unchanged:

```json
{
  "plugins": [
    {
      "name": "bf-ops-alerts",
      "exec": "/usr/bin/python3",
      "args": ["-u", "/home/you/.local/share/bf-ops/alert_plugin.py"],
      "cwd": "/home/you/.local/share/bf-ops",
      "targets": [
        { "name": "ops", "handle": "ops", "coalesceSeconds": 60, "maxWaitSeconds": 180, "wakesPerHour": 20 }
      ]
    }
  ]
}
```

---

## 3. Writing Your Own Plugin (fd-3 Protocol v1)

Use the bundled zero-dependency SDK helpers in [plugins/sdk/client.mjs](file:///Users/bogdan/Workspace/hyphae/plugins/sdk/client.mjs) (Node 24) or [plugins/sdk/client.py](file:///Users/bogdan/Workspace/hyphae/plugins/sdk/client.py) (Python 3 stdlib):

```js
#!/usr/bin/env node
import { MeshPluginClient } from "/path/to/hyphae/plugins/sdk/client.mjs";

const mesh = new MeshPluginClient();
const { targets } = await mesh.ready;

await mesh.send(targets[0], {
  specversion: "1.0",
  id: crypto.randomUUID(),
  source: "my-plugin/local",
  type: "com.example.ping",
  datacontenttype: "application/json",
  data: { text: "hello from custom plugin" },
});
```

Protocol summary (full wire spec in [packages/t3-mesh/SPEC.md §13](../packages/t3-mesh/SPEC.md#13-connector-plugins-local-delivery)):
1. Daemon spawns plugin with duplex pipe on **fd 3** and sets `T3_MESH_FD=3`, `AGENTS_MESH_FD=3`, `T3_MESH_PLUGIN=<name>`, `T3_MESH_PROTOCOL=1`.
2. Daemon sends `{"type":"hello","protocol":1,"plugin":"<name>","targets":["<target>",...]}\n`.
3. Plugin writes newline-delimited JSON (≤ 64 KiB/line): `{"type":"event","to":"<target>","event":<CloudEvent 1.0>}\n` (`data` ≤ 8 KiB, whole event ≤ 12 KiB).
4. Daemon answers in order with `{"type":"ack","id":"...","source":"...","status":"stored"|"duplicate"}` or `{"type":"nack",...}` (retry only `unavailable`).
5. Daemon periodically sends `status` (backlog warnings) and `delivery_failed` notices. Plugin should exit cleanly when fd 3 reaches EOF.

---

## 4. Router Event Publishers

For external feeds shared across multiple sessions or machines, configure a topic on the router and issue a publisher token restricted to that topic:

```sh
hyp router add-publisher github-hub --topic github --db router.sqlite --token-out pub.token
hyp router serve --db router.sqlite --audit audit.log --topic github=github-hub
```

Publishers post CloudEvents 1.0 to `POST /v1/events?topic=github`. The built-in GitHub webhook receiver (`hyp router github-receiver ...`) verifies `X-Hub-Signature-256` and publishes normalized GitHub events directly. Sessions subscribe with `hyp_subscribe` filters and choose their own `mode` (`queue` or `interrupt`).
