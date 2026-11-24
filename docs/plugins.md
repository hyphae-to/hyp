# Router Data Streams, Connector Thread Bridges & Secrets

`hyphae` intentionally separates **Router Data Streams** (1-to-many pub/sub) from **Connector Thread Bridges** (thread-owned bidirectional messaging with multi-thread fan-in), while letting both share the **same fd-3 plugin SDK** (`plugins/sdk/client.{mjs,py}`) and **OS Keychain-first secrets store** (`hyp secret`).

## Why Both Layers Exist

| Layer | Where it runs | Routing model | Where secrets live | Best for |
| --- | --- | --- | --- | --- |
| **Router Data Streams** (`localRouter.streams`) | Supervised on the **router host** (or external HTTP publisher posting to `POST /v1/events?topic=<name>`) | **1-to-many Pub/Sub** — any agent on any machine subscribes with CloudEvents filters (`hyp_subscribe`) | Router host's OS keyring (or headless `~/.config/hyphae/secrets/` fallback) | **GitHub events** (`github-webhook`), **Prometheus / Alertmanager alerts** (`prometheus-webhook`), **CI / Linear / Sentry / Stripe** webhooks (`webhook-stream`), **custom polling/streaming data source plugins** |
| **Connector Thread Bridges** (`plugins`) | Supervised on a **local connector daemon** (`hyp daemon`) | **Thread-Owned + Multi-Thread Fan-In + Outbound Replies** — pinned to a primary agent `handle` / `sessionId` with live `hyp_plugin_handoff`, multi-thread `hyp_bridge_link` fan-in, and outbound `hyp_plugin_post` replies | Local machine's OS keyring (or local fallback) — never sent to a shared router | **Personal Slack / Telegram / WhatsApp DM & mention bridges**, machine-local alerts, and **100% drop-in compatibility with existing `t3-mesh` plugins** |

### Interactive Setup & Built-In Guides

```sh
hyp plugin setup                      # Interactive TUI for both Router Data Streams & Connector Bridges
hyp plugin list                       # Inspect configured streams and bridges
hyp plugin guide                      # List all built-in plugins & streams
hyp plugin guide slack                # Print step-by-step setup guide + agent usage for Slack
hyp plugin guide whatsapp             # WhatsApp Business Cloud API bridge guide
hyp plugin guide github-webhook       # GitHub webhook stream guide
hyp plugin guide prometheus-webhook   # Prometheus Alertmanager v4 stream guide
```

---

## 0. Secrets Management (`hyp secret`)

Never put raw API tokens or webhook secrets directly in `connector.json`. `hyp secret set` stores secrets in your OS keyring first, with a private local file fallback on headless hosts:
- **macOS Keychain** (`security`, service `hyphae`, written over stdin so values never appear in argv/`ps`)
- **Linux Secret Service** (`secret-tool` — GNOME Keyring, KDE KWallet, KeePassXC — written over stdin when a desktop keyring is available)
- **Private local file fallback** (`~/.config/hyphae/secrets/<name>.secret` with user-only permissions) on headless servers and containers without a system keyring (overrideable via `HYPHAE_SECRET_BACKEND=keychain|secret-service|file`)

```sh
hyp secret set slack-app-token --web  # one-shot 127.0.0.1 password form (zero secret bytes in LLM context)
hyp secret set github-webhook-secret  # hidden TTY prompt (or reads stdin)
hyp secret list                       # lists secret names & backend status (never prints values)
hyp secret check                      # verifies every secret referenced in connector.json
hyp secret rm old-token
```

Reference secrets in any plugin or stream `env` block using:
- `{ "secret": "<name>" }` — resolves the secret from your OS keyring (or local fallback) and injects it **only** into that plugin/stream child process's environment.
- `{ "secretFile": "<name>" }` — provides a private user-only file path (for plugins expecting `*_FILE`).

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
          "GITHUB_WEBHOOK_SECRET": { "secret": "github-webhook-secret" },
          "GITHUB_REPOS": "myorg/myrepo",
          "GITHUB_ORGS": "myorg"
        }
      },
      {
        "name": "prometheus",
        "topic": "alerts",
        "builtin": "prometheus-webhook",
        "env": {
          "PROMETHEUS_PORT": "8793",
          "PROMETHEUS_TOPIC": "alerts",
          "PROMETHEUS_BEARER_TOKEN": { "secret": "prometheus-bearer-token" }
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

### Built-In `github-webhook` Stream & Dead-Subscription Protection

- Receives signed GitHub webhooks on `POST /hooks/github` (default port `8791`, verifies `X-Hub-Signature-256` against `GITHUB_WEBHOOK_SECRET`).
- **Option A — Repository / Organization Webhook**: GitHub -> Repo or Org -> Settings -> Webhooks -> Add webhook -> Payload URL `https://<your-public-host>/hooks/github`, Content type `application/json`, Secret from `hyp secret set github-webhook-secret --web`, events: Pull requests, Pull request reviews, Pull request review comments, Issues, Issue comments, Workflow runs, Pushes.
- **Option B — GitHub App**: Developer settings -> GitHub Apps -> New GitHub App -> Webhook Active + URL `https://<your-public-host>/hooks/github` + Secret -> read-only permissions (Pull requests, Issues, Actions, Contents, Metadata) -> install the App on selected repos or org.
- **CloudEvents attributes**: `repo` (`"owner/repo"`), `source` (`"github.com/owner/repo"`), `type` (`"com.github.pull_request.opened"`, etc.), `action`, `actor`, and `subject` (`"pull/<n>"`, `"issues/<n>"`, `"actions/runs/<id>"`, `"refs/heads/<branch>"`).
- **Preventing silent dead subscriptions**:
  - Set `GITHUB_REPOS` / `GITHUB_ORGS` (or `scope: { repos, orgs }`) in `connector.json` to match where the webhook/App is installed.
  - Agents should call **`hyp_topics()`** first to inspect available topics, monitored repos/orgs, observed webhook sources, valid filter attributes, and setup instructions.
  - **`hyp_subscribe(...)`** automatically runs reachability checks and returns `reachable: false` with actionable `diagnostics` (or fails closed when `strict: true`) if a filter references an unmonitored repo, uses `subject` instead of `repo`, or has a malformed `repo`/`source` prefix!

### Built-In `prometheus-webhook` Stream (`plugins/prometheus/index.mjs`)

- Receives **Prometheus Alertmanager v4** webhook payloads on `POST /alerts` (default port `8793`).
- Optional authentication via `PROMETHEUS_BEARER_TOKEN` (`Authorization: Bearer <token>`) and/or `PROMETHEUS_WEBHOOK_SECRET` (HMAC-SHA256), referenced via `{ "secret": "..." }` or `{ "secretFile": "..." }`.
- Emits one CloudEvent per alert in the batch:
  - `type`: `io.prometheus.alert.firing` or `io.prometheus.alert.resolved`
  - `subject`: `severity=<severity>/<alertname>` (e.g. `severity=critical/CheckoutHighErrorRate`)

Any agent on any connected machine can inspect topics via `hyp_topics()` and subscribe with CloudEvents filters so only the relevant thread wakes up:

```json
hyp_subscribe({
  "key": "github:repo-prs",
  "topic": "github",
  "filters": [{ "exact": { "repo": "myorg/myrepo" } }],
  "mode": "queue",
  "strict": true
})
```

```json
hyp_subscribe({
  "key": "prom:critical",
  "topic": "alerts",
  "filters": [{ "prefix": { "subject": "severity=critical" } }],
  "mode": "interrupt"
})
```

Custom router data sources use the **exact same fd-3 SDK** (`plugins/sdk/client.mjs` or `plugins/sdk/client.py`) — emitting `{"type":"event","to":"<topic>","event":<CloudEvent 1.0>}` publishes directly into the router's topic fan-out engine.

---

## 2. Universal Local Connector Bridges (Works Across All Harnesses)

`hyphae` builds on the battle-tested fd-3 plugin supervisor, SQLite coalescing/retention store (`local.db`), wake caps, backlog status reporting, and CloudEvent validation — while routing targets to **any** harness session on the daemon and adding **multi-thread fan-in** and **bidirectional outbound replies**.

- **100% drop-in compatible with existing `t3-mesh` plugins**: Any plugin built for `t3-mesh` (such as Python Slack Socket Mode bridges, Telegram long-polling connectors, `bf-ops-alerts`, or `scalable`) runs unmodified under `hyp daemon`.
- **Zero credentials shared**: Plugins receive only their explicitly configured secrets (from OS Keychain / Linux Secret Service, local fallback, or `systemd-creds`), never see router tokens, and communicate solely over anonymous duplex fd 3 (`T3_MESH_FD=3` / `AGENTS_MESH_FD=3`).
- **Durable buffering & coalescing**: Events are persisted in `state/local.db` (24h retention, 100 pending batches per target, configurable `coalesceSeconds`, `maxWaitSeconds`, `wakesPerHour`). If the target agent hasn't joined yet, batches wait durably and flush automatically once the target session enrolls.

### Target Addressing

Each plugin target in `~/.config/hyphae/connector.json` accepts one of:

| Field | Example | Behavior |
| --- | --- | --- |
| `handle` | `"pm"` | Routes to whichever enrolled session (Antigravity, Claude, Codex, Herdr, T3 Code, OpenClaw, Cursor, OpenCode, Gemini) currently holds handle `pm`. Best for desktop workflows. |
| `sessionId` | `"antigravity:<uuid>"` / `"claude:<uuid>"` / `"codex:<uuid>"` | Pins delivery to one specific persistent conversation/session ID. |
| `threadId` | `"30227355-..."` | Matches exact `sessionId` or `<harness>:<threadId>` suffix (drop-in compatibility with `t3-mesh` configs). |

### Inspecting Targets & Live Handoffs (`hyp_plugin_targets` / `hyp_plugin_handoff`)

- **`hyp_plugin_targets()`** lists every local plugin target routed or linked to the caller, including `linkedSessions` currently fanned into each target.
- **`hyp_plugin_handoff({ plugin, target, sessionId?, handle?, threadId? })`** transfers primary ownership live to another session (even across different harnesses) with zero daemon restart:

```json
hyp_plugin_handoff({ "plugin": "slack", "target": "pm", "handle": "codex-pm" })
```

### Multi-Thread Bridge Fan-In (`hyp_bridge_link` / `hyp_bridge_unlink`)

Multiple agent threads — even across different harnesses — can share a single Slack, Telegram, WhatsApp, or webhook bridge:

- **`hyp_bridge_link({ plugin, target, sessionId?, handle?, threadId? })`** links a session (defaults to the caller) to `(plugin, target)` so it receives fan-in copies of inbound events and is authorized to post replies via `hyp_plugin_post`.
- **`hyp_bridge_unlink({ plugin, target, sessionId?, handle?, threadId?, all? })`** removes a session's bridge link (defaults to the caller; `all: true` removes every link on the target and requires the primary/configured holder).

```json
hyp_bridge_link({ "plugin": "slack", "target": "pm" })
hyp_bridge_link({ "plugin": "slack", "target": "pm", "handle": "claude-ops" })
hyp_bridge_unlink({ "plugin": "slack", "target": "pm" })
```

### Outbound Chat Bridge Replies (`hyp_plugin_post`)

Agents can reply directly back into Slack, Telegram, WhatsApp, or an outbound webhook callback over the bidirectional fd-3 protocol (`request` / `response`, SDK `mesh.onPost(handler)`):

```json
hyp_plugin_post({
  "plugin": "slack",
  "target": "pm",
  "text": "Investigating checkout-api 5xx spike now — fix PR #412 is running CI.",
  "threadTs": "1732435200.000100"
})
```

| Parameter | Required | Description |
| --- | --- | --- |
| `plugin` | Yes | Configured plugin name (e.g. `"slack"`, `"telegram"`, `"whatsapp"`, `"alerts"`). |
| `target` | Yes | Configured target name on that plugin (e.g. `"pm"`, `"assistant"`, `"ops"`). |
| `text` | Yes | Outbound message body. |
| `channel` | No | Slack channel override (defaults to `SLACK_DEFAULT_CHANNEL` or last inbound channel). |
| `threadTs` | No | Slack thread timestamp to reply in-thread. |
| `chatId` | No | Telegram chat ID override (defaults to `TELEGRAM_DEFAULT_CHAT` or last inbound chat). |
| `to` | No | WhatsApp recipient phone number override (defaults to `WHATSAPP_DEFAULT_TO` or last inbound sender). |
| `replyTo` | No | Message ID to quote/reply to on Telegram or WhatsApp. |

**Fail-closed authorization**: the caller must be the target holder (primary handoff owner, configured target, or linked via `hyp_bridge_link`). Calls from unlinked sessions are rejected with `not_target_holder`.

---

## 3. Built-In Zero-Dependency Plugins (`plugins/`)

`hyphae` ships ready-to-use Node 24 plugins with **zero external npm or Python dependencies**. Configure connector bridges in `connector.json` under `plugins` using `"builtin"`, or router streams under `localRouter.streams`.

### A. Slack (`builtin: "slack"`) — Socket Mode DMs, `@mentions`, Threads & Replies

```json
{
  "plugins": [
    {
      "name": "slack",
      "builtin": "slack",
      "env": {
        "SLACK_APP_TOKEN_FILE": { "secretFile": "slack-app-token" },
        "SLACK_BOT_TOKEN_FILE": { "secretFile": "slack-bot-token" },
        "SLACK_ALLOWED_USERS": "U01234567",
        "SLACK_DEFAULT_CHANNEL": "C01234567"
      },
      "targets": [
        { "name": "pm", "handle": "pm", "coalesceSeconds": 5, "maxWaitSeconds": 30, "wakesPerHour": 120 }
      ]
    }
  ]
}
```

- Uses Slack Socket Mode (`apps.connections.open` + Node 24 native `WebSocket`). No public URL or Funnel required.
- Outbound `hyp_plugin_post`: calls Slack `chat.postMessage` using explicit `channel`, `SLACK_DEFAULT_CHANNEL`, or the last inbound channel, with optional `threadTs` for threaded replies (requires `chat:write` bot scope).
- Optional env vars: `SLACK_TARGET`, `SLACK_ALLOWED_USERS` (comma-separated user IDs), `SLACK_ALLOWED_CHANNELS`, `SLACK_DEFAULT_CHANNEL`.

### B. Telegram (`builtin: "telegram"`) — Bot API Long Polling & Replies

```json
{
  "plugins": [
    {
      "name": "telegram",
      "builtin": "telegram",
      "env": {
        "TELEGRAM_BOT_TOKEN_FILE": { "secretFile": "telegram-bot-token" },
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
- Outbound `hyp_plugin_post`: calls Bot API `sendMessage` using explicit `chatId`, `TELEGRAM_DEFAULT_CHAT`, or the last inbound chat, with optional `replyTo` message ID.
- Optional env vars: `TELEGRAM_TARGET`, `TELEGRAM_ALLOWED_CHATS`, `TELEGRAM_ALLOWED_USERS`, `TELEGRAM_DEFAULT_CHAT`, `TELEGRAM_STATE_FILE`.

### C. WhatsApp (`builtin: "whatsapp"`) — Meta WhatsApp Business Cloud API

`plugins/whatsapp/index.mjs` receives Meta WhatsApp Business Cloud API webhooks and sends replies back via the Graph API:

```json
{
  "plugins": [
    {
      "name": "whatsapp",
      "builtin": "whatsapp",
      "env": {
        "WHATSAPP_PORT": "8796",
        "WHATSAPP_VERIFY_TOKEN": { "secret": "whatsapp-verify-token" },
        "WHATSAPP_APP_SECRET": { "secret": "whatsapp-app-secret" },
        "WHATSAPP_ACCESS_TOKEN": { "secret": "whatsapp-access-token" },
        "WHATSAPP_PHONE_NUMBER_ID": "123456789012345",
        "WHATSAPP_ALLOWED_NUMBERS": "15551234567"
      },
      "targets": [
        { "name": "assistant", "handle": "assistant", "coalesceSeconds": 2, "maxWaitSeconds": 10, "wakesPerHour": 120 }
      ]
    }
  ]
}
```

- **Inbound webhook**: handles Meta `GET` webhook verification challenge (`hub.verify_token` against `WHATSAPP_VERIFY_TOKEN`) and verifies `POST` bodies with constant-time HMAC-SHA256 `X-Hub-Signature-256` against `WHATSAPP_APP_SECRET`.
- **Fail-closed allowlist**: drops inbound senders unless listed in `WHATSAPP_ALLOWED_NUMBERS` (or explicitly opted out via `WHATSAPP_ALLOW_ALL=1`).
- **CloudEvents format**: emits `com.whatsapp.message.received` CloudEvents with `subject: "wa/<from>"`.
- **Outbound `hyp_plugin_post`**: posts via Meta Graph API `/${phoneNumberId}/messages` using `WHATSAPP_ACCESS_TOKEN`, targeting explicit `to`, `WHATSAPP_DEFAULT_TO`, or the last inbound sender, with optional `replyTo` message ID.
- All three secrets (`WHATSAPP_VERIFY_TOKEN`, `WHATSAPP_APP_SECRET`, `WHATSAPP_ACCESS_TOKEN`) can be provided via `{ "secret": "..." }` or `{ "secretFile": "..." }` (`*_FILE`).

### D. Local Webhook (`builtin: "webhook"`) — Loopback / Tailnet HTTP ↔ CloudEvent Bridge

```json
{
  "plugins": [
    {
      "name": "alerts",
      "builtin": "webhook",
      "env": {
        "WEBHOOK_PORT": "8795",
        "WEBHOOK_PATH": "/webhook",
        "WEBHOOK_SECRET_FILE": { "secretFile": "local-webhook-secret" },
        "WEBHOOK_POST_URL": "http://127.0.0.1:9000/reply",
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

- Verifies `X-Webhook-Signature-256: sha256=<hex>` with constant-time HMAC when `WEBHOOK_SECRET` / `WEBHOOK_SECRET_FILE` is set.
- Outbound `hyp_plugin_post`: when `WEBHOOK_POST_URL` is configured, POSTs outbound reply payloads to that callback URL.

### E. Custom / Existing `t3-mesh` Plugins (`exec` + `args`)

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

## 4. Writing Your Own Plugin (fd-3 Protocol v1)

Use the bundled zero-dependency SDK helpers in [plugins/sdk/client.mjs](../plugins/sdk/client.mjs) (Node 24) or [plugins/sdk/client.py](../plugins/sdk/client.py) (Python 3 stdlib):

```js
#!/usr/bin/env node
import { MeshPluginClient } from "/path/to/hyphae/plugins/sdk/client.mjs";

const mesh = new MeshPluginClient();
const { targets } = await mesh.ready;

// Handle outbound `hyp_plugin_post` replies from target holders / linked sessions:
mesh.onPost(async ({ target, text, channel, chatId, threadTs, replyTo, to }) => {
  // Dispatch to your external service here
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

Protocol summary (compatible with `t3-mesh` fd-3 Protocol v1, extended with bidirectional `request`/`response` for outbound replies):
1. Daemon spawns plugin with duplex pipe on **fd 3** and sets `T3_MESH_FD=3`, `AGENTS_MESH_FD=3`, `T3_MESH_PLUGIN=<name>`, `T3_MESH_PROTOCOL=1`.
2. Daemon sends `{"type":"hello","protocol":1,"plugin":"<name>","targets":["<target>",...]}\n`.
3. Plugin writes newline-delimited JSON (≤ 64 KiB/line): `{"type":"event","to":"<target>","event":<CloudEvent 1.0>}\n` (`data` ≤ 8 KiB, whole event ≤ 12 KiB).
4. Daemon answers in order with `{"type":"ack","id":"...","source":"...","status":"stored"|"duplicate"}` or `{"type":"nack",...}` (retry only `unavailable`).
5. Daemon periodically sends `status` (backlog warnings) and `delivery_failed` notices. Plugin should exit cleanly when fd 3 reaches EOF.
6. For outbound `hyp_plugin_post` calls, the daemon sends `{"type":"request","id":"...","method":"post","target":"<target>","params":{...}}\n` on fd 3; the plugin responds with `{"type":"response","id":"...","ok":true,"result":{...}}\n` (or `ok: false` with `"error"`). In Node, `mesh.onPost(handler)` handles this framing automatically.

---

## 5. Router Event Publishers

For external feeds shared across multiple sessions or machines, configure a topic on the router and issue a publisher token restricted to that topic:

```sh
hyp router add-publisher github-hub --topic github --db router.sqlite --token-out pub.token
hyp router serve --db router.sqlite --audit audit.log --topic github=github-hub
```

Publishers post CloudEvents 1.0 to `POST /v1/events?topic=github`. Built-in receivers (`github-webhook`, `prometheus-webhook`, and `webhook-stream`) verify signatures/tokens and publish normalized CloudEvents directly. Sessions subscribe with `hyp_subscribe` filters and choose their own `mode` (`queue` or `interrupt`).
