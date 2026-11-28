# Chat Bridges *(Beta)*

Connect personal Telegram, Slack (Socket Mode), or WhatsApp chats directly to live coding agent sessions on your machine.

> **Status & Platform Scope:** Chat bridges are **Beta** and run as optional external Node.js subprocesses (`Node 24+`) supervised natively across **macOS, Linux, and Windows** (duplex Unix fd 3 on Unix; authenticated loopback TCP on Windows — see [Windows Operations](../operations/windows.md)). Bridges send plaintext to the external chat provider (Slack, Telegram, WhatsApp), so they are outside Hyphae's node-to-node E2EE boundary.

---

## 1. Store Bot Tokens Out-of-Band

```sh
# Telegram: create a bot via https://t.me/BotFather and find your numeric ID via https://t.me/userinfobot
hyp secret set telegram-bot-token --web

# Slack: enable Socket Mode at https://api.slack.com/apps (xapp-... and xoxb-... tokens)
hyp secret set slack-app-token --web
hyp secret set slack-bot-token --web
```

---

## 2. Install a Verified Official Bridge (`hyp plugin`)

Always install official bridges via `hyp plugin install` (never point `node.json` at a local git checkout). `hyp` verifies every file in constant time against compile-time pinned SHA-256 digests before writing to `~/.config/hyphae/plugins/`:

```sh
hyp plugin install telegram --json
hyp plugin install slack --json
```

Capture the returned `data.nodePath` and `data.plugins[0].scriptPath`. For **Telegram**, when `telegram-bot-token` is already stored in your keystore, `hyp plugin install telegram --json` automatically fetches your bot's public `@username` via Telegram `getMe` (without echoing the token) and returns it as `data.plugins[0].defaultTarget` (lowercase, leading `@` stripped, e.g. `my_assistant_bot`, falling back to `"personal"` if offline or unreachable).

---

## 3. Configure `plugins[]` in `~/.config/hyphae/node.json`

Use `{ "secret": "<name>" }` for all credentials (plaintext secret-like values in `plugins[].env` trigger a startup warning) and **always configure explicit sender allowlists** (all included bridges drop unauthorized senders fail-closed):

- **Telegram:** `TELEGRAM_ALLOWED_USERS` and/or `TELEGRAM_ALLOWED_CHATS` (numeric IDs); set `"targets"` to `["<bot_username>"]` from `data.plugins[0].defaultTarget` (or omit `"targets"` on `id: "telegram"` to auto-resolve the bot's Telegram username via `getMe` at daemon startup, with `"personal"` as fallback)
- **Slack:** `SLACK_ALLOWLIST_FILE` for named senders and roles, or `SLACK_ALLOWED_USERS` and/or `SLACK_ALLOWED_CHANNELS`. See the [Slack sender and channel rules](../plugins.md#slack-sender-and-channel-allowlists).
- **WhatsApp:** `WHATSAPP_ALLOWED_NUMBERS`

See the verified, test-checked `plugins[]` JSON example in [docs/plugins.md](../plugins.md#example-plugins-configuration-confighyphaenodejson).

### Important Security Defaults

- **Local-only bridge topics by default (`exposeTopic: true`):** Bridge topics (`telegram`, `slack`, `whatsapp`, `webhook`) are **never** advertised to paired remote peers and cannot be subscribed to remotely — even by peers holding `stream:subscribe=*` — unless you explicitly add `"exposeTopic": true` to that plugin entry in `node.json`.
- **Fail-closed webhook/Prometheus scripts (`*_ALLOW_UNSIGNED=1`):** The optional Node scripts `plugins/webhook/index.mjs` and `plugins/prometheus/index.mjs` refuse to boot without configured auth secrets. Setting `WEBHOOK_ALLOW_UNSIGNED=1` or `PROMETHEUS_ALLOW_UNSIGNED=1` is permitted **strictly on loopback binds (`127.0.0.1` / `::1`)** for local dev — non-loopback binds still fail closed.

Restart the service and refresh skills so your harnesses advertise `hyp_bridge`:

```sh
hyp service restart
hyp setup --refresh-skills
```

---

## 4. Link a Live Session & Reply

In any agent session (replace `my_assistant_bot` with your bot's Telegram username target from `hyp_bridge({ action: "targets" })`, or `"personal"` if using the fallback):
- **List targets:** `hyp_bridge({ action: "targets" })`
- **Link session:** `hyp_bridge({ action: "link", plugin: "telegram", target: "my_assistant_bot" })` *(automatically claims primary ownership if unowned unless `readOnly: true` is passed)*
- **Hand off primary ownership:** `hyp_bridge({ action: "handoff", plugin: "telegram", target: "my_assistant_bot", handle: "codex" })`
- **Reply or react:** `hyp_send({ to: "telegram:my_assistant_bot", text: "Tests are green." })` or `hyp_send({ to: "telegram:my_assistant_bot", reaction: "👍", replyTo: "<msg-id>" })`

---

## 5. Logs, Crash-Loop Circuit Breaker & Removal

- **Redacted stderr logs:** Each bridge writes stderr to `<state_dir>/logs/plugin-<id>.log` (`0600` permissions, configured secret values scrubbed to `[REDACTED]`).
- **Crash-loop protection:** After 5 consecutive rapid crashes, `SubprocessSupervisor` trips into `crash_loop_backoff` (visible in `node.status.json` and `hyp doctor`), isolating the faulty bridge without taking down the daemon.
- **Clean removal:** `hyp plugin remove telegram` removes the installed files **and** automatically cleans matching `plugins[]` entries from `node.json` (pass `--keep-config` to preserve `node.json`).

---

## What You Should See

- `hyp doctor` reports `OK` for `plugin:telegram` / `plugin:slack` and zero `crash_loop_backoff` warnings.
- Messaging your bot from an allowlisted user wakes the linked agent session with `[hyphae · telegram:my_assistant_bot]`, and replies appear back in chat.

If a bridge crashes or messages are dropped, inspect `<state_dir>/logs/plugin-<id>.log` and see [Troubleshooting](../operations/troubleshooting.md).
