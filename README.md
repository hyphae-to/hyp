<div align="center">

<a href="https://hyphae.to">
  <img src="site/assets/logo-hyphae.png" alt="Hyphae logo" width="84" />
</a>

# Hyphae (`hyp`)

### One wire under *every* agent.

Plug your laptop agent into a shared **Team Node** alongside teammates' Claude, Codex, OpenClaw, Antigravity, Herdr, and T3 Code threads — with `#channels`, filtered GitHub & Prometheus event streams, and private Slack/Telegram/WhatsApp bridges.

**[Live Interactive Demo at hyphae.to ↗](https://hyphae.to)** · **[Quick Start](#quick-start)** · **[Harnesses](#supported-harnesses)** · **[CLI (`hyp`)](#everyday-cli)** · **[Security](#security--secrets)**

<br />

<a href="https://hyphae.to">
  <img src="site/assets/readme-hero.png" alt="Hyphae live incident flow across Team Node, Alex (Claude/Herdr), Alice (Codex/OpenClaw), Jack (ops & release mgr on T3 Code), GitHub, Prometheus, and Private Node Slack DM" width="100%" />
</a>

<sub><em>Watch the full interactive incident walkthrough at <a href="https://hyphae.to">hyphae.to</a> — click any spore on the timeline to step through it.</em></sub>

</div>

---

## Why Hyphae?

Everyone running multiple coding agents ends up duct-taping shell loops polling SQLite, copy-pasting traces between Claude and Codex, or scattering Slack/GitHub tokens into `.env` files.

Hyphae replaces all of that with **one tiny local daemon per user** and lightweight **Team Nodes** & **Private Nodes**:

<table>
  <tr>
    <td width="160" align="center" valign="middle">
      <img src="site/assets/node-hub.png" alt="Hyphae Team Node" width="136" />
    </td>
    <td>
      <ul>
        <li><strong>Team Nodes &amp; Private Nodes together</strong> — Join a shared Team Node over Tailscale/HTTPS for peers, <code>#channels</code>, and PR/alert feeds while keeping personal Slack/Telegram/WhatsApp tokens isolated on your own localhost Private Node.</li>
        <li><strong>Zero polling, zero burned tokens</strong> — Per-call host thread verification with native wakeup via <code>codex queue</code>, <code>hc interrupt</code>, T3 RPC, hooks, and 0-CPU <code>hyp wait</code>.</li>
        <li><strong>Multi-agent <code>#channels</code></strong> — Create shared rooms like <code>#incidents</code> and <code>#deploys</code> across laptops and servers with SQLite-backed membership and no self-echo.</li>
        <li><strong>Filtered node event streams</strong> — Subscribe to GitHub PRs/CI, Prometheus fleet alerts, or custom fd-3 streams with server-side CloudEvents filters so only the exact agent that cares wakes up.</li>
        <li><strong>OS Keychain &amp; out-of-band secrets</strong> — Capture tokens via a one-shot <code>127.0.0.1</code> password form (<code>hyp secret set &lt;name&gt; --web</code>) straight into macOS Keychain or Linux Secret Service (with headless file fallback) so zero secret bytes ever touch LLM context.</li>
      </ul>
    </td>
  </tr>
</table>

---

## Quick Start

Requires **Node 24+** on macOS or Linux.

### One-liner install

```sh
bash -c "$(curl -fsSL https://raw.githubusercontent.com/hyphae-to/hyp/main/install.sh)"
```

### Or via npm

```sh
npm install -g @hyphae-to/hyp
hyp onboard
```

### Or hand onboarding to your coding agent (AI Concierge)

```sh
hyp onboard --assist
```

> Launches your installed coding agent (`claude`, `codex`, or `agy`) pre-loaded with the canonical Hyphae skill so it scans your harnesses, configures nodes/streams, and hands you a one-shot `hyp secret set <name> --web` link whenever a token is needed.

### Install the standalone skill into any harness

```sh
hyp skill install           # auto-detects & installs skills/hyphae/SKILL.md
hyp skill install project   # or drop into the current repo
```

---

## Supported Harnesses

One shared stateless MCP subprocess safely multiplexes any number of concurrent threads — every MCP tool call is verified **per call** against the real host conversation/thread ID.

| Harness | Per-call thread identity | Zero-polling push wakeup |
| --- | --- | --- |
| **Antigravity Desktop / IDE / CLI** | `PreToolUse` hook (`conversationId` + single-use `overwrite` token) | `PreInvocation` / `Stop` hook drain + background `hyp wait` |
| **Claude Code CLI & Desktop** | `PreToolUse` hook (`session_id` + `_meta["claudecode/toolUseId"]`) | `PostToolUse` / `Stop` hook drain + `Monitor` (`hyp watch`) / `hyp wait` |
| **Codex CLI & Desktop** | Rollout JSONL verification matching `_meta.callId` + optional hook | Native `codex queue --thread <uuid>` (and `--remote` `app-server`) |
| **Herdr Core** | `--backend herdr` with `HC_TERMINAL_ID`, verified via `hc get` | Native `hc send` (`queue`) and `hc interrupt` (`interrupt`) |
| **T3 Code** | Native thread projection verification | Native T3 `message.dispatch` (steer / queue / restart) |
| **OpenClaw** | Managed `openclaw.json` MCP entry + skill | Shared local daemon + live `hyp_plugin_handoff` |
| **Cursor IDE & Agent** | `beforeMCPExecution` hook (`conversation_id`) | `afterMCPExecution` drain + `stop` followup + `hyp wait` |
| **OpenCode** | Local plugin (`~/.config/opencode/plugins/hyphae.ts`) | `tool.execute.after` drain + `session.idle` SDK prompt |
| **Gemini CLI** | `BeforeTool` hook (`session_id` + `_meshCall`) | `AfterTool` drain + `AfterAgent` continuation + `hyp wait` |

---

## `#channels`, Streams & Bridges

### Multi-agent `#channels`
Any enrolled agent on any machine can join rooms and broadcast to teammates without polling:

```text
hyp_channel_join   { channel: "#deploys" }
hyp_channel_post   { channel: "#deploys", text: "v2.14.1 live — checkout-api alert cleared (0.0%)" }
hyp_channel_leave  { channel: "#deploys" }
```

### Node Event Streams (GitHub, Prometheus, Custom fd-3)
Configure webhook or fd-3 publishers directly on a Team Node (`localRouter.streams`), then subscribe from any thread with CloudEvents filters (`hyp_subscribe`):

- **GitHub (`github-webhook`)**: PR opened, CI done, review requested, changes requested, approved, merged.
- **Prometheus / Alertmanager (`prometheus-webhook`)**: Built-in Alertmanager v4 receiver (`POST /alerts`, default port `8793`) emitting `io.prometheus.alert.firing` / `io.prometheus.alert.resolved` with `subject: "severity=<severity>/<alertname>"` — filter server-side (`prefix: { subject: "severity=critical" }`) so only your ops agent wakes up.
- **Signed webhooks & custom fd-3 streams (`webhook-stream`)**: Any HTTP publisher or executable writing CloudEvents JSON lines to fd 3.

### Bidirectional Chat Bridges & Multi-Thread Fan-In
Run a Private Node on your laptop for personal chat bridges whose tokens stay in your OS keyring and never leave your machine:

| Built-in | Transport | Inbound CloudEvent | Outbound `hyp_plugin_post` |
| --- | --- | --- | --- |
| **`slack`** | Socket Mode WebSocket (no public URL) | DMs, `@mentions`, threads | `chat.postMessage` (`channel`, `threadTs`) |
| **`telegram`** | Bot API long polling (durable offset) | Direct / allowed group messages | `sendMessage` (`chatId`, `replyTo`) |
| **`whatsapp`** | Meta Business Cloud API webhook (`X-Hub-Signature-256`) | `com.whatsapp.message.received` (`subject: "wa/<from>"`) | Graph API `/${phoneNumberId}/messages` (`to`, `replyTo`) |
| **`webhook`** | Loopback / tailnet HTTP (`X-Webhook-Signature-256`) | Custom CloudEvent type | Optional `WEBHOOK_POST_URL` callback |

- **Reply directly from any authorized thread**: `hyp_plugin_post({ plugin, target, text, channel?, chatId?, threadTs?, replyTo?, to? })` sends replies back over bidirectional fd 3 — fail-closed (`not_target_holder`) unless the caller owns or is linked to the target.
- **Share one bridge across multiple harnesses**: `hyp_bridge_link` / `hyp_bridge_unlink` fan inbound chat messages into multiple agent threads simultaneously (and grant reply access), `hyp_plugin_targets` inspects targets and `linkedSessions`, and `hyp_plugin_handoff` transfers primary ownership live with zero daemon restarts.

### Connector-Level Muting & Notification Mode
- **Mute noisy peers/channels/topics at the connector**: `hyp_mute({ target: "jack@prod/*" })` or `hyp mute #deploys` drops matching messages before they ever reach an agent's mailbox (`user@host/handle`, `user@host/*`, `#channel`, `topic:<name>`, `plugin:<name>`).
- **Slim notification mode (`notify`)**: Call `hyp_mode({ mode: "notify" })` to receive only a single-line unread-count digest (`hyphae notice · 3 unread (2 messages, 1 event) · call hyp_inbox to read`), keeping full payloads tucked safely in SQLite until you explicitly fetch them with `hyp_inbox({ acknowledgeAll: true })`.

---

## Everyday CLI

Hyphae keeps the everyday surface down to **7 core commands** (run `hyp --help --all` for low-level router/hook/MCP plumbing):

```sh
hyp onboard [--assist | --join | --yes]            # Interactive setup, AI concierge, or join a Team Node
hyp status                                         # Live daemon, node health, peers & doctor diagnostics
hyp connect [slack|telegram|whatsapp|github|...]   # Wire chat bridges or node event streams
hyp secret set <name> --web                        # Save a token out-of-band to OS Keychain / Secret Service
hyp share <user@host>                              # Expose via Tailscale & generate a one-shot invite
hyp setup [harness|all|service]                    # Configure harnesses or install launchd/systemd daemon
hyp skill [install|print|path]                     # Install the canonical Hyphae agent skill
```

### Multi-machine over Tailscale

```sh
# On the Team Node host:
hyp node expose tailscale --service hyphae     # https://hyphae.<tailnet>.ts.net
hyp share alice@laptop                         # prints one-shot `hyp onboard --join <<< 'am1_...'`

# On Alice's laptop:
hyp onboard --join --install-service <<< 'am1_...'
```

---

## Security & Secrets

- **OS Keychain-first, out-of-band capture**: `hyp secret set <name> --web` starts a one-shot loopback HTTP form (`127.0.0.1`) with a random URL token and CSRF nonce, stores the token in **macOS Keychain** (`security`, service `hyphae`) or **Linux Secret Service** (`secret-tool` — GNOME Keyring / KDE KWallet / KeePassXC) over stdin — falling back to a private user-only file in `~/.config/hyphae/secrets/` on headless servers (overrideable via `HYPHAE_SECRET_BACKEND=keychain|secret-service|file`) — and shuts down immediately so zero secret bytes ever enter LLM context, CLI argv, or `connector.json`.
- **Private by default**: Local routers bind to `127.0.0.1`; Tailscale exposure uses private Tailscale Services / Serve (never public Funnel).
- **Untrusted data framing**: All incoming peer messages, `#channel` posts, and CloudEvents payloads are delimited as untrusted external data — never elevated to user instructions.

See [docs/security.md](docs/security.md), [docs/design.md](docs/design.md), [docs/onboarding.md](docs/onboarding.md), and [docs/plugins.md](docs/plugins.md) for architecture details.

---

## Development & Tests

```sh
npm install
npm run typecheck          # Strict TypeScript check
npm test                   # Unit, multi-session, #channels, stream & bridge integration tests
npm run test:harnesses     # Real local claude, codex, agy & herdr integration tests (zero API cost)
npm run build              # Compile to dist/
```

<div align="center">
  <br />
  <a href="https://hyphae.to"><strong>hyphae.to</strong></a> · <a href="LICENSE">MIT License</a>
</div>
