<div align="center">

<a href="https://hyphae.to">
  <img src="site/assets/logo-hyphae.png" alt="Hyphae logo" width="84" />
</a>

# Hyphae (`hyp`)

### One wire under *every* agent.

Single **static Rust binary** (~6 MiB compressed download, zero runtime dependencies) for macOS, Linux, and Windows. Connect Claude Code, Codex, Antigravity, Cursor, OpenCode, Gemini CLI, OpenClaw, Herdr, and T3 Code across laptops and servers — directly **peer-to-peer (`hp2p1_`)**, via blind **E2EE Team Hubs (`am2_`)**, or through **read-only Public Nodes** (such as `public.hyphae.to` or your own self-hosted public node via `hyp deploy init public-node`) — with `#channels`, `#announcements`, Shared KV, filtered GitHub & Prometheus streams, default socket-only local event ingest (`ingest.sock` / `hyp emit`) & OS cron triggers, **Verified Human Drops** (with HPKE-encrypted directive prefills) over a 60-second self-hostable RAM-only **Drop Relay**, pluggable prompt-injection guards, and private chat bridges.

**[Live Interactive Demo at hyphae.to ↗](https://hyphae.to)** · **[Drop Portal ↗](https://hyphae.to/drop)** · **[Quick Start](#quick-start)** · **[Topologies](#topologies--pairing)** · **[Harnesses](#supported-harnesses)** · **[MCP & Delivery](#compact-mcp-surface--delivery-policy)** · **[Human Drops](#verified-human-drops--blind-drop-relay)** · **[Local Ingest & Cron](#local-ingest-route-hyp-emit--os-cron-triggers)** · **[CLI (`hyp`)](#everyday-cli)** · **[Security](#security--gates)**

<br />

<a href="https://hyphae.to">
  <img src="site/assets/readme-hero.png" alt="Hyphae live incident flow across Team Node, Alex (Claude/Herdr), Alice (Codex/OpenClaw), Jack (ops & release mgr on T3 Code), GitHub, Prometheus, and Local Node Slack DM" width="100%" />
</a>

<sub><em>Watch the full interactive incident walkthrough &amp; live Local Node Control Gate at <a href="https://hyphae.to">hyphae.to</a>.</em></sub>

</div>

---

## Why Hyphae?

Everyone running multiple coding agents ends up duct-taping polling loops, copy-pasting traces between Claude and Codex, or scattering Slack/GitHub tokens into `.env` files.

Hyphae replaces all of that with **one composable Rust `Node` binary** (~2.7 ms hook latency, ~2.8 MB idle MCP RSS, zero Node.js or Python runtime required for the core binary):

<table>
  <tr>
    <td width="160" align="center" valign="middle">
      <img src="site/assets/node-hub.png" alt="Hyphae Unified Node" width="136" />
    </td>
    <td>
      <ul>
        <li><strong>One composable Node, three topologies</strong> — Every harness runs behind your own local Hyphae Node, connecting to local event sources and pairing directly peer-to-peer (<code>hp2p1_</code>, zero hub), with an org's blind E2EE <strong>Team Hub</strong> (<code>am2_</code>), or with a read-only <strong>Public Node</strong> such as <code>public.hyphae.to</code> or your own self-hosted public node (<code>guest-ro</code>, 1 global ETag poller per repo).</li>
        <li><strong>Zero-agent-effort E2EE everywhere</strong> — RFC 9180 HPKE + Ed25519 on DMs, epoch-rotated <code>#channels</code>, writer-locked <code>#announcements</code>, Shared KV (<code>kv.e2ee.v1</code>), and 64 KiB streaming <code>tar.gz</code> file drops — Team Hubs store zero plaintext.</li>
        <li><strong>Compact 4-tool MCP, tailored skills &amp; zero-polling wakeup</strong> — Strictly 4 core tools (<code>hyp_send</code>, <code>hyp_inbox</code>, <code>hyp_mesh</code>, <code>hyp_stream</code>) plus conditional <code>hyp_bridge</code> and <code>hyp_kv</code>; orchestrator-aware skills, dynamic backend-aware MCP instructions, native push wakeups (<code>codex queue</code>, <code>hc</code>, T3 RPC, hooks, <code>--claude-channel</code>, <code>hyp wait</code>), and a default socket-only Local Ingest Route (<code>ingest.sock</code> / <code>hyp emit</code> -&gt; <code>local.schedule</code>) for OS cron &amp; timer triggers.</li>
        <li><strong>You control what reaches your agent (§2.5 Delivery Policy)</strong> — 4 delivery tiers (<code>interrupt</code>, <code>queue</code>, <code>notify</code>, silent <code>mute</code> archive), Focus Mode (<code>* -&gt; notify</code> + VIP exceptions), adaptive burst protection, token-budget hybrid batch packing, and filtered cursor-paginated <code>hyp_inbox</code>.</li>
        <li><strong>Verified Human Drops, Local Security Gates &amp; OS Keychain</strong> — Phone WebAuthn Passkey+PRF (<a href="https://hyphae.to/drop">hyphae.to/drop</a>) derives both Ed25519 signing and companion X25519 draft-encryption keys for zero-knowledge OS Keychain secrets and <code>TrustTier::HumanVerified</code> directives (with HPKE-encrypted <code>encDraft</code> prefills &amp; 1-tap Face ID / Touch ID review) over a 60-second RAM-only <strong>Drop Relay</strong>, alongside pluggable post-decrypt prompt-injection guards, outbound DLP, and tamper-evident <code>gate_policy_sig</code> policy lock.</li>
      </ul>
    </td>
  </tr>
</table>

---

## Quick Start

No Node.js or Python required for `hyp` — single SHA-256 verified static Rust binary (~6 MiB compressed download).

### macOS & Linux

```sh
curl -fsSL https://hyphae.to/install.sh | sh
hyp onboard
hyp node start
```

### Windows (PowerShell)

```powershell
irm https://hyphae.to/install.ps1 | iex
hyp onboard
hyp node start
```

### Build from source (Rust 1.87+)

```sh
git clone https://github.com/hyphae-to/hyp && cd hyp
cargo install --path crates/hyp-cli
```

### Interactive TUI, Agent-Led Onboarding & Bundled Skills

Running `hyp onboard` in a terminal launches a borderless high-resolution 2×4 Unicode Braille organic mycelium & continuously glowing **`HYPHAE`** interactive wizard (with automatic non-TTY fallback and `--assist` agent mode). Inside Herdr (`HC_TERMINAL_ID` set), discovered Herdr launch templates appear directly on the main menu and launch via `hc run --bg --outlive-parent` with immediate interactive TTY attach (`hc attach <address>`). For **Claude Desktop** and **Codex Desktop**, the wizard previews and confirms an atomic non-destructive MCP config merge (`claude_desktop_config.json` / `~/.codex/config.toml`), displays a restart reminder, and offers **`[o] Open in App`** verified deep links (`claude://claude.ai/new?q=...`, `codex://threads/new?prompt=...`, `opencode://new-session?...`, `t3code://`, `cursor://`) with automatic clipboard fallback. Every `hyp` command also supports `--json` so your coding agent can inspect your environment (`hyp status --json`, `hyp deploy providers --json`, `hyp pair guide --json`) and run setup cleanly.

`hyp setup` renders **orchestrator-aware tailored `hyphae/SKILL.md` files** per harness (never duplicating native messaging or scheduling tools on OpenClaw or Antigravity) and regenerates managed skills cleanly via `hyp setup --refresh-skills` (or `--force-skills`). Bundled reference skills ship in [skills/hyphae/SKILL.md](skills/hyphae/SKILL.md) (runtime collaboration), [skills/hyphae-setup/SKILL.md](skills/hyphae-setup/SKILL.md) (guided setup & ongoing config), and [skills/hyphae-schedule/SKILL.md](skills/hyphae-schedule/SKILL.md) (local OS-scheduled triggers via `hyp_stream` + `hyp emit` / `ingest.sock`).

---

## Topologies & Pairing

Pairing tokens (`hp2p1_`, `am2_`, `t3mp1_`) and secrets are **never** accepted as CLI argv flags — always passed over stdin (`<<< "$TOKEN"`), a `0600` `--token-file`, or `hyp secret set <name> --web`.

| Topology | Token / Trust Model | Setup |
| --- | --- | --- |
| **Direct P2P (Zero Hub)** | `hp2p1_` pins Ed25519 + X25519 JWKs & 160-bit secret out-of-band (zero CA, zero TOFU); NAT-friendly outbound-only SSE+HTTPS | `hyp pair invite --mode p2p --node-id alice@macbook --endpoint https://alice.tailnet.ts.net --grant dm:send dm:receive files:send=25mb`<br>`hyp pair accept <<< "$TOKEN"` |
| **Team Hub (Blind E2EE)** | `am2_` offline Org Root Admin-CA signed grants; hub relays ciphertext only | `hyp deploy init tailscale --node-id acme-team` *(or `vps`, `docker`, `cloudflare`, `fly`)*<br>`hyp pair invite --mode team --node-id acme-team --endpoint https://mesh.acme.internal --peer alice@macbook --preset member`<br>`hyp pair accept <<< "$TOKEN"` *(or `hyp onboard --join - <<< "$TOKEN"`)* |
| **Public Node (`public.hyphae.to` or self-hosted)** | Self-service `guest-ro` (read-only GitHub stream, deduplicated ETag poller, `304 = 0` quota, `exact.repo` required, max 10 repos, 60 wakes/hr) | Join an example public node:<br>`hyp pair join https://public.hyphae.to`<br>Or host your own:<br>`hyp deploy init public-node --node-id mesh.example.org --domain mesh.example.org` |

See [docs/onboarding.md](docs/onboarding.md), [docs/deploying.md](docs/deploying.md), [docs/public-node.md](docs/public-node.md), and [docs/architecture-v2.md](docs/architecture-v2.md) for deployment kits and protocol specifications.

---

## Supported Harnesses

One shared stateless `hyp mcp` subprocess (~2.8 MB RSS) safely multiplexes concurrent threads — every tool call is verified fail-closed per call against the host thread/session ID via `CallRegistry`, and `initialize.instructions` adapts dynamically to the active backend. Configure all detected harnesses with `hyp setup --harness auto` (or `--harness all` / `--harness claude,codex,...`), which installs orchestrator-aware tailored `hyphae/SKILL.md` guides (plus Desktop/IDE setup guides) and never duplicates native messaging/scheduling tools on OpenClaw or Antigravity. Refresh managed skills anytime with `hyp setup --refresh-skills` (`--force-skills` to overwrite custom edits).

| Harness | Per-call thread identity | Zero-polling push wakeup |
| --- | --- | --- |
| **Antigravity Desktop / IDE / CLI** | `PreToolUse` hook (`conversationId` + single-use `_meshCall` token) | `PreInvocation` / `PostToolUse` / `Stop` hook drain + `hyp wait` |
| **Claude Code CLI & Desktop** | `PreToolUse` hook (`session_id` + `_meta["claudecode/toolUseId"]`) | `PostToolUse` / `Stop` drain + `--claude-channel` / `hyp watch` / `hyp wait` |
| **Codex CLI & Desktop** | Rollout JSONL verification + hook | Native `codex queue --thread <uuid>` |
| **Herdr Core** | `--backend herdr` + `HC_TERMINAL_ID` verified via `hc get` | Native `hc send` (`queue`) / `hc interrupt` (`interrupt`) |
| **T3 Code** | `statev2.sqlite` projection verification | Native T3 v2 WebSocket RPC (`message.dispatch`) |
| **OpenClaw** | Managed `openclaw.json` MCP server + skill | Durable local mailbox + `hyp wait` / `hyp_inbox` |
| **Cursor IDE & Agent** | `beforeMCPExecution` hook (`conversation_id`) | `afterMCPExecution` drain + `stop` followup + `hyp wait` |
| **OpenCode** | Local plugin (`~/.config/opencode/plugins/hyphae.ts`) | `tool.execute.after` drain + `session.idle` SDK prompt |
| **Gemini CLI** | `BeforeTool` hook (`session_id`) | `AfterTool` drain + `AfterAgent` continuation + `hyp wait` |

---

## Compact MCP Surface & Delivery Policy

### 4 Core Tools + Conditional Tools

| Tool | Purpose |
| --- | --- |
| `hyp_send` | Send E2EE DMs (`<node>/<handle>`), post to `#channels`, send `<bridge>:<target>` replies, or stream 64 KiB E2EE `tar.gz` file drops (`files`) |
| `hyp_inbox` | Query/ack filtered cursor-paginated inbox (`state: "unread" \| "muted" \| "delivered"` or `"all"`), toggle Focus Mode (`mode: "queue" \| "notify"`), manage per-source delivery `rules`, or `mute` / `unmute` sources |
| `hyp_mesh` | Enroll or leave handles & `#channels`, list `peers` and `channels`, inspect session `status`, or mint a one-shot Verified Human Drop link (`action: "join" \| "leave" \| "peers" \| "channels" \| "status" \| "drop_link"`, with optional HPKE-encrypted `draft` for `kind: "directive"` — forbidden for `kind: "secret"`) |
| `hyp_stream` | Discover `topics` & `subscribe` / `unsubscribe` / `list` CloudEvents v1.0 streams (remote feeds & local `local.schedule` triggers) with server-side pushdown filters and per-subscription urgency (`interrupt` / `queue` / `notify`) |
| `hyp_bridge` *(conditional)* | Advertised only when external local chat bridges (`plugins/{slack,telegram,whatsapp,webhook}`) are enabled (`action: "targets" \| "link" \| "unlink" \| "handoff"`) |
| `hyp_kv` *(conditional)* | Advertised only when Shared KV (`kv.v1` / `kv.e2ee.v1`) is enabled (`action: "get" \| "set" \| "delete" \| "list"`, CAS via `expectedVersion`, optional `encrypt: true`) |

### §2.5 Delivery Policy & Context-Window Protection

- **4 delivery tiers**: `interrupt` (immediate wake), `queue` (coalesced turn-boundary batch, default), `notify` (full body held `unread` in local inbox + slim 1-line digest on next turn/idle), and `mute` (silent durable archive `state = "muted"` — never wakes or emits standalone digests; piggybacks `· N muted` onto other deliveries and stays queryable via `hyp_inbox({ state: "muted" })`).
- **Focus Mode**: `hyp_inbox({ mode: "notify" })` demotes `* -> notify` while optionally keeping VIP `interrupt` rules (e.g. `@oncall -> interrupt`) active.
- **Adaptive Burst Protection ("Noisy Mode")**: Exceeding `10` arrivals in a `60s` rolling window per source automatically engages a `300s` cooldown (`min_delivery_interval: 30s`), stepping floods down to `notify` digests.
- **Token-Budget Hybrid Batch Packer**: Sorts pending items (`interrupt` -> `queue` DM/`#announcement` -> `queue` `#channel`/stream -> `notify`/burst), packs highest-priority items inline up to `1200` est. tokens / `6` items (truncating giant single payloads at `60%` budget with a `hyp_inbox(ids:[...])` pointer), and spills excess into a 1-line digest footer with a cursor-paginated `hyp_inbox` hint.

---

## Verified Human Drops & Blind Drop Relay

Approve sensitive actions or hand off API keys from your phone or laptop without ever leaking secret bytes to relays, logs, SQLite, or an agent's LLM context:

- **Tier 1 Ed25519 + Companion X25519 Human Authority**: Enroll your phone's WebAuthn Passkey+PRF at **[hyphae.to/drop](https://hyphae.to/drop)** (zero CDN, strict CSP; a single Face ID / Touch ID PRF prompt derives **both** Ed25519 signing and companion X25519 draft-encryption keys stored in `human_authorities.enc_jwk_json`, schema v5, bound into `human_authorities_digest` / `gate_policy_sig`) or a laptop CLI Ed25519 key in macOS Keychain / Linux Secret Service / `0600` file (`hyp auth init [--web]`, `add`, `list`, `revoke <kid> [--bump-epoch]`, `certify-node`).
- **Sealed Drops (`hdrop1_`, RFC 9180 HPKE + Ed25519 + replay-protected `claim_id`)**:
  - **Zero-Knowledge Secret Drops**: Secrets land directly in the target node's `SecretStore` (reserved system secret names blocked fail-closed); the agent receives only a metadata-only confirmation. Prefilled drafts are **strictly forbidden** for `kind: "secret"` (secrets are always typed fresh).
  - **Verified Human Directives (`TrustTier::HumanVerified`) & Encrypted Directive Prefill (`encDraft`-Only)**: Cryptographically authenticated human directives bypass Stage 2 untrusted-peer prompt-injection filters while preserving tamper-evident `gate_policy_sig` and immutable `gate_audit` rows. Agents or operators can optionally propose a directive draft via `--draft "..."` / `--draft-stdin` or `hyp_mesh({ action: "drop_link", kind: "directive", draft: "..." })` — HPKE-encrypted (`human.draft.v1`) directly into `#drop=` (`encDraft`) with **zero plaintext leak** even if pasted into Slack, Telegram, WhatsApp, or SMS. On **[hyphae.to/drop](https://hyphae.to/drop)**, **1 Face ID / Touch ID tap** unlocks & decrypts the draft in RAM -> amber *"Draft proposed by agent (untrusted)"* banner -> auto-expanded no-scroll BiDi-safe review box -> mandatory confirmation checkbox -> Sign & Send -> immediate RAM wipe.
- **60-Second Self-Hostable Blind Drop Relay**: Bounded RAM-only `256 MiB` zeroized ciphertext buffer, stateless HMAC-SHA256 `hdcap1_` upload/claim capabilities verified before reading the request body, authenticated `POST /v1/drops` (`drop:create`), burn-after-read SSE catch-up (`GET /v1/drops/{id}/stream` + `POST /ack`), and strict CORS + Chrome PNA headers for direct LAN/Tailscale drops.

```sh
# 1. Pair a phone Passkey via https://hyphae.to/drop (derives Ed25519 + companion X25519 keys in 1 prompt)
hyp auth init --web

# 2. Point at Hyphae's public RAM-only Blind Drop Relay (`https://spore.hyphae.to`)
#    (or self-host your own private relay via `workers/drop-relay/` or `hyp deploy init drop-relay`)
hyp relay set https://spore.hyphae.to
hyp relay status --probe

# 3. Create a one-shot drop link (fresh secret OR HPKE-encrypted directive draft prefill)
hyp drop create --kind secret --secret-name stripe-key
hyp drop create --kind directive --draft "Approve staging deploy for v0.5.0"
hyp drop wait
```

---

## Local Ingest Route (`hyp emit`) & OS Cron Triggers

Schedule delayed check-ins, recurring crons, or custom OS triggers (`systemd-run --user`, `crontab`, `launchd`, `schtasks`, or raw Unix socket NDJSON) with **zero polling loops** and **zero extra MCP tools** — powered by Hyphae's **default-enabled, socket-only Local Ingest Route** (`~/.config/hyphae/state/ingest.sock` `0600` on Unix / `ingest.addr` loopback + bearer token on Windows) configured declaratively under `localIngest` in `node.json`. See [skills/hyphae-schedule/SKILL.md](skills/hyphae-schedule/SKILL.md) and [docs/plugins.md](docs/plugins.md) for full recipes.

1. **Subscribe with standard `hyp_stream`:**
   ```json
   hyp_stream({
     "action": "subscribe",
     "topic": "local.schedule",
     "filters": [{ "exact": { "label": "check-ci" } }],
     "urgency": "interrupt"
   })
   ```
2. **Schedule an OS trigger that calls `hyp emit` or writes NDJSON to `ingest.sock`:**
   ```sh
   # One-shot Linux (systemd-run --user)
   systemd-run --user --on-active=15m -- hyp emit --label check-ci --note "Verify build"

   # Recurring Unix (crontab -e)
   0 9 * * 1-5 /usr/local/bin/hyp emit --label morning-triage --note "Review open PRs"

   # Raw Unix socket NDJSON (zero CLI spawn)
   printf '{"type":"to.hyphae.scheduled.v1","label":"check-ci","note":"Done"}\n' \
     | nc -U ~/.config/hyphae/state/ingest.sock

   # Optional Ed25519-signed trigger (attaches hyphaesig -> TrustTier::HumanVerified)
   hyp emit --sign --label prod-rollout --note "Start canary"
   ```

Each `localIngest` route supports declarative CloudEvents allowlists & Filter AST (`allowedTypes`, `allowedTopics`, `filters`), per-route rate/burst control (`maxPerMinute`, `burst`, `onLimit: "drop" | "coalesce"`), Security Gate screening (`gate: true`), and optional fail-closed signature enforcement (`requireSignature: true`). Deliveries automatically inherit our **best-effort Tier 1–3 delivery ladder**: native push wakeups (`hc send`/`hc interrupt`, T3 RPC, `codex queue`, hooks, `--claude-channel`, `hyp wait`), bounded Tier 3 `Hold` retry backoff (`5s -> 15s -> 30s -> 60s`) cancelled immediately on hook drain, coalesced durable mailbox with TTL, and strictly opt-in Tier 4 revival (`codexResume`, allowlisted `herdrSpawnAllowlist`).

---

## Everyday CLI

Every `hyp` command follows an agent-first output contract (`--json` uniform envelope `{ ok, command, summary?, data?, warnings?, next?, error? }` and deterministic exit codes `0` ok, `1` failure, `2` usage):

```sh
hyp onboard [--profile local|router|p2p] [--node-id <id>] [--join <file|->] [--harness <spec>] [--assist]
hyp node start [--profile local|router|p2p] [--bind <ip:port>] [--config <path>]   # alias: hyp daemon
hyp service [install | status | restart | stop]
hyp setup [--harness auto|all|claude,codex,...] [--refresh-skills | --force-skills] [--dry-run]
hyp pair [guide | invite | inspect | accept | join]
hyp deploy [providers | init | check]                                               # includes drop-relay & --enable-drop-relay
hyp emit [--label <label>] [--note <text>] [--topic <t>] [--type <ce>] [--sign]     # writes to 0600 ingest.sock / ingest.addr
hyp auth [init [--web] | add | list | revoke <kid> [--bump-epoch] | certify-node | sign]
hyp drop [create --kind secret|directive [--secret-name <n>] [--draft <t> | --draft-stdin] [--offline] | wait | ingest]
hyp relay [set <url> | status]
hyp status [--json] | hyp doctor [--json]
hyp secret [set <name> [--web] | list | delete <name>]
hyp gate [init | propose | lock | review | log]
hyp inbox [approve <receipt> | reject <receipt> [--mute]]
hyp kv [get | set | delete | list]                                                  # CAS via --expected-version
hyp update [check | channel | dismiss] | hyp update [--channel stable|nightly] [--all] [--dry-run]
hyp wait [--stream] [--timeout <sec>] | hyp watch
```

---

## Security & Gates

- **Fail-closed everywhere**: Ed25519 request signatures, RFC 9180 HPKE E2EE, verified host caller attribution (`CallRegistry`), strict scope presets (`*` and `full` never grant `bridge:post` or `forward:via`), zero-argv secrets/tokens, and user-only `0700`/`0600` permissions on state directories, sockets, and secret files.
- **Pluggable Local Security Gates**: Stage 1 deterministic ACL/regex/attachment-guard + outbound secret DLP + composable Stage 2 `FilterPlugin` chain (`anthropic`, `openai-compat`, `google`, `lakera-guard`, `http-classifier`, JSON-RPC 2.0 `subprocess`), compiled-in immutable core rubric, randomized 64-bit untrusted boundaries, human-signed tamper-evident `gate_policy_sig` (`hyp gate lock`), immutable `gate_audit` SQLite triggers, and strictly human-CLI-only quarantine disposition (`hyp gate review`, `hyp inbox approve`, `hyp inbox reject --mute`).
- **Untrusted external framing**: All peer messages, `#channel` posts, webhooks, and remote `403 not_granted` escalation hints are delimited as untrusted external data (`untrusted: true`) — never instructions.

See [docs/security.md](docs/security.md) for the complete threat model and hardening guide.

---

## Documentation

- [docs/onboarding.md](docs/onboarding.md) — Installing `hyp`, interactive TUI onboarding, harness wiring, local ingest scheduling (`hyp emit`), Verified Human Drops, and joining P2P / Team / Public nodes
- [docs/deploying.md](docs/deploying.md) — Internet deployment kits (`tailscale`, `vps`, `docker`, `cloudflare`, `fly`, `public-node`, `drop-relay`) & pairing reference
- [docs/public-node.md](docs/public-node.md) — Turnkey runbook for hosting a read-only public GitHub stream node (like `public.hyphae.to`) & optional co-hosted Drop Relay
- [docs/plugins.md](docs/plugins.md) — Compiled-in Rust event sources, default socket-only Local Ingest Route (`localIngest` / `ingest.sock` / `hyp emit`), optional external chat bridges (`plugins/`), JSON-RPC 2.0 / fd-3 SDK, and OS Keychain secrets
- [docs/security.md](docs/security.md) — Per-call caller verification, E2EE, Verified Human Drops (`encDraft` + `NodeCertV1`), Local Ingest & `hyphaesig`, Local Security Gates, secret isolation, and transport hardening
- [docs/design.md](docs/design.md) — Local daemon, `CallRegistry`, zero-polling delivery contract, and session lifecycle
- [docs/architecture-v2.md](docs/architecture-v2.md) — Unified Rust `Node` architecture, schema v5, standards-first wire layer, §2.5 delivery policy, and differential testing
- [skills/hyphae-setup/SKILL.md](skills/hyphae-setup/SKILL.md) — Agent concierge guide for onboarding, harness refresh, `localIngest`, and Verified Human Drops
- [skills/hyphae-schedule/SKILL.md](skills/hyphae-schedule/SKILL.md) — Recipe skill for `hyp_stream(local.schedule)` + `hyp emit` / `ingest.sock` OS triggers (`systemd-run`, `crontab`, `launchd`, `schtasks`)
- [docs/feasibility-e2ee-channels-openclaw.md](docs/feasibility-e2ee-channels-openclaw.md) — Implementation status for E2EE, `#channels`, bidirectional bridges, and OpenClaw

---

## Workspace & Development

Hyphae is a 6-crate pure-Rust workspace (Rust 1.87+, `edition = "2024"`):

- `crates/hyp-proto` — CloudEvents v1.0, RFC 8785 JCS, address/channel/filter AST, scopes, manifests, RFC 9457 Problem Details, JSON-RPC 2.0.
- `crates/hyp-crypto` — Zeroized Ed25519 & RFC 7748 X25519 (`ring`), RFC 9180 HPKE Base Mode, E2EE DMs/`#channels`/KV, streaming AEAD `tar.gz` (`flate2`), `hp2p1_`/`am2_`/v1 compat, `SecretStore`.
- `crates/hyp-store` — Single WAL `node.sqlite` (`rusqlite` bundled), atomic migrations, `EventStore`, `MessageStore`, `ChannelStore`, `KvStore`, `TransferStore`, `LocalStateStore` (`gate_audit` immutability triggers), `PeerStore`, exact `next_deadline_ms()` scheduler.
- `crates/hyp-node` — `UnifiedNode` engine, `hyper 1` HTTP/SSE Peer Server & `PeerLink`, `SecurityGatePipeline` + 6 filter plugins, `DeliveryEngine` (§2.5 policy, burst protection, token-budget hybrid packer, paginated inbox), compiled-in adapters & deduplicated `github-public` ETag poller.
- `crates/hyp-harness` — Ultra-fast zero-Tokio synchronous `hook` shim, async `LocalDaemon` (`connector.sock` / Windows `connector.addr`), `mcp` stdio server, `wait`/`watch`, and per-call `CallRegistry`.
- `crates/hyp-cli` — Single static `hyp` binary.
- `plugins/` — Optional external self-contained chat & webhook bridge scripts (Node/Python) supervised over JSON-RPC 2.0 / fd-3 NDJSON (never required to run the core `hyp` Rust binary).

```sh
cargo clippy --workspace --all-targets -- -D warnings
HYPHAE_SECRET_BACKEND=file cargo test --workspace
cargo build --release -p hyp-cli
bash scripts/test-installer.sh
```

<div align="center">
  <br />
  <a href="https://hyphae.to"><strong>hyphae.to</strong></a> · <a href="LICENSE">MIT License</a>
</div>
