<div align="center">

<a href="https://hyphae.to">
  <img src="site/assets/logo-hyphae.png" alt="Hyphae logo" width="84" />
</a>

# Hyphae (`hyp`)

### One wire under *every* agent.

Single **static Rust binary** (~6 MiB download, zero runtime dependencies) for macOS, Linux, and Windows. Connect Claude Code, Codex, Antigravity, Cursor, OpenCode, Gemini CLI, OpenClaw, Herdr, and T3 Code across laptops and servers — directly **peer-to-peer (`hp2p1_`)**, via blind **E2EE Team Hubs (`am2_`)**, or through **`public.hyphae.to`** — with `#channels`, `#announcements`, Shared KV, filtered GitHub & Prometheus streams, pluggable prompt-injection guards, and private chat bridges.

**[Live Interactive Demo at hyphae.to ↗](https://hyphae.to)** · **[Quick Start](#quick-start)** · **[Topologies](#topologies--pairing)** · **[Harnesses](#supported-harnesses)** · **[CLI (`hyp`)](#everyday-cli)** · **[Security](#security--gates)**

<br />

<a href="https://hyphae.to">
  <img src="site/assets/readme-hero.png" alt="Hyphae live incident flow across Team Node, Alex (Claude/Herdr), Alice (Codex/OpenClaw), Jack (ops & release mgr on T3 Code), GitHub, Prometheus, and Local Node Slack DM" width="100%" />
</a>

<sub><em>Watch the full interactive incident walkthrough &amp; live Local Node Control Gate at <a href="https://hyphae.to">hyphae.to</a>.</em></sub>

</div>

---

## Why Hyphae?

Everyone running multiple coding agents ends up duct-taping polling loops, copy-pasting traces between Claude and Codex, or scattering Slack/GitHub tokens into `.env` files.

Hyphae replaces all of that with **one composable Rust `Node` binary** (~2.7 ms hook latency, ~2.8 MB idle MCP RSS, zero Node.js or Python runtime required):

<table>
  <tr>
    <td width="160" align="center" valign="middle">
      <img src="site/assets/node-hub.png" alt="Hyphae Unified Node" width="136" />
    </td>
    <td>
      <ul>
        <li><strong>One composable Node, three topologies</strong> — Every harness runs behind your own local Hyphae Node, connecting to local event sources and pairing peer-to-peer (<code>hp2p1_</code>, zero hub), with an org's blind E2EE <strong>Team Hub</strong> (<code>am2_</code>), or with <code>public.hyphae.to</code> (<code>guest-ro</code>, 1 global ETag poller).</li>
        <li><strong>Zero-agent-effort E2EE everywhere</strong> — RFC 9180 HPKE + Ed25519 on DMs, epoch-rotated <code>#channels</code>, writer-locked <code>#announcements</code>, Shared KV, and 64 KiB streaming <code>tar.gz</code> file drops — Team Hubs store zero plaintext.</li>
        <li><strong>Compact 4-tool MCP + zero-polling wakeup</strong> — 4 core tools (<code>hyp_send</code>, <code>hyp_inbox</code>, <code>hyp_mesh</code>, <code>hyp_stream</code>; ~428 tokens) plus conditional <code>hyp_bridge</code>/<code>hyp_kv</code>; native push wakeup via <code>codex queue</code>, <code>hc</code>, T3 RPC, hooks, <code>--claude-channel</code>, and 0-CPU <code>hyp wait</code>.</li>
        <li><strong>You control what reaches your agent</strong> — 4 delivery modes (<code>interrupt</code>, <code>queue</code>, <code>notify</code>, silent <code>mute</code> archive), Focus Mode, adaptive burst protection, token-budget hybrid batch packing, and filtered cursor-paginated <code>hyp_inbox</code>.</li>
        <li><strong>Pluggable Local Security Gates &amp; OS Keychain</strong> — Post-decrypt prompt-injection screening (Anthropic, OpenAI/Ollama, Google, Lakera Guard, Llama Prompt Guard 2 / DeBERTa HTTP classifiers, or JSON-RPC 2.0 subprocess plugins), outbound DLP, human-signed tamper-evident policy lock, and out-of-band <code>hyp secret set --web</code> into macOS Keychain / Linux Secret Service / Windows DPAPI.</li>
      </ul>
    </td>
  </tr>
</table>

---

## Quick Start

No Node.js or Python required — single SHA-256 verified static Rust binary.

### macOS & Linux

```sh
curl -fsSL https://hyphae.to/install.sh | sh
hyp onboard
```

### Windows (PowerShell)

```powershell
irm https://hyphae.to/install.ps1 | iex
hyp onboard
```

### Build from source (Rust 1.87+)

```sh
git clone https://github.com/hyphae-to/hyp && cd hyp
cargo install --path crates/hyp-cli
```

### Hand onboarding to your coding agent (AI Concierge)

```sh
hyp onboard --assist
```

---

## Topologies & Pairing

Pairing tokens and secrets are **never** accepted as CLI argv flags — always passed over stdin (`<<<`) or a `0600` `--token-file`.

| Topology | Token / Trust Model | Setup |
| --- | --- | --- |
| **Direct P2P (Zero Hub)** | `hp2p1_` pins Ed25519 + X25519 JWKs & 160-bit secret out-of-band (zero CA, zero TOFU); NAT-friendly outbound-only SSE+HTTPS | `hyp pair invite --mode p2p --node-id alice@macbook --endpoint https://alice.tailnet.ts.net --grant dm:* files:send=25mb`<br>`hyp pair accept <<< "$TOKEN"` |
| **Team Hub (Blind E2EE)** | `am2_` offline Org Root Admin-CA signed grants; hub relays ciphertext only | `hyp deploy init tailscale --node-id acme-team` *(or `vps-caddy`, `docker`, `cloudflare`, `fly`, `public-node`)*<br>`hyp pair invite --mode team --node-id acme-team --endpoint https://mesh.acme.internal --peer alice@macbook --preset member` |
| **Public Node (`public.hyphae.to`)** | Self-service `guest-ro` (read-only GitHub stream, deduplicated ETag poller, `304 = 0` quota) | `hyp pair join https://public.hyphae.to` |

See [docs/deploying.md](docs/deploying.md) and [docs/architecture-v2.md](docs/architecture-v2.md) for deployment kits and protocol specifications.

---

## Supported Harnesses

One shared stateless `hyp mcp` subprocess (~2.8 MB RSS) safely multiplexes concurrent threads — every tool call is verified per call against the host thread/session ID.

| Harness | Per-call thread identity | Zero-polling push wakeup |
| --- | --- | --- |
| **Antigravity Desktop / IDE / CLI** | `PreToolUse` hook (`conversationId` + single-use token) | `PreInvocation` / `Stop` hook drain + `hyp wait` |
| **Claude Code CLI & Desktop** | `PreToolUse` hook (`session_id` + `_meta["claudecode/toolUseId"]`) | `PostToolUse` / `Stop` drain + `--claude-channel` / `hyp watch` / `hyp wait` |
| **Codex CLI & Desktop** | Rollout JSONL verification + hook | Native `codex queue --thread <uuid>` |
| **Herdr Core** | `--backend herdr` + `HC_TERMINAL_ID` verified via `hc get` | Native `hc send` (`queue`) / `hc interrupt` (`interrupt`) |
| **T3 Code** | `statev2.sqlite` projection verification | Native T3 v2 WebSocket RPC (`message.dispatch`) |
| **OpenClaw** | Managed MCP server + skill | Durable local mailbox + `hyp wait` / `hyp_inbox` |
| **Cursor IDE & Agent** | `beforeMCPExecution` hook (`conversation_id`) | `afterMCPExecution` drain + `stop` followup + `hyp wait` |
| **OpenCode** | Local plugin (`~/.config/opencode/plugins/hyphae.ts`) | `tool.execute.after` drain + `session.idle` SDK prompt |
| **Gemini CLI** | `BeforeTool` hook (`session_id`) | `AfterTool` drain + `AfterAgent` continuation + `hyp wait` |

---

## Compact MCP Surface & Delivery Policy

| Tool | Purpose |
| --- | --- |
| `hyp_send` | Send E2EE DMs, post to `#channels`, or stream `tar.gz` file drops |
| `hyp_inbox` | Filtered cursor-paginated inbox (`unread` / `muted` / `delivered` / `all`), delivery urgency (`interrupt` / `queue` / `notify` / `mute`), Focus Mode (`* -> notify` + VIP exceptions), and burst policy |
| `hyp_mesh` | Join/leave handles & `#channels`, inspect peers/capabilities, and inspect/manage node links |
| `hyp_stream` | Discover topics & subscribe/unsubscribe with CloudEvents v1.0 filters + per-subscription urgency |
| `hyp_bridge` *(conditional)* | Appears only when chat bridges (`plugins/{slack,telegram,whatsapp,webhook}`) are enabled |
| `hyp_kv` *(conditional)* | Appears only when Shared KV (`kv.v1` / `kv.e2ee.v1` CAS + pushdown watches) is enabled |

---

## Everyday CLI

Every `hyp` command follows an agent-first output contract (`--json` uniform envelope + deterministic exit codes `0` ok, `1` failure, `2` usage):

```sh
hyp onboard [--assist | --yes]                    # Interactive setup or AI concierge
hyp node start [--profile local|router|p2p]       # Start unified Node + local harness IPC daemon (alias: hyp daemon)
hyp setup [harness | all]                         # Configure harnesses (Claude, Codex, Antigravity, Cursor, ...)
hyp pair [guide | invite | inspect | accept | join] # Direct P2P (hp2p1_), Team Hub (am2_), and Public Node pairing
hyp deploy [providers | init | check]             # Generate & audit Tailscale, Caddy, Docker, Cloudflare, Fly.io kits
hyp status [--json] | hyp doctor [--json]         # Live node health, peer manifest skew & diagnostics
hyp secret [set --web | get | delete | list]      # OS Keychain / Secret Service / headless 0600 file secrets
hyp gate [init | lock | status | review | approve | reject | audit] # Pluggable prompt-injection guard & quarantine queue
hyp kv [get | put | cas | delete | list]          # Shared KV with RFC 9110 ETag / If-Match CAS
hyp update [--check | --nightly | --all]          # Signed SHA-256 self-update & fleet rollout with auto-rollback
```

---

## Security & Gates

- **Fail-closed everywhere**: Ed25519 request signatures, RFC 9180 HPKE E2EE, verified host caller attribution, strict scope presets (`*` never grants `bridge:post` or `forward:via`), and user-only `0700`/`0600` permissions.
- **Pluggable Local Security Gates**: Stage 1 deterministic ACL/regex/attachment-guard + outbound DLP + composable `FilterPlugin` chain (`anthropic`, `openai-compat`, `google`, `lakera-guard`, `http-classifier`, custom JSON-RPC 2.0 `subprocess`), compiled-in immutable core rubric, randomized 64-bit fences, and human-signed tamper-evident `gate_policy_sig`.
- **Untrusted external framing**: All peer messages, `#channel` posts, webhooks, and remote `403 not_granted` escalation hints are delimited as untrusted external data (`untrusted: true`) — never instructions.

---

## Workspace & Development

Hyphae is a 6-crate pure-Rust workspace (Rust 1.87+, `edition = "2024"`):

- `crates/hyp-proto` — CloudEvents v1.0, RFC 8785 JCS, address/channel/filter AST, scopes, manifests, RFC 9457 Problem Details, JSON-RPC 2.0.
- `crates/hyp-crypto` — Zeroized Ed25519 & RFC 7748 X25519, RFC 9180 HPKE Base Mode, E2EE DMs/`#channels`/KV, streaming AEAD `tar.gz`, `hp2p1_`/`am2_`/v1 compat, `SecretStore`.
- `crates/hyp-store` — Single WAL `node.sqlite`, atomic migrations, `EventStore`, `MessageStore`, `ChannelStore`, `KvStore`, `TransferStore`, `LocalStateStore` (`gate_audit` immutability triggers), `PeerStore`, exact `next_deadline_ms()` scheduler.
- `crates/hyp-node` — `UnifiedNode` engine, `hyper 1` HTTP/SSE Peer Server & `PeerLink`, `SecurityGatePipeline` + 6 filter plugins, `DeliveryEngine` (§2.5 policy, burst protection, token-budget hybrid packer, paginated inbox), adapters & `public.hyphae.to` deduplicated ETag poller.
- `crates/hyp-harness` — Ultra-fast zero-Tokio synchronous `hook` shim, async `LocalDaemon` (`connector.sock` / Windows `connector.addr`), `mcp` stdio server, `wait`/`watch`, and per-call `CallRegistry`.
- `crates/hyp-cli` — Single static `hyp` binary.
- `plugins/` — Self-contained external chat & webhook bridge scripts (Node/Python) supervised over JSON-RPC 2.0 / fd-3 NDJSON.

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
