# Onboarding Guide

Hyphae (`hyp`) ships as a **single static Rust binary** (~8 MiB compressed download, ~2.7 ms hooks, ~2.8 MB idle MCP RSS, zero Node.js or Python runtime required for the core binary) and supports three composable topologies with the exact same `Node` binary:

1. **Local Multi-Harness Node (`profile: "local"`)** — connects all coding agents on one workstation across Antigravity, Claude Code / Desktop, Codex / Desktop, Cursor, OpenCode, Gemini CLI, OpenClaw, Herdr Core, and T3 Code.
2. **Direct P2P Collaborator Mesh (`profile: "p2p"`, `hp2p1_`)** — direct mutual E2EE pairing between two laptops or servers with **zero** central hub or CA.
3. **Team Hub (`profile: "router"`, `am2_`) & Read-Only Public Nodes (`guest-ro`)** — blind E2EE hub-and-spoke federation for teams, plus one-command read-only subscriptions to public GitHub stream nodes (such as `public.hyphae.to` or your own self-hosted public node via `hyp deploy init public-node`).

---

## 1. Install `hyp`

### macOS & Linux

```sh
curl -fsSL https://hyphae.to/install.sh | sh
```

### Windows (PowerShell)

```powershell
irm https://hyphae.to/install.ps1 | iex
```

### Build from source (Rust 1.87+)

```sh
git clone https://github.com/hyphae-to/hyp && cd hyp
cargo install --path crates/hyp-cli
```

---

## 2. Bootstrap Your Local Node

Run `hyp onboard` in an interactive terminal to launch the borderless high-resolution 2×4 Unicode Braille organic mycelium & continuously glowing **`HYPHAE`** interactive onboarding TUI wizard (automatically falling back to prompts/flags on non-TTY pipes, or pass `--assist` to let your coding agent run setup):
- **Inside Herdr (`HC_TERMINAL_ID` set)**: discovered Herdr launch templates appear directly on the main menu; launching any template runs `hc run --bg --outlive-parent` and immediately attaches your interactive TTY (`hc attach <address>`).
- **Claude Desktop & Codex Desktop**: previews and confirms an atomic non-destructive MCP config merge (`claude_desktop_config.json` / `~/.codex/config.toml`), shows a restart reminder, and offers **`[o] Open in App`** verified deep links (`claude://claude.ai/new?q=...`, `codex://threads/new?prompt=...`, `opencode://new-session?...`, `t3code://`, `cursor://`) with automatic clipboard fallback.

To bootstrap non-interactively in one command:

```sh
hyp onboard --profile local --node-id alice@macbook --harness auto
```

What `hyp onboard` sets up:
- **Persistent cryptographic identity**: Generates Ed25519 signing and X25519 encryption keypairs in your OS secret store (macOS Keychain via `/usr/bin/security`, Linux Secret Service via `secret-tool`, or `0600` files in `~/.config/hyphae/secrets/` on headless servers and Windows; overrideable with `HYPHAE_SECRET_BACKEND=keychain|secret-service|file`).
- **Unified config & state**: Writes `~/.config/hyphae/node.json` (`0600`) and initializes `~/.config/hyphae/node.sqlite`. *(Existing legacy `connector.json` configs are also read transparently.)*
- **Orchestrator-aware harness wiring & tailored skills**: Points detected harnesses directly to the static `hyp` binary (no cached Node/NVM paths that break on upgrades) and renders tailored `hyphae/SKILL.md` files per harness (plus Desktop/IDE guides) so OpenClaw and Antigravity never receive duplicate messaging/scheduling instructions.

You can inspect, wire, or refresh managed skills independently at any time:

```sh
# Preview planned harness changes without touching disk
hyp setup --harness auto --dry-run

# Configure specific harnesses or all 9 harnesses
hyp setup --harness claude,codex,antigravity
hyp setup --harness all

# Regenerate managed orchestrator-aware skills after an upgrade (use --force-skills to overwrite local edits)
hyp setup --refresh-skills
```

Install the persistent background daemon service (macOS LaunchAgent / Linux `systemd --user`) or run in the foreground:

```sh
hyp service install
hyp service status

# Or run foreground directly (containers / Windows / debugging):
hyp node start
# Alias: hyp daemon
```

Restart any open Desktop app once so it loads the updated MCP entry and hooks, then check health:

```sh
hyp status
hyp doctor
# Structured agent-first output:
hyp doctor --json
```

### Agent-Led Onboarding

Prefer having your coding agent guide setup? Run `hyp onboard --assist` or load [skills/hyphae-setup/SKILL.md](../skills/hyphae-setup/SKILL.md). Every CLI command supports `--json` so agents can inspect your environment (`hyp status --json`, `hyp deploy providers --json`, `hyp pair guide --json`) and capture credentials strictly out-of-band via `hyp secret set <name> --web`.

---

## 3. Connect Topologies (Stdin / `--token-file` Only)

> **Security invariant:** `hyp` **never** accepts raw pairing tokens (`hp2p1_`, `am2_`, `t3mp1_`) or secrets as CLI argv flags (where they leak to `ps` and shell history). Always pass tokens via stdin (`<<< "$TOKEN"`) or a `0600` `--token-file`.

### A. Direct P2P Pairing (`hp2p1_`, Zero Hub)

1. **Inviter** exposes their Node behind Tailscale Serve (or any HTTPS reverse proxy; see [docs/deploying.md](deploying.md)) and mints a one-shot mutual offer:
   ```sh
   hyp pair invite \
     --mode p2p \
     --node-id alice@macbook \
     --endpoint https://alice.tailnet.ts.net \
     --grant dm:send dm:receive files:send=25mb \
     --request kv:read=pair/*
   ```
2. **Accepter** inspects the offer (verifying JWK `kid` thumbprint, scopes, and expiry) and accepts over stdin:
   ```sh
   hyp pair inspect <<< "$TOKEN"
   hyp pair accept <<< "$TOKEN"
   ```
   Only **one** peer needs a reachable HTTPS endpoint — a peer behind strict NAT maintains an outbound-only HTTPS+SSE link carrying bidirectional traffic.

### B. Team Hub (`am2_`, Blind E2EE Org Admin-CA)

1. **Deploy the Team Hub** using any of the 7 hardened deployment kits (`tailscale`, `vps`, `docker`, `cloudflare`, `fly`, `public-node`, `drop-relay`) documented in [docs/deploying.md](deploying.md):
   ```sh
   hyp deploy init tailscale \
     --node-id acme-team \
     --domain hyphae.your-tailnet.ts.net \
     --out ./deploy-tailscale

   hyp deploy check --config ./deploy-tailscale/node.json
   ```
2. **Issue a per-member Admin-CA invite** (the offline Admin-CA signing key stays on the admin machine, never on the hub):
   ```sh
   hyp pair invite \
     --mode team \
     --node-id acme-team \
     --endpoint https://hyphae.your-tailnet.ts.net \
     --peer alice@macbook \
     --preset member
   ```
3. **Accept on each member workstation** (either during initial onboarding or on an existing node):
   ```sh
   # Existing node:
   hyp pair accept <<< "$TOKEN"

   # Or during first-time bootstrap (stages token in SecretStore, never plaintext in node.json):
   hyp onboard --node-id alice@macbook --join - <<< "$TOKEN"
   ```

### C. Public Read-Only Node (`guest-ro`)

Join an example hosted public node such as `public.hyphae.to` — or any self-hosted public read-only GitHub stream node — in one command:

```sh
hyp pair join https://public.hyphae.to
```

Want to host your own public read-only GitHub stream node for your organization or open-source community? Generate a turnkey kit with `hyp deploy init public-node` and follow [docs/public-node.md](public-node.md).

---

## 4. Secrets & Optional Local Security Gate

Store API keys and webhook secrets out-of-band so zero secret bytes enter LLM chat context or shell history:

```sh
# Opens a one-shot 127.0.0.1 CSRF-protected browser form -> OS Keychain / Secret Service / 0600 file
hyp secret set anthropic-api-key --web

# Or pipe via stdin on headless hosts
printf '%s' "$API_KEY" | hyp secret set anthropic-api-key

# Inspect stored secret metadata (never prints secret values)
hyp secret list
```

Reference secrets in `~/.config/hyphae/node.json` strictly as `{ "secret": "<name>" }`.

To enable post-decrypt prompt-injection screening and tamper-evident policy signing on inbound peer/webhook traffic:

```sh
hyp gate init --adapter anthropic --secret anthropic-api-key --lock
# Or with a custom Anthropic-compatible gateway/proxy URL:
hyp gate init --adapter anthropic --base-url https://ai-gateway.company.internal --secret company-anthropic-token --lock
hyp doctor
```

---

## 5. Local Ingest Scheduling (`hyp emit`) & Verified Human Drops

### A. Schedule Local Wakeups via `ingest.sock` / `hyp emit` & `hyp_stream`

Hyphae's **socket-only Local Ingest Route** (`~/.config/hyphae/state/ingest.sock` `0600` on Unix / `<state_dir>/ingest.addr` loopback TCP + constant-time bearer token on Windows) is **enabled by default** under `localIngest` in `node.json` — zero extra MCP tools and zero separate enable command required:

1. **Subscribe with standard `hyp_stream`:**
   ```json
   hyp_stream({
     "action": "subscribe",
     "topic": "local.schedule",
     "filters": [{ "exact": { "label": "check-ci" } }],
     "urgency": "interrupt"
   })
   ```
2. **Schedule an OS trigger calling `hyp emit` (or writing NDJSON directly to `ingest.sock`):**
   ```sh
   # One-shot Linux timer
   systemd-run --user --on-active=15m -- hyp emit --label check-ci --note "Verify build"

   # Recurring cron (crontab -e)
   # 0 9 * * 1-5 /usr/local/bin/hyp emit --label morning-triage --note "Review open PRs"

   # Raw Unix socket NDJSON
   printf '{"type":"to.hyphae.scheduled.v1","label":"check-ci","note":"Done"}\n' \
     | nc -U ~/.config/hyphae/state/ingest.sock

   # Optional signed high-trust trigger (attaches Ed25519 hyphaesig -> TrustTier::HumanVerified)
   hyp emit --sign --label prod-rollout --note "Start canary"
   ```

See [skills/hyphae-schedule/SKILL.md](../skills/hyphae-schedule/SKILL.md) and [docs/plugins.md](plugins.md) for macOS `launchd` / Windows `schtasks` recipes, declarative `localIngest` route policy (`allowedTypes`, `allowedTopics`, `filters`, `maxPerMinute`, `burst`, `onLimit`, `gate`, `requireSignature`), and the Tier 1–3 delivery ladder + opt-in Tier 4 revival.

### B. Enroll a Phone Passkey & Configure a Drop Relay

Verified Human Drops let you send zero-knowledge OS Keychain secrets and `TrustTier::HumanVerified` directives straight from your phone (`https://hyphae.to/drop`) or laptop CLI:

```sh
# 1. Pair your phone's WebAuthn Passkey+PRF — 1 prompt derives BOTH Ed25519 signing
#    and companion X25519 draft-encryption keys (`enc_jwk_json`, schema v5)
#    (omit --web for a local CLI Ed25519 key in Keychain)
hyp auth init --web
hyp auth list

# 2. Point your node at Hyphae's public RAM-only Drop Relay (`https://spore.hyphae.to`)
#    or your own private relay (`workers/drop-relay/` / `hyp deploy init drop-relay`)
hyp relay set https://spore.hyphae.to
hyp relay status --probe

# 3. Mint a one-shot drop link (fresh secret OR HPKE-encrypted directive prefill) and wait
hyp drop create --kind secret --secret-name stripe-key
hyp drop create --kind directive --draft "Approve staging deploy for v0.5.0"
hyp drop wait
```

*(Agents can also request a drop link via `hyp_mesh({ action: "drop_link", kind: "secret", secretName: "stripe-key" })` or `hyp_mesh({ action: "drop_link", kind: "directive", draft: "..." })` — directive drafts are HPKE-encrypted (`human.draft.v1`) directly into `#drop=` (`encDraft`) with zero plaintext leak even when pasted into Slack/Telegram/WhatsApp/SMS, and are strictly forbidden for `kind: "secret"`. On `https://hyphae.to/drop`, 1 Face ID / Touch ID tap unlocks & decrypts the draft in RAM with an amber untrusted-draft banner, auto-expanded BiDi-safe review box, and mandatory confirmation checkbox before signing and wiping RAM.)*

---

## 6. Verification, Diagnostics & Updates

- **`hyp status [--json]`**: Renders node identity (`kid`, fingerprint), local IPC status, Security Gate signature & quarantine count, update channel status, and the **Peer Capabilities & Version Skew** table.
- **`hyp doctor [--json]`**: Runs fail-closed diagnostics across `node.json`, `node.sqlite` WAL health, peer capability skew, `gate_policy_sig`, and all 9 harness integrations (exit `0` ok, `1` failure).
- **`hyp deploy check --config <node.json> [--url https://...]`**: Validates fail-closed deployment hardening, zero plaintext secrets, TLS origin, signed `/v1/manifest`, and anti-recon compliance.
- **`hyp update check` / `hyp update [--channel stable|nightly] [--all]`**: Cryptographically verifies Ed25519-signed release manifests, SHA-256 archive hashes, and anti-rollback timestamps before atomic binary swap with smoke-check rollback.
