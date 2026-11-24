# Onboarding Guide

Hyphae (`hyp`) ships as a **single static Rust binary** (~6 MiB compressed download, ~2.7 ms hooks, ~2.8 MB idle MCP RSS, zero Node.js or Python runtime required for the core binary) and supports three composable topologies with the exact same `Node` binary:

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

Run `hyp onboard` in an interactive terminal to launch the fullscreen arrow-key **Mycelium onboarding TUI wizard** (automatically falling back to prompts/flags on non-TTY pipes, or pass `--assist` to let your coding agent run setup). To bootstrap non-interactively in one command:

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
hyp doctor
```

---

## 5. Opt-In Wakeups & Verified Human Drops

### A. Enable Local Wakeups & OS Cron Triggers

Add the compiled-in `wakeup` event source once (writes a `kind: "wakeup"` entry in `node.json`; default `--mcp-tool auto` exposes `hyp_wakeup` on Herdr/Codex/Claude/T3/Cursor/OpenCode/Gemini while keeping 0 extra tokens on OpenClaw & Antigravity):

```sh
hyp wakeup enable
hyp wakeup set --in 15m --label check-ci --note "Verify CI build"
hyp wakeup set --cron "0 9 * * 1-5" --timezone local --label morning-triage --to dev

# One-liner for crontab / systemd --user / launchd:
hyp wakeup fire --to dev --label nightly-audit --note "Check advisories"
```

See [skills/hyphae-wakeup/SKILL.md](../skills/hyphae-wakeup/SKILL.md) and [docs/plugins.md](plugins.md) for OS scheduler examples and the Tier 1–4 delivery ladder.

### B. Enroll a Phone Passkey & Configure a Drop Relay

Verified Human Drops let you send zero-knowledge OS Keychain secrets and `TrustTier::HumanVerified` directives straight from your phone (`https://hyphae.to/drop`) or laptop CLI:

```sh
# 1. Pair your phone's WebAuthn Passkey+PRF (or omit --web for a local CLI Ed25519 key in Keychain)
hyp auth init --web
hyp auth list

# 2. Point your node at a self-hosted (or team) RAM-only Drop Relay
hyp relay set https://drop.example.com
hyp relay status

# 3. Mint a one-shot drop link (zero-knowledge secret or verified directive) and wait for it
hyp drop create --kind secret --secret-name stripe-key
hyp drop wait
```

*(Agents can also request a fresh human drop link via `hyp_mesh({ action: "drop_link", kind: "secret", secretName: "stripe-key" })` — never pre-filling directive text and never seeing secret bytes.)*

---

## 6. Verification, Diagnostics & Updates

- **`hyp status [--json]`**: Renders node identity (`kid`, fingerprint), local IPC status, Security Gate signature & quarantine count, update channel status, and the **Peer Capabilities & Version Skew** table.
- **`hyp doctor [--json]`**: Runs fail-closed diagnostics across `node.json`, `node.sqlite` WAL health, peer capability skew, `gate_policy_sig`, and all 9 harness integrations (exit `0` ok, `1` failure).
- **`hyp deploy check --config <node.json> [--url https://...]`**: Validates fail-closed deployment hardening, zero plaintext secrets, TLS origin, signed `/v1/manifest`, and anti-recon compliance.
- **`hyp update check` / `hyp update [--channel stable|nightly] [--all]`**: Cryptographically verifies Ed25519-signed release manifests, SHA-256 archive hashes, and anti-rollback timestamps before atomic binary swap with smoke-check rollback.
