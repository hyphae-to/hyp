---
name: hyphae-onboard
description: Install and onboard the pure-Rust Hyphae (hyp) binary on laptops and servers — local, Direct P2P (hp2p1_), Team Hub (am2_), and Public Nodes (public.hyphae.to or self-hosted), all 9 coding harnesses, OS Keychain secrets, and Local Security Gates.
---

# Hyphae (`hyp`) — Installation & Agent-Led Onboarding

## 1. Check or Install `hyp` (Single Static Rust Binary)

No Node.js or Python runtime is required for `hyp` (~6 MiB compressed download, SHA-256 verified):

```sh
hyp version --json || hyp status --json
```

If `hyp` is not installed yet:
- **macOS & Linux**:
  ```sh
  curl -fsSL https://hyphae.to/install.sh | sh
  ```
- **Windows (PowerShell)**:
  ```powershell
  irm https://hyphae.to/install.ps1 | iex
  ```
- **From source (Rust 1.87+)**:
  ```sh
  cargo install --path crates/hyp-cli
  ```

## 2. Inspect Environment & Available Topologies (Secret-Free)

Run structured JSON probes first:

```sh
hyp status --json
hyp doctor --json
hyp deploy providers --json
hyp pair guide --json
```

Ask 1–2 concise questions to pick:
1. **Topology**: Local solo multi-harness (`local`), Direct P2P collaborator (`p2p`, `hp2p1_`), Blind E2EE Team Hub (`router`, `am2_`), and/or read-only Public Node (`public.hyphae.to` or self-hosted via `hyp deploy init public-node`).
2. **Harnesses**: `auto` (detected), `all`, or a comma-separated subset of `antigravity,claude,codex,cursor,opencode,gemini,openclaw,herdr,t3`.
3. **Optional**: Internet deployment provider (`tailscale`, `vps`, `docker`, `cloudflare`, `fly`, `public-node`) and optional Local Security Gate classifier (`anthropic`, `openai-compat`, `google`, `lakera-guard`, `http-classifier`, `subprocess`).

## 3. Bootstrap the Node & Configure Harnesses

```sh
# Local workstation node + persistent Ed25519/X25519 keys + node.json + node.sqlite + detected harnesses
hyp onboard --profile local --node-id alice@macbook --harness auto

# Or dry-run / explicitly configure specific harnesses
hyp setup --harness claude,codex,antigravity --dry-run
hyp setup --harness claude,codex,antigravity

# Start the unified Node + local IPC daemon (alias: hyp daemon)
hyp node start
```

## 4. Pair Across Topologies (Stdin / `--token-file` Only — NEVER CLI Argv!)

Never place `hp2p1_`, `am2_`, or `t3mp1_` tokens in CLI arguments (they leak to `ps` and shell history).

- **Direct P2P (Zero Hub, `hp2p1_`)**:
  ```sh
  # Inviter:
  hyp pair invite --mode p2p --node-id alice@macbook \
    --endpoint https://alice.tailnet.ts.net \
    --grant dm:send dm:receive files:send=25mb --request kv:read=pair/*

  # Accepter (always inspect & accept over stdin or 0600 --token-file):
  hyp pair inspect <<< "$TOKEN"
  hyp pair accept <<< "$TOKEN"
  ```
- **Team Hub (Org Admin-CA, `am2_`)**:
  ```sh
  # Generate a hardened deployment kit (tailscale | vps | docker | cloudflare | fly):
  hyp deploy init tailscale --node-id acme-team --domain hyphae.your-tailnet.ts.net --out ./deploy-tailscale
  hyp deploy check --config ./deploy-tailscale/node.json --json

  # Issue per-member grant & accept on member laptop:
  hyp pair invite --mode team --node-id acme-team --endpoint https://hyphae.your-tailnet.ts.net --peer alice@macbook --preset member
  hyp pair accept <<< "$TOKEN"
  # Or during initial machine bootstrap:
  hyp onboard --join - <<< "$TOKEN"
  ```
- **Public Read-Only Node (`guest-ro`)**:
  ```sh
  # Join an example public node (or your own self-hosted public node URL):
  hyp pair join https://public.hyphae.to --json

  # Or self-host a community/org public read-only GitHub stream hub:
  hyp deploy init public-node --node-id mesh.example.org --domain mesh.example.org --out ./deploy-public
  ```

## 5. Secrets Out-of-Band & Optional Security Gate

- **Capture secrets OUT-OF-BAND** (never ask the user to paste raw keys in chat or CLI argv):
  ```sh
  hyp secret set <name> --web         # one-shot 127.0.0.1 CSRF-protected form -> Keychain / Secret Service / 0600 file
  hyp secret list --json              # inspect names & permissions (never prints secret values)
  ```
  Reference secrets in `~/.config/hyphae/node.json` strictly as `{ "secret": "<name>" }`.
- **Stage a Local Security Gate proposal** (agents should propose; humans review and lock with `hyp gate lock`):
  ```sh
  hyp gate propose --adapter anthropic --secret anthropic-api-key --json
  # Human reviews ~/.config/hyphae/gate.proposed.json, then applies & signs gate_policy_sig:
  # hyp gate init --adapter anthropic --secret anthropic-api-key --lock
  ```

## 6. Verify Health & Diagnostics

```sh
hyp doctor --json
hyp status --json
hyp deploy check --config ~/.config/hyphae/node.json --json
```
