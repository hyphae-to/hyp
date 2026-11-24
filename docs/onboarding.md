# Onboarding Guide

`hyphae` (`hyp`) supports two topologies with the same CLI and MCP tools:

1. **Single-machine Private Node** — agents across Antigravity, Claude Code / Desktop, Codex / Desktop, Cursor, OpenCode, Gemini CLI, OpenClaw, Herdr Core, and T3 Code on one computer.
2. **Multi-machine Team / Private Node over Tailscale or VPN** — one host runs the Node (exposed privately over Tailscale Services / Serve or any HTTPS reverse proxy on your VPN), and remote machines join with a one-shot invite or token file.

Requires **Node 24+** (`mise` automatically picks up Node 24 via `.node-version`).

---

## 1. Interactive & One-Command Onboarding

```sh
# Install via npm (or from source: npm ci && npm run build && ./bin/hyphae.mjs onboard)
npm install -g @hyphae-to/hyp
hyp onboard
```

When run in an interactive terminal without `--yes`, `hyp onboard` launches a `@clack/prompts` terminal UI with capability cards, arrow-key selectors, checkbox multi-selects, spinners, and masked secret prompts:
- Scans installed harnesses (**Antigravity**, **Claude Code / Desktop**, **Codex / Desktop**, **Cursor**, **OpenCode**, **Gemini CLI**, **OpenClaw**), **Herdr Core** (`hc` / `HC_TERMINAL_ID` + Herdr remote machines), **T3 Code**, and **Tailscale** (`tailscale status`).
- Lets you select **one or more** Node roles together:
  - **Private Node** — connect all your sessions across harnesses & machines, subscribe to GitHub / Prometheus & custom Node Streams with filters, and bridge threads to personal messaging tools (Slack, Telegram, WhatsApp).
  - **Public-Webhook / Team Node** — HTTPS webhook & event hub (prints hardened Caddy / Tailscale Funnel config for webhook paths).
  - **Join a Team Node** — join a team/org or shared Hyphae Node via `am1_...` invite or HTTPS URL + token (as `primary`, or as a secondary named Node alongside your Private Node).
- Presents checkbox multi-selects for **harness connectors** (all supported harnesses), **Node Streams** (**GitHub Events**, **Prometheus Alertmanager**, **Signed Webhook Stream**, **Custom Data Source Plugin**), and **Connector Bridges** (**Slack**, **Telegram**, **WhatsApp**, **Local Webhook**, **Custom fd-3 Plugin**), storing secrets in your OS keyring (macOS Keychain / Linux Secret Service, with a private local file fallback in `~/.config/hyphae/secrets/` on headless servers) with built-in step-by-step setup guides.
- Offers **Tailscale exposure** (`tailscale serve --service=svc:hyphae` or node-scoped Serve) and OS background service installation (`launchd` / `systemd --user`).
- Discovers remote machines defined in **Herdr Core**, **`~/.ssh/config`**, and your **Tailscale** tailnet, probes SSH reachability in parallel with a spinner, and presents a checkbox selector to invite & onboard reachable hosts over SSH (piping one-shot invites over stdin).

For scripted / non-interactive local setup, pass `--yes`:

```sh
hyp onboard --yes
```

### Agent-Assisted Onboarding (Let Your AI Agent Set It Up With You)

Prefer a conversational setup where your coding agent inspects your environment, explains the options, and runs the commands for you?

```sh
hyp onboard --assist             # auto-picks claude / codex / agy / opencode
hyp onboard --agent claude       # launch a specific agent
hyp onboard --prompt             # print secret-free concierge prompt for Claude Desktop / Cursor
```

You can also choose **"Guided by an AI agent"** right at the start of `hyp onboard`. The concierge receives a strictly **secret-free** snapshot and guides you to store tokens out-of-band via `hyp secret set <name> --web` without ever handling raw secrets.

What local `onboard` (alias `up`) configures:
- Creates `~/.config/hyphae/connector.json` with an **embedded local Node** (`127.0.0.1:8790`, SQLite DB at `~/.config/hyphae/router/router.sqlite`) and a private user-only connector token.
- Auto-detects installed harnesses (**Antigravity**, **Claude Code / Desktop**, **Codex / Desktop**, **Cursor**, **OpenCode**, **Gemini CLI**, **OpenClaw**) and merges MCP + hook configs non-destructively using your exact Node 24 binary path.
- Starts `hyp daemon` (running both the embedded Node and Connector in one process). Pass `--install-service` to also install a macOS LaunchAgent or Linux `systemd --user` unit.

Restart any open Desktop app once so it loads the new MCP server and hooks, then run:

```sh
hyp status                       # or `hyp status --json` for structured output
hyp status --discover --probe-ssh
```

### Onboarding Remote Machines Over SSH

You can also discover and onboard remote hosts directly from the CLI:

```sh
# Inspect local harnesses, Herdr/T3 Code, Tailscale, and SSH-reachable machines
hyp status --discover --probe-ssh

# Onboard a remote host over SSH (generates an invite on the local Node and pipes it via stdin)
hyp onboard --remote-ssh bogdan@solace --id bogdan@solace --install-service
```

---

## 2. Multi-Machine Onboarding Over Tailscale (Recommended)

`hyphae` **never** exposes a main Node to the public internet—the Node always binds loopback (`127.0.0.1:8790`), and Tailscale terminates TLS privately inside your tailnet (`tailscale serve`, never `funnel`).

### Step A — On the Node host: expose over Tailscale

**Option 1: Tailscale Service (recommended — stable DNS name & virtual IP)**

```sh
hyp share tailscale --service hyphae
# Runs: tailscale serve --bg --yes --service=svc:hyphae --https=443 http://127.0.0.1:8790
# URL:  https://hyphae.<your-tailnet>.ts.net
```

*(Make sure the `svc:hyphae` service is defined/approved in your Tailscale admin console if your tailnet enforces service approval.)*

**Option 2: Node-scoped Tailscale Serve (zero tailnet admin setup)**

```sh
hyp share tailscale
# Runs: tailscale serve --bg --yes --https=8790 http://127.0.0.1:8790
# URL:  https://<this-node>.<your-tailnet>.ts.net:8790
```

Pass `--dry-run` to preview the exact `tailscale serve` command and URL first. To remove exposure later:

```sh
hyp share stop --service hyphae
# or:
hyp share stop --https 8790
```

### Step B — On the Node host: generate a one-shot invite

```sh
hyp share invite bogdan@solace
# Auto-detects the exposed Tailscale HTTPS URL from `tailscale serve status --json`
# (or pass `--router https://hyphae.<tailnet>.ts.net` explicitly).
```

This creates a connector token in `~/.config/hyphae/router/router.sqlite` and prints a single command with an `am1_...` invite bundle passed over **stdin** (never in CLI argv / `ps`):

```sh
hyp onboard --join <<< 'am1_...'
```

### Step C — On each remote machine: join in 1 command

Run the printed command on the remote host (optionally adding `--install-service`):

```sh
hyp onboard --join --install-service <<< 'am1_...'
```

What `onboard --join` does automatically:
1. Decodes `{ connectorId, router, token }` from stdin and enforces an `https://` origin.
2. Runs a **live pre-flight check** (`GET <router>/v1/peers` with the bearer token) so VPN, Tailscale DNS, TLS, or auth errors are caught immediately before writing config (pass `--offline` to skip during image/Ansible provisioning).
3. Saves the token to `~/.config/hyphae/tokens/primary.token` (user-only permissions) and writes `~/.config/hyphae/connector.json` (remote mode with no embedded local Node).
4. Configures local harnesses, installs the OS background service if requested, and starts `hyp daemon`.

> **Migrating an already-onboarded machine from local to remote**: pass `--replace` (or `--join` / `--router` automatically replaces `connector.json`), then restart the daemon so it connects to the remote Node instead of its local embedded one.

---

## 3. Non-Tailscale VPN / Reverse Proxy Onboarding (WireGuard, Caddy, nginx)

If your Node runs behind any private HTTPS reverse proxy on a VPN:

1. On the Node host, issue a token file:
   ```sh
   hyp node add-connector bogdan@worker --db /path/to/router.sqlite --token-out connector.token
   ```
2. Copy `connector.token` securely (user-only permissions) to the remote machine and onboard:
   ```sh
   hyp onboard --id bogdan@worker --router https://mesh.internal.example --token-file /path/to/connector.token --install-service
   ```
   Or generate an invite bundle on the Node host:
   ```sh
   hyp share invite bogdan@worker --router https://mesh.internal.example --db /path/to/router.sqlite
   ```

---

## 4. Verifying & Troubleshooting

- **`hyp status`** (alias `hyp doctor`, supports `--json`): checks Node ≥ 24, `connector.json` permissions, live daemon socket, **live HTTPS reachability + auth for every configured Node**, secret references, and installed harness configs.
- **`hyp status --sessions`** (alias `hyp sessions`): outputs active sessions across all harnesses, handles, pending mailbox counts, and live push transports.
- **`hyp status --prune --older-than-hours 24`** (alias `hyp prune`): removes stale inactive sessions and frees their handles/subscriptions on the Node (never prunes sessions with an active `wait`/`watch`/`channel`).
- **Revoking a remote machine**:
  ```sh
  hyp node revoke-connector bogdan@solace --db ~/.config/hyphae/router/router.sqlite
  ```
