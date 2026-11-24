# Onboarding Guide

`hyphae` supports two topologies with the same CLI and MCP tools:

1. **Single-machine local mesh** — agents across Antigravity, Claude Code / Desktop, Codex / Desktop, and Herdr on one computer.
2. **Multi-machine VPN / Tailscale mesh** — one host runs the router (exposed privately over Tailscale Serve / Tailscale Services or any HTTPS reverse proxy on your VPN), and remote machines join with a one-shot invite or token file.

Requires **Node 24+** (`mise` automatically picks up Node 24 via `.node-version`).

---

## 1. Interactive & One-Command Onboarding

```sh
npm ci && npm run build
./bin/hyphae.mjs onboard
```

When run in an interactive terminal without `--yes`, `hph onboard` launches a `@clack/prompts` terminal UI with capability cards, arrow-key selectors, checkbox multi-selects, spinners, and masked secret prompts:
- Scans installed harnesses (**Antigravity**, **Claude Code / Desktop**, **Codex / Desktop**, **Cursor**, **OpenCode**, **Gemini CLI**), **Herdr Core** (`hc` / `HC_TERMINAL_ID` + Herdr remote machines), **T3 Code** (`~/.t3` / `~/.t3-mesh/config.json`), and **Tailscale** (`tailscale status`).
- Displays capability cards and lets you select **one or more** router roles together:
  - **Setup Private Router** — connect all your sessions across harnesses & machines, subscribe to GitHub events & custom router data streams with filters, and bridge threads to 3rd-party messaging tools (Slack, Telegram).
  - **Setup Public Router** — internet-reachable HTTPS webhook & event hub (prints hardened Caddy / Tailscale Funnel config).
  - **Join a Shared Router** — join a team/org or existing `t3-mesh` router via `am1_...` invite or HTTPS URL + token (as `primary`, or as a secondary named router alongside your private router).
- Presents checkbox multi-selects for **harness connectors** (all 6 harnesses), **router data streams** (**GitHub Events**, **Signed Webhook Stream**, **Custom Data Source Plugin**), and **connector thread bridges** (**Slack**, **Telegram**, **Local Webhook**, **Custom / t3-mesh Plugin**), storing secrets privately in `~/.config/hyphae/secrets/` (`0600`) with built-in step-by-step setup guides.
- Offers **Tailscale exposure** (`tailscale serve --service=svc:hyphae` or node-scoped Serve) and OS background service installation (`launchd` / `systemd --user`).
- Discovers remote machines defined in **Herdr Core**, **`~/.ssh/config`**, and your **Tailscale** tailnet, probes SSH reachability in parallel with a spinner, and presents a checkbox selector to invite & onboard reachable hosts over SSH (piping one-shot invites over stdin).

For scripted / non-interactive local setup, pass `--yes`:

```sh
./bin/hyphae.mjs onboard --yes
```

### Agent-Assisted Onboarding (Let Your AI Agent Set It Up With You)

Prefer a conversational setup where your coding agent inspects your environment, explains the options, and runs the commands for you?

```sh
./bin/hyphae.mjs onboard --assist             # auto-picks claude / codex / agy / opencode
./bin/hyphae.mjs onboard --agent claude       # launch a specific agent
./bin/hyphae.mjs onboard --prompt             # print secret-free concierge prompt for Claude Desktop / Cursor
```

You can also choose **"Guided by an AI agent"** right at the start of `./bin/hyphae.mjs onboard`. The concierge receives a strictly **secret-free** snapshot and guides you to store tokens via `hph secret set <name>` without ever handling raw secrets.

What local `onboard` (alias `up`) configures:
- Creates `~/.config/hyphae/connector.json` (`0600`) with an **embedded local router** (`127.0.0.1:8790`, SQLite DB at `~/.config/hyphae/router/router.sqlite`) and a private connector token (`0600`).
- Auto-detects installed harnesses (**Antigravity**, **Claude Code / Desktop**, **Codex / Desktop**) and merges MCP + hook configs non-destructively using your exact Node 24 binary path.
- Starts `hph daemon` (running both the embedded router and connector in one process). Pass `--install-service` to also install a macOS LaunchAgent or Linux `systemd --user` unit.

Restart any open Desktop app once so it loads the new MCP server and hooks, then run:

```sh
./bin/hyphae.mjs doctor
./bin/hyphae.mjs discover --probe-ssh
```

### Onboarding Remote Machines Over SSH

You can also discover and onboard remote hosts directly from the CLI:

```sh
# Inspect local harnesses, Herdr/T3 Code, Tailscale, and SSH-reachable machines
./bin/hyphae.mjs discover --probe-ssh

# Onboard a remote host over SSH (generates an invite on the local router and pipes it via stdin)
./bin/hyphae.mjs onboard --remote-ssh bogdan@solace --remote-id bogdan@solace --install-service
```

---

## 2. Multi-Machine Onboarding Over Tailscale (Recommended)

`hyphae` **never** exposes a router to the public internet—the router always binds loopback (`127.0.0.1:8790`), and Tailscale terminates TLS privately inside your tailnet (`tailscale serve`, never `funnel`).

### Step A — On the router host: expose over Tailscale

**Option 1: Tailscale Service (recommended — stable DNS name & virtual IP)**

```sh
./bin/hyphae.mjs router expose tailscale --service hyphae
# Runs: tailscale serve --bg --yes --service=svc:hyphae --https=443 http://127.0.0.1:8790
# URL:  https://hyphae.<your-tailnet>.ts.net
```

*(Make sure the `svc:hyphae` service is defined/approved in your Tailscale admin console if your tailnet enforces service approval.)*

**Option 2: Node-scoped Tailscale Serve (zero tailnet admin setup)**

```sh
./bin/hyphae.mjs router expose tailscale
# Runs: tailscale serve --bg --yes --https=8790 http://127.0.0.1:8790
# URL:  https://<this-node>.<your-tailnet>.ts.net:8790
```

Pass `--dry-run` to preview the exact `tailscale serve` command and URL first. To remove exposure later:

```sh
./bin/hyphae.mjs router unexpose tailscale --service hyphae
# or:
./bin/hyphae.mjs router unexpose tailscale --https 8790
```

### Step B — On the router host: generate a one-shot invite

```sh
./bin/hyphae.mjs router invite bogdan@solace
# Auto-detects the exposed Tailscale HTTPS URL from `tailscale serve status --json`
# (or pass `--router https://hyphae.<tailnet>.ts.net` explicitly).
```

This creates a connector token in `~/.config/hyphae/router/router.sqlite` and prints a single command with an `am1_...` invite bundle passed over **stdin** (never in CLI argv / `ps`):

```sh
hph onboard --join <<< 'am1_...'
```

### Step C — On each remote machine: join in 1 command

Run the printed command on the remote host (optionally adding `--install-service`):

```sh
./bin/hyphae.mjs onboard --join --install-service <<< 'am1_...'
```

What `onboard --join` does automatically:
1. Decodes `{ connectorId, router, token }` from stdin and enforces an `https://` origin.
2. Runs a **live pre-flight check** (`GET <router>/v1/peers` with the bearer token) so VPN, Tailscale DNS, TLS, or auth errors are caught immediately before writing config (pass `--offline` to skip during image/Ansible provisioning).
3. Saves the token to `~/.config/hyphae/tokens/primary.token` (`0600`) and writes `~/.config/hyphae/connector.json` (`0600`, remote mode with no embedded local router).
4. Configures local harnesses (Antigravity, Claude, Codex), installs the OS background service if requested, and starts `hph daemon`.

> **Migrating an already-onboarded machine from local to remote**: pass `--replace` (or `--join` / `--router` automatically replaces `connector.json`), then restart the daemon so it connects to the remote router instead of its local embedded one.

---

## 3. Non-Tailscale VPN / Reverse Proxy Onboarding (WireGuard, Caddy, nginx)

If your router runs behind any private HTTPS reverse proxy on a VPN:

1. On the router host, issue a token file:
   ```sh
   hph router add-connector bogdan@worker --db /path/to/router.sqlite --token-out connector.token
   ```
2. Copy `connector.token` securely (`0600`) to the remote machine and onboard:
   ```sh
   hph onboard --id bogdan@worker --router https://mesh.internal.example --token-file /path/to/connector.token --install-service
   ```
   Or generate an invite bundle on the router host:
   ```sh
   hph router invite bogdan@worker --router https://mesh.internal.example --db /path/to/router.sqlite
   ```

---

## 4. Verifying & Troubleshooting

- **`hph doctor`**: checks Node ≥ 24, `connector.json` permissions, live daemon socket, **live HTTPS reachability + auth for every configured router**, and installed harness configs.
- **`hph status`** / **`hph sessions`**: shows connected routers, active sessions across all harnesses, handles, pending mailbox counts, and live push transports.
- **`hph prune --older-than-hours 24`**: removes stale inactive sessions and frees their handles/subscriptions on the router (never prunes sessions with an active `wait`/`watch`/`channel`).
- **Revoking a remote machine**:
  ```sh
  hph router revoke-connector bogdan@solace --db ~/.config/hyphae/router/router.sqlite
  ```
