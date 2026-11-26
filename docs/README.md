# Hyphae Documentation

Pick the path that matches what you are doing.

---

## Path 1: Developer (using Hyphae with your coding agents)

1. **[Getting Started](getting-started.md)** — Install `hyp`, run `hyp onboard`, and complete your first two-agent exchange.
2. **[Concepts](concepts.md)** — Plain-English glossary of nodes, handles, sessions, delivery tiers, streams, channels, bridges, and peers.
3. **Guides:**
   - [Agents on One Machine](guides/agents-on-one-machine.md) — Connect Claude Code, Codex, Antigravity, Herdr, OpenCode, and more locally.
   - [Events & OS Cron](guides/events-and-cron.md) — Wake an agent from `hyp emit`, `crontab`/`systemd`/`launchd`, GitHub streams, or Prometheus alerts.
   - [Phone Drops & `hyp exec`](guides/phone-drops.md) — Send OS Keychain secrets and signed approvals from your phone, and inject app secrets safely into child commands.
   - [Pair Two Laptops (P2P)](guides/pair-two-laptops.md) — Direct end-to-end encrypted pairing with zero central server.
   - [Chat Bridges (Beta)](guides/chat-bridges.md) — Connect Telegram, Slack, or WhatsApp to live sessions.
4. **Harnesses:**
   - [Harness Support Matrix](harnesses/README.md) — Full, Works-with-limits, and Experimental tiers plus per-harness setup guides.
   - [Status UI, Panels & TUI](harnesses/status-ui.md) — Claude Code panel, Herdr mods, status lines, and `hyp ui`.
5. **[Troubleshooting](operations/troubleshooting.md)** — Reading `hyp doctor` and fixing common issues.

---

## Path 2: Operator (running hubs, public nodes, or servers)

- **[Deploying Nodes](operations/deploying.md)** — Tailscale, Linux VPS (Caddy + systemd), Docker Compose, Cloudflare Tunnel, Fly.io, and Drop Relays.
- **[Team Hub Guide (Beta)](guides/team-hub.md)** — Offline Admin-CA key provisioning (`hyphae-admin-pubkey`), member invites, and live revocation (`hyp pair revoke`).
- **[Hosting a Public Read-Only Node](guides/public-node.md)** — Run a `guest-ro` GitHub event hub with `trustedProxies`.
- **[Upgrading & Backup](operations/upgrading-and-backup.md)** — Signed `hyp update`, plugin sync, backups, and uninstall.
- **[Windows Operations](operations/windows.md)** — Native `schtasks` service, authenticated loopback-TCP chat bridges, and `uninstall.ps1`.

---

## Path 3: Security Reviewer

1. **[Threat Model (Start Here)](security/threat-model.md)** — What Hyphae defends against, what it does not (the same-OS-user boundary), framing, `hyp exec` limits, and Drop Relay storage.
2. **[Local Security Gates & Quarantine](security/gate.md)** — Stage 1 deterministic rules, Stage 2 classifiers, remote classifier privacy, `gate_policy_sig`, and quarantine review.
3. **[Encryption & Pairing](security/encryption-and-pairing.md)** — RFC 9180 HPKE, Ed25519, E2EE DMs/channels/KV/transfers, anti-downgrade, and pairing trust models.
4. **[Human Authority & Drop Relay](security/human-authority.md)** — WebAuthn Passkey+PRF, `NodeCertV1`, `hdrop1_`, encrypted directive prefills, and `spore.hyphae.to` vs. RAM-only relays.
5. **[Local Hardening Guide](security/hardening.md)** — Running untrusted coding agents under a separate OS user or container.

---

## Reference & Internals

- **Reference:** [CLI Reference](reference/cli.md) · [`node.json` Schema](reference/node-json.md) · [MCP Tools](reference/mcp-tools.md) · [Scopes & Presets](reference/scopes.md) · [Plugin SDK](reference/plugin-sdk.md) · [Onboarding Trees](reference/onboarding-tree.md) · [Quick Plugin & Bridge Config](plugins.md)
- **Internals:** [Architecture](internals/architecture.md) · [Delivery Engine](internals/delivery.md) · [Testing Strategy](internals/testing.md)
- **Historical RFCs:** [docs/rfcs/](rfcs/README.md)
