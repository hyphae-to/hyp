---
name: hyphae-onboard
description: Install and onboard Hyphae (hyp) on laptops and Linux servers — Private & Team Nodes, all 9 coding harnesses, GitHub/Prometheus streams, Slack/Telegram/WhatsApp bridges, OS Keychain secrets, Tailscale, and remote SSH hosts.
---

# Hyphae (`hyp`) — Installation & Agent-Led Onboarding

## 1. Check or Install `hyp` (Node 24+)

```bash
hyp status
# If not installed:
bash -c "$(curl -fsSL https://raw.githubusercontent.com/hyphae-to/hyp/main/install.sh)"
# Or via npm:
npm install -g @hyphae-to/hyp
```

## 2. Secret-Free Onboarding Flow

1. **Inspect the machine**:
   ```bash
   hyp onboard --prompt
   ```
2. **Ask 1–2 concise questions**: Private Node vs. Team Node vs. Join Team Node; harnesses (`antigravity`, `claude`, `codex`, `cursor`, `opencode`, `gemini`, `openclaw`, `t3`, Herdr); Node Streams (`github-webhook`, `prometheus-webhook`, `webhook-stream`, custom fd-3); Connector Bridges (`slack`, `telegram`, `whatsapp`, `webhook`); remote SSH hosts.
3. **Run setup commands**:
   ```bash
   hyp onboard --yes
   hyp setup <harness|all|service>
   hyp connect guide <id> --json
   hyp share tailscale --service hyphae        # private tailnet HTTPS (never Funnel main router)
   hyp status --discover --probe-ssh
   hyp onboard --remote-ssh <host>
   ```
4. **Capture secrets OUT-OF-BAND** (never ask the user to paste secrets in chat or CLI args):
   ```bash
   hyp secret set <name> --web                 # one-shot localhost form -> OS Keychain / Secret Service
   ```
   Reference secrets in `~/.config/hyphae/connector.json` ONLY as `{ "secret": "<name>" }` or `{ "secretFile": "<name>" }`. Always set bridge sender allowlists (`SLACK_ALLOWED_USERS`, `TELEGRAM_ALLOWED_USERS`, `WHATSAPP_ALLOWED_NUMBERS`).
5. **Verify**:
   ```bash
   hyp secret check --json
   hyp status --json
   ```
