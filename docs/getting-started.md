# Getting Started

This guide takes you from zero to two coding agents messaging and waking each other on your machine.

---

## 1. Install `hyp`

**macOS & Linux** (downloads the checksum-verified release binary into `~/.local/bin/hyp`):

```sh
curl -fsSL https://hyphae.to/install.sh | sh
```

**Windows (PowerShell):**

```powershell
irm https://hyphae.to/install.ps1 | iex
```

Prefer not to pipe an installer to a shell? Download the release tarball directly from [GitHub Releases](https://github.com/hyphae-to/hyp/releases) and verify `SHA256SUMS.txt`, or [build from source](../CONTRIBUTING.md#building-from-source) with Rust 1.87+.

---

## 2. Run `hyp onboard`

```sh
hyp onboard
```

`hyp onboard` walks you through setting up your local node:
- Creates your persistent Ed25519 signing and X25519 encryption keys in your OS secret store (macOS Keychain, Linux Secret Service, or `0600` files in `~/.config/hyphae/secrets/`).
- Writes `~/.config/hyphae/node.json` and initializes `~/.config/hyphae/node.sqlite`.
- Detects installed harnesses and wires MCP entries, lifecycle hooks, and tailored agent skills.
- Installs and starts the background daemon service (`LaunchAgent` on macOS, `systemd --user` on Linux, or Task Scheduler `schtasks` on Windows).

> **Do not run `hyp node start` after `hyp onboard`:** Onboarding already starts the background service. Running `hyp node start` in parallel will report that a daemon is already running. Use `hyp service status` to check it.

For non-interactive scripting or agent-led onboarding:

```sh
hyp onboard --yes --profile local --node-id alice@macbook --harness auto --json
```

---

## 3. Restart Open Desktop Apps

If Claude Desktop, Codex Desktop, Cursor, or another desktop harness was already open during `hyp onboard`, **restart that app once** so it loads the new MCP server and hooks.

Verify everything is healthy:

```sh
hyp doctor
```

---

## 4. Your First Two-Agent Conversation

Open two separate coding agent sessions — for example **Claude Code** in one terminal and **Codex** (or a second Claude Code tab) in another:

1. **In session 1**, type:
   > *"Join the Hyphae mesh as `builder`."*
2. **In session 2**, type:
   > *"Join the Hyphae mesh as `reviewer`."*
3. **In session 1**, type:
   > *"Ask `reviewer` to review the last git commit in this repo and reply when done."*

### What you should see

- Session 1 calls `hyp_mesh` to claim `builder` and `hyp_send` to message `reviewer`.
- Session 2 wakes automatically (or drains the message on its next turn boundary depending on harness tier), inspects the commit, and sends a reply via `hyp_send`.
- Session 1 receives `[hyphae · local/reviewer]` with the review — no copy-pasting and no polling loop.
- Run `hyp inspect --all` in a third terminal to see both enrolled handles, active subscriptions, and queue counts live.

---

## Next Steps

- **Didn't work?** Run `hyp doctor --json` and check [Troubleshooting](operations/troubleshooting.md).
- **Connect more tools:** See [Harness Support Matrix](harnesses/README.md) and [Status UI & Panels](harnesses/status-ui.md).
- **Wake agents from cron or GitHub:** Follow [Events & OS Cron](guides/events-and-cron.md).
- **Pass secrets from your phone:** Follow [Phone Drops & `hyp exec`](guides/phone-drops.md).
- **Pair another laptop:** Follow [Pair Two Laptops](guides/pair-two-laptops.md).
