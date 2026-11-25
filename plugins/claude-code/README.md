# Hyphae Plugin for Claude Code

First-class [Hyphae v2 (`hyp`)](https://hyphae.to) integration for Claude Code: E2EE DMs, `#channels`, CloudEvents streams, verified MCP caller hooks, `$HYPHAE_SESSION_ID` propagation, slash commands, zero-token `!hyp ui` inspector, and non-destructive live `statusLine` chaining.

## Prerequisites

Install the single static Rust `hyp` binary (no Node.js or Python runtime required) and initialize your local node:

```sh
curl -fsSL https://hyphae.to/install.sh | sh
hyp onboard --profile local
hyp node start
```

Verify your node and harness setup anytime with `hyp doctor`.

## Install the Plugin

### Option A — Claude Code Plugin Directory / Marketplace

Test locally directly from this repository:

```sh
claude --plugin-dir ./plugins/claude-code
```

Or install via Claude Code's plugin manager directly from the marketplace:

```sh
/plugin install hyphae --marketplace hyphae-to/hyp
```

Or via the CLI:

```sh
claude plugin install hyphae
```

Validate the plugin bundle locally:

```sh
claude plugin validate --strict plugins/claude-code
```

### Option B — Direct `hyp setup` (Hooks, MCP, Slash Commands & Live `statusLine`)

Configure Claude Code hooks, MCP server, `/hyphae*` slash commands, and opt into the persistent live `statusLine`:

```sh
hyp setup --harness claude --statusline
```

## Non-Destructive `statusLine` Chaining

Plugins never silently overwrite your existing `~/.claude/settings.json` `statusLine`. Instead, `hyp setup --harness claude --statusline` is explicitly opt-in and **non-destructive**:

- **No existing `statusLine`**: writes `hyp statusline --harness claude` with `"refreshInterval": 5`.
- **Pre-existing custom `statusLine`**: saves your original `statusLine` object atomically to `~/.config/hyphae/claude-statusline-chain.json` (`0600`) and configures:
  ```json
  {
    "statusLine": {
      "type": "command",
      "command": "/path/to/hyp statusline --harness claude --chain-file ~/.config/hyphae/claude-statusline-chain.json",
      "refreshInterval": 5
    }
  }
  ```
  At runtime, `hyp statusline` runs your existing status line and Hyphae's compact indicator concurrently and stacks Hyphae cleanly below your existing bar.
- **Re-running is strictly idempotent**: Hyphae detects its own `statusLine` entry and never double-chains into itself.
- **Clean restore anytime**:
  ```sh
  hyp setup --harness claude --restore-statusline
  ```
  Restores your original `statusLine` verbatim from `claude-statusline-chain.json` (or removes Hyphae's `statusLine` if none was chained) and deletes the chain file.

### Antigravity CLI (`agy`) Bonus `statusLine`

Antigravity CLI natively supports stacking a custom status bar via `"stack_with_default": true`:

```sh
hyp setup --harness antigravity --statusline
# Restore anytime:
hyp setup --harness antigravity --restore-statusline
```

## Live Inspector & Slash Commands

On `SessionStart`, `hyp hook claude session-start` validates the Claude session ID and exports `HYPHAE_SESSION_ID='claude:<id>'` to `$CLAUDE_ENV_FILE`, so every command and `!` shell invocation automatically targets the active Claude session with zero flags:

| Command | Action |
|---|---|
| `!hyp ui` | Launch the zero-token live interactive TUI inspector (Subscriptions, Queue, Rules & Mutes, Channels) |
| `hyp inspect [--json]` | Print a read-only metadata snapshot for this session |
| `/hyphae` *(or `/hyphae:hyphae`)* | Render a concise summary table of handle, Focus Mode, subscriptions, queued metadata, rules, and quarantine alerts |
| `/hyphae-subs` *(or `/hyphae:hyphae-subs`)* | List active subscriptions, unsubscribe (`hyp session unsubscribe <id>`), update delivery rules (`hyp session rule <target> <urgency>`), or leave channels (`hyp session leave <channel>`) |
| `/hyphae-focus [on\|off]` | Toggle or set Focus Mode (`hyp session focus on\|off`) |
| `/hyphae-mute <pattern> [--ttl <sec>]` | Mute or unmute a source, `#channel`, topic, or `*` (`hyp session mute` / `hyp session unmute`) |

## Security & Privacy Invariants

- **Metadata-only UI**: `hyp statusline` and `hyp inspect` expose counts and sanitized metadata only — never message bodies, CloudEvent data payloads, quarantined text, secrets, or pairing tokens.
- **Untrusted external data**: All mesh messages, `#channel` posts, stream events, and metadata strings are treated strictly as untrusted data, never as instructions.
- **Human-CLI quarantine boundary**: When Security Gate items are quarantined, the status line and `/hyphae` surface only the count and direct you to review them via `hyp gate review` in your terminal.
