# Hyphae Plugin for Claude Code

First-class [Hyphae v2 (`hyp`)](https://hyphae.to) integration for Claude Code: E2EE DMs, `#channels`, CloudEvents streams, verified MCP caller hooks, `$HYPHAE_SESSION_ID` propagation, **native Claude Code Side Panel Mod (`/hyphae-panel`, v2.1.287+)**, slash commands, zero-token `!hyp ui` inspector, and non-destructive live `statusLine` chaining.

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

Validate and test the plugin bundle (including the native side-panel mod) locally:

```sh
claude plugin validate --strict plugins/claude-code
claude plugin test plugins/claude-code
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

## Native Claude Code Side Panel (`/hyphae-panel`)

On Claude Code **v2.1.287+**, `hooks/hooks.json` loads the in-process TypeScript/JSX mod (`hooks/register.tsx`) alongside the standard lifecycle shell hooks:

- Run **`/hyphae-panel`** (or `/hyphae-panel subs|queue|rules|mesh|close`) to open a docked live side panel (`Esc` closes it) showing:
  - **Header**: active `@handle`, `nodeId`, daemon online state, peer count, `FOCUS` / `MUTED*` badges, and a prominent red `⚠ N quarantined` alert pointing you to `hyp gate review` in your terminal.
  - **Tabs**: **Subs** (`topic`, `mode`, `originNode`, `filterSummary` + `Unsub`), **Queue** (metadata-only `kind`, `source`, `urgency`, relative age), **Rules** (active mutes + `Unmute`, per-source urgency rules), and **Mesh** (`#channels` + `Leave`, durable wakeup schedules).
  - **Quick Controls**: toggle Focus Mode, refresh state, toggle the optional compact `AbovePrompt` badge (`/hyphae-panel strip on|off`), or close the panel — all invoking `hyp session ...` with strict argv arrays (never shell string interpolation).
- **Zero-clutter `AbovePrompt` strip**: stays completely hidden unless Security Gate items are quarantined (`quarantined > 0`) or you explicitly toggle it on.
- **State projection**: reads Hyphae's atomic metadata-only snapshot at `~/.config/hyphae/ui/state.json` (respecting `HYPHAE_STATE_DIR` and `node.json`'s `stateDir` override) and degrades cleanly when the daemon is offline.

## Live Inspector & Slash Commands

On `SessionStart`, `hyp hook claude session-start` validates the Claude session ID and exports `HYPHAE_SESSION_ID='claude:<id>'` to `$CLAUDE_ENV_FILE`, so every command and `!` shell invocation automatically targets the active Claude session with zero flags:

| Command | Action |
|---|---|
| `/hyphae-panel [subs\|queue\|rules\|mesh\|close]` | Open or control the native live Claude Code side panel (Claude Code v2.1.287+) |
| `!hyp ui` | Launch the zero-token live interactive TUI inspector (Subscriptions, Queue, Rules & Mutes, Channels) |
| `hyp inspect [--json]` | Print a read-only metadata snapshot for this session |
| `/hyphae` *(or `/hyphae:hyphae`)* | Render a concise summary table of handle, Focus Mode, subscriptions, queued metadata, rules, and quarantine alerts |
| `/hyphae-subs` *(or `/hyphae:hyphae-subs`)* | List active subscriptions, unsubscribe (`hyp session unsubscribe <id>`), update delivery rules (`hyp session rule <target> <urgency>`), or leave channels (`hyp session leave <channel>`) |
| `/hyphae-focus [on\|off]` | Toggle or set Focus Mode (`hyp session focus on\|off`) |
| `/hyphae-mute <pattern> [--ttl <sec>]` | Mute or unmute a source, `#channel`, topic, or `*` (`hyp session mute` / `hyp session unmute`) |

## Security & Privacy Invariants

- **Metadata-only UI**: `hyp statusline`, `hyp inspect`, and the `/hyphae-panel` native side panel expose counts and sanitized metadata only — never message bodies, CloudEvent `data` payloads, wakeup `note`s, quarantined text, secrets, or pairing tokens.
- **Untrusted external data**: All mesh messages, `#channel` posts, stream events, and metadata strings are stripped of ANSI escapes, control characters, and Unicode BiDi overrides, and treated strictly as untrusted data — never as instructions.
- **Human-CLI quarantine boundary**: When Security Gate items are quarantined, the status line, `/hyphae`, and `/hyphae-panel` surface only the count and direct you to review them via `hyp gate review` in your terminal (never approve/reject buttons inside the agent UI).
