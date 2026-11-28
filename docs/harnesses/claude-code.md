# Claude Code & Claude Desktop *(Full Support)*

## Setup

```sh
hyp setup --harness claude
```

What this configures (respecting `CLAUDE_CONFIG_DIR` and preserving symlinks):
- MCP server entry in `~/.claude.json` pointing to `hyp mcp`.
- Lifecycle hooks (`SessionStart`, `UserPromptSubmit`, `PreToolUse`, `PostToolUse`, `Stop`) in `~/.claude/settings.json`.
- Tailored skill `~/.claude/skills/hyp-mesh/SKILL.md` (omit with `--no-skills`).
- Slash commands (`/hyp`, `/hyp-subs`, `/hyp-focus`, `/hyp-mute`) and the native UI plugin (`~/.claude/skills/hyp-panel/`) for Claude Code v2.1.287+ (omit with `--no-commands`).

For additional profiles, pass `--claude-config-dir ~/.claude-work`. For Claude Desktop, run `hyp onboard --assist claude-desktop` to merge `claude_desktop_config.json` safely, then **restart Claude Desktop**.

## Caller Identity & Wakeups

- **Identity:** `PreToolUse` registers `(session_id, tool_name, tool_use_id)` in `CallRegistry`; `tools/call` must match `_meta["claudecode/toolUseId"]`.
- Queued messages arrive at the foreground turn’s `Stop` hook. Between turns, Hyphae can send a digest through Herdr even when a background monitor keeps the terminal marked `working`. Prompt submission and tool hooks refresh the activity estimate. After 15 seconds without another hook, Hyphae retries a deferred wake automatically. A long tool call can outlast that estimate. Herdr still verifies the target and waits for user drafts before typing.
- **Channels:** Plain `hyp mcp` advertises channel capability to Claude Code. For Claude to accept notices, select the Hyphae MCP server when launching Claude Code. A channel notice carries unread counts and sources. Open the inbox with `hyp_inbox` to read and acknowledge the receipts. Hooks and waiters can still surface the same receipts if Claude ignores the notice or reads it slowly. [Claude Code channels](https://code.claude.com/docs/en/channels)

## Status UI

Claude Code v2.1.287+ gets a persistent live status indicator beneath the prompt plus `/hyp-panel` automatically via `hyphae-panel`. Only enable shell `--statusline` if you run older Claude Code or explicitly want chained shell bars — see [Status UI](status-ui.md).

## What You Should See

- `hyp doctor` reports `OK` for Claude MCP, hooks, and `plugin:claude-panel`.
- Asking Claude to *"join the Hyphae mesh as `builder`"* succeeds and updates the live status indicator.

If messages do not arrive, restart Claude Desktop/Code and check [Troubleshooting](../operations/troubleshooting.md).
