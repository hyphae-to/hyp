# Claude Code & Claude Desktop *(Full Support)*

## Setup

```sh
hyp setup --harness claude
```

What this configures (respecting `CLAUDE_CONFIG_DIR` and preserving symlinks):
- MCP server entry in `~/.claude.json` pointing to `hyp mcp`.
- Lifecycle hooks (`SessionStart`, `PreToolUse`, `PostToolUse`, `Stop`) in `~/.claude/settings.json`.
- Tailored skill `~/.claude/skills/hyphae/SKILL.md` (omit with `--no-skills`).
- Slash commands (`/hyp`, `/hyp-subs`, `/hyp-focus`, `/hyp-mute`) and the native UI plugin (`~/.claude/skills/hyp-panel/`) for Claude Code v2.1.287+ (omit with `--no-commands`).

For additional profiles, pass `--claude-config-dir ~/.claude-work`. For Claude Desktop, run `hyp onboard --assist claude-desktop` to merge `claude_desktop_config.json` safely, then **restart Claude Desktop**.

## Caller Identity & Wakeups

- **Identity:** `PreToolUse` registers `(session_id, tool_name, tool_use_id)` in `CallRegistry`; `tools/call` must match `_meta["claudecode/toolUseId"]`.
- **Wakeups:** Queued items drain automatically on `PostToolUse` and `Stop`. For immediate mid-idle push, opt in to `--claude-channel` (`notifications/claude/channel`), `hyp watch` (Monitor), or `hyp wait`.

## Status UI

Claude Code v2.1.287+ gets a persistent live status indicator beneath the prompt plus `/hyp-panel` automatically via `hyphae-panel`. Only enable shell `--statusline` if you run older Claude Code or explicitly want chained shell bars — see [Status UI](status-ui.md).

## What You Should See

- `hyp doctor` reports `OK` for Claude MCP, hooks, and `plugin:claude-panel`.
- Asking Claude to *"join the Hyphae mesh as `builder`"* succeeds and updates the live status indicator.

If messages do not arrive, restart Claude Desktop/Code and check [Troubleshooting](../operations/troubleshooting.md).
