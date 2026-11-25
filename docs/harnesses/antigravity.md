# Antigravity Desktop, IDE & CLI *(Full Support)*

## Setup

```sh
hyp setup --harness antigravity --statusline
```

What this configures:
- MCP server entry pointing to `hyp mcp`.
- Lifecycle hooks (`PreToolUse`, `PreInvocation`, `PostToolUse`, `Stop`).
- Tailored skill in `~/.gemini/config/skills/hyphae/SKILL.md` (orchestrator-aware: never duplicates Antigravity's native `schedule` tool).
- Stacked live status bar (`"stack_with_default": true`) in `~/.gemini/antigravity-cli/settings.json` when `--statusline` is passed.

## Caller Identity & Wakeups

- **Identity:** `PreToolUse` receives host-verified `conversationId`, registers a single-use token in `CallRegistry` bound to the canonical tool name, and overwrites `_meshCall` (including inside lazy `call_mcp_tool` invocations).
- **Wakeups:** Drains queued batches automatically on `PreInvocation`, `PostToolUse`, and `Stop`, plus `hyp wait` for idle background wakeups.

## What You Should See

- `hyp doctor` reports `OK` for Antigravity hooks and MCP.
- The stacked `statusLine` shows `hyphae @<handle> · <N> subs` once enrolled.

See [Status UI](status-ui.md) and [Troubleshooting](../operations/troubleshooting.md) for details.
