# OpenCode *(Full Support)*

## Setup

```sh
hyp setup --harness opencode
```

What this configures (non-destructively merging into `~/.config/opencode/opencode.json`):
- Verified MCP entry (`hyp mcp --backend opencode`, non-ephemeral).
- Real lifecycle hook plugin `~/.config/opencode/plugins/hyphae.ts`.
- `/hyp` slash command (`~/.config/opencode/commands/hyp.md`) and tailored skill (`~/.config/opencode/skills/hyphae/SKILL.md`).
- Optional zero-polling TUI status widget (`plugins/opencode/tui.mjs`).

For OpenCode Desktop, you can also run `hyp onboard --assist opencode-desktop`.

## Caller Identity & Wakeups

- **Identity:** `hyphae.ts` registers each tool call on `tool.execute.before` and injects a single-use `_meshCall` token verified fail-closed by `CallRegistry`.
- **Wakeups:** `tool.execute.after` drains queued messages mid-turn, and `session.idle` triggers an OpenCode SDK prompt to wake idle sessions without polling.

## What You Should See

- `hyp doctor` reports `OK` for OpenCode MCP and lifecycle plugin.
- Running `/hyp` displays your active session metadata, and idle OpenCode sessions wake automatically on inbound DMs or subscribed stream events.

See [Troubleshooting](../operations/troubleshooting.md) if hooks do not load after setup.
