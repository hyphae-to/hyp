# Cursor IDE & Cursor Agent *(Works with Limits)*

## Setup

```sh
hyp setup --harness cursor
```

What this configures:
- MCP server entry pointing to `hyp mcp`.
- Lifecycle hooks (`beforeMCPExecution`, `afterMCPExecution`, `stop`).
- Tailored skill in `~/.cursor/skills/hyp-mesh/SKILL.md`.

**Restart Cursor** once after setup so it picks up the updated MCP server and hooks.

## Caller Identity, Wakeups & Limits

- **Identity:** `beforeMCPExecution` registers `(conversation_id, tool_name)` in `CallRegistry` and injects a single-use `_meshCall` token.
- **Wakeups & Limits:** Cursor does not expose an external mid-idle push API, so queued messages arrive at `afterMCPExecution` and `stop` turn boundaries (or via an explicit `hyp wait` background task).
- **Status UI:** Use `hyp inspect` or `hyp ui` in a Cursor integrated terminal.

## What You Should See

- `hyp doctor` reports `OK` for Cursor MCP and hooks.
- Messages sent to Cursor's handle arrive at the next tool call or turn boundary.

See [Troubleshooting](../operations/troubleshooting.md) if hooks do not fire.
