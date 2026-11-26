# Gemini CLI *(Works with Limits)*

## Setup

```sh
hyp setup --harness gemini
```

What this configures:
- MCP server entry pointing to `hyp mcp`.
- Lifecycle hooks (`BeforeTool`, `AfterTool`, `AfterAgent`) in `~/.gemini/settings.json`.
- Tailored skill in `~/.gemini/skills/hyp-mesh/SKILL.md`.

## Caller Identity, Wakeups & Limits

- **Identity:** `BeforeTool` registers `(session_id, tool_name)` in `CallRegistry` and injects a single-use `_meshCall` token into `tool_input`.
- **Wakeups & Limits:** Messages drain on `AfterTool` and `AfterAgent` continuation hooks, or wake via an explicit `hyp wait` background task. There is no standalone external push API when the session is completely idle outside `hyp wait`.
- **Status UI:** Use `hyp inspect` or `hyp ui` in a split terminal (or run inside [Herdr](herdr.md)).

## What You Should See

- `hyp doctor` reports `OK` for Gemini CLI MCP and hooks.
- Messages sent to Gemini CLI's handle appear on the next `AfterTool` or `AfterAgent` turn boundary.

See [Troubleshooting](../operations/troubleshooting.md) if hooks do not trigger.
