# Codex CLI & Codex Desktop *(Full Support)*

## Setup

```sh
hyp setup --harness codex
```

What this configures:
- MCP entry in `~/.codex/config.toml` (`hyp mcp --backend codex`).
- Hooks (`SessionStart`, `PreToolUse`, `PostToolUse`, `Stop`) in `~/.codex/hooks.json`.
- Tailored skill in `~/.codex/skills/hyp-mesh/SKILL.md` and `~/.agents/skills/hyp-mesh/SKILL.md`.

For Codex Desktop, run `hyp onboard --assist codex-desktop` to preview and merge `~/.codex/config.toml`, then **restart Codex Desktop**. Both setup paths use the same MCP entry and keep any socket set by `hyp setup --harness codex --socket <path>`.

## Caller Identity & Wakeups

- **Identity:** Verifies thread rollout presence in `$CODEX_HOME/sessions/` alongside `~/.codex/hooks.json` lifecycle hooks.
- **Wakeups:** Native push via `codex queue --thread <uuid>` delivers messages directly into idle Codex threads alongside hook drains on `PostToolUse`/`Stop`. Standalone threads can pass `--thread <uuid>`, `--resume` (strictly opt-in cold revival), or `--remote <addr>` to `hyp mcp`.

## Status UI

Use `hyp inspect` / `hyp ui` in a split terminal, or run Codex inside [Herdr](herdr.md) for per-pane GPU status pills.

## What You Should See

- `hyp doctor` reports `OK` for Codex MCP and hooks.
- An idle Codex thread enrolled via `hyp_mesh` wakes via `codex queue` when another agent messages its handle.

See [Troubleshooting](../operations/troubleshooting.md) if `codex` is not on `PATH` or a thread does not wake.
