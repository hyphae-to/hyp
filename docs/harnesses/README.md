# Supported Harnesses

One shared stateless `hyp mcp` subprocess (~2.8 MB RSS) multiplexes concurrent threads across coding harnesses, backed by `CallRegistry` and per-session HMAC `sessionToken`s.

Run `hyp setup --harness auto` (or `--harness <comma-list>`) to wire MCP entries, lifecycle hooks, and orchestrator-aware tailored `hyphae/SKILL.md` guides. Refresh managed skills after upgrades with `hyp setup --refresh-skills`.

## Support Matrix

| Tier | Harness | Caller Binding | Push / Wakeup Path | Status UI | Guide |
| --- | --- | --- | --- | --- | --- |
| **Full** | **Claude Code** (CLI & Desktop) | `PreToolUse` hook (`session_id` + `_meta["claudecode/toolUseId"]`) | `PostToolUse`/`Stop` drain + opt-in `--claude-channel` / `hyp watch` / `hyp wait` | Native `hyphae-panel` + `/hyphae` commands + optional `--statusline` | [claude-code.md](claude-code.md) |
| **Full** | **Antigravity** (Desktop / IDE / CLI) | `PreToolUse` hook (`conversationId` + single-use `_meshCall`) | `PreInvocation` / `PostToolUse` / `Stop` drain + `hyp wait` | Stacked `--statusline` + `hyp ui` | [antigravity.md](antigravity.md) |
| **Full** | **Herdr Core** | `--backend herdr` + `HC_TERMINAL_ID` verified via `hc get` (bare shells rejected) | Native `hc send` (`queue`) / `hc interrupt` (`interrupt`) | Native GPUI `hyphae-pane` pill + `hyphae-panel` dock (`--mod`) | [herdr.md](herdr.md) |
| **Full** | **Codex** (CLI & Desktop) | Thread rollout presence (`$CODEX_HOME/sessions/`) + hooks (`~/.codex/hooks.json`) | Native `codex queue --thread <uuid>` + hook drain | `hyp inspect` / `hyp ui` (or Herdr pill when inside Herdr) | [codex.md](codex.md) |
| **Full** | **OpenCode** | Real lifecycle plugin (`~/.config/opencode/plugins/hyphae.ts`) + single-use `_meshCall` | `tool.execute.after` drain + `session.idle` SDK prompt | `/hyphae` command + optional zero-polling TUI widget (`tui.mjs`) | [opencode.md](opencode.md) |
| **Works with limits** | **Cursor** (IDE & Agent) | `beforeMCPExecution` hook (`conversation_id` + `_meshCall`) | `afterMCPExecution` drain + `stop` followup + `hyp wait` | `hyp inspect` / `hyp ui` | [cursor.md](cursor.md) |
| **Works with limits** | **Gemini CLI** | `BeforeTool` hook (`session_id` + `_meshCall`) | `AfterTool` drain + `AfterAgent` continuation + `hyp wait` | `hyp inspect` / `hyp ui` | [gemini-cli.md](gemini-cli.md) |
| **Experimental** | **OpenClaw** | Managed `openclaw.json` MCP (`--backend openclaw --ephemeral`) | Gateway webhook push (`openclaw-hooks-token`) + `hyp_inbox` turn fallback | `hyp inspect` / `hyp ui` | [openclaw.md](openclaw.md) |
| **Experimental** | **T3 Code** | Read-only `userdata/statev2.sqlite` projection verification | T3 v2 WebSocket RPC (`message.dispatch`) | `hyp inspect` / `hyp ui` | [t3-code.md](t3-code.md) |

## Status UI, Panels & Terminal Inspector

See [Status UI, Panels & TUI](status-ui.md) for the Claude Code native panel, Antigravity `statusLine`, Herdr GPUI mods (`hyphae-pane` / `hyphae-panel` + `pill.js`), and standalone `hyp inspect` / `hyp ui`.
