# Hyphae

One local connector daemon per OS user connects any number of independent agent threads across harnesses (**Antigravity**, **Claude Code CLI & Desktop**, **Codex CLI & Desktop**, **Cursor**, **OpenCode**, **Gemini CLI**, **Herdr Core**, and native **T3 Code**) to one or more routers. Every MCP tool call is verified **per call** against the real host thread/conversation ID (never 1:1 per MCP process), and inbound messages/events are pushed automatically without polling `mesh_inbox`.

| Runtime | Per-call thread/session identity | Zero-polling push delivery | Modes |
| --- | --- | --- | --- |
| **Antigravity Desktop / IDE / CLI** | `PreToolUse` hook (`conversationId` + single-use `overwrite` token) | `PreInvocation`/`Stop` hook drain while active; blocking `hyp wait` background task wakes idle conversations automatically | `queue` |
| **Claude Code CLI & Desktop (Code tab)** | `PreToolUse` hook (`session_id` + `_meta["claudecode/toolUseId"]`) | `PostToolUse`/`Stop` hook drain while active; `Monitor` (`hyp watch`) or `Bash(run_in_background=true)` (`hyp wait`) for idle wakeup; optional `--claude-channel` in CLI | `queue` |
| **Codex CLI & Desktop** | In-flight rollout JSONL verification (`$CODEX_HOME/sessions/.../rollout-*.jsonl` matching `_meta.callId`, mirroring `t3-mesh`) + optional `PreToolUse` hook | Native `codex queue --thread <uuid>` (and `--remote` for shared `app-server`); `PostToolUse`/`Stop` hook drain when hooks are active | `queue` |
| **Cursor IDE & Agent** | `beforeMCPExecution` hook (`conversation_id`) in `~/.cursor/hooks.json` | `afterMCPExecution` context drain + `stop` hook `followup_message` continuation + background `hyp wait` | `queue` |
| **OpenCode** | Local plugin (`~/.config/opencode/plugins/hyphae.ts`) injects single-use `_meshCall` token in `tool.execute.before` | `tool.execute.after` drain + `session.idle` prompt injection via OpenCode SDK client | `queue` |
| **Gemini CLI** | `BeforeTool` hook (`session_id` + `tool_input._meshCall`) in `~/.gemini/settings.json` | `AfterTool` `additionalContext` drain + `AfterAgent` continuation + background `hyp wait` | `queue` |
| **Herdr Core** | Explicit `--backend herdr` with `HC_TERMINAL_ID`, verified via `hc get` (PID + `created_ms` + `app`) | `hc send` when ready; `hc interrupt` + `hc send` for `interrupt` | `queue`, `interrupt` |
| **T3 Code** | Native `packages/t3-mesh` connector verifies `_meta` call IDs against T3's live thread projection | Native T3 `message.dispatch` (steer / queue / restart) | `queue`, `interrupt` |

The `primary` router carries peer messages and events. Additional routers carry only the subscriptions explicitly assigned to them. See [onboarding guide](docs/onboarding.md), [connector and session design](docs/design.md), [event publishers and plugins](docs/plugins.md), and [security model](docs/security.md).

## Quickstart

Requires **Node 24+** on macOS or Linux (`mise` activates Node 24 automatically via `.node-version`).

### Interactive / Local Quickstart (1 command)

```sh
npm ci && npm run build
./bin/hyphae.mjs onboard
```

In an interactive terminal, `hyp onboard` launches a `@clack/prompts` TUI with arrow-key selectors, checkbox multi-selects, and spinners: it scans **Antigravity**, **Claude**, **Codex**, **Cursor**, **OpenCode**, **Gemini CLI**, **Herdr Core** (and its remote machines), **T3 Code** (`~/.t3-mesh`), and **Tailscale**, lets you select harnesses and optional built-in plugins (**Slack**, **Telegram**, **Webhook**), configure Tailscale exposure, and probe & onboard reachable remote machines over SSH. Pass `--yes` for non-interactive single-machine setup.

### Universal Plugins, Router Data Streams & Secrets

- **Router Data Streams (`localRouter.streams`)**: Feed **GitHub webhooks** (`github-webhook`), **signed webhooks** (`webhook-stream`), or **custom fd-3 data source scripts** directly into router topics so any agent on any machine subscribes with CloudEvents filters (`mesh_subscribe`).
- **Connector Thread Bridges (`plugins`)**: Bridge 3rd-party messaging tools (**Slack** Socket Mode, **Telegram** long-polling, **local webhooks**, or existing `t3-mesh` Python plugins) directly to an owning agent handle across **any** harness, with live `mesh_plugin_targets` / `mesh_plugin_handoff`.
- **Private Secrets Store (`hyp secret`)**: Store tokens/keys in `~/.config/hyphae/secrets/` (`0600`) and reference them via `{ "secret": "<name>" }` — never plaintext in `connector.json`. Run `hyp plugin setup` or see [docs/plugins.md](docs/plugins.md).

### Multi-machine over Tailscale / VPN

On the router host, expose the loopback router privately on your tailnet (Tailscale Service with its own TailVIP/DNS name, or node-scoped Serve) and generate a one-shot invite:

```sh
./bin/hyphae.mjs router expose tailscale --service hyphae   # https://hyphae.<tailnet>.ts.net
./bin/hyphae.mjs router invite user@remote-host                   # prints `hyp onboard --join <<< 'am1_...'`
```

On the remote machine, run the printed command (pre-flight checks HTTPS + auth before writing `0600` credentials):

```sh
./bin/hyphae.mjs onboard --join --install-service <<< 'am1_...'
```

For plain WireGuard / HTTPS reverse proxies (`--router https://... --token-file ...`), secondary event routers, and revocation, see [docs/onboarding.md](docs/onboarding.md).

Verify everything anytime with:

```sh
./bin/hyphae.mjs doctor    # checks Node 24, config, daemon, live router reachability/auth, and harness configs
./bin/hyphae.mjs status
./bin/hyphae.mjs sessions
```

## How agents use it

1. Call `mesh_join` with a short handle (e.g. `frontend`, `ops`) to claim `<connector>/<handle>`.
2. Call `mesh_peers` to discover enrolled agents and `mesh_send` to message them.
3. Call `mesh_subscribe` with a key, topic, and CloudEvents filters (optional `router` and `mode`).
4. **No polling**: while active, hooks inject arriving messages mid-turn or at turn end; when enrolled and going idle, Antigravity and Claude `Stop` hooks automatically prompt the session once to arm `hyp wait` / `hyp watch` in the background (0 CPU, 0 tokens while idle) so arriving messages wake the conversation live.

## CLI reference

```sh
hyp onboard [--id <user@host>] [--join | --router <https://...> --token-file <file>] [--port <n>] [--replace] [--offline] [--no-start] [--install-service]
hyp init [config] --id <user@host> --router <origin> --token-file <file>
hyp daemon [config] [--socket <path>]
hyp setup <antigravity|claude|codex|cursor|opencode|gemini|all|service> [--scope user|project] [--dir <path>] [--install] [--channel] [--no-sidecar] [--remote <addr>]
hyp mcp [socket] [--claude-channel] [--backend herdr] [--thread UUID] [--resume] [--remote <addr>] [--ephemeral]
hyp hook <antigravity|claude|codex|cursor|opencode|gemini> <pre-tool-use|post-tool-use|pre-invocation|stop> [--socket <path>]
hyp wait [--session <id> | --handle <handle>] [--socket <path>] [--timeout <sec>]
hyp watch [--session <id> | --handle <handle>] [--socket <path>] [--timeout <sec>]
hyp status | sessions | prune [--older-than-hours <n>] | doctor
hyp plugin <setup|list|guide [name]> [--config <path>]
hyp stream <add|list|guide [name]> [--config <path>]
hyp secret <set <name>|list|rm <name>|check [config]>
hyp router expose tailscale [--service <name>] [--port 8790] [--https <port>] [--dry-run]
hyp router unexpose tailscale [--service <name>] [--https 8790]
hyp router invite <user@host> [--router https://...] [--db <router.sqlite>]
hyp router <serve|add-connector|revoke-connector|add-publisher|revoke-publisher|github-receiver>
```

## Tests

```sh
npm run typecheck          # Strict TypeScript check
npm test                   # Fast unit + multi-session + real t3-mesh router integration tests
npm run test:harnesses     # Local integration tests against REAL installed `claude`, `codex`, and `agy` binaries using local dummy LLM API servers (zero API cost / zero cloud calls)
npm run build              # Compile to dist/
```
