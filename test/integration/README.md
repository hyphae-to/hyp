# Hyphae End-to-End Integration Test Suite

Comprehensive, zero-cloud-cost integration tests exercising real Hyphae routers, multi-connector daemons, signed webhook streams, bridge plugins, and real installed AI harness CLI binaries on `127.0.0.1`.

## Running

```bash
npm run test:integration
```

Or run a single suite:

```bash
node --test test/integration/network-topology.test.ts
node --test test/integration/webhooks-and-bridges.test.ts
node --test test/integration/real-harnesses.test.ts
node --test test/integration/incident-and-resilience.test.ts
```

## Architecture & Topology

Every test spins up an isolated `MeshTopology` ([harness/topology.ts](./harness/topology.ts)) backed by ephemeral temp directories, `127.0.0.1` `port: 0` bindings, and guaranteed teardown in `finally`:

- **Multi-Router Topology**: Simultaneous **Team/Public Router** + per-user **Private Router(s)** with multiple independent **Connector daemons** (`alex@laptop`, `alice@laptop`, `jack@prod`) joined across them.
- **External Service Shims** ([shims/services.ts](./shims/services.ts)):
  - **GitHub Webhooks**: Signed & tampered `X-Hub-Signature-256` payloads delivered to Hyphae's built-in `github-webhook` stream.
  - **Prometheus / Alertmanager**: Signed & tampered `X-Webhook-Signature-256` alerts delivered to `webhook-stream`.
  - **Mock Slack Socket Mode Server**: Zero-dependency `127.0.0.1` HTTP (`auth.test`, `apps.connections.open`) + RFC 6455 WebSocket server driving the real `plugins/slack/index.mjs` bridge via `SLACK_API_BASE` and `0600` `{ "secret": "..." }` tokens.
  - **Mock Telegram Bot API Server**: Loopback `POST /bot<token>/getUpdates` long-polling server driving the real `plugins/telegram/index.mjs` bridge via `TELEGRAM_API_BASE` and `0600` `{ "secret": "..." }` tokens.
- **Scripted Local LLM API Shims** ([shims/llm.ts](./shims/llm.ts)):
  - `startScriptedAnthropicServer` (`/v1/messages` SSE + JSON, `/v1/messages/count_tokens`) for real `claude` CLI.
  - `startScriptedOpenAIResponsesServer` (`/v1/responses` SSE) for real `codex` CLI and real `opencode` v2 CLI.
  - Deterministic turn-by-turn `TurnContext` helpers (`findTool`, `callTool`, `callOpenCodeTool`, `selectClaudeTools`, `hasText`, `reply`) with full turn transcripts on assertion failure.

## Test Suites

| File | Coverage |
| --- | --- |
| [network-topology.test.ts](./network-topology.test.ts) | Multi-router Team + Private isolation, cross-connector `hyp_send` & `#channels`, all mute targets (`peer`, `connector/*`, `#channel`, `topic:*`, session vs connector scope), slim `notify` mode with real `hyp wait` / `hyp watch` & `hyp_inbox`. |
| [webhooks-and-bridges.test.ts](./webhooks-and-bridges.test.ts) | Built-in `github-webhook` & Prometheus `webhook-stream` (`0600` secrets, 401 bad signature rejection), real built-in Slack Socket Mode & Telegram bridges (allowlists, offset checkpointing, `plugin:*` muting, live `hyp_plugin_handoff`). |
| [real-harnesses.test.ts](./real-harnesses.test.ts) | Real `claude`, `codex`, and `opencode` v2 CLI binaries driven via local LLM shims (including a live cross-connector `claude <-> opencode` conversation!), plus `agy` plugin discovery, `cursor-agent` setup/hooks, and `hc` (Herdr Core) fail-closed check. Missing binaries auto-skip cleanly. |
| [incident-and-resilience.test.ts](./incident-and-resilience.test.ts) | Full multi-owner incident workflow (Prometheus -> `#deploys` -> GitHub PR -> private Slack bridge + live handoff), 6-harness concurrent multiplexing over one shared `hyp mcp` subprocess, router restart/reconnect, stale socket recovery, forged/replayed/cross-tool token rejection, and `0644` secret rejection. |

## Strict Isolation Guarantees

- Tests **never** touch `~/.config/hyphae`, `~/.claude`, `~/.codex`, `~/.gemini`, `~/.config/opencode`, `~/.cursor`, or live Herdr tabs.
- Every real harness CLI is launched with isolated `HOME`, `XDG_CONFIG_HOME`, `XDG_DATA_HOME`, `XDG_CACHE_HOME`, `XDG_STATE_HOME`, `CODEX_HOME`, and stripped `HC_TERMINAL_ID` / `ANTIGRAVITY_SOURCE_METADATA` / `CLAUDE_SESSION_ID` / `CODEX_THREAD_ID`.
- Zero real cloud API calls and zero API token cost.

## Updating Shims When Harness CLIs Upgrade

- **Claude Code (`claude`)**: Configured via `ANTHROPIC_BASE_URL` + `--mcp-config --strict-mcp-config --settings --no-session-persistence`. If Claude changes deferred MCP tool loading or SSE event names, update `selectClaudeTools` or `startScriptedAnthropicServer` in [shims/llm.ts](./shims/llm.ts) and flags in `runRealClaude` ([harness/drivers.ts](./harness/drivers.ts)).
- **Codex CLI (`codex`)**: Configured via `-c model_providers.dummy.base_url=...` + `wire_api="responses"` and isolated `CODEX_HOME`. If Codex updates its Responses API event schema or rollout JSONL format, update `startScriptedOpenAIResponsesServer` in [shims/llm.ts](./shims/llm.ts) or `createRealCodexRunner` ([harness/drivers.ts](./harness/drivers.ts)).
- **OpenCode (`opencode`)**: Configured via `providers.openai.settings.baseURL` in isolated `XDG_CONFIG_HOME/opencode/opencode.json` + `opencode run --standalone --auto`. OpenCode v2 exposes MCP servers through Code Mode (`execute` calling `tools.hyphae.<tool>(args)`) and loads plugins exporting `{ id, setup(ctx) }` with `ctx.tool.hook("execute.before" | "execute.after", ...)`. Update `runRealOpenCode` ([harness/drivers.ts](./harness/drivers.ts)) or `setupOpenCode` (`src/setup.ts`) if OpenCode changes its plugin or provider config schema.
- **Antigravity (`agy`), Cursor (`cursor-agent`), Herdr (`hc`)**: Do not expose a local unauthenticated LLM base-URL override; `real-harnesses.test.ts` verifies real CLI discovery/fail-closed behavior alongside full hook/MCP/waiter protocol tests.
