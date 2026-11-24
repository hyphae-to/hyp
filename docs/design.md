# Connector and session design

A connector daemon is the single local authority for a router identity. One shared daemon per OS user multiplexes **any number of agent threads/conversations across harnesses** (`antigravity`, `claude`, `codex`, `herdr`) over a private user-only Unix socket (`connector.sock`) and SQLite database (`state.sqlite`). A T3 Code instance uses its native daemon in [packages/t3-mesh](../packages/t3-mesh) with its own router connector ID.

## Per-call caller verification (never 1:1 per MCP process)

Inspired directly by [t3-mesh's caller verification](../packages/t3-mesh/SPEC.md#3-caller-verification), `hyp mcp` is a **stateless stdio shim**. It does not invent a per-process UUID or assume one MCP subprocess equals one conversation. One shared MCP subprocess (such as Antigravity's Language Server or a pooled desktop MCP host) can safely serve dozens of concurrent threads:

- **Antigravity (Desktop / IDE / CLI)**: `PreToolUse` receives the host-verified `conversationId` and `toolCall.id` on stdin, registers the in-flight call with `connector.sock`, and returns `"overwrite": { "_meshCall": "<single-use-token>" }`. Because `PreToolUse` unconditionally overwrites `_meshCall` before execution, the model cannot forge or replay another conversation's token. The MCP shim strips `_meshCall` and forwards it to the daemon, which consumes the token and binds the call to `antigravity:<conversationId>`.
- **Claude Code (CLI & Desktop Code tab)**: `PreToolUse` receives host-verified `{ session_id, tool_use_id, tool_name }` and registers the in-flight call in the daemon's `CallRegistry`. The MCP shim forwards `params._meta["claudecode/toolUseId"]`, which the daemon verifies against the exact tool name and consumes on first use → `claude:<session_id>`.
- **Codex (CLI & Desktop)**: Codex flushes each `function_call` item (`call_id` + tool name) to `$CODEX_HOME/sessions/.../rollout-*.jsonl` before dispatching the MCP tool call, and sends `params._meta.callId` to the MCP shim. Even if `PreToolUse` hooks are not active, the daemon verifies the in-flight `call_id` directly against recent rollout files (matching exact tool name with no `function_call_output` yet) → `codex:<thread_id>`. Zero manual `--thread <UUID>` flags are needed, and N concurrent Codex threads share one static config.
- **Herdr Core**: Explicitly configured with `hyp mcp --backend herdr`. Reads `HC_TERMINAL_ID` and verifies the live Core terminal's `address`, `created_ms`, `pid`, and `status.app` via `hc get --json`.
- **Fail closed**: Any MCP call without a verified caller fails closed with `caller_unverifiable` or `caller_not_found` (unless `--ephemeral` is explicitly passed for scratch tests).

## Zero-polling delivery contract

Desktop hosts (Antigravity 2.0, Claude Desktop Code tab, Codex Desktop) own their internal UI state and do not expose an external prompt-injection RPC like T3's WebSocket server. To avoid burning tokens polling `hyp_inbox`, delivery is **durable-first** (committed atomically to SQLite `mailbox` with router ack) and pushed immediately through the best available transport:

1. **Live native channel (`--claude-channel`)**: In Claude Code CLI, once a verified `claude:<session_id>` calls through a channel-enabled MCP socket, the daemon binds that socket as the live delivery transport and pushes `notifications/claude/channel`, draining any items queued while offline.
2. **Streaming watcher (`hyp watch`)**: Connects to `connector.sock`, blocks silently with 0 CPU / 0 tokens, and flushes one NDJSON line per inbound item—designed for Claude Code's `Monitor` tool.
3. **One-shot blocking waiter (`hyp wait`)**: Connects to `connector.sock` (auto-inferring `antigravity:<conversationId>` from `ANTIGRAVITY_SOURCE_METADATA`), blocks silently until ≥1 item arrives, prints the formatted payload, and exits `0`—triggering Antigravity's native reactive background-task wakeup (`run_command`, `WaitMsBeforeAsync: 500`, `IsDaemon: false`) or Claude's `Bash(run_in_background=true)`.
4. **Native Codex queue**: Codex threads resolved from rollout JSONLs dispatch directly via `codex queue --thread <uuid>` (with optional `--remote ws://...` / `unix://...` for a shared `codex app-server`), holding cleanly if the binary or target daemon is temporarily unavailable.
5. **Mid-turn & turn-boundary hook drain (`PreInvocation` / `PostToolUse` / `Stop`)**: Any item arriving while an agent is mid-turn (before a waiter is re-armed) is drained immediately on the next hook boundary and injected via `injectSteps`, `additionalContext`, or `Stop` continuation (`continue` / `block`).
6. **Self-healing waiter arming**: On `Stop`, if an Antigravity or Claude session is enrolled (holds a handle or subscription) and has no active push transport attached—and `continuationActive` / `stop_hook_active` is `false` so it never loops—the hook prompts once to start `hyp wait` / `hyp watch` before going idle.

## Session hygiene & socket lifecycle

- On startup, the daemon probes `connector.sock`: if a live daemon answers, startup fails cleanly; if the socket is stale (`ECONNREFUSED`), it is unlinked and rebound with user-only permissions.
- Every tool call, hook invocation, and waiter attachment refreshes `sessions.last_seen`. A periodic sweep (and `hyp prune`) removes stale inactive sessions, their subscriptions, and their handles from the router while never pruning sessions with an active push transport.
