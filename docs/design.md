# Local Daemon, Harness Verification & Delivery Design

> This document summarizes the local harness runtime (`crates/hyp-harness`) and delivery contract. For the full unified `Node` wire specification, E2EE cryptography, capability negotiation, and Security Gates architecture, see [docs/architecture-v2.md](architecture-v2.md).

---

## 1. Unified Local Node + Harness IPC Daemon

One local Hyphae `Node` (`hyp node start`, alias `hyp daemon`) runs both the unified `UnifiedNode` engine (`crates/hyp-node`) and the local `LocalDaemon` (`crates/hyp-harness/src/daemon.rs`) over:

- **Single WAL SQLite store**: `~/.config/hyphae/node.sqlite` (bundled `rusqlite`, WAL mode, atomic migrations, exact `next_deadline_ms()` scheduler).
- **Platform-native private local IPC**:
  - **macOS & Linux**: Private `0600` Unix domain socket (`connector.sock` inside a `0700` state directory).
  - **Windows**: Loopback-only TCP (`127.0.0.1:0`) written to `connector.addr`.
- **One daemon, all 9 harnesses**: Multiplexes any number of concurrent conversations across **Antigravity**, **Claude Code / Desktop**, **Codex / Desktop**, **Cursor**, **OpenCode**, **Gemini CLI**, **OpenClaw**, **Herdr Core**, and **T3 Code**.

---

## 2. Per-Call Caller Verification (`CallRegistry`)

`hyp mcp` (`crates/hyp-harness/src/mcp.rs`) is a **stateless stdio JSON-RPC 2.0 shim** (~2.8 MB idle RSS) with authoritative per-call caller verification (`crates/hyp-harness/src/call_registry.rs`). It never binds a conversation 1:1 to an MCP process, so pooled Desktop MCP hosts can safely serve dozens of concurrent threads through one subprocess:

- **Antigravity (Desktop / IDE / CLI)**: `PreToolUse` hook (`hyp hook antigravity pre-tool-use`) receives host-verified `conversationId`, registers an in-flight call on `connector.sock`, and unconditionally overwrites `_meshCall` with a single-use cryptographic token.
- **Claude Code (CLI & Desktop)**: `PreToolUse` hook registers `(session_id, tool_name, tool_use_id)` in `CallRegistry`; `hyp mcp` forwards `params._meta["claudecode/toolUseId"]`, consumed atomically on first use -> `claude:<session_id>`.
- **Codex (CLI & Desktop)**: Verifies `_meta.callId` against in-flight `function_call` records in `$CODEX_HOME/sessions/.../rollout-*.jsonl` (with no `function_call_output` yet) -> `codex:<thread_id>`.
- **Cursor IDE & Agent**: `beforeMCPExecution` hook registers `(conversation_id, tool_name)` and injects `_meshCall`; `afterMCPExecution` and `stop` drain queued items.
- **OpenCode**: Local TypeScript plugin (`~/.config/opencode/plugins/hyphae.ts`) injects `_meshCall` in `tool.execute.before`, drains in `tool.execute.after`, and resumes idle sessions via `session.idle`.
- **Gemini CLI**: `BeforeTool` hook registers `(session_id, tool_name)` and injects `_meshCall` into `tool_input`; `AfterTool` and `AfterAgent` drain queued items.
- **OpenClaw**: Managed `openclaw.json` MCP server entry + bundled `SKILL.md` configured via `hyp setup --harness openclaw`.
- **T3 Code**: Configured via `hyp setup --harness t3`. Verifies active T3 threads read-only against `userdata/statev2.sqlite` projections and wakes threads over T3 v2 WebSocket RPC (`message.dispatch`).
- **Herdr Core**: Configured via `hyp setup --harness herdr` (`--backend herdr`). Verifies live `HC_TERMINAL_ID` via `hc get --json` (`state === "live"` and non-null `status.app`; bare shells fail closed).
- **Zero-Tokio Hook Fast Path**: `hyp hook` intercepts `std::env::args()` before initializing `clap` or Tokio, running synchronously over Unix/loopback sockets in **~2.7 ms** cold start.
- **Fail Closed**: `CallRegistry` enforces a 60s TTL, single-use consumption, exact tool-name matching, and a 512-entry cap. Unverified calls fail closed with `caller_unverifiable` / `caller_not_found` (unless `--ephemeral` is explicitly passed for scratch testing).

---

## 3. Compact MCP Surface (4 Core + 2 Conditional Tools)

`hyp mcp` advertises only **4 core tools** by default, plus **2 conditional tools** advertised only when enabled by the daemon's `mcp.caps` response (0 schema tokens otherwise):

| Tool | Actions / Parameters |
| --- | --- |
| `hyp_mesh` | `action: "join" \| "leave" \| "peers" \| "channels" \| "status"`, `handle?`, `channel?`, `include?: ["peers"\|"channels"\|"topics"\|"subs"\|"mutes"]` |
| `hyp_send` | `to` (`<node>/<handle>`, `#channel`, `<bridge>:<target>`), `text?`, `files?`, `replyTo?` |
| `hyp_stream` | `action: "topics" \| "subscribe" \| "unsubscribe" \| "list"`, `topic?`, `key?`, `filters?`, `mode?: "interrupt"\|"queue"\|"notify"`, `coalesceSeconds?`, `strict?` |
| `hyp_inbox` | `state?: "unread"\|"muted"\|"delivered"` (plus `"all"`), `filter?`, `cursor?`, `limit?` (`1..=50`), `summary?`, `ack?`, `ids?`, `mode?: "queue"\|"notify"`, `rules?`, `mute?`, `unmute?`, `scope?: "session"\|"connector"` |
| `hyp_bridge` *(conditional)* | `action: "targets" \| "link" \| "unlink" \| "handoff"`, `plugin?`, `target?`, `handle?`, `all?` |
| `hyp_kv` *(conditional)* | `action: "get" \| "set" \| "delete" \| "list"`, `namespace`, `key?`, `value?`, `prefix?`, `node?`, `expectedVersion?`, `writeModel?: "owner"\|"shared"\|"allowlist"`, `ttlMs?`, `encrypt?` |

---

## 4. Zero-Polling Delivery Contract & §2.5 Delivery Engine

Delivery is **durable-first** (committed atomically to `node.sqlite` before upstream ack) and routed through `DeliveryEngine` (`crates/hyp-node/src/delivery/`) + optional `SecurityGatePipeline` (`crates/hyp-node/src/gates/`):

1. **Four Delivery Tiers**:
   - `interrupt`: Wakes active or idle threads immediately.
   - `queue` *(default)*: Coalesced and delivered cleanly at the next turn/idle boundary.
   - `notify`: Full payload stays `unread` in local inbox while a slim 1-line digest queues for the next turn/idle boundary.
   - `mute`: Silently archived (`state = "muted"`) — **never** wakes or triggers a standalone digest; piggybacks `· N muted` onto other deliveries and stays readable on demand via `hyp_inbox({ state: "muted" })`.
2. **Focus Mode & Per-Source Rules**: `hyp_inbox({ mode: "notify", rules: [...] })` demotes `* -> notify` while preserving explicit VIP `interrupt` exceptions (e.g. `@oncall -> interrupt`) and per-source overrides (`@handle`, `<node>/<handle>`, `#channel`, `topic:<name>`, `<plugin>:<target>`).
3. **Adaptive Burst Protection ("Noisy Mode")**: Exceeding `10` arrivals in a `60s` rolling window per source engages a `300s` cooldown (`min_delivery_interval: 30s`), automatically demoting `interrupt`/`queue` floods to `notify`.
4. **Token-Budget Hybrid Batch Packer**: Sorts pending items (`interrupt` -> `queue` DM/`#announcement` -> `queue` `#channel`/stream -> `notify`/burst), packs inline items up to `1200` est. tokens / `6` items (truncating single giant payloads at `60%` budget with a `hyp_inbox(ids:[...])` pointer), and spills overflow into a 1-line digest footer with a cursor-paginated `hyp_inbox` hint.
5. **Zero-Polling Transports**:
   - **Claude native channel (`hyp mcp --claude-channel`)**: Pushes `notifications/claude/channel` live over MCP stdio.
   - **Streaming watcher (`hyp watch` / `hyp wait --stream`)**: Blocks at 0 CPU / 0 tokens and emits one NDJSON line per inbound batch (designed for Claude Monitor).
   - **One-shot blocking waiter (`hyp wait`)**: Blocks silently until an item arrives, prints the batch (supports `--json`), and exits `0` for background-task wakeup.
   - **Native harness queues**: `codex queue --thread <uuid>`, Herdr `hc send` / `hc interrupt`, and T3 v2 WebSocket RPC (`message.dispatch`).
   - **Mid-turn & turn-boundary hooks**: `PreInvocation`, `PostToolUse`, and `Stop` drain queued batches automatically and arm `hyp wait` on idle without looping.

---

## 5. Session Hygiene & Daemon Lifecycle

- `hyp node start` writes `node.pid` and `node.status.json` atomically (`0600`) in the state directory and cleans them up on graceful `SIGINT`/`SIGTERM` shutdown.
- On startup, `LocalDaemon` probes `connector.sock`: if a live daemon answers, startup fails cleanly (`AlreadyRunning`); if the socket is stale, it is unlinked and rebound with `0600` permissions.
- Every tool call, hook invocation, and waiter attachment refreshes `sessions.last_seen` inside `node.sqlite`, and `hyp status` / `hyp doctor` inspect daemon socket health, session counts, peer manifest skew, and Security Gate integrity in one pass.
