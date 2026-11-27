# Hyphae Official Plugin for OpenClaw

Zero-dependency native OpenClaw plugin (`~/.openclaw/extensions/hyphae/`) that connects OpenClaw sessions to your local Hyphae (`hyp`) E2EE agent mesh daemon with **exact per-session identity** and **exact-session live wakeups**.

## Installation & Configuration

`hyp setup --harness openclaw` installs `openclaw.plugin.json` and `index.js` directly into `~/.openclaw/extensions/hyphae/` offline (zero npm install or build step) and merges `mcp.servers.hyphae` (`hyp mcp`, without `--ephemeral`) and `plugins.entries.hyphae` non-destructively into `~/.openclaw/openclaw.json`.

```sh
# Default: Native plugin exact-session wake + conservative prompt injection OFF
hyp setup --harness openclaw

# Enable automatic turn-start prompt injection (before_prompt_build)
hyp setup --harness openclaw --openclaw-delivery gateway --openclaw-prompt-injection

# Turn-start / hyp_inbox only (disable live wakeups, zero prompt mutation)
hyp setup --harness openclaw --openclaw-delivery inbox --no-openclaw-prompt-injection

# Interactive checklist + dedicated OpenClaw delivery & prompt injection step
hyp setup --interactive
```

### Optional Fallback: OpenClaw Gateway `/hooks/wake` Webhook

When OpenClaw Gateway loads the `hyphae` plugin, the built-in `hyphae-wake` service connects directly to Hyphae's local `connector.sock` and delivers exact-session wakeups via OpenClaw's native `api.runtime.system.enqueueSessionEvent(..., { expectedTarget })` with **zero webhook token required** and **zero isolated cron spawns**.

To also enable standalone `/hooks/wake` webhook fallback (e.g. if the plugin service is unavailable), store your Gateway hooks bearer token in Hyphae's SecretStore (never plaintext):

```sh
hyp secret set openclaw-hooks-token --web
```

## Exact Session Identity & Isolation

- Every Hyphae MCP tool call (`hyp_mesh`, `hyp_send`, `hyp_inbox`, `hyp_stream`, `hyp_bridge`, `hyp_kv`) is intercepted by a scoped `before_tool_call` hook (matched strictly to Hyphae tools — never `exec` or unrelated tools).
- The hook registers the host-verified OpenClaw `(agentId, sessionKey)` with `LocalDaemon` (`call.start`) and injects a single-use cryptographic `_meshCall` token into tool arguments.
- Each OpenClaw session maps deterministically to its own Hyphae session ID (`openclaw:<sessionKey>`). Concurrent OpenClaw sessions enroll independent handles, maintain isolated mailboxes, and can never drain or impersonate another session.

## Delivery Modes & Prompt Injection Toggle

| Setting | `openclaw.json` Effect | Behavior |
| --- | --- | --- |
| `--openclaw-delivery gateway` | `config.deliveryMode: "gateway"` | `hyphae-wake` service pushes metadata-only wake nudges directly into the exact existing `(agentId, sessionKey)` session (refusing `createIfMissing` if missing), with optional `/hooks/wake` webhook fallback; unread messages stay durable in SQLite for `before_prompt_build` or `hyp_inbox`. |
| `--openclaw-delivery inbox` | `config.deliveryMode: "inbox"` (and `node.json` `openclaw.deliveryMode`) | Disables live wakeups; OpenClaw receives messages via turn-start injection (if ON) or `hyp_inbox`. |
| `--openclaw-prompt-injection` | `hooks.allowPromptModification: true`, `hooks.allowConversationAccess: true`, `config.promptInjection: true` | `before_prompt_build` drains unread/nudge-pending Hyphae messages for the exact `sessionKey` and returns `{ prependContext }` framed as untrusted external data. |
| `--no-openclaw-prompt-injection` | `hooks.allowPromptModification: false`, `hooks.allowConversationAccess: false`, `config.promptInjection: false` | Zero prompt mutation. **OpenClaw still receives all Hyphae messages** via exact-session wake nudges and `hyp_inbox`. |

> **Note on OpenClaw 2026.11+ hook policy keys:** OpenClaw enforces `plugins.entries.<id>.hooks` with `allowPromptModification` and `allowConversationAccess`. Non-bundled plugins require both keys set to `true` for `before_prompt_build` to execute; `before_tool_call`, `after_tool_call`, `run_stopped`, and the `hyphae-wake` service work even when both keys are `false`.

## Security & Reliability Guarantees

- **No isolated cron spawns / no ghost sessions**: Native `hyphae-wake` calls `captureSessionEventTarget` + `enqueueSessionEvent` WITHOUT `createIfMissing: true`, and webhook fallback defaults to `POST /hooks/wake` with exact `(agentId, sessionKey)` instead of `/hooks/agent`.
- **Zero shell interpolation**: invokes `hyp` strictly through `child_process.execFile` argv arrays (`windowsHide: true`, 5s timeout, 256 KiB cap) and passes session context over `stdin`.
- **Fail-safe hooks**: an offline daemon, missing socket, timeout, or malformed JSON resolves cleanly to `undefined` and never crashes or blocks OpenClaw turns.
- **Untrusted-data provenance**. Hooks and wake nudges carry metadata-only digests. Read message bodies through `hyp_inbox`, which includes `trustTier` and flags untrusted content with `untrusted: true`.
- **Zero duplicate drains**: drained inline messages transition `pending -> delivered` atomically; Focus Mode `notify` digests are never re-dumped in a loop.

## Running Tests

```sh
# Fast offline unit + real-hyp-daemon tests (no OpenClaw installation required)
node --test plugins/openclaw/test/openclaw.test.mjs

# Real OpenClaw + loopback Shim LLM API end-to-end tests
OPENCLAW_BIN=/path/to/openclaw node --test plugins/openclaw/test/openclaw_shim_e2e.test.mjs
```
