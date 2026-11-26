# OpenClaw

OpenClaw acts as a human-facing orchestrator while Hyphae links it to coding agent sessions on the same machine or across paired nodes.

## Setup

```sh
hyp setup --harness openclaw
```

What this configures:
- Official zero-dependency OpenClaw plugin in `~/.openclaw/extensions/hyphae/` (`openclaw.plugin.json` + `index.js`) providing:
  - Scoped `before_tool_call` / `after_tool_call` hooks that bind every Hyphae MCP call to the exact OpenClaw `(agentId, sessionKey)` via single-use `_meshCall` tokens (no `--ephemeral` split-brain).
  - Native `hyphae-wake` Gateway service (`api.registerService`) delivering metadata-only wakeups directly into the exact existing `(agentId, sessionKey)` session via `enqueueSessionEvent` (strictly without `createIfMissing`, never spawning isolated cron jobs).
  - Optional `before_prompt_build` turn-start context injection (`--openclaw-prompt-injection`) and observational `agent_end` / `run_stopped` Queue flushing.
- Managed MCP server entry in `~/.openclaw/openclaw.json` (`hyp mcp --backend openclaw`).
- Orchestrator-aware skill in `~/.openclaw/skills/hyphae/SKILL.md` (intentionally avoids duplicating OpenClaw's native `cron`, `HEARTBEAT.md`, or `sessions_send`).

### Optional Fallback: OpenClaw Gateway `/hooks/wake` Webhook

With the `hyphae` plugin active in OpenClaw Gateway, live exact-session wakeups work automatically over local `connector.sock` with **no webhook token required**.

If you also want standalone `/hooks/wake` webhook fallback when the plugin service is not connected, store the Gateway hooks token out-of-band and configure `"openclaw"` in `~/.config/hyphae/node.json`:

```sh
hyp secret set openclaw-hooks-token --web
```

```json
{
  "openclaw": {
    "url": "http://127.0.0.1:18789",
    "hooksPath": "/hooks",
    "mode": "wake",
    "agentId": "main",
    "tokenSecret": "openclaw-hooks-token"
  }
}
```

Restart the Hyphae service (`hyp service restart`). Note: if routing non-main sessions over `/hooks/wake`, enable `hooks.allowRequestSessionKey: true` in `~/.openclaw/openclaw.json` so OpenClaw accepts per-session `sessionKey` targeting.

## Multi-Session Isolation

- Each OpenClaw session (`agent:main:main`, `agent:main:explicit:thread-2`, `agent:ops:main`, etc.) maps deterministically to its own Hyphae session ID (`openclaw:<sessionKey>`).
- Concurrent OpenClaw sessions enroll independent handles, maintain separate mailboxes, and never drain or impersonate each other's messages.
- If a target OpenClaw session is closed or deleted before wakeup, Hyphae fails cleanly without creating a ghost session and preserves unread messages durably in SQLite.

See [Troubleshooting](../operations/troubleshooting.md) if Gateway wakeups fail to attach.
