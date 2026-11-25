# OpenClaw *(Experimental)*

OpenClaw acts as a human-facing orchestrator while Hyphae links it to coding agent sessions on the same machine or across paired nodes.

## Setup

```sh
hyp setup --harness openclaw
```

What this configures:
- Managed MCP server entry in `~/.openclaw/openclaw.json` (`hyp mcp --backend openclaw --ephemeral`).
- Orchestrator-aware skill in `~/.openclaw/skills/hyphae/SKILL.md` (intentionally avoids duplicating OpenClaw's native `cron`, `HEARTBEAT.md`, or `sessions_send`).

### Optional: Enable OpenClaw Gateway Push Wakeups

To let Hyphae push metadata wakeups directly into OpenClaw Gateway webhooks (instead of relying only on `hyp_inbox` at turn start), store the Gateway hooks token out-of-band and add the `"openclaw"` block in `~/.config/hyphae/node.json`:

```sh
hyp secret set openclaw-hooks-token --web
```

```json
{
  "openclaw": {
    "url": "http://127.0.0.1:18789",
    "hooksPath": "/hooks",
    "agentId": "main",
    "tokenSecret": "openclaw-hooks-token"
  }
}
```

Restart the Hyphae service (`hyp service restart`).

## Current Limitations

- OpenClaw runs with `--ephemeral` MCP identity fallback (no per-tool-call hook injection).
- When `openclaw-hooks-token` is absent, OpenClaw checks `hyp_inbox` once at the start of each gateway turn (never poll in a loop).

## What You Should See

- With `openclaw-hooks-token` configured, inbound DMs/events push wakeups directly to OpenClaw's `/hooks` endpoint; without it, `hyp_inbox` surfaces unread items cleanly on the next turn.

See [Troubleshooting](../operations/troubleshooting.md) if Gateway push fails to attach.
