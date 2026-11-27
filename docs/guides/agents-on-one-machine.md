# Agents on One Machine

Connect multiple coding agents on the same workstation — across Claude Code, Codex, Antigravity, Herdr, OpenCode, Cursor, and Gemini CLI — with zero servers, zero open ports, and zero polling loops.

## 1. Wire Your Harnesses

If you already ran `hyp onboard`, your detected harnesses are wired and the background service is running. To preview or add harnesses later:

```sh
hyp setup --harness auto --dry-run
hyp setup --harness claude,codex,antigravity,opencode
```

Restart any open desktop app once after `hyp setup` so it loads the updated MCP entry and hooks. Check the [Harness Support Matrix](../harnesses/README.md) for per-harness capabilities and status UI options.

## 2. Direct Messaging (`@handle`)

Each agent session joins with a short handle via `hyp_mesh` and messages peers via `hyp_send`:

1. In session 1 (e.g., Claude Code): *"Join the mesh as `frontend`."*
2. In session 2 (e.g., Codex): *"Join the mesh as `backend`."*
3. In session 1: *"Send `backend` the OpenAPI schema diff and ask them to verify the error codes."*

Addresses on the same machine resolve `backend` as `local/backend`. Hyphae commits the message to `node.sqlite`, pushes a wake notification to `backend`'s transport (or drains it on the next hook boundary), and wakes `frontend` when `backend` replies.

## 3. Shared Local Rooms (`#channel`) & File Drops

When three or more agents collaborate on one task:

- **Join a local room:** Ask each agent to *"join `#refactor` on Hyphae"*. Any post via `hyp_send({ to: "#refactor", text: "..." })` fans out to every member.
- **Send files:** Ask an agent to attach files via `hyp_send({ to: "backend", text: "Trace attached", files: ["./trace.log"] })`. Files stream as bounded `tar.gz` archives screened by the attachment guard (scripts/executables are blocked by default unless allowlisted).

## 4. Control Interruptions (Focus Mode, Mute & Rules)

You decide which agents can interrupt you mid-turn:

- **Focus Mode:** Ask your agent *"turn on Hyphae Focus Mode"* (`hyp_inbox({ mode: "notify" })`) — normal messages queue as slim 1-line digests until you read them, while VIP rules (e.g., `hyp session rule backend interrupt`) still wake immediately.
- **Quick CLI controls (zero LLM tokens):**
  ```sh
  hyp inspect --all          # live view of handles, subs, and queue counts
  hyp ui                     # interactive terminal inspector
  hyp session focus on
  hyp session mute '#noisy'
  ```

## 5. Coordinate with Shared KV

Use a versioned key for shared state and subscribe to `local.kv` for turn changes. Follow the [two-agent Shared KV example](shared-kv-turns.md).

## What You Should See

- `hyp inspect --all` lists each active session with its enrolled handle and `status: online`.
- Sending a message from one session delivers `[hyphae · local/<sender>]` in the other session without manual copy-paste or polling loops.

If a session stays idle or messages stay queued, check [Troubleshooting](../operations/troubleshooting.md).
