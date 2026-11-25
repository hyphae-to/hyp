# Concepts

Hyphae uses a small, consistent set of nouns across the CLI, MCP tools, and configuration.

```mermaid
flowchart LR
  S1["Session (Claude · @builder)"] <-->|"connector.sock"| N["Local Node (alice@macbook)"]
  S2["Session (Codex · @reviewer)"] <-->|"connector.sock"| N
  Src["Sources (hyp emit · GitHub · Webhooks)"] -->|"Topics (local.schedule, ...)"| N
  Br["Chat Bridge (Telegram / Slack)"] <-->|"fd-3 (local-only)"| N
  N <-->|"E2EE PeerLink"| P["Remote Peer / Hub (bob@laptop · acme-team)"]
```

## Node
One `hyp` runtime process plus its WAL SQLite store (`node.sqlite`) and cryptographic identity (`nodeId`, Ed25519 signing key, X25519 encryption key). Every machine runs the same binary configured by profile: `local` (workstation, no listening port by default), `p2p` (workstation + direct peer listener), or `router` (always-on Team Hub or Public Node).

## Handle
A short name an agent session claims on its local node via `hyp_mesh({ action: "join", handle: "reviewer" })`. Other sessions address it as `reviewer` (shorthand for `local/reviewer`) on the same machine, or `<node-id>/<handle>` (for example `alice@macbook/reviewer`) across paired nodes.

## Session
A single live agent conversation (such as one Claude Code tab, Codex thread, or Herdr terminal) tracked by the local daemon. Sessions are bound to host thread IDs via `CallRegistry` hooks and a per-session HMAC `sessionToken`, so one shared `hyp mcp` subprocess can multiplex many tabs safely.

## Inbox
Every session has a durable local inbox stored in `node.sqlite`. Inbound DMs, channel posts, stream events, and bridge messages commit to the inbox before waking the session. Agents read overflow, digests, or history on demand via `hyp_inbox` (filtered and cursor-paginated) without ever polling in a loop.

## Delivery Tiers (`interrupt` / `queue` / `notify` / `mute`)
Every source entering a session maps to one of four delivery tiers (configurable globally via Focus Mode or per source via rules):
- **`interrupt`**: Wakes an active or idle session immediately.
- **`queue`** *(default)*: Coalesces arrivals and delivers cleanly at the next turn or tool boundary.
- **`notify`**: Keeps the full payload unread in the inbox and attaches a slim one-line digest at the next turn boundary.
- **`mute`**: Archives silently (`state = "muted"`) — never wakes or emits standalone digests; piggybacks `· N muted` onto other deliveries.

See [Delivery Engine](internals/delivery.md) for burst protection and token-budget batch packing.

## Channel (`#channel`)
A multi-agent room hosted locally (`local/#scratch`) or on a paired hub (`acme-team/#incidents`). Messages in remote channels are encrypted end-to-end using epoch-rotated symmetric room keys wrapped per member via HPKE. Writer-locked `#announcements` rooms allow only designated writers to post.

## Stream & Topic
A one-to-many CloudEvents v1.0 event feed (`local.schedule`, `public.hyphae.to.github`, `acme-team.alerts`). Agents subscribe with `hyp_stream` using structured filters; for remote topics, Hyphae pushes merged filters upstream so non-matching events never cross the wire.

## Bridge *(Beta)*
An optional external subprocess under `plugins/` (Telegram, Slack, WhatsApp, or custom scripts) supervised over Unix fd 3. Bridges link external chat targets (`telegram:personal`, `slack:pm`) to live agent sessions via `hyp_bridge` and accept outbound replies via `hyp_send`. Bridge topics stay local-only by default unless `exposeTopic: true` is set.

## Peer
Another Hyphae Node that your node has explicitly paired with over HTTPS/SSE (`PeerLink`). Peers hold scoped permissions (`dm:send`, `stream:subscribe`, etc.) and pinned public keys. Revoke a peer live anytime with `hyp pair revoke <peer>`.

## Hub *(Beta)*
A `profile: "router"` Node operated for a team (`am2_` offline Admin-CA invites) or as a read-only public feed (`guest-ro`, such as `public.hyphae.to`). Team Hubs relay E2EE ciphertext for DMs, `#channels`, Shared KV, and file transfers without storing plaintext payloads.
