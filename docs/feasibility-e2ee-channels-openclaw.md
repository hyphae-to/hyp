# Feasibility & Design: End-to-End Encryption, Chat Channels, Bidirectional Bridges & OpenClaw

This document evaluates the engineering feasibility and concrete wire designs for four next-stage capabilities on top of `hyphae` (working brand name: **Patchbay**).

---

## 1. End-to-End Encryption (E2EE) — **High Feasibility (Zero External Deps)**

Node 24's built-in `node:crypto` natively supports **Ed25519**, **X25519** (Curve25519 ECDH), **HKDF-SHA256**, and **AES-256-GCM / ChaCha20-Poly1305**, and `packages/t3-mesh/src/identity/keys.ts` already implements Ed25519 connector identity keys.

### A. Direct Peer Messages (`mesh_send`) — ~1–2 days
- **Key advertisement**: Each connector generates a static X25519 encryption keypair (`encPub`, `encPriv` in `state/` `0600`), signs `encPub` with its Ed25519 identity key, and publishes it to the router. `GET /v1/peers` returns `{ address, identityPub, encPub, encSig }`.
- **Sealed envelope**: Before calling `POST /v1/messages`, the sender generates an ephemeral X25519 keypair, derives a per-message AEAD key via `HKDF-SHA256(X25519(ephPriv, recipientEncPub), salt, info="hyphae-dm-v1|" + from + "|" + to + "|" + msgId)`, and encrypts `text` with `AES-256-GCM` using the envelope metadata as AAD.
- **Router blindness**: Even on a **public or shared team router**, the router sees only routing metadata (`from`, `to`, `id`, timestamp) and opaque ciphertext — never prompts, code snippets, or tool outputs.
- **Compatibility**: Pure additive field (`ciphertext` / `enc: "x25519-aes256gcm-v1"`); plaintext peers continue working unless `requireE2EE: true` is set on the connector.

### B. Event Streams (GitHub / Prometheus) — Hybrid Payload E2EE
- **Tradeoff**: Router-side CloudEvents filtering (`exact`, `prefix`, `suffix` on `type`, `source`, `subject`) requires the router to inspect those header attributes so it doesn't broadcast every repo event to every laptop.
- **Best design**: Keep CloudEvents routing attributes (`topic`, `type`, `source`, `subject`) cleartext for server-side filtering, and encrypt `data` (`datacontenttype: "application/vnd.hyphae.e2ee+json"`) using a topic key wrapped to each authorized subscriber's X25519 public key. For ultra-sensitive small private topics, offer optional full-envelope E2EE with client-side filter evaluation.

---

## 2. Multi-Agent Chat Channels (`#incidents`, `#frontend`) — **High Feasibility (~2–3 days)**

Agents often need shared rooms where multiple sessions across machines collaborate (e.g. `#incidents` with `herdr/oncall`, `t3/backend`, `macbook/agy`, and `gn/openclaw`) without knowing every peer handle in advance.

- **New MCP tools**:
  - `mesh_channel_join({ channel: "#incidents", mode?: "queue" | "interrupt" })`
  - `mesh_channel_leave({ channel: "#incidents" })`
  - `mesh_channel_post({ channel: "#incidents", text })`
  - `mesh_channel_members({ channel: "#incidents" })`
- **Router model**: Reuses the existing `EventRouter` SQLite batch/fan-out engine! Each channel `#name` maps to a router room topic `chan:<name>` with dynamic member-publish ACLs (only joined connectors may publish, plus optional admin/invite-only rooms).
- **E2EE for Channels (Sender Keys / Epoch Keys)**:
  - Each room maintains an `epoch` counter and a random 256-bit room key (or per-sender chain key, Signal/WhatsApp Sender-Keys style).
  - When a member joins, an existing member (or room creator) wraps the current epoch key to the new member's verified X25519 `encPub`.
  - When a member leaves or is revoked, the next sender increments `epoch`, generates a fresh room key, and wraps it only to remaining members (forward/post-compromise secrecy).

---

## 3. Bidirectional Communication Bridges (Telegram, WhatsApp, Slack, BYO Plugin) + Multi-Thread Link/Unlink

Currently connector plugins support inbound fd-3 events + 1:1 `mesh_plugin_handoff`. Extending the fd-3 protocol v1 → v2 adds two lightweight capabilities while remaining 100% backward compatible with existing `t3-mesh` plugins:

### A. Link / Unlink One or More Threads to Any Channel
Replace the single-owner `PRIMARY KEY (plugin, target)` table with a many-to-many `plugin_links (plugin, target, session_id, role, linked_at)` table:
- `mesh_bridge_link({ plugin: "telegram", target: "ops", sessionId? })` — attaches this (or another) thread to receive events from `telegram/ops`. Multiple threads across harnesses (e.g. a Claude researcher + a Codex fixer) can listen simultaneously!
- `mesh_bridge_unlink({ plugin: "telegram", target: "ops", sessionId? })` — detaches one or all threads cleanly at runtime without editing `connector.json` or restarting the daemon.

### B. Outbound Posting (`mesh_plugin_post`) Over fd 3
Add a symmetric daemon → plugin frame on fd 3:
```json
{ "type": "post", "id": "req-1", "target": "ops", "replyTo": "chat:12345", "text": "Fix deployed — p99 latency back to 42ms." }
```
Plugin executes the native API call (Telegram `sendMessage`, WhatsApp Cloud API / Baileys `sendMessage`, Slack `chat.postMessage`, or custom webhook) and replies:
```json
{ "type": "post_ack", "id": "req-1", "ok": true, "externalId": "msg-998" }
```
**Security win**: Agents NEVER see Telegram/WhatsApp/Slack bot tokens — the plugin holds the `0600` secret in an isolated subprocess, enforces per-target channel/user allowlists, and rate-limits outbound posts!

### C. WhatsApp Support
Two clean options fit the exact same fd-3 plugin model:
1. **WhatsApp Cloud API (`builtin: "whatsapp-cloud"`)**: Official Meta webhook + Graph API (`WEBHOOK_SECRET` + `WHATSAPP_TOKEN` in `~/.config/hyphae/secrets/`), zero third-party deps.
2. **OpenClaw Gateway Bridge**: Delegate WhatsApp/Telegram/Discord/Signal session management to an **OpenClaw** Gateway and connect it to the mesh via `openclaw mcp serve` or a tiny fd-3 bridge!

---

## 4. OpenClaw as a Mesh Orchestrator

**OpenClaw** is an open-source self-hosted AI agent gateway supporting multi-channel chat routing (WhatsApp, Telegram, Discord, Slack), `SKILL.md` skills, and bidirectional MCP (`mcp.servers` client + `openclaw mcp serve`).

Pairing **OpenClaw** with `hyphae` creates a clean separation of concerns:
- **OpenClaw** acts as the **high-level orchestrator & human-facing multi-channel gateway** (receiving user requests from WhatsApp/Telegram/Discord or Prometheus/GitHub escalations).
- **`hyphae`** acts as the **authenticated, zero-polling cross-machine execution bus** connecting OpenClaw to live coding threads running on your MacBook (**Antigravity**, **Claude Desktop**, **Cursor**), Linux boxes (**Codex**, **Herdr Core**, **OpenCode**), and **T3 Code** servers.
- **Configuration**: Add `hph mcp` under OpenClaw's `mcp.servers` config + install our bundled `SKILL.md`, and OpenClaw immediately gains `mesh_join`, `mesh_peers`, `mesh_send`, `mesh_subscribe`, and `mesh_plugin_handoff` across your entire fleet.
