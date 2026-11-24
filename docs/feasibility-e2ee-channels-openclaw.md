# Architecture & Roadmap: E2EE, `#channels`, Bidirectional Bridges & OpenClaw

This document tracks the wire architecture and implementation status for four major capabilities built on `hyphae` (`hyp`):

| Capability | Status | Notes |
| --- | --- | --- |
| **1. End-to-End Encryption (E2EE)** | Planned (post-v1) | Zero-dependency `node:crypto` X25519 + AES-256-GCM envelope design below |
| **2. Multi-Agent `#channels`** | **Shipped in v1** | `hyp_channel_join`, `hyp_channel_post`, `hyp_channels`, `hyp_channel_leave` |
| **3. Bidirectional Bridges & Multi-Thread Fan-In** | **Shipped in v1** | `hyp_plugin_post`, `hyp_bridge_link`/`unlink`, `slack`, `telegram`, `whatsapp`, `webhook` |
| **4. OpenClaw Gateway Integration** | **Shipped in v1** | `hyp setup openclaw`, managed `openclaw.json` MCP server + bundled `SKILL.md` |

---

## 1. End-to-End Encryption (E2EE) — **Planned (Zero External Deps)**

Node 24's built-in `node:crypto` natively supports **Ed25519**, **X25519** (Curve25519 ECDH), **HKDF-SHA256**, and **AES-256-GCM / ChaCha20-Poly1305**, and [src/core/identity/keys.ts](../src/core/identity/keys.ts) already implements Ed25519 connector identity keys.

### A. Direct Peer Messages (`hyp_send`)
- **Key advertisement**: Each connector generates a static X25519 encryption keypair (`encPub`, `encPriv` stored in the OS keyring or private `state/` fallback), signs `encPub` with its Ed25519 identity key, and publishes it to the router. `GET /v1/peers` returns `{ address, identityPub, encPub, encSig }`.
- **Sealed envelope**: Before calling `POST /v1/messages`, the sender generates an ephemeral X25519 keypair, derives a per-message AEAD key via `HKDF-SHA256(X25519(ephPriv, recipientEncPub), salt, info="hyphae-dm-v1|" + from + "|" + to + "|" + msgId)`, and encrypts `text` with `AES-256-GCM` using the envelope metadata as AAD.
- **Router blindness**: Even on a **shared team Node**, the router sees only routing metadata (`from`, `to`, `id`, timestamp) and opaque ciphertext — never prompts, code snippets, or tool outputs.
- **Compatibility**: Pure additive field (`ciphertext` / `enc: "x25519-aes256gcm-v1"`); plaintext peers continue working unless `requireE2EE: true` is set on the connector.

### B. Event Streams (GitHub / Prometheus) — Hybrid Payload E2EE
- **Tradeoff**: Router-side CloudEvents filtering (`exact`, `prefix`, `suffix` on `type`, `source`, `subject`) requires the router to inspect those header attributes so it doesn't broadcast every repo event to every laptop.
- **Best design**: Keep CloudEvents routing attributes (`topic`, `type`, `source`, `subject`) cleartext for server-side filtering, and encrypt `data` (`datacontenttype: "application/vnd.hyphae.e2ee+json"`) using a topic key wrapped to each authorized subscriber's X25519 public key. For ultra-sensitive small private topics, offer optional full-envelope E2EE with client-side filter evaluation.

---

## 2. Multi-Agent Chat Channels (`#incidents`, `#deploys`) — **Shipped in v1**

Agents collaborate in shared rooms across machines without knowing every peer handle in advance:

- **Shipped MCP tools**:
  - `hyp_channel_join({ channel: "#incidents", mode?: "queue" | "interrupt" })`
  - `hyp_channel_leave({ channel: "#incidents" })`
  - `hyp_channel_post({ channel: "#incidents", text })`
  - `hyp_channels()` — lists active channels and enrolled members
- **SQLite-backed fan-out**: Membership and delivery live in `RouterCore`, fanning messages out to every other member in the room with no self-echo.
- **Future E2EE extension (Sender Keys / Epoch Keys)**:
  - Each room can add an `epoch` counter and a random 256-bit room key wrapped to each member's verified X25519 `encPub`, rotating the epoch whenever a member leaves or is revoked for forward/post-compromise secrecy.

---

## 3. Bidirectional Bridges & Multi-Thread Fan-In — **Shipped in v1**

See [docs/plugins.md](./plugins.md) for full configuration and protocol details. The shipped v1 implementation extends the fd-3 NDJSON protocol with backward-compatible bidirectional `request`/`response` frames and multi-thread bridge linking:

### A. Multi-Thread Link / Unlink (`bridge_links`)
- `hyp_bridge_link({ plugin, target, sessionId?, handle?, threadId? })` — attaches one or more threads (even across different harnesses) to receive fan-in copies of inbound bridge events and post replies.
- `hyp_bridge_unlink({ plugin, target, sessionId?, handle?, threadId?, all? })` — detaches a session (or all linked sessions when called by the primary/configured holder) with zero daemon restarts.
- `hyp_plugin_targets()` — inspects targets routed or linked to the caller, including `linkedSessions`.

### B. Outbound Replies (`hyp_plugin_post`) Over fd 3
- The daemon sends `{"type":"request","id":"...","method":"post","target":"<target>","params":{...}}\n` over fd 3 and awaits `{"type":"response","id":"...","ok":true,"result":{...}}\n` (handled automatically in Node via `mesh.onPost(handler)`).
- Fail-closed authorization rejects unlinked callers with `not_target_holder`.
- Agents never see Slack, Telegram, WhatsApp, or webhook credentials—plugins resolve secrets inside an isolated subprocess from the OS keyring (or headless fallback) and enforce per-target allowlists.

### C. Built-In WhatsApp Bridge (`builtin: "whatsapp"`)
- Implemented in [plugins/whatsapp/index.mjs](../plugins/whatsapp/index.mjs) with zero external dependencies: Meta `GET` webhook verification, constant-time `X-Hub-Signature-256` verification, fail-closed `WHATSAPP_ALLOWED_NUMBERS` allowlist, `com.whatsapp.message.received` CloudEvents, and outbound Graph API replies via `hyp_plugin_post`.

---

## 4. OpenClaw as a Mesh Orchestrator — **Shipped in v1**

**OpenClaw** is an open-source self-hosted AI agent gateway supporting multi-channel chat routing (WhatsApp, Telegram, Discord, Slack), `SKILL.md` skills, and bidirectional MCP.

- **One-command wiring**: `hyp setup openclaw` configures OpenClaw's `openclaw.json` MCP server entry (`hyp mcp`) and installs the bundled `skills/hyphae/SKILL.md`.
- **Clean separation of concerns**: OpenClaw acts as a human-facing multi-channel orchestrator while `hyphae` acts as the authenticated, zero-polling cross-machine execution bus connecting OpenClaw to live coding threads across **Antigravity**, **Claude Code / Desktop**, **Codex**, **Cursor**, **OpenCode**, **Gemini CLI**, **Herdr Core**, and **T3 Code**.
