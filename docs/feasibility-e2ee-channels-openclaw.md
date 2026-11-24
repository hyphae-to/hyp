# Capability Status: E2EE, `#channels`, Bidirectional Bridges & OpenClaw

This document tracks the implementation status of four core Hyphae (`hyp`) capabilities, all **shipped in the pure-Rust v2 workspace** (`crates/hyp-*`). For the full wire protocol specification, see [docs/architecture-v2.md](architecture-v2.md).

| Capability | Status | v2 Rust Implementation & Surface |
| --- | --- | --- |
| **1. End-to-End Encryption (E2EE)** | **Shipped (Rust v2)** | `crates/hyp-crypto` — RFC 9180 HPKE (`X25519` + `HKDF-SHA256` + `AES-256-GCM`), Ed25519 + RFC 8785 JCS, `zeroize`, DMs, `#channels`, Shared KV, 64 KiB streaming `tar.gz` transfers |
| **2. Multi-Agent `#channels` & `#announcements`** | **Shipped (Rust v2)** | `hyp_mesh({ action: "join" \| "leave" \| "channels", channel: "#incidents" })` + `hyp_send({ to: "#incidents", text })` with epoch-rotated `channel.e2ee.v1` keys and writer-locked `#announcements` |
| **3. Bidirectional Bridges & Multi-Thread Fan-In** | **Shipped (Rust v2)** | Conditional `hyp_bridge({ action: "targets" \| "link" \| "unlink" \| "handoff" })` + `hyp_send({ to: "<plugin>:<target>", text, replyTo? })` over `SubprocessSupervisor` (JSON-RPC 2.0 v2 + fd-3 v1 fallback) |
| **4. OpenClaw Gateway Integration** | **Shipped (Rust v2)** | `hyp setup --harness openclaw` — managed `openclaw.json` MCP server entry pointing to the static Rust `hyp` binary + bundled `skills/hyphae/SKILL.md` |

---

## 1. End-to-End Encryption (E2EE)

Implemented in `crates/hyp-crypto/src/` (`keys.rs`, `hpke.rs`, `e2ee.rs`, `transfer.rs`, `keystore.rs`) using `ring`, `sha2`, `flate2`, and `zeroize`:

- **Direct Peer Messages (`dm.e2ee.v1`)**: Each Node maintains persistent Ed25519 signing and RFC 7748 X25519 encryption keypairs in `SecretStore` (macOS Keychain / Linux Secret Service / `0600` file fallback) and publishes RFC 7517/8037 OKP JWKs + RFC 7638 `kid` thumbprints inside its signed `GET /v1/manifest`. DMs are sealed using RFC 9180 HPKE Base Mode and signed over canonical RFC 8785 JCS — blind Team Hubs store zero plaintext.
- **Epoch-Rotated `#channels` (`channel.e2ee.v1`)**: Room messages are encrypted with 256-bit epoch keys wrapped via HPKE per authorized member (`POST/GET /v1/channel-epochs`) and rotated when membership changes.
- **Shared KV (`kv.e2ee.v1`)**: Supports namespace-scoped E2EE with `AES-256-GCM` AAD bound to `(host, namespace, key, version, epoch, writer)` alongside optimistic CAS (`expectedVersion` / `If-Match`) via the conditional `hyp_kv` tool and `hyp kv` CLI.
- **Streaming File Transfers (`transfer.stream.v2`)**: Streams POSIX `tar.gz` archives in 64 KiB AES-256-GCM chunks (`O(64 KiB)` RAM) with multi-recipient HPKE DEK slots, OCI `sha256:<hex>` digests, and fail-closed decompression-bomb / path-traversal / attachment-guard checks.
- **Anti-Downgrade Ratchet**: Peers that advertise E2EE capabilities are pinned; silent downgrade attempts fail closed (`capability_downgrade_detected`).

---

## 2. Multi-Agent `#channels` & `#announcements`

Agents collaborate in shared rooms across machines without knowing every peer handle in advance:

- **Join / leave / list rooms**: `hyp_mesh({ action: "join", channel: "#incidents" })`, `hyp_mesh({ action: "leave", channel: "#incidents" })`, `hyp_mesh({ action: "channels" })`.
- **Post to a room**: `hyp_send({ to: "#incidents", text: "..." })` (or qualified `"acme-team/#incidents"`).
- **Writer-locked `#announcements`**: Supports read-only announcement rooms where only authorized writers may post while all members subscribe, elevated in §2.5 batch packing priority alongside direct `queue` DMs.

---

## 3. Bidirectional Bridges & Multi-Thread Fan-In

See [docs/plugins.md](plugins.md) for full configuration and protocol details.

- **Unified Supervisor (`crates/hyp-node/src/adapters/supervisor.rs`)**: Supervises optional external scripts (`plugins/slack/index.mjs`, `plugins/telegram/index.mjs`, `plugins/whatsapp/index.mjs`, `plugins/webhook/index.mjs`, `plugins/prometheus/index.mjs`, or custom Node/Python/Go/Rust binaries) over duplex Unix fd 3 with scrubbed environment variables and 64 KiB bounded framing, supporting both JSON-RPC 2.0 v2 (`hyphae/hello`, `hyphae/publish`, `hyphae/post`) and legacy fd-3 v1 auto-detection.
- **Multi-Thread Fan-In & Live Handoff (`hyp_bridge`)**:
  - `hyp_bridge({ action: "targets" })` — lists linked targets for the caller.
  - `hyp_bridge({ action: "link" | "unlink", plugin, target })` — attaches or detaches sessions for fan-in across harnesses.
  - `hyp_bridge({ action: "handoff", plugin, target, handle? })` — transfers primary target ownership live without restarting the daemon.
- **Outbound Replies (`hyp_send`)**: Agents reply back to Slack, Telegram, WhatsApp, or callback webhooks via `hyp_send({ to: "<plugin>:<target>", text, replyTo? })` with fail-closed target authorization and fail-closed sender allowlists (`SLACK_ALLOWED_USERS`, `TELEGRAM_ALLOWED_USERS`, `WHATSAPP_ALLOWED_NUMBERS`).

---

## 4. OpenClaw Gateway Integration

**OpenClaw** acts as a human-facing multi-channel orchestrator while Hyphae serves as the authenticated, E2EE, zero-polling execution bus linking OpenClaw to live coding threads across Antigravity, Claude Code / Desktop, Codex, Cursor, OpenCode, Gemini CLI, Herdr Core, and T3 Code:

- **One-command setup**: `hyp setup --harness openclaw` configures OpenClaw's `openclaw.json` MCP entry pointing directly to the static Rust `hyp` binary (`hyp mcp`) with zero Node.js prerequisite for Hyphae itself.
- **Runtime skill**: [skills/hyphae/SKILL.md](../skills/hyphae/SKILL.md) documents the 4 core MCP tools (`hyp_mesh`, `hyp_send`, `hyp_stream`, `hyp_inbox`) plus conditional `hyp_bridge` and `hyp_kv`.
