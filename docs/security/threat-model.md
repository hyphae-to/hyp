# Threat Model (Start Here)

Hyphae (`hyp`) connects autonomous coding agents across harnesses, terminals, and machines. This document states clearly **what Hyphae defends against**, **what it does not defend against**, and **where each trust boundary lives**.

---

## 1. The Local Threat Boundary (Same-OS-User Agents)

> **Hyphae protects against untrusted network input. It does not create an OS sandbox against a coding agent running with arbitrary shell access as the same OS user.** Interactive TTY confirmation prompts (`hyp gate lock`, locked `hyp gate init`, `hyp inbox approve`/`reject`, `hyp auth add`/`revoke`/`sign`, `hyp emit --sign`, and re-initializing an initialized node via `hyp auth init --web`) stop accidental, scripted, and MCP-driven use and raise friction until full Passkey confirmation ships (`#2`, `#10`), but a same-user shell process can still drive a pseudo-terminal or access `~/.config/hyphae`. **For hard isolation against shell-capable agents today, run untrusted agents under a separate OS user or container without access to `~/.config/hyphae`.**

See the [Local Hardening Guide](hardening.md) for concrete separate-user and container isolation patterns.

---

## 2. What Hyphae Protects vs. What Is Outside Its Boundary

| Surface | Protected by Hyphae | Explicit Caveats / Limits |
| --- | --- | --- |
| **Node-to-node traffic** (DMs, `#channels`, Shared KV, streaming file drops) | End-to-end encrypted with RFC 9180 HPKE + Ed25519; Team Hubs store zero plaintext payloads; signed manifests enforce E2EE anti-downgrade. | Team Hub peer directory keys use **pin-on-first-use** (signed anti-rollback `directory.checkpoint.v1` is planned). |
| **Untrusted inbound text** (peer DMs, `#channels`, webhooks, bridges, unsigned `ingest.sock` events, remote `403` escalation notes) | Treated as untrusted external data, screened by [Local Security Gates](gate.md), and wrapped by `packer.rs` with sanitized provenance headers (`[hyphae · <source>]` / `[hyphae interrupt · <source>]`) and framing-spoof neutralization (`---` and `[hyphae...]` body lines prefixed with `> `; control/BiDi chars and `[`/`]` stripped from source labels). | Prompt-injection classifiers reduce risk but are never 100% infallible; remote Stage 2 classifiers receive decrypted untrusted text over HTTPS (use local Ollama or `subprocess` if plaintext must stay local). |
| **Chat bridges** (`plugins/slack`, `telegram`, `whatsapp`) | Fail-closed sender allowlists; scrubbed subprocess env; local-only bridge topics by default (`exposeTopic: true` opt-in); `0600` secret-redacted stderr logs. | External providers (Slack, Telegram, WhatsApp) see message plaintext — outside node-to-node E2EE. |
| **Compiled-in webhooks** (`github-webhook`, `prometheus-webhook`, `webhook-stream`) | Pure-Rust adapters wired into `hyp node start`; constant-time HMAC/bearer/basic-auth verification; raw-body SHA-256 deduplication; hub-relayed events capped at `ExternalWebhook` trust tier. | Webhook payloads remain untrusted external data. |
| **Caller attribution & session binding** (`CallRegistry` + `sessionToken`) | Hook-verified harnesses bind each MCP tool call to the host thread/session via single-use tokens (60s TTL, 512 cap); Codex verifies thread rollout presence in `$CODEX_HOME/sessions/` alongside hooks; Herdr rejects bare shells fail-closed. Per-session HMAC `sessionToken`s (never exposed in `ui/state.json`) prevent accidental cross-session `hyp wait` or hook-drain mistakes. | `sessionToken` guards against accidental cross-session mixups within the same OS user, not a malicious same-user process. OpenClaw uses `--ephemeral` fallback. |
| **Secrets & `hyp exec --env`** | OS Keychain / Linux Secret Service / `0600` file backend; zero-argv secrets; core `node.json` rejects plaintext strings fail-closed (`plugins[].env` warns on secret-like plaintext). `hyp exec --env VAR=<secret> -- <cmd>` injects user app secrets directly into child env (zero shell interpolation; blocks reserved Hyphae keys, all `node.json` secrets, and dangerous loader env vars) with streaming stdout/stderr redaction (exact, trimmed, whole-value Base64/Base64url, URL-encoded). | `hyp exec` stream scrubbing prevents **accidental echo** (debug logs, tracebacks), **not** intentional exfiltration or custom encoding by a malicious child process. |
| **Blind Drop Relay** (`spore.hyphae.to` vs. self-hosted Rust relay) | Zero drop plaintext or decryption keys ever touch any relay; stateless `hdcap1_` capabilities checked before reading request bodies. | The hosted Cloudflare Worker (`https://spore.hyphae.to`) persists blind `hdrop1_` ciphertext **plus slot creator node ID & Ed25519 public key metadata** in ephemeral Durable Object storage with a hard **15-minute alarm `storage.deleteAll()` wipe** (or immediate burn-after-read close). The self-hosted in-node Rust relay is strictly RAM-only. |
| **Quarantine review** | Zero MCP surface (`hyp_inbox` rejects `quarantined`/`rejected` fail-closed); quarantined notices are metadata-only; `hyp gate review --json` returns metadata only (never raw body previews); `hyp inbox approve`/`reject` require interactive TTY confirmation. | Interactive TTY friction is not a same-OS-user OS sandbox (see §1). |

---

## 3. Deep-Dive Security Pages

- [Local Security Gates & Quarantine](gate.md)
- [Encryption & Pairing](encryption-and-pairing.md)
- [Human Authority & Drop Relay](human-authority.md)
- [Local Hardening Guide (Separate User / Containers)](hardening.md)
- [Reporting a Vulnerability](../../SECURITY.md)
