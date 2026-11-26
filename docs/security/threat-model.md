# Threat Model (Start Here)

Hyphae (`hyp`) connects autonomous coding agents across harnesses, terminals, and machines. This document states clearly **what Hyphae defends against**, **what it does not defend against**, and **where each trust boundary lives**.

---

## 1. The Local Threat Boundary (Same-OS-User Agents)

> **Hyphae protects against untrusted network input and requires a fresh live Passkey Admin signature for normal gate-policy and human-authority mutation commands. It does not sandbox an arbitrary process running as the same OS user.** The signature prevents a shell agent from authorizing changes through supported CLI/IPC/HTTP routes by driving a pseudo-terminal or reusing an old approval. Durable policy evidence detects unsigned config edits, including a deleted gate block, while its database and enrolled keys remain trustworthy. A same-user process can rewrite or roll back the SQLite database, replace the binary, change the browser, or redirect execution; signatures stored in that same database do not provide an external rollback-resistant anchor. Run untrusted agents under a separate OS user or container without access to Hyphae state when that stronger boundary is needed. No keychain high-water mark, OS isolation, or recovery mechanism is added by the per-operation approval model.

Freshness means a nonce and expiry created by the currently waiting CLI process, exact signed operation parameters and target node, active Passkey Admin verification, and single-use replay tracking. Offline approval files and an old unlocked seal never grant permission. A configuration or authority change while the ceremony is pending cancels the operation. Initial enrollment is a trust-establishment boundary: `auth init --web` enrolls the first Passkey Admin, legacy local-key initialization remains available before Passkey enrollment, and migration from existing local keys still requires its controlling-terminal confirmation. That initial trust choice cannot authenticate itself against a previously unknown human. Once Passkey enrollment history exists, revocation or absence of an active key cannot reopen initialization.

Passkey-managed nodes require local live approval for delegated authority admission and revocation too. Offline `hjoin1_` invite claims, direct cascade APIs and `auth join` cannot bypass that boundary; use `auth admit`, `auth add`, and `auth revoke` locally. Legacy unmanaged hubs retain their existing signed invite and revocation flows. This is a deliberate compatibility boundary: migrate those hubs by enrolling a Passkey Admin and using live local administration. Quarantine disposition, body review, local-key signing, and other existing interactive features retain their documented TTY guards unless explicitly listed as a Passkey operation; a TTY is not a cryptographic human-presence boundary.


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

Authenticated remote revocations remain a monotonic **reduction** protocol on Passkey-managed subscribers. The node verifies the enrolled Admin issuer, signature, and target before marking a key revoked and advancing the minimum epoch. This can only remove trust: it cannot enroll a key, change policy, or authorize a local operation. Malformed and non-admin revocations are audited and rejected. Existing signed policy evidence remains valid when its historical signer is later revoked or falls below the minimum epoch; fresh ceremonies still reject that key. This relies on the evidence having been persisted by a previously accepted live ceremony. A revoked key can backdate a signature, so signatures supplied later are not a replacement for that stored evidence. Same-user SQLite replacement/rollback remains outside the protection boundary.

If an authenticated reduction leaves no eligible Passkey Admin, directives from invalidated keys are rejected immediately, the existing approved policy stays enforced, and local policy/authority changes fail closed. `hyp doctor` reports that administration is blocked and `hyp auth list --json` exposes the revoked records/epochs. Enrollment history remains present; `auth init` cannot reset it. Local revocation commands still refuse to remove their only eligible approver. No recovery bypass is provided.

Local stream/adapter publication on a managed node cannot introduce a revocation: it may only broadcast an exact, signature-verified revocation already persisted by the local command. Authenticated remote ingress may introduce monotonic reductions, provided the Admin issuer is active at the current minimum epoch. Issuer checks and the reduction share one serialized SQLite writer; exact verified replay remains harmless after issuer retirement.

The final approved commit holds a serialized writer while it rechecks the ceremony snapshot, consumes replay IDs, applies authority/delegation changes, checks the surviving eligible Admin for local revocation, validates the signed resulting state, and persists policy evidence. Ordinary errors roll back SQLite and restore the original config. Config files and SQLite are separate resources: a crash or SQLite commit failure between them can leave a mismatched config and seal, which fails closed on integrity verification. This is not a cross-resource atomic commit or protection against same-user file replacement.
