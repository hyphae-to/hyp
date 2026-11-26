# Local Security Gates & Quarantine

Implemented in `crates/hyp-node/src/gates/` and managed exclusively via the local CLI (`hyp gate`, `hyp inbox` — zero MCP surface).

> Start with the [Threat Model](threat-model.md) for the honest same-OS-user boundary.

---

## 1. Architectural Placement

Security Gates run **strictly post-decrypt on inbound traffic** (inside your local node, right before an event enters a session's mailbox) and **pre-encrypt on outbound traffic** (scanning outbound messages for accidental credential leaks before encrypting).

---

## 2. Stage 1: Deterministic Policy (0 ms, 0 Tokens, Fail-Closed)

- Cryptographic identity & E2EE anti-downgrade verification.
- Trust-tier tagging (`self`, `human-verified`, `org`, `peer`, `guest`, `external-webhook`, `bridge`). Hub-relayed webhook events are capped at `ExternalWebhook` so they never escalate to `Org` or `Peer` trust.
- Session/connector mute lookup, CloudEvents Filter AST allow/denylists, per-sender token-bucket rate limits, payload size ceilings, inbound regex denylists, and a per-tier urgency ceiling (`guest`/`external-webhook` default to `cap_to_queue`; `downgrade_to_notify` and `quarantine` remain configurable).
- **Transfer Attachment Guard:** Inspects every `tar.gz` path during streaming unpack and blocks executable, script, and startup files (`.sh`, `.exe`, `.dmg`, `.pkg`, `.ps1`, `.bashrc`, `.zshrc`, `.git/hooks/*`, `.claude/*`, etc.) unless explicitly allowlisted for that peer.
- **Outbound Secret DLP Scanner:** Blocks accidental exfiltration of AWS keys (`AKIA...`), GitHub tokens (`gh[pousr]_...`), Slack tokens (`xox...`), Anthropic/OpenAI keys, PEM private keys, and JWTs — returning redacted category names only.

---

## 3. Stage 2: Composable `FilterPlugin` Chain

Opt-in per `(peer | #channel | topic | bridge | trustTier)` across 6 adapters: `anthropic` (supports `--base-url` and `--auth-header x-api-key|bearer`), `openai-compat` (e.g. local Ollama `http://127.0.0.1:11434/v1`), `google`, `lakera-guard`, `http-classifier` (Llama Prompt Guard 2 / DeBERTa), and JSON-RPC 2.0 `subprocess`.

- **Isolation:** Zero tools, zero workspace context, zero conversation history, zero host secrets; compiled-in immutable core rubric; randomized 64-bit untrusted payload fences; bounded budget (`16,384` chars, `160` output tokens, `4,000 ms` timeout, `4` max concurrent -> `Hold("gate_busy")`).
- **Fail-closed error handling:** `on_error` accepts **only** `quarantine` or `block` (enforced at the Rust type level — never fails open to `allow`). Low-confidence allows (`< 0.75`) downgrade to `quarantine`.
- **HTTPS-only & Remote Classifier Privacy Notice:** Remote Stage 2 classifier URLs reject non-loopback `http://` fail-closed. When a remote Stage 2 classifier is enabled, **decrypted inbound untrusted plaintext** is sent over HTTPS to that endpoint. If inbound plaintext must never leave your machine, use local Ollama (`http://127.0.0.1:11434/v1`) or a local JSON-RPC 2.0 `subprocess` filter.

---

## 4. Per-operation Passkey Approval, Policy Integrity & Live Reload

```sh
# First enroll a browser Passkey Admin on a new node.
hyp auth init --web
# Agents can stage proposals without changing live policy.
hyp gate propose --adapter anthropic --secret anthropic-api-key --json
# Apply exactly this proposal after a fresh live Passkey approval.
hyp gate apply --local
# Direct additions and removals each require their own fresh approval too.
hyp gate init --adapter anthropic --secret anthropic-api-key --local
hyp gate remove anthropic-guard --local
```

There is no persistent unlocked mode. `gate lock`, `gate unlock`, and `--lock` have been removed. `gate init` (including its `add` alias), `gate apply`, and `gate remove` always request a live Passkey Admin approval. An existing approval never authorizes another operation. `gate propose` writes only `gate.proposed.json`; it does not apply policy.

The approval page displays the signed node, operation, parameters, resulting policy hash and authority digest. Review these before signing. Public policy configuration (including secret **names**, never secret values) is carried in the approval URL fragment; treat the URL as private. Only enrolled active Passkey Admins without shell-accessible private keys can approve. The node compares every signed field, including its freshly generated nonce and expiry, and consumes both nonce and claim ID once. The requesting process waits for its own loopback or remote relay ceremony; `--no-wait` and `--approval-file` are not supported for protected operations.

The accepted signature remains as durable **integrity evidence**, not permission to mutate. Historical SQLite table/field names (`gate_lock_seal`, `sealSeq`, `locked`) remain for compatibility with existing signatures. New approvals always certify the resulting policy; no command creates an unlock record. Existing signed policies and legacy HMAC policies still verify, including after their original ceremony expires. Stored Passkey evidence is checked against the actual local node identity, policy, and authority digest. The daemon reloads only a policy whose evidence verifies; unsigned edits fail closed.

Existing unsigned configurations and old signed unlock records remain readable at startup with their previous runtime filtering semantics; this compatibility window does not establish integrity for an unsigned policy. Once Passkey history exists, `gate.reload` cannot install an unsigned or HMAC-only policy, or disable the pipeline. Establish signed integrity with the first live `gate apply`; raw-file and restart behavior before that first signed baseline is a migration boundary, not a claimed protection against same-user writes. A legacy HMAC-only policy without Passkey history can enroll its first Passkey Admin with `auth init --web` after its existing integrity check succeeds (and the existing-authority terminal confirmation, when applicable). Enrollment preserves the policy; follow it with a separate live `gate apply` approval. If enrollment changes a bound authority digest, runtime remains fail closed until that apply completes. They acquire a signed policy on the next approved policy/authority mutation; they do not exempt that mutation from approval. Revoked or expired Passkey admins do not reopen bootstrap. An unreadable authority database fails closed. Installations without an available Passkey Admin cannot mutate protected policy through a TTY fallback; no new recovery bypass is provided.

See [Threat Model](threat-model.md) for database rollback and same-user shell limits. Every gate verdict writes a `gate_audit` row protected by SQLite triggers rejecting `UPDATE`/`DELETE`.

---

## 5. Quarantine Review & Disposition (No MCP Self-Approval)

- Quarantined items add only `<quarantined count="N"/>` to the next `<hyphae-inbox>` digest (never counted in `unread`); receipt, source, and reason are shown by `hyp gate review` — unscreened body text is never injected into agent context.
- `hyp_inbox` refuses `state: "quarantined"` / `"rejected"` fail-closed.
- `hyp gate review --json` returns **metadata only** (receipt ID, source, reason, trust tier, timestamps — never raw body previews).
- `hyp inbox approve <receipt>` and `hyp inbox reject <receipt> [--mute]` require **interactive TTY confirmation** and send live **`inbox.wake`** to deliver approved items immediately.

Authenticated remote revocations remain a monotonic **reduction** protocol on Passkey-managed subscribers. The node verifies the enrolled Admin issuer, signature, and target before marking a key revoked and advancing the minimum epoch. This can only remove trust: it cannot enroll a key, change policy, or authorize a local operation. Malformed and non-admin revocations are audited and rejected. Existing signed policy evidence remains valid when its historical signer is later revoked or falls below the minimum epoch; fresh ceremonies still reject that key. This relies on the evidence having been persisted by a previously accepted live ceremony. A revoked key can backdate a signature, so signatures supplied later are not a replacement for that stored evidence. Same-user SQLite replacement/rollback remains outside the protection boundary.

If an authenticated reduction leaves no eligible Passkey Admin, directives from invalidated keys are rejected immediately, the existing approved policy stays enforced, and local policy/authority changes fail closed. `hyp doctor` reports that administration is blocked and `hyp auth list --json` exposes the revoked records/epochs. Enrollment history remains present; `auth init` cannot reset it. Local revocation commands still refuse to remove their only eligible approver. No recovery bypass is provided.

Local stream/adapter publication on a managed node cannot introduce a revocation: it may only broadcast an exact, signature-verified revocation already persisted by the local command. Authenticated remote ingress may introduce monotonic reductions, provided the Admin issuer is active at the current minimum epoch. Issuer checks and the reduction share one serialized SQLite writer; exact verified replay remains harmless after issuer retirement.

The final approved commit holds a serialized writer while it rechecks the ceremony snapshot, consumes replay IDs, applies authority/delegation changes, checks the surviving eligible Admin for local revocation, validates the signed resulting state, and persists policy evidence. Ordinary errors roll back SQLite and restore the original config. Config files and SQLite are separate resources: a crash or SQLite commit failure between them can leave a mismatched config and seal, which fails closed on integrity verification. This is not a cross-resource atomic commit or protection against same-user file replacement.
