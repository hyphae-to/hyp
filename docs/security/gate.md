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
- Session/connector mute lookup, CloudEvents Filter AST allow/denylists, per-sender token-bucket rate limits, payload size ceilings, inbound regex denylists, and automatic `guest`/`external-webhook` downgrade to `notify` or `quarantine`.
- **Transfer Attachment Guard:** Inspects every `tar.gz` path during streaming unpack and blocks executable, script, and startup files (`.sh`, `.exe`, `.dmg`, `.pkg`, `.ps1`, `.bashrc`, `.zshrc`, `.git/hooks/*`, `.claude/*`, etc.) unless explicitly allowlisted for that peer.
- **Outbound Secret DLP Scanner:** Blocks accidental exfiltration of AWS keys (`AKIA...`), GitHub tokens (`gh[pousr]_...`), Slack tokens (`xox...`), Anthropic/OpenAI keys, PEM private keys, and JWTs — returning redacted category names only.

---

## 3. Stage 2: Composable `FilterPlugin` Chain

Opt-in per `(peer | #channel | topic | bridge | trustTier)` across 6 adapters: `anthropic` (supports `--base-url` and `--auth-header x-api-key|bearer`), `openai-compat` (e.g. local Ollama `http://127.0.0.1:11434/v1`), `google`, `lakera-guard`, `http-classifier` (Llama Prompt Guard 2 / DeBERTa), and JSON-RPC 2.0 `subprocess`.

- **Isolation:** Zero tools, zero workspace context, zero conversation history, zero host secrets; compiled-in immutable core rubric; randomized 64-bit untrusted payload fences; bounded budget (`16,384` chars, `160` output tokens, `4,000 ms` timeout, `4` max concurrent -> `Hold("gate_busy")`).
- **Fail-closed error handling:** `on_error` accepts **only** `quarantine` or `block` (enforced at the Rust type level — never fails open to `allow`). Low-confidence allows (`< 0.75`) downgrade to `quarantine`.
- **HTTPS-only & Remote Classifier Privacy Notice:** Remote Stage 2 classifier URLs reject non-loopback `http://` fail-closed. When a remote Stage 2 classifier is enabled, **decrypted inbound untrusted plaintext** is sent over HTTPS to that endpoint. If inbound plaintext must never leave your machine, use local Ollama (`http://127.0.0.1:11434/v1`) or a local JSON-RPC 2.0 `subprocess` filter.

---

## 4. Policy Lock (`gate_policy_sig`), Live Reload & Immutable Audit

```sh
# Stage a proposal safely (agents can run this without modifying live policy)
hyp gate propose --adapter anthropic --secret anthropic-api-key --json

# Review and lock interactively in your terminal (interactive TTY confirm + live `gate.reload`)
hyp gate lock
# Or initialize and lock directly:
hyp gate init --adapter anthropic --secret anthropic-api-key --lock
```

- `hyp gate lock` computes a domain-separated HMAC-SHA256 (`"hyphae/v2/gate-policy-sig\n"`) over RFC 8785 JCS of the `gate` config (plus `human_authorities_digest`) keyed from `SecretStore` (`gate-policy-hmac-key`), and signals **`gate.reload`** to hot-swap the running daemon's `SecurityGatePipeline` without restart (`gate.reload` fails closed against downgrading a locked policy to unsigned).
- Accidental or unsigned edits to a locked `gate` block in `node.json` fail closed in `hyp doctor` and runtime startup. *(Because `gate-policy-hmac-key` resides in the same OS user's `SecretStore`, this catches unsigned edits and accidental/MCP modifications rather than stopping a malicious shell process running as the same OS user — see [Threat Model](threat-model.md) and [Hardening](hardening.md).)*
- Every gate verdict writes an immutable `gate_audit` row protected by SQLite triggers rejecting `UPDATE`/`DELETE`.

---

## 5. Quarantine Review & Disposition (No MCP Self-Approval)

- Quarantined items emit a metadata-only notice (`hyphae quarantine · 1 item held (reason: ...) · review via hyp gate review`) — unscreened body text is never injected into agent context.
- `hyp_inbox` refuses `state: "quarantined"` / `"rejected"` fail-closed.
- `hyp gate review --json` returns **metadata only** (receipt ID, source, reason, trust tier, timestamps — never raw body previews).
- `hyp inbox approve <receipt>` and `hyp inbox reject <receipt> [--mute]` require **interactive TTY confirmation** and send live **`inbox.wake`** to deliver approved items immediately.
