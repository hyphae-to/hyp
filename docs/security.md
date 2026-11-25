# Security Model & Hardening Guide

Hyphae (`hyp`) connects autonomous AI coding agents across harnesses, terminals, and hosts. Every architectural choice assumes that **inbound mesh messages, `#channel` posts, webhooks, remote escalation hints, and external chat bridge messages are untrusted external data** and that **a compromised or confused agent must never impersonate another thread, bypass Security Gates, or leak host credentials**.

---

## 1. Per-Call Caller Verification (Anti-Impersonation)

A single stateless `hyp mcp` subprocess (~2.8 MB RSS) can be shared across many tabs and conversations in Desktop apps. Therefore Hyphae **never** binds identity 1:1 to an MCP process — every tool call is verified fail-closed via `CallRegistry` (`crates/hyp-harness/src/call_registry.rs`):

- **Antigravity**: `PreToolUse` hook receives host-verified `conversationId`, registers a single-use cryptographic token in `CallRegistry` bound to the exact canonical tool name, and overwrites `_meshCall` (including inside lazy `call_mcp_tool` invocations). Replay or cross-session spoofing fails closed.
- **Claude Code & Desktop**: `PreToolUse` hook registers `(session_id, tool_name, tool_use_id)` before tool execution; `tools/call` must present the matching `_meta["claudecode/toolUseId"]`.
- **Codex CLI & Desktop**: Verifies `_meta.callId` against in-flight `function_call` records in `$CODEX_HOME/sessions/.../rollout-*.jsonl` (with no `function_call_output` yet) to prove the real Codex thread UUID.
- **Cursor IDE & Agent**: `beforeMCPExecution` hook registers `(conversation_id, tool_name)` and injects a single-use `_meshCall` token.
- **OpenCode**: Local plugin (`~/.config/opencode/plugins/hyphae.ts`) injects a single-use `_meshCall` token in `tool.execute.before`.
- **Gemini CLI**: `BeforeTool` hook registers `(session_id, tool_name)` and injects `_meshCall` into `tool_input`.
- **OpenClaw**: Managed `openclaw.json` MCP server entry binds OpenClaw sessions into the local daemon alongside desktop and terminal harnesses.
- **T3 Code**: Verifies active non-deleted, non-archived T3 threads read-only from `userdata/statev2.sqlite`, failing closed on ambiguous or missing threads. Auth tokens are stored in `SecretStore` (never plaintext in `node.json`), and `t3.url` enforces HTTPS or loopback HTTP origins.
- **Herdr Core**: Requires explicit `--backend herdr` and verifies `HC_TERMINAL_ID` via `hc get --json` (`state === "live"` and non-null `status.app`). **Bare shell terminals (`status: null`) are rejected fail-closed**, preventing untrusted mesh text from ever being typed into a raw shell after an agent exits.
- **Bounded Registry**: `CallRegistry` enforces a 60s TTL, single-use atomic consumption, exact canonical tool-name matching, and a hard cap of `512` in-flight entries. Unverified callers fail closed with `caller_unverifiable` / `caller_not_found` (unless `--ephemeral` is explicitly passed for scratch testing).

---

## 2. End-to-End Encryption & Zeroized Cryptography (`hyp-crypto`)

All cryptographic primitives live in `crates/hyp-crypto` (`ring`, `sha2`, `zeroize`, `flate2`):

- **Persistent Node Identity**: Each Node generates persistent Ed25519 signing and RFC 7748 X25519 encryption keypairs stored in `SecretStore` (`node-sign-<hash12>`, `node-enc-<hash12>`, transparently reading legacy `id-sign-*`/`id-enc-*`). Public keys travel as RFC 7517/8037 OKP JWKs identified by RFC 7638 SHA-256 JWK Thumbprints (`kid`).
- **Memory Zeroization**: Private keys, HPKE shared secrets, epoch room keys, and streaming transfer DEKs are wrapped in `Zeroizing` buffers and scrubbed deterministically on drop.
- **RFC 9180 HPKE Base Mode Everywhere**:
  - **1-to-1 DMs (`dm.e2ee.v1`)**: Sealed with `DHKEM(X25519, HKDF-SHA256)` + `HKDF-SHA256` + `AES-256-GCM` and signed with domain-separated Ed25519 over RFC 8785 JCS. Team Hubs store zero plaintext DM bodies.
  - **Epoch-Rotated `#channels` (`channel.e2ee.v1`) & Writer-Locked `#announcements`**: Symmetric 256-bit epoch room keys wrapped via HPKE per authorized member, rotated on membership leave/revocation.
  - **Shared KV (`kv.e2ee.v1`)**: Namespace-scoped E2EE with `AES-256-GCM` AAD binding host, namespace, key, version, epoch, and writer identity, plus optimistic CAS (`If-Match` / `expectedVersion`).
  - **Streaming File Drops (`transfer.stream.v2`)**: O(64 KiB) constant-RAM streaming POSIX `tar.gz` (`flate2`) encrypted in 64 KiB AES-256-GCM chunks (`base_nonce XOR chunk_index` + final-chunk AAD flag) with multi-recipient HPKE DEK slots and OCI `sha256:<hex>` digests. Unpacking fails closed on symlinks, hardlinks, FIFOs, device nodes, absolute paths, `..` traversal, NUL bytes, `> 200` files, or `> 256 MiB` uncompressed decompression bombs, and forces `0600`/`0700` file modes.
- **Anti-Downgrade & Anti-Rollback**: Signed capability manifests (`GET /v1/manifest`) enforce monotonic `manifestVersion`, expiry checks, and an E2EE ratchet — if a peer previously advertised `dm.e2ee.v1` or `channel.e2ee.v1` and drops it, connections fail closed with `capability_downgrade_detected`.

---

## 3. Permissioned Pairing, Scopes & Anti-Recon

- **Zero-Argv Pairing Tokens**: `hp2p1_` (Direct P2P mutual pairing with out-of-band OKP JWKs + 160-bit CSPRNG secret — zero CA, zero TOFU), `am2_` (offline Org Root Admin-CA grants — Team Hub never holds the Admin private key), and legacy `t3mp1_` tokens are **never** accepted as CLI argv flags. Always use stdin (`hyp pair inspect <<< "$TOKEN"`, `hyp pair accept <<< "$TOKEN"`, `hyp onboard --join - <<< "$TOKEN"`) or a `0600` `--token-file`.
- **Self-Service Guest Confinement (`guest-ro`)**: Read-only public nodes (`POST /v1/guest/pair`) require a fresh (±5 min) Ed25519 possession proof (`409 peer_key_mismatch` on key hijacking) and confine guests strictly to `stream:subscribe=github[require=exact.repo;maxValues=10;maxBatchesPerHour=60]` — zero DM, `#channel`, file, or KV write scopes.
- **Fail-Closed Scope Presets**: Unknown scopes are ignored fail-closed. The `full` / `*` preset explicitly **excludes** `bridge:post` and `forward:via` (opt-in only).
- **Anti-Recon Unauthenticated `/v1/manifest`**: Unauthenticated `GET /v1/manifest` requests return `audience: "public"` with **strictly empty `advertised` arrays** and no `escalation` text — preventing enumeration of internal topics, private `#channels`, KV namespaces, or internal contacts. Verified automatically by `hyp deploy check --url https://<domain>`.

---

## 4. Pluggable Local Security Gates & Human-CLI Quarantine

Implemented in `crates/hyp-node/src/gates/` and controlled strictly via the human CLI (`hyp gate`, `hyp inbox`):

1. **Strictly Post-Decrypt (Inbound) & Pre-Encrypt (Outbound)**: Because E2EE terminates inside the Local Node, the Local Node is the exact trust boundary that screens plaintext CloudEvents before they enter an agent context window and scans outbound text before encrypting.
2. **Stage 1 Deterministic Policy (0 ms, 0 tokens, fail-closed)**:
   - Cryptographic identity & anti-downgrade E2EE checks, trust-tier tagging (`self`, `org`, `peer`, `guest`, `external-webhook`, `bridge`), session/connector mute lookup, CloudEvents Filter AST allow/denylists, per-sender token-bucket rate limits, payload size ceilings, inbound regex denylists, and automatic `guest`/`external-webhook` downgrade to `notify` or `quarantine`.
   - **Transfer Attachment Guard**: Inspects every `tar.gz` path during streaming unpack and blocks executable/script/startup files (`.sh`, `.exe`, `.dmg`, `.pkg`, `.ps1`, `.bashrc`, `.zshrc`, `.git/hooks/*`, `.claude/*`, etc.) unless explicitly allowlisted for that peer.
   - **Outbound Secret DLP Scanner**: Blocks accidental exfiltration of AWS keys (`AKIA...`), GitHub tokens (`gh[pousr]_...`), Slack tokens (`xox...`), Anthropic/OpenAI keys, PEM private keys, and JWTs — returning redacted category names only (never echoing leaked values).
3. **Stage 2 Composable `FilterPlugin` Chain**:
   - Opt-in per `(peer | #channel | topic | bridge | trustTier)` across 6 adapters: `anthropic`, `openai-compat` (e.g. Ollama `http://127.0.0.1:11434/v1`), `google`, `lakera-guard`, `http-classifier` (Llama Prompt Guard 2 / DeBERTa), and JSON-RPC 2.0 `subprocess`.
   - **Isolation**: Zero tools, zero workspace context, zero conversation history, zero host secrets; compiled-in immutable core rubric; randomized 64-bit untrusted payload fences; bounded budget (`16,384` chars, `160` output tokens, `4,000 ms` timeout, `4` max concurrent -> `Hold("gate_busy")`).
   - **Fail-Closed Error Semantics**: `on_error` accepts **only** `quarantine` or `block` (enforced at the Rust type level — never fails open to `allow`). Low-confidence allows (`< 0.75`) downgrade to `quarantine`.
4. **Tamper-Evident Policy Lock (`gate_policy_sig`) & Immutable Audit Trail**:
   - `hyp gate init --adapter <name> --secret <secret-name> --lock` (or `hyp gate lock`) computes a domain-separated HMAC-SHA256 (`"hyphae/v2/gate-policy-sig\n"`) over RFC 8785 JCS of the gate policy keyed from `SecretStore` (`gate-policy-hmac-key`). Unauthorized edits to `node.json` fail closed in `hyp doctor` and runtime startup.
   - Agents may stage an unsigned proposal via `hyp gate propose`, which writes `gate.proposed.json` without modifying live signed policy.
   - Every gate verdict writes an immutable `gate_audit` row protected by SQLite triggers (rejecting `UPDATE`/`DELETE`).
5. **Human-CLI-Only Quarantine Review (No MCP Self-Approval)**:
   - Quarantined items emit a strictly metadata-only notice (`hyphae quarantine · 1 item held (reason: ...) · review via hyp gate review`) — never leaking unscreened body text.
   - `hyp_inbox` refuses `state: "quarantined"` / `"rejected"` fail-closed. Only a human at the local CLI can run `hyp gate review`, `hyp gate log`, `hyp inbox approve <receipt>`, or `hyp inbox reject <receipt> [--mute]`.

---

## 5. Verified Human Drops & Human Authority (`human.auth.v1` / `drop.relay.v1`)

Verified Human Drops provide a cryptographic out-of-band channel from an enrolled human (phone or laptop) directly to a target Hyphae Node without exposing secrets to relays, logs, SQLite, or agent LLM contexts:

- **Tier 1 Ed25519 + Companion X25519 Human Authority**:
  - **Phone WebAuthn Passkey+PRF** (`https://hyphae.to/drop` — self-contained static page, zero CDN, strict CSP): during `hyp auth init --web`, a single Face ID / Touch ID PRF prompt derives **both** the Ed25519 signing keypair and a companion X25519 draft-encryption keypair (`human_authorities.enc_jwk_json`, schema v5). Both public keys are bound into `human_authorities_digest` / `gate_policy_sig`.
  - **Laptop CLI Ed25519 keys** stored strictly in `SecretStore` (macOS Keychain / Linux Secret Service / `0600` file).
  - Managed strictly via human CLI: `hyp auth init [--web]`, `hyp auth add`, `hyp auth list`, `hyp auth revoke <kid> [--bump-epoch]`, `hyp auth certify-node`, and `hyp auth sign --kind directive|secret` (reading stdin).
- **Anti-Phishing `NodeCertV1` (`hcert1_`) & Encrypted Directive Prefill (`encDraft`-Only)**:
  - Target nodes carry human-signed `NodeCertV1` certificates (`human_node_certs`) binding `nodeId` and X25519 encryption JWK so the portal verifies the recipient node before sealing.
  - Plaintext prefill fields in drop URLs remain strictly forbidden. For **`kind: "directive"` ONLY**, `hyp drop create --kind directive --draft "..."` (or `--draft-stdin`) and `hyp_mesh({ action: "drop_link", kind: "directive", draft: "..." })` HPKE-encrypt the proposed draft (`human.draft.v1`, AAD-bound to `nodeId` + `recipientKid`, bucket-padded, validated ≤ 512 chars with C0/C1 control, zero-width, and BiDi override characters rejected fail-closed) to the human's Passkey-PRF X25519 public key directly inside `#drop=` (`encDraft`) — **zero plaintext leak even if the link is pasted into Slack, Telegram, WhatsApp, or SMS**.
  - Draft prefills are **strictly forbidden for `kind: "secret"`** (secrets are always typed fresh).
  - On `https://hyphae.to/drop`, **1 Face ID / Touch ID tap** unlocks & decrypts the draft in RAM -> amber *"Draft proposed by agent (untrusted)"* banner -> auto-expanded no-scroll BiDi-safe review box -> mandatory confirmation checkbox (*"I have read and approve every line above"*) -> Sign & Send -> immediate RAM wipe.
- **Sealed Drops (`hdrop1_`) & Replay Protection**:
  - Sealed with RFC 9180 HPKE (`DHKEM(X25519, HKDF-SHA256)` + `AES-256-GCM`) and Ed25519-signed over RFC 8785 JCS.
  - Every drop embeds a single-use `claim_id` recorded atomically in `human_nonces` (and pruned after expiry by the exact deadline scheduler) so replayed envelopes fail closed.
  - Revoking a key (`hyp auth revoke <kid> [--bump-epoch]`) advances the node's monotonic revocation epoch; drops signed by revoked keys or stale epochs fail closed.
- **Zero-Knowledge Secret Sink & Reserved Denylist**:
  - Secret drops (`kind: "secret"`) decrypt in memory and write directly into the target node's `SecretStore` (macOS Keychain / Linux Secret Service / `0600` file) with **zero secret bytes** ever written to SQLite, logs, relay plaintext RAM, or agent LLM context. The agent receives only a metadata-only confirmation notice.
  - Reserved internal secret names and prefixes (`node-sign-*`, `node-enc-*`, `id-sign-*`, `id-enc-*`, `admin-ca*`, `gate-policy*`, `human-admin*`, `human-authority*`, `auth-token*`) are blocked fail-closed so a secret drop can never overwrite node identity or gate signing keys.
- **Verified Human Directives (`TrustTier::HumanVerified`) & Tamper-Evident Policy Binding**:
  - Cryptographically authenticated directives receive `TrustTier::HumanVerified`, bypassing Stage 2 untrusted-peer prompt-injection filters while still writing immutable `gate_audit` rows (`stage: "human_authority"`, `trust_tier: "human-verified"`).
  - When a gate policy is locked (`hyp gate lock`), `human_authorities_digest` (computed over `human_authorities` in `node.sqlite`) is bound into `gate_policy_sig`. Unauthorized SQLite tampering with enrolled human keys fails closed at runtime and in `hyp doctor`.
- **RAM-Only Blind Drop Relay (`dropRelay`)**:
  - Holds ciphertext exclusively in a bounded RAM-only zeroized buffer (`256 MiB` default, zero disk writes, zero plaintext).
  - Stateless HMAC-SHA256 `hdcap1_` upload and claim capability tokens are verified **before** reading the HTTP request body.
  - Allocating slots (`POST /v1/drops`) requires the explicit `drop:create` scope (never included in `guest-ro`).
  - Target nodes catch up via burn-after-read SSE (`GET /v1/drops/{id}/stream` + `POST /v1/drops/{id}/ack`), and strict CORS + Chrome Private Network Access (PNA) headers protect direct LAN/Tailscale drops.

---

## 6. Secrets Isolation (`SecretStore` & Subprocess Scrubbing)

- **Zero plaintext secrets in config, argv, or LLM context**: `node.json` references credentials solely via `{ "secret": "<name>" }` (never raw strings). `hyp secret set <name> --web` launches an ephemeral `127.0.0.1` one-shot HTML form protected by a random 192-bit URL path token and a constant-time verified CSRF nonce so secret bytes never touch an agent conversation or shell history. Headless setups pipe values over stdin (`printf '%s' "$VAL" | hyp secret set <name>`).
- **Three Storage Backends (`crates/hyp-crypto/src/keystore.rs`)**:
  1. **macOS Keychain** (`keychain`, default on macOS): `/usr/bin/security -i` over stdin (`-X <hex>`, service `hyphae`) — zero secret bytes in argv.
  2. **Linux Secret Service** (`secret-service`, default on Linux desktop sessions with `DBUS_SESSION_BUS_ADDRESS`): `secret-tool` over stdin.
  3. **Private Local File Fallback** (`file`, headless servers, containers, Windows, and isolated `--state-dir` / temp tests): `<state_dir>/secrets/<name>.secret` inside a user-owned `0700` directory with atomic `0600` permissions, rejecting symlinks (`symlink_metadata`) and wrong UID/mode fail-closed.
  - Override explicitly with `HYPHAE_SECRET_BACKEND=keychain|secret-service|file`.
  - `hyp secret list` and `hyp doctor` audit secret names and permissions without ever printing secret values (there is intentionally no CLI subcommand that prints raw secret values).
- **Subprocess Environment Scrubbing**: `SubprocessSupervisor` (`crates/hyp-node/src/adapters/supervisor.rs`) spawns external `plugins/` scripts with only `ALLOWED_PARENT_ENV` (`PATH`, `HOME`, `TMPDIR`, `LANG`, `XDG_RUNTIME_DIR`, `DBUS_SESSION_BUS_ADDRESS`) plus the plugin's explicitly configured env/secrets — unrelated host env vars (`ANTHROPIC_API_KEY`, `AWS_*`, `GH_TOKEN`, etc.) are never inherited.

---

## 7. Untrusted External Framing & Chat Bridge Guards

- **Untrusted external data**: All peer messages, `#channel` posts, webhooks, unsigned local ingest (`ingest.sock` / `hyp emit`) event payloads, bridged chat texts, and remote `403 not_granted` escalation notes (capped at `512` UTF-8 bytes, stripped of control characters, wrapped as `{ untrusted: true, provenance, text }`) are strictly delimited as untrusted data — never instructions.
- **Socket-only Local Event Ingest (`localIngest` / `ingest.sock`)**: Listens strictly on a user-only `0600` Unix domain socket (`~/.config/hyphae/state/ingest.sock` inside a `0700` directory; loopback TCP + `0600` constant-time 32-byte bearer token `ingest.addr` on Windows — never FIFO pipes), enforcing 64 KiB max NDJSON lines, 5 s read timeout, 64 max concurrent connections, per-route CloudEvents allowlists (`allowedTypes`, `allowedTopics`, Filter AST), `maxPayloadBytes`, token-bucket rate/burst caps (`onLimit: "drop" | "coalesce"`), and `SecurityGatePipeline` screening (`gate: true`). Optional attached Ed25519 `hyphaesig` extensions (`ed25519:<kid>:<b64url>`) are **always** verified fail-closed against active `human_authorities` when present (upgrading verified events to `TrustTier::HumanVerified` with an immutable `gate_audit` row); routes setting `requireSignature: true` reject unsigned events fail-closed.
- **Fail-closed chat bridge allowlists**: Optional external scripts `plugins/slack/index.mjs`, `plugins/telegram/index.mjs`, and `plugins/whatsapp/index.mjs` drop unauthorized senders unless explicit allowlists (`SLACK_ALLOWED_USERS`/`SLACK_ALLOWED_CHANNELS`, `TELEGRAM_ALLOWED_USERS`/`TELEGRAM_ALLOWED_CHATS`, `WHATSAPP_ALLOWED_NUMBERS`) are configured.
- **Constant-time signed webhooks**: Compiled-in `GitHubWebhookAdapter`, `GitHubPublicAdapter` (`POST /v1/webhooks/github-app`), `PrometheusWebhookAdapter`, and `GenericWebhookAdapter` verify `X-Hub-Signature-256` / bearer tokens / HMAC-SHA256 in constant time (`ring::hmac`).

---

## 8. Network, Transport & Self-Update Hardening

- **Loopback-only binding & private IPC**: Remote-capable profiles bind `127.0.0.1:8790` behind TLS termination (Tailscale Serve, Caddy, Cloudflare Tunnel, or Fly Proxy); `deploy check` fails closed on unprotected wildcard binds. Local IPC and default local event ingestion use user-only `0600` Unix domain sockets (`connector.sock`, `ingest.sock`) on macOS/Linux or loopback `127.0.0.1` TCP (`connector.addr`, `ingest.addr` with constant-time bearer token) on Windows.
- **No implicit open relay**: `forwarding.mode` defaults to `"deny"` (only `"deny"` or explicit `"allowlist"` is accepted), backed by `hyphaevia`/`hyphaehops` cycle and hop-limit checks (hard cap `4`).
- **Signed self-update (`hyp update`)**: Release manifests are RFC 8785 JCS canonicalized and Ed25519-signed under `"hyphae/v2/release\n"`, checked for version & `publishedAt` anti-rollback, verified against constant-time archive SHA-256 before extraction, and smoke-tested (`hyp version --json`) with automatic rollback (`hyp.prev` / `hyp.old.exe`) on failure.
