# Human Authority & Blind Drop Relay

Verified Human Drops (`human.auth.v1` / `drop.relay.v1`) provide a cryptographic out-of-band channel from an enrolled human (phone or laptop) to a Hyphae node without exposing secret bytes to relays, logs, SQLite, or agent LLM contexts.

---

## 1. Tier 1 Ed25519 + Companion X25519 Human Authority

- **Phone WebAuthn Passkey+PRF (`https://hyphae.to/drop`):** Self-contained static page (zero CDN, strict CSP). During first-time `hyp auth init --web`, a single Face ID / Touch ID PRF prompt derives **both** an Ed25519 signing keypair and a companion X25519 draft-encryption keypair (`human_authorities.enc_jwk_json`, schema v5). Both public keys bind into `human_authorities_digest` / `gate_policy_sig`.
- **Laptop CLI Ed25519 keys:** Stored in `SecretStore` (macOS Keychain / Linux Secret Service / `0600` file).
- **Interactive TTY confirmation:** Mutating/signing CLI operations (`hyp auth add`, `hyp auth revoke`, `hyp auth sign`, `hyp emit --sign`, and re-running `hyp auth init --web` on an already-initialized node) enforce interactive TTY confirmation.

---

## 2. Anti-Phishing `NodeCertV1` & Encrypted Directive Prefills

- **Node certificates (`hcert1_`):** Target nodes hold human-signed `NodeCertV1` records (`human_node_certs`) binding `nodeId` and X25519 encryption JWK so the Drop Portal verifies the recipient before sealing.
- **Zero plaintext prefills:** Plaintext prefill fields in drop URLs are forbidden. For **`kind: "directive"` ONLY**, `--draft` / `--draft-stdin` or `hyp_mesh({ action: "drop_link", kind: "directive", draft: "..." })` HPKE-encrypts the draft (`human.draft.v1`, AAD-bound to `nodeId` + `recipientKid`, bucket-padded, ≤ 512 chars, rejecting C0/C1/zero-width/BiDi override chars fail-closed) into `#drop=` (`encDraft`). Draft prefills are **strictly forbidden for `kind: "secret"`**.
- On `https://hyphae.to/drop`, 1 Face ID / Touch ID tap decrypts the draft in RAM -> amber *"Draft proposed by agent (untrusted)"* banner -> auto-expanded BiDi-safe review box -> mandatory confirmation checkbox -> Sign & Send -> immediate RAM wipe.

---

## 3. Sealed Drops (`hdrop1_`), Replay Protection & Secret Sink

- Sealed with RFC 9180 HPKE (`DHKEM(X25519, HKDF-SHA256)` + `AES-256-GCM`) and Ed25519-signed over RFC 8785 JCS.
- Single-use `claim_id` nonces record atomically in `human_nonces` (pruned on expiry) so replays fail closed. Revoking a key (`hyp auth revoke <kid> --bump-epoch`) advances the node's monotonic revocation epoch.
- **Zero-knowledge secret sink:** `kind: "secret"` drops decrypt in memory and write straight into `SecretStore` (blocking reserved system secret names `node-sign-*`, `node-enc-*`, `id-sign-*`, `id-enc-*`, `admin-ca*`, `gate-policy*`, `human-admin*`, `human-authority*`, `auth-token*` fail-closed). Agents receive only metadata confirmation.
- **Verified directives (`TrustTier::HumanVerified`):** Authenticated directives bypass Stage 2 untrusted-peer prompt-injection filters while recording immutable `gate_audit` rows.

---

## 4. Blind Drop Relay: `spore.hyphae.to` vs. Self-Hosted Rust Relay

| Deployment | Storage Model | Retention & Wipe | Auth Mode |
| --- | --- | --- | --- |
| **Hosted public relay (`https://spore.hyphae.to`)** (`workers/drop-relay`) | Ephemeral Cloudflare Durable Object storage (`DropSlotDO`) persisting blind encrypted `hdrop1_` ciphertext envelopes **plus slot creator node ID and Ed25519 public key metadata** so drops survive isolate eviction. **Zero drop plaintext or decryption keys ever touch the relay.** | Hard **15-minute (`900s`)** Durable Object alarm unconditionally runs `storage.deleteAll()` (or immediate wipe + RAM zeroization on burn-after-read ack). | `DROP_AUTH_MODE = "open"` with Ed25519 request signatures (`X-Hyphae-Public-Key`) + durable per-IP & per-pubkey `RateLimiterDO` quotas. |
| **Self-hosted Cloudflare Worker** (`workers/drop-relay`) | Same ephemeral DO storage + 15-min alarm `storage.deleteAll()`. | Hard 15-min alarm or immediate burn-after-read wipe. | Defaults fail-closed to `DROP_AUTH_MODE = "private"` (`ALLOWED_NODE_KEYS`). |
| **Self-hosted in-node Rust Drop Relay** (`hyp deploy init drop-relay` / `--enable-drop-relay`) | **Strictly RAM-only** bounded zeroized buffer (`256 MiB` default, zero disk writes). | Zeroized immediately on burn-after-read ack or TTL expiry. | Authenticated paired peers holding explicit `drop:create` scope (excluded from `guest-ro`). |

All relay implementations verify stateless HMAC-SHA256 `hdcap1_` upload and claim capability tokens in constant time **before** reading the HTTP request body, deliver over burn-after-read SSE (`GET /v1/drops/{id}/stream` + `POST /v1/drops/{id}/ack`), and enforce explicit CORS + Chrome Private Network Access (PNA) headers.

## Live administration and migration

After first enrollment via `hyp auth init --web`, use `hyp auth add`, `hyp auth admit`, and `hyp auth revoke` with a fresh live browser Passkey approval for each operation. These commands do not accept offline approval files or offer a TTY-only authorization fallback. `auth admit` signs the exact authority and delegation settings, including scopes, device prefix and device limit. Authority changes also approve the resulting gate policy and authority digest. A revocation must leave an active Passkey Admin at the resulting epoch; enroll a replacement before retiring a key. `auth init` cannot reset an installation with Passkey enrollment history, even if all keys were revoked. No recovery bypass is implied.

On Passkey-managed installations, `auth join`, offline invite claims, direct cascade APIs cannot change human authorities. Use live local administration instead. Unmanaged legacy hubs retain their existing signed invite/revocation behavior. See [the threat model](threat-model.md) for the initial trust boundary and database rollback limits.

Authenticated remote revocations remain a monotonic **reduction** protocol on Passkey-managed subscribers. The node verifies the enrolled Admin issuer, signature, and target before marking a key revoked and advancing the minimum epoch. This can only remove trust: it cannot enroll a key, change policy, or authorize a local operation. Malformed and non-admin revocations are audited and rejected. Existing signed policy evidence remains valid when its historical signer is later revoked or falls below the minimum epoch; fresh ceremonies still reject that key. This relies on the evidence having been persisted by a previously accepted live ceremony. A revoked key can backdate a signature, so signatures supplied later are not a replacement for that stored evidence. Same-user SQLite replacement/rollback remains outside the protection boundary.

If an authenticated reduction leaves no eligible Passkey Admin, directives from invalidated keys are rejected immediately, the existing approved policy stays enforced, and local policy/authority changes fail closed. `hyp doctor` reports that administration is blocked and `hyp auth list --json` exposes the revoked records/epochs. Enrollment history remains present; `auth init` cannot reset it. Local revocation commands still refuse to remove their only eligible approver. No recovery bypass is provided.

Local stream/adapter publication on a managed node cannot introduce a revocation: it may only broadcast an exact, signature-verified revocation already persisted by the local command. Authenticated remote ingress may introduce monotonic reductions, provided the Admin issuer is active at the current minimum epoch. Issuer checks and the reduction share one serialized SQLite writer; exact verified replay remains harmless after issuer retirement.

The final approved commit holds a serialized writer while it rechecks the ceremony snapshot, consumes replay IDs, applies authority/delegation changes, checks the surviving eligible Admin for local revocation, validates the signed resulting state, and persists policy evidence. Ordinary errors roll back SQLite and restore the original config. Config files and SQLite are separate resources: a crash or SQLite commit failure between them can leave a mismatched config and seal, which fails closed on integrity verification. This is not a cross-resource atomic commit or protection against same-user file replacement.
