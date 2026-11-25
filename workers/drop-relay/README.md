# Hyphae Blind Drop Relay — Cloudflare Workers Kit

A zero-dependency, ciphertext-only Blind Ephemeral Drop Relay for **Hyphae Verified Human Drops** (`hdrop1_`), built on Cloudflare Workers + Durable Objects (`DropSlotDO` + `RateLimiterDO`).

Speaks the exact same HTTP/SSE and stateless `hdcap1_` wire protocol as `crates/hyp-node/src/engine/drop_relay.rs`, and supports both **Private / Enterprise allowlist mode** (`"private"` / `"allowlist"`, default, fail-closed) and **Public relay mode** (`"open"`, e.g. `https://spore.hyphae.to`) via a single `DROP_AUTH_MODE` switch.

---

## Privacy, Ephemeral Storage & Rate-Limiting Guarantees

- **Blind ciphertext-only ephemeral DO storage (survives isolate eviction)**: `DropSlotDO` persists **only** opaque encrypted `hdrop1_` ciphertext envelopes and minimal slot metadata in Durable Object storage (`ctx.storage`) so an in-flight drop is never silently lost if Cloudflare evicts an idle DO isolate before the receiving node subscribes. The relay never possesses any decryption key and never sees drop plaintext.
- **Alarm-driven hard delete + immediate burn & zeroization**: Every allocated slot schedules a Cloudflare Durable Object alarm (`storage.setAlarm(expiresAtMs)`, hard max `900s` / 15 min) whose `alarm()` handler unconditionally calls `storage.deleteAll()` to wipe all stored ciphertext and metadata. On `POST /v1/drops/{id}/ack { burn: true }`, burned items are immediately overwritten in RAM with `.fill(0)` and deleted from `ctx.storage` (and closing a burn-after-read slot calls `storage.deleteAll()` + `deleteAlarm()` immediately). Temporary Worker copies are zeroized immediately after forwarding.
- **Zero sensitive logging**: The Worker never calls `console.*` and never logs `dropId`, client IPs, `postCap`/`subCap` tokens, public keys, or payload bytes.
- **Durable cross-PoP rate limits (`RateLimiterDO`)**: Enforces **both** per-IP (1-minute burst + 1-hour sliding window) and per-signer-key (1-hour sliding window) creation quotas, plus a global per-minute isolate guardrail. A single IP cannot bypass per-key limits in `open` mode by rotating fresh self-generated Ed25519 keys. Bucket IDs are HMAC-blinded with `DROP_CAP_HMAC_KEY` so raw IPs and public keys are never persisted, and idle rate-limit windows auto-delete via DO alarms. If the `RATE_LIMITER` binding is omitted, the Worker falls back gracefully to an equivalent in-isolate sliding-window limiter.
- **Pre-body stateless capability checks**: `POST /v1/drops/{id}` verifies the HMAC-SHA256 `X-Hyphae-Drop-Cap` (`hdcap1_`) in constant time **before** reading a single byte of the request body.
- **Fail-closed CORS & Chrome PNA**: Only explicitly configured `ALLOWED_ORIGINS` (default `https://hyphae.to`) receive `Access-Control-Allow-Origin` and `Access-Control-Allow-Private-Network: true`. Wildcard `*` and `null` are always rejected.
- **Aggregate-only health**: `GET /v1/health` exposes only runtime mode and configured ceilings — never active drop IDs, client IPs, or keys.

---

## Auth Modes: `open` vs. `private` / `allowlist`

| Mode | Intended Deployment | `POST /v1/drops` Auth | Quotas & Abuse Protection |
| --- | --- | --- | --- |
| **`private`** *(alias `allowlist`, default)* | Self-hosted personal / team / enterprise relays | Fail-closed: Ed25519 signature required from a node pre-registered in `ALLOWED_NODE_KEYS` (alias `DROP_ALLOWED_KEYS`) | Per-node hourly + per-IP burst/hourly quotas via `RateLimiterDO` |
| **`open`** | Public zero-friction relay (e.g. `https://spore.hyphae.to`) | Any node can allocate a short-lived ciphertext-only slot without pre-registration by signing with `Hyphae-Ed25519` + `X-Hyphae-Public-Key` | Durable per-IP burst (`5/min`) + per-IP hourly (`20/hr`) + per-pubkey hourly (`10/hr`) + global guardrail (`120/min`) + recommended Cloudflare WAF rules |

---

## 30-Second Deploy

All commands run from `workers/drop-relay/` (no `npm install` or build step required):

```bash
cd workers/drop-relay
```

### Option A — Private Personal or Enterprise Drop Relay (Recommended Default)

`wrangler.toml` defaults to `DROP_AUTH_MODE = "private"` (alias `"allowlist"`, fail-closed). Only Ed25519 nodes listed in `ALLOWED_NODE_KEYS` (or alias `DROP_ALLOWED_KEYS`) can allocate drop slots.

1. **Set the stateless capability HMAC secret** (>= 32 random bytes):

   ```bash
   openssl rand -base64 32 | npx wrangler secret put DROP_CAP_HMAC_KEY
   ```

2. **Allowlist your Hyphae node(s)' Ed25519 public key(s)**:

   `ALLOWED_NODE_KEYS` (or alias `DROP_ALLOWED_KEYS`) accepts either a JSON object mapping `nodeId` to a 43-char unpadded base64url Ed25519 public key (or OKP JWK), or comma-separated `nodeId=<b64url>` pairs:

   ```bash
   # Example JSON format (recommended for teams):
   printf '%s' '{"alice@macbook":"<43-char-b64url-ed25519-pubkey>","bob@laptop":"<43-char-b64url-ed25519-pubkey>"}' \
     | npx wrangler secret put ALLOWED_NODE_KEYS

   # Or pair-list format:
   printf '%s' 'alice@macbook=<43-char-b64url-ed25519-pubkey>' \
     | npx wrangler secret put ALLOWED_NODE_KEYS
   ```

   *(Tip: you can read your local node's Ed25519 `signingJwk.x` from your node's signed manifest at `GET /v1/manifest` or from `hyp pair offer` / `node.sqlite`.)*

3. **Deploy**:

   ```bash
   npx wrangler deploy
   ```

4. **Point your Hyphae CLI at your private relay**:

   ```bash
   hyp relay set https://<your-worker-or-custom-domain>
   hyp relay status --probe
   ```

   *(Optional — self-host your own `/drop` UI & Passkey domain: upload the 4 static files in [`site/drop/`](../../site/drop/) to e.g. `https://drop.acme.com`, set `ALLOWED_ORIGINS = "https://drop.acme.com"` in `wrangler.toml`, and set `"dropPortalUrl": "https://drop.acme.com"` in `node.json` or `HYPHAE_DROP_PORTAL_URL=https://drop.acme.com`. Passkeys automatically bind to your own domain!)*

---

### Option B — Public Drop Relay (e.g. `https://spore.hyphae.to`)

Public `"open"` mode is intentionally used for `https://spore.hyphae.to` (`[env.production]` in `wrangler.toml`) so any Hyphae user can onboard with zero pre-registration. Any node can allocate a short-lived ciphertext-only slot by signing `POST /v1/drops` with `Authorization: Hyphae-Ed25519 ...` and supplying its Ed25519 public key in `X-Hyphae-Public-Key` (raw 43-char base64url or OKP JWK). Slots are pinned to the creator's `(nodeId, pubKey)` and enforced with durable `RateLimiterDO` per-IP burst (`5/min`), per-IP hourly (`20/hr`), and per-pubkey hourly (`10/hr`) limits.

1. **Enable `"open"` mode and custom domain in `wrangler.toml`** (already configured under `[env.production]` for `spore.hyphae.to`):

   ```toml
   [env.production]
   routes = [
     { pattern = "spore.hyphae.to", custom_domain = true }
   ]

   [env.production.vars]
   DROP_AUTH_MODE = "open"
   ALLOWED_ORIGINS = "https://hyphae.to"
   CREATES_PER_HOUR_PER_NODE = "10"
   CREATES_PER_HOUR_PER_IP = "20"
   CREATES_PER_MINUTE_PER_IP = "5"
   CREATES_PER_MINUTE_GLOBAL = "120"
   ```

2. **Set the HMAC secret and deploy**:

   ```bash
   openssl rand -base64 32 | npx wrangler secret put DROP_CAP_HMAC_KEY --env production
   npx wrangler deploy --env production
   ```

3. **Add Cloudflare WAF Edge Rate-Limiting Rules (Defense-in-Depth for Public Relays)**:

   Pair the built-in durable `RateLimiterDO` quotas with Cloudflare WAF edge rate-limiting rules so volumetric floods are dropped before invoking Worker compute:
   - **Rule 1 (Slot creation)**: `http.request.method eq "POST" and http.request.uri.path eq "/v1/drops"` -> limit e.g. `20 requests / 10 minutes` per IP (`429 Too Many Requests`).
   - **Rule 2 (Drop submission)**: `http.request.method eq "POST" and starts_with(http.request.uri.path, "/v1/drops/")` -> limit e.g. `60 requests / 1 minute` per IP.
   - **Privacy**: Disable or redact path/header logging in Cloudflare Logpush for `/v1/drops/*`.

4. **Point any Hyphae CLI at the public relay**:

   ```bash
   hyp relay set https://spore.hyphae.to
   hyp relay status --probe
   ```

---

## Zero-Downtime HMAC Key Rotation

Because drop slots have a hard maximum TTL of 15 minutes (`900s`), you can rotate `DROP_CAP_HMAC_KEY` without dropping a single in-flight session:

1. Copy the current key into `DROP_CAP_HMAC_KEY_PREV`:
   ```bash
   npx wrangler secret put DROP_CAP_HMAC_KEY_PREV
   ```
2. Generate and upload a fresh `DROP_CAP_HMAC_KEY`:
   ```bash
   openssl rand -base64 32 | npx wrangler secret put DROP_CAP_HMAC_KEY
   ```
3. After 15 minutes, delete the retired key:
   ```bash
   npx wrangler secret delete DROP_CAP_HMAC_KEY_PREV
   ```

---

## Wire API Summary

| Method & Path | Auth | Purpose |
| --- | --- | --- |
| `OPTIONS /v1/drops` & `/v1/drops/*` | None | Strict explicit CORS + Chrome PNA preflight (`204`) |
| `POST /v1/drops` | `Hyphae-Ed25519` (+ `X-Hyphae-Public-Key` in `open` mode) | Allocate ephemeral ciphertext-only DO slot with TTL alarm (`201`: `dropId`, `expiresAtMs`, `postCap`, `subCap`, `maxPayloadBytes`, `maxItems`) |
| `POST /v1/drops/{id}` | `X-Hyphae-Drop-Cap: <postCap>` (verified pre-body) | Persist opaque ciphertext `<= 64 KiB` in DO storage & wake SSE (`201`: `seq`, `expiresAtMs`) |
| `GET /v1/drops/{id}/stream` | `X-Hyphae-Drop-Cap: <subCap>` or creator `Hyphae-Ed25519` | SSE catch-up (`Last-Event-ID` / `?after=`, survives eviction) + live push + 25s `: keepalive` |
| `POST /v1/drops/{id}/ack` | `X-Hyphae-Drop-Cap: <subCap>` or creator `Hyphae-Ed25519` | Ack & burn/zeroize items in RAM + DO storage (`200`: `ackedSeq`, `burnedItems`, `burnedBytes`, `remainingItems`, `slotClosed`) |
| `GET /` & `GET /drop` | None | `302` redirect to the static zero-trust Drop UI (`https://hyphae.to/drop`, preserving `#fragment` client-side) |
| `GET /v1/health` | None | Aggregate-only health JSON (zero drop IDs, IPs, or secrets) |

---

## Local Verification (Zero Dependencies, Node 22/24+)

```bash
node --check src/index.mjs
node test/worker.test.mjs
```

---

## GitHub Actions Auto-Deploy Setup (`spore.hyphae.to`)

The workflow [`.github/workflows/deploy-drop-relay.yml`](../../.github/workflows/deploy-drop-relay.yml) automatically tests and deploys `workers/drop-relay/` to `https://spore.hyphae.to` (`--env production`) on every push to `main` touching `workers/drop-relay/**` (and skips cleanly without failing CI if secrets aren't configured yet).

**One-time operator setup (3 steps):**

1. **Create a minimally scoped Cloudflare Custom API Token** (*Cloudflare Dashboard → Profile → API Tokens → Create Custom Token*):
   - `Account → Workers Scripts → Edit`
   - `Account → Account Settings → Read`
   - `Zone → Workers Routes → Edit` (scoped strictly to zone `hyphae.to`)
2. **Add 2 GitHub Actions Secrets** (*Repo Settings → Secrets and variables → Actions*, or inside the `production-drop-relay` environment):
   - `CLOUDFLARE_API_TOKEN` — the scoped token from Step 1
   - `CLOUDFLARE_ACCOUNT_ID` — your 32-hex Cloudflare Account ID
3. **Seed `DROP_CAP_HMAC_KEY` once directly on Cloudflare** (NEVER store this key in GitHub Actions or `wrangler.toml`; `wrangler deploy` preserves existing Worker secrets automatically):
   ```bash
   cd workers/drop-relay
   openssl rand -base64 32 | tr '+/' '-_' | tr -d '=' | npx wrangler secret put DROP_CAP_HMAC_KEY --env production
   ```
   *(If `hyphae-drop-relay` doesn't exist yet on Cloudflare, trigger the `Deploy Drop Relay (Cloudflare Workers)` workflow once via `workflow_dispatch` first so the Worker is created, then run Step 3 to seed `DROP_CAP_HMAC_KEY` — `/v1/health` works immediately, and `POST /v1/drops` activates the moment `DROP_CAP_HMAC_KEY` is set.)*
