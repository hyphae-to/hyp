# Hyphae Blind Drop Relay — Cloudflare Workers Kit

A zero-dependency, RAM-only Blind Ephemeral Drop Relay for **Hyphae Verified Human Drops** (`hdrop1_`), built on Cloudflare Workers + Durable Objects (`DropSlotDO`).

Speaks the exact same HTTP/SSE and stateless `hdcap1_` wire protocol as `crates/hyp-node/src/engine/drop_relay.rs`, and supports both **Private / Team allowlist mode** (default, fail-closed) and **Public relay mode** (e.g. `spore.hyphae.to`) via a single `DROP_AUTH_MODE` switch.

---

## Privacy & RAM-Only Guarantees

- **Zero persistent storage**: `DropSlotDO` **never** calls `ctx.storage` (`get`, `put`, `delete`, or `setAlarm`). Every ciphertext payload lives strictly as an in-memory `Uint8Array` inside volatile isolate RAM.
- **Immediate zeroization**: Every buffered `Uint8Array` is overwritten in place with `.fill(0)` on burn (`POST /v1/drops/{id}/ack { burn: true }`), TTL expiration (hard max `900s` / 15 min), or slot close. Temporary Worker copies are zeroized immediately after forwarding.
- **Zero sensitive logging**: The Worker never calls `console.log` and never records `dropId`, client IPs, `postCap`/`subCap` tokens, public keys, or payload bytes.
- **Pre-body stateless capability checks**: `POST /v1/drops/{id}` verifies the HMAC-SHA256 `X-Hyphae-Drop-Cap` (`hdcap1_`) in constant time **before** reading a single byte of the request body.
- **Fail-closed CORS & Chrome PNA**: Only explicitly configured `ALLOWED_ORIGINS` (default `https://hyphae.to`) receive `Access-Control-Allow-Origin` and `Access-Control-Allow-Private-Network: true`. Wildcard `*` and `null` are always rejected.
- **Aggregate-only health**: `GET /v1/health` exposes only runtime mode and configured ceilings — never active drop IDs, client IPs, or keys.

---

## 30-Second Deploy

All commands run from `workers/drop-relay/` (no `npm install` or build step required):

```bash
cd workers/drop-relay
```

### Option A — Private Personal or Team Drop Relay (Recommended Default)

`wrangler.toml` defaults to `DROP_AUTH_MODE = "private"` (fail-closed). Only Ed25519 nodes listed in `ALLOWED_NODE_KEYS` can allocate drop slots.

1. **Set the stateless capability HMAC secret** (>= 32 random bytes):

   ```bash
   openssl rand -base64 32 | npx wrangler secret put DROP_CAP_HMAC_KEY
   ```

2. **Allowlist your Hyphae node(s)' Ed25519 public key(s)**:

   `ALLOWED_NODE_KEYS` accepts either a JSON object mapping `nodeId` to a 43-char unpadded base64url Ed25519 public key (or OKP JWK), or comma-separated `nodeId=<b64url>` pairs:

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

### Option B — Public Drop Relay (e.g. `spore.hyphae.to`)

Public mode allows any Hyphae node to allocate ephemeral blind slots by signing `POST /v1/drops` with `Authorization: Hyphae-Ed25519 ...` and supplying its Ed25519 public key in `X-Hyphae-Public-Key` (raw 43-char base64url or OKP JWK). Slots are pinned to the creator's `(nodeId, pubKey)` and rate-limited per IP and per public key.

1. **Enable `"open"` mode and custom domain in `wrangler.toml`**:

   ```toml
   routes = [
     { pattern = "spore.hyphae.to", custom_domain = true }
   ]

   [vars]
   DROP_AUTH_MODE = "open"
   ALLOWED_ORIGINS = "https://hyphae.to"
   ```

2. **Set the HMAC secret and deploy**:

   ```bash
   openssl rand -base64 32 | npx wrangler secret put DROP_CAP_HMAC_KEY
   npx wrangler deploy
   ```

3. **Add a Cloudflare WAF Rate-Limiting Rule (Recommended for Public Relays)**:

   Because Worker isolate memory is per-PoP, pair the built-in isolate limiter with a Cloudflare WAF edge rate-limiting rule:
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
| `POST /v1/drops` | `Hyphae-Ed25519` (+ `X-Hyphae-Public-Key` in `open` mode) | Allocate ephemeral RAM slot (`201`: `dropId`, `expiresAtMs`, `postCap`, `subCap`, `maxPayloadBytes`, `maxItems`) |
| `POST /v1/drops/{id}` | `X-Hyphae-Drop-Cap: <postCap>` (verified pre-body) | Post opaque ciphertext `<= 64 KiB` (`201`: `seq`, `expiresAtMs`) |
| `GET /v1/drops/{id}/stream` | `X-Hyphae-Drop-Cap: <subCap>` or creator `Hyphae-Ed25519` | SSE catch-up (`Last-Event-ID` / `?after=`) + live push + 25s `: keepalive` |
| `POST /v1/drops/{id}/ack` | `X-Hyphae-Drop-Cap: <subCap>` or creator `Hyphae-Ed25519` | Ack & burn/zeroize items (`200`: `ackedSeq`, `burnedItems`, `burnedBytes`, `remainingItems`, `slotClosed`) |
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
