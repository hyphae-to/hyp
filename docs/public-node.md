# Hosting a Public Read-Only Node (Turnkey Runbook)

This runbook provides zero-ambiguity steps for an operator or autonomous agent to deploy and verify a read-only public Hyphae GitHub stream hub — such as the example hosted node `public.hyphae.to` or your own self-hosted community/organization public node — in under 5 minutes.

*(Substitute your own hostname for `public.hyphae.to` below whenever self-hosting your own public node.)*

## Architecture & Security Guarantees

- **Strict `guest-ro` confinement**: Self-service `POST /v1/guest/pair` enrolls clients into `TrustTier::Guest` with `stream:subscribe=github[require=exact.repo;maxValues=10;maxBatchesPerHour=60]` — **zero** DM (`dm:send`), `#channel` write (`channel:post`), KV write (`kv:write`), or file transfer scopes.
- **Anti-hijack identity pinning**: `POST /v1/guest/pair` requires a fresh (±5 min RFC 3339) Ed25519 possession proof under domain `"guest-pair"` over canonical RFC 8785 JCS. Re-enrolling with the same Ed25519 key is idempotent; attempting to claim an existing `nodeId` with a different key fails closed with HTTP `409 peer_key_mismatch`.
- **Fail-closed GitHub visibility lint**: `PUT /v1/subscriptions` verifies every requested `exact.repo` via `GET /repos/{owner}/{repo}` before persisting. Private or missing repos are rejected fail-closed with HTTP `422 subscription_rejected`.
- **Demand-driven deduplicated ETag polling**: Exactly **one** poller runs per distinct `owner/repo` regardless of subscriber count (1 or 5,000). Conditional `If-None-Match` polls returning `304 Not Modified` consume **0** GitHub API quota, adaptively back off (`1x -> 2x -> 5x`), snap back on `200`, and tear down cleanly after the grace window once subscriber refcount drops to `0`.
- **Anti-recon unauthenticated `/v1/manifest`**: Unauthenticated `GET /v1/manifest` returns a signed manifest with `audience: "public"`, strictly empty `advertised` arrays, and no `escalation` text.
- **Unauthenticated health telemetry**: `GET /v1/health` exposes only aggregate operational counters (`ok`, `nodeId`, `profile`, `guestPairingEnabled`, `githubPublic.activePollers`, `pollsTotal`, `polls200`, `polls304`, `appWebhooksPublished`) — zero private data or repo names.
- **Zero plaintext secrets**: Optional `github-public-token` (5,000 req/hr instead of 60 req/hr) and `github-app-webhook-secret` (for `<1s` GitHub App push on `POST /v1/webhooks/github-app`) are stored strictly in `SecretStore` (`0600` files when `HYPHAE_SECRET_BACKEND=file`), referenced in `node.json` only as `{ "secret": "<name>" }`.

---

## Prerequisites

1. **DNS**: Point an `A` (and optional `AAAA`) record for your public node domain (e.g. `public.hyphae.to` or `mesh.example.org`) to the host's public IPv4/IPv6 address.
2. **Firewall**: Allow inbound TCP `80` and `443` (and UDP `443` for HTTP/3) to Caddy / Fly Proxy. Keep Hyphae port `8790` strictly loopback (`127.0.0.1:8790`) or on an internal Docker network.
3. **Binary**: Install the static `hyp` binary (~6 MiB compressed download) on the server via `curl -fsSL https://hyphae.to/install.sh | sh` (or build via [deploy/Dockerfile](../deploy/Dockerfile)).

---

## Step 1 — Generate the Hardened Public Node Kit

Run once to generate `node.json`, `Caddyfile`, `hyphae-node.service`, `Dockerfile`, and `docker-compose.yml` (replace `public.hyphae.to` with your domain when self-hosting):

```sh
hyp deploy init public-node \
  --node-id public.hyphae.to \
  --domain public.hyphae.to \
  --out ./deploy-public \
  --json
```

Verify the generated configuration passes all checks and contains zero plaintext secrets:

```sh
hyp deploy check --config ./deploy-public/node.json --json
```

---

## Step 2 — Choose One Deployment Target

### Option A: Linux VPS + Caddy Auto-TLS + Hardened `systemd` (Recommended)

1. Create the dedicated unprivileged user and install the generated files:

```sh
sudo useradd --system --home-dir /var/lib/hyphae --shell /usr/sbin/nologin hyphae || true
sudo install -d -m 0700 -o hyphae -g hyphae /var/lib/hyphae
sudo install -d -m 0750 -o root -g hyphae /etc/hyphae
sudo install -m 0640 -o root -g hyphae ./deploy-public/node.json /etc/hyphae/node.json
sudo cp ./deploy-public/hyphae-node.service /etc/systemd/system/hyphae-node.service
sudo cp ./deploy-public/Caddyfile /etc/caddy/Caddyfile
```

2. *(Optional, recommended for production traffic)* Store a fine-grained public read-only GitHub PAT in `SecretStore` (raises GitHub REST rate limit from 60 req/hr to 5,000 req/hr; **never** put tokens in CLI argv or `node.json`):

```sh
# Pipe token via stdin as the `hyphae` service user (0600 file in /var/lib/hyphae/secrets/)
printf '%s' "$GITHUB_PUBLIC_PAT" | sudo -u hyphae \
  HYPHAE_SECRET_BACKEND=file HYPHAE_STATE_DIR=/var/lib/hyphae \
  /usr/local/bin/hyp secret set github-public-token --state-dir /var/lib/hyphae
```

*(If skipped, `hyp node start` starts cleanly in unauthenticated public GitHub mode and logs a concise warning.)*

3. Start and enable both services:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now hyphae-node caddy
sudo systemctl status hyphae-node --no-pager
```

---

### Option B: Docker Compose + Caddy Auto-TLS

1. In `./deploy-public/node.json`, change `listen.bind` from `"127.0.0.1:8790"` to `"0.0.0.0:8790"` (safe because `behindReverseProxy: true` and `docker-compose.yml` does **not** publish port `8790` on the host).
2. In `./deploy-public/Caddyfile`, change `reverse_proxy 127.0.0.1:8790` to `reverse_proxy hyphae-node:8790` (keeping `flush_interval -1`).
3. Copy `Cargo.toml`, `Cargo.lock`, and `crates/` (or run from repo root with [deploy/Dockerfile](../deploy/Dockerfile) and [deploy/docker-compose.yml](../deploy/docker-compose.yml)) and launch:

```sh
docker compose -f ./deploy-public/docker-compose.yml up -d --build
```

4. *(Optional)* Set `github-public-token` inside the persistent `hyphae_state` volume via stdin:

```sh
printf '%s' "$GITHUB_PUBLIC_PAT" | docker compose -f ./deploy-public/docker-compose.yml exec -T hyphae-node \
  hyp secret set github-public-token --state-dir /var/lib/hyphae
docker compose -f ./deploy-public/docker-compose.yml restart hyphae-node
```

---

### Option C: Fly.io Always-On Machine

1. Generate a Fly config (or start from [deploy/fly.toml.example](../deploy/fly.toml.example)) and include `./deploy-public/node.json` with `listen.bind = "0.0.0.0:8790"` and `listen.behindReverseProxy = true` mounted/copied to `/etc/hyphae/node.json`.
2. Create the Fly app, persistent `/var/lib/hyphae` volume (retains `node.sqlite`, persistent Ed25519/X25519 keys, and `secrets/`), and TLS certificate:

```sh
flyctl apps create public-hyphae-to
flyctl volumes create hyphae_data --size 1 --region iad --app public-hyphae-to
flyctl certs add public.hyphae.to --app public-hyphae-to
```

3. Deploy (Fly keeps `min_machines_running = 1` and `auto_stop_machines = "off"` so long-lived SSE `/v1/inbox` streams never disconnect, and probes `GET /v1/health`):

```sh
flyctl deploy --app public-hyphae-to
```

4. *(Optional)* Store `github-public-token` on the mounted volume via `flyctl ssh console`:

```sh
printf '%s' "$GITHUB_PUBLIC_PAT" | flyctl ssh console --app public-hyphae-to \
  -C "hyp secret set github-public-token --state-dir /var/lib/hyphae"
flyctl machine restart --app public-hyphae-to
```

---

## Step 3 — Live Post-Deploy Verification (Smoke Test)

Run every check below from any developer machine or CI runner:

### 1. Hardening, TLS, Signed Manifest & Anti-Recon Check

```sh
hyp deploy check --url https://public.hyphae.to --config ./deploy-public/node.json --json
```

Expected: exit code `0`, `ok: true`, `data.manifest.signatureVerified == true`, `data.manifest.advertisedEmpty == true`, `data.manifest.escalationPresent == false`, and `data.checks` reporting `status == "ok"` for `manifest.signature`, `manifest.anti_recon`, and `config.secrets`.

### 2. Health & Adapter Readiness Check

```sh
curl -fsS https://public.hyphae.to/v1/health
```

Expected JSON:

```json
{
  "ok": true,
  "nodeId": "public.hyphae.to",
  "profile": "router",
  "guestPairingEnabled": true,
  "githubPublic": {
    "enabled": true,
    "activePollers": 0,
    "pollsTotal": 0,
    "polls200": 0,
    "polls304": 0,
    "appWebhooksPublished": 0
  }
}
```

### 3. Developer Laptop Self-Service Enrollment Smoke Test

Test joining from an isolated temporary state directory (never touches your live `~/.config/hyphae`):

```sh
SMOKE_DIR=$(mktemp -d)
HYPHAE_SECRET_BACKEND=file hyp pair join https://public.hyphae.to \
  --state-dir "$SMOKE_DIR" \
  --node-id smoke@verify \
  --json
rm -rf "$SMOKE_DIR"
```

Expected: exit code `0`, `ok: true`, `data.enrolled == true`, `data.preset == "guest-ro"`, `data.manifestVerified == true`, and `data.scopes` equal to `["stream:subscribe=github[require=exact.repo;maxValues=10;maxBatchesPerHour=60]"]`.

---

## Optional: `<1s` GitHub App Push Upgrade (`POST /v1/webhooks/github-app`)

To receive sub-second push deliveries for repositories that install a GitHub App pointed at your public node:

1. Add `"appWebhookSecret": { "secret": "github-app-webhook-secret" }` to the `github-public` entry in `sources[]` inside `/etc/hyphae/node.json`.
2. Store the webhook secret via stdin:
   ```sh
   printf '%s' "$GITHUB_APP_WEBHOOK_SECRET" | sudo -u hyphae \
     HYPHAE_SECRET_BACKEND=file HYPHAE_STATE_DIR=/var/lib/hyphae \
     /usr/local/bin/hyp secret set github-app-webhook-secret --state-dir /var/lib/hyphae
   ```
3. Restart `hyphae-node`. GitHub App deliveries to `POST https://<your-domain>/v1/webhooks/github-app` are strictly HMAC-SHA256 verified (`X-Hub-Signature-256`; invalid signatures return HTTP `401`) and deduplicated with the ETag poller pool. When `appWebhookSecret` is not configured, the route fails closed with HTTP `404`.

---

## Optional: Co-Hosting a RAM-Only Blind Drop Relay (`--enable-drop-relay`)

You can optionally co-host Hyphae's RAM-only zeroized ciphertext **Drop Relay** (`drop.relay.v1`) on the same host by passing `--enable-drop-relay` (and optional `--max-memory-mb 256`) during kit generation:

```sh
hyp deploy init public-node \
  --node-id mesh.example.org \
  --domain mesh.example.org \
  --enable-drop-relay \
  --max-memory-mb 256 \
  --out ./deploy-public
```

- **Strict `drop:create` isolation**: Default self-service `guest-ro` grants strictly **exclude** `drop:create`, so anonymous public-node guests cannot allocate relay slots. Operators grant `drop:create` explicitly only to trusted/paired nodes (or issue dedicated `am2_` grants).
- **Zero-disk ciphertext & health telemetry**: Relay slots hold only bounded RAM-only ciphertext verified via stateless HMAC-SHA256 `hdcap1_` tokens before reading request bodies, burned on `POST /v1/drops/{id}/ack` or TTL expiry. Works seamlessly with both zero-knowledge secret drops and v0.5.0 HPKE-encrypted directive prefills (`encDraft` / `human.draft.v1` sealed in `#drop=`). `GET /v1/health` reports only aggregate `dropRelay` counters (zero slot IDs or payloads).
- Want a dedicated relay-only host without public GitHub streams? Use `hyp deploy init drop-relay --domain drop.example.com --max-memory-mb 256` (see [docs/deploying.md](deploying.md)).
