# Hosting a Public Read-Only Node (Operator Runbook)

This runbook provides step-by-step instructions for an operator or autonomous agent to deploy, configure DNS and optional secrets for, and verify a read-only public Hyphae GitHub stream hub — such as the example hosted node `public.hyphae.to` or your own self-hosted community/organization public node.

*(Substitute your own hostname for `public.hyphae.to` below whenever self-hosting your own public node.)*

## Architecture & Security Guarantees

- **Strict `guest-ro` confinement**: Self-service `POST /v1/guest/pair` enrolls clients into `TrustTier::Guest` with `stream:subscribe=github[require=exact.repo;maxValues=10;maxBatchesPerHour=60]` — **zero** DM (`dm:send`), `#channel` write (`channel:post`), KV write (`kv:write`), or file transfer scopes.
- **Anti-hijack identity pinning**: `POST /v1/guest/pair` requires a fresh (±5 min RFC 3339) Ed25519 possession proof under domain `"guest-pair"` over canonical RFC 8785 JCS. Re-enrolling with the same Ed25519 key is idempotent; attempting to claim an existing `nodeId` with a different key fails closed with HTTP `409 peer_key_mismatch`.
- **Trusted reverse proxy CIDR allowlist (`listen.trustedProxies`)**: Forwarded client IP headers (`X-Forwarded-For` / `Forwarded`) are trusted **only** when the immediate peer socket address matches `listen.trustedProxies` — a CIDR allowlist defaulting to **`["127.0.0.1/32", "::1/128"]`** (preventing rate-limit spoofing from untrusted network peers).
- **Fail-closed GitHub visibility lint**: `PUT /v1/subscriptions` verifies every requested `exact.repo` via `GET /repos/{owner}/{repo}` before persisting. Private or missing repos are rejected fail-closed with HTTP `422 subscription_rejected`.
- **Demand-driven deduplicated ETag polling**: Exactly **one** poller runs per distinct `owner/repo` regardless of subscriber count (1 or 5,000). Conditional `If-None-Match` polls returning `304 Not Modified` consume **0** GitHub API quota, adaptively back off (`1x -> 2x -> 5x`), snap back on `200`, and tear down cleanly after the grace window once subscriber refcount drops to `0`.
- **Anti-recon unauthenticated `/v1/manifest`**: Unauthenticated `GET /v1/manifest` returns a signed manifest with `audience: "public"`, strictly empty `advertised` arrays, and no `escalation` text.
- **Unauthenticated health telemetry**: `GET /v1/health` exposes only aggregate operational counters (`ok`, `nodeId`, `profile`, `guestPairingEnabled`, `githubPublic.activePollers`, `pollsTotal`, `polls200`, `polls304`) — zero private data or repo names.
- **Zero plaintext secrets**: An optional `github-public-token` (5,000 req/hr instead of 60 req/hr) is stored strictly in `SecretStore` (`0600` files when `HYPHAE_SECRET_BACKEND=file`), referenced in `node.json` only as `{ "secret": "<name>" }`.

---

## Prerequisites

1. **DNS**: Point an `A` (and optional `AAAA`) record for your public node domain (e.g. `public.hyphae.to` or `mesh.example.org`) to the host's public IPv4/IPv6 address.
2. **Firewall**: Allow inbound TCP `80` and `443` (and UDP `443` for HTTP/3) to Caddy / Fly Proxy. Keep Hyphae port `8790` strictly loopback (`127.0.0.1:8790`) or on an internal Docker network.
3. **Binary**: Install the self-contained `hyp` binary (~8 MiB compressed download; static musl on Linux x86_64, native glibc on Linux arm64) on the server via `curl -fsSL https://hyphae.to/install.sh | sh` (or build via [deploy/Dockerfile](../../deploy/Dockerfile)).

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

*(With Caddy running on loopback `127.0.0.1`, the default `listen.trustedProxies: ["127.0.0.1/32", "::1/128"]` works out of the box.)*

2. *(Optional, recommended for production traffic)* Store a fine-grained public read-only GitHub PAT in `SecretStore` (raises GitHub REST rate limit from 60 req/hr to 5,000 req/hr; **never** put tokens in CLI argv or `node.json`):

```sh
# Pipe token via stdin as the `hyphae` service user (0600 file in /var/lib/hyphae/secrets/)
printf '%s' "$GITHUB_PUBLIC_PAT" | sudo -u hyphae HYPHAE_SECRET_BACKEND=file \
  hyp secret set github-public-token --state-dir /var/lib/hyphae
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

1. In `./deploy-public/node.json` (kept at host mode `0644` so non-root container UID `10001` can read it bind-mounted `:ro`, since `node.json` holds zero plaintext secrets), set `listen.bind` to `"0.0.0.0:8790"` and configure **`listen.trustedProxies`** to include the isolated internal Docker bridge subnet (for example `["127.0.0.1/32", "::1/128", "172.16.0.0/12"]`, or your exact Compose bridge CIDR). `docker-compose.yml` does **not** publish port `8790` on the host, and `trustedProxies` ensures forwarded IP headers are honored strictly from Caddy.
2. In `./deploy-public/Caddyfile`, change `reverse_proxy 127.0.0.1:8790` to `reverse_proxy hyphae-node:8790` (keeping `flush_interval -1`).
3. Launch from the kit directory (or repo root with [deploy/Dockerfile](../../deploy/Dockerfile) and [deploy/docker-compose.yml](../../deploy/docker-compose.yml)):

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

1. Generate a Fly config (or start from [deploy/fly.toml.example](../../deploy/fly.toml.example)) and include `./deploy-public/node.json` with `listen.bind = "0.0.0.0:8790"` and **`listen.trustedProxies`** scoped to loopback + Fly Proxy's private network CIDRs (e.g. `["127.0.0.1/32", "::1/128", "172.16.0.0/12", "fdaa::/16"]`) baked/copied to `/etc/hyphae/node.json`.
2. Create the Fly app, persistent `/var/lib/hyphae` volume (the container entrypoint fixes volume ownership to non-root UID `10001:10001` `0700` before starting `hyp`; retains `node.sqlite`, persistent Ed25519/X25519 keys, and `secrets/`), and TLS certificate:

```sh
flyctl apps create public-hyphae-to
flyctl volumes create hyphae_data --size 1 --region iad --app public-hyphae-to
flyctl certs add public.hyphae.to --app public-hyphae-to
```

3. Deploy (Fly keeps `min_machines_running = 1` and `auto_stop_machines = "off"` so long-lived SSE `/v1/inbox` streams never disconnect, and probes `GET /v1/health`):

```sh
flyctl deploy --app public-hyphae-to
```

4. *(Optional)* Store `github-public-token` on the mounted volume as UID `10001` via `flyctl ssh console`:

```sh
printf '%s' "$GITHUB_PUBLIC_PAT" | flyctl ssh console --app public-hyphae-to \
  -C "su -s /bin/sh hyphae -c 'HYPHAE_SECRET_BACKEND=file hyp secret set github-public-token --state-dir /var/lib/hyphae'"
flyctl apps restart public-hyphae-to
```

---

## Step 3 — Live Post-Deploy Verification (Smoke Test)

### 1. Hardening, TLS, Signed Manifest & Anti-Recon Check

```sh
hyp deploy check --url https://public.hyphae.to --config ./deploy-public/node.json --json
```

### 2. Health & Adapter Readiness Check

```sh
curl -fsS https://public.hyphae.to/v1/health
```

### 3. Developer Laptop Self-Service Enrollment Smoke Test

```sh
SMOKE_DIR=$(mktemp -d)
HYPHAE_SECRET_BACKEND=file hyp pair join https://public.hyphae.to \
  --state-dir "$SMOKE_DIR" \
  --node-id smoke@verify \
  --json
rm -rf "$SMOKE_DIR"
```

---

## Repository webhooks

This public node uses the GitHub Events API for polling. For signed push delivery from a repository you manage, configure the [repository webhook receiver](../plugins.md#repository-webhook-setup) on your own node. The unfinished hosted App route was removed. You can remove any old `appWebhookSecret` reference from the polling source.

## Optional: Co-Hosted RAM-Only Drop Relay

- **Co-hosted RAM-only Drop Relay:** Pass `--enable-drop-relay --max-memory-mb 256` to `hyp deploy init public-node` (see [Deploying Nodes](../operations/deploying.md#27-self-hostable-blind-drop-relay-drop-relay)). Default `guest-ro` grants strictly exclude `drop:create`.

---

## What You Should See

- `hyp deploy check --url https://<domain>` exits `0` with `manifest.signatureVerified == true` and `manifest.advertisedEmpty == true`.
- The isolated `hyp pair join` smoke test returns `enrolled == true`, `preset == "guest-ro"`, and `scopes == ["stream:subscribe=github[require=exact.repo;maxValues=10;maxBatchesPerHour=60]"]`.

If TLS, manifest verification, or polling fails, see [Troubleshooting](../operations/troubleshooting.md).
