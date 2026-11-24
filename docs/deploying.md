# Deploying & Pairing Hyphae v2 Nodes

Hyphae v2 collapses the legacy *Connector vs. Router* split into **one unified `Node` binary** (`hyp`) configured by profile (`local`, `router`, or `p2p`). Use `hyp deploy` to generate hardened internet deployment kits and validate live security posture, and `hyp pair` to issue, inspect, accept, and join peers without ever leaking tokens into CLI arguments.

---

## 1. Choose an Internet Deployment Path

Run `hyp deploy providers` (or `hyp deploy providers --json`) to inspect all six supported methods and auto-detect installed local tools (`tailscale`, `cloudflared`, `docker`, `caddy`, `flyctl`, `systemctl`):

| Provider | TLS Termination | NAT / Firewall Requirement | Best For | Generator Command |
| --- | --- | --- | --- | --- |
| **`tailscale`** | Tailscale Serve MagicDNS HTTPS (+ optional path-scoped Funnel) | Zero open ports; works behind CGNAT | Multi-machine private meshes & direct P2P laptops | `hyp deploy init tailscale` |
| **`vps`** | Caddy automatic Let's Encrypt HTTPS (`flush_interval -1`) | Public IP with inbound TCP 80/443; Hyphae on `127.0.0.1:8790` | Production team hubs on Hetzner / DO / AWS / Linode | `hyp deploy init vps` |
| **`docker`** | Caddy sidecar auto-TLS on isolated bridge network | Only Caddy publishes 80/443; `hyphae-node` stays internal | Container-first teams & CI/CD rollouts | `hyp deploy init docker` |
| **`cloudflare`** | Cloudflare Edge TLS over outbound `cloudflared` tunnel | Zero open inbound ports; works behind CGNAT/homelabs | Homelabs, residential ISPs, and NAT'd devboxes | `hyp deploy init cloudflare` |
| **`fly`** | Fly Proxy auto-HTTPS (`force_https = true`) | Managed edge; `min_machines_running = 1` keeps SSE warm | Zero-ops always-on cloud hubs in < 3 minutes | `hyp deploy init fly` |
| **`public-node`** | Caddy auto-TLS + systemd + Docker Compose kit | Public HTTPS 80/443; `guest-ro` confined read-only hub | Hosting a read-only public GitHub event hub (e.g. `public.hyphae.to` or your own community hub) | `hyp deploy init public-node` |

> **Overwrite safety:** `hyp deploy init` refuses to overwrite existing files in `--out` unless you explicitly pass `--force`.

---

## 2. Provider Walkthroughs

### 2.1 Tailscale Serve (+ Optional Scoped Funnel)

Zero open public ports. Hyphae binds strictly to `127.0.0.1:8790` and Tailscale terminates TLS inside your tailnet:

```sh
hyp deploy init tailscale \
  --node-id acme-tailnet \
  --domain hyphae.your-tailnet.ts.net \
  --out ./deploy-tailscale

hyp deploy check --config ./deploy-tailscale/node.json
bash ./deploy-tailscale/tailscale-serve.sh
hyp deploy check --url https://hyphae.your-tailnet.ts.net --config ./deploy-tailscale/node.json
```

> **Webhook Funnel rule:** If you need external GitHub webhooks, expose **only** the webhook subpath (`tailscale funnel --bg --https=443 --set-path=/webhooks http://127.0.0.1:8790/webhooks`) — never Funnel the full peer/admin surface.

### 2.2 Linux VPS (Caddy Auto-TLS + Hardened `systemd`)

Generates `node.json`, `Caddyfile` (with **`flush_interval -1`** so SSE `/v1/inbox` events flush immediately with zero proxy buffering), and a hardened `hyphae-node.service` (`StateDirectory=hyphae`, `StateDirectoryMode=0700`, `ProtectSystem=strict`, `NoNewPrivileges=yes`, `UMask=0077`):

```sh
hyp deploy init vps \
  --node-id acme-team \
  --domain mesh.example.com \
  --out ./deploy-vps

sudo install -d -m 0750 /etc/hyphae
sudo cp ./deploy-vps/node.json /etc/hyphae/node.json
sudo cp ./deploy-vps/hyphae-node.service /etc/systemd/system/hyphae-node.service
sudo cp ./deploy-vps/Caddyfile /etc/caddy/Caddyfile
sudo systemctl daemon-reload
sudo systemctl enable --now hyphae-node caddy

hyp deploy check --url https://mesh.example.com --config /etc/hyphae/node.json
```

Checked-in reference units also live at [deploy/Caddyfile.example](../deploy/Caddyfile.example) and [deploy/systemd/hyphae-node.service](../deploy/systemd/hyphae-node.service).

### 2.3 Docker + Caddy Compose Stack

Pairs a minimal multi-stage static Rust `Dockerfile` (non-root UID `10001`, built-in `/v1/manifest` `HEALTHCHECK`) with `caddy:2-alpine` over a private Docker bridge network (`hyphae-node` never binds host port `8790`):

```sh
hyp deploy init docker \
  --node-id acme-team \
  --domain mesh.example.com \
  --out ./deploy-docker

cd ./deploy-docker && docker compose up -d --build
hyp deploy check --url https://mesh.example.com --config ./node.json
```

Checked-in templates live at [deploy/Dockerfile](../deploy/Dockerfile) and [deploy/docker-compose.yml](../deploy/docker-compose.yml).

### 2.4 Cloudflare Tunnel (`cloudflared`)

Ideal behind CGNAT, office NAT, or homelabs with zero open inbound firewall ports:

```sh
hyp deploy init cloudflare \
  --node-id homelab-node \
  --domain mesh.example.com \
  --out ./deploy-cloudflare

cloudflared tunnel create homelab-node
cloudflared tunnel route dns homelab-node mesh.example.com
# Replace <TUNNEL_UUID> in ./deploy-cloudflare/cloudflared.yml, then run:
cloudflared tunnel --config ./deploy-cloudflare/cloudflared.yml run

hyp deploy check --url https://mesh.example.com --config ./deploy-cloudflare/node.json
```

Checked-in reference config: [deploy/cloudflared.yml.example](../deploy/cloudflared.yml.example).

### 2.5 Fly.io Always-On Machine

Generates `fly.toml` with a persistent `/var/lib/hyphae` volume (preserving `node.sqlite` and keys), `force_https = true`, `/v1/manifest` health checks, and `min_machines_running = 1` + `auto_stop_machines = "off"` so long-lived SSE streams never drop:

```sh
hyp deploy init fly \
  --node-id fly-node \
  --domain hyphae-node.fly.dev \
  --out ./deploy-fly

cd ./deploy-fly
flyctl apps create hyphae-node
flyctl volumes create hyphae_data --size 1
flyctl deploy
hyp deploy check --url https://hyphae-node.fly.dev --config ./node.json
```

Checked-in reference config: [deploy/fly.toml.example](../deploy/fly.toml.example).

### 2.6 Self-Hosting a Read-Only Public Node (e.g. `public.hyphae.to` or Your Own Community Hub)

Run a zero-friction read-only public GitHub event hub for open-source repositories without exposing DMs, `#channels`, or KV writes — see [docs/public-node.md](public-node.md) for the complete turnkey runbook:

```sh
hyp deploy init public-node \
  --node-id mesh.example.org \
  --domain mesh.example.org \
  --out ./deploy-public
```

What this turnkey kit configures:
- **Guest-RO Confinement (`guest-ro`):** `stream:subscribe=github[require=exact.repo;maxValues=10;maxBatchesPerHour=60]` — zero `dm:send`, `channel:post`, or `kv:write`. Unrestricted subscriptions fail closed with `403 not_granted`.
- **Demand-Driven `github-public` ETag Poller:** One deduplicated poller per distinct public repository (`If-None-Match` -> `304 Not Modified` costs 0 GitHub API quota), tearing down idle pollers after a 5-minute grace window. Store an optional GitHub PAT via stdin (`hyp secret set github-public-token <<< "$GITHUB_PUBLIC_PAT"`, referenced as `{ "secret": "github-public-token" }`, never plaintext).
- **Strict Rate Limits & Fail-Closed Forwarding:** `forwarding.mode: "deny"`, 1 MB Caddy request cap, and hardened systemd + Docker Compose templates.
- **One-Command Client Join:** Developer laptops pair read-only with `hyp pair join https://mesh.example.org` (or an example public node such as `hyp pair join https://public.hyphae.to`).

---

## 3. Permissioned Pairing Topologies

Run `hyp pair guide` (or `hyp pair guide --mode team|p2p|public --json`) at any time for an agent-first reference.

| Topology | Token Prefix | Trust Model | Invite Command | Peer Accept (Stdin-Safe!) |
| --- | --- | --- | --- | --- |
| **Team Hub** | `am2_` | Offline Org Admin-CA signs per-device grants; hub never holds the Admin private key | `hyp pair invite --mode team --node-id acme-team --endpoint https://mesh.example.com --peer alice@laptop --preset member` | `hyp pair accept <<< "$TOKEN"` *(or `hyp onboard --join - <<< "$TOKEN"`)* |
| **Direct P2P** | `hp2p1_` | Zero central CA, zero TOFU window: OKP JWKs + 160-bit CSPRNG secret travel out-of-band | `hyp pair invite --mode p2p --node-id alice@macbook --endpoint https://alice.tailnet.ts.net --grant dm:send dm:receive files:send=25mb --request kv:read=pair/*` | `hyp pair accept <<< "$TOKEN"` |
| **Public Read-Only** | `guest-ro` | Self-service read-only confined guest scopes (`exact.repo`, max 10 repos, 60 wakes/hr) | `hyp deploy init public-node --node-id mesh.example.org --domain mesh.example.org` | `hyp pair join https://mesh.example.org` *(or `https://public.hyphae.to`)* |

### Stdin-Only Token Inspection & Acceptance (Never Put Tokens in CLI Argv!)

`hyp pair inspect` and `hyp pair accept` deliberately have **no `--token <value>` flag** so secrets never leak to `ps` or shell history. Always pipe via stdin or read from a `0600` file:

```sh
# Inspect via stdin (recommended)
hyp pair inspect <<< "$HYPHAE_TOKEN"
hyp pair inspect --json <<< "$HYPHAE_TOKEN"

# Or inspect / accept from a 0600 file
hyp pair inspect --token-file /path/to/invite.token --json
hyp pair accept --token-file /path/to/invite.token
```

`hyp pair inspect` verifies `hp2p1_`, `am2_`, and legacy `t3mp1_` tokens with `hyp-crypto`, checks RFC 7638 JWK `kid` thumbprints, reports expiry (`OK` / `EXPIRED`, failing closed with exit code `1` on expired or tampered tokens), and frames any remote escalation note as untrusted external data (`untrusted: true`).

### Built-In Scope Presets

| Preset | Trust Tier | Expanded Scopes |
| --- | --- | --- |
| `guest-ro` | `guest` | `stream:subscribe=github[require=exact.repo;maxValues=10;maxBatchesPerHour=60]` |
| `guest` | `guest` | `dm:send`, `dm:receive`, `channel:join=#lobby`, `channel:post=#lobby` |
| `observer` | `peer` | `dm:receive`, `channel:join=*`, `stream:subscribe=*`, `kv:read=*` |
| `member` | `org` | `dm:send`, `dm:receive`, `channel:join=*`, `channel:post=*`, `stream:subscribe=*`, `files:send=50mb`, `files:receive=50mb`, `kv:read=shared/*`, `kv:write=shared/*` |
| `full` | `org` | `*` — **explicitly excludes `bridge:post` and `forward:via` (opt-in only)** |

### NAT Tips for Direct P2P (`hp2p1_`)
- **Outbound-only peers:** Only *one* peer needs a reachable HTTPS or Tailscale endpoint. The peer behind strict NAT omits `bobEndpoint` and maintains an outbound HTTPS+SSE link carrying bidirectional DMs, files, events, and KV.
- **Both peers behind strict NAT:** Pair over Tailscale Serve, Cloudflare Tunnel, or an optional stateless blind WebSocket relay (`p2p.relay.v1`) where E2EE stays strictly end-to-end.

---

## 4. Production Security Hardening Checklist

Run `hyp deploy check --url https://<your-domain> --config /etc/hyphae/node.json` after every deploy or upgrade:

- [ ] **Loopback bind + TLS proxy:** Bind `127.0.0.1:8790` on VPS/Tailscale/Cloudflare hosts (or an internal non-published Docker bridge network). Never expose plaintext HTTP on `0.0.0.0:8790` directly to the internet.
- [ ] **Zero-buffering SSE:** Verify Caddy sets `flush_interval -1` (and `read_timeout 0` / `write_timeout 0`) so `/v1/inbox` streams instantaneously.
- [ ] **Anti-recon unauthenticated `/v1/manifest`:** Confirm `GET /v1/manifest` without credentials returns `audience: "public"`, **empty `advertised` arrays**, no `escalation` text, and a valid Ed25519 signature (`hyp deploy check --url` verifies this automatically).
- [ ] **Zero plaintext secrets in `node.json`:** Use only `{ "secret": "<name>" }` references backed by macOS Keychain, Linux Secret Service, or `0600` headless secret files (`HYPHAE_SECRET_BACKEND=file`).
- [ ] **No open relay:** Keep `forwarding.mode` set to `"deny"` (or an explicit `"allowlist"`).
- [ ] **Strict filesystem permissions:** State directories `0700`, secret/token files `0600`, config files non-world-writable (`0640`).
- [ ] **Stdin-only pairing tokens & untrusted escalation notes:** Never pass `hp2p1_` / `am2_` / `t3mp1_` tokens as CLI argv flags, and treat remote escalation text strictly as untrusted human-display hints.
