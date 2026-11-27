# Deploying Hyphae Nodes

Every Hyphae deployment runs the exact same `hyp` binary configured by profile (`local`, `router`, or `p2p`). Use `hyp deploy init` to generate hardened deployment kits and `hyp deploy check` to validate live security posture.

---

## 1. Choose a Deployment Provider

Run `hyp deploy providers` (or `--json`) to inspect all seven supported kits and auto-detect installed local tools (`tailscale`, `cloudflared`, `docker`, `caddy`, `flyctl`, `systemctl`):

| Provider | TLS Termination | NAT / Firewall Requirement | Best For | Generator Command |
| --- | --- | --- | --- | --- |
| **`tailscale`** | Tailscale Serve MagicDNS HTTPS (plus optional dedicated webhook Funnel port) | Zero open ports; works behind CGNAT | Private meshes & Direct P2P laptops | `hyp deploy init tailscale` |
| **`vps`** | Caddy automatic Let's Encrypt HTTPS (`flush_interval -1`) | Public IP with inbound TCP 80/443; Hyphae on `127.0.0.1:8790` | Production hubs on Hetzner / DO / AWS / Linode | `hyp deploy init vps` |
| **`docker`** | Caddy sidecar auto-TLS on isolated bridge network | Only Caddy publishes 80/443; `hyphae-node` stays internal | Container-first teams & CI/CD rollouts | `hyp deploy init docker` |
| **`cloudflare`** | Cloudflare Edge TLS over outbound `cloudflared` tunnel | Zero open inbound ports; works behind CGNAT/homelabs | Homelabs and NAT'd devboxes | `hyp deploy init cloudflare` |
| **`fly`** | Fly Proxy auto-HTTPS (`force_https = true`) | Managed edge; `min_machines_running = 1` keeps SSE warm | Always-on cloud hubs (requires app/volume creation, optional DNS cert, and `hyphae-admin-pubkey` provisioning) | `hyp deploy init fly` |
| **`public-node`** | Caddy auto-TLS + systemd + Docker Compose kit | Public HTTPS 80/443; `guest-ro` confined read-only hub | Read-only public GitHub stream hub ([runbook](../guides/public-node.md)) | `hyp deploy init public-node` |
| **`drop-relay`** | Caddy auto-TLS (`flush_interval -1`) + systemd + Docker Compose + Fly kit | Public HTTPS 80/443 (or Tailscale Serve); RAM-only ciphertext buffer | Self-hosted Blind Drop Relay (`256 MiB` default RAM cap) | `hyp deploy init drop-relay` |

> **Overwrite safety:** `hyp deploy init` refuses to overwrite existing files in `--out` unless `--force` is passed.
> **Co-hosting a RAM-only Drop Relay:** Pass `--enable-drop-relay` (and optional `--max-memory-mb 256`) to `hyp deploy init <public-node|vps|docker|tailscale|fly>`.

---

## 2. Provider Walkthroughs

### 2.1 Tailscale Serve (+ Optional Scoped Funnel)

```sh
hyp deploy init tailscale \
  --node-id acme-tailnet \
  --domain hyphae.your-tailnet.ts.net \
  --out ./deploy-tailscale

hyp deploy check --config ./deploy-tailscale/node.json
bash ./deploy-tailscale/tailscale-serve.sh
hyp deploy check --url https://hyphae.your-tailnet.ts.net --config ./deploy-tailscale/node.json
```

For public plugin webhooks, run [webhook routing setup](#public-webhook-routing) with the plugin’s dedicated loopback receiver. Funnel and Serve share the visibility of an HTTPS port. Keep the private peer server on a different port.

### 2.2 Linux VPS (Caddy Auto-TLS + Hardened `systemd`)

Generates `node.json`, `Caddyfile` (with **`flush_interval -1`** for zero-buffering SSE), and a hardened `hyphae-node.service` (`StateDirectory=hyphae`, `StateDirectoryMode=0700`, `ProtectSystem=strict`, `NoNewPrivileges=yes`, `UMask=0077`):

```sh
hyp deploy init vps \
  --node-id acme-team \
  --domain mesh.example.com \
  --out ./deploy-vps

sudo useradd --system --home-dir /var/lib/hyphae --shell /usr/sbin/nologin hyphae || true
sudo install -d -m 0700 -o hyphae -g hyphae /var/lib/hyphae
sudo install -d -m 0750 -o root -g hyphae /etc/hyphae
sudo install -m 0640 -o root -g hyphae ./deploy-vps/node.json /etc/hyphae/node.json
sudo cp ./deploy-vps/hyphae-node.service /etc/systemd/system/hyphae-node.service
sudo cp ./deploy-vps/Caddyfile /etc/caddy/Caddyfile
sudo systemctl daemon-reload
sudo systemctl enable --now hyphae-node caddy

# Team Hubs: provision ONLY the public Admin-CA JWK (keep the private key on the admin laptop):
printf '%s\n' "$ADMIN_JWK" | sudo -u hyphae HYPHAE_SECRET_BACKEND=file \
  hyp secret set hyphae-admin-pubkey --state-dir /var/lib/hyphae
sudo systemctl restart hyphae-node

hyp deploy check --url https://mesh.example.com --config /etc/hyphae/node.json
```

Reference files: [deploy/Caddyfile.example](../../deploy/Caddyfile.example), [deploy/systemd/hyphae-node.service](../../deploy/systemd/hyphae-node.service).

### 2.3 Docker + Caddy Compose Stack

Pairs a minimal multi-stage Rust `Dockerfile` (non-root UID `10001:10001`, built-in `/v1/manifest` `HEALTHCHECK`) with `caddy:2-alpine` over an isolated Docker bridge network (`hyphae-node` never publishes port `8790` on the host):

- **`node.json` permissions (`0644` host bind-mount vs. `0640` VPS/baked):** Because `node.json` holds **zero plaintext secrets** (all credentials live in `/var/lib/hyphae/secrets` inside the `0700` UID `10001` `hyphae_state` volume), keep host `./node.json` at mode **`0644`** (non-world-writable) so container UID `10001:10001` can read `./node.json:/etc/hyphae/node.json:ro`. (On systemd VPS hosts or inside baked images owned `10001:10001`, use `0640`.)
- **Trusted proxy CIDRs:** Scope `listen.trustedProxies` to loopback plus your isolated Compose bridge CIDR (e.g. `["127.0.0.1/32", "::1/128", "172.16.0.0/12"]`).

```sh
hyp deploy init docker \
  --node-id acme-team \
  --domain mesh.example.com \
  --out ./deploy-docker

cd ./deploy-docker && docker compose up -d --build

# Team Hubs: provision the public Admin-CA JWK into /var/lib/hyphae/secrets:
printf '%s\n' "$ADMIN_JWK" | docker compose exec -T hyphae-node \
  hyp secret set hyphae-admin-pubkey --state-dir /var/lib/hyphae
docker compose restart hyphae-node

hyp deploy check --url https://mesh.example.com --config ./node.json
```

Reference files: [deploy/Dockerfile](../../deploy/Dockerfile), [deploy/docker-compose.yml](../../deploy/docker-compose.yml).

### 2.4 Cloudflare Tunnel (`cloudflared`)

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

Reference file: [deploy/cloudflared.yml.example](../../deploy/cloudflared.yml.example).

### 2.5 Fly.io Always-On Machine

Generates `fly.toml`, `node.json` (baked into `/etc/hyphae/node.json`), and a `Dockerfile` whose entrypoint normalizes persistent `/var/lib/hyphae` volume ownership to non-root **UID `10001:10001` (`0700`)** before dropping privileges to run `hyp node start` (ensuring freshly mounted `root:root` Fly volumes boot cleanly). `fly.toml` enforces `force_https = true`, `/v1/health` checks, and `min_machines_running = 1` + `auto_stop_machines = "off"` so SSE streams stay warm:

```sh
hyp deploy init fly \
  --node-id fly-node \
  --domain hyphae-node.fly.dev \
  --out ./deploy-fly

cd ./deploy-fly
flyctl apps create hyphae-node
flyctl volumes create hyphae_data --size 1 --region iad
# For custom domains, configure DNS + Fly certificate:
# flyctl certs add mesh.example.com --app hyphae-node
flyctl deploy

# Team Hubs: provision ONLY the public Admin-CA JWK as UID 10001 (private key stays on admin laptop):
ADMIN_JWK=$(hyp pair invite --mode team --node-id fly-node --endpoint https://hyphae-node.fly.dev --peer alice@laptop --preset member --json | jq -c '.data.adminJwk')
printf '%s\n' "$ADMIN_JWK" | flyctl ssh console -a hyphae-node \
  -C "su -s /bin/sh hyphae -c 'HYPHAE_SECRET_BACKEND=file hyp secret set hyphae-admin-pubkey --state-dir /var/lib/hyphae'"
flyctl apps restart hyphae-node

hyp deploy check --url https://hyphae-node.fly.dev --config ./node.json
```

*(Until `hyphae-admin-pubkey` is provisioned, a Team Hub boots cleanly with `am2_` pairing disabled.)* Reference file: [deploy/fly.toml.example](../../deploy/fly.toml.example).

### 2.6 Public Read-Only Node (`public-node`)

See the full operator runbook in [Hosting a Public Read-Only Node](../guides/public-node.md).

### 2.7 Self-Hostable Blind Drop Relay (`drop-relay`)

Use Hyphae's official public Blind Drop Relay (`https://spore.hyphae.to` — Cloudflare Worker persisting blind encrypted `hdrop1_` ciphertext plus creator node ID/public key metadata in ephemeral Durable Object storage wiped unconditionally by a hard 15-min alarm `storage.deleteAll()`), deploy a private Cloudflare Workers relay from [`workers/drop-relay/`](../../workers/drop-relay/README.md) (after setting `DROP_CAP_HMAC_KEY` and `ALLOWED_NODE_KEYS`), or stand up a strictly **RAM-only** Rust `drop-relay` host:

```sh
# Hosted public blind relay (zero-knowledge ciphertext, 15-min alarm-wiped DO storage):
hyp relay set https://spore.hyphae.to
hyp relay status --probe

# Or self-host a dedicated 256 MiB strictly RAM-only Rust Drop Relay:
hyp deploy init drop-relay \
  --domain drop.example.com \
  --max-memory-mb 256 \
  --out ./deploy-drop-relay

hyp deploy check --config ./deploy-drop-relay/node.json
# Deploy via Docker Compose, systemd + Caddy, or Fly.io, then verify:
hyp deploy check --url https://drop.example.com --config ./deploy-drop-relay/node.json
hyp relay set https://drop.example.com
hyp relay status --probe
```

### 2.8 Zero-Port SSH-Only Node (`ssh://` + `peer.sock` + `hyp connect`)

For personal servers, bastions, or private VPC machines already reachable over SSH (`~/.ssh/config` + key auth), you can run a Hyphae `router` or `p2p` node with **zero listening TCP ports**:

```sh
# On the remote server (binds only user-only 0600 <state_dir>/peer.sock):
hyp node start --profile p2p --node-id maple-relay --bind none

# From your laptop (one-command mutual P2P pairing over ssh://ops@maple-relay):
hyp pair ssh ops@maple-relay --preset member
```

- `router` and `p2p` nodes automatically bind `<state_dir>/peer.sock` (`0600`) on Unix (opt-in on `local` nodes via `--peer-socket <path>` or `listen.peerSocket: true`).
- Remote peers tunnel HTTP/1.1 + SSE via `ssh -o BatchMode=yes -T -- <target>` invoking `hyp connect`, which bridges stdio directly to `peer.sock` (falling back to loopback `listen.bind` if `peer.sock` is absent).
- Optional query parameters `?stateDir=/path` and `?bin=/path/to/hyp` are strictly validated against shell/option injection.

---

### Public webhook routing

Run the setup on the machine that runs the signed receiver. For example, Sentry uses `http://127.0.0.1:8796/sentry`.

```sh
hyp deploy webhook --local-target http://127.0.0.1:8796/sentry --json
```

- **Tailscale Funnel**. Choose `--provider tailscale`. Hyphae checks node login, HTTPS certificates, Funnel policy, available HTTPS ports, and the running loopback receiver. It enables an unused port or reuses the exact isolated route and prints its public callback URL. If another operator changes Serve configuration during setup, Tailscale rejects the stale update. When the provider only issues a signing secret after it gets a callback URL, use `--plan` first. After the receiver starts, use `--funnel-port <planned-port>` with the activation command to keep the URL stable.
- **Configured Cloudflare Tunnel**. Pass `--provider cloudflare --url https://hooks.example.com/sentry` to check that the callback's ingress rule points to the receiver. Add `--cloudflare-config <file>` if the running tunnel uses a non-default local configuration. Start the operator-managed tunnel if it is offline.
- **Existing HTTPS callback**. Pass `--provider existing --url https://hooks.example.com/callbacks/alerts`. Configure your proxy to forward that URL to the exact loopback target. A path rewrite can map the public path to the local receiver path. Preserve the method, headers, and raw body.

After the receiver starts, send a signed test delivery from the event provider and confirm the resulting event landed in the expected topic.

The SDK's signed Node.js webhook receiver answers `OPTIONS` at its exact path with HTTP `204` and `X-Hyphae-Webhook-Receiver: signed`. A Python or native plugin can implement the same readiness response on a dedicated, loopback-only listener whose `POST` handler verifies signatures before publishing.

## 3. Production Hardening Checklist

Run `hyp deploy check --url https://<your-domain> --config /etc/hyphae/node.json` after every deploy or upgrade:

- [ ] **Loopback bind + TLS proxy + `trustedProxies`:** Bind `127.0.0.1:8790` (or internal Docker bridge) and scope `listen.trustedProxies` to your proxy CIDRs (default `["127.0.0.1/32", "::1/128"]`).
- [ ] **Zero-buffering SSE:** Caddy sets `flush_interval -1` (and `read_timeout 0` / `write_timeout 0`).
- [ ] **Anti-recon `/v1/manifest`:** Unauthenticated `GET /v1/manifest` returns `audience: "public"`, empty `advertised` arrays, and no `escalation` text.
- [ ] **Zero plaintext secrets in `node.json`:** Credentials stored strictly in `SecretStore` (`0600` files when `HYPHAE_SECRET_BACKEND=file`).
- [ ] **No open relay:** `forwarding.mode` is `"deny"` (or explicit `"allowlist"`).
- [ ] **Permissions:** State directories `0700`, secret/token files `0600`, config files non-world-writable (`0640` on systemd VPS; `0644` on host for `:ro` UID `10001` Docker Compose bind mounts).
