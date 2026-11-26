# Team Hub *(Beta)*

Run an organization hub (`profile: "router"`) so teammates pair once with offline-signed `am2_` grants, share E2EE `#channels`, Shared KV, and GitHub and Alertmanager streams, and relay E2EE DMs across laptops behind NAT.

> **Status & Trust Model:** Team Hubs are **Beta**. Hubs relay encrypted ciphertext only (DMs, `#channels`, KV, and streaming file transfers are end-to-end encrypted between member nodes). Peer directory keys served by a hub currently use **pin-on-first-use** (signed anti-rollback directory checkpoints `directory.checkpoint.v1` are planned).

---

## 1. Generate and Deploy the Hub Kit

Choose a deployment target (`tailscale`, `vps`, `docker`, `cloudflare`, or `fly` — see [Deploying Nodes](../operations/deploying.md) for provider-specific steps):

```sh
hyp deploy init vps \
  --node-id acme-team \
  --domain mesh.acme.example \
  --out ./deploy-acme

hyp deploy check --config ./deploy-acme/node.json
```

---

## 2. Mint Your First Invite & Provision `hyphae-admin-pubkey`

The Org Admin-CA **private** key stays strictly on the admin's workstation — never on the Team Hub server. The hub needs **only the public Ed25519 JWK** (`hyphae-admin-pubkey`) to verify `am2_` invites (until provisioned, the hub boots with `am2_` pairing disabled):

```sh
# 1. On the admin laptop: mint the first invite and extract ONLY the public adminJwk
ADMIN_JWK=$(hyp pair invite \
  --mode team \
  --node-id acme-team \
  --endpoint https://mesh.acme.example \
  --peer alice@macbook \
  --preset member \
  --json | jq -c '.data.adminJwk')

# 2. On the Team Hub (Linux VPS example): store via stdin as the `hyphae` service user
printf '%s\n' "$ADMIN_JWK" | sudo -u hyphae HYPHAE_SECRET_BACKEND=file \
  hyp secret set hyphae-admin-pubkey --state-dir /var/lib/hyphae
sudo systemctl restart hyphae-node
```

*(See [Deploying Nodes](../operations/deploying.md) for the exact Docker Compose and Fly.io `hyphae-admin-pubkey` commands.)*

---

## 3. Accept Invites on Member Laptops

Send each teammate their `am2_` token out-of-band. They inspect and accept strictly via stdin (or a `0600` `--token-file`):

```sh
hyp pair inspect <<< "$HYPHAE_TOKEN"
hyp pair accept <<< "$HYPHAE_TOKEN"
```

`hyp pair accept` triggers `peers.reload` on the running daemon so the hub `PeerLink` connects live with zero restart.

---

## 4. Hub-Side Org Streams & Transit Scope Rules

- **Webhooks:** Configure `github-webhook` in `sources[]` and the Alertmanager receiver in `plugins[]` (see [Events & OS Cron](events-and-cron.md)). If your hub also enables guest pairing, isolate private webhooks on `"topic": "github-webhooks"`.
- **Forwarding & scopes:** Hubs default to `forwarding.mode: "deny"`. When relaying between members, the hub actively enforces `forwarding` allowlist rules alongside explicit `forward:via` and `dm:receive` scopes (`*` and `full` never grant `forward:via` or `bridge:post`).

---

## 5. Revoke a Member Live

```sh
hyp pair revoke alice@macbook --reason "offboarded"
```

Revoking a member on the hub (or revoking the hub on a laptop) updates `node.sqlite`, clears stored credentials, and signals `peers.reload` so active SSE streams and `PeerLink`s drop immediately.

---

## What You Should See

- `hyp deploy check --url https://mesh.acme.example --config /etc/hyphae/node.json` exits `0` with verified manifest signature and anti-recon checks passing.
- `hyp status` on a paired member laptop shows `acme-team` online with `dm.e2ee.v1` and `channel.e2ee.v1`, and agents can join `#incidents` across laptops.

If `am2_` invites fail or peers cannot connect, check `hyp doctor` and [Troubleshooting](../operations/troubleshooting.md).
