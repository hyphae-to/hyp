# Pair Two Laptops (Direct P2P)

Connect agents across two laptops or workstations directly peer-to-peer — **zero central hub, zero CA, zero TOFU window**. DMs, channels, KV, and file transfers are end-to-end encrypted with RFC 9180 HPKE and Ed25519.

Only **one** machine needs a reachable HTTPS endpoint (such as Tailscale Serve). The other machine can sit behind strict NAT and connects outbound over a single bidirectional HTTPS+SSE link.

---

## 1. Expose Machine A Behind HTTPS (Tailscale Serve Example)

On Machine A (`alice@macbook`), generate a hardened P2P config or expose loopback `127.0.0.1:8790` privately inside your tailnet:

```sh
hyp deploy init tailscale \
  --node-id alice@macbook \
  --domain alice.your-tailnet.ts.net \
  --out ./deploy-tailscale

bash ./deploy-tailscale/tailscale-serve.sh
hyp deploy check --url https://alice.your-tailnet.ts.net --config ./deploy-tailscale/node.json
```

*(See [Deploying Nodes](../operations/deploying.md) for Cloudflare Tunnel, Caddy VPS, and other HTTPS frontends.)*

---

## 2. Mint a One-Shot P2P Invite on Machine A

```sh
hyp pair invite \
  --mode p2p \
  --node-id alice@macbook \
  --endpoint https://alice.your-tailnet.ts.net \
  --grant dm:send dm:receive files:send=25mb \
  --request dm:send dm:receive
```

Send the printed `hp2p1_` token to Machine B out-of-band (Signal, Slack DM, SSH, or QR). It embeds Alice's Ed25519 + X25519 public JWKs and a single-use 160-bit pairing secret, eliminating any TOFU MITM window.

---

## 3. Inspect and Accept on Machine B (Stdin Only!)

Never pass pairing tokens as CLI arguments (where they appear in `ps` and shell history). Pipe via stdin or read from a `0600` file:

```sh
# Inspect JWK thumbprint, scopes, and expiry first
hyp pair inspect <<< "$HYPHAE_TOKEN"

# Accept and automatically trigger live `peers.reload` on the running daemon
hyp pair accept <<< "$HYPHAE_TOKEN"
```

*(You can also pass `--token-file /path/to/0600-invite.tok` instead of stdin.)*

---

## 4. Message Across Machines

Once paired, agents address remote peers with `<node-id>/<handle>`:

- On Alice's laptop: *"Join Hyphae as `alice` and message `bob@laptop/codex` with the failing test output."*
- On Bob's laptop: *"Join Hyphae as `codex`."*

---

## 5. Revoke a Peer Live

To immediately cut off a paired laptop (for example, if a machine is lost or a collaboration ends):

```sh
hyp pair revoke bob@laptop --reason "project finished"
```

This marks the peer revoked in `node.sqlite`, clears stored credentials, and signals `peers.reload` so active `PeerLink`s and SSE streams close immediately without restarting the daemon.

---

## What You Should See

- `hyp status` on both machines shows the peer online with `dm.e2ee.v1` verified and zero version-skew errors.
- A message sent to `bob@laptop/codex` arrives encrypted end-to-end as `[hyphae · alice@macbook/alice]`.

If the peer shows offline or fails key verification, run `hyp doctor` and see [Troubleshooting](../operations/troubleshooting.md).
