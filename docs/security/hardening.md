# Local Hardening & Isolation Guide

As explained in the [Threat Model](threat-model.md), Hyphae protects against untrusted network input, not against a shell-capable coding agent running as the **same OS user**. If you run autonomous agents with unrestricted shell execution and want hard local isolation against `~/.config/hyphae`, Keychain secrets, or Security Gate tampering, enforce the boundary at the OS or container level.

---

## 1. Run Untrusted Agents Under a Separate OS User

Isolate the agent's OS UID from your primary user account that owns Hyphae's keys, `node.sqlite`, and OS Keychain:

1. **Dedicated agent user (`agent`):** Run your coding agent inside a separate OS account (or `sudo -u agent` / dedicated macOS user / Linux UID) that has **no read or write permissions** on your human user's `~/.config/hyphae` (`0700`) or Keychain.
2. **Pair as two separate Hyphae nodes (strongest boundary):**
   - Run your human/operator node (`alice@host`, holding your Security Gate policy, Human Authority keys, and sensitive `SecretStore` entries) under your primary OS user.
   - Run the sandboxed agent's node (`agent@sandbox`) under the restricted OS user or container, and pair it over loopback or Tailscale with **least-privilege scopes** (for example `dm:send=alice@host/ops dm:receive` only — zero `drop:create`, zero `kv:write`, zero access to your host secrets).
3. **Never mount `~/.config/hyphae` into an untrusted container.** If a container only needs to talk to your host node, pair it as a scoped peer over HTTPS/Tailscale instead of bind-mounting your host state directory or Unix socket.

---

## 2. Container & VM Sandboxing (Docker / Devcontainers / MicroVMs)

When running coding agents in containers (Docker, Podman, Lima, OrbStack, Firecracker):
- Give the container its own isolated `HYPHAE_STATE_DIR` and `HYPHAE_SECRET_BACKEND=file` (zero host Keychain access).
- Keep the host's `hyp gate apply`, `hyp auth`, and `hyp inbox approve`/`reject` operations strictly on the host outside the container.
- Use `hyp exec --env VAR=<secret> -- <cmd>` only for narrow application secrets intended for that environment — never place Hyphae system keys or host-wide credentials in the container's `SecretStore`.

---

## 3. Server & Network Hardening Defaults

- **Loopback bind + `listen.trustedProxies`:** Bind `127.0.0.1:8790` behind TLS termination (Tailscale Serve, Caddy, Cloudflare Tunnel, or Fly Proxy). Configure `listen.trustedProxies` strictly to the reverse proxy's CIDRs (default `["127.0.0.1/32", "::1/128"]`) so spoofed `X-Forwarded-For` headers from untrusted peers are ignored.
- **No implicit open relay:** Keep `forwarding.mode: "deny"` unless explicitly running a hub with `"allowlist"` rules, `forward:via`, and `dm:receive` scope enforcement.
- **Strict filesystem permissions:**
  - State directories (`~/.config/hyphae`, `/var/lib/hyphae`): `0700`
  - Sockets (`connector.sock`, `ingest.sock`), Windows `*.addr` files, `node.sqlite`, `secrets/*.secret`, `logs/plugin-*.log`: `0600`
  - `node.json` (contains zero plaintext secrets): `0600` on workstations, `0640` (`root:hyphae`) on Linux systemd VPS hosts, `0644` (non-world-writable) on Docker hosts when bind-mounted `:ro` into non-root UID `10001` containers.
- **Signed self-update (`hyp update`):** Verifies Ed25519-signed RFC 8785 JCS release manifests (`"hyphae/v2/release\n"`), anti-rollback version/`publishedAt`, constant-time archive SHA-256, and post-swap `hyp version --json` smoke check with automatic rollback on failure.
- **Live audit:** Run `hyp doctor --json` on workstations and `hyp deploy check --url https://<domain> --config <node.json>` after every server deployment or upgrade.
