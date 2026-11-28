# `node.json` Configuration Reference

Default workstation path: `~/.config/hyphae/node.json` (`0600`). Server path: `/etc/hyphae/node.json` (`0640` `root:hyphae` on systemd VPS; `0644` host bind-mount `:ro` for non-root UID `10001` Docker Compose containers). Override via `--config <path>` or `HYPHAE_CONFIG`.

**Secret rule:** Core secret fields (`sources[]`, `pairing`, `gate`, `t3`, `openclaw`) **require** `{ "secret": "<name>" }` references backed by `SecretStore` and reject raw plaintext strings fail-closed. For `plugins[].env`, `{ "secret": "<name>" }` is strongly recommended; plaintext secret-like values emit a startup warning.

---

## Top-Level Structure

```json
{
  "v": 2,
  "nodeId": "alice@macbook",
  "profile": "local",
  "stateDir": "/Users/alice/.config/hyphae",
  "listen": {
    "bind": "127.0.0.1:8790",
    "trustedProxies": ["127.0.0.1/32", "::1/128"]
  },
  "forwarding": {
    "mode": "deny",
    "rules": []
  },
  "pairing": {
    "adminKey": { "secret": "hyphae-admin-pubkey" }
  },
  "sources": [],
  "localIngest": {},
  "plugins": [],
  "kv": false,
  "gate": {},
  "dropRelay": {},
  "t3": {},
  "openclaw": {}
}
```

---

## Section Details

### Core Identity & Listener (`listen`)
- `v`: Schema version (`2`).
- `nodeId`: Canonical node ID matching `/^[a-z0-9][a-z0-9@._-]{0,63}$/` (`local` is reserved).
- `profile`: `"local"` (default workstation, no HTTP listener unless `listen.bind` is set), `"p2p"` (workstation + peer listener), or `"router"` (Team Hub or Public Node).
- `stateDir`: Optional path holding `node.sqlite`, sockets (`connector.sock`, `ingest.sock`), `secrets/`, `ui/state.json`, and `logs/`.
- `listen.bind`: Bind address (e.g. `"127.0.0.1:8790"` behind TLS termination, or `"0.0.0.0:8790"` inside an isolated Docker bridge / Fly container).
- `listen.trustedProxies`: CIDR allowlist of reverse proxies whose `X-Forwarded-For` / `Forwarded` client IP headers are honored. Defaults to **`["127.0.0.1/32", "::1/128"]`**.

### Forwarding (`forwarding`)
- `mode`: `"deny"` (default, fail-closed) or `"allowlist"`. No node is ever an implicit open relay.
- `rules`: Explicit transit allowlist rules enforced together with `forward:via` and `dm:receive` scopes.

### Pairing (`pairing`)
- `adminKey`: `{ "secret": "hyphae-admin-pubkey" }` (or inline public Ed25519 OKP JWK object `{ "kty": "OKP", "crv": "Ed25519", "x": "..." }` — never a private `"d"` field) on Team Hubs to verify offline-signed `am2_` invites.
- `guestPairing`: Enables self-service `guest-ro` pairing on read-only public nodes.

### Compiled-In Event Sources (`sources[]`)
- **`kind: "github-public"`**: `topic` (`"github"`), `allowPrivateWithToken` (bool), `minPollIntervalSeconds` (`60`), `graceWindowSeconds` (`300`), `maxActivePollers` (`100`), `repoTokens` (`{ "owner/*": { "secret": "..." }, "owner/repo": { "secret": "..." } }`).
- **`kind: "github-webhook"`**: `topic` (recommend `"github-webhooks"` on hubs with guest pairing), `secret: { "secret": "..." }`, optional `allowedRepos`, `allowedOrgs`, `maxBodyBytes`. See [repository webhook setup](../plugins.md#repository-webhook-setup).

Both native source kinds accept `exposeTopic: false` to keep their topic local. Same-node sessions can still discover, subscribe to, and receive the topic. Paired peers and relays cannot discover or subscribe to it, even with a wildcard stream grant. An enabled native source's local-only setting takes precedence over declarations of the same topic in `topics[]` or another source or plugin. Omit the setting or use `true` to retain the existing scope-based remote access. Other values cause a startup config error.

Restart the node to apply changes to `sources[]`. Startup removes existing remote subscriptions and their queued batches on newly local-only topics. Local subscriptions stay active.

Configure generic HTTP and Alertmanager receivers in `plugins[]`. See [webhook plugin migration](../plugins.md#webhook-plugin-migration) for the former native source settings.

### Local Ingest (`localIngest`)
Enabled by default even when omitted (`defaultTopic: "schedule"`, accepting `to.hyphae.scheduled.v1` and `to.hyphae.local.v1` on `["schedule", "local"]`). Each route in `localIngest.routes[]` supports:
- `id`, `allowedTypes`, `allowedTopics`, `filters` (CloudEvents Filter AST), `maxPerMinute`, `burst`, `onLimit` (`"drop"` | `"coalesce"`), `maxPayloadBytes`, `gate` (bool), `requireSignature` (bool — rejects unsigned events fail-closed).

### External Subprocess Bridges (`plugins[]`)
- `id`: Unique plugin identifier (also determines `<state_dir>/logs/plugin-<id>.log`).
- `command` *(alias `exec`)* and `args`: Absolute binary and verified script path returned by `hyp plugin install <name> --json`.
- `targets`: List of target identifiers (e.g. `["my_assistant_bot"]`; for `id: "telegram"`, omitting `targets` auto-resolves the bot's Telegram username via `getMe` with `"personal"` as fallback).
- `kind`: `"bridge"` (thread-linked chat bridge) or `"source"` (1-to-many `hyp_stream` topic named after each target). Omitted, it defaults to `source` for `prometheus`, `agentmail`, `sentry`, `gmail`, `google-calendar`, `vercel`, `notion` and for `webhook` without `WEBHOOK_POST_URL`; otherwise `bridge`.
- `exposeTopic`: Boolean (default **`false`**). Bridge and source topics stay local-only unless explicitly exposed. Remote access to an exposed topic still requires a matching `stream:subscribe` scope.
- The node adds `HYPHAE_STATE_DIR` (its state directory) to every plugin's environment unless `env` sets it.
- `env`: Map of string values or `{ "secret": "<name>" }` references.

### Shared Key-Value Tool (`kv`)

`"kv": true` exposes `hyp_kv` in local MCP tool discovery and generated harness skills. `"kv": false` hides it even when KV namespaces are configured or advertised by peers. The setting affects tool discovery and leaves the KV CLI, stored data, peer access rules, and namespace policies intact. The equivalent object form is `"kv": { "enabled": true }`.

Interactive onboarding asks whether to enable the tool. For noninteractive setup, use `hyp onboard --yes --kv` or `hyp onboard --yes --no-kv`. New configurations default to `false`. Rerunning without a choice preserves the current setting. Existing configurations without an explicit choice retain automatic MCP discovery from local namespaces and peer manifests.

After editing `node.json`, restart the daemon and reconnect the MCP client. Run `hyp setup --refresh-skills` to update generated harness skills.

### Security Gate (`gate`)
Managed via `hyp gate propose` + `hyp gate apply` (writes `gate_policy_sig` over canonical JCS of `gate` + `human_authorities_digest`). Remote Stage 2 classifier URLs reject non-loopback `http://` fail-closed.

### Optional Blocks (`dropRelay`, `t3`, `openclaw`, `revival`)
- `dropRelay`: `{ "enabled": true, "maxMemoryMb": 256 }` for the in-node strictly RAM-only Blind Drop Relay.
- `t3`: `{ "url": "http://127.0.0.1:3773", "tokenSecret": "t3-session-token" }` (HTTPS or loopback HTTP only).
- `openclaw`: `{ "url": "http://127.0.0.1:18789", "hooksPath": "/hooks", "agentId": "main", "tokenSecret": "openclaw-hooks-token" }`.
- `revival`: Strictly opt-in Tier 4 cold-session revival (`codexResume`, allowlisted `herdrSpawnAllowlist`).
