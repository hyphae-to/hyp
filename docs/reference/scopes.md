# Scopes, Presets & Capability Tokens

Hyphae uses OAuth 2.0 (RFC 6749)-style space-delimited ASCII resource- and predicate-confined scopes (`crates/hyp-proto/src/scopes.rs`). Unknown scope tokens fail closed.

---

## 1. Scope Grammar

| Scope Pattern | Meaning & Enforcement Status |
| --- | --- |
| `dm:send` / `dm:send=<t1,t2>` | Send DMs to `*` or specific `<handle>` / `<node>/<handle>` targets. |
| `dm:receive` | Receive DMs from peers (**actively enforced** on transit/hubs). |
| `channel:join=<#c1,#c2\|*>` / `channel:post=<#c1,#c2\|*>` | Join or post to `#channels` (supports read-only observers). |
| `stream:subscribe=<topic>[<constraints>]` | Subscribe to `<topic>` with server-enforced constraints (e.g. `stream:subscribe=github[require=exact.repo;maxValues=10;maxBatchesPerHour=60]`). |
| `stream:publish=<topic>` | Publish CloudEvents into `<topic>`. |
| `files:send[=<maxBytes>]` / `files:receive[=<maxBytes>]` | Send/receive E2EE file transfers capped at `maxBytes` (e.g. `files:send=50mb`). |
| `kv:read=<ns/prefix*>` / `kv:write=<ns/prefix*>` | Read/watch or mutate KV entries matching namespace + prefix glob. |
| `forward:via=<node-pattern>` | Permit transit forwarding through this node (**actively enforced** alongside `forwarding` allowlist rules on transit/hubs). **Never included in `*`; explicit opt-in only.** |
| `drop:create` | Allocate ephemeral Blind Drop Relay slots (`POST /v1/drops`). Excluded from `guest-ro` unless explicitly granted. |
| `bridge:post=<plugin:target>` | **Reserved / Planned** — remote `POST /v1/bridges/post` RPC is not shipped yet. **Never included in `*`; explicit opt-in only.** |

---

## 2. Built-In Scope Presets (`hyp pair guide`)

| Preset | Trust Tier | Expanded Scopes |
| --- | --- | --- |
| `guest-ro` | `guest` | `stream:subscribe=github[require=exact.repo;maxValues=10;maxBatchesPerHour=60]` |
| `guest` | `guest` | `dm:send`, `dm:receive`, `channel:join=#lobby`, `channel:post=#lobby` |
| `observer` | `peer` | `dm:receive`, `channel:join=*`, `stream:subscribe=*`, `kv:read=*` |
| `member` | `org` | `dm:send`, `dm:receive`, `channel:join=*`, `channel:post=*`, `stream:subscribe=*`, `files:send=50mb`, `files:receive=50mb`, `kv:read=shared/*`, `kv:write=shared/*` |
| `full` | `org` | `*` (includes `drop:create`; **explicitly excludes `bridge:post` and `forward:via`**) |

---

## 3. Reserved / Planned Capabilities & Endpoints

The wire grammar reserves the following tokens and RPC paths, which are **not shipped** in the current release:
- **`POST /v1/bridges/post` (`bridge:post` remote RPC):** Chat bridges are local-only today.
- **`POST /v1/node/update` (`node.self-update.v1` / `hyp update --all` fleet push):** Signed local `hyp update` (with plugin auto-sync and managed service restart) is shipped; remote fleet push is planned.
- **`directory.checkpoint.v1` / `keys.prekey.v1`:** Team Hub peer directory keys use pin-on-first-use today; signed anti-rollback directory checkpoints and rotating prekeys are planned.
