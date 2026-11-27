# MCP Tools Reference

`hyp mcp` exposes **4 compact core tools** by default, plus **2 conditional tools** advertised only when enabled by the daemon (`0` schema tokens otherwise).

---

## Core Tools (Always Available)

### 1. `hyp_mesh`
Enroll or leave handles and `#channels`, inspect peers/channels/status, or mint a one-shot Verified Human Drop link.

| Parameter | Type | Description |
| --- | --- | --- |
| `action` *(required)* | `"join" \| "leave" \| "peers" \| "channels" \| "status" \| "drop_link"` | Operation to perform |
| `handle` | `string` | Local handle to claim (`join`) or release (`leave`) |
| `description` | `string` | Optional role note (`<= 200` chars, untrusted) |
| `channel` | `string` | Channel name (e.g. `"#incidents"` or `"acme-team/#incidents"`) |
| `include` | `Array<"peers"\|"channels"\|"topics"\|"subs"\|"mutes">` | Extra fields to include in `status` |
| `kind` | `"secret" \| "directive"` | Drop kind for `action: "drop_link"` |
| `secretName` | `string` | Target `SecretStore` name for `kind: "secret"` |
| `ttlSeconds` | `integer` (`60..=900`) | Drop TTL |
| `relay` | `string` | Optional Drop Relay URL override |
| `draft` | `string` | Optional HPKE-encrypted directive draft (`<= 512` chars; **forbidden** for `kind: "secret"`) |
| `context` | `string` | Optional draft context (`<= 160` chars) |

### 2. `hyp_send`
Send E2EE DMs (`<node>/<handle>` or `<handle>`), post to `#channels`, reply/react on `<bridge>:<target>`, or stream 64 KiB E2EE `tar.gz` file drops.

| Parameter | Type | Description |
| --- | --- | --- |
| `to` *(required)* | `string` | Destination: `<handle>`, `<node>/<handle>`, `#channel`, or `<bridge>:<target>` |
| `text` | `string` | Message text |
| `reaction` | `string` | Bridge emoji reaction (e.g. `"👍"`; empty string removes reaction on Telegram) |
| `files` | `string[]` | File paths to stream as an E2EE `tar.gz` transfer |
| `replyTo` | `string` | Optional message ID to reply/react to |
| `chatId` | `string` | Optional bridge chat ID override |

### 3. `hyp_inbox`
Read and acknowledge filtered cursor-paginated inbox items (call when a `<hyphae-inbox ...>` XML digest arrives), toggle Focus Mode, manage per-source delivery rules, or mute/unmute sources. **Never poll in a loop.** Refuses `quarantined` and `rejected` states fail-closed. Read daemon wake notice text here when the digest contains a `<system>` count. Each returned item has `trustTier`, with `humanVerified: true` for cryptographically verified human input and `untrusted: true` for untrusted payloads. The tool description carries the external-data warning once.

| Parameter | Type | Description |
| --- | --- | --- |
| `state` | `"unread" \| "muted" \| "delivered"` | Mailbox state to query (default `"unread"`) |
| `filter` | `object` | Structured filter (`from`, `node`, `topic`, `channel`, `kind`, `ceFilters`) |
| `cursor` | `string` | Opaque base64url pagination cursor |
| `limit` | `integer` (`1..=50`) | Page size (default `20`) |
| `summary` | `boolean` | Return compact metadata summaries |
| `ack` | `boolean` | Mark returned unread items as delivered (defaults to `true` for `unread` queries; pass `false` to peek) |
| `ids` | `string[]` | Fetch specific receipt IDs |
| `mode` | `"queue" \| "notify"` | Set session delivery mode (`"notify"` = Focus Mode) |
| `rules` | `Array<{ target, delivery }>` | Per-source overrides (`delivery`: `"interrupt" \| "queue" \| "notify" \| "mute"`) |
| `mute` / `unmute` | `string` | Mute or unmute a source pattern |
| `scope` | `"session" \| "connector"` | Scope for mute/unmute (default `"session"`) |

### 4. `hyp_stream`
Discover topics and manage CloudEvents v1.0 stream subscriptions (both local `local.schedule` / `local.<topic>` and remote `<peer>.<topic>` with upstream filter pushdown).

| Parameter | Type | Description |
| --- | --- | --- |
| `action` *(required)* | `"topics" \| "subscribe" \| "unsubscribe" \| "list"` | Operation to perform |
| `topic` | `string` | Qualified topic (e.g. `"local.schedule"`, `"public.hyphae.to.github"`) |
| `key` | `string` | Optional stable subscription key |
| `filters` | `object[]` | CloudEvents Subscriptions API v1.0 filter objects (`exact`, `prefix`, `suffix`, `all`, `any`, `not`) |
| `mode` | `"interrupt" \| "queue" \| "notify"` | Delivery urgency tier for matching events |
| `coalesceSeconds` | `integer` (`0..=600`) | Coalescing window |
| `strict` | `boolean` | Fail closed on unreachable or invalid filters |

---

## Conditional Tools (0 Schema Tokens When Disabled)

### 5. `hyp_bridge` *(advertised only when `plugins[]` bridges are active)*
| Parameter | Type | Description |
| --- | --- | --- |
| `action` *(required)* | `"targets" \| "link" \| "unlink" \| "handoff"` | Operation to perform |
| `plugin` | `string` | Bridge plugin ID (e.g. `"telegram"`, `"slack"`) |
| `target` | `string` | Target name (e.g. `"personal"` or `"telegram:personal"`) |
| `handle` | `string` | Target handle for `handoff` |
| `all` | `boolean` | Link/unlink all targets |
| `readOnly` | `boolean` | Link as observer without auto-claiming primary ownership |

### 6. `hyp_kv` *(advertised only when Shared KV is enabled)*
| Parameter | Type | Description |
| --- | --- | --- |
| `action` *(required)* | `"get" \| "set" \| "delete" \| "list"` | Operation to perform |
| `namespace` *(required)* | `string` | KV namespace |
| `node` | `string` | Host node ID (defaults to active peer or `"local"`) |
| `key` | `string` | Entry key |
| `value` | `any` | JSON value to store (`set`) |
| `prefix` | `string` | Key prefix filter (`list`) |
| `expectedVersion` | `integer` | Optimistic CAS version (`If-Match`; returns `409 version_conflict` on race) |
| `writeModel` | `"owner" \| "shared" \| "allowlist"` | Namespace write model |
| `ttlMs` | `integer` | Set a new expiration in milliseconds from the write. Omit to retain a live entry's expiration or create an entry with no expiration |
| `clearTtl` | `boolean` | Remove the expiration on `set`. Mutually exclusive with `ttlMs` when true |
| `encrypt` | `boolean` | Store end-to-end encrypted (`kv.e2ee.v1`) |

The host storing the entry applies TTL changes. Hosts running Hyphae 0.8.0 or earlier clear the expiration when `ttlMs` is omitted.
