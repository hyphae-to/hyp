# Publish Herdr builder status to Shared KV

This optional publisher follows Herdr Core's event stream and records a small status for one explicitly selected local terminal. It requires Node.js 24, Herdr Core `hc` 0.1.22 or later, and a `hyp` build that supports `kv set --clear-ttl`. Keep the publisher and reader clocks synchronized when using leases across hosts. Run it alongside the local node. Loading the Herdr UI mods does not start the publisher.

## Start

Choose a public-safe builder key and obtain the terminal's creation timestamp. For instance, for terminal `t7` and a node with state at `/path/to/hyp-state`:

```sh
hc get --json t7 | jq '{address, created_ms}'
node plugins/herdr-status/publish.mjs builder-a t7 1795860000000 /path/to/hyp-state
```

From an official plugin archive that includes this plugin, `hyp plugin install herdr-status` puts the script under `<state-dir>/plugins/herdr-status/`. Run a second publisher with a different key and pin for a second builder. Choose a new key for a new terminal session. The publisher checks both the terminal address and creation timestamp. A publisher for a recycled terminal cannot take over the old key.

## Read and subscribe

Read `herdr-status/builder-a` using `hyp kv get --ns herdr-status --key builder-a --json`. The value contains the schema, a session fingerprint, and the state. Native states include `idle`, `working`, `done`, `blocked`, and `error`. `blocked` can include `kind` with the native value `permission`, `question`, or `auth`. It signals that the builder may need input. `unknown` covers a live terminal with no recognized status or a lost process. `finished` records an observed terminal exit.

Check `herdr-status-lease/builder-a` when reading a current status. Treat the status as stale unless the lease has the same session fingerprint, its `statusVersion` matches the status entry’s KV `version`, and `validUntil` is later than the current epoch time in milliseconds. A recorded `finished` remains historical evidence of exit. A clean publisher stop clears the lease. A crash or lost connection makes the lease stale within 75 seconds of its last renewal. A service supervisor can restart the foreground publisher. After an abrupt exit, wait for the previous lease to become stale before restarting it.

For notifications, subscribe to the built-in `local.kv` stream with both fields in the exact filter:

```json
{"action":"subscribe","topic":"local.kv","filters":[{"exact":{"ns":"herdr-status","key":"builder-a"}}],"mode":"queue"}
```

Only changes to the status or blocker kind update that status key. The Herdr heartbeat renews the separate lease key, which the exact filter excludes. After a restart the initial snapshot is compared to the stored status before writing.

## Access

The publisher writes as the local node, with an owner-mode entry and a version check. Keep it on a trusted node and use public-safe key names. The payload excludes terminal text, prompts, commands, working directories, process IDs, labels, and freeform status fields.

A remote reader that only needs these two records can be granted `kv:read=herdr-status/builder-a` and `kv:read=herdr-status-lease/builder-a`; it needs no write scope. Remote subscriptions to `<peer>.kv` use separate stream permissions. A broad KV stream grant exposes KV event values even when direct KV reads are scoped. Exact filters select notifications and do not restrict a grantee's authorization. Keep remote stream access limited to peers trusted to read the KV event stream.
