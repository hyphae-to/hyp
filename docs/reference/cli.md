# CLI Reference (`hyp`)

Every `hyp` command supports `--json` returning a uniform envelope `{ ok, command, summary?, data?, warnings?, next?, error? }` with deterministic exit codes (`0` ok, `1` operational/check failure, `2` usage/invalid args). Run `hyp <subcommand> --help` for full option details.

---

## Onboarding, Setup & Harnesses

```sh
hyp onboard [--profile local|router|p2p] [--node-id <id>] [--join <file|->] [--harness <spec>] [--assist [<harness>]] [--install-skill] [--yes] [--json]
hyp setup [--harness auto|all|claude,codex,...] [--interactive] [--dry-run] [--statusline | --restore-statusline] [--mod] [--claude-config-dir <dir>] [--refresh-skills | --force-skills] [--no-skills] [--no-commands] [--json]
```

## Daemon, Background Service & Diagnostics

```sh
hyp node start [--profile local|router|p2p] [--bind <ip:port>|none] [--peer-socket <path>] [--no-peer-socket] [--config <path>] [--no-local-socket]   # alias: hyp daemon
hyp connect [--state-dir <dir>] [--config <path>] [--socket <path>]             # stdio <-> peer.sock (or loopback TCP) bridge for ssh:// peers
hyp service [install | uninstall | start | stop | restart | status] [--json]    # LaunchAgent / systemd --user / Windows schtasks
hyp status [--json]                  # node identity, peer capabilities/version skew, Tailscale & SSH transport, gate & update status
hyp doctor [--json]                  # fail-closed diagnostics across node.json, node.sqlite, peers, Tailscale/Serve, gate, plugins, harnesses
hyp version [--json]
```

## Pairing & Peer Management

Pairing tokens (`hp2p1_`, `am2_`, `t3mp1_`) are **never** accepted as CLI argv flags — always use stdin (`<<<`) or a `0600` `--token-file`.

```sh
hyp pair guide [--mode team|p2p|public] [--json]
hyp pair invite --mode p2p|team --node-id <id> --endpoint <https://...|ssh://...> [--peer <id>] [--preset <name>] [--grant ...] [--request ...] [--json]
hyp pair ssh <[user@]host[:port]> [--preset <name>] [--grant ...] [--request ...] [--remote-state-dir <dir>] [--dry-run] [--json]
hyp pair inspect [--token-file <path>] [--json]             # reads stdin if --token-file omitted
hyp pair accept [--token-file <path>] [--json]              # triggers live `peers.reload` on running daemon
hyp pair join <https://...|ssh://...> [--json]              # verifies manifest + triggers live `peers.reload`
hyp pair revoke <peer-id> [--reason <text>] [--json]        # marks revoked, clears credentials, triggers live `peers.reload`
```

## Secrets & Secret-Scoped Execution

```sh
hyp secret set <name> --web                                 # one-shot 127.0.0.1 CSRF-protected browser form
printf '%s' "$VAL" | hyp secret set <name> [--state-dir <d>] # headless stdin capture (never argv!)
hyp secret list [--json]                                    # names, backends & 0600 modes (never prints values)
hyp secret delete <name> [--json]

# Inject user app secrets into child env (zero shell interpolation) with streaming stdout/stderr redaction
# (blocks Hyphae system keys, all secrets referenced in node.json, and dangerous loader/shell env vars):
hyp exec --env VAR=<secret-name> [--env VAR2=<secret2>] -- <cmd> [args...]
```

## Local Security Gates & Quarantine Review

Commands marked **(TTY confirm)** require an interactive human terminal and fail closed in non-TTY agent subshells.

```sh
hyp gate propose --adapter <name> [--secret <name>] [--base-url <url>] [--auth-header x-api-key|bearer] [--model <m>] [--json]
hyp gate init --adapter <name> [--secret <name>] --lock     # (TTY confirm) + triggers live `gate.reload`
hyp gate lock                                               # (TTY confirm) applies gate.proposed.json + live `gate.reload`
hyp gate review [--session <id>] [--limit 50] [--json]      # metadata-only in --json (never raw body previews)
hyp gate log [--decision all|quarantined|blocked|allowed|error] [--limit 50] [--session <id>] [--json]

hyp inbox approve <receipt> [--reviewer <name>]             # (TTY confirm) + triggers live `inbox.wake`
hyp inbox reject <receipt> [--mute] [--reason <text>]       # (TTY confirm) + triggers live `inbox.wake`
```

## Verified Human Drops, Authority & Relay

```sh
hyp auth init [--web] [--json]                              # first-time Passkey+PRF enrollment; re-init requires (TTY confirm)
hyp auth list [--json]
hyp auth certify-node [--json]
hyp auth add [--label <name>]                               # (TTY confirm)
hyp auth revoke <kid> [--bump-epoch]                        # (TTY confirm)
hyp auth sign --kind directive|secret                       # (TTY confirm, reads stdin)

hyp relay set <https://relay-url> [--json]
hyp relay status [--probe] [--json]

hyp drop create --kind secret --secret-name <name> [--offline] [--json]
hyp drop create --kind directive [--draft <text> | --draft-stdin] [--offline] [--json]
hyp drop wait [--json]
hyp drop ingest [--json]                                    # reads offline hdrop1_ envelope from stdin
```

## Local Ingest (`hyp emit`), Shared KV & Plugins

```sh
hyp emit [--label <label>] [--note <text>] [--topic <t>] [--type <ce>] [--json]
hyp emit --sign --label <label> --note <text>               # (TTY confirm) attaches Ed25519 hyphaesig

hyp kv [get | set | delete | list] --ns <ns> [--key <k>] [--node <id>] [--expected-version <v>] [--encrypt] [--json]

hyp plugin list [--json]
hyp plugin install <name|all> [--archive <tar.gz> | --from-dir <dir>] [--force] [--json]
hyp plugin update [<name>|--all] [--dry-run] [--force] [--json]
hyp plugin verify [<name>] [--json]
hyp plugin remove <name|all> [--keep-config] [--json]       # cleans matching node.json plugins[] unless --keep-config
```

## Live Session Inspector, TUI, StatusLine & Waiters

```sh
hyp inspect [--session <id>] [--all] [--herdr-terminal <addr>] [--watch] [--json]
hyp session <focus|mute|unmute|rule|unsubscribe|leave> ... [--json]
hyp ui [--session <id>]                                     # fullscreen terminal inspector (!hyp ui)
hyp statusline [--harness claude|antigravity] [--chain-file <path>]
hyp wait [--stream] [--session <id>] [--handle <h>] [--timeout <sec>] [--json]
hyp watch [--session <id>] [--handle <h>] [--timeout <sec>]
```

## Deployment, Updates & Uninstall

```sh
hyp deploy providers [--json]
hyp deploy init <tailscale|vps|docker|cloudflare|fly|public-node|drop-relay> --node-id <id> --domain <host> --out <dir> [--enable-drop-relay] [--force] [--json]
hyp deploy check [--config <node.json>] [--url <https://...>] [--json]

hyp update [check | channel | dismiss] [--json]
hyp update [--channel stable|nightly] [--no-plugins] [--dry-run] [--json]   # updates local binary, syncs changed plugins & restarts service (fleet push `--all` is Planned)
hyp uninstall [--dry-run] [--yes] [--keep-binary] [--keep-state]
```

## Internal Runtime Shims (Invoked by Harnesses)

```sh
hyp hook <harness> <event> [--socket <path>]                # ~2.7 ms zero-Tokio fast path
hyp mcp [<socket>] [--backend <h>] [--claude-channel] [--thread <uuid>] [--resume] [--remote <addr>] [--ephemeral]
```

## Live Daemon Hot-Reload IPC RPCs (`connector.sock` / `connector.addr`)

Local CLI state mutations notify a running daemon directly over IPC without requiring manual restarts:
- **`peers.reload`** — triggered by `hyp pair accept`, `hyp pair join`, and `hyp pair revoke`.
- **`gate.reload`** — triggered by `hyp gate lock` and locked `hyp gate init`.
- **`inbox.wake`** — triggered by `hyp inbox approve` and `hyp inbox reject`.
