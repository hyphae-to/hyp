# Changelog

All notable changes to Hyphae (`hyp`) are documented in this file.

## [0.8.0] - 2026-11-27

### Changed
- **Timestamp parsing**: Invalid non-ASCII seconds fields now fail cleanly instead of panicking. Wire timestamps keep strict uppercase separators; compatibility timestamps retain their existing lowercase and space forms.
- **Abandoned v1 interoperability ([#62](https://github.com/hyphae-to/hyp/issues/62))**: Removed the unused HYP1 transfer, entry-verification, revocation and key-registration compatibility routines. Missing peer manifests now fail normally instead of negotiating an unsigned TypeScript-router fallback. Active `t3mp1_` pairing codes, pairing-key derivation and grant issuance remain supported.
- **Unused store records ([#57](https://github.com/hyphae-to/hyp/issues/57))**: Migration 12 drops the unused publisher token and directory checkpoint tables. The pre-migration backup retains their rows. Existing webhook, peer, and local ingest authorization remains in effect. Earlier binaries cannot open a database upgraded to schema 12.
- **Scheduled wakeups ([#52](https://github.com/hyphae-to/hyp/issues/52))**: Migration 11 drops the retired timer and cron table after backing up the database. Session summaries and panels omit scheduled wakeups. Use the [local ingest route and OS schedulers](docs/guides/events-and-cron.md) for timed events. Earlier binaries cannot open a database upgraded to schema 11.
- **Canonical MCP tools ([#61](https://github.com/hyphae-to/hyp/issues/61))**: Hooks and MCP now register and forward the six documented tool names directly. Retired tool names and unused socket aliases are rejected; existing argument shorthands remain supported. Rerun `hyp setup` for obsolete hook configurations. The retired TypeScript daemon is unsupported.
- **Per-operation Passkey administration (#10, #83, #84)**: `gate init`/`add`, `gate apply`, `gate remove`/`rm`, and `auth add`/`admit`/`revoke` each require a fresh live Passkey Admin approval for the exact signed operation. `gate lock`, `gate unlock`, `--lock`, `--no-wait`, and `--approval-file` have been removed from these administration flows. Existing signed policy evidence still verifies; historical unlocked state never grants mutation permission. Passkey-managed nodes reject offline authority admission, and initialization cannot bypass revoked or unavailable Passkey enrollment history. See [migration and threat boundaries](docs/security/gate.md#4-per-operation-passkey-approval-policy-integrity--live-reload), including the lack of same-user database rollback protection and recovery bypasses.
- **Plugin IPC v2 only ([#55](https://github.com/hyphae-to/hyp/issues/55))**: The supervisor and bundled Node/Python SDKs use host-first JSON-RPC 2.0 on Unix fd 3 and authenticated Windows loopback TCP. Legacy plugin frames and negotiation timers are removed. Custom v1 plugins must migrate; publish calls return durable results or structured numeric errors, with independent RPC IDs for concurrent sends.
- **Metadata-only delivery ([RFC 0004](docs/rfcs/0004-metadata-only-delivery.md), #49)**: Hooks and push wakes no longer carry message or event text for any source or tier. Every delivery is a small `<hyphae-inbox>` XML digest of counts grouped by source, and an agent reads content by calling `hyp_inbox`, which now acknowledges `unread` items by default (`ack: false` peeks). Each returned item states its `trustTier`.
- **Untrusted tiers can wake a thread**: Security Gate Stage 1 now defaults `guest` and `external-webhook` to `cap_to_queue` (never `interrupt`) instead of `downgrade_to_notify`, so mail, calendar and webhook events wake an idle agent at turn end. `downgrade_to_notify` remains available per tier.
- **Long-turn reminder**: during a long active turn, unread `queue` items produce a digest on `PostToolUse` every 30 minutes. Set `delivery.midturnQueueDigestSeconds` in `node.json` to change it (`0` disables).
- **Quarantine in digests**: a digest shows only `<quarantined count="N"/>`; receipt, source and reason stay in `hyp gate review`.
- **Rollback note**: saved per-session delivery policies no longer contain `maxBatchTokens`, `maxInlineItems` or `maxSingleItemShare`. Releases up to 0.7.0 require those fields, so after a downgrade a session whose policy was saved by this version fails to load its delivery policy.

### Added
- **Scoped Shared KV**. Browse peer namespaces and entries in the terminal inspector, Herdr, and Claude Code panels. Agent access to Shared KV is an onboarding choice.
- **SSH peer transport**. Connect and pair over SSH, with Tailscale checks in `hyp doctor`. The `/join` portal supports delegated human-certificate admission.
- **Six event-source plugins (Beta)**: `agentmail`, `sentry`, `gmail`, `google-calendar`, `vercel` and `notion`, installed with `hyp plugin install <name>` and wired as `kind: "source"` so each thread subscribes with its own `hyp_stream` filter. All are outbound-only by default (WebSocket or polling) and run on a laptop or a hub; Sentry, Vercel and Notion also accept signed webhooks (`*_MODE=webhook`). Events carry routing metadata and short previews only, never message or page bodies.
- **Tailscale Funnel for plugin webhooks (`<PREFIX>_WEBHOOK_FUNNEL`)**: Sentry, Vercel and Notion webhook modes can publish their own loopback path through Funnel and log the public URL, with no reverse proxy to configure; their onboarding trees offer it as the recommended route on a tailnet.
- **AgentMail catch-up**: mail received while the WebSocket was down (reconnects, restarts, sleep) is listed over REST on connect and delivered, deduplicated by message ID.
- **Google sign-in helper (`plugins/sdk/google-oauth.mjs auth`)**: One-time PKCE + loopback consent for the user's own Google OAuth client. The refresh token goes from Google straight into the node's secret store; a fixed `--port` (ssh tunnel) or `--stdout` (pipe over ssh, refused on a terminal) covers hubs.
- **Onboarding trees (`hyphae.onboarding/v1`)**: A structured, agent-walkable setup format ([docs/reference/onboarding-tree.md](docs/reference/onboarding-tree.md)). Each event-source plugin ships a pinned `onboarding.json`, `hyp plugin list/install --json` report it as `onboardingPath`, and the `hyphae-setup` skill carries the first-time onboarding flow as a root tree in the same format.
- **`HYPHAE_STATE_DIR` for plugins**: The node now passes its state directory to every `plugins[]` subprocess so polling cursors survive restarts without per-plugin path config (an explicit `plugins[].env` value wins).

### Security & Hardening
- **Private directories**: Reject symlink directories before tightening permissions, leaving their targets unchanged. Node staging directories now use the same owner and permission checks as the keystore.
- **Plugins that crash after connecting now stop**: `plugins/sdk/client.mjs` logs one line (message only) and hard-stops the process on an uncaught error or unhandled rejection. Previously the open channel kept a crashed Node bridge (Telegram, Slack, WhatsApp, webhook, Prometheus or a custom plugin) alive, so the node reported it as running and the restart backoff and `CrashLoopBackOff` breaker never engaged.

### Fixed
- **Verified Human Drop enrollment**. Restored browser Passkey enrollment on the Drop portal. [#208](https://github.com/hyphae-to/hyp/pull/208)
- **Node and harness reliability**. Register shutdown signal handlers before signaling readiness and wait for committed Codex Queue fallbacks in integration tests. [#206](https://github.com/hyphae-to/hyp/pull/206) · [#203](https://github.com/hyphae-to/hyp/pull/203)

### Release verification
- Rehearse updates on a configured, paired installation before publishing. Stable and nightly releases share the archive build workflow. [#211](https://github.com/hyphae-to/hyp/pull/211) · [#214](https://github.com/hyphae-to/hyp/pull/214)

## [0.7.0] - 2026-11-25

### Added
- **Secret-scoped execution (`hyp exec --env VAR=<secret> -- <cmd>`)**: Injects user application secrets from `SecretStore` directly into child environment variables (zero shell interpolation) with overlap-window streaming stdout/stderr redaction (exact, trimmed, Base64/Base64url, and URL-encoded forms). Fails closed on Hyphae reserved system keys, all secrets referenced in `node.json`, and dangerous loader/shell env vars.
- **Live peer revocation (`hyp pair revoke <peer>`) & daemon hot-reload**: Revoking a peer updates `node.sqlite`, clears stored credentials, and signals the running daemon over local IPC (`peers.reload`). Security gate locks (`gate.reload`) and quarantine dispositions (`inbox.wake`) likewise hot-reload without restarting the daemon.
- **Compiled-in pure-Rust webhooks**: `github-webhook`, `prometheus-webhook`, and `webhook-stream` sources wired directly into `hyp node start` with constant-time auth verification, raw-body SHA-256 deduplication, and `ExternalWebhook` trust-tier capping on hub relays.
- **Full OpenCode & Codex parity**: OpenCode real lifecycle hooks (`plugins/opencode/hyphae.ts`), `/hyphae` command, and optional zero-polling TUI status widget (`tui.mjs`); Codex rollout presence verification + hooks + native `codex queue` auto-wiring; OpenClaw Gateway push (`openclaw-hooks-token`) with `hyp_inbox` turn fallback.
- **Full Windows native parity (service, uninstaller & bridges)**: Native Windows Task Scheduler (`schtasks`) support in `hyp service`, safe rename-aside swaps in `install.ps1`, full `uninstall.ps1`, and authenticated loopback-TCP transport (`PluginTransportMode::LoopbackTcp` with per-spawn 256-bit CSPRNG token) in `SubprocessSupervisor` + `client.mjs` + `client.py` so all external chat bridges and custom plugins run natively on Windows without WSL.
- **Reorganized documentation**: Concise README, audience-indexed `docs/` hierarchy (`getting-started`, `concepts`, `guides/`, `harnesses/`, `security/`, `operations/`, `reference/`, `internals/`, `rfcs/`), plus `SECURITY.md` and `CONTRIBUTING.md`.

### Security & Hardening
- **Honest local same-OS-user boundary**: Added interactive TTY confirmation friction on sensitive CLI mutations (`hyp gate lock`, locked `hyp gate init`, `hyp inbox approve`/`reject`, `hyp auth add`/`revoke`/`sign`, `hyp emit --sign`, and re-initializing an initialized node with `hyp auth init --web`) and metadata-only `hyp gate review --json` output. Documented clearly that TTY prompts stop accidental/scripted/MCP misuse rather than sandboxing a same-OS-user shell (hardware Passkey confirmation tracked in `#2` / `#10`).
- **Reverse-proxy CIDR allowlist (`listen.trustedProxies`)**: Replaced boolean reverse-proxy header trust with an explicit CIDR list defaulting to `["127.0.0.1/32", "::1/128"]`.
- **Per-session HMAC `sessionToken`**: Bound local daemon sessions against accidental cross-session `hyp wait` / hook-drain mixups without exposing tokens in `ui/state.json`.
- **Transit & hub scope enforcement**: Enforced `forwarding` allowlists alongside explicit `forward:via` and `dm:receive` scopes on transit/hubs, and closed pairing takeover and key-swap edge cases.
- **Cloudflare Drop Relay durability & quotas**: Persisted blind encrypted `hdrop1_` ciphertext plus creator node ID/public key metadata in ephemeral Durable Object storage with a hard 15-minute alarm `storage.deleteAll()` wipe and durable cross-PoP `RateLimiterDO` quotas.
- **Plugin hardening**: Bridge topics are now local-only by default (`exposeTopic: true` opt-in); `plugins/webhook` and `plugins/prometheus` fail closed without auth (`*_ALLOW_UNSIGNED=1` restricted strictly to loopback binds); `SubprocessSupervisor` adds a `CrashLoopBackOff` circuit breaker and `0600` secret-redacted per-plugin logs (`logs/plugin-<id>.log`); `hyp plugin remove` cleans matching `plugins[]` entries from `node.json` (`--keep-config` to preserve).
- **Stage 2 HTTPS enforcement**: Remote Stage 2 classifier URLs reject non-loopback `http://` fail-closed.

### Changed / Scope Notes
- **Fleet push (`hyp update --all`, `POST /v1/node/update`)**, **remote bridge posting (`POST /v1/bridges/post`)**, and **signed directory checkpoints (`directory.checkpoint.v1`)** remain **Reserved / Planned** and are not shipped in `v0.7.0`. Local signed `hyp update` updates the local binary, auto-syncs changed plugins, and auto-restarts the managed background service.
- **Container & Fly deploy kits**: Fixed non-root UID `10001` volume ownership on Fly mounts, `0644` bind-mount permissions for non-secret Docker Compose `node.json`, and `hyphae-admin-pubkey` provisioning steps for Team Hubs.

---

## [0.6.1] - 2026-11-23

### Added
- **Unified non-Rust plugin & harness mod manager (`hyp plugin`)**: Compile-time SHA-256 + `treeSha256` pinning, three-way selective updates (`up_to_date` / `outdated` / `modified` / `corrupt`), local verified tarball cache, and automatic post-upgrade sync in `hyp update`.
- **Bridge emoji reactions**: First-class `reaction` support in `hyp_send` for Telegram, Slack, and WhatsApp bridges.
- **Claude Code native panel & `CLAUDE_CONFIG_DIR` support**: Bracketless native Claude Code status indicator and `/hyphae-panel` side panel, symlink-safe atomic writes across custom `CLAUDE_CONFIG_DIR` profiles, and Herdr custom-header diagnostics.
- **Mobile-first Drop Portal UX**: Progressive stepper flow on `site/drop/` with automatic enrollment handoff back to `hyp auth init --web`.
- **Auto-claim primary on `hyp_bridge`**: `hyp_bridge({ action: "link" })` automatically claims primary ownership for unowned targets unless `readOnly: true` is passed.
