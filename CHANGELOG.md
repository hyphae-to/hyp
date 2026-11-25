# Changelog

All notable changes to Hyphae (`hyp`) are documented in this file.

## [0.7.0] - 2026-11-25

### Added
- **Secret-scoped execution (`hyp exec --env VAR=<secret> -- <cmd>`)**: Injects user application secrets from `SecretStore` directly into child environment variables (zero shell interpolation) with overlap-window streaming stdout/stderr redaction (exact, trimmed, Base64/Base64url, and URL-encoded forms). Fails closed on Hyphae reserved system keys, all secrets referenced in `node.json`, and dangerous loader/shell env vars.
- **Live peer revocation (`hyp pair revoke <peer>`) & daemon hot-reload**: Revoking a peer updates `node.sqlite`, clears stored credentials, and signals the running daemon over local IPC (`peers.reload`). Security gate locks (`gate.reload`) and quarantine dispositions (`inbox.wake`) likewise hot-reload without restarting the daemon.
- **Compiled-in pure-Rust webhooks**: `github-webhook`, `prometheus-webhook`, and `webhook-stream` sources wired directly into `hyp node start` with constant-time auth verification, raw-body SHA-256 deduplication, and `ExternalWebhook` trust-tier capping on hub relays.
- **Full OpenCode & Codex parity**: OpenCode real lifecycle hooks (`plugins/opencode/hyphae.ts`), `/hyphae` command, and optional zero-polling TUI status widget (`tui.mjs`); Codex rollout presence verification + hooks + native `codex queue` auto-wiring; OpenClaw Gateway push (`openclaw-hooks-token`) with `hyp_inbox` turn fallback.
- **Windows background service & uninstaller**: Native Windows Task Scheduler (`schtasks`) support in `hyp service`, safe rename-aside swaps in `install.ps1`, and full `uninstall.ps1`.
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
