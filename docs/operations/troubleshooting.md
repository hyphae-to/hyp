# Troubleshooting & `hyp doctor`

Always start with:

```sh
hyp doctor
hyp status
hyp service status
```

Use `--json` on any command for structured diagnostics and suggested `next` commands.

---

## Common Failures & Fixes

### 1. First two-agent message never arrives
- **Desktop app not restarted:** If Claude Desktop, Codex Desktop, or Cursor was open during `hyp onboard` or `hyp setup`, restart it once so it loads the new MCP server and hooks.
- **Session never joined:** Confirm both sessions enrolled via `hyp inspect --all`.
- **Focus Mode or Mute active:** Check `hyp inspect --all` for `focus` or active mutes; clear with `hyp session focus off` or `hyp session unmute <target>`.
- **Daemon offline:** Run `hyp service status`. If stopped, start it via `hyp service install` or `hyp service restart`.

### 2. `AlreadyRunning` when running `hyp node start`
`hyp onboard` already installs and starts the persistent background service (`LaunchAgent` / `systemd --user` / Windows `schtasks`). Do **not** run `hyp node start` manually alongside it — use `hyp service status` and `hyp service restart`.

### 3. `INTERACTIVE_TTY_REQUIRED` on `hyp gate lock`, `hyp inbox approve`, `hyp auth revoke`, or `hyp emit --sign`
Security-sensitive mutations enforce interactive TTY confirmation and **fail closed inside non-TTY agent subshells** (such as a coding agent's bash tool). Run the printed command directly in your own interactive terminal.

### 4. `caller_unverifiable` / `caller_not_found` from MCP tools
- A harness's `PreToolUse` / `BeforeTool` hook did not run before `tools/call` (re-run `hyp setup --harness <name>` and restart the harness).
- Inside **Herdr**, bare shell terminals (`status: null`) are rejected fail-closed; run your coding agent inside the Herdr pane so `hc get --json` reports a live `status.app`.
- Inside **Codex**, verify `$CODEX_HOME/sessions/` contains the active thread rollout JSONL file and `~/.codex/hooks.json` is wired (`hyp setup --harness codex`).

### 5. `gate_policy_sig` verification failed in `hyp doctor`
A locked `gate` block in `node.json` (or `human_authorities` in `node.sqlite`) was modified without re-signing. Inspect the diff, then re-lock from an interactive terminal with `hyp gate lock`.

### 6. Messages held in Quarantine (`⚠ N held`)
Untrusted inbound messages held by Stage 1/Stage 2 gates never appear in `hyp_inbox`. Inspect metadata and decide in a terminal:

```sh
hyp gate review               # metadata only in --json
hyp gate log --decision quarantined
hyp inbox approve <receipt>   # TTY confirm + live inbox.wake
hyp inbox reject <receipt> --mute
```

### 7. Chat bridge `crash_loop_backoff` or missing messages
- Inspect `<state_dir>/logs/plugin-<id>.log` (`0600`, secret-redacted) and `hyp doctor --json`.
- Verify `Node 24+` is installed at the `"command"` path configured in `node.json` `plugins[]`.
- Verify sender allowlists (`TELEGRAM_ALLOWED_USERS`, `SLACK_ALLOWED_USERS`, `WHATSAPP_ALLOWED_NUMBERS`) are non-empty — all included bridges drop unauthorized senders fail-closed.
- For `plugins/webhook` and `plugins/prometheus`, verify auth secrets are configured (or `*_ALLOW_UNSIGNED=1` on **loopback only**).

### 8. Peer offline, Tailscale stopped/misconfigured, `capability_downgrade_detected`, or `am2_` pairing rejected
- **Tailscale offline or missing Serve route:** `hyp doctor` and `hyp status` probe `tailscale status --json` and `tailscale serve status --json` (non-blocking, 1.5s budget). If `*.ts.net` peers or `deploymentProvider: "tailscale"` are configured while Tailscale is stopped/logged out, run `tailscale up` (or reconnect the Tailscale app). If `tailscale.serve` warns of a missing HTTPS route, run the printed `tailscale serve --bg --https=<port> http://<bind>` command.
- **SSH peer (`ssh://`) connection failed:** Verify non-interactive SSH works (`ssh -o BatchMode=yes <target> true`), confirm `hyp` is on remote `PATH` or `~/.local/bin/hyp` (or pass `?bin=/path/to/hyp`), and confirm the remote daemon has `<state_dir>/peer.sock` (`0600`) or loopback `listen.bind` active (`hyp connect` bridges stdio cleanly with zero banner output on stdout).
- **`am2_` disabled on Team Hub:** Provision the public Admin-CA JWK (`hyphae-admin-pubkey`) on the hub and restart it (see [Team Hub Guide](../guides/team-hub.md)).
- **Key mismatch / downgrade:** A previously pinned peer changed keys or dropped `dm.e2ee.v1`. Verify out-of-band before revoking (`hyp pair revoke <peer>`) and re-pairing.
- **Behind a reverse proxy:** Confirm Caddy sets `flush_interval -1` and `listen.trustedProxies` includes the proxy's CIDR (default `["127.0.0.1/32", "::1/128"]`).
- **Verify live server:** Run `hyp deploy check --url https://<domain> --config <node.json>`.

### 9. `plugin:modified` or `plugin:corrupt` in `hyp doctor`
- Locally edited plugin (`modified`): `hyp plugin update <name> --force` to reset to the compile-time pinned SHA-256, or keep your edit knowingly.
- Corrupted/missing plugin (`corrupt`): repair with `hyp plugin install <name> --force`.
