# Windows Operations

Hyphae runs natively on Windows (`x86_64-pc-windows-msvc`), including core `hyp`, MCP, hooks, scheduled background service, and external chat bridges.

---

## What Works Natively on Windows

- **Core `hyp` binary & MCP server (`hyp mcp`):** Full local node, `node.sqlite` (WAL), E2EE Direct P2P, Team Hub client, Public Nodes, Local Security Gates, Verified Human Drops, and `hyp exec --env`.
- **Installer & Uninstaller:**
  ```powershell
  # Install (checksum-verified, safe rename-aside swap on upgrades)
  irm https://hyphae.to/install.ps1 | iex

  # Clean uninstall (stops scheduled task, cleans harness configs, optional state/binary removal)
  irm https://hyphae.to/uninstall.ps1 | iex
  ```
- **Background service (`schtasks`):** `hyp service install` registers a Windows Task Scheduler task (`HyphaeDaemon`) so the local daemon runs automatically at login; manage via `hyp service status`, `hyp service restart`, and `hyp service stop`.
- **Private local IPC & Local Ingest:** Uses loopback `127.0.0.1` TCP (`connector.addr` and `ingest.addr`) protected by a constant-time 32-byte CSPRNG bearer token instead of Unix domain sockets. `hyp emit` and Windows Task Scheduler triggers (`schtasks`) work natively.
- **External chat bridges & custom plugins (`plugins/slack`, `plugins/telegram`, `plugins/whatsapp`, `plugins/webhook`, `plugins/prometheus`):** `SubprocessSupervisor` automatically switches to **authenticated loopback-only TCP** (`127.0.0.1:0`) on Windows, passing `HYPHAE_PLUGIN_TRANSPORT=tcp`, `HYPHAE_PLUGIN_ADDR`, and a one-shot 256-bit CSPRNG `HYPHAE_PLUGIN_TOKEN` in the scrubbed child environment. Both `plugins/sdk/client.mjs` and `plugins/sdk/client.py` auto-detect `HYPHAE_PLUGIN_ADDR`, complete the constant-time token handshake, and immediately delete the token from the process environment — so all official bridges run natively on Windows with no WSL required.
- **Secrets backend:** Uses private user-only files under `<state_dir>\secrets\` (`HYPHAE_SECRET_BACKEND=file`).

---

## Platform Notes

- **Secrets storage:** Windows currently uses the private user-only file store (`<state_dir>\secrets\`) rather than an OS keyring backend.
- **Harness config cleanup in `uninstall.ps1`:** Removing JSON/TOML harness entries cleanly uses PowerShell / optional `python3` or `node` where needed; check `uninstall.ps1 -DryRun` first if you have heavily customized harness configs.
- **WSL2:** If your coding agents run inside WSL2 rather than native Windows, install and run Hyphae inside WSL2 directly using `install.sh` (where Unix domain sockets, fd 3, and `systemd --user` are used natively).
