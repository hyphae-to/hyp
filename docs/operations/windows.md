# Windows Operations

Hyphae runs natively on Windows (`x86_64-pc-windows-msvc`) with a few explicit platform differences compared to macOS and Linux.

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
- **Secrets backend:** Uses private user-only files under `<state_dir>\secrets\` (`HYPHAE_SECRET_BACKEND=file`).

---

## What Does Not Work Natively on Windows

- **Optional external chat bridges (`plugins/slack`, `plugins/telegram`, `plugins/whatsapp`, `plugins/webhook`, `plugins/prometheus`):** External bridge subprocesses communicate over duplex **Unix fd 3** socketpairs (`SubprocessSupervisor`), which are currently supported only on **macOS, Linux, and WSL2**.
- **Workaround:** If you need external chat bridges on a Windows machine, run Hyphae inside **WSL2** (where Unix domain sockets, fd-3 bridges, and `systemd --user` work natively).
- **Harness config cleanup in `uninstall.ps1`:** Removing JSON/TOML harness entries cleanly uses PowerShell / optional `python3` or `node` where needed; check `uninstall.ps1 -DryRun` first if you have heavily customized harness configs.
