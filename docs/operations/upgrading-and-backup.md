# Upgrading, Backups & Uninstalling

## 1. Signed Local Self-Update (`hyp update`)

`hyp update` checks Ed25519-signed RFC 8785 JCS release manifests (`"hyphae/v2/release\n"`), enforces version & `publishedAt` anti-rollback, verifies constant-time archive SHA-256 before extraction, runs a `hyp version --json` smoke check (rolling back automatically via `hyp.prev` / `hyp.old.exe` on failure), auto-syncs changed official plugins (`hyp plugin update --all`), and restarts the managed background service:

```sh
# Check for updates without modifying anything
hyp update check --json

# Preview update plan
hyp update --dry-run

# Upgrade local binary, sync changed official plugins, and restart managed service
hyp update

# Switch channel or skip plugin sync
hyp update --channel nightly
hyp update --no-plugins
```

*(Note: remote fleet push via `hyp update --all` / `POST /v1/node/update` is **Planned** and not shipped yet — run `hyp update` on each host or rebuild your container image.)*

After upgrading, refresh managed harness skills cleanly:

```sh
hyp setup --refresh-skills
hyp doctor
```

---

## 2. Selective Official Plugin Updates (`hyp plugin`)

```sh
hyp plugin list --json                # shows up_to_date / outdated / modified / corrupt / not_installed
hyp plugin update --all --dry-run
hyp plugin update --all               # skips up_to_date (0 downloads), protects locally modified files
hyp plugin verify --json              # exits 1 on any tamper or drift
```

---

## 3. Backing Up a Node

A Hyphae node's entire durable state lives in two places:

1. **Config & SQLite state (`~/.config/hyphae/` on workstations, `/etc/hyphae/node.json` + `/var/lib/hyphae/` on servers):**
   - `node.json` (contains zero plaintext secrets)
   - `node.sqlite` (use SQLite online backup while running, or stop `hyp service stop` first so WAL checkpoints cleanly):
     ```sh
     sqlite3 ~/.config/hyphae/node.sqlite ".backup '/path/to/backup/node.sqlite'"
     ```
2. **Cryptographic identity keys & secrets (`SecretStore`):**
   - On headless servers (`HYPHAE_SECRET_BACKEND=file`), back up `<state_dir>/secrets/` (`0700`/`0600`) encrypted at rest — it holds `node-sign-*`, `node-enc-*`, `hyphae-admin-pubkey`, and source tokens.
   - On macOS/Linux desktop machines, keys reside in macOS Keychain (service `hyphae`) or Linux Secret Service (`secret-tool`).

---

## 4. Clean Uninstall

`hyp uninstall` stops the managed service, restores any chained `statusLine`, cleans Hyphae MCP/hook entries across harnesses, and optionally removes state and the binary:

```sh
# Preview everything that would be touched
hyp uninstall --dry-run

# Uninstall (interactive confirmation, or --yes)
hyp uninstall --keep-state            # preserve node.sqlite & secrets for reinstall
hyp uninstall                         # full removal
```

Standalone uninstallers (if `hyp` is already removed or broken):

```sh
# macOS & Linux
curl -fsSL https://hyphae.to/uninstall.sh | sh
```

```powershell
# Windows (PowerShell)
irm https://hyphae.to/uninstall.ps1 | iex
```
