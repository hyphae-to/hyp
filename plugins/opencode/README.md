# Hyphae Plugin & Optional TUI Widget for OpenCode

Real lifecycle hooks, `/hyphae` slash command, and an optional zero-polling, metadata-only TUI status widget for [OpenCode](https://opencode.ai).

## Automatic Setup (Lifecycle Hooks + `/hyphae` Command)

Run the static `hyp` binary configurator:

```sh
hyp setup --harness opencode
```

This configures OpenCode idempotently while preserving all existing settings:

- **`~/.config/opencode/opencode.json`** — registers the local `hyphae` MCP server (`hyp mcp --backend opencode`, with verified per-session identity — no `--ephemeral`!).
- **`~/.config/opencode/plugins/hyphae.ts`** — installs the real OpenCode lifecycle hook plugin:
  - `tool.execute.before`: invokes `hyp hook opencode pre-tool-use` for Hyphae MCP tools (`hyp_mesh`, `hyp_send`, `hyp_inbox`, `hyp_stream`, `hyp_bridge`, `hyp_kv`, `hyphae_*`, `mcp__hyphae__*`) and injects the verified `_meshCall` token into `output.args` so `CallRegistry` verifies `opencode:<sessionID>`.
  - `tool.execute.after`: invokes `hyp hook opencode post-tool-use` to clean up `callID` and append any drained `additionalContext` cleanly without breaking non-string tool outputs.
  - `event` (`session.idle`): invokes `hyp hook opencode stop` and delivers any returned `followupMessage` via `client.session.prompt` (guarded against infinite continuation loops and missing APIs).
- **`~/.config/opencode/commands/hyphae.md`** — installs the `/hyphae` snapshot slash command (skip with `--no-commands`).
- **`~/.config/opencode/skills/hyphae/SKILL.md`** — installs the OpenCode runtime skill (skip with `--no-skills`).

## Optional Zero-Polling TUI Status Widget (`tui.json`)

`plugins/opencode/tui.mjs` is a dependency-free, zero-polling (`fs.watch` only — never `setInterval`), metadata-only TUI plugin compatible with both OpenCode v2 (`setup(api)`) and OpenCode v1 (`tui(api)`).

To enable it, add `file:///path/to/plugins/opencode/tui.mjs` to `~/.config/opencode/tui.json` (preserving any existing plugins):

```json
{
  "$schema": "https://opencode.ai/tui.json",
  "plugin": [
    "file:///absolute/path/to/plugins/opencode/tui.mjs"
  ]
}
```

### What It Displays

Reads `<state_dir>/ui/state.json` (honoring `HYPHAE_STATE_DIR`, `stateDir` in `~/.config/hyphae/node.json`, `~/.config/hyphae/ui/state.json`, and `~/.config/hyphae/state/ui/state.json`):

- Compact status badge: `⟁ @alice · 3 subs · 2 queued · FOCUS · 1 muted` (hidden when unenrolled for zero clutter).
- Sidebar summary lines: handle/address, Focus Mode, subscription/queue/channel/bridge/mute counts, and source labels.
- Security Gate alert: `⚠ hyphae: N held · run \`hyp gate review\`` whenever items are quarantined (human-CLI-only boundary).

## Security Invariants

- **Strict `execFile` argv arrays** — `hyphae.ts` never invokes a shell or interpolates strings into commands, enforces a 5 s timeout, and fails safe (`{}`) when the daemon is offline.
- **Metadata-only boundary** — `tui.mjs` recursively strips forbidden body/payload/note/secret/token keys (`body`, `text`, `note`, `payload`, `data`, `content`, `message`, `raw`, `ciphertext`, `plaintext`, `secret`, `token`, `quarantinedText`, `quarantinedItems`) before parsing.
- **Terminal injection stripping** — `sanitizeUiText` strips ANSI escapes (OSC/CSI/DCS/ESC), C0/C1 controls, zero-width marks, and Unicode BiDi overrides/isolates from all untrusted external metadata strings.
- **Quarantine isolation** — neither `/hyphae` nor `tui.mjs` ever displays quarantined payloads or auto-approves quarantined items; humans review directly via `hyp gate review`.

## Verification

```sh
node --check plugins/opencode/tui.mjs
node plugins/opencode/test/opencode.test.mjs
```
