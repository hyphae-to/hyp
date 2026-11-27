# Hyphae Plugin & Optional TUI Widget for OpenCode

Real lifecycle hooks, `/hyp` slash command, and an optional zero-polling, metadata-only TUI status widget for [OpenCode](https://opencode.ai).

## Automatic Setup (Lifecycle Hooks + `/hyp` Command)

Run the static `hyp` binary configurator:

```sh
hyp setup --harness opencode
```

This configures OpenCode idempotently while preserving all existing settings:

- **`~/.config/opencode/opencode.json`** — registers the local `hyphae` MCP server (`hyp mcp --backend opencode`, with verified per-session identity — no `--ephemeral`!).
- **`~/.config/opencode/plugins/hyphae.ts`** — installs the real OpenCode lifecycle hook plugin supporting BOTH OpenCode v2 (`export default { id: "hyphae", setup(api) }`, including Code Mode `execute` + `tools.hyphae.hyp_*`) and OpenCode v1 (`export const HyphaePlugin`):
  - `api.tool.hook("execute.before")` / v1 `tool.execute.before`: strips any untrusted `_meshCall`, invokes `hyp hook opencode pre-tool-use` for Hyphae MCP tools (`hyp_mesh`, `hyp_send`, `hyp_inbox`, `hyp_stream`, `hyp_bridge`, `hyp_kv`, `hyphae_*`, `mcp__hyphae__*`), and injects the verified single-use `_meshCall` token into tool arguments so `CallRegistry` verifies `opencode:<sessionID>`.
  - `api.tool.hook("execute.after")` / v1 `tool.execute.after`: scrubs consumed `_meshCall`, avoids losing Interrupt messages inside inner Code Mode calls, and appends drained `additionalContext` cleanly to `ev.result.content` / tool output without breaking non-string outputs.
  - `api.session.hook("prompt")`: invokes `hyp hook opencode pre-invocation` to inject queued messages at the start of a turn.
  - `api.event.subscribe` (`session.execution.succeeded` / `session.idle`) / v1 `event` (`session.idle`): invokes `hyp hook opencode stop` and delivers any returned `followupMessage` via `api.session.prompt({ sessionID, text })` / `client.session.prompt` (guarded against infinite continuation loops and missing APIs).
- **`~/.config/opencode/commands/hyp.md`** — installs the `/hyp` snapshot slash command (skip with `--no-commands`).
- **`~/.config/opencode/skills/hyp-mesh/SKILL.md`** — installs the OpenCode runtime skill (skip with `--no-skills`).

## Optional Zero-Polling TUI Status Widget (`tui.json`)

`plugins/opencode/tui.mjs` is a dependency-free, zero-polling (`fs.watch` only — never `setInterval`), metadata-only TUI plugin compatible with both OpenCode v2 (`setup(api)`) and OpenCode v1 (`tui(api)`).

To enable it, add `file:///path/to/plugins/opencode/tui.mjs` to `~/.config/opencode/tui.json` (preserving any existing plugins). Keep the adjacent `ui-snapshot.mjs` file with `tui.mjs` when copying it out of the checkout.

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
- **Quarantine isolation** — neither `/hyp` nor `tui.mjs` ever displays quarantined payloads or auto-approves quarantined items; humans review directly via `hyp gate review`.

## Verification

```sh
node --check plugins/opencode/tui.mjs
node plugins/opencode/test/opencode.test.mjs
```
