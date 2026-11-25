# Hyphae Harness Live Status Plugins, TUI & Native Herdr Mod

Hyphae `v0.6.0` gives you live visibility and quick session controls directly inside your coding harness — **strictly metadata-only** (zero message bodies, CloudEvent `data`, wakeup notes, quarantined payloads, or secrets ever leave the agent thread).

## Capability Matrix

| Harness | Live Status Bar | Inspector / Quick Controls | Thread Binding |
|---|---|---|---|
| **Claude Code** | Native `statusLine` (`hyp statusline --harness claude`, `< 5 ms`, non-destructive chaining) | Plugin commands (`/hyphae`, `/hyphae-subs`, `/hyphae-focus`, `/hyphae-mute`, `/hyphae-panel`) + `!hyp ui` | `session_id` + `$HYPHAE_SESSION_ID` via `CLAUDE_ENV_FILE` |
| **Herdr Desktop App** | Native GPUI per-pane top-bar pill (`mods/hyphae-pane`) | Native GPUI `mods/hyphae-panel` (right dock, `cmd-shift-h` floating window, or split/tab) — works across **local & remote SSH spaces** for every harness inside Herdr | Per-pane `herdrTerminalId` + `herdrCreatedMs` anti-recycle pin |
| **Antigravity CLI (`agy`)** | Native `statusLine` with `"stack_with_default": true` | `hyp inspect` / `hyp ui` | `conversation_id` / `session_id` |
| **Codex / OpenCode / Gemini / Shells** | Automatic when running inside **Herdr**, or split terminal | Standalone `hyp inspect [--watch]` and interactive `hyp ui` | `$HYPHAE_SESSION_ID`, `$CODEX_THREAD_ID`, `$HC_TERMINAL_ID` |

---

## 1. Claude Code Plugin & Non-Destructive `statusLine`

### Install

```sh
# Install Claude Code hooks, MCP server, slash commands, and composable statusLine
hyp setup --harness claude --statusline
```

- **Non-destructive `statusLine` chaining:** If `~/.claude/settings.json` already defines a custom `statusLine.command` (model, git branch, context bar), `hyp setup` backs up your original config to `~/.claude/settings.json.hyp.bak`, stores the existing command in `~/.config/hyphae/claude-statusline-chain.json` (`0600`), and chains it so Hyphae appends cleanly on the next row.
- Remove cleanly at any time while restoring your original `statusLine`:

```sh
hyp setup --harness claude --restore-statusline
```

### Visual States (`hyp statusline` & Claude native plugin)

- Idle enrolled: `hyphae @alice · 3 subs`
- Linked bridge: `hyphae @integration-tests · telegram:personal`
- Queued items: `hyphae @alice · 3 subs · 2 queued`
- Focus Mode: `hyphae @alice · 3 subs · 2 queued · focus`
- Muted: `hyphae @alice · 3 subs · 2 queued · 1 muted` (`muted` when wildcard `*` is muted)
- Quarantine alert: `hyphae @alice · 3 subs · ⚠ 1 held` (run `hyp gate review` in a terminal)
- Unenrolled / offline: empty by default (`--when-unenrolled dim` prints `hyphae: idle` / `hyphae: offline`)

> **Claude Code v2.1.287+ tip — pick one status bar:** `hyp setup --harness claude` installs `~/.claude/skills/hyphae-panel/` automatically, which already renders a persistent live status line (`$.ui.status`) whenever your session is enrolled plus the `/hyphae-panel` side panel. You don't need `--statusline` on Claude Code unless you explicitly want shell `statusLine` chaining (for Antigravity CLI `agy` or older Claude Code). Run `hyp setup --harness claude --restore-statusline` if you previously enabled both.

### Slash Commands & Zero-Token TUI

On `SessionStart`, Hyphae writes `export HYPHAE_SESSION_ID='claude:<validated-id>'` to `$CLAUDE_ENV_FILE` so commands target the exact Claude thread automatically:

- `/hyphae` — compact snapshot of subscriptions, queue, mutes, focus, channels, and wakeups
- `/hyphae-subs` — list/manage active stream subscriptions
- `/hyphae-focus [on|off]` — toggle Focus Mode
- `/hyphae-mute <target>` — mute/unmute a source or pattern
- `/hyphae-panel` — open the native Claude Code Hyphae side panel
- `!hyp ui` — open the interactive zero-token terminal inspector inside Claude Code

---

## 2. Antigravity CLI (`agy`) `statusLine`

Antigravity CLI supports `"stack_with_default": true`, so Hyphae stacks below the built-in status bar without wrapping your existing command:

```sh
hyp setup --harness antigravity --statusline
```

This adds the following entry to `~/.gemini/antigravity-cli/settings.json`:

```json
{
  "statusLine": {
    "type": "command",
    "command": "hyp statusline --harness antigravity",
    "enabled": true,
    "stack_with_default": true,
    "padding": 0
  }
}
```

---

## 3. Native Herdr Mod (`hyphae-pane` + `hyphae-panel`)

Running Claude Code, Codex, OpenCode, Antigravity CLI, Gemini, or plain shells inside [Herdr](https://herdr.dev) gives you native GPU status pills in every pane header plus a full expandable inspector panel across both **local** and **remote SSH** spaces.

### Zero-Polling Architecture

- **Local panes:** The local Hyphae daemon atomically writes a metadata-only projection to `<state_dir>/ui/state.json` (`~/.config/hyphae/ui/state.json` by default, `0600` inside `0700` `ui/`). Both mods watch that directory with Herdr's native `watchFolder` + `readTextFile` — **0 polling and 0 subprocess spawns**.
- **Remote SSH spaces (`solace/t4g`):** Panes sharing a remote host deduplicate in-flight and cached fetches through `shared("hyphae.remoteInFlight")` + `shared("hyphae.remoteCache")` and invoke `hyp inspect --all --json` via `exec(..., { on: machine })` with backoff.

### Safe Installation

```sh
# Via hyp (embedded in the static binary)
hyp setup --harness herdr --mod

# Or standalone POSIX script from this repo
sh plugins/herdr-mod/scripts/install.sh
```

Safety guarantees enforced by both `hyp` and `scripts/install.sh`:

1. **Real directory copies (never symlinks by default):** Installs `mods/hyphae-pane/` and `mods/hyphae-panel/` directly into `~/.config/herdr-app/mods/` so macOS FSEvents hot-reload works immediately.
2. **Non-clobbering `keys.json`:** Adds `"cmd-shift-h": "mod.open:hyphae-panel"` under `"global"` only when `cmd-shift-h` is not already bound.
3. **Shipped layout preservation:** Never modifies Herdr's shipped `main`, `terminals`, or `win98` layouts (which Herdr overwrites on startup). Press `cmd-shift-h` immediately for the floating inspector, or pass `--clone-layout herdr-hyphae` to clone `main.json` into a personal layout with both `hyphae-pane` and the docked `hyphae-panel`.
4. **Symlink safety:** If your active layout JSON is a symlink (for example, `herdr-folders.json -> ~/Workspace/herdr-custom-ui/...`), the installer **refuses to edit it** unless you explicitly pass `--patch-layout`, and prints the exact 2-line layout snippet instead.
5. **Custom pane header safety:** If `pane.header.content.mod` is already customized (neither `"pane"` nor `"hyphae-pane"`), the installer **never clobbers it** without `--force-layout`.

### Composing `pill.js` Into a Custom Pane Header

Because Herdr (`gpui-shell`) sandboxes JS module imports to each mod's own folder (`../` imports fail `herdr-app check`), copy three files from `mods/hyphae-pane/` into your custom pane header mod folder:

```sh
cp ~/.config/herdr-app/mods/hyphae-pane/pill.js ~/.config/herdr-app/mods/my-pane/
cp ~/.config/herdr-app/mods/hyphae-pane/shared-client.js ~/.config/herdr-app/mods/my-pane/
cp ~/.config/herdr-app/mods/hyphae-pane/hyphae.svg ~/.config/herdr-app/mods/my-pane/
```

Then import and render the pill side by side with your own header widgets:

```js
import { createHyphaeClient } from "./shared-client.js";
import { renderHyphaePill } from "./pill.js";

// Inside render(cx):
const { entry } = this.hyphaeClient.resolveTerminal(p.terminal);
const pill = renderHyphaePill({
  theme: t,
  paneId: p.pane,
  terminal: p.terminal,
  entry,
  compact: this.width < 360,
  iconPath: "mods/my-pane/hyphae.svg",
});
```

Clicking the pill publishes `shared("hyphae.selected")`: if your layout has a `"hyphae"` block inside `"panel-body"`, it selects and opens the right dock panel; otherwise it opens `hyphae-panel` as a floating window overlay.

### `hyphae-panel` Inspector Features

- **Target tracking:** Follows `focused()?.terminal` automatically, locks onto clicked pane pills, and shows quick session switcher chips when multiple sessions are active.
- **Quick controls:** Toggle **Focus Mode** (`hyp session focus`) and **Mute All (`*`)** (`hyp session mute` / `unmute`), plus a metadata-only **Quarantine** banner directing you to `hyp gate review`.
- **4 tabs (`1`–`4` keys, `r` refresh, `Esc` close):**
  - **Subs:** Topic, origin node, urgency badge, coalesce window, filter summary, and `[×]` Unsubscribe.
  - **Queue:** Kind breakdown (`DMs`, `Events`, `Plugins`, `Transfers`, `KV`) and metadata-only queued rows (source, kind, urgency, age, `[Mute]`).
  - **Rules:** Delivery policy summary, active mutes with `[Unmute]`, per-source delivery rules with one-click urgency cycling, and an inline mute input.
  - **Mesh:** Node status & peers online, joined `#channels` with `[Leave]`, and active scheduled wakeups.

---

## 4. Standalone CLI Inspector, Quick Controls & Interactive TUI

These commands work in any terminal, tmux split, or SSH session (and auto-detect the active session from `$HYPHAE_SESSION_ID`, `$CLAUDE_SESSION_ID`, `$CODEX_THREAD_ID`, or `$HC_TERMINAL_ID`):

```sh
# Snapshot current thread (or all threads) as TTY table or agent-first JSON
hyp inspect
hyp inspect --all --json
hyp inspect --herdr-terminal t4g --watch   # zero-polling live stream over connector.sock

# Interactive terminal UI (keys: 1-4/Tab tabs, j/k navigate, f focus, m mute, u/x remove/unsub/leave, s switch session, r refresh, q quit)
hyp ui

# Scriptable session quick controls
hyp session focus on --herdr-terminal t4g --json
hyp session mute '#noisy-ci' --herdr-terminal t4g --json
hyp session unmute '#noisy-ci' --herdr-terminal t4g --json
hyp session rule bob/rev interrupt --herdr-terminal t4g --json
hyp session unsubscribe sub_01J... --herdr-terminal t4g --json
hyp session leave 'local/#ops' --herdr-terminal t4g --json
```

---

## Security & Metadata Boundary

1. **Zero body leakage:** `ui/state.json`, `hyp statusline`, `hyp inspect`, `hyp ui`, and the Herdr mods never read or display message bodies, CloudEvent `data`, wakeup `note`s, quarantined payloads, or secrets.
2. **Terminal injection defense:** Untrusted metadata fields (`handle`, `topic`, `source`, `channel`, `label`) are stripped of ANSI CSI/OSC sequences and C0/C1 control characters before rendering.
3. **Human-CLI quarantine boundary:** UI surfaces show quarantined counts only and always direct review to `hyp gate review` in a terminal.
4. **Private permissions:** `<state_dir>/ui/` is created `0700` and `ui/state.json` is atomically replaced with `0600`.
