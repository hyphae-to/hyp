# Status UI, Panels, Herdr Mods & Terminal Inspector

Hyphae gives you live visibility and quick session controls directly inside your coding harness — **strictly metadata-only** (zero message bodies, CloudEvent `data`, quarantined payloads, `sessionToken`s, or secrets ever appear in `ui/state.json` or UI components).

## Overview

| Harness | Live Status Bar | Inspector / Quick Controls | Thread Binding |
| --- | --- | --- | --- |
| **Claude Code** | Native `hyphae-panel` status indicator (v2.1.287+) or optional shell `--statusline` (`< 5 ms`, chains custom lines) | `/hyphae`, `/hyphae-subs`, `/hyphae-focus`, `/hyphae-mute`, `/hyphae-panel` + `!hyp ui` | `session_id` + `$HYPHAE_SESSION_ID` via `CLAUDE_ENV_FILE` |
| **Herdr Desktop App** | Native GPUI per-pane header pill (`mods/hyphae-pane`) | Native GPUI `mods/hyphae-panel` (right dock, `Cmd+Shift+H` floating window, or split) across **local & remote SSH spaces** | Per-pane `herdrTerminalId` + `herdrCreatedMs` anti-recycle pin |
| **Antigravity CLI (`agy`)** | Stacked native `--statusline` (`"stack_with_default": true`) | `hyp inspect` / `hyp ui` | `conversation_id` / `session_id` |
| **OpenCode** | Optional zero-polling TUI status widget (`tui.mjs`) | `/hyphae` command + `hyp inspect` / `hyp ui` | OpenCode plugin session ID |
| **Codex / Cursor / Gemini / Shells** | Automatic when running inside **Herdr**, or split terminal | Standalone `hyp inspect [--watch]` and interactive `hyp ui` | `$HYPHAE_SESSION_ID`, `$CODEX_THREAD_ID`, `$HC_TERMINAL_ID` |

---

## 1. Claude Code Native Panel & Optional Shell `statusLine`

`hyp setup --harness claude` installs `~/.claude/skills/hyphae-panel/` automatically on Claude Code v2.1.287+, providing a persistent live status indicator beneath the prompt (ON when enrolled; toggleable via `/hyphae-panel status off|on`) plus the `/hyphae-panel` side panel with zero changes to `settings.json` `statusLine`.

If you prefer shell `statusLine` chaining (for older Claude Code or custom shell bars):

```sh
hyp setup --harness claude --statusline
# Restore your original statusLine cleanly anytime:
hyp setup --harness claude --restore-statusline
```

- **Visual states:** `hyphae @alice · 3 subs` · `hyphae @alice · telegram:personal` · `hyphae @alice · 2 queued · focus` · `hyphae @alice · ⚠ 1 held` (run `hyp gate review` in a terminal).
- **Slash commands & zero-token TUI:** `/hyphae`, `/hyphae-subs`, `/hyphae-focus [on|off]`, `/hyphae-mute <target>`, `/hyphae-panel`, and `!hyp ui`.

---

## 2. Antigravity CLI (`agy`) Stacked `statusLine`

```sh
hyp setup --harness antigravity --statusline
```

Adds a stacked entry (`"stack_with_default": true`) to `~/.gemini/antigravity-cli/settings.json` without replacing your existing bar.

---

## 3. Native Herdr Mod (`hyphae-pane` + `hyphae-panel`)

```sh
hyp setup --harness herdr --mod
```

- **Zero-polling local architecture:** The daemon atomically writes metadata-only `<state_dir>/ui/state.json` (`0600` inside `0700` `ui/`); both mods watch it with Herdr's native `watchFolder` (zero polling, zero subprocess spawns).
- **Remote SSH spaces:** Panes sharing a remote host deduplicate fetches via `shared("hyphae.remoteInFlight")` / `shared("hyphae.remoteCache")` and call `hyp inspect --all --json` over SSH.
- **Safety guarantees:** Copies real directories (macOS FSEvents friendly), never clobbers an existing `cmd-shift-h` keybinding, never modifies shipped layouts (`main`, `terminals`, `win98` — use `--clone-layout herdr-hyphae` instead), refuses to edit symlinked layouts without `--patch-layout`, and never replaces custom pane headers without `--force-layout`.

### Composing `pill.js` Into a Custom Pane Header

Copy the three helper files into your custom pane mod folder (Herdr sandboxes imports per mod directory):

```sh
cp ~/.config/herdr-app/mods/hyphae-pane/{pill.js,shared-client.js,hyphae.svg} \
  ~/.config/herdr-app/mods/my-pane/
```

```js
import { createHyphaeClient } from "./shared-client.js";
import { renderHyphaePill } from "./pill.js";

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

---

## 4. Standalone CLI Inspector, Quick Controls & Interactive TUI

Works in any terminal, tmux split, or SSH session:

```sh
hyp inspect                          # snapshot current session
hyp inspect --all --json             # snapshot all sessions
hyp inspect --herdr-terminal t4g --watch
hyp ui                               # interactive fullscreen TUI (keys: 1-4, j/k, f, m, u/x, s, r, q)

hyp session focus on --json
hyp session mute '#noisy-ci' --json
hyp session unmute '#noisy-ci' --json
hyp session rule bob/rev interrupt --json
hyp session unsubscribe sub_01J... --json
hyp session leave 'local/#ops' --json
```

---

## Security & Metadata Boundary

1. **Zero body or token leakage:** `ui/state.json`, `hyp statusline`, `hyp inspect`, `hyp ui`, and harness UI mods never include message bodies, CloudEvent `data`, quarantined payloads, `sessionToken`s, or secrets.
2. **Terminal injection defense:** Untrusted labels (`handle`, `topic`, `source`, `channel`, `label`) are stripped of ANSI CSI/OSC escapes and C0/C1 control characters before rendering.
3. **Quarantine boundary:** UI surfaces show quarantined counts only and direct review to `hyp gate review` in a terminal.
