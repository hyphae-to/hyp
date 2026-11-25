# Hyphae Native Herdr Mod (`hyphae-pane` + `hyphae-panel`)

Native GPUI pane header status pills and expandable thread inspector for [Herdr](https://herdr.dev) terminals — works across **every coding harness** running inside Herdr (Claude Code, Codex, OpenCode, Antigravity CLI, Gemini, shells) on both **local** and **remote SSH** spaces.

## What's Included

| Mod | Role | Placement |
|---|---|---|
| `mods/hyphae-pane/` | Drop-in replacement for Herdr's shipped `mods/pane` header with a right-aligned Hyphae live status pill (`pill.js`). Hidden on plain shells. | `pane.header.content.mod = "hyphae-pane"` |
| `mods/hyphae-panel/` | Expandable **Hyphae Thread Inspector** (`Subs`, `Queue`, `Rules`, `Mesh`, Focus Mode & Mute All toggles, metadata-only quarantine alert). | Right `panel-body` dock, floating window (`cmd-shift-h`), or split/tab pane |
| `keys.json` | Global shortcut `"cmd-shift-h": "mod.open:hyphae-panel"` (merged only if unbound). | `~/.config/herdr-app/keys.json` |

## Zero-Polling Architecture

- **Local panes:** Watches `~/.config/hyphae/ui/` (or `<stateDir>/ui` from `node.json`, with `~/.config/hyphae/state/ui` fallback) using Herdr's native `watchFolder` + `readTextFile("state.json")` — zero polling and zero subprocess spawns.
- **Remote SSH spaces (`solace/t4g`):** Deduplicates in-flight and cached fetches across all panes on the same remote host through `shared("hyphae.remoteInFlight")` + `shared("hyphae.remoteCache")` and runs `exec("hyp", ["inspect", "--all", "--json"], { on: machine })` with exponential backoff.
- **Strict metadata boundary:** Neither `ui/state.json` nor the Herdr mods ever read or render message bodies, CloudEvent `data`, wakeup `note`s, quarantined payloads, or secrets. Quarantined alerts direct you to `hyp gate review` in your terminal.

## Install

### Option 1 — Via `hyp` CLI (Recommended)

```sh
hyp setup --harness herdr --mod
```

By default, `hyp` copies both mods into `~/.config/herdr-app/mods/`, merges `cmd-shift-h` into `keys.json` (if unbound), and **never** mutates symlinked layouts, shipped layouts (`main`, `terminals`, `win98`), or custom pane headers without explicit opt-in (`--patch-layout`, `--clone-layout <name>`, or `--force-layout`).

### Option 2 — Standalone Script

```sh
sh plugins/herdr-mod/scripts/install.sh
# Clone shipped `main` layout into a personal layout with pane header + dock panel:
sh plugins/herdr-mod/scripts/install.sh --clone-layout herdr-hyphae
```

## Composing `pill.js` Into a Custom Pane Header

Because Herdr (`gpui-shell`) sandboxes JavaScript module imports to each mod's own directory (`../` imports are rejected by `herdr-app check`), custom pane headers can compose the Hyphae pill cleanly by copying three files from `mods/hyphae-pane/` into their own mod folder:

```sh
cp ~/.config/herdr-app/mods/hyphae-pane/pill.js ~/.config/herdr-app/mods/my-pane/
cp ~/.config/herdr-app/mods/hyphae-pane/shared-client.js ~/.config/herdr-app/mods/my-pane/
cp ~/.config/herdr-app/mods/hyphae-pane/hyphae.svg ~/.config/herdr-app/mods/my-pane/
```

Then render the pill beside your own pane-header widgets:

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

## Verification

```sh
node --check plugins/herdr-mod/mods/hyphae-pane/shared-client.js
node --check plugins/herdr-mod/mods/hyphae-pane/pill.js
node --check plugins/herdr-mod/mods/hyphae-pane/main.js
node --check plugins/herdr-mod/mods/hyphae-panel/main.js
node plugins/herdr-mod/test/mod.test.mjs
herdr-app check plugins/herdr-mod/mods/hyphae-pane
herdr-app check plugins/herdr-mod/mods/hyphae-panel
sh -n plugins/herdr-mod/scripts/install.sh
```
