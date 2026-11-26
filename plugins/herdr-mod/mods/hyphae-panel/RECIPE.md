# Hyphae Inspector (`hyphae-pane` + `hyphae-panel`)

Live per-pane Hyphae mesh status pills in every Herdr terminal header paired with an expandable thread inspector for subscriptions, metadata-only inbox queues, focus/mute delivery rules and channels across local and remote SSH spaces.

## What you see

- **Pane header (`hyphae-pane`, 30 px):** Drop-in replacement for Herdr's shipped `pane` header. Preserves the program icon, agent/terminal title, cwd folder, working spinner / `Needs you` badge / done dot, and hover split/zoom/close buttons. Adds a right-aligned Hyphae status pill immediately before the agent status indicator:
  - Hidden on plain shells and unenrolled terminals with 0 subscriptions and 0 queued items.
  - Enrolled idle: sage mycelium glyph (`hyphae.svg`) with `@handle · 3 subs` (wide), `3s` (medium), or `3s` (compact).
  - Queued unread items: amber highlight pill (`3·2` / `3s · 2q` / `@alice · 3 subs · 2 queued`).
  - Focus Mode or Mute All (`*`): compact `focus` / `muted` chip.
  - Security Gate quarantine pending: warm alert badge `⚠ N`.
- **Thread Inspector (`hyphae-panel`, 380×560 floating window or 368 px right dock panel):**
  - **Header bar (40 px):** Mycelium glyph, `@handle` (or `Unenrolled`), terminal address badge (`t4g` / `solace/t4g`), transport badge (`herdr` / `claude_channel`), Refresh (`↻`), and Close (`×`).
  - **Contextual focus tracking:** Automatically follows the currently focused Herdr pane (`focused()?.terminal`) with zero multi-agent switcher clutter.
  - **Quick-control strip:** `Focus ON/OFF` toggle, `Mute All` (`*`) toggle, and a metadata-only Quarantine banner (`⚠ N quarantined · Run hyp gate review in terminal`) when quarantined items exist.
  - **4 segmented tabs (`Subs`, `Queue`, `Rules`, `Mesh`):**
    - `Subs (N)`: topic, origin node, urgency badge, coalesce seconds, filter summary, and `[×]` Unsubscribe button.
    - `Queue (N)`: kind breakdown pills (`DMs`, `Events`, `Plugins`, `Transfers`, `KV`) and metadata-only queued rows (source, kind, urgency, age, unnotified dot, `[Mute]`). Zero message bodies are ever read or rendered.
    - `Rules (N)`: delivery mode summary, active mutes with `[Unmute]`, per-source rules with click-to-cycle urgency (`interrupt → queue → notify → mute`), and an inline mute input at the bottom.
    - `Mesh`: local/remote node card (`nodeId`, version, profile, peers online), and joined `#channels` with `[Leave]`.

## How it behaves

- **Local panes:** Watches `~/.config/hyphae/ui` (or `<stateDir>/ui` from `node.json`, with `~/.config/hyphae/state/ui` fallback) via `watchFolder` + `readTextFile("state.json")` — zero subprocess spawns and zero polling.
- **Remote SSH spaces (`solace/t4g`):** Deduplicates fetches across all panes on the same machine via `shared("hyphae.remoteCache")` and refreshes via `exec("hyp", ["inspect", "--all", "--json"], { on: machine })` every 10 s with exponential backoff up to 60 s on error.
- **Clicking the header pill:** Publishes `shared("hyphae.selected")`. If the active layout has a `"hyphae"` child inside `"panel-body"`, selects and opens the right dock panel (`layout.select` + `layout.show`); otherwise opens `hyphae-panel` as a floating window overlay (`key: "hyphae-inspector"`).
- **Keyboard in `hyphae-panel`:** `1`–`4` switch tabs, `r` refreshes, `Esc` blurs the mute input or closes the overlay. `cmd-shift-h` toggles `hyphae-panel` globally from `keys.json`.
- **Space switching:** When mounted in `panel-body`, `hyphae-panel` appends `"hyphae"` to `shared("workspace.panels")` once so shipped `mods/tabs` remembers it per space.

## Built from

- `mods/hyphae-pane/`: `mod.json`, `main.js`, `pill.js`, `shared-client.js`, `hyphae.svg`.
- `mods/hyphae-panel/`: `mod.json`, `main.js`, `shared-client.js`, `hyphae.svg`.
- `keys.json`: `{ "global": { "cmd-shift-h": "mod.open:hyphae-panel" } }`.
- Herdr APIs: `panes`, `focused`, `terminals`, `layout`, `props`, `run`, `theme`, `home`, `readTextFile`, `watchFolder`, `exec`, `openOverlay`, `closeOverlay`, `shared`, `setShared`, `checking`, `nextCommand`.
- External CLI invoked on user quick-control clicks (and remote machine refresh): `hyp inspect --all --json` and `hyp session focus|mute|unmute|rule|unsubscribe|leave --herdr-terminal <tid> --json`.

### Composing `pill.js` into a custom pane header

Herdr sandboxes JS module imports to each mod's own folder (`../` imports fail `herdr-app check`). To embed the Hyphae status pill alongside your own widgets in a custom pane header mod (`mods/my-pane/`):

1. Copy `pill.js`, `shared-client.js`, and `hyphae.svg` from `mods/hyphae-pane/` into `mods/my-pane/`.
2. Import and render the pill in `mods/my-pane/main.js`:

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

## Watch out

- Shipped Herdr layouts (`main`, `terminals`, `win98`) are overwritten on app start; clone a layout first (`herdr-app do layout.clone '{"name":"main","as":"herdr-hyphae"}'`) before pointing `pane.header.content.mod` to `"hyphae-pane"`.
- Symlinked layouts (e.g. git-managed `herdr-custom-ui`) are never edited automatically by `hyp setup --harness herdr --mod` or `scripts/install.sh` without explicit `--patch-layout`.
- All `init()` side effects are guarded with `if (checking()) return;`, and `async close()` calls `watch.cancel()` on active `watchFolder` handles.

## Done when

- `herdr-app check plugins/herdr-mod/mods/hyphae-pane` passes with 0 errors and 0 warnings.
- `herdr-app check plugins/herdr-mod/mods/hyphae-panel` passes with 0 errors and 0 warnings.
- `node plugins/herdr-mod/test/mod.test.mjs` passes all unit & anti-body-leakage tests.
- Clicking a pill in `hyphae-pane` focuses the matching session in `hyphae-panel` (docked or floating overlay), and `cmd-shift-h` toggles the inspector from any layout.
