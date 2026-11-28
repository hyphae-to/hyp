# Herdr Core & Herdr Desktop *(Full Support)*

Running Claude Code, Codex, OpenCode, Antigravity CLI, or Gemini inside [Herdr](https://herdr.dev) provides native push wakeups (`hc send` / `hc interrupt`) and GPU status pills across local and remote SSH spaces.

## Setup

```sh
hyp setup --harness herdr --mod
```

What this configures:
- Tailored Herdr skill in `~/.config/herdr/skills/hyp-mesh/SKILL.md`.
- Native GPUI mods `hyphae-pane` (per-pane header pill + reusable `pill.js`) and `hyphae-panel` (docked or `Cmd+Shift+H` floating inspector) in `~/.config/herdr-app/mods/` when `--mod` is passed.

Herdr setup never mutates shipped layouts (`main`, `terminals`, `win98`), symlinked git-tracked layouts (unless `--patch-layout` is passed), or custom pane headers (unless `--force-layout` is passed). See [Status UI](status-ui.md#3-native-herdr-mod-hyphae-pane--hyphae-panel) for `--clone-layout` and composing `pill.js` into a custom pane header.

## Caller Identity & Wakeups

- **Identity:** Requires `--backend herdr` and verifies `HC_TERMINAL_ID` via `hc get --json` (`state === "live"` and non-null `status.app`). **Bare shell terminals (`status: null`) are rejected fail-closed** so inbound mesh text can never be typed into a raw shell after an agent exits.
- **Wakeups:** Native `hc send` (`queue`) and `hc interrupt` (`interrupt`) push directly into live Herdr tabs without polling.

## Launch Templates in `hyp onboard`

When `HC_TERMINAL_ID` is set, `hyp onboard` discovers Herdr launch templates (`hc templates --json`), launches them detached (`hc run --bg --outlive-parent`), and attaches your interactive TTY (`hc attach <address>`).

## What You Should See

- Each enrolled Herdr pane displays a compact Hyphae pill; clicking it or pressing `Cmd+Shift+H` opens `hyphae-panel`.
- Sending an `interrupt`-tier message wakes an active or idle Herdr tab immediately.

See [Troubleshooting](../operations/troubleshooting.md) if pills stay blank or a custom layout was skipped.

## Builder status in Shared KV

The optional Herdr status publisher follows the native event stream and exposes one stable status key per selected builder session. See the [publisher setup and access controls](../../plugins/herdr-status/README.md).
