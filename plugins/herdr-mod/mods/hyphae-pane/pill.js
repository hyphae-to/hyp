// Standalone composable Hyphae status pill for Herdr pane headers.
//
// Custom pane header mods can copy `pill.js`, `shared-client.js`, and `hyphae.svg`
// into their own mod folder (Herdr sandboxes JS module imports per mod folder)
// and render the pill side-by-side with other widgets:
//
//   import { renderHyphaePill } from "./pill.js";
//
// Returns `null` when the terminal is unenrolled and has 0 subscriptions, 0 queued
// items, and 0 quarantined items so plain shells stay visually clean.

import { div, svg } from "gpui-kit";
import { h_flex } from "gpui-base";
import { layout, openOverlay, run, setShared } from "herdr";
import {
  findLayoutNode,
  formatPillMetrics,
  parseTerminalAddress,
  withAlpha,
} from "./shared-client.js";

export { formatPillMetrics };

/**
 * Opens the Hyphae inspector for the clicked terminal:
 * - If the active layout includes a `"hyphae"` block inside `"panel-body"`, selects
 *   and reveals the right-side dock panel.
 * - Otherwise opens `hyphae-panel` as a draggable floating window overlay.
 */
export function openHyphaeInspector({ terminal, entry }) {
  const { machine, rawTid, address } = parseTerminalAddress(terminal);
  setShared("hyphae.selected", {
    terminal: address ?? terminal ?? null,
    machine,
    rawTid,
    sessionId: entry?.sessionId ?? null,
    pinned: true,
    at: Date.now(),
  });

  const root = layout();
  const panelBody = findLayoutNode(root, "panel-body");
  const hasDockedHyphae = Boolean(panelBody && findLayoutNode(panelBody, "hyphae"));

  if (hasDockedHyphae) {
    const panel = findLayoutNode(root, "panel");
    const isAlreadyShowing = panel && !panel.hidden && panelBody.active === "hyphae";
    if (!isAlreadyShowing) {
      run("layout.select", { stack: "panel-body", child: "hyphae" });
      run("layout.show", { id: "panel" });
    }
    return "dock";
  }

  openOverlay({
    mod: "hyphae-panel",
    kind: "window",
    key: "hyphae-inspector",
    width: 380,
    height: 560,
    props: { terminal: address ?? terminal ?? null },
  });
  return "overlay";
}

/**
 * Renders the right-aligned Hyphae pane header pill, or `null` when hidden.
 *
 * @param {object} opts
 * @param {Record<string, string>} opts.theme - Current Herdr `theme()` colors.
 * @param {string} opts.paneId - Pane identifier for stable element IDs.
 * @param {string | null} opts.terminal - Terminal address (`"t4g"` or `"solace/t4g"`).
 * @param {object | null} opts.entry - Session summary object from `ui/state.json`.
 * @param {boolean | "compact" | "medium" | "wide"} [opts.compact=false] - Width density mode.
 * @param {string} [opts.iconPath="mods/hyphae-pane/hyphae.svg"] - Tinted SVG path under Herdr home.
 * @param {(ctx: { terminal: string | null, entry: object | null }, cx: any) => void} [opts.onClick]
 */
export function renderHyphaePill({
  theme: t,
  paneId,
  terminal,
  entry,
  daemon = null,
  snapshot = null,
  compact = false,
  iconPath = "mods/hyphae-pane/hyphae.svg",
  onClick,
}) {
  const m = formatPillMetrics(entry, daemon ?? snapshot);
  if (!m.visible) return null;

  const mode =
    compact === true || compact === "compact"
      ? "compact"
      : compact === "wide"
        ? "wide"
        : "medium";

  const sage = t.done || t.ansi2 || t.accent;
  const amber = t.blocked || t.ansi3 || t.accent;
  const alert = t.ansi1 || t.blocked || t.accent;
  const focusTint = t.accent || t.ansi4 || t.foreground;

  let pillBg = withAlpha(sage, "1c");
  let pillBorder = withAlpha(sage, "48");
  let glyphColor = sage;
  let textColor = t.foreground;

  if (m.tone === "alert") {
    pillBg = withAlpha(alert, "24");
    pillBorder = withAlpha(alert, "66");
    glyphColor = alert;
    textColor = alert;
  } else if (m.tone === "queued") {
    pillBg = withAlpha(amber, "26");
    pillBorder = withAlpha(amber, "66");
    glyphColor = amber;
    textColor = amber;
  } else if (m.tone === "focus") {
    pillBg = withAlpha(focusTint, "20");
    pillBorder = withAlpha(focusTint, "55");
    glyphColor = focusTint;
    textColor = t.foreground;
  } else if (m.tone === "muted") {
    pillBg = t.raised || t.surface;
    pillBorder = t.border;
    glyphColor = t.dim;
    textColor = t.muted;
  }

  const primaryText =
    mode === "wide" ? m.wideLabel : mode === "medium" ? m.mediumLabel : m.compactLabel;

  const chipBg =
    m.chip === "muted"
      ? withAlpha(t.dim || t.muted, "28")
      : withAlpha(focusTint, "2c");
  const chipColor = m.chip === "muted" ? t.muted : focusTint;

  const handleClick = (e, cx) => {
    cx.stop_propagation();
    if (typeof onClick === "function") {
      onClick({ terminal, entry, event: e }, cx);
      return;
    }
    openHyphaeInspector({ terminal, entry });
  };

  return h_flex()
    .id(`hyphae-pill-${paneId ?? terminal ?? "pane"}`)
    .flex_none()
    .h(20)
    .px(6)
    .gap(5)
    .items_center()
    .rounded(5)
    .border_1()
    .border_color(pillBorder)
    .bg(pillBg)
    .cursor_pointer()
    .hover((s) => s.bg(t.hover).border_color(t.accent))
    .on_mouse_down("left", (_e, cx) => cx.stop_propagation())
    .on_click(handleClick)
    .child(svg(iconPath).size(11).flex_none().text_color(glyphColor))
    .child(
      div()
        .flex_none()
        .text_size(10.5)
        .font_medium()
        .text_color(textColor)
        .child(primaryText)
    )
    .when(Boolean(m.chip) && mode === "compact", (el) =>
      el.child(
        div()
          .flex_none()
          .px(4)
          .h(14)
          .flex()
          .items_center()
          .rounded(3)
          .bg(chipBg)
          .text_size(9.5)
          .font_semibold()
          .text_color(chipColor)
          .child(m.chip)
      )
    )
    .when(Boolean(m.alertLabel), (el) =>
      el.child(
        div()
          .flex_none()
          .px(4)
          .h(14)
          .flex()
          .items_center()
          .rounded(3)
          .bg(withAlpha(alert, "30"))
          .text_size(9.5)
          .font_semibold()
          .text_color(alert)
          .child(m.alertLabel)
      )
    );
}
