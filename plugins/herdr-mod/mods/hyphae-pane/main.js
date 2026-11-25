// Drop-in replacement for Herdr's shipped `mods/pane` header with a right-aligned
// Hyphae live session pill (`renderHyphaePill`).
//
// Preserves 100% of shipped `mods/pane`: program icon, agent name or terminal title,
// folder path, agent status (working spinner / Needs you / done dot), and hover
// split/zoom/close buttons. Reads local Hyphae state via `watchFolder` + `readTextFile`
// (zero polling, zero spawns) and remote SSH spaces via deduplicated cached `exec`.

import { View, div, svg, image } from "gpui-kit";
import { h_flex } from "gpui-base";
import {
  panes,
  props,
  run,
  theme,
  home,
  layout,
  terminals,
  readTextFile,
  watchFolder,
  exec,
  shared,
  setShared,
  checking,
} from "herdr";
import { createHyphaeClient, parseTerminalAddress } from "./shared-client.js";
import { renderHyphaePill } from "./pill.js";

// Match the first visible tab frame, including the active child of a stack.
function paneFrame(node) {
  if (!node || node.hidden) return null;
  if (node.content?.tab && node.content.pane) return node.content.pane;
  let children = node.children ?? [];
  if (node.type === "stack") {
    const visible = children.filter((child) => !child.hidden);
    children = [visible.find((child) => child.id === node.active) ?? visible[0]];
  }
  for (const child of children) {
    const frame = paneFrame(child);
    if (frame) return frame;
  }
  return null;
}

function icon(p, size, color) {
  if (!p?.icon) return null;
  return p.tint
    ? svg(p.icon).size(size).flex_none().text_color(color)
    : image(p.icon).w(size).h(size).flex_none();
}

function folder(cwd) {
  if (!cwd) return "";
  const h = home();
  return cwd === h ? "~" : cwd.startsWith(h + "/") ? "~" + cwd.slice(h.length) : cwd;
}

export default class HyphaePane extends View {
  init(_props, cx) {
    this.hovered = false;
    this.width = 480;
    this.client = createHyphaeClient({
      home,
      readTextFile,
      watchFolder,
      exec,
      shared,
      setShared,
      terminals,
    });

    if (checking()) return;

    const p = this.me();
    const { machine } = parseTerminalAddress(p?.terminal ?? props()?.terminal ?? null);
    if (machine) {
      this.client.ensureRemoteFresh(machine, cx, false);
    } else {
      this.client.ensureLocal(cx);
    }

    // Gentle fallback timer: retries local watcher if ui/ dir did not exist yet,
    // and refreshes remote SSH machines (deduplicated through shared remoteCache).
    cx.timer.every(10000, (timerCx) => {
      const cur = this.me();
      const addr = cur?.terminal ?? props()?.terminal ?? null;
      const parsed = parseTerminalAddress(addr);
      if (parsed.machine) {
        this.client.ensureRemoteFresh(parsed.machine, timerCx, false);
      } else {
        this.client.ensureLocal(timerCx);
      }
    });
  }

  async close(_cx) {
    if (this.client) {
      this.client.dispose();
    }
  }

  me() {
    const paneId = props()?.pane;
    if (!paneId) return null;
    return panes().find((p) => p.pane === paneId) ?? null;
  }

  button(t, id, iconName, command, args) {
    return div()
      .id(id)
      .p(3)
      .rounded(4)
      .text_color(t.dim)
      .hover((s) => s.bg(t.hover).text_color(t.foreground))
      .on_mouse_down("left", (_e, cx) => cx.stop_propagation())
      .on_click((_e, cx) => {
        cx.stop_propagation();
        run(command, args);
      })
      .child(svg(`mods/pane/${iconName}.svg`).size(14));
  }

  render(cx) {
    const t = theme();
    const p = this.me();
    if (!p) return div();

    const name =
      ((p.program?.agent || p.program?.shell) && p.program.name) ||
      p.title ||
      p.program?.name ||
      "shell";
    const pic = icon(p.program, 14, t.dim);
    const st = p.status;
    const pane = p.pane;
    const bottom = paneFrame(layout())?.header?.position === "bottom";

    const terminalAddr = p.terminal ?? props()?.terminal ?? null;
    const { machine, entry } = this.client
      ? this.client.resolveTerminal(terminalAddr)
      : { machine: null, entry: null };

    if (!checking() && this.client) {
      if (machine) {
        this.client.ensureRemoteFresh(machine, cx, false);
      } else {
        this.client.ensureLocal(cx);
      }
    }

    const density = this.width >= 540 ? "wide" : this.width >= 360 ? "medium" : "compact";
    const pill = renderHyphaePill({
      theme: t,
      paneId: pane,
      terminal: terminalAddr,
      entry,
      compact: density,
    });

    return h_flex()
      .id(`pane-head-${pane}`)
      .size_full()
      .px(10)
      .gap(8)
      .items_center()
      .bg(t.background)
      .when(bottom, (el) => el.border_t(1))
      .when(!bottom, (el) => el.border_b(1))
      .border_color(t.border)
      .text_size(12)
      .on_size_change((size, sizeCx) => {
        const nextWidth = Math.round(size?.width ?? 480);
        if (Math.abs(nextWidth - this.width) >= 16) {
          this.width = nextWidth;
          sizeCx.notify();
        }
      })
      .on_hover((hovered, hoverCx) => {
        this.hovered = hovered;
        hoverCx.notify();
      })
      .on_click(() => run("pane.focus", { pane }))
      .when(Boolean(pic), (el) => el.child(pic))
      .child(
        div()
          .flex_none()
          .truncate()
          .max_w(260)
          .font_medium()
          .text_color(t.foreground)
          .child(name)
      )
      .child(div().flex_1().min_w(0).truncate().text_color(t.dim).child(folder(p.cwd)))
      .when(Boolean(pill), (el) => el.child(pill))
      .when(st === "working", (el) =>
        el.child(
          svg("mods/workspace-chrome/spinner.svg")
            .size(12)
            .flex_none()
            .text_color(t.working)
            .spin(900)
        )
      )
      .when(st === "blocked", (el) =>
        el.child(
          div()
            .flex_none()
            .px(6)
            .h(18)
            .flex()
            .items_center()
            .rounded(5)
            .bg(t.blocked + "26")
            .text_size(10.5)
            .font_semibold()
            .text_color(t.blocked)
            .child("Needs you")
        )
      )
      .when(st === "done", (el) => el.child(div().size(7).flex_none().rounded(4).bg(t.done)))
      .when(this.hovered, (el) =>
        el
          .child(this.button(t, `ph-r-${pane}`, "split-right", "pane.split", { direction: "right", pane }))
          .child(this.button(t, `ph-d-${pane}`, "split-down", "pane.split", { direction: "down", pane }))
          .child(this.button(t, `ph-z-${pane}`, p.zoomed ? "unzoom" : "zoom", "pane.zoom", { pane }))
          .child(this.button(t, `ph-x-${pane}`, "close", "pane.close", { pane }))
      );
  }
}
