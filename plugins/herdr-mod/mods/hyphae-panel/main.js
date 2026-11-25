// Expandable Hyphae Thread Inspector for Herdr.
//
// Works cleanly in all 3 mount modes:
//   1. Right-side `panel-body` stack child (beside Files & Changes)
//   2. Floating persistent window overlay (`cmd-shift-h` or `hyphae-pane` pill click)
//   3. Split or tab mod pane (`pane.split { mod: "hyphae-panel" }`)
//
// Security invariant: strictly metadata-only (zero message bodies, zero CloudEvent
// payloads, zero wakeup notes, zero quarantined content; quarantine directs human
// to `hyp gate review` in terminal).

import { View, div, svg } from "gpui-kit";
import { v_flex, h_flex, InputState, Input, ScrollHandle } from "gpui-base";
import {
  focused,
  terminals,
  layout,
  props,
  run,
  theme,
  home,
  readTextFile,
  watchFolder,
  exec,
  closeOverlay,
  shared,
  setShared,
  checking,
  nextCommand,
} from "herdr";
import {
  createHyphaeClient,
  executeSessionControl,
  findLayoutNode,
  formatNextFire,
  formatRelativeAge,
  parseTerminalAddress,
  resolveSessionById,
  sanitizeUiText,
  withAlpha,
} from "./shared-client.js";

const TABS = [
  { id: "subs", label: "Subs" },
  { id: "queue", label: "Queue" },
  { id: "rules", label: "Rules" },
  { id: "mesh", label: "Mesh" },
];

const URGENCY_CYCLE = ["interrupt", "queue", "notify", "mute"];

function nextUrgency(current) {
  const idx = URGENCY_CYCLE.indexOf(String(current || "").toLowerCase());
  return URGENCY_CYCLE[(idx + 1) % URGENCY_CYCLE.length];
}

function urgencyColor(t, urgency) {
  switch (String(urgency || "").toLowerCase()) {
    case "interrupt":
      return t.ansi1 || t.blocked || t.accent;
    case "notify":
      return t.blocked || t.ansi3 || t.accent;
    case "mute":
      return t.dim || t.muted;
    case "queue":
    default:
      return t.accent || t.done || t.foreground;
  }
}

export default class HyphaePanel extends View {
  init(initialProps, cx) {
    this.tab = "subs";
    this.overrideTerminal = initialProps?.terminal ?? null;
    this.overrideSessionId = null;
    this.lastFocusedTerminal = checking() ? null : focused()?.terminal ?? null;
    this.lastSelectedAt = 0;
    this.busy = false;
    this.statusNote = null;
    this.statusError = null;
    this.typing = false;
    this.muteText = "";
    this.panelsRegistered = false;

    this.handle = cx.focus_handle();
    this.scroll = ScrollHandle.new();
    this.muteInput = InputState.new({ placeholder: "Mute #channel, peer/handle, or topic…" });
    this.muteInput.on("change", (_e, inputCx) => {
      const prev = Boolean(this.muteText.trim());
      this.muteText = this.muteInput.value();
      if (prev !== Boolean(this.muteText.trim())) inputCx.notify();
    });
    this.muteInput.on("submit", (_e, inputCx) => this.submitMute(inputCx));
    this.muteInput.on("focus", (_e, inputCx) => {
      this.typing = true;
      inputCx.notify();
    });
    this.muteInput.on("blur", (_e, inputCx) => {
      this.typing = false;
      inputCx.notify();
    });

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

    this.ensureDockPanelRegistered();
    this.client.ensureLocal(cx);

    const initialTarget = this.resolveTarget();
    if (initialTarget.machine) {
      this.client.ensureRemoteFresh(initialTarget.machine, cx, false);
    }

    cx.timer.every(10000, (timerCx) => {
      this.client.ensureLocal(timerCx);
      const target = this.resolveTarget();
      if (target.machine) {
        this.client.ensureRemoteFresh(target.machine, timerCx, false);
      }
    });

    cx.spawn(async (cmdCx) => {
      for (;;) {
        const cmd = await nextCommand();
        if (cmd === "focus") {
          this.handle.focus();
          cmdCx.notify();
        } else if (cmd === "refresh") {
          this.refresh(cmdCx);
        }
      }
    });
  }

  async close(_cx) {
    if (this.client) {
      this.client.dispose();
    }
  }

  /**
   * When mounted inside `panel-body`, ensure `"hyphae"` is in `shared("workspace.panels")`
   * so shipped `mods/tabs` preserves the panel across space switches.
   */
  ensureDockPanelRegistered() {
    if (checking() || this.panelsRegistered) return;
    if (props()?.overlay) return;
    const body = findLayoutNode(layout(), "panel-body");
    if (!body || !findLayoutNode(body, "hyphae")) return;
    const current = shared("workspace.panels");
    const list = Array.isArray(current) ? current : ["files", "changes"];
    if (!list.includes("hyphae")) {
      setShared("workspace.panels", [...list, "hyphae"]);
    }
    this.panelsRegistered = true;
  }

  syncExternalSelection() {
    const sel = shared("hyphae.selected");
    if (!sel || typeof sel !== "object") return;
    const at = Number(sel.at) || 0;
    if (at <= this.lastSelectedAt) return;
    this.lastSelectedAt = at;
    this.lastFocusedTerminal = focused()?.terminal ?? null;
    if (sel.terminal) {
      this.overrideTerminal = sel.terminal;
      this.overrideSessionId = sel.sessionId ?? null;
    } else if (sel.sessionId) {
      this.overrideTerminal = null;
      this.overrideSessionId = sel.sessionId;
    }
  }

  resolveTarget() {
    const f = focused();
    const activeTerminal = f?.terminal ?? null;
    if (activeTerminal && activeTerminal !== this.lastFocusedTerminal) {
      this.lastFocusedTerminal = activeTerminal;
      this.overrideTerminal = null;
      this.overrideSessionId = null;
    }
    const chosenTerminal = this.overrideTerminal ?? activeTerminal;

    if (chosenTerminal) {
      const resolved = this.client.resolveTerminal(chosenTerminal);
      if (resolved.entry) {
        return {
          terminal: resolved.address,
          machine: resolved.machine,
          rawTid: resolved.rawTid,
          sessionId: resolved.entry.sessionId,
          entry: resolved.entry,
          snapshot: resolved.snapshot,
        };
      }
      if (this.overrideSessionId && resolved.snapshot) {
        const byId = resolveSessionById(resolved.snapshot, this.overrideSessionId);
        if (byId) {
          return {
            terminal: resolved.address,
            machine: resolved.machine,
            rawTid: byId.herdrTerminalId ?? resolved.rawTid,
            sessionId: byId.sessionId,
            entry: byId,
            snapshot: resolved.snapshot,
          };
        }
      }
      return {
        terminal: resolved.address,
        machine: resolved.machine,
        rawTid: resolved.rawTid,
        sessionId: null,
        entry: null,
        snapshot: resolved.snapshot,
      };
    }

    const localSnap = this.client.getSnapshot(null);
    if (this.overrideSessionId) {
      const byId = resolveSessionById(localSnap, this.overrideSessionId);
      if (byId) {
        return {
          terminal: byId.herdrTerminalId ?? null,
          machine: null,
          rawTid: byId.herdrTerminalId ?? null,
          sessionId: byId.sessionId,
          entry: byId,
          snapshot: localSnap,
        };
      }
    }

    return {
      terminal: null,
      machine: null,
      rawTid: null,
      sessionId: null,
      entry: null,
      snapshot: localSnap,
    };
  }

  refresh(cx) {
    if (checking()) return;
    const target = this.resolveTarget();
    this.statusError = null;
    cx.spawn(async (spawnCx) => {
      await this.client.refreshNow(target.machine, spawnCx);
      spawnCx.notify();
    });
  }

  runAction(action, payload, noteOnOk, cx) {
    if (this.busy || checking()) return;
    const target = this.resolveTarget();
    if (!target.rawTid && !target.sessionId) {
      this.statusError = "No active Hyphae session selected.";
      cx.notify();
      return;
    }
    this.busy = true;
    this.statusError = null;
    this.statusNote = null;
    cx.notify();

    cx.spawn(async (spawnCx) => {
      try {
        const res = await executeSessionControl(
          { exec },
          action,
          {
            machine: target.machine,
            rawTid: target.rawTid,
            sessionId: target.sessionId,
            handle: target.entry?.handle ?? null,
          },
          payload
        );
        if (!res.ok) {
          this.statusError = res.error;
        } else {
          this.statusNote = noteOnOk;
          await this.client.refreshNow(target.machine, spawnCx);
        }
      } catch (err) {
        this.statusError = sanitizeUiText(String(err), 160);
      } finally {
        this.busy = false;
        spawnCx.notify();
      }
    });
  }

  submitMute(cx) {
    const pattern = this.muteText.trim();
    if (!pattern || this.busy) return;
    this.muteText = "";
    this.muteInput.set_value("");
    this.runAction("mute", { pattern, scope: "session" }, `Muted ${sanitizeUiText(pattern, 48)}`, cx);
  }

  closePanel() {
    const overlayId = props()?.overlay;
    if (overlayId) {
      closeOverlay(overlayId);
      return;
    }
    const panel = findLayoutNode(layout(), "panel");
    if (panel) {
      run("layout.hide", { id: "panel" });
    }
  }

  stop(e, cx) {
    cx.stop_propagation();
  }

  pillButton(t, id, label, active, color, onClick) {
    return h_flex()
      .id(id)
      .flex_none()
      .h(24)
      .px(8)
      .gap(5)
      .items_center()
      .rounded(6)
      .border_1()
      .border_color(active ? withAlpha(color, "66") : t.border)
      .bg(active ? withAlpha(color, "22") : t.raised || t.surface)
      .text_size(11)
      .font_medium()
      .text_color(active ? color : t.muted)
      .cursor_pointer()
      .hover((s) => s.bg(t.hover).text_color(t.foreground))
      .on_mouse_down("left", (_e, cx) => cx.stop_propagation())
      .on_click(onClick)
      .child(label);
  }

  renderHeader(t, target, cx) {
    const entry = target.entry;
    const isOverlay = Boolean(props()?.overlay);
    const hasDockPanel = Boolean(findLayoutNode(layout(), "panel-body") && findLayoutNode(layout(), "hyphae"));
    const canClose = isOverlay || hasDockPanel;

    const handleLabel = entry?.handle
      ? `@${sanitizeUiText(entry.handle, 28)}`
      : entry
        ? "Unenrolled"
        : target.snapshot?.daemon?.online
          ? "No session"
          : "Hyphae";

    const termBadge = target.terminal
      ? sanitizeUiText(target.terminal, 28)
      : entry?.harness
        ? sanitizeUiText(entry.harness, 16)
        : null;

    const transportLabel = entry?.transportKind ? sanitizeUiText(entry.transportKind, 18) : null;
    const sage = t.done || t.ansi2 || t.accent;

    return h_flex()
      .id("hyphae-panel-header")
      .h(40)
      .flex_none()
      .px(12)
      .gap(7)
      .items_center()
      .border_b(1)
      .border_color(t.border)
      .bg(t.chrome || t.surface || t.background)
      .child(
        svg("mods/hyphae-panel/hyphae.svg")
          .size(14)
          .flex_none()
          .text_color(entry?.enrolled ? sage : t.muted)
      )
      .child(
        div()
          .flex_1()
          .min_w(0)
          .truncate()
          .font_semibold()
          .text_size(12.5)
          .text_color(t.foreground)
          .child(handleLabel)
      )
      .when(Boolean(termBadge), (el) =>
        el.child(
          div()
            .flex_none()
            .px(5)
            .py(1)
            .rounded(4)
            .border_1()
            .border_color(t.border)
            .bg(t.background)
            .text_size(10)
            .text_color(t.muted)
            .child(termBadge)
        )
      )
      .when(Boolean(transportLabel), (el) =>
        el.child(
          div()
            .flex_none()
            .px(5)
            .py(1)
            .rounded(4)
            .bg(withAlpha(entry?.hasLiveTransport ? sage : t.dim, "22"))
            .text_size(10)
            .text_color(entry?.hasLiveTransport ? sage : t.dim)
            .child(transportLabel)
        )
      )
      .child(
        div()
          .id("hyphae-refresh")
          .flex_none()
          .px(5)
          .py(2)
          .rounded(4)
          .text_size(11)
          .text_color(t.dim)
          .cursor_pointer()
          .hover((s) => s.bg(t.hover).text_color(t.foreground))
          .on_mouse_down("left", (_e, mCx) => mCx.stop_propagation())
          .on_click((_e, clickCx) => this.refresh(clickCx))
          .child("↻")
      )
      .when(canClose, (el) =>
        el.child(
          div()
            .id("hyphae-close")
            .flex_none()
            .p(3)
            .rounded(4)
            .text_color(t.dim)
            .cursor_pointer()
            .hover((s) => s.bg(t.hover).text_color(t.foreground))
            .on_mouse_down("left", (_e, mCx) => mCx.stop_propagation())
            .on_click(() => this.closePanel())
            .child(svg("mods/pane/close.svg").size(12))
        )
      );
  }

  renderQuickControls(t, target) {
    const entry = target.entry;
    const alert = t.ansi1 || t.blocked || t.accent;
    const focusTint = t.accent || t.ansi4;
    const muteTint = t.blocked || t.ansi3 || t.muted;

    const quarantinedLocal = Number(entry?.counts?.quarantined) || 0;
    const quarantinedGlobal = Number(target.snapshot?.daemon?.quarantinedGlobal) || 0;
    const quarantinedTotal = Math.max(quarantinedLocal, quarantinedGlobal);

    return v_flex()
      .id("hyphae-controls")
      .flex_none()
      .px(10)
      .py(8)
      .gap(6)
      .border_b(1)
      .border_color(t.border)
      .when(Boolean(entry), (el) =>
        el.child(
          h_flex()
            .gap(6)
            .items_center()
            .child(
              this.pillButton(
                t,
                "hyphae-btn-focus",
                entry.focusMode ? "Focus ON" : "Focus OFF",
                Boolean(entry.focusMode),
                focusTint,
                (_e, clickCx) =>
                  this.runAction(
                    "focus",
                    { enabled: !entry.focusMode },
                    entry.focusMode ? "Focus Mode disabled" : "Focus Mode enabled",
                    clickCx
                  )
              )
            )
            .child(
              this.pillButton(
                t,
                "hyphae-btn-mute-all",
                entry.mutedAll ? "Muted (*)" : "Mute All",
                Boolean(entry.mutedAll),
                muteTint,
                (_e, clickCx) =>
                  this.runAction(
                    entry.mutedAll ? "unmute" : "mute",
                    { pattern: "*", scope: "session" },
                    entry.mutedAll ? "Unmuted all sources" : "Muted all sources (*)",
                    clickCx
                  )
              )
            )
            .child(div().flex_1())
            .when(this.busy, (b) =>
              b.child(div().text_size(10.5).text_color(t.dim).child("Applying…"))
            )
        )
      )
      .when(quarantinedTotal > 0, (el) =>
        el.child(
          h_flex()
            .id("hyphae-quarantine-banner")
            .px(8)
            .py(6)
            .gap(6)
            .rounded(6)
            .border_1()
            .border_color(withAlpha(alert, "66"))
            .bg(withAlpha(alert, "1e"))
            .items_center()
            .child(div().flex_none().font_semibold().text_size(11).text_color(alert).child(`⚠ ${quarantinedTotal} quarantined`))
            .child(
              div()
                .flex_1()
                .min_w(0)
                .truncate()
                .text_size(10.5)
                .text_color(t.foreground)
                .child("Run hyp gate review in terminal")
            )
        )
      )
      .when(Boolean(this.statusError), (el) =>
        el.child(
          h_flex()
            .id("hyphae-status-err")
            .px(8)
            .py(4)
            .gap(6)
            .rounded(5)
            .bg(withAlpha(alert, "1c"))
            .items_center()
            .child(div().flex_1().min_w(0).truncate().text_size(10.5).text_color(alert).child(this.statusError))
            .child(
              div()
                .id("hyphae-err-dismiss")
                .flex_none()
                .text_size(10)
                .text_color(t.dim)
                .cursor_pointer()
                .on_mouse_down("left", (_e, mCx) => mCx.stop_propagation())
                .on_click((_e, clickCx) => {
                  this.statusError = null;
                  clickCx.notify();
                })
                .child("×")
            )
        )
      )
      .when(!this.statusError && Boolean(this.statusNote), (el) =>
        el.child(
          h_flex()
            .id("hyphae-status-note")
            .px(8)
            .py(4)
            .gap(6)
            .rounded(5)
            .bg(withAlpha(t.done || t.ansi2, "18"))
            .items_center()
            .child(div().flex_1().min_w(0).truncate().text_size(10.5).text_color(t.done || t.ansi2).child(this.statusNote))
            .child(
              div()
                .id("hyphae-note-dismiss")
                .flex_none()
                .text_size(10)
                .text_color(t.dim)
                .cursor_pointer()
                .on_mouse_down("left", (_e, mCx) => mCx.stop_propagation())
                .on_click((_e, clickCx) => {
                  this.statusNote = null;
                  clickCx.notify();
                })
                .child("×")
            )
        )
      );
  }

  renderTabBar(t, entry) {
    const counts = entry?.counts ?? {};
    const rulesCount = (entry?.details?.mutes?.length ?? counts.mutedRules ?? 0) + (entry?.details?.rules?.length ?? 0);
    const badgeFor = (id) => {
      if (!entry) return null;
      if (id === "subs") {
        const subCount = Number(counts.subscriptions) || 0;
        const bridgeCount =
          Number(counts.bridges) ||
          (Array.isArray(entry?.details?.bridges) ? entry.details.bridges.length : 0);
        return subCount + bridgeCount;
      }
      if (id === "queue") return Number(counts.queued) || 0;
      if (id === "rules") return rulesCount;
      return null;
    };

    return h_flex()
      .id("hyphae-tabs")
      .flex_none()
      .h(34)
      .px(8)
      .gap(4)
      .items_center()
      .border_b(1)
      .border_color(t.border)
      .children(
        TABS.map((tab) => {
          const active = this.tab === tab.id;
          const count = badgeFor(tab.id);
          const text = count !== null ? `${tab.label} (${count})` : tab.label;
          return h_flex()
            .id(`hyphae-tab-${tab.id}`)
            .flex_1()
            .h(24)
            .px(6)
            .items_center()
            .justify_center()
            .rounded(6)
            .bg(active ? t.selected : t.background)
            .text_size(11)
            .font_medium()
            .text_color(active ? t.foreground : t.muted)
            .cursor_pointer()
            .hover((s) => s.bg(t.hover).text_color(t.foreground))
            .on_mouse_down("left", (_e, mCx) => mCx.stop_propagation())
            .on_click((_e, clickCx) => {
              this.tab = tab.id;
              clickCx.notify();
            })
            .child(div().truncate().child(text));
        })
      );
  }

  renderSubsTab(t, entry) {
    const bridges = Array.isArray(entry?.details?.bridges) ? entry.details.bridges : [];
    const subs = Array.isArray(entry?.details?.subscriptions) ? entry.details.subscriptions : [];
    if (bridges.length === 0 && subs.length === 0) {
      return [
        div()
          .p(12)
          .text_size(11.5)
          .text_color(t.dim)
          .child("No linked bridges or stream subscriptions for this session."),
      ];
    }

    const cards = bridges.map((bridge, idx) => {
      const label = sanitizeUiText(
        bridge.label || `${bridge.plugin || "bridge"}:${bridge.target || "*"}`,
        64
      );
      const role = bridge.role === "primary" ? "primary" : "reader";
      return v_flex()
        .id(`hyphae-bridge-${idx}`)
        .flex_none()
        .p(8)
        .pr(10)
        .gap(4)
        .rounded(7)
        .border_1()
        .border_color(t.border)
        .bg(t.surface || t.raised || t.background)
        .child(
          h_flex()
            .gap(6)
            .items_center()
            .child(
              div()
                .flex_1()
                .min_w(0)
                .truncate()
                .font_medium()
                .text_size(12)
                .text_color(t.foreground)
                .child(label)
            )
            .child(
              div()
                .flex_none()
                .px(6)
                .py(1)
                .rounded(4)
                .bg(t.background)
                .text_size(10)
                .font_medium()
                .text_color(role === "primary" ? t.success || t.accent : t.muted)
                .child(role)
            )
        )
        .child(
          div()
            .text_size(10.5)
            .text_color(t.dim)
            .child("External chat bridge · inbound wakeups & replies")
        );
    });

    const subCards = subs.map((sub, idx) => {
      const topic = sanitizeUiText(sub.topic || "(topic)", 64);
      const origin = sanitizeUiText(sub.originNode || "local", 40);
      const mode = sanitizeUiText(sub.mode || "queue", 16);
      const keyName = sub.key ? sanitizeUiText(sub.key, 32) : null;
      const filterSummary = sanitizeUiText(sub.filterSummary || "", 90);
      const coalesce = Number(sub.coalesceSeconds) || 0;
      const uColor = urgencyColor(t, mode);

      return v_flex()
        .id(`hyphae-sub-${sub.id || idx}`)
        .flex_none()
        .p(8)
        .pr(10)
        .gap(4)
        .rounded(7)
        .border_1()
        .border_color(t.border)
        .bg(t.surface || t.raised || t.background)
        .child(
          h_flex()
            .gap(6)
            .items_center()
            .child(
              div()
                .flex_1()
                .min_w(0)
                .truncate()
                .font_medium()
                .text_size(12)
                .text_color(t.foreground)
                .child(topic)
            )
            .child(
              div()
                .flex_none()
                .px(5)
                .py(1)
                .rounded(4)
                .bg(withAlpha(uColor, "22"))
                .text_size(10)
                .font_medium()
                .text_color(uColor)
                .child(mode)
            )
            .child(
              div()
                .id(`hyphae-unsub-${sub.id || idx}`)
                .flex_none()
                .px(5)
                .py(1)
                .rounded(4)
                .text_size(11)
                .text_color(t.dim)
                .cursor_pointer()
                .hover((s) => s.bg(withAlpha(t.ansi1 || t.blocked, "24")).text_color(t.ansi1 || t.blocked))
                .on_mouse_down("left", (_e, mCx) => mCx.stop_propagation())
                .on_click((_e, clickCx) =>
                  this.runAction(
                    "unsubscribe",
                    { id: sub.id, key: sub.key },
                    `Unsubscribed ${topic}`,
                    clickCx
                  )
                )
                .child("×")
            )
        )
        .child(
          h_flex()
            .gap(8)
            .items_center()
            .text_size(10.5)
            .text_color(t.dim)
            .child(div().flex_1().min_w(0).truncate().child(keyName ? `${origin} · ${keyName}` : origin))
            .when(coalesce > 0, (el) => el.child(div().flex_none().child(`${coalesce}s coalesce`)))
        )
        .when(Boolean(filterSummary), (el) =>
          el.child(
            div()
              .w_full()
              .min_w(0)
              .truncate()
              .px(6)
              .py(2)
              .rounded(4)
              .bg(t.background)
              .text_size(10)
              .text_color(t.muted)
              .child(filterSummary)
          )
        );
    });

    return [...cards, ...subCards];
  }

  renderQueueTab(t, entry) {
    const breakdown = entry?.unreadBreakdown ?? {};
    const items = Array.isArray(entry?.details?.queuedItems) ? entry.details.queuedItems : [];
    const nowMs = Date.now();

    const kindChips = [
      ["DMs", Number(breakdown.messages) || 0],
      ["Events", Number(breakdown.events) || 0],
      ["Plugins", Number(breakdown.plugins) || 0],
      ["Transfers", Number(breakdown.transfers) || 0],
      ["KV", Number(breakdown.kv) || 0],
    ].filter(([, count]) => count > 0);

    const rows = [];

    if (kindChips.length > 0) {
      rows.push(
        h_flex()
          .id("hyphae-queue-breakdown")
          .flex_none()
          .pr(10)
          .gap(5)
          .flex_wrap()
          .children(
            kindChips.map(([label, count]) =>
              div()
                .flex_none()
                .px(6)
                .py(2)
                .rounded(5)
                .border_1()
                .border_color(t.border)
                .bg(t.raised || t.surface)
                .text_size(10)
                .text_color(t.muted)
                .child(`${label}: ${count}`)
            )
          )
      );
    }

    if (items.length === 0) {
      rows.push(
        div()
          .p(12)
          .text_size(11.5)
          .text_color(t.dim)
          .child("Inbox queue is empty. Metadata-only view (message bodies stay inside the agent thread).")
      );
      return rows;
    }

    for (let i = 0; i < items.length; i++) {
      const item = items[i];
      const source = sanitizeUiText(item.source || "(unknown)", 64);
      const kind = sanitizeUiText(item.kind || "item", 16);
      const urgency = sanitizeUiText(item.urgency || "queue", 16);
      const age = formatRelativeAge(Number(item.receivedAt), nowMs);
      const uColor = urgencyColor(t, urgency);
      const unnotified = item.notified === false;

      rows.push(
        h_flex()
          .id(`hyphae-q-${item.receipt || i}`)
          .flex_none()
          .p(8)
          .pr(10)
          .gap(7)
          .items_center()
          .rounded(7)
          .border_1()
          .border_color(t.border)
          .bg(t.surface || t.raised || t.background)
          .child(
            div()
              .size(6)
              .flex_none()
              .rounded(3)
              .bg(unnotified ? t.blocked || t.ansi3 : t.dim)
          )
          .child(
            v_flex()
              .flex_1()
              .min_w(0)
              .gap(2)
              .child(
                div()
                  .flex_1()
                  .min_w(0)
                  .truncate()
                  .font_medium()
                  .text_size(11.5)
                  .text_color(t.foreground)
                  .child(source)
              )
              .child(
                h_flex()
                  .gap(6)
                  .items_center()
                  .text_size(10)
                  .text_color(t.dim)
                  .child(div().flex_none().child(kind))
                  .child(div().flex_none().text_color(uColor).child(urgency))
                  .when(Boolean(age), (el) => el.child(div().flex_none().child(age)))
              )
          )
          .child(
            div()
              .id(`hyphae-q-mute-${item.receipt || i}`)
              .flex_none()
              .px(6)
              .py(2)
              .rounded(4)
              .border_1()
              .border_color(t.border)
              .text_size(10)
              .text_color(t.muted)
              .cursor_pointer()
              .hover((s) => s.bg(t.hover).text_color(t.foreground))
              .on_mouse_down("left", (_e, mCx) => mCx.stop_propagation())
              .on_click((_e, clickCx) =>
                this.runAction(
                  "mute",
                  { pattern: source, scope: "session" },
                  `Muted ${source}`,
                  clickCx
                )
              )
              .child("Mute")
          )
      );
    }

    return rows;
  }

  renderRulesTab(t, entry) {
    const mutes = Array.isArray(entry?.details?.mutes) ? entry.details.mutes : [];
    const rules = Array.isArray(entry?.details?.rules) ? entry.details.rules : [];
    const rows = [];

    rows.push(
      v_flex()
        .id("hyphae-policy-summary")
        .flex_none()
        .p(8)
        .pr(10)
        .gap(3)
        .rounded(7)
        .border_1()
        .border_color(t.border)
        .bg(t.surface || t.background)
        .child(
          h_flex()
            .gap(6)
            .items_center()
            .child(div().flex_1().min_w(0).truncate().text_size(11).text_color(t.muted).child("Default delivery"))
            .child(
              div()
                .flex_none()
                .text_size(11)
                .font_medium()
                .text_color(t.foreground)
                .child(sanitizeUiText(entry?.deliveryMode || "queue", 20))
            )
        )
        .child(
          h_flex()
            .gap(6)
            .items_center()
            .child(div().flex_1().min_w(0).truncate().text_size(11).text_color(t.muted).child("Focus VIP interrupts"))
            .child(
              div()
                .flex_none()
                .text_size(11)
                .text_color(t.foreground)
                .child(entry?.focusAllowInterruptVips ? "allowed" : "paused")
            )
        )
    );

    rows.push(
      div()
        .flex_none()
        .pt(4)
        .pr(10)
        .text_size(10.5)
        .font_semibold()
        .text_color(t.dim)
        .child(`Active Mutes (${mutes.length})`)
    );

    if (mutes.length === 0) {
      rows.push(
        div()
          .flex_none()
          .px(4)
          .py(4)
          .text_size(11)
          .text_color(t.dim)
          .child("No active mute patterns.")
      );
    } else {
      for (let i = 0; i < mutes.length; i++) {
        const m = mutes[i];
        const pattern = sanitizeUiText(m.pattern || "", 64);
        const scope = m.scope === "connector" ? "connector" : "session";
        rows.push(
          h_flex()
            .id(`hyphae-mute-${i}-${pattern}`)
            .flex_none()
            .p(7)
            .pr(10)
            .gap(6)
            .items_center()
            .rounded(6)
            .border_1()
            .border_color(t.border)
            .bg(t.surface || t.background)
            .child(
              div()
                .flex_1()
                .min_w(0)
                .truncate()
                .text_size(11.5)
                .text_color(t.foreground)
                .child(pattern)
            )
            .child(
              div()
                .flex_none()
                .px(5)
                .py(1)
                .rounded(4)
                .bg(t.raised || t.background)
                .text_size(9.5)
                .text_color(t.dim)
                .child(scope)
            )
            .child(
              div()
                .id(`hyphae-unmute-${i}-${pattern}`)
                .flex_none()
                .px(6)
                .py(2)
                .rounded(4)
                .border_1()
                .border_color(t.border)
                .text_size(10)
                .text_color(t.muted)
                .cursor_pointer()
                .hover((s) => s.bg(t.hover).text_color(t.foreground))
                .on_mouse_down("left", (_e, mCx) => mCx.stop_propagation())
                .on_click((_e, clickCx) =>
                  this.runAction(
                    "unmute",
                    { pattern, scope },
                    `Unmuted ${pattern}`,
                    clickCx
                  )
                )
                .child("Unmute")
            )
        );
      }
    }

    rows.push(
      div()
        .flex_none()
        .pt(6)
        .pr(10)
        .text_size(10.5)
        .font_semibold()
        .text_color(t.dim)
        .child(`Delivery Rules (${rules.length})`)
    );

    if (rules.length === 0) {
      rows.push(
        div()
          .flex_none()
          .px(4)
          .py(4)
          .text_size(11)
          .text_color(t.dim)
          .child("No per-source urgency overrides.")
      );
    } else {
      for (let i = 0; i < rules.length; i++) {
        const r = rules[i];
        const ruleTarget = sanitizeUiText(r.target || "", 64);
        const delivery = sanitizeUiText(r.delivery || "queue", 16);
        const next = nextUrgency(delivery);
        const uColor = urgencyColor(t, delivery);
        rows.push(
          h_flex()
            .id(`hyphae-rule-${i}-${ruleTarget}`)
            .flex_none()
            .p(7)
            .pr(10)
            .gap(6)
            .items_center()
            .rounded(6)
            .border_1()
            .border_color(t.border)
            .bg(t.surface || t.background)
            .child(
              div()
                .flex_1()
                .min_w(0)
                .truncate()
                .text_size(11.5)
                .text_color(t.foreground)
                .child(ruleTarget)
            )
            .child(
              div()
                .id(`hyphae-rule-cycle-${i}-${ruleTarget}`)
                .flex_none()
                .px(6)
                .py(2)
                .rounded(4)
                .border_1()
                .border_color(withAlpha(uColor, "66"))
                .bg(withAlpha(uColor, "20"))
                .text_size(10)
                .font_medium()
                .text_color(uColor)
                .cursor_pointer()
                .hover((s) => s.bg(t.hover))
                .on_mouse_down("left", (_e, mCx) => mCx.stop_propagation())
                .on_click((_e, clickCx) =>
                  this.runAction(
                    "rule",
                    { target: ruleTarget, delivery: next },
                    `Rule ${ruleTarget} -> ${next}`,
                    clickCx
                  )
                )
                .child(`${delivery} ↻`)
            )
        );
      }
    }

    return rows;
  }

  renderMeshTab(t, target) {
    const entry = target.entry;
    const daemon = target.snapshot?.daemon;
    const nowMs = Date.now();
    const rows = [];

    const sage = t.done || t.ansi2 || t.accent;
    rows.push(
      v_flex()
        .id("hyphae-node-card")
        .flex_none()
        .p(8)
        .pr(10)
        .gap(4)
        .rounded(7)
        .border_1()
        .border_color(t.border)
        .bg(t.surface || t.background)
        .child(
          h_flex()
            .gap(6)
            .items_center()
            .child(div().size(7).flex_none().rounded(4).bg(daemon?.online ? sage : t.dim))
            .child(
              div()
                .flex_1()
                .min_w(0)
                .truncate()
                .font_medium()
                .text_size(11.5)
                .text_color(t.foreground)
                .child(sanitizeUiText(daemon?.nodeId || "Local node offline", 48))
            )
            .when(Boolean(daemon?.version), (el) =>
              el.child(div().flex_none().text_size(10).text_color(t.dim).child(`v${sanitizeUiText(daemon.version, 16)}`))
            )
        )
        .child(
          h_flex()
            .gap(10)
            .text_size(10.5)
            .text_color(t.muted)
            .child(div().flex_none().child(`Profile: ${sanitizeUiText(daemon?.profile || "—", 16)}`))
            .child(div().flex_none().child(`Peers: ${Number(daemon?.peersOnline) || 0}`))
        )
    );

    const channelEntries = Array.isArray(entry?.details?.channelEntries)
      ? entry.details.channelEntries
      : Array.isArray(entry?.details?.channels)
        ? entry.details.channels.map((ch) => ({ channel: ch, hostNode: "local", mode: "open" }))
        : [];

    rows.push(
      div()
        .flex_none()
        .pt(6)
        .pr(10)
        .text_size(10.5)
        .font_semibold()
        .text_color(t.dim)
        .child(`Channels (${channelEntries.length})`)
    );

    if (channelEntries.length === 0) {
      rows.push(
        div()
          .flex_none()
          .px(4)
          .py(4)
          .text_size(11)
          .text_color(t.dim)
          .child("Not joined to any #channels.")
      );
    } else {
      for (let i = 0; i < channelEntries.length; i++) {
        const ch = channelEntries[i];
        const chName = sanitizeUiText(ch.channel || "", 48);
        const mode = sanitizeUiText(ch.mode || "open", 16);
        rows.push(
          h_flex()
            .id(`hyphae-ch-${i}-${chName}`)
            .flex_none()
            .p(7)
            .pr(10)
            .gap(6)
            .items_center()
            .rounded(6)
            .border_1()
            .border_color(t.border)
            .bg(t.surface || t.background)
            .child(
              div()
                .flex_1()
                .min_w(0)
                .truncate()
                .font_medium()
                .text_size(11.5)
                .text_color(t.foreground)
                .child(chName)
            )
            .child(
              div()
                .flex_none()
                .px(5)
                .py(1)
                .rounded(4)
                .bg(t.raised || t.background)
                .text_size(9.5)
                .text_color(t.dim)
                .child(mode)
            )
            .child(
              div()
                .id(`hyphae-leave-${i}-${chName}`)
                .flex_none()
                .px(6)
                .py(2)
                .rounded(4)
                .border_1()
                .border_color(t.border)
                .text_size(10)
                .text_color(t.muted)
                .cursor_pointer()
                .hover((s) => s.bg(withAlpha(t.ansi1 || t.blocked, "22")).text_color(t.ansi1 || t.blocked))
                .on_mouse_down("left", (_e, mCx) => mCx.stop_propagation())
                .on_click((_e, clickCx) =>
                  this.runAction("leave", { channel: chName }, `Left ${chName}`, clickCx)
                )
                .child("Leave")
            )
        );
      }
    }

    const wakeups = Array.isArray(entry?.details?.wakeups) ? entry.details.wakeups : [];
    rows.push(
      div()
        .flex_none()
        .pt(6)
        .pr(10)
        .text_size(10.5)
        .font_semibold()
        .text_color(t.dim)
        .child(`Active Wakeups (${wakeups.length})`)
    );

    if (wakeups.length === 0) {
      rows.push(
        div()
          .flex_none()
          .px(4)
          .py(4)
          .text_size(11)
          .text_color(t.dim)
          .child("No active scheduled wakeups.")
      );
    } else {
      for (let i = 0; i < wakeups.length; i++) {
        const w = wakeups[i];
        const label = sanitizeUiText(w.label || w.id || "wakeup", 48);
        const trigger = sanitizeUiText(w.triggerKind || "timer", 16);
        const nextDue = formatNextFire(Number(w.nextFireAt), nowMs);
        const uColor = urgencyColor(t, w.urgency);
        rows.push(
          h_flex()
            .id(`hyphae-wk-${w.id || i}`)
            .flex_none()
            .p(7)
            .pr(10)
            .gap(6)
            .items_center()
            .rounded(6)
            .border_1()
            .border_color(t.border)
            .bg(t.surface || t.background)
            .child(
              v_flex()
                .flex_1()
                .min_w(0)
                .gap(2)
                .child(div().flex_1().min_w(0).truncate().text_size(11.5).text_color(t.foreground).child(label))
                .child(div().text_size(10).text_color(t.dim).child(`${trigger} · ${nextDue}`))
            )
            .child(
              div()
                .flex_none()
                .px(5)
                .py(1)
                .rounded(4)
                .bg(withAlpha(uColor, "20"))
                .text_size(10)
                .text_color(uColor)
                .child(sanitizeUiText(w.urgency || "queue", 14))
            )
        );
      }
    }

    return rows;
  }

  renderEmptyState(t, target) {
    const remoteStatus = target.machine ? this.client.getRemoteStatus(target.machine) : null;
    const msg = remoteStatus?.error
      ? `Remote ${sanitizeUiText(target.machine, 24)}: ${remoteStatus.error}`
      : !target.snapshot
        ? "Waiting for local Hyphae daemon (`hyp node start`)…"
        : target.terminal
          ? `Terminal ${sanitizeUiText(target.terminal, 28)} is not enrolled in Hyphae.`
          : "Focus a Herdr terminal running an agent to inspect its Hyphae thread.";

    return [
      v_flex()
        .id("hyphae-empty")
        .flex_none()
        .p(14)
        .pr(16)
        .gap(6)
        .child(div().text_size(12).text_color(t.muted).child(msg))
        .child(
          div()
            .text_size(11)
            .text_color(t.dim)
            .child("Enrolled agents appear automatically with zero polling once joined.")
        ),
    ];
  }

  render(cx) {
    if (!checking()) {
      this.ensureDockPanelRegistered();
      this.syncExternalSelection();
    }

    const t = theme();
    const target = this.resolveTarget();
    if (!checking() && target.machine) {
      this.client.ensureRemoteFresh(target.machine, cx, false);
    }

    const entry = target.entry;
    const showMuteInput = Boolean(entry) && this.tab === "rules";
    const canSubmitMute = Boolean(this.muteText.trim()) && !this.busy;

    let bodyRows;
    if (!entry && this.tab !== "mesh") {
      bodyRows = this.renderEmptyState(t, target);
    } else if (this.tab === "subs") {
      bodyRows = this.renderSubsTab(t, entry);
    } else if (this.tab === "queue") {
      bodyRows = this.renderQueueTab(t, entry);
    } else if (this.tab === "rules") {
      bodyRows = this.renderRulesTab(t, entry);
    } else {
      bodyRows = this.renderMeshTab(t, target);
    }

    return v_flex()
      .id("hyphae-panel")
      .size_full()
      .min_h(0)
      .rounded(10)
      .overflow_hidden()
      .bg(t.background)
      .border_1()
      .border_color(t.border)
      .text_color(t.foreground)
      .text_size(12)
      .track_focus(this.handle)
      .on_key_down((e, keyCx) => {
        if (e.key === "escape") {
          if (this.typing) {
            this.typing = false;
            this.handle.focus();
            keyCx.stop_propagation();
            keyCx.notify();
            return;
          }
          if (props()?.overlay) {
            closeOverlay(props().overlay);
            keyCx.stop_propagation();
          }
          return;
        }
        if (this.typing) return;
        if (e.key === "1") { this.tab = "subs"; keyCx.notify(); }
        else if (e.key === "2") { this.tab = "queue"; keyCx.notify(); }
        else if (e.key === "3") { this.tab = "rules"; keyCx.notify(); }
        else if (e.key === "4") { this.tab = "mesh"; keyCx.notify(); }
        else if (e.key === "r") { this.refresh(keyCx); }
      })
      .child(this.renderHeader(t, target, cx))
      .child(this.renderQuickControls(t, target))
      .child(this.renderTabBar(t, entry))
      .child(
        v_flex()
          .id("hyphae-scroll-body")
          .flex_1()
          .min_h(0)
          .overflow_y_scrollbar()
          .mode("always")
          .track_scroll(this.scroll)
          .p(8)
          .gap(6)
          .children(bodyRows)
      )
      .when(showMuteInput, (el) =>
        el.child(
          h_flex()
            .id("hyphae-mute-footer")
            .flex_none()
            .p(8)
            .gap(6)
            .border_t(1)
            .border_color(t.border)
            .child(
              div()
                .id("hyphae-mute-input-box")
                .flex_1()
                .min_w(0)
                .h(30)
                .px(8)
                .flex()
                .items_center()
                .rounded(7)
                .border_1()
                .border_color(this.typing ? t.accent : t.border)
                .cursor_text()
                .on_mouse_down("left", (_e, mCx) => mCx.stop_propagation())
                .child(Input.new(this.muteInput).h_full().text_size(11.5).text_color(t.foreground))
            )
            .child(
              div()
                .id("hyphae-mute-submit")
                .flex_none()
                .h(30)
                .px(10)
                .flex()
                .items_center()
                .rounded(7)
                .bg(canSubmitMute ? t.solid : t.raised)
                .text_color(canSubmitMute ? t.solid_foreground : t.dim)
                .text_size(11.5)
                .font_medium()
                .when(canSubmitMute, (b) => b.cursor_pointer())
                .on_mouse_down("left", (_e, mCx) => mCx.stop_propagation())
                .on_click((_e, clickCx) => this.submitMute(clickCx))
                .child("Mute")
            )
        )
      );
  }
}
