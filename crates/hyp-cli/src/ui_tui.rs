//! Pure-Rust Zero-Dependency Interactive TUI (`hyp ui`).
//!
//! Follows the exact zero-dep terminal pattern established in `wizard.rs`:
//! - Unix `/dev/tty` raw mode (`stty -g` -> `stty raw -echo min 0 time 1` -> unconditional restore
//!   via RAII `Drop` guard)
//! - Alternate screen (`\x1b[?1049h` / `\x1b[?1049l`) + synchronized redraw (`\x1b[?2026h`/`l`)
//! - Live zero-polling updates pushed over a background `inspect.watch` NDJSON stream
//! - Instant quick-control actions (`f` focus, `m` mute, `u`/`x` unsubscribe/unmute/leave,
//!   `s` switch session, `r` refresh, `1`–`4` / `Tab` / `←` / `→` tabs, `↑`/`↓`/`j`/`k` nav)
//! - Clean non-TTY / Windows interactive fallback printing `hyp inspect` output without hanging
//! - Pure deterministic frame renderer (`render_ui_frame`) verified across `24×80` and `18×40`
//!   viewports with strict column/row bounds and zero untrusted body leakage.

#![cfg_attr(not(unix), allow(dead_code))]

use crate::inspect_cmd::{InspectArgs, format_age_ms, run_inspect};
use crate::statusline_cmd::sanitize_terminal_text;
#[cfg(unix)]
use crate::ui::EXIT_OK;
use crate::wizard::ColorMode;
#[cfg(unix)]
use crate::wizard::{detect_color_mode, detect_terminal_size};
use clap::Args;
#[cfg(unix)]
use hyp_harness::sock::{
    MAX_SOCKET_LINE_BYTES, connect_daemon_async, daemon_rpc_sync, default_socket_path,
    read_bounded_line_async, write_ndjson_line_async,
};
#[cfg(unix)]
use hyp_harness::wait::{infer_herdr_terminal_from_env, infer_session_id_from_env};
use serde_json::Value;
#[cfg(any(unix, test))]
use serde_json::json;
#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::io::{self, IsTerminal, Read, Write};
#[cfg(not(unix))]
use std::io::{self, IsTerminal};
#[cfg(unix)]
use std::path::Path;
use std::path::PathBuf;
#[cfg(unix)]
use std::process::{Command, Stdio};
use std::process::ExitCode;
#[cfg(unix)]
use std::sync::Arc;
#[cfg(unix)]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(unix)]
use std::sync::mpsc;
#[cfg(unix)]
use std::thread;
#[cfg(unix)]
use std::time::Duration;

#[cfg(unix)]
const ACTION_RPC_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Args)]
pub struct UiArgs {
    /// Initial session ID to select
    #[arg(long)]
    pub session: Option<String>,
    /// Initial Herdr terminal ID to select
    #[arg(long)]
    pub herdr_terminal: Option<String>,
    /// Initial enrolled handle to select
    #[arg(long)]
    pub handle: Option<String>,
    /// Explicit connector.sock / connector.addr path
    #[arg(long)]
    pub socket: Option<PathBuf>,
    /// Render in main terminal buffer instead of entering alternate screen
    #[arg(long)]
    pub no_alt_screen: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UiTab {
    Subscriptions,
    Queue,
    RulesAndMutes,
    MeshAndChannels,
}

impl UiTab {
    pub const ALL: [Self; 4] = [
        Self::Subscriptions,
        Self::Queue,
        Self::RulesAndMutes,
        Self::MeshAndChannels,
    ];

    pub const fn title(self) -> &'static str {
        match self {
            Self::Subscriptions => "Subscriptions",
            Self::Queue => "Queue",
            Self::RulesAndMutes => "Rules & Mutes",
            Self::MeshAndChannels => "Mesh & Channels",
        }
    }

    pub const fn short_title(self) -> &'static str {
        match self {
            Self::Subscriptions => "Subs",
            Self::Queue => "Queue",
            Self::RulesAndMutes => "Rules",
            Self::MeshAndChannels => "Mesh",
        }
    }

    pub const fn number(self) -> usize {
        match self {
            Self::Subscriptions => 1,
            Self::Queue => 2,
            Self::RulesAndMutes => 3,
            Self::MeshAndChannels => 4,
        }
    }

    pub const fn next(self) -> Self {
        match self {
            Self::Subscriptions => Self::Queue,
            Self::Queue => Self::RulesAndMutes,
            Self::RulesAndMutes => Self::MeshAndChannels,
            Self::MeshAndChannels => Self::Subscriptions,
        }
    }

    pub const fn prev(self) -> Self {
        match self {
            Self::Subscriptions => Self::MeshAndChannels,
            Self::Queue => Self::Subscriptions,
            Self::RulesAndMutes => Self::Queue,
            Self::MeshAndChannels => Self::RulesAndMutes,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct DaemonView {
    pub online: bool,
    pub node_id: String,
    pub profile: String,
    pub peers_online: u64,
    pub quarantined_global: u64,
}

#[derive(Debug, Clone, Default)]
pub struct SubRow {
    pub id: String,
    pub origin_node: String,
    pub topic: String,
    pub mode: String,
    pub coalesce_seconds: i64,
    pub filter_summary: String,
}

#[derive(Debug, Clone, Default)]
pub struct QueuedRow {
    pub kind: String,
    pub source: String,
    pub received_at: i64,
    pub notified: bool,
    pub urgency: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleOrMuteRow {
    Mute {
        pattern: String,
        scope: String,
        muted_at: i64,
    },
    Rule {
        target: String,
        delivery: String,
    },
}

#[derive(Debug, Clone, Default)]
pub struct ChannelRow {
    pub channel: String,
    pub host_node: String,
    pub mode: String,
}

#[derive(Debug, Clone, Default)]
pub struct WakeupRow {
    pub label: String,
    pub trigger_kind: String,
    pub urgency: String,
    pub state: String,
}

#[derive(Debug, Clone, Default)]
pub struct SessionView {
    pub session_id: String,
    pub harness: String,
    pub enrolled: bool,
    pub handle: Option<String>,
    pub herdr_terminal_id: Option<String>,
    pub transport_kind: Option<String>,
    pub has_live_transport: bool,
    pub delivery_mode: String,
    pub focus_mode: bool,
    pub muted_all: bool,
    pub count_subs: u64,
    pub count_queued: u64,
    pub count_quarantined: u64,
    pub count_muted_rules: u64,
    pub count_muted_archived: u64,
    pub count_wakeups: u64,
    pub subscriptions: Vec<SubRow>,
    pub queued_items: Vec<QueuedRow>,
    pub rules_and_mutes: Vec<RuleOrMuteRow>,
    pub channels: Vec<ChannelRow>,
    pub wakeups: Vec<WakeupRow>,
}

#[derive(Debug, Clone)]
pub struct UiState {
    pub daemon: DaemonView,
    pub sessions: Vec<SessionView>,
    pub active_session_idx: usize,
    pub active_tab: UiTab,
    pub selected_row: usize,
    pub scroll_offset: usize,
    pub rev: u64,
    pub updated_at: i64,
    pub status_message: Option<(String, bool)>,
    pub color_mode: ColorMode,
}

impl Default for UiState {
    fn default() -> Self {
        Self {
            daemon: DaemonView::default(),
            sessions: Vec::new(),
            active_session_idx: 0,
            active_tab: UiTab::Subscriptions,
            selected_row: 0,
            scroll_offset: 0,
            rev: 0,
            updated_at: 0,
            status_message: None,
            color_mode: ColorMode::Plain,
        }
    }
}

fn clean_opt_str(v: Option<&Value>) -> Option<String> {
    v.and_then(Value::as_str)
        .map(sanitize_terminal_text)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn clean_str_or(v: Option<&Value>, fallback: &str) -> String {
    clean_opt_str(v).unwrap_or_else(|| fallback.to_string())
}

fn parse_session_view(val: &Value) -> SessionView {
    let counts = val.get("counts").and_then(Value::as_object);
    let details = val.get("details").and_then(Value::as_object);

    let subscriptions = details
        .and_then(|d| d.get("subscriptions"))
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .map(|s| SubRow {
                    id: clean_str_or(s.get("id"), ""),
                    origin_node: clean_str_or(s.get("originNode"), ""),
                    topic: clean_str_or(s.get("topic"), ""),
                    mode: clean_str_or(s.get("mode"), "queue"),
                    coalesce_seconds: s
                        .get("coalesceSeconds")
                        .and_then(Value::as_i64)
                        .unwrap_or(0),
                    filter_summary: clean_str_or(s.get("filterSummary"), ""),
                })
                .collect()
        })
        .unwrap_or_default();

    let queued_items = details
        .and_then(|d| d.get("queuedItems"))
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .map(|q| QueuedRow {
                    kind: clean_str_or(q.get("kind"), "item"),
                    source: clean_str_or(q.get("source"), ""),
                    received_at: q.get("receivedAt").and_then(Value::as_i64).unwrap_or(0),
                    notified: q.get("notified").and_then(Value::as_bool).unwrap_or(false),
                    urgency: clean_str_or(q.get("urgency"), "queue"),
                })
                .collect()
        })
        .unwrap_or_default();

    let mut rules_and_mutes = Vec::new();
    if let Some(mutes) = details.and_then(|d| d.get("mutes")).and_then(Value::as_array) {
        for m in mutes {
            rules_and_mutes.push(RuleOrMuteRow::Mute {
                pattern: clean_str_or(m.get("pattern"), ""),
                scope: clean_str_or(m.get("scope"), "session"),
                muted_at: m.get("mutedAt").and_then(Value::as_i64).unwrap_or(0),
            });
        }
    }
    if let Some(rules) = details.and_then(|d| d.get("rules")).and_then(Value::as_array) {
        for r in rules {
            rules_and_mutes.push(RuleOrMuteRow::Rule {
                target: clean_str_or(r.get("target"), ""),
                delivery: clean_str_or(r.get("delivery"), "queue"),
            });
        }
    }

    let channels = if let Some(entries) = details
        .and_then(|d| d.get("channelEntries"))
        .and_then(Value::as_array)
    {
        entries
            .iter()
            .map(|c| ChannelRow {
                channel: clean_str_or(c.get("channel"), ""),
                host_node: clean_str_or(c.get("hostNode"), ""),
                mode: clean_str_or(c.get("mode"), "open"),
            })
            .collect()
    } else if let Some(flat) = details
        .and_then(|d| d.get("channels"))
        .and_then(Value::as_array)
    {
        flat.iter()
            .filter_map(Value::as_str)
            .map(|c| ChannelRow {
                channel: sanitize_terminal_text(c),
                host_node: String::new(),
                mode: String::new(),
            })
            .collect()
    } else {
        Vec::new()
    };

    let wakeups = details
        .and_then(|d| d.get("wakeups"))
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .map(|w| WakeupRow {
                    label: clean_str_or(w.get("label"), ""),
                    trigger_kind: clean_str_or(w.get("triggerKind"), "timer"),
                    urgency: clean_str_or(w.get("urgency"), "queue"),
                    state: clean_str_or(w.get("state"), "active"),
                })
                .collect()
        })
        .unwrap_or_default();

    SessionView {
        session_id: clean_str_or(val.get("sessionId"), ""),
        harness: clean_str_or(val.get("harness"), "unknown"),
        enrolled: val
            .get("enrolled")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        handle: clean_opt_str(val.get("handle")),
        herdr_terminal_id: clean_opt_str(val.get("herdrTerminalId")),
        transport_kind: clean_opt_str(val.get("transportKind")),
        has_live_transport: val
            .get("hasLiveTransport")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        delivery_mode: clean_str_or(val.get("deliveryMode"), "queue"),
        focus_mode: val
            .get("focusMode")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        muted_all: val
            .get("mutedAll")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        count_subs: counts
            .and_then(|c| c.get("subscriptions"))
            .and_then(Value::as_u64)
            .unwrap_or(0),
        count_queued: counts
            .and_then(|c| c.get("queued"))
            .and_then(Value::as_u64)
            .unwrap_or(0),
        count_quarantined: counts
            .and_then(|c| c.get("quarantined"))
            .and_then(Value::as_u64)
            .unwrap_or(0),
        count_muted_rules: counts
            .and_then(|c| c.get("mutedRules"))
            .and_then(Value::as_u64)
            .unwrap_or(0),
        count_muted_archived: counts
            .and_then(|c| c.get("mutedArchived"))
            .and_then(Value::as_u64)
            .unwrap_or(0),
        count_wakeups: counts
            .and_then(|c| c.get("wakeups"))
            .and_then(Value::as_u64)
            .unwrap_or(0),
        subscriptions,
        queued_items,
        rules_and_mutes,
        channels,
        wakeups,
    }
}

impl UiState {
    /// Applies a `sessions.summary` / `inspect.snapshot` JSON snapshot while preserving the
    /// currently selected session (or matching the initial target preference on first load).
    pub fn apply_snapshot(
        &mut self,
        snap: &Value,
        prefer_session: Option<&str>,
        prefer_herdr: Option<&str>,
        prefer_handle: Option<&str>,
    ) {
        let prev_sid = self.active_session().map(|s| s.session_id.clone());

        self.rev = snap.get("rev").and_then(Value::as_u64).unwrap_or(self.rev);
        self.updated_at = snap
            .get("updatedAt")
            .and_then(Value::as_i64)
            .unwrap_or(self.updated_at);

        if let Some(d) = snap.get("daemon").and_then(Value::as_object) {
            self.daemon = DaemonView {
                online: d.get("online").and_then(Value::as_bool).unwrap_or(true),
                node_id: clean_str_or(d.get("nodeId"), "local"),
                profile: clean_str_or(d.get("profile"), "local"),
                peers_online: d.get("peersOnline").and_then(Value::as_u64).unwrap_or(0),
                quarantined_global: d
                    .get("quarantinedGlobal")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
            };
        }

        let mut parsed_sessions = Vec::new();
        if let Some(arr) = snap.get("sessions").and_then(Value::as_array) {
            for item in arr {
                parsed_sessions.push(parse_session_view(item));
            }
        } else if let Some(single) = snap.get("session").filter(|v| !v.is_null()) {
            parsed_sessions.push(parse_session_view(single));
        }

        // Stable sort: enrolled sessions first, then session_id lexicographically.
        parsed_sessions.sort_by(|a, b| {
            b.enrolled
                .cmp(&a.enrolled)
                .then_with(|| a.session_id.cmp(&b.session_id))
        });
        self.sessions = parsed_sessions;

        if self.sessions.is_empty() {
            self.active_session_idx = 0;
        } else if let Some(ref sid) = prev_sid {
            if let Some(pos) = self.sessions.iter().position(|s| &s.session_id == sid) {
                self.active_session_idx = pos;
            } else {
                self.active_session_idx = self.active_session_idx.min(self.sessions.len() - 1);
            }
        } else if let Some(pos) =
            find_preferred_session(&self.sessions, prefer_session, prefer_herdr, prefer_handle)
        {
            self.active_session_idx = pos;
        } else {
            self.active_session_idx = 0;
        }

        self.clamp_selection();
    }

    pub fn active_session(&self) -> Option<&SessionView> {
        self.sessions.get(self.active_session_idx)
    }

    pub fn current_row_count(&self) -> usize {
        let Some(sess) = self.active_session() else {
            return 0;
        };
        match self.active_tab {
            UiTab::Subscriptions => sess.subscriptions.len(),
            UiTab::Queue => sess.queued_items.len(),
            UiTab::RulesAndMutes => sess.rules_and_mutes.len(),
            UiTab::MeshAndChannels => sess.channels.len(),
        }
    }

    pub fn clamp_selection(&mut self) {
        let count = self.current_row_count();
        if count == 0 {
            self.selected_row = 0;
            self.scroll_offset = 0;
        } else if self.selected_row >= count {
            self.selected_row = count - 1;
        }
    }

    pub fn select_tab(&mut self, tab: UiTab) {
        if self.active_tab != tab {
            self.active_tab = tab;
            self.selected_row = 0;
            self.scroll_offset = 0;
            self.clamp_selection();
        }
    }

    pub fn move_up(&mut self) {
        if self.selected_row > 0 {
            self.selected_row -= 1;
        }
    }

    pub fn move_down(&mut self) {
        let count = self.current_row_count();
        if count > 0 && self.selected_row + 1 < count {
            self.selected_row += 1;
        }
    }

    pub fn cycle_session(&mut self) {
        if self.sessions.len() > 1 {
            self.active_session_idx = (self.active_session_idx + 1) % self.sessions.len();
            self.selected_row = 0;
            self.scroll_offset = 0;
            self.clamp_selection();
        }
    }
}

fn find_preferred_session(
    sessions: &[SessionView],
    prefer_session: Option<&str>,
    prefer_herdr: Option<&str>,
    prefer_handle: Option<&str>,
) -> Option<usize> {
    if let Some(sid) = prefer_session {
        if let Some(pos) = sessions.iter().position(|s| s.session_id == sid) {
            return Some(pos);
        }
    }
    if let Some(tid) = prefer_herdr {
        if let Some(pos) = sessions
            .iter()
            .position(|s| s.herdr_terminal_id.as_deref() == Some(tid))
        {
            return Some(pos);
        }
    }
    if let Some(h) = prefer_handle {
        let clean = h.trim().trim_start_matches('@');
        if let Some(pos) = sessions
            .iter()
            .position(|s| s.handle.as_deref() == Some(clean))
        {
            return Some(pos);
        }
    }
    None
}

// ============================================================================
// Pure Deterministic Frame Renderer (Testable Without PTY!)
// ============================================================================

/// Returns visible column count ignoring ANSI SGR escape sequences (`ESC [ ... m`).
#[cfg_attr(not(test), allow(dead_code))]
pub fn visible_width(line: &str) -> usize {
    let mut width = 0usize;
    let mut chars = line.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\x1b' && chars.peek() == Some(&'[') {
            chars.next();
            for c in chars.by_ref() {
                if ('\x40'..='\x7e').contains(&c) {
                    break;
                }
            }
            continue;
        }
        width += 1;
    }
    width
}

/// Truncates a plain (already sanitized) string to strictly `<= max_cols` characters.
fn truncate_plain(text: &str, max_cols: usize) -> String {
    if max_cols == 0 {
        return String::new();
    }
    let clean = sanitize_terminal_text(text);
    let char_count = clean.chars().count();
    if char_count <= max_cols {
        return clean;
    }
    if max_cols == 1 {
        return "…".to_string();
    }
    let mut out: String = clean.chars().take(max_cols - 1).collect();
    out.push('…');
    out
}

fn pad_or_truncate(text: &str, width: usize) -> String {
    let truncated = truncate_plain(text, width);
    let len = truncated.chars().count();
    if len < width {
        format!("{truncated}{}", " ".repeat(width - len))
    } else {
        truncated
    }
}

fn style_wrap(text: &str, sgr: &str, use_color: bool) -> String {
    if use_color {
        format!("\x1b[{sgr}m{text}\x1b[0m")
    } else {
        text.to_string()
    }
}

/// Pure deterministic frame renderer for `hyp ui`.
///
/// Invariants guaranteed for EVERY `(rows, cols)` input:
/// - `lines.len() <= rows`
/// - Every line satisfies `visible_width(&line) <= cols`
/// - Every untrusted string is sanitized (zero injected ANSI/control characters)
/// - Never displays untrusted message bodies, wakeup notes, or quarantined payloads
pub fn render_ui_frame(state: &UiState, rows: usize, cols: usize) -> Vec<String> {
    if rows == 0 || cols == 0 {
        return Vec::new();
    }

    let use_color = state.color_mode != ColorMode::Plain;
    let mut lines: Vec<String> = Vec::with_capacity(rows);

    // 1. Header bar
    lines.push(render_header_line(state, cols, use_color));
    if lines.len() >= rows {
        return lines;
    }

    // 2. Tab bar
    lines.push(render_tab_bar(state, cols, use_color));
    if lines.len() >= rows {
        return lines;
    }

    // 3. Divider
    if rows >= 5 {
        let div = "─".repeat(cols);
        lines.push(style_wrap(&div, "2", use_color));
    }

    // Reserve bottom rows for status/toast (1 row when rows >= 7) + footer key hints (1 row when rows >= 4).
    let show_footer = rows >= 4;
    let show_status = rows >= 7;
    let reserved_bottom = usize::from(show_footer) + usize::from(show_status);
    let body_budget = rows.saturating_sub(lines.len() + reserved_bottom);

    let body_lines = render_active_tab_body(state, body_budget, cols, use_color);
    for l in body_lines.into_iter().take(body_budget) {
        lines.push(l);
    }

    // Pad remaining body rows so footer anchors cleanly to bottom of viewport.
    while lines.len() + reserved_bottom < rows {
        lines.push(String::new());
    }

    // Status / quarantine banner line
    if show_status && lines.len() < rows {
        lines.push(render_status_line(state, cols, use_color));
    }

    // Footer key hints line
    if show_footer && lines.len() < rows {
        lines.push(render_footer_line(state.active_tab, cols, use_color));
    }

    lines.truncate(rows);
    lines
}

fn render_header_line(state: &UiState, cols: usize, use_color: bool) -> String {
    let mut parts: Vec<String> = Vec::new();
    parts.push("⟁ HYPHAE".to_string());

    if let Some(sess) = state.active_session() {
        let id_label = match &sess.handle {
            Some(h) => format!("@{h}"),
            None => sess.session_id.clone(),
        };
        if state.sessions.len() > 1 {
            parts.push(format!(
                "{id_label} ({}/{})",
                state.active_session_idx + 1,
                state.sessions.len()
            ));
        } else {
            parts.push(id_label);
        }
        parts.push(if sess.focus_mode {
            "focus ON".to_string()
        } else {
            "focus OFF".to_string()
        });
        parts.push(format!("{} subs", sess.count_subs));
        parts.push(format!("{} queued", sess.count_queued));
        if sess.muted_all {
            parts.push("muted ALL".to_string());
        } else if sess.count_muted_rules > 0 {
            parts.push(format!("{} muted", sess.count_muted_rules));
        }
        let q = sess.count_quarantined.max(state.daemon.quarantined_global);
        if q > 0 {
            parts.push(format!("⚠ {q} held"));
        }
    } else if !state.daemon.online {
        parts.push("daemon offline".to_string());
    } else {
        parts.push(format!("{} (no sessions)", state.daemon.node_id));
    }

    let raw = parts.join(" · ");
    let fitted = truncate_plain(&raw, cols);
    style_wrap(&fitted, "1;32", use_color)
}

fn render_tab_bar(state: &UiState, cols: usize, use_color: bool) -> String {
    let compact = cols < 64;
    let mut built_plain = String::new();
    let mut built_styled = String::new();

    for (idx, tab) in UiTab::ALL.iter().enumerate() {
        let sep = if idx == 0 { "" } else { "  " };
        let label = if compact {
            format!("[{}]{}", tab.number(), tab.short_title())
        } else {
            format!("[{}] {}", tab.number(), tab.title())
        };

        let next_len = built_plain.chars().count() + sep.len() + label.chars().count();
        if next_len > cols {
            // Fall back to ultra-compact truncated single line if terminal is extremely narrow.
            let rem = cols.saturating_sub(built_plain.chars().count());
            if rem > 2 {
                let tail = truncate_plain(&format!("{sep}{label}"), rem);
                built_plain.push_str(&tail);
                built_styled.push_str(&style_wrap(&tail, "2", use_color));
            }
            break;
        }

        built_plain.push_str(sep);
        built_styled.push_str(sep);
        built_plain.push_str(&label);
        if *tab == state.active_tab {
            built_styled.push_str(&style_wrap(&label, "1;7;32", use_color));
        } else {
            built_styled.push_str(&style_wrap(&label, "2", use_color));
        }
    }

    if use_color {
        built_styled
    } else {
        built_plain
    }
}

fn render_active_tab_body(
    state: &UiState,
    budget: usize,
    cols: usize,
    use_color: bool,
) -> Vec<String> {
    if budget == 0 {
        return Vec::new();
    }
    let Some(sess) = state.active_session() else {
        let msg = if state.daemon.online {
            "No sessions registered yet. Start an agent session or press `r` to refresh."
        } else {
            "Local Hyphae daemon is offline. Start it with `hyp daemon`, then press `r`."
        };
        return vec![style_wrap(&truncate_plain(msg, cols), "2", use_color)];
    };

    match state.active_tab {
        UiTab::Subscriptions => render_subs_tab(
            &state.daemon.node_id,
            sess,
            state.selected_row,
            budget,
            cols,
            use_color,
        ),
        UiTab::Queue => {
            render_queue_tab(sess, state.selected_row, state.updated_at, budget, cols, use_color)
        }
        UiTab::RulesAndMutes => {
            render_rules_tab(sess, state.selected_row, state.updated_at, budget, cols, use_color)
        }
        UiTab::MeshAndChannels => render_mesh_tab(
            &state.daemon,
            sess,
            state.selected_row,
            budget,
            cols,
            use_color,
        ),
    }
}

fn compute_window(selected: usize, total: usize, visible_rows: usize) -> (usize, usize) {
    if total == 0 || visible_rows == 0 {
        return (0, 0);
    }
    if total <= visible_rows {
        return (0, total);
    }
    let half = visible_rows / 2;
    let start = selected
        .saturating_sub(half)
        .min(total.saturating_sub(visible_rows));
    let end = (start + visible_rows).min(total);
    (start, end)
}

fn render_selectable_row(plain: &str, selected: bool, cols: usize, use_color: bool) -> String {
    let prefix = if selected { "▸ " } else { "  " };
    let body_w = cols.saturating_sub(2);
    let fitted = format!("{prefix}{}", truncate_plain(plain, body_w));
    if selected {
        let padded = pad_or_truncate(&fitted, cols);
        style_wrap(&padded, "1;7", use_color)
    } else {
        fitted
    }
}

fn render_subs_tab(
    local_node_id: &str,
    sess: &SessionView,
    selected: usize,
    budget: usize,
    cols: usize,
    use_color: bool,
) -> Vec<String> {
    let mut out = Vec::new();
    if sess.subscriptions.is_empty() {
        out.push(style_wrap(
            &truncate_plain("No active stream subscriptions.", cols),
            "2",
            use_color,
        ));
        return out;
    }

    let narrow = cols < 60;
    let header = if narrow {
        format!("  {:<12} {:<12} {}", "TOPIC", "MODE", "ID")
    } else {
        format!(
            "  {:<14} {:<18} {:<9} {:<6} {}",
            "ID", "TOPIC", "MODE", "COAL", "FILTERS"
        )
    };
    out.push(style_wrap(&truncate_plain(&header, cols), "2", use_color));

    let list_budget = budget.saturating_sub(1);
    let (start, end) = compute_window(selected, sess.subscriptions.len(), list_budget);
    for (idx, sub) in sess.subscriptions[start..end].iter().enumerate() {
        let abs_idx = start + idx;
        let line = if narrow {
            format!(
                "{} {} {}",
                pad_or_truncate(&sub.topic, 12),
                pad_or_truncate(&sub.mode, 12),
                sub.id
            )
        } else {
            let topic_disp = if sub.origin_node.is_empty()
                || sub.origin_node == "local"
                || sub.origin_node == local_node_id
            {
                sub.topic.clone()
            } else {
                format!("{}.{}", sub.origin_node, sub.topic)
            };
            let filt = if sub.filter_summary.is_empty() {
                "*"
            } else {
                sub.filter_summary.as_str()
            };
            format!(
                "{} {} {} {} {}",
                pad_or_truncate(&sub.id, 14),
                pad_or_truncate(&topic_disp, 18),
                pad_or_truncate(&sub.mode, 9),
                pad_or_truncate(&format!("{}s", sub.coalesce_seconds), 6),
                filt
            )
        };
        out.push(render_selectable_row(&line, abs_idx == selected, cols, use_color));
    }
    out
}

fn render_queue_tab(
    sess: &SessionView,
    selected: usize,
    now_ms: i64,
    budget: usize,
    cols: usize,
    use_color: bool,
) -> Vec<String> {
    let mut out = Vec::new();
    if sess.queued_items.is_empty() {
        out.push(style_wrap(
            &truncate_plain("Queue empty — zero pending items (metadata-only view).", cols),
            "2",
            use_color,
        ));
        return out;
    }

    let narrow = cols < 60;
    let header = if narrow {
        format!("  {:<6} {:<18} {}", "KIND", "SOURCE", "AGE")
    } else {
        format!(
            "  {:<9} {:<28} {:<10} {:<6} {}",
            "KIND", "SOURCE", "URGENCY", "AGE", "STATE"
        )
    };
    out.push(style_wrap(&truncate_plain(&header, cols), "2", use_color));

    let list_budget = budget.saturating_sub(1);
    let (start, end) = compute_window(selected, sess.queued_items.len(), list_budget);
    for (idx, item) in sess.queued_items[start..end].iter().enumerate() {
        let abs_idx = start + idx;
        let age = format_age_ms(item.received_at, now_ms);
        let state_lbl = if item.notified { "seen" } else { "new" };
        let line = if narrow {
            format!(
                "{} {} {}",
                pad_or_truncate(&item.kind, 6),
                pad_or_truncate(&item.source, 18),
                age
            )
        } else {
            format!(
                "{} {} {} {} {}",
                pad_or_truncate(&item.kind, 9),
                pad_or_truncate(&item.source, 28),
                pad_or_truncate(&item.urgency, 10),
                pad_or_truncate(&age, 6),
                state_lbl
            )
        };
        out.push(render_selectable_row(&line, abs_idx == selected, cols, use_color));
    }
    out
}

fn render_rules_tab(
    sess: &SessionView,
    selected: usize,
    now_ms: i64,
    budget: usize,
    cols: usize,
    use_color: bool,
) -> Vec<String> {
    let mut out = Vec::new();
    if sess.rules_and_mutes.is_empty() {
        out.push(style_wrap(
            &truncate_plain("No delivery rules or mutes active. Press `m` to mute all.", cols),
            "2",
            use_color,
        ));
        return out;
    }

    let narrow = cols < 60;
    let header = if narrow {
        format!("  {:<6} {:<16} {}", "TYPE", "PATTERN", "ACTION")
    } else {
        format!(
            "  {:<8} {:<28} {:<14} {}",
            "TYPE", "TARGET / PATTERN", "ACTION / SCOPE", "AGE"
        )
    };
    out.push(style_wrap(&truncate_plain(&header, cols), "2", use_color));

    let list_budget = budget.saturating_sub(1);
    let (start, end) = compute_window(selected, sess.rules_and_mutes.len(), list_budget);
    for (idx, item) in sess.rules_and_mutes[start..end].iter().enumerate() {
        let abs_idx = start + idx;
        let (kind, pat, action, age) = match item {
            RuleOrMuteRow::Mute {
                pattern,
                scope,
                muted_at,
            } => (
                "MUTE",
                pattern.as_str(),
                scope.as_str(),
                format_age_ms(*muted_at, now_ms),
            ),
            RuleOrMuteRow::Rule { target, delivery } => {
                ("RULE", target.as_str(), delivery.as_str(), "-".to_string())
            }
        };
        let line = if narrow {
            format!(
                "{} {} {}",
                pad_or_truncate(kind, 6),
                pad_or_truncate(pat, 16),
                action
            )
        } else {
            format!(
                "{} {} {} {}",
                pad_or_truncate(kind, 8),
                pad_or_truncate(pat, 28),
                pad_or_truncate(action, 14),
                age
            )
        };
        out.push(render_selectable_row(&line, abs_idx == selected, cols, use_color));
    }
    out
}

fn render_mesh_tab(
    daemon: &DaemonView,
    sess: &SessionView,
    selected: usize,
    budget: usize,
    cols: usize,
    use_color: bool,
) -> Vec<String> {
    let mut out = Vec::new();
    let transport = match &sess.transport_kind {
        Some(t) if sess.has_live_transport => format!("{t} (live)"),
        Some(t) => format!("{t} (idle)"),
        None => "hook/poll".to_string(),
    };
    let info1 = format!(
        "Node: {} · peersOnline={} · profile={} · transport={}",
        daemon.node_id, daemon.peers_online, daemon.profile, transport
    );
    out.push(truncate_plain(&info1, cols));
    if out.len() >= budget {
        return out;
    }

    let info2 = format!(
        "Session: {} ({}) · delivery={} · wakeups={} · archivedMuted={}",
        sess.session_id,
        sess.harness,
        sess.delivery_mode,
        sess.count_wakeups,
        sess.count_muted_archived
    );
    out.push(style_wrap(&truncate_plain(&info2, cols), "2", use_color));
    if out.len() >= budget {
        return out;
    }

    out.push(style_wrap(
        &truncate_plain(&format!("Channels ({}):", sess.channels.len()), cols),
        "1",
        use_color,
    ));
    if out.len() >= budget {
        return out;
    }

    if sess.channels.is_empty() {
        out.push(style_wrap(
            &truncate_plain("  (no joined channels)", cols),
            "2",
            use_color,
        ));
    } else {
        let wakeup_reserve = if !sess.wakeups.is_empty() && budget.saturating_sub(out.len()) > 3 {
            2
        } else {
            0
        };
        let chan_budget = budget.saturating_sub(out.len() + wakeup_reserve);
        let (start, end) = compute_window(selected, sess.channels.len(), chan_budget);
        for (idx, ch) in sess.channels[start..end].iter().enumerate() {
            let abs_idx = start + idx;
            let line = if cols < 52 {
                format!("{} ({})", ch.channel, ch.mode)
            } else {
                format!(
                    "{} {} {}",
                    pad_or_truncate(&ch.channel, 18),
                    pad_or_truncate(&ch.host_node, 20),
                    ch.mode
                )
            };
            out.push(render_selectable_row(&line, abs_idx == selected, cols, use_color));
        }
    }

    // Show metadata-only wakeups summary if space remains (ZERO wakeup note!)
    if !sess.wakeups.is_empty() && out.len() + 2 <= budget {
        out.push(style_wrap(
            &truncate_plain(&format!("Wakeups ({}):", sess.wakeups.len()), cols),
            "1",
            use_color,
        ));
        for wk in &sess.wakeups {
            if out.len() >= budget {
                break;
            }
            let line = format!(
                "  {} [{}] {} ({})",
                wk.label, wk.trigger_kind, wk.urgency, wk.state
            );
            out.push(truncate_plain(&line, cols));
        }
    }

    out
}

fn render_status_line(state: &UiState, cols: usize, use_color: bool) -> String {
    if let Some((ref msg, is_err)) = state.status_message {
        let fitted = truncate_plain(msg, cols);
        return if is_err {
            style_wrap(&fitted, "1;31", use_color)
        } else {
            style_wrap(&fitted, "33", use_color)
        };
    }

    let q = state
        .active_session()
        .map(|s| s.count_quarantined)
        .unwrap_or(0)
        .max(state.daemon.quarantined_global);
    if q > 0 {
        let msg = format!("⚠ {q} item(s) quarantined by Local Security Gate — run `hyp gate review`");
        return style_wrap(&truncate_plain(&msg, cols), "1;31", use_color);
    }

    let meta = format!(
        "rev {} · live inspect.watch (zero polling)",
        state.rev
    );
    style_wrap(&truncate_plain(&meta, cols), "2", use_color)
}

fn render_footer_line(tab: UiTab, cols: usize, use_color: bool) -> String {
    let text = match tab {
        UiTab::Subscriptions => {
            if cols < 56 {
                "1-4 tab · ↑↓ · f focus · m mute · u unsub · s sess · q"
            } else {
                "1-4/Tab tabs · ↑↓ nav · f focus · m mute · u unsub · s sess · r refresh · q quit"
            }
        }
        UiTab::Queue => {
            if cols < 56 {
                "1-4 tab · ↑↓ · f focus · m mute src · s sess · q"
            } else {
                "1-4/Tab tabs · ↑↓ nav · f focus · m mute src · s sess · r refresh · q quit"
            }
        }
        UiTab::RulesAndMutes => {
            if cols < 56 {
                "1-4 tab · ↑↓ · f focus · m mute · u rm · s sess · q"
            } else {
                "1-4/Tab tabs · ↑↓ nav · f focus · m mute · u unmute/rm · s sess · r refresh · q quit"
            }
        }
        UiTab::MeshAndChannels => {
            if cols < 56 {
                "1-4 tab · ↑↓ · f focus · m mute · u leave · s sess · q"
            } else {
                "1-4/Tab tabs · ↑↓ nav · f focus · m mute · u leave ch · s sess · r refresh · q quit"
            }
        }
    };
    style_wrap(&truncate_plain(text, cols), "2", use_color)
}

// ============================================================================
// VT100 Key Parsing & Pure-Rust Terminal RAII Guards (Unix)
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TuiKey {
    Up,
    Down,
    Left,
    Right,
    Tab,
    BackTab,
    TabNum(u8),
    Focus,
    Mute,
    Remove,
    SwitchSession,
    Refresh,
    Quit,
    Other,
}

pub fn parse_tui_key(bytes: &[u8]) -> TuiKey {
    match bytes {
        [0x1b, b'[', b'A', ..] | [0x1b, b'O', b'A', ..] | [b'k'] | [b'K'] => TuiKey::Up,
        [0x1b, b'[', b'B', ..] | [0x1b, b'O', b'B', ..] | [b'j'] | [b'J'] => TuiKey::Down,
        [0x1b, b'[', b'C', ..] | [0x1b, b'O', b'C', ..] | [b'l'] | [b'L'] => TuiKey::Right,
        [0x1b, b'[', b'D', ..] | [0x1b, b'O', b'D', ..] | [b'h'] | [b'H'] => TuiKey::Left,
        [0x1b, b'[', b'Z', ..] => TuiKey::BackTab,
        [b'\t', ..] => TuiKey::Tab,
        [b'1'] => TuiKey::TabNum(1),
        [b'2'] => TuiKey::TabNum(2),
        [b'3'] => TuiKey::TabNum(3),
        [b'4'] => TuiKey::TabNum(4),
        [b'f'] | [b'F'] => TuiKey::Focus,
        [b'm'] | [b'M'] => TuiKey::Mute,
        [b'u'] | [b'U'] | [b'x'] | [b'X'] => TuiKey::Remove,
        [b's'] | [b'S'] => TuiKey::SwitchSession,
        [b'r'] | [b'R'] => TuiKey::Refresh,
        [b'q'] | [b'Q'] | [0x03, ..] | [0x1b] => TuiKey::Quit,
        _ => TuiKey::Other,
    }
}

#[cfg(unix)]
struct AltScreenGuard {
    active: bool,
}

#[cfg(unix)]
impl AltScreenGuard {
    fn enter_if(enabled: bool) -> Self {
        if enabled {
            let mut out = io::stdout().lock();
            let _ = out.write_all(b"\x1b[?1049h\x1b[2J\x1b[H\x1b[?25l");
            let _ = out.flush();
        } else {
            let mut out = io::stdout().lock();
            let _ = out.write_all(b"\x1b[?25l");
            let _ = out.flush();
        }
        Self { active: enabled }
    }

    fn leave(&mut self) {
        let mut out = io::stdout().lock();
        if self.active {
            self.active = false;
            let _ = out.write_all(b"\x1b[?25h\x1b[0m\x1b[?1049l");
        } else {
            let _ = out.write_all(b"\x1b[?25h\x1b[0m\r\n");
        }
        let _ = out.flush();
    }
}

#[cfg(unix)]
impl Drop for AltScreenGuard {
    fn drop(&mut self) {
        self.leave();
    }
}

#[cfg(unix)]
struct RawTtyGuard {
    saved_state: String,
    tty: fs::File,
    active: bool,
}

#[cfg(unix)]
impl RawTtyGuard {
    fn run_stty(tty: &fs::File, args: &[&str]) -> io::Result<std::process::Output> {
        let stdin_file = tty.try_clone()?;
        Command::new("stty")
            .args(args)
            .stdin(Stdio::from(stdin_file))
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output()
    }

    fn enter() -> io::Result<Self> {
        let tty = fs::File::open("/dev/tty")?;
        let saved_out = Self::run_stty(&tty, &["-g"])?;
        if !saved_out.status.success() {
            return Err(io::Error::other("stty -g failed on /dev/tty"));
        }
        let saved_state = String::from_utf8_lossy(&saved_out.stdout)
            .trim()
            .to_string();
        if saved_state.is_empty() {
            return Err(io::Error::other("stty -g returned empty state"));
        }

        let mut guard = Self {
            saved_state,
            tty,
            active: true,
        };
        let raw_out = Self::run_stty(&guard.tty, &["raw", "-echo", "min", "0", "time", "1"])?;
        if !raw_out.status.success() {
            guard.restore();
            return Err(io::Error::other("stty raw -echo failed on /dev/tty"));
        }
        Ok(guard)
    }

    fn read_key_timeout(&mut self) -> io::Result<Option<TuiKey>> {
        let mut buf = [0u8; 8];
        match self.tty.read(&mut buf) {
            Ok(0) => Ok(None),
            Ok(n) => {
                let mut total = n;
                if total == 1 && buf[0] == 0x1b {
                    if let Ok(extra) = self.tty.read(&mut buf[1..]) {
                        total += extra;
                    }
                }
                Ok(Some(parse_tui_key(&buf[..total])))
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn restore(&mut self) {
        if self.active {
            self.active = false;
            let _ = Self::run_stty(&self.tty, &[self.saved_state.as_str()]);
        }
    }
}

#[cfg(unix)]
impl Drop for RawTtyGuard {
    fn drop(&mut self) {
        self.restore();
    }
}

#[cfg(unix)]
enum WatchEvent {
    Snapshot(Value),
    Disconnected(String),
}

#[cfg(unix)]
fn spawn_watch_thread(
    socket_path: PathBuf,
    tx: mpsc::Sender<WatchEvent>,
    stop: Arc<AtomicBool>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let Ok(rt) = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        else {
            let _ = tx.send(WatchEvent::Disconnected(
                "Failed to build watch runtime".into(),
            ));
            return;
        };

        rt.block_on(async move {
            let (read_half, mut write_half) = match connect_daemon_async(&socket_path).await {
                Ok(pair) => pair,
                Err(e) => {
                    let _ = tx.send(WatchEvent::Disconnected(format!("Daemon offline: {e}")));
                    return;
                }
            };
            if let Err(e) = write_ndjson_line_async(
                &mut write_half,
                &json!({ "type": "inspect.watch", "detail": "full" }),
            )
            .await
            {
                let _ = tx.send(WatchEvent::Disconnected(format!("Watch error: {e}")));
                return;
            }

            let mut reader = tokio::io::BufReader::new(read_half);
            while !stop.load(Ordering::Relaxed) {
                let line = tokio::time::timeout(
                    Duration::from_millis(250),
                    read_bounded_line_async(&mut reader, MAX_SOCKET_LINE_BYTES),
                )
                .await;
                match line {
                    Err(_) => continue, // wake periodically to observe stop flag cleanly
                    Ok(Ok(Some(raw))) => {
                        if let Ok(val) = serde_json::from_str::<Value>(&raw) {
                            if tx.send(WatchEvent::Snapshot(val)).is_err() {
                                break;
                            }
                        }
                    }
                    Ok(Ok(None)) => {
                        let _ = tx.send(WatchEvent::Disconnected("Daemon disconnected".into()));
                        break;
                    }
                    Ok(Err(e)) => {
                        let _ = tx.send(WatchEvent::Disconnected(format!("Watch error: {e}")));
                        break;
                    }
                }
            }
        });
    })
}

#[cfg(unix)]
fn draw_frame_sync(lines: &[String]) {
    let mut buf = String::with_capacity(lines.len() * 96);
    buf.push_str("\x1b[?2026h\x1b[H");
    for (idx, line) in lines.iter().enumerate() {
        buf.push_str(line);
        buf.push_str("\x1b[K");
        if idx + 1 < lines.len() {
            buf.push_str("\r\n");
        }
    }
    buf.push_str("\x1b[J\x1b[?2026l");
    let mut out = io::stdout().lock();
    let _ = out.write_all(buf.as_bytes());
    let _ = out.flush();
}

#[cfg(unix)]
fn perform_action_rpc(socket_path: &Path, state: &mut UiState, key: TuiKey) {
    let Some(sess) = state.active_session().cloned() else {
        state.status_message = Some(("No active session selected".into(), true));
        return;
    };

    let (pkt, ok_label): (Value, String) = match key {
        TuiKey::Focus => {
            let next_on = !sess.focus_mode;
            (
                json!({
                    "type": "session.focus",
                    "sessionId": sess.session_id,
                    "enabled": next_on
                }),
                format!("Focus mode {}", if next_on { "ON" } else { "OFF" }),
            )
        }
        TuiKey::Mute => {
            if state.active_tab == UiTab::Queue {
                if let Some(item) = sess.queued_items.get(state.selected_row) {
                    (
                        json!({
                            "type": "session.mute",
                            "sessionId": sess.session_id,
                            "source": item.source,
                            "scope": "session"
                        }),
                        format!("Muted source '{}'", item.source),
                    )
                } else {
                    toggle_mute_all_packet(&sess)
                }
            } else {
                toggle_mute_all_packet(&sess)
            }
        }
        TuiKey::Remove => match state.active_tab {
            UiTab::Subscriptions => {
                let Some(sub) = sess.subscriptions.get(state.selected_row) else {
                    state.status_message = Some(("No subscription selected".into(), true));
                    return;
                };
                (
                    json!({
                        "type": "session.unsubscribe",
                        "sessionId": sess.session_id,
                        "subscriptionId": sub.id
                    }),
                    format!("Unsubscribed '{}'", sub.id),
                )
            }
            UiTab::RulesAndMutes => {
                let Some(row) = sess.rules_and_mutes.get(state.selected_row) else {
                    state.status_message = Some(("No rule or mute selected".into(), true));
                    return;
                };
                match row {
                    RuleOrMuteRow::Mute { pattern, scope, .. } => (
                        json!({
                            "type": "session.unmute",
                            "sessionId": sess.session_id,
                            "source": pattern,
                            "scope": scope
                        }),
                        format!("Unmuted '{pattern}' ({scope})"),
                    ),
                    RuleOrMuteRow::Rule { target, .. } => (
                        json!({
                            "type": "session.rule",
                            "sessionId": sess.session_id,
                            "source": target,
                            "urgency": "remove",
                            "remove": true
                        }),
                        format!("Removed rule '{target}'"),
                    ),
                }
            }
            UiTab::MeshAndChannels => {
                let Some(ch) = sess.channels.get(state.selected_row) else {
                    state.status_message = Some(("No channel selected".into(), true));
                    return;
                };
                (
                    json!({
                        "type": "session.leave_channel",
                        "sessionId": sess.session_id,
                        "channel": ch.channel
                    }),
                    format!("Left channel '{}'", ch.channel),
                )
            }
            UiTab::Queue => {
                state.status_message = Some(("Use `m` to mute the selected source".into(), false));
                return;
            }
        },
        _ => return,
    };

    let res = daemon_rpc_sync(socket_path, &pkt, ACTION_RPC_TIMEOUT);
    if res.ok {
        state.status_message = Some((ok_label, false));
    } else {
        let err = res.error.unwrap_or_else(|| "Daemon RPC failed".into());
        state.status_message = Some((format!("Error: {}", sanitize_terminal_text(&err)), true));
    }
}

#[cfg(unix)]
fn toggle_mute_all_packet(sess: &SessionView) -> (Value, String) {
    if sess.muted_all {
        let scope = sess
            .rules_and_mutes
            .iter()
            .find_map(|r| match r {
                RuleOrMuteRow::Mute { pattern, scope, .. } if pattern == "*" => {
                    Some(scope.as_str())
                }
                _ => None,
            })
            .unwrap_or("session");
        (
            json!({
                "type": "session.unmute",
                "sessionId": sess.session_id,
                "source": "*",
                "scope": scope
            }),
            format!("Unmuted all (*, {scope})"),
        )
    } else {
        (
            json!({
                "type": "session.mute",
                "sessionId": sess.session_id,
                "source": "*",
                "scope": "session"
            }),
            "Muted all (*)".to_string(),
        )
    }
}

fn fallback_to_inspect(args: &UiArgs) -> ExitCode {
    let inspect_args = InspectArgs {
        session: args.session.clone(),
        herdr_terminal: args.herdr_terminal.clone(),
        herdr_created_ms: None,
        handle: args.handle.clone(),
        all: args.session.is_none() && args.herdr_terminal.is_none() && args.handle.is_none(),
        watch: false,
        socket: args.socket.clone(),
        json: false,
    };
    run_inspect(&inspect_args)
}

pub fn run_ui(args: &UiArgs) -> ExitCode {
    if !io::stdout().is_terminal() {
        return fallback_to_inspect(args);
    }

    #[cfg(not(unix))]
    {
        return fallback_to_inspect(args);
    }

    #[cfg(unix)]
    {
        let Ok(mut tty) = RawTtyGuard::enter() else {
            return fallback_to_inspect(args);
        };
        let _alt = AltScreenGuard::enter_if(!args.no_alt_screen);

        let socket_path = args.socket.clone().unwrap_or_else(default_socket_path);
        let prefer_session = args.session.clone().or_else(infer_session_id_from_env);
        let prefer_herdr = args
            .herdr_terminal
            .clone()
            .or_else(infer_herdr_terminal_from_env);
        let prefer_handle = args.handle.clone();

        let mut state = UiState {
            color_mode: detect_color_mode(),
            ..Default::default()
        };

        // Initial fast synchronous snapshot so frame 1 renders immediately with zero blank flash.
        let init_res = daemon_rpc_sync(
            &socket_path,
            &json!({ "type": "sessions.summary", "detail": "full" }),
            ACTION_RPC_TIMEOUT,
        );
        if init_res.ok {
            if let Some(map) = init_res.result {
                state.apply_snapshot(
                    &Value::Object(map),
                    prefer_session.as_deref(),
                    prefer_herdr.as_deref(),
                    prefer_handle.as_deref(),
                );
            }
        } else {
            state.daemon.online = false;
            state.status_message = Some((
                format!(
                    "Daemon offline at {} — start with `hyp daemon`",
                    socket_path.display()
                ),
                true,
            ));
        }

        // Start zero-polling `inspect.watch` background listener.
        let (tx, rx) = mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let watch_handle = spawn_watch_thread(socket_path.clone(), tx, Arc::clone(&stop));

        let (mut rows, mut cols) = detect_terminal_size();
        let mut dirty = true;
        let mut idle_ticks: u32 = 0;

        loop {
            // Drain all pending pushed watch snapshots without blocking.
            while let Ok(ev) = rx.try_recv() {
                match ev {
                    WatchEvent::Snapshot(snap) => {
                        state.apply_snapshot(
                            &snap,
                            prefer_session.as_deref(),
                            prefer_herdr.as_deref(),
                            prefer_handle.as_deref(),
                        );
                        dirty = true;
                    }
                    WatchEvent::Disconnected(reason) => {
                        state.daemon.online = false;
                        state.status_message = Some((reason, true));
                        dirty = true;
                    }
                }
            }

            if dirty {
                let frame = render_ui_frame(&state, rows, cols);
                draw_frame_sync(&frame);
                dirty = false;
            }

            match tty.read_key_timeout() {
                Ok(Some(key)) => {
                    idle_ticks = 0;
                    match key {
                        TuiKey::Quit => break,
                        TuiKey::TabNum(1) => state.select_tab(UiTab::Subscriptions),
                        TuiKey::TabNum(2) => state.select_tab(UiTab::Queue),
                        TuiKey::TabNum(3) => state.select_tab(UiTab::RulesAndMutes),
                        TuiKey::TabNum(4) => state.select_tab(UiTab::MeshAndChannels),
                        TuiKey::Tab | TuiKey::Right => state.select_tab(state.active_tab.next()),
                        TuiKey::BackTab | TuiKey::Left => state.select_tab(state.active_tab.prev()),
                        TuiKey::Up => state.move_up(),
                        TuiKey::Down => state.move_down(),
                        TuiKey::SwitchSession => {
                            state.cycle_session();
                            if let Some(s) = state.active_session() {
                                let label = s
                                    .handle
                                    .as_deref()
                                    .map(|h| format!("@{h}"))
                                    .unwrap_or_else(|| s.session_id.clone());
                                state.status_message =
                                    Some((format!("Switched to {label}"), false));
                            }
                        }
                        TuiKey::Refresh => {
                            let (r, c) = detect_terminal_size();
                            rows = r;
                            cols = c;
                            let res = daemon_rpc_sync(
                                &socket_path,
                                &json!({ "type": "sessions.summary", "detail": "full" }),
                                ACTION_RPC_TIMEOUT,
                            );
                            if res.ok {
                                if let Some(map) = res.result {
                                    state.apply_snapshot(
                                        &Value::Object(map),
                                        prefer_session.as_deref(),
                                        prefer_herdr.as_deref(),
                                        prefer_handle.as_deref(),
                                    );
                                    state.status_message = Some(("Refreshed".into(), false));
                                }
                            } else {
                                state.daemon.online = false;
                                state.status_message =
                                    Some(("Refresh failed: daemon offline".into(), true));
                            }
                        }
                        TuiKey::Focus | TuiKey::Mute | TuiKey::Remove => {
                            perform_action_rpc(&socket_path, &mut state, key);
                            // Fetch fresh state immediately in case watch stream had disconnected.
                            let res = daemon_rpc_sync(
                                &socket_path,
                                &json!({ "type": "sessions.summary", "detail": "full" }),
                                ACTION_RPC_TIMEOUT,
                            );
                            if res.ok {
                                if let Some(map) = res.result {
                                    state.apply_snapshot(
                                        &Value::Object(map),
                                        prefer_session.as_deref(),
                                        prefer_herdr.as_deref(),
                                        prefer_handle.as_deref(),
                                    );
                                }
                            }
                        }
                        TuiKey::TabNum(_) | TuiKey::Other => continue,
                    }
                    dirty = true;
                }
                Ok(None) => {
                    idle_ticks = idle_ticks.saturating_add(1);
                    // Periodically re-check terminal resize (~every 0.6s while idle).
                    if idle_ticks % 6 == 0 {
                        let (r, c) = detect_terminal_size();
                        if r != rows || c != cols {
                            rows = r;
                            cols = c;
                            dirty = true;
                        }
                    }
                }
                Err(_) => break,
            }
        }

        stop.store(true, Ordering::Relaxed);
        let _ = watch_handle.join();
        ExitCode::from(EXIT_OK)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_state_with_ansi_traps() -> UiState {
        let mut st = UiState {
            color_mode: ColorMode::TrueColor,
            ..Default::default()
        };
        let snap = json!({
            "schemaVersion": 1,
            "rev": 12,
            "updatedAt": 1_750_000_120_000i64,
            "daemon": {
                "online": true,
                "nodeId": "alice@\x1b[31mmacbook",
                "version": "0.6.0",
                "profile": "local",
                "peersOnline": 3,
                "quarantinedGlobal": 1
            },
            "sessions": [{
                "sessionId": "claude:ui-1",
                "harness": "claude",
                "enrolled": true,
                "handle": "\x1b[31malice\x1b]0;pwn\x07",
                "herdrTerminalId": "t4g",
                "transportKind": "herdr",
                "hasLiveTransport": true,
                "deliveryMode": "notify",
                "focusMode": true,
                "focusAllowInterruptVips": true,
                "mutedAll": false,
                "counts": {
                    "subscriptions": 2,
                    "queued": 2,
                    "unnotified": 1,
                    "quarantined": 1,
                    "mutedRules": 1,
                    "mutedArchived": 4,
                    "channels": 2,
                    "wakeups": 1
                },
                "details": {
                    "subscriptions": [
                        {
                            "id": "sub-gh-very-long-identifier-123456",
                            "originNode": "alice@macbook",
                            "topic": "github",
                            "mode": "queue",
                            "coalesceSeconds": 15,
                            "filterSummary": "type=pr.review_requested, repo=hyphae-to/hyp"
                        },
                        {
                            "id": "sub-alerts-2",
                            "originNode": "alice@macbook",
                            "topic": "alerts",
                            "mode": "interrupt",
                            "coalesceSeconds": 0,
                            "filterSummary": ""
                        }
                    ],
                    "queuedItems": [
                        {
                            "receipt": "rcpt-1",
                            "kind": "message",
                            "source": "bob@laptop/reviewer\x1b[35m",
                            "originNode": "bob@laptop",
                            "receivedAt": 1_750_000_060_000i64,
                            "notified": false,
                            "urgency": "interrupt",
                            "text": "SENTINEL_UNTRUSTED_BODY_MUST_NEVER_APPEAR"
                        },
                        {
                            "receipt": "rcpt-2",
                            "kind": "event",
                            "source": "alice@macbook.github",
                            "originNode": "alice@macbook",
                            "receivedAt": 1_750_000_000_000i64,
                            "notified": true,
                            "urgency": "queue"
                        }
                    ],
                    "mutes": [
                        {
                            "pattern": "#noisy-ci-spam-channel",
                            "scope": "session",
                            "mutedAt": 1_750_000_000_000i64
                        }
                    ],
                    "rules": [
                        {
                            "target": "bob@laptop/reviewer",
                            "delivery": "interrupt"
                        }
                    ],
                    "channelEntries": [
                        {
                            "hostNode": "alice@macbook",
                            "channel": "#ops",
                            "mode": "open"
                        },
                        {
                            "hostNode": "acme-hub",
                            "channel": "#release",
                            "mode": "restricted"
                        }
                    ],
                    "wakeups": [
                        {
                            "id": "wk-1",
                            "label": "check-deploy",
                            "triggerKind": "timer",
                            "urgency": "queue",
                            "state": "active",
                            "note": "SENTINEL_WAKEUP_NOTE_MUST_NEVER_APPEAR"
                        }
                    ]
                }
            }]
        });
        st.apply_snapshot(&snap, None, None, None);
        st
    }

    #[test]
    fn render_ui_frame_fits_strictly_at_24x80_and_18x40_across_all_4_tabs() {
        let mut state = sample_state_with_ansi_traps();

        for (rows, cols) in [(24usize, 80usize), (18, 40), (10, 32)] {
            for mode in [ColorMode::TrueColor, ColorMode::Plain] {
                state.color_mode = mode;
                for tab in UiTab::ALL {
                    state.select_tab(tab);
                    let frame = render_ui_frame(&state, rows, cols);
                    assert!(
                        frame.len() <= rows,
                        "tab={tab:?} rows={rows} cols={cols}: frame len {} > {rows}",
                        frame.len()
                    );
                    assert_eq!(
                        frame.len(),
                        rows,
                        "tab={tab:?} rows={rows} cols={cols}: expected exact full height"
                    );

                    let joined = frame.join("\n");
                    // Security: zero untrusted body/note leakage and zero injected OSC/pwn payload!
                    assert!(!joined.contains("SENTINEL_UNTRUSTED_BODY_MUST_NEVER_APPEAR"));
                    assert!(!joined.contains("SENTINEL_WAKEUP_NOTE_MUST_NEVER_APPEAR"));
                    assert!(!joined.contains("pwn"));
                    assert!(!joined.contains("\x1b]0;"));

                    if rows == 24 && cols == 80 && mode == ColorMode::Plain {
                        assert!(frame[0].contains("@alice"));
                        assert!(frame[0].contains("focus ON"));
                        assert!(frame[0].contains("2 subs"));
                        assert!(frame[0].contains("2 queued"));
                        assert!(frame[0].contains("⚠ 1 held"));
                        match tab {
                            UiTab::Subscriptions => {
                                assert!(joined.contains("github"));
                                assert!(joined.contains("alerts"));
                            }
                            UiTab::Queue => {
                                assert!(joined.contains("bob@laptop/reviewer"));
                                assert!(joined.contains("interrupt"));
                            }
                            UiTab::RulesAndMutes => {
                                assert!(joined.contains("#noisy-ci-spam-channel"));
                                assert!(joined.contains("bob@laptop/reviewer"));
                            }
                            UiTab::MeshAndChannels => {
                                assert!(joined.contains("#ops"));
                                assert!(joined.contains("#release"));
                                assert!(joined.contains("check-deploy"));
                            }
                        }
                    }

                    for (line_idx, line) in frame.iter().enumerate() {
                        let vis = visible_width(line);
                        assert!(
                            vis <= cols,
                            "tab={tab:?} mode={mode:?} ({rows}x{cols}) line {line_idx} overflowed: vis={vis} > cols={cols}: {line:?}"
                        );
                        if mode == ColorMode::Plain {
                            assert!(
                                !line.contains('\x1b'),
                                "Plain mode must emit zero ANSI escapes: {line:?}"
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn parses_vt100_and_single_char_keys() {
        assert_eq!(parse_tui_key(b"\x1b[A"), TuiKey::Up);
        assert_eq!(parse_tui_key(b"\x1b[B"), TuiKey::Down);
        assert_eq!(parse_tui_key(b"\x1b[C"), TuiKey::Right);
        assert_eq!(parse_tui_key(b"\x1b[D"), TuiKey::Left);
        assert_eq!(parse_tui_key(b"\x1b[Z"), TuiKey::BackTab);
        assert_eq!(parse_tui_key(b"\t"), TuiKey::Tab);
        assert_eq!(parse_tui_key(b"1"), TuiKey::TabNum(1));
        assert_eq!(parse_tui_key(b"4"), TuiKey::TabNum(4));
        assert_eq!(parse_tui_key(b"f"), TuiKey::Focus);
        assert_eq!(parse_tui_key(b"m"), TuiKey::Mute);
        assert_eq!(parse_tui_key(b"u"), TuiKey::Remove);
        assert_eq!(parse_tui_key(b"x"), TuiKey::Remove);
        assert_eq!(parse_tui_key(b"s"), TuiKey::SwitchSession);
        assert_eq!(parse_tui_key(b"r"), TuiKey::Refresh);
        assert_eq!(parse_tui_key(b"q"), TuiKey::Quit);
        assert_eq!(parse_tui_key(b"\x1b"), TuiKey::Quit);
        assert_eq!(parse_tui_key(b"\x03"), TuiKey::Quit);
    }

    #[test]
    fn session_cycling_and_row_clamping_work_cleanly() {
        let mut st = UiState::default();
        let snap = json!({
            "rev": 1,
            "daemon": { "online": true, "nodeId": "alice@mac" },
            "sessions": [
                { "sessionId": "claude:a", "enrolled": true, "handle": "alice", "counts": {} },
                { "sessionId": "codex:b", "enrolled": true, "handle": "bob", "counts": {} }
            ]
        });
        st.apply_snapshot(&snap, Some("codex:b"), None, None);
        assert_eq!(st.active_session().unwrap().session_id, "codex:b");
        st.cycle_session();
        assert_eq!(st.active_session().unwrap().session_id, "claude:a");
        st.cycle_session();
        assert_eq!(st.active_session().unwrap().session_id, "codex:b");
    }
}
