//! Pure-Rust Zero-Dependency Interactive TUI (`hyp ui`).
//!
//! Follows the exact zero-dep terminal pattern established in `wizard.rs`:
//! - Unix `/dev/tty` raw mode (`stty -g` -> `stty raw -echo min 0 time 1` -> unconditional restore
//!   via RAII `Drop` guard)
//! - Alternate screen (`\x1b[?1049h` / `\x1b[?1049l`) + synchronized redraw (`\x1b[?2026h`/`l`)
//! - Live zero-polling updates pushed over a background `inspect.watch` NDJSON stream
//! - Instant quick-control actions (`f` focus, `m` mute, `u`/`x` unsubscribe/unmute/leave,
//!   `s` switch session, `r` refresh, `1`–`5` / `Tab` / `←` / `→` tabs, `↑`/`↓`/`j`/`k` nav)
//! - Clean non-TTY / Windows interactive fallback printing `hyp inspect` output without hanging
//! - Pure deterministic frame renderer (`render_ui_frame`) verified across `24×80` and `18×40`
//!   viewports with strict column/row bounds and zero untrusted body leakage.

#![cfg_attr(not(unix), allow(dead_code))]

use crate::inspect_cmd::{InspectArgs, format_age_ms, run_inspect};
use crate::statusline_cmd::sanitize_terminal_text;
#[cfg(unix)]
use crate::term::{AltScreenGuard, RawTtyGuard};
#[cfg(unix)]
use crate::ui::EXIT_OK;
#[cfg(unix)]
use crate::wizard::{detect_color_mode, detect_terminal_size};
use clap::Args;
#[cfg(unix)]
use hyp_harness_client::wait::{infer_herdr_terminal_from_env, infer_session_id_from_env};
#[cfg(unix)]
use hyp_harness_ipc::sock::{
    MAX_SOCKET_LINE_BYTES, connect_daemon_async, daemon_rpc_sync, default_socket_path,
    read_bounded_line_async, write_ndjson_line_async,
};
use hyp_mycelium::ColorMode;
use serde_json::Value;
#[cfg(any(unix, test))]
use serde_json::json;
#[cfg(not(unix))]
use std::io::{self, IsTerminal};
#[cfg(unix)]
use std::io::{self, IsTerminal, Write};
#[cfg(unix)]
use std::path::Path;
use std::path::PathBuf;
#[cfg(unix)]
use std::process::ExitCode;
#[cfg(unix)]
use std::sync::Arc;
#[cfg(unix)]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(unix)]
use std::sync::mpsc;
#[cfg(unix)]
use std::thread;
use std::time::Duration;

mod kv;
use kv::KvBrowser;

/// Bounded reconnect backoff schedule for `inspect.watch`: 500ms -> 1s -> 2s -> 5s.
pub const WATCH_BACKOFF_SCHEDULE_MS: [u64; 4] = [500, 1_000, 2_000, 5_000];

/// Returns bounded reconnect delay for 1-based retry attempt `attempt`.
pub fn watch_reconnect_backoff(attempt: u32) -> Duration {
    let idx = (attempt.saturating_sub(1) as usize).min(WATCH_BACKOFF_SCHEDULE_MS.len() - 1);
    Duration::from_millis(WATCH_BACKOFF_SCHEDULE_MS[idx])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WatchStatus {
    #[default]
    Connecting,
    Live,
    Reconnecting {
        attempt: u32,
    },
}

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
    Kv,
}

impl UiTab {
    pub const ALL: [Self; 5] = [
        Self::Subscriptions,
        Self::Queue,
        Self::RulesAndMutes,
        Self::MeshAndChannels,
        Self::Kv,
    ];

    pub const fn title(self) -> &'static str {
        match self {
            Self::Subscriptions => "Subscriptions",
            Self::Queue => "Queue",
            Self::RulesAndMutes => "Rules & Mutes",
            Self::MeshAndChannels => "Mesh & Channels",
            Self::Kv => "KV",
        }
    }

    pub const fn short_title(self) -> &'static str {
        match self {
            Self::Subscriptions => "Subs",
            Self::Queue => "Queue",
            Self::RulesAndMutes => "Rules",
            Self::MeshAndChannels => "Mesh",
            Self::Kv => "KV",
        }
    }

    pub const fn number(self) -> usize {
        match self {
            Self::Subscriptions => 1,
            Self::Queue => 2,
            Self::RulesAndMutes => 3,
            Self::MeshAndChannels => 4,
            Self::Kv => 5,
        }
    }

    pub const fn next(self) -> Self {
        match self {
            Self::Subscriptions => Self::Queue,
            Self::Queue => Self::RulesAndMutes,
            Self::RulesAndMutes => Self::MeshAndChannels,
            Self::MeshAndChannels => Self::Kv,
            Self::Kv => Self::Subscriptions,
        }
    }

    pub const fn prev(self) -> Self {
        match self {
            Self::Subscriptions => Self::Kv,
            Self::Kv => Self::MeshAndChannels,
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
pub struct BridgeRow {
    pub label: String,
    pub role: String,
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
    pub count_bridges: u64,
    pub count_queued: u64,
    pub count_quarantined: u64,
    pub count_muted_rules: u64,
    pub count_muted_archived: u64,
    pub bridge_labels: Vec<String>,
    pub bridges: Vec<BridgeRow>,
    pub subscriptions: Vec<SubRow>,
    pub queued_items: Vec<QueuedRow>,
    pub rules_and_mutes: Vec<RuleOrMuteRow>,
    pub channels: Vec<ChannelRow>,
}

#[derive(Debug, Clone)]
pub struct UiState {
    pub daemon: DaemonView,
    kv: KvBrowser,
    pub sessions: Vec<SessionView>,
    pub active_session_idx: usize,
    pub active_tab: UiTab,
    pub selected_row: usize,
    pub scroll_offset: usize,
    pub rev: u64,
    pub updated_at: i64,
    pub watch_status: WatchStatus,
    pub status_message: Option<(String, bool)>,
    pub color_mode: ColorMode,
}

impl Default for UiState {
    fn default() -> Self {
        Self {
            daemon: DaemonView::default(),
            kv: KvBrowser::default(),
            sessions: Vec::new(),
            active_session_idx: 0,
            active_tab: UiTab::Subscriptions,
            selected_row: 0,
            scroll_offset: 0,
            rev: 0,
            updated_at: 0,
            watch_status: WatchStatus::Connecting,
            status_message: None,
            color_mode: ColorMode::Plain,
        }
    }
}

/// Qualifies a channel target as `<hostNode>/<channel>` so leaving a local channel
/// never resolves to a connected remote Hub (`resolve_channel_coord`).
pub fn qualify_channel_target(host_node: &str, channel: &str, local_node_id: &str) -> String {
    let ch = channel.trim();
    if ch.contains('/') {
        return ch.to_string();
    }
    let host = host_node.trim();
    let chosen_host = if !host.is_empty() {
        host
    } else {
        let local = local_node_id.trim();
        if !local.is_empty() { local } else { "local" }
    };
    format!("{chosen_host}/{ch}")
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

    let mut bridges: Vec<BridgeRow> = details
        .and_then(|d| d.get("bridges"))
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|b| {
                    let plugin = clean_str_or(b.get("plugin"), "");
                    let target = clean_str_or(b.get("target"), "");
                    let label = clean_opt_str(b.get("label")).unwrap_or_else(|| {
                        if !plugin.is_empty() && !target.is_empty() {
                            format!("{plugin}:{target}")
                        } else if !plugin.is_empty() {
                            plugin.clone()
                        } else {
                            target.clone()
                        }
                    });
                    if label.is_empty() {
                        return None;
                    }
                    let role = clean_str_or(b.get("role"), "reader");
                    Some(BridgeRow { label, role })
                })
                .collect()
        })
        .unwrap_or_default();

    let compact_bridge_labels: Vec<String> = val
        .get("bridges")
        .and_then(Value::as_array)
        .map(|arr| arr.iter().filter_map(|b| clean_opt_str(Some(b))).collect())
        .unwrap_or_default();

    if bridges.is_empty() && !compact_bridge_labels.is_empty() {
        bridges = compact_bridge_labels
            .iter()
            .map(|lbl| BridgeRow {
                label: lbl.clone(),
                role: "reader".to_string(),
            })
            .collect();
    }

    let bridge_labels = if !compact_bridge_labels.is_empty() {
        compact_bridge_labels
    } else {
        bridges.iter().map(|b| b.label.clone()).collect()
    };

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
    if let Some(mutes) = details
        .and_then(|d| d.get("mutes"))
        .and_then(Value::as_array)
    {
        for m in mutes {
            rules_and_mutes.push(RuleOrMuteRow::Mute {
                pattern: clean_str_or(m.get("pattern"), ""),
                scope: clean_str_or(m.get("scope"), "session"),
                muted_at: m.get("mutedAt").and_then(Value::as_i64).unwrap_or(0),
            });
        }
    }
    if let Some(rules) = details
        .and_then(|d| d.get("rules"))
        .and_then(Value::as_array)
    {
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
        count_bridges: counts
            .and_then(|c| c.get("bridges"))
            .and_then(Value::as_u64)
            .unwrap_or(bridges.len().max(bridge_labels.len()) as u64),
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
        bridge_labels,
        bridges,
        subscriptions,
        queued_items,
        rules_and_mutes,
        channels,
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
            if self.daemon.online {
                self.watch_status = WatchStatus::Live;
            } else if !matches!(self.watch_status, WatchStatus::Reconnecting { .. }) {
                self.watch_status = WatchStatus::Reconnecting { attempt: 1 };
            }
        }

        if let Some(kv) = snap.get("kv") {
            self.kv.apply_local_snapshot(kv, &self.daemon.node_id);
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

    /// Consistently computes `max(session.counts.quarantined, daemon.quarantinedGlobal)`.
    pub fn effective_quarantined(&self) -> u64 {
        self.active_session()
            .map(|s| s.count_quarantined)
            .unwrap_or(0)
            .max(self.daemon.quarantined_global)
    }

    pub fn is_offline(&self) -> bool {
        !self.daemon.online || matches!(self.watch_status, WatchStatus::Reconnecting { .. })
    }

    pub fn current_row_count(&self) -> usize {
        if self.active_tab == UiTab::Kv {
            return self.kv.row_count();
        }
        let Some(sess) = self.active_session() else {
            return 0;
        };
        match self.active_tab {
            UiTab::Subscriptions => sess.subscriptions.len(),
            UiTab::Queue => sess.queued_items.len(),
            UiTab::RulesAndMutes => sess.rules_and_mutes.len(),
            UiTab::MeshAndChannels => sess.channels.len(),
            UiTab::Kv => self.kv.row_count(),
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
            if self.active_tab == UiTab::Kv {
                self.kv.close();
            }
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
#[cfg(test)]
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

    let offline = state.is_offline();
    if offline {
        parts.push("OFFLINE (reconnecting…)".to_string());
    }

    let q = state.effective_quarantined();
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
        if !sess.bridge_labels.is_empty() {
            if sess.bridge_labels.len() == 1 {
                parts.push(sess.bridge_labels[0].clone());
            } else {
                parts.push(format!(
                    "{} +{}",
                    sess.bridge_labels[0],
                    sess.bridge_labels.len() - 1
                ));
            }
        } else if sess.count_bridges > 0 {
            parts.push(if sess.count_bridges == 1 {
                "1 bridge".to_string()
            } else {
                format!("{} bridges", sess.count_bridges)
            });
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
        if q > 0 {
            parts.push(format!("⚠ {q} held"));
        }
    } else if !offline {
        parts.push(format!("{} (no sessions)", state.daemon.node_id));
        if q > 0 {
            parts.push(format!("⚠ {q} held"));
        }
    } else if q > 0 {
        parts.push(format!("⚠ {q} held"));
    }

    let raw = parts.join(" · ");
    let fitted = truncate_plain(&raw, cols);
    style_wrap(&fitted, if offline { "1;31" } else { "1;32" }, use_color)
}

fn render_tab_bar(state: &UiState, cols: usize, use_color: bool) -> String {
    let compact = cols < 80;
    let mut built_plain = String::new();
    let mut built_styled = String::new();

    for (idx, tab) in UiTab::ALL.iter().enumerate() {
        let sep = if idx == 0 {
            ""
        } else if compact {
            " "
        } else {
            "  "
        };
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

    if use_color { built_styled } else { built_plain }
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
    if state.active_tab == UiTab::Kv {
        return state.kv.render(
            state.selected_row,
            state.updated_at,
            budget,
            cols,
            use_color,
        );
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
        UiTab::Queue => render_queue_tab(
            sess,
            state.selected_row,
            state.updated_at,
            budget,
            cols,
            use_color,
        ),
        UiTab::RulesAndMutes => render_rules_tab(
            sess,
            state.selected_row,
            state.updated_at,
            budget,
            cols,
            use_color,
        ),
        UiTab::MeshAndChannels => render_mesh_tab(
            &state.daemon,
            sess,
            state.selected_row,
            budget,
            cols,
            use_color,
        ),
        UiTab::Kv => state.kv.render(
            state.selected_row,
            state.updated_at,
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
    if sess.bridges.is_empty() && sess.subscriptions.is_empty() {
        out.push(style_wrap(
            &truncate_plain("No linked bridges or active stream subscriptions.", cols),
            "2",
            use_color,
        ));
        return out;
    }

    let narrow = cols < 60;

    if !sess.bridges.is_empty() && out.len() < budget {
        let reserve_for_subs = if sess.subscriptions.is_empty() {
            0
        } else {
            3.min(budget.saturating_sub(2))
        };
        let bridge_budget = budget.saturating_sub(reserve_for_subs);
        if bridge_budget > 0 {
            out.push(style_wrap(
                &truncate_plain(&format!("Bridges ({}):", sess.bridges.len()), cols),
                "1;36",
                use_color,
            ));
            let rows_for_bridges = bridge_budget.saturating_sub(1);
            for bridge in sess.bridges.iter().take(rows_for_bridges) {
                let line = if narrow {
                    format!("  ● {} ({})", bridge.label, bridge.role)
                } else {
                    format!(
                        "  ● {} {} bridge",
                        pad_or_truncate(&bridge.label, 24),
                        pad_or_truncate(&bridge.role, 10)
                    )
                };
                out.push(style_wrap(
                    &truncate_plain(&line, cols),
                    if bridge.role == "primary" { "36" } else { "2" },
                    use_color,
                ));
            }
        }
    }

    if out.len() >= budget {
        return out;
    }

    if sess.subscriptions.is_empty() {
        out.push(style_wrap(
            &truncate_plain("No active stream subscriptions.", cols),
            "2",
            use_color,
        ));
        return out;
    }

    let header = if narrow {
        format!("  {:<12} {:<12} {}", "TOPIC", "MODE", "ID")
    } else {
        format!(
            "  {:<14} {:<18} {:<9} {:<6} {}",
            "ID", "TOPIC", "MODE", "COAL", "FILTERS"
        )
    };
    out.push(style_wrap(&truncate_plain(&header, cols), "2", use_color));

    let list_budget = budget.saturating_sub(out.len());
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
        out.push(render_selectable_row(
            &line,
            abs_idx == selected,
            cols,
            use_color,
        ));
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
            &truncate_plain(
                "Queue empty — zero pending items (metadata-only view).",
                cols,
            ),
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
        out.push(render_selectable_row(
            &line,
            abs_idx == selected,
            cols,
            use_color,
        ));
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
            &truncate_plain(
                "No delivery rules or mutes active. Press `m` to mute all.",
                cols,
            ),
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
        out.push(render_selectable_row(
            &line,
            abs_idx == selected,
            cols,
            use_color,
        ));
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
        "Session: {} ({}) · delivery={} · archivedMuted={}",
        sess.session_id, sess.harness, sess.delivery_mode, sess.count_muted_archived
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
        let chan_budget = budget.saturating_sub(out.len());
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
            out.push(render_selectable_row(
                &line,
                abs_idx == selected,
                cols,
                use_color,
            ));
        }
    }

    out
}

fn render_status_line(state: &UiState, cols: usize, use_color: bool) -> String {
    if state.is_offline() {
        let offline_tag = match state.watch_status {
            WatchStatus::Reconnecting { attempt } if attempt > 1 => {
                format!("OFFLINE (reconnecting… attempt #{attempt})")
            }
            _ => "OFFLINE (reconnecting…)".to_string(),
        };
        let msg = match &state.status_message {
            Some((m, _)) if m.contains("OFFLINE") => m.clone(),
            Some((m, _)) => format!("{offline_tag} · {m}"),
            None => format!("rev {} · {offline_tag}", state.rev),
        };
        return style_wrap(&truncate_plain(&msg, cols), "1;31", use_color);
    }

    if let Some((ref msg, is_err)) = state.status_message {
        let fitted = truncate_plain(msg, cols);
        return if is_err {
            style_wrap(&fitted, "1;31", use_color)
        } else {
            style_wrap(&fitted, "33", use_color)
        };
    }

    let q = state.effective_quarantined();
    if q > 0 {
        let msg =
            format!("⚠ {q} item(s) quarantined by Local Security Gate — run `hyp gate review`");
        return style_wrap(&truncate_plain(&msg, cols), "1;31", use_color);
    }

    let meta = match state.watch_status {
        WatchStatus::Live => format!("rev {} · live inspect.watch (zero polling)", state.rev),
        WatchStatus::Connecting => format!("rev {} · connecting inspect.watch…", state.rev),
        WatchStatus::Reconnecting { .. } => format!("rev {} · OFFLINE (reconnecting…)", state.rev),
    };
    style_wrap(&truncate_plain(&meta, cols), "2", use_color)
}

fn render_footer_line(tab: UiTab, cols: usize, use_color: bool) -> String {
    let text = match tab {
        UiTab::Subscriptions => {
            if cols < 56 {
                "1-5 tab · ↑↓ · f focus · m mute · u unsub · s sess · q"
            } else {
                "1-5/Tab tabs · ↑↓ nav · f focus · m mute · u unsub · s sess · r refresh · q quit"
            }
        }
        UiTab::Queue => {
            if cols < 56 {
                "1-5 tab · ↑↓ · f focus · m mute src · s sess · q"
            } else {
                "1-5/Tab tabs · ↑↓ nav · f focus · m mute src · s sess · r refresh · q quit"
            }
        }
        UiTab::RulesAndMutes => {
            if cols < 56 {
                "1-5 tab · ↑↓ · f focus · m mute · u rm · s sess · q"
            } else {
                "1-5/Tab tabs · ↑↓ nav · f focus · m mute · u unmute/rm · s sess · r refresh · q quit"
            }
        }
        UiTab::MeshAndChannels => {
            if cols < 56 {
                "1-5 tab · ↑↓ · f focus · m mute · u leave · s sess · q"
            } else {
                "1-5/Tab tabs · ↑↓ nav · f focus · m mute · u leave ch · s sess · r refresh · q quit"
            }
        }
        UiTab::Kv => {
            if cols < 56 {
                "↑↓ · Enter view · b back · n/p page · r"
            } else {
                "1-5 tabs · ↑↓ select · Enter view · b back · n/p page · r refresh · q quit"
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
    Enter,
    Back,
    NextPage,
    PreviousPage,
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
        [b'5'] => TuiKey::TabNum(5),
        [b'\r'] | [b'\n'] => TuiKey::Enter,
        [b'b'] | [b'B'] | [0x7f] | [0x08] => TuiKey::Back,
        [b'n'] | [b'N'] => TuiKey::NextPage,
        [b'p'] | [b'P'] => TuiKey::PreviousPage,
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
enum WatchEvent {
    Snapshot(Value),
    Disconnected { reason: String, attempt: u32 },
}

#[cfg(unix)]
async fn sleep_interruptible(dur: Duration, stop: &AtomicBool) -> bool {
    let deadline = tokio::time::Instant::now() + dur;
    while !stop.load(Ordering::Relaxed) {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return true;
        }
        let step = (deadline - now).min(Duration::from_millis(50));
        tokio::time::sleep(step).await;
    }
    false
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
            let _ = tx.send(WatchEvent::Disconnected {
                reason: "Failed to build watch runtime".into(),
                attempt: 1,
            });
            return;
        };

        rt.block_on(async move {
            let mut attempt: u32 = 0;

            while !stop.load(Ordering::Relaxed) {
                let (read_half, mut write_half) = match connect_daemon_async(&socket_path).await {
                    Ok(pair) => pair,
                    Err(e) => {
                        attempt = attempt.saturating_add(1);
                        if tx
                            .send(WatchEvent::Disconnected {
                                reason: format!("Daemon offline: {e}"),
                                attempt,
                            })
                            .is_err()
                        {
                            break;
                        }
                        if !sleep_interruptible(watch_reconnect_backoff(attempt), &stop).await {
                            break;
                        }
                        continue;
                    }
                };

                if let Err(e) = write_ndjson_line_async(
                    &mut write_half,
                    &json!({ "type": "inspect.watch", "detail": "full" }),
                )
                .await
                {
                    attempt = attempt.saturating_add(1);
                    if tx
                        .send(WatchEvent::Disconnected {
                            reason: format!("Watch error: {e}"),
                            attempt,
                        })
                        .is_err()
                    {
                        break;
                    }
                    if !sleep_interruptible(watch_reconnect_backoff(attempt), &stop).await {
                        break;
                    }
                    continue;
                }

                let mut reader = tokio::io::BufReader::new(read_half);
                let mut saw_snapshot = false;
                let disconnect_reason = loop {
                    if stop.load(Ordering::Relaxed) {
                        return;
                    }
                    let line = tokio::time::timeout(
                        Duration::from_millis(250),
                        read_bounded_line_async(&mut reader, MAX_SOCKET_LINE_BYTES),
                    )
                    .await;
                    match line {
                        Err(_) => continue, // wake periodically to observe stop flag cleanly
                        Ok(Ok(Some(raw))) => {
                            if let Ok(val) = serde_json::from_str::<Value>(&raw) {
                                if !saw_snapshot {
                                    saw_snapshot = true;
                                    attempt = 0;
                                }
                                if tx.send(WatchEvent::Snapshot(val)).is_err() {
                                    return;
                                }
                            }
                        }
                        Ok(Ok(None)) => break "Daemon disconnected".to_string(),
                        Ok(Err(e)) => break format!("Watch error: {e}"),
                    }
                };

                if stop.load(Ordering::Relaxed) {
                    break;
                }
                attempt = attempt.saturating_add(1);
                if tx
                    .send(WatchEvent::Disconnected {
                        reason: disconnect_reason,
                        attempt,
                    })
                    .is_err()
                {
                    break;
                }
                if !sleep_interruptible(watch_reconnect_backoff(attempt), &stop).await {
                    break;
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

#[cfg(any(unix, test))]
fn build_action_rpc_packet(
    state: &UiState,
    key: TuiKey,
) -> Option<Result<(Value, String), (String, bool)>> {
    let Some(sess) = state.active_session() else {
        return Some(Err(("No active session selected".into(), true)));
    };

    let pair = match key {
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
                    toggle_mute_all_packet(sess)
                }
            } else {
                toggle_mute_all_packet(sess)
            }
        }
        TuiKey::Remove => match state.active_tab {
            UiTab::Subscriptions => {
                let Some(sub) = sess.subscriptions.get(state.selected_row) else {
                    return Some(Err(("No subscription selected".into(), true)));
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
                    return Some(Err(("No rule or mute selected".into(), true)));
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
                    return Some(Err(("No channel selected".into(), true)));
                };
                let qualified =
                    qualify_channel_target(&ch.host_node, &ch.channel, &state.daemon.node_id);
                (
                    json!({
                        "type": "session.leave_channel",
                        "sessionId": sess.session_id,
                        "channel": qualified
                    }),
                    format!("Left channel '{qualified}'"),
                )
            }
            UiTab::Queue => {
                return Some(Err(("Use `m` to mute the selected source".into(), false)));
            }
            UiTab::Kv => return None,
        },
        _ => return None,
    };

    Some(Ok(pair))
}

#[cfg(unix)]
fn perform_action_rpc(socket_path: &Path, state: &mut UiState, key: TuiKey) {
    let Some(built) = build_action_rpc_packet(state, key) else {
        return;
    };
    let (pkt, ok_label) = match built {
        Ok(pair) => pair,
        Err(msg) => {
            state.status_message = Some(msg);
            return;
        }
    };

    let res = daemon_rpc_sync(socket_path, &pkt, ACTION_RPC_TIMEOUT);
    if res.ok {
        state.status_message = Some((ok_label, false));
    } else {
        let err = res.error.unwrap_or_else(|| "Daemon RPC failed".into());
        state.status_message = Some((format!("Error: {}", sanitize_terminal_text(&err)), true));
    }
}

#[cfg(any(unix, test))]
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

#[cfg(unix)]
fn refresh_kv_report(socket: &Path, state: &mut UiState) {
    state.status_message = if state.kv.refresh(socket, &state.daemon.node_id) {
        None
    } else {
        Some(("Could not refresh KV metadata from the daemon".into(), true))
    };
    state.clamp_selection();
}

fn fallback_to_inspect(args: &UiArgs) -> crate::ui::CommandResult {
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

pub fn run_ui(args: &UiArgs) -> crate::ui::CommandResult {
    if !io::stdout().is_terminal() {
        return fallback_to_inspect(args);
    }

    #[cfg(not(unix))]
    {
        fallback_to_inspect(args)
    }

    #[cfg(unix)]
    {
        let Ok(mut tty) = RawTtyGuard::enter(false) else {
            return fallback_to_inspect(args);
        };
        let _alt = AltScreenGuard::inspector(!args.no_alt_screen);

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
            state.watch_status = WatchStatus::Reconnecting { attempt: 1 };
            state.status_message = Some((
                format!(
                    "OFFLINE (reconnecting…) · Daemon offline at {} — start with `hyp daemon`",
                    socket_path.display()
                ),
                true,
            ));
        }

        // Start zero-polling `inspect.watch` background listener with bounded reconnect backoff.
        let (tx, rx) = mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let watch_handle = spawn_watch_thread(socket_path.clone(), tx, Arc::clone(&stop));

        let (mut rows, mut cols) = detect_terminal_size();
        let mut dirty = true;
        let mut idle_ticks: u32 = 0;

        loop {
            let mut refresh_kv_page = false;
            // Drain all pending pushed watch snapshots without blocking.
            while let Ok(ev) = rx.try_recv() {
                match ev {
                    WatchEvent::Snapshot(snap) => {
                        let was_offline = state.is_offline();
                        let previous_rev = state.rev;
                        state.apply_snapshot(
                            &snap,
                            prefer_session.as_deref(),
                            prefer_herdr.as_deref(),
                            prefer_handle.as_deref(),
                        );
                        refresh_kv_page |= state.rev != previous_rev;
                        if was_offline && state.daemon.online {
                            state.status_message = Some(("Reconnected to daemon".into(), false));
                        }
                        dirty = true;
                    }
                    WatchEvent::Disconnected { reason, attempt } => {
                        state.daemon.online = false;
                        state.kv.close();
                        state.watch_status = WatchStatus::Reconnecting { attempt };
                        state.status_message =
                            Some((format!("OFFLINE (reconnecting…) · {reason}"), true));
                        dirty = true;
                    }
                }
            }

            if refresh_kv_page && state.active_tab == UiTab::Kv && state.daemon.online {
                state
                    .kv
                    .refresh_open_page(&socket_path, Some(&state.daemon.node_id));
                state.clamp_selection();
            }

            if dirty {
                let frame = render_ui_frame(&state, rows, cols);
                draw_frame_sync(&frame);
                dirty = false;
            }

            match tty.read_key_timeout(parse_tui_key) {
                Ok(Some(key)) => {
                    idle_ticks = 0;
                    let was_kv = state.active_tab == UiTab::Kv;
                    match key {
                        TuiKey::Quit => break,
                        TuiKey::TabNum(1) => state.select_tab(UiTab::Subscriptions),
                        TuiKey::TabNum(2) => state.select_tab(UiTab::Queue),
                        TuiKey::TabNum(3) => state.select_tab(UiTab::RulesAndMutes),
                        TuiKey::TabNum(4) => state.select_tab(UiTab::MeshAndChannels),
                        TuiKey::TabNum(5) => state.select_tab(UiTab::Kv),
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
                        TuiKey::Enter if was_kv => {
                            if state.kv.open_selected(&socket_path, state.selected_row) {
                                state.selected_row = 0;
                                state.status_message = None;
                            } else {
                                state.status_message =
                                    Some(("Could not open the selected KV record".into(), true));
                            }
                        }
                        TuiKey::Back if was_kv => {
                            state.kv.back();
                            state.selected_row = 0;
                            state.status_message = None;
                        }
                        TuiKey::NextPage | TuiKey::PreviousPage if was_kv => {
                            if state.kv.page(&socket_path, key == TuiKey::NextPage) {
                                state.selected_row = 0;
                                state.status_message = None;
                            }
                        }
                        TuiKey::Refresh if was_kv => {
                            let (r, c) = detect_terminal_size();
                            rows = r;
                            cols = c;
                            refresh_kv_report(&socket_path, &mut state);
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
                                if !matches!(state.watch_status, WatchStatus::Reconnecting { .. }) {
                                    state.watch_status = WatchStatus::Reconnecting { attempt: 1 };
                                }
                                state.status_message = Some((
                                    "OFFLINE (reconnecting…) · Refresh failed: daemon offline"
                                        .into(),
                                    true,
                                ));
                            }
                        }
                        TuiKey::Focus | TuiKey::Mute | TuiKey::Remove if !was_kv => {
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
                        _ => continue,
                    }
                    if !was_kv && state.active_tab == UiTab::Kv {
                        refresh_kv_report(&socket_path, &mut state);
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
        crate::ui::CommandResult::new("ui", false, Ok(ExitCode::from(EXIT_OK)))
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
                }
            }]
        });
        st.apply_snapshot(&snap, None, None, None);
        st
    }

    #[test]
    fn render_ui_frame_fits_strictly_at_24x80_and_18x40_across_all_tabs() {
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
                            }
                            UiTab::Kv => {
                                assert!(joined.contains("KV namespaces"));
                                assert!(joined.contains("No visible KV records."));
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
        assert_eq!(parse_tui_key(b"5"), TuiKey::TabNum(5));
        assert_eq!(parse_tui_key(b"\r"), TuiKey::Enter);
        assert_eq!(parse_tui_key(b"b"), TuiKey::Back);
        assert_eq!(parse_tui_key(b"n"), TuiKey::NextPage);
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

    #[test]
    fn watch_reconnect_backoff_schedule_is_bounded() {
        assert_eq!(watch_reconnect_backoff(1), Duration::from_millis(500));
        assert_eq!(watch_reconnect_backoff(2), Duration::from_millis(1_000));
        assert_eq!(watch_reconnect_backoff(3), Duration::from_millis(2_000));
        assert_eq!(watch_reconnect_backoff(4), Duration::from_millis(5_000));
        assert_eq!(watch_reconnect_backoff(10), Duration::from_millis(5_000));
        assert_eq!(
            watch_reconnect_backoff(u32::MAX),
            Duration::from_millis(5_000)
        );
    }

    #[test]
    fn offline_state_shows_persistent_reconnecting_banner_never_claims_live() {
        let mut st = sample_state_with_ansi_traps();
        st.color_mode = ColorMode::Plain;
        // Simulate disconnect AFTER a live snapshot populated active_session()
        st.daemon.online = false;
        st.watch_status = WatchStatus::Reconnecting { attempt: 2 };
        st.status_message = None;

        let frame = render_ui_frame(&st, 24, 80);
        let joined = frame.join("\n");
        assert!(
            frame[0].contains("OFFLINE (reconnecting…)"),
            "header must display persistent offline indicator even with stale session: {:?}",
            frame[0]
        );
        assert!(
            joined.contains("OFFLINE (reconnecting…"),
            "status bar must show offline reconnecting status: {joined}"
        );
        assert!(
            !joined.contains("live inspect.watch"),
            "offline frame must NEVER claim live inspect.watch: {joined}"
        );

        // Even if a transient non-offline status_message was set, offline remains clearly visible!
        st.status_message = Some(("Switched to @alice".into(), false));
        let frame2 = render_ui_frame(&st, 24, 80);
        assert!(frame2[0].contains("OFFLINE (reconnecting…)"));
        assert!(!frame2.join("\n").contains("live inspect.watch"));
    }

    #[test]
    fn bridges_surface_in_subs_tab_and_header_within_viewport_bounds() {
        let mut st = UiState {
            color_mode: ColorMode::Plain,
            ..Default::default()
        };
        let snap = json!({
            "rev": 4,
            "daemon": { "online": true, "nodeId": "alice@macbook", "quarantinedGlobal": 0 },
            "sessions": [{
                "sessionId": "claude:b1",
                "harness": "claude",
                "enrolled": true,
                "handle": "alice",
                "bridges": ["telegram:\x1b[31mpersonal\x1b]0;pwn\x07"],
                "counts": { "bridges": 1, "subscriptions": 1, "queued": 0, "quarantined": 0 },
                "details": {
                    "bridges": [
                        {
                            "plugin": "telegram",
                            "target": "personal",
                            "label": "telegram:\x1b[31mpersonal\x1b]0;pwn\x07",
                            "role": "primary"
                        }
                    ],
                    "subscriptions": [
                        {
                            "id": "sub-ci-1",
                            "originNode": "alice@macbook",
                            "topic": "ci.builds",
                            "mode": "queue",
                            "coalesceSeconds": 10,
                            "filterSummary": "branch=main"
                        }
                    ]
                }
            }]
        });
        st.apply_snapshot(&snap, None, None, None);

        for (rows, cols) in [(24usize, 80usize), (18, 40), (10, 32)] {
            for mode in [ColorMode::Plain, ColorMode::TrueColor] {
                st.color_mode = mode;
                let frame = render_ui_frame(&st, rows, cols);
                assert_eq!(frame.len(), rows);
                for line in &frame {
                    assert!(
                        visible_width(line) <= cols,
                        "overflow at {rows}x{cols}: {line:?}"
                    );
                }
                let joined = frame.join("\n");
                assert!(!joined.contains("pwn"));
                assert!(!joined.contains("\x1b]0;"));
                if rows == 24 && cols == 80 && mode == ColorMode::Plain {
                    assert!(frame[0].contains("telegram:personal"));
                    assert!(joined.contains("Bridges (1):"));
                    assert!(joined.contains("telegram:personal"));
                    assert!(joined.contains("primary"));
                    assert!(joined.contains("ci.builds"));
                }
            }
        }
    }

    #[test]
    fn leave_channel_action_always_sends_qualified_host_node_channel() {
        assert_eq!(
            qualify_channel_target("alice@macbook", "#ops", "alice@macbook"),
            "alice@macbook/#ops"
        );
        assert_eq!(
            qualify_channel_target("", "#ops", "alice@macbook"),
            "alice@macbook/#ops"
        );
        assert_eq!(qualify_channel_target("", "#ops", ""), "local/#ops");
        assert_eq!(
            qualify_channel_target("acme-hub", "#release", "alice@macbook"),
            "acme-hub/#release"
        );
        assert_eq!(
            qualify_channel_target("local", "acme-hub/#release", "alice@macbook"),
            "acme-hub/#release"
        );

        let mut st = sample_state_with_ansi_traps();
        st.select_tab(UiTab::MeshAndChannels);
        // Row 0: local channel `#ops` hosted on `alice@macbook`
        st.selected_row = 0;
        let (pkt0, _) = build_action_rpc_packet(&st, TuiKey::Remove)
            .unwrap()
            .unwrap();
        assert_eq!(pkt0["type"], "session.leave_channel");
        assert_eq!(pkt0["channel"], "alice@macbook/#ops");

        // Row 1: remote channel `#release` hosted on `acme-hub`
        st.selected_row = 1;
        let (pkt1, _) = build_action_rpc_packet(&st, TuiKey::Remove)
            .unwrap()
            .unwrap();
        assert_eq!(pkt1["type"], "session.leave_channel");
        assert_eq!(pkt1["channel"], "acme-hub/#release");
    }

    #[test]
    fn effective_quarantined_uses_max_of_session_and_global() {
        let mut st = UiState {
            color_mode: ColorMode::Plain,
            ..Default::default()
        };
        let snap = json!({
            "rev": 2,
            "daemon": { "online": true, "nodeId": "alice@mac", "quarantinedGlobal": 3 },
            "sessions": [{
                "sessionId": "claude:q0",
                "enrolled": true,
                "handle": "alice",
                "counts": { "quarantined": 0 }
            }]
        });
        st.apply_snapshot(&snap, None, None, None);
        assert_eq!(st.effective_quarantined(), 3);
        let frame = render_ui_frame(&st, 24, 80);
        assert!(frame[0].contains("⚠ 3 held"));
        assert!(frame.join("\n").contains("3 item(s) quarantined"));
    }

    #[cfg(unix)]
    #[test]
    fn watch_thread_reconnects_after_disconnect_over_tcp_loopback() {
        use std::io::{BufRead, BufReader, Write as _};
        use std::net::TcpListener;

        let dir = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let addr_file = dir.path().join("reconnect.addr");
        std::fs::write(&addr_file, format!("{addr}\n")).unwrap();

        let server = thread::spawn(move || {
            // Connection 1: read inspect.watch, send rev=1, then close abruptly to simulate daemon restart.
            let (stream1, _) = listener.accept().unwrap();
            let mut r1 = BufReader::new(stream1.try_clone().unwrap());
            let mut req1 = String::new();
            let _ = r1.read_line(&mut req1);
            let mut w1 = stream1;
            let _ = writeln!(
                w1,
                "{}",
                json!({ "type": "inspect.snapshot", "rev": 1, "daemon": { "online": true, "nodeId": "local" }, "sessions": [] })
            );
            let _ = w1.flush();
            drop(w1);
            drop(r1);

            // Connection 2: watch thread must reconnect automatically and receive rev=2!
            let (stream2, _) = listener.accept().unwrap();
            let mut r2 = BufReader::new(stream2.try_clone().unwrap());
            let mut req2 = String::new();
            let _ = r2.read_line(&mut req2);
            let mut w2 = stream2;
            let _ = writeln!(
                w2,
                "{}",
                json!({ "type": "inspect.snapshot", "rev": 2, "daemon": { "online": true, "nodeId": "local" }, "sessions": [] })
            );
            let _ = w2.flush();
            // Keep connection alive briefly until client stops.
            thread::sleep(Duration::from_millis(300));
        });

        let (tx, rx) = mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let handle = spawn_watch_thread(addr_file, tx, Arc::clone(&stop));

        // Expect Snapshot(rev=1), then Disconnected(attempt=1), then Snapshot(rev=2)!
        let ev1 = rx.recv_timeout(Duration::from_secs(3)).unwrap();
        match ev1 {
            WatchEvent::Snapshot(v) => assert_eq!(v["rev"], 1),
            WatchEvent::Disconnected { reason, .. } => {
                panic!("unexpected early disconnect: {reason}")
            }
        }

        let ev2 = rx.recv_timeout(Duration::from_secs(3)).unwrap();
        match ev2 {
            WatchEvent::Disconnected { attempt, .. } => assert_eq!(attempt, 1),
            WatchEvent::Snapshot(v) => panic!("expected disconnect before reconnect, got {v}"),
        }

        let ev3 = rx.recv_timeout(Duration::from_secs(3)).unwrap();
        match ev3 {
            WatchEvent::Snapshot(v) => assert_eq!(v["rev"], 2),
            WatchEvent::Disconnected { reason, .. } => {
                panic!("expected reconnected snapshot, got disconnect: {reason}")
            }
        }

        stop.store(true, Ordering::Relaxed);
        handle.join().unwrap();
        server.join().unwrap();
    }
}
