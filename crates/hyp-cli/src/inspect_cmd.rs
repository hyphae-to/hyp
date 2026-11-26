//! Agent-first `hyp inspect` command for live session & mesh inspection.
//!
//! - One-shot mode queries `session.summary` (or `sessions.summary` under `--all` or when no
//!   session target is provided) synchronously over `connector.sock` / `connector.addr`.
//! - `--json` emits the standard `ui::JsonEnvelope` wrapping the exact summary payload.
//! - `--watch` streams live `inspect.watch` NDJSON updates with zero polling.
//! - Strictly metadata-only (ZERO message bodies, ZERO quarantined payloads)
//!   and strips all terminal control/escape sequences from untrusted fields.

use crate::statusline_cmd::sanitize_terminal_text;
use crate::ui::{
    EXIT_ERROR, EXIT_OK, JsonEnvelope, emit_error, print_json, print_next_steps, print_warnings,
};
use clap::Args;
use hyp_harness::sock::{
    MAX_SOCKET_LINE_BYTES, connect_daemon_async, daemon_rpc_sync, default_socket_path,
    read_bounded_line_async, write_ndjson_line_async,
};
use hyp_harness::wait::{infer_herdr_terminal_from_env, infer_session_id_from_env};
use serde_json::{Map, Value, json};
use std::fmt::Write as _;
use std::io::{self, IsTerminal, Write as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

const INSPECT_RPC_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Debug, Clone, Args)]
pub struct InspectArgs {
    /// Explicit session ID to inspect (e.g. claude:<id>)
    #[arg(long)]
    pub session: Option<String>,
    /// Resolve session by Herdr terminal ID (e.g. t4g)
    #[arg(long)]
    pub herdr_terminal: Option<String>,
    /// Optional Herdr terminal creation timestamp (ms) anti-recycle pin
    #[arg(long)]
    pub herdr_created_ms: Option<i64>,
    /// Resolve session by enrolled handle (e.g. alice or @alice)
    #[arg(long)]
    pub handle: Option<String>,
    /// Inspect all active sessions via `sessions.summary`
    #[arg(long)]
    pub all: bool,
    /// Stream live updates via zero-polling `inspect.watch`
    #[arg(long)]
    pub watch: bool,
    /// Explicit connector.sock / connector.addr path
    #[arg(long)]
    pub socket: Option<PathBuf>,
    /// Emit structured JSON (standard envelope one-shot, NDJSON frames under --watch)
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Clone, Default)]
pub struct ResolvedInspectTarget {
    pub session_id: Option<String>,
    pub herdr_terminal: Option<String>,
    pub herdr_created_ms: Option<i64>,
    pub handle: Option<String>,
    pub all: bool,
}

impl ResolvedInspectTarget {
    pub fn from_args(args: &InspectArgs) -> Self {
        if args.all {
            return Self {
                all: true,
                ..Default::default()
            };
        }
        let session_id = args
            .session
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToString::to_string);
        let herdr_terminal = args
            .herdr_terminal
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToString::to_string);
        let handle = args
            .handle
            .as_deref()
            .map(|s| s.trim().trim_start_matches('@'))
            .filter(|s| !s.is_empty())
            .map(ToString::to_string);

        if session_id.is_some() || herdr_terminal.is_some() || handle.is_some() {
            return Self {
                session_id,
                herdr_terminal,
                herdr_created_ms: args.herdr_created_ms,
                handle,
                all: false,
            };
        }

        // Fall back to ambient harness environment variables before defaulting to `--all`.
        if let Some(env_sid) = infer_session_id_from_env() {
            return Self {
                session_id: Some(env_sid),
                herdr_created_ms: args.herdr_created_ms,
                ..Default::default()
            };
        }
        if let Some(env_tid) = infer_herdr_terminal_from_env() {
            return Self {
                herdr_terminal: Some(env_tid),
                herdr_created_ms: args.herdr_created_ms,
                ..Default::default()
            };
        }

        Self {
            all: true,
            ..Default::default()
        }
    }

    pub fn build_rpc_packet(&self, watch: bool) -> Value {
        let mut map = Map::new();
        if watch {
            map.insert("type".into(), json!("inspect.watch"));
            map.insert("detail".into(), json!("full"));
            if !self.all {
                self.insert_selector_fields(&mut map);
            }
        } else if self.all {
            map.insert("type".into(), json!("sessions.summary"));
            map.insert("detail".into(), json!("full"));
        } else {
            map.insert("type".into(), json!("session.summary"));
            map.insert("detail".into(), json!("full"));
            self.insert_selector_fields(&mut map);
        }
        Value::Object(map)
    }

    fn insert_selector_fields(&self, map: &mut Map<String, Value>) {
        if let Some(ref sid) = self.session_id {
            map.insert("sessionId".into(), json!(sid));
        }
        if let Some(ref tid) = self.herdr_terminal {
            map.insert("herdrTerminalId".into(), json!(tid));
        }
        if let Some(ms) = self.herdr_created_ms {
            map.insert("herdrCreatedMs".into(), json!(ms));
        }
        if let Some(ref handle) = self.handle {
            map.insert("handle".into(), json!(handle));
        }
    }
}

/// Formats relative elapsed time between `then_ms` and `now_ms` concisely (`12s`, `4m`, `2h`, `3d`).
pub fn format_age_ms(then_ms: i64, now_ms: i64) -> String {
    if then_ms <= 0 || now_ms <= 0 {
        return "-".to_string();
    }
    let delta_secs = now_ms.saturating_sub(then_ms).max(0) / 1000;
    if delta_secs < 60 {
        format!("{delta_secs}s")
    } else if delta_secs < 3600 {
        format!("{}m", delta_secs / 60)
    } else if delta_secs < 86_400 {
        format!("{}h", delta_secs / 3600)
    } else {
        format!("{}d", delta_secs / 86_400)
    }
}

fn clean_str(val: Option<&Value>) -> String {
    val.and_then(Value::as_str)
        .map(sanitize_terminal_text)
        .unwrap_or_default()
}

fn render_table(out: &mut String, headers: &[&str], rows: &[Vec<String>]) {
    let mut widths: Vec<usize> = headers.iter().map(|h| h.chars().count()).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            if i < widths.len() {
                widths[i] = widths[i].max(cell.chars().count());
            }
        }
    }

    let _ = write!(out, "  ");
    for (i, h) in headers.iter().enumerate() {
        if i + 1 == headers.len() {
            let _ = write!(out, "{h}");
        } else {
            let _ = write!(out, "{:<width$}  ", h, width = widths[i]);
        }
    }
    out.push('\n');

    let _ = write!(out, "  ");
    for (i, &w) in widths.iter().enumerate() {
        let sep = "-".repeat(w.min(40));
        if i + 1 == widths.len() {
            let _ = write!(out, "{sep}");
        } else {
            let _ = write!(out, "{:<width$}  ", sep, width = w);
        }
    }
    out.push('\n');

    for row in rows {
        let _ = write!(out, "  ");
        for (i, cell) in row.iter().enumerate() {
            let w = widths.get(i).copied().unwrap_or(0);
            if i + 1 == row.len() {
                let _ = write!(out, "{cell}");
            } else {
                let _ = write!(out, "{:<width$}  ", cell, width = w);
            }
        }
        out.push('\n');
    }
}

fn render_single_session_block(out: &mut String, sess: &Value, peers_online: u64, now_ms: i64) {
    let sid = clean_str(sess.get("sessionId"));
    let harness = clean_str(sess.get("harness"));
    let handle = clean_str(sess.get("handle"));
    let enrolled = sess
        .get("enrolled")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let transport_kind = clean_str(sess.get("transportKind"));
    let has_live = sess
        .get("hasLiveTransport")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let delivery_mode = clean_str(sess.get("deliveryMode"));
    let focus_mode = sess
        .get("focusMode")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let allow_vips = sess
        .get("focusAllowInterruptVips")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let muted_all = sess
        .get("mutedAll")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let herdr_tid = clean_str(sess.get("herdrTerminalId"));

    let counts = sess.get("counts").and_then(Value::as_object);
    let c_subs = counts
        .and_then(|c| c.get("subscriptions"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let c_bridges = counts
        .and_then(|c| c.get("bridges"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let c_queued = counts
        .and_then(|c| c.get("queued"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let c_unnotified = counts
        .and_then(|c| c.get("unnotified"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let c_quarantined = counts
        .and_then(|c| c.get("quarantined"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let c_muted_rules = counts
        .and_then(|c| c.get("mutedRules"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let c_muted_archived = counts
        .and_then(|c| c.get("mutedArchived"))
        .and_then(Value::as_u64)
        .unwrap_or(0);

    let handle_disp = if enrolled && !handle.is_empty() {
        format!("@{handle}")
    } else {
        "(unenrolled)".to_string()
    };
    let transport_disp = if transport_kind.is_empty() {
        "none (hook/poll)".to_string()
    } else if has_live {
        format!("{transport_kind} (live)")
    } else {
        format!("{transport_kind} (idle)")
    };
    let focus_disp = if focus_mode {
        if allow_vips {
            "ON (VIPs ok)"
        } else {
            "ON (strict)"
        }
    } else {
        "OFF"
    };
    let muted_disp = if muted_all { "ALL" } else { "off" };

    let _ = writeln!(out, "Session:    {handle_disp}  [{sid}] ({harness})");
    if !herdr_tid.is_empty() {
        let _ = writeln!(out, "Herdr:      {herdr_tid}");
    }
    let _ = writeln!(
        out,
        "State:      transport={transport_disp}  mode={delivery_mode}  focus={focus_disp}  muted={muted_disp}  peersOnline={peers_online}"
    );
    let _ = writeln!(
        out,
        "Counts:     bridges={c_bridges}  subs={c_subs}  queued={c_queued} (unnotified={c_unnotified})  mutes={c_muted_rules} (archived={c_muted_archived})  quarantined={c_quarantined}"
    );

    if c_quarantined > 0 {
        let _ = writeln!(
            out,
            "WARN        {c_quarantined} item(s) quarantined by Local Security Gate — run `hyp gate review`"
        );
    }

    let details = sess.get("details").and_then(Value::as_object);

    // Linked bridges table (when any bridge target is linked)
    let bridges = details
        .and_then(|d| d.get("bridges"))
        .and_then(Value::as_array);
    if let Some(list) = bridges {
        if !list.is_empty() {
            out.push('\n');
            let _ = writeln!(out, "Bridges ({}):", list.len());
            let rows: Vec<Vec<String>> = list
                .iter()
                .map(|b| {
                    let label = clean_str(b.get("label"));
                    let role = clean_str(b.get("role"));
                    vec![
                        label,
                        if role.is_empty() {
                            "reader".to_string()
                        } else {
                            role
                        },
                    ]
                })
                .collect();
            render_table(out, &["TARGET", "ROLE"], &rows);
        }
    }

    // Subscriptions table
    let subs = details
        .and_then(|d| d.get("subscriptions"))
        .and_then(Value::as_array);
    out.push('\n');
    let _ = writeln!(out, "Subscriptions ({c_subs}):");
    match subs {
        Some(list) if !list.is_empty() => {
            let rows: Vec<Vec<String>> = list
                .iter()
                .map(|s| {
                    let id = clean_str(s.get("id"));
                    let topic = clean_str(s.get("topic"));
                    let origin = clean_str(s.get("originNode"));
                    let mode = clean_str(s.get("mode"));
                    let coalesce = s
                        .get("coalesceSeconds")
                        .and_then(Value::as_i64)
                        .map(|n| format!("{n}s"))
                        .unwrap_or_else(|| "0s".into());
                    let filter_sum = clean_str(s.get("filterSummary"));
                    let filters_disp = if filter_sum.is_empty() {
                        "*".to_string()
                    } else {
                        filter_sum
                    };
                    let topic_disp = if origin.is_empty() {
                        topic
                    } else {
                        format!("{origin}.{topic}")
                    };
                    vec![id, topic_disp, mode, coalesce, filters_disp]
                })
                .collect();
            render_table(out, &["ID", "TOPIC", "MODE", "COALESCE", "FILTERS"], &rows);
        }
        _ => {
            let _ = writeln!(out, "  (none)");
        }
    }

    // Queued Metadata table (strictly ZERO bodies!)
    let queued = details
        .and_then(|d| d.get("queuedItems"))
        .and_then(Value::as_array);
    out.push('\n');
    let _ = writeln!(out, "Queued Metadata ({c_queued}):");
    match queued {
        Some(list) if !list.is_empty() => {
            let rows: Vec<Vec<String>> = list
                .iter()
                .map(|q| {
                    let kind = clean_str(q.get("kind"));
                    let source = clean_str(q.get("source"));
                    let rec = q.get("receivedAt").and_then(Value::as_i64).unwrap_or(0);
                    let age = format_age_ms(rec, now_ms);
                    let urgency = clean_str(q.get("urgency"));
                    let notified = if q.get("notified").and_then(Value::as_bool).unwrap_or(false) {
                        "yes".to_string()
                    } else {
                        "no".to_string()
                    };
                    vec![kind, source, age, urgency, notified]
                })
                .collect();
            render_table(
                out,
                &["KIND", "SOURCE", "AGE", "URGENCY", "NOTIFIED"],
                &rows,
            );
        }
        _ => {
            let _ = writeln!(out, "  (empty)");
        }
    }

    // Delivery Rules & Mutes
    let rules = details
        .and_then(|d| d.get("rules"))
        .and_then(Value::as_array);
    let mutes = details
        .and_then(|d| d.get("mutes"))
        .and_then(Value::as_array);
    out.push('\n');
    let _ = writeln!(out, "Delivery Rules & Mutes:");
    let mut rm_rows: Vec<Vec<String>> = Vec::new();
    if let Some(list) = mutes {
        for m in list {
            let scope = clean_str(m.get("scope"));
            let pattern = clean_str(m.get("pattern"));
            let muted_at = m.get("mutedAt").and_then(Value::as_i64).unwrap_or(0);
            rm_rows.push(vec![
                "mute".to_string(),
                pattern,
                scope,
                format_age_ms(muted_at, now_ms),
            ]);
        }
    }
    if let Some(list) = rules {
        for r in list {
            let target = clean_str(r.get("target"));
            let delivery = clean_str(r.get("delivery"));
            rm_rows.push(vec!["rule".to_string(), target, delivery, "-".to_string()]);
        }
    }
    if rm_rows.is_empty() {
        let _ = writeln!(out, "  (none)");
    } else {
        render_table(
            out,
            &["TYPE", "TARGET / PATTERN", "ACTION / SCOPE", "AGE"],
            &rm_rows,
        );
    }

    // Channels
    let channel_entries = details
        .and_then(|d| d.get("channelEntries"))
        .and_then(Value::as_array);
    let channels_flat = details
        .and_then(|d| d.get("channels"))
        .and_then(Value::as_array);
    out.push('\n');
    let _ = writeln!(out, "Channels:");
    if let Some(entries) = channel_entries {
        if entries.is_empty() {
            let _ = writeln!(out, "  (none)");
        } else {
            let rows: Vec<Vec<String>> = entries
                .iter()
                .map(|c| {
                    vec![
                        clean_str(c.get("channel")),
                        clean_str(c.get("hostNode")),
                        clean_str(c.get("mode")),
                    ]
                })
                .collect();
            render_table(out, &["CHANNEL", "HOST", "MODE"], &rows);
        }
    } else if let Some(flat) = channels_flat {
        if flat.is_empty() {
            let _ = writeln!(out, "  (none)");
        } else {
            let joined: Vec<String> = flat
                .iter()
                .filter_map(Value::as_str)
                .map(sanitize_terminal_text)
                .collect();
            let _ = writeln!(out, "  {}", joined.join(", "));
        }
    } else {
        let _ = writeln!(out, "  (none)");
    }
}

/// Renders a `session.summary` or `sessions.summary` payload into crisp, sanitized plain text.
/// Reused by `hyp ui` as its non-TTY fallback.
pub fn render_inspect_text(payload: &Value, is_all: bool) -> String {
    let mut out = String::new();
    let now_ms = payload
        .get("updatedAt")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let rev = payload.get("rev").and_then(Value::as_u64).unwrap_or(0);
    let daemon = payload.get("daemon").and_then(Value::as_object);
    let node_id = daemon
        .and_then(|d| d.get("nodeId"))
        .and_then(Value::as_str)
        .map(sanitize_terminal_text)
        .unwrap_or_else(|| "unknown".into());
    let version = daemon
        .and_then(|d| d.get("version"))
        .and_then(Value::as_str)
        .map(sanitize_terminal_text)
        .unwrap_or_default();
    let profile = daemon
        .and_then(|d| d.get("profile"))
        .and_then(Value::as_str)
        .map(sanitize_terminal_text)
        .unwrap_or_default();
    let peers_online = daemon
        .and_then(|d| d.get("peersOnline"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let quarantined_global = daemon
        .and_then(|d| d.get("quarantinedGlobal"))
        .and_then(Value::as_u64)
        .unwrap_or(0);

    let _ = writeln!(
        out,
        "HYPHAE INSPECT  node={node_id}  v{version}  profile={profile}  peersOnline={peers_online}  rev={rev}"
    );
    if quarantined_global > 0 {
        let _ = writeln!(
            out,
            "WARN  Global quarantined items: {quarantined_global} — inspect with `hyp gate review`"
        );
    }
    out.push('\n');

    if is_all || payload.get("sessions").is_some() {
        let sessions = payload
            .get("sessions")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        if sessions.is_empty() {
            let _ = writeln!(out, "No active sessions registered on this node.");
        } else {
            for (idx, sess) in sessions.iter().enumerate() {
                if idx > 0 {
                    out.push_str(
                        "\n------------------------------------------------------------\n\n",
                    );
                }
                render_single_session_block(&mut out, sess, peers_online, now_ms);
            }
        }
    } else {
        match payload.get("session") {
            Some(sess) if !sess.is_null() => {
                render_single_session_block(&mut out, sess, peers_online, now_ms);
            }
            _ => {
                let _ = writeln!(out, "Session not found (unenrolled or inactive).");
            }
        }
    }

    out
}

fn collect_warnings_and_next(payload: &Value) -> (Vec<String>, Vec<String>) {
    let mut warnings = Vec::new();
    let mut next = Vec::new();

    let global_q = payload
        .get("daemon")
        .and_then(|d| d.get("quarantinedGlobal"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let sess_q = payload
        .get("session")
        .and_then(|s| s.get("counts"))
        .and_then(|c| c.get("quarantined"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let q = sess_q.max(global_q);
    if q > 0 {
        warnings.push(format!(
            "{q} item(s) held in Local Security Gate quarantine"
        ));
        next.push("hyp gate review".to_string());
    }
    (warnings, next)
}

fn summarize_payload(payload: &Value, is_all: bool) -> String {
    if is_all || payload.get("sessions").is_some() {
        let count = payload
            .get("sessions")
            .and_then(Value::as_array)
            .map(Vec::len)
            .unwrap_or(0);
        let node = payload
            .get("daemon")
            .and_then(|d| d.get("nodeId"))
            .and_then(Value::as_str)
            .map(sanitize_terminal_text)
            .unwrap_or_else(|| "local".into());
        format!("{count} session(s) on {node}")
    } else if let Some(sess) = payload.get("session").filter(|v| !v.is_null()) {
        let handle = clean_str(sess.get("handle"));
        let sid = clean_str(sess.get("sessionId"));
        let subs = sess
            .get("counts")
            .and_then(|c| c.get("subscriptions"))
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let queued = sess
            .get("counts")
            .and_then(|c| c.get("queued"))
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let who = if handle.is_empty() {
            sid
        } else {
            format!("@{handle}")
        };
        format!("{who}: {subs} subs, {queued} queued")
    } else {
        "session not found".to_string()
    }
}

fn run_inspect_watch_mode(
    socket_path: &Path,
    target: &ResolvedInspectTarget,
    as_json: bool,
) -> ExitCode {
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            return emit_error(
                "inspect",
                as_json,
                EXIT_ERROR,
                "RUNTIME_ERROR",
                format!("Failed to start async runtime: {e}"),
                None,
            );
        }
    };

    let packet = target.build_rpc_packet(true);
    let is_all = target.all;

    rt.block_on(async move {
        let (read_half, mut write_half) = match connect_daemon_async(socket_path).await {
            Ok(pair) => pair,
            Err(e) => {
                return emit_error(
                    "inspect",
                    as_json,
                    EXIT_ERROR,
                    "DAEMON_OFFLINE",
                    format!(
                        "Could not connect to local Hyphae daemon at {}: {e}",
                        socket_path.display()
                    ),
                    Some("Run `hyp daemon` or `hyp service start`".to_string()),
                );
            }
        };

        if let Err(e) = write_ndjson_line_async(&mut write_half, &packet).await {
            return emit_error(
                "inspect",
                as_json,
                EXIT_ERROR,
                "WATCH_WRITE_FAILED",
                format!("Failed sending inspect.watch request: {e}"),
                None,
            );
        }

        let mut reader = tokio::io::BufReader::new(read_half);
        let is_tty = io::stdout().is_terminal();
        let mut frame_idx: u64 = 0;

        loop {
            let line_opt = tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    return ExitCode::from(EXIT_OK);
                }
                res = read_bounded_line_async(&mut reader, MAX_SOCKET_LINE_BYTES) => {
                    match res {
                        Ok(Some(line)) => Some(line),
                        Ok(None) => {
                            return emit_error(
                                "inspect",
                                as_json,
                                EXIT_ERROR,
                                "WATCH_DISCONNECTED",
                                "Local Hyphae daemon closed the inspect.watch stream unexpectedly",
                                Some(
                                    "Check daemon status with `hyp status` or restart with `hyp service restart`."
                                        .to_string(),
                                ),
                            );
                        }
                        Err(e) => {
                            return emit_error(
                                "inspect",
                                as_json,
                                EXIT_ERROR,
                                "WATCH_READ_FAILED",
                                format!("inspect.watch stream error: {e}"),
                                None,
                            );
                        }
                    }
                }
            };

            let Some(line) = line_opt else {
                break;
            };
            let Ok(parsed) = serde_json::from_str::<Value>(&line) else {
                continue;
            };

            if parsed.get("type").and_then(Value::as_str) == Some("inspect.error") {
                let code = parsed
                    .get("code")
                    .and_then(Value::as_str)
                    .unwrap_or("INSPECT_ERROR");
                let msg = parsed
                    .get("error")
                    .and_then(Value::as_str)
                    .unwrap_or("inspect.watch failed");
                return emit_error("inspect", as_json, EXIT_ERROR, code, msg, None);
            }

            if as_json {
                let mut out = io::stdout().lock();
                if writeln!(out, "{line}").is_err() || out.flush().is_err() {
                    return ExitCode::from(EXIT_OK);
                }
            } else {
                let rendered = render_inspect_text(&parsed, is_all);
                let mut out = io::stdout().lock();
                if is_tty {
                    let _ = write!(out, "\x1b[2J\x1b[H{rendered}");
                } else {
                    if frame_idx > 0 {
                        let _ = writeln!(out, "============================================================");
                    }
                    let _ = write!(out, "{rendered}");
                }
                if out.flush().is_err() {
                    return ExitCode::from(EXIT_OK);
                }
            }
            frame_idx += 1;
        }

        ExitCode::from(EXIT_OK)
    })
}

pub fn run_inspect(args: &InspectArgs) -> ExitCode {
    let socket_path = args.socket.clone().unwrap_or_else(default_socket_path);
    let target = ResolvedInspectTarget::from_args(args);

    if args.watch {
        return run_inspect_watch_mode(&socket_path, &target, args.json);
    }

    let packet = target.build_rpc_packet(false);
    let res = daemon_rpc_sync(&socket_path, &packet, INSPECT_RPC_TIMEOUT);
    if !res.ok {
        let err_msg = res.error.unwrap_or_else(|| {
            format!(
                "Could not reach local Hyphae daemon at {}",
                socket_path.display()
            )
        });
        return emit_error(
            "inspect",
            args.json,
            EXIT_ERROR,
            "DAEMON_UNAVAILABLE",
            err_msg,
            Some("Run `hyp daemon` or `hyp service start`".to_string()),
        );
    }

    let payload = Value::Object(res.result.unwrap_or_default());
    let (warnings, next) = collect_warnings_and_next(&payload);

    if args.json {
        let env = JsonEnvelope {
            ok: true,
            command: "inspect".to_string(),
            summary: Some(summarize_payload(&payload, target.all)),
            data: Some(payload),
            warnings,
            next,
            error: None,
        };
        print_json(&env);
        return ExitCode::from(EXIT_OK);
    }

    print!("{}", render_inspect_text(&payload, target.all));
    print_warnings(&warnings);
    print_next_steps(&next);
    ExitCode::from(EXIT_OK)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_sanitized_tables_without_bodies_or_escape_sequences() {
        let payload = json!({
            "schemaVersion": 1,
            "rev": 7,
            "updatedAt": 1_750_000_120_000i64,
            "daemon": {
                "online": true,
                "nodeId": "alice@\x1b[31mmac",
                "version": "0.6.0",
                "profile": "local",
                "peersOnline": 2,
                "quarantinedGlobal": 1
            },
            "session": {
                "sessionId": "claude:s1",
                "harness": "claude",
                "enrolled": true,
                "handle": "alice\x1b]0;evil\x07",
                "transportKind": "herdr",
                "hasLiveTransport": true,
                "deliveryMode": "notify",
                "focusMode": true,
                "focusAllowInterruptVips": true,
                "mutedAll": false,
                "counts": {
                    "subscriptions": 1,
                    "queued": 1,
                    "unnotified": 1,
                    "quarantined": 1,
                    "mutedRules": 1,
                    "mutedArchived": 2,
                    "channels": 1,

                },
                "details": {
                    "subscriptions": [{
                        "id": "sub-1",
                        "originNode": "alice@mac",
                        "topic": "github",
                        "mode": "queue",
                        "coalesceSeconds": 15,
                        "filterSummary": "type=pr.opened"
                    }],
                    "queuedItems": [{
                        "receipt": "r-1",
                        "kind": "message",
                        "source": "bob/dev",
                        "originNode": "bob@lap",
                        "receivedAt": 1_750_000_060_000i64,
                        "notified": false,
                        "urgency": "queue"
                    }],
                    "mutes": [{
                        "pattern": "#noisy",
                        "scope": "session",
                        "mutedAt": 1_750_000_000_000i64
                    }],
                    "rules": [{
                        "target": "bob/dev",
                        "delivery": "interrupt"
                    }],
                    "channelEntries": [{
                        "hostNode": "alice@mac",
                        "channel": "#ops",
                        "mode": "open"
                    }],
                }
            }
        });

        let text = render_inspect_text(&payload, false);
        assert!(text.contains("@alice"));
        assert!(text.contains("sub-1"));
        assert!(text.contains("type=pr.opened"));
        assert!(text.contains("bob/dev"));
        assert!(text.contains("1m"));
        assert!(text.contains("#noisy"));
        assert!(text.contains("#ops"));
        assert!(text.contains("hyp gate review"));
        assert!(!text.contains('\x1b'));
        assert!(!text.contains("evil"));
    }

    #[test]
    fn formats_relative_ages() {
        assert_eq!(format_age_ms(1_000_000, 1_045_000), "45s");
        assert_eq!(format_age_ms(1_000_000, 1_180_000), "3m");
        assert_eq!(format_age_ms(1_000_000, 8_200_000), "2h");
        assert_eq!(format_age_ms(0, 1_000_000), "-");
    }

    #[test]
    fn u8_watch_mode_returns_error_exit_code_on_unexpected_daemon_disconnect() {
        use std::io::BufRead;

        let dir = tempfile::tempdir().expect("tempdir");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().unwrap();
        let addr_file = dir.path().join("mock-disconnect.addr");
        std::fs::write(&addr_file, format!("{addr}\n")).unwrap();

        let srv = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept client");
            let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            let _ = reader.read_line(&mut line);
            // Send one valid snapshot frame, then close socket abruptly (unexpected daemon EOF).
            let mut writer = stream;
            let frame = json!({
                "type": "inspect.snapshot",
                "rev": 1,
                "updatedAt": 1_750_000_000_000i64,
                "daemon": { "online": true, "nodeId": "alice@test", "version": "0.7.0", "profile": "local", "peersOnline": 0, "quarantinedGlobal": 0 },
                "sessions": []
            });
            let _ = writeln!(writer, "{frame}");
            let _ = writer.flush();
            drop(writer);
        });

        let args = InspectArgs {
            session: None,
            herdr_terminal: None,
            herdr_created_ms: None,
            handle: None,
            all: true,
            watch: true,
            socket: Some(addr_file),
            json: true,
        };
        let code = run_inspect(&args);
        srv.join().unwrap();
        assert_eq!(
            code,
            ExitCode::from(EXIT_ERROR),
            "U8: inspect --watch must return non-zero EXIT_ERROR when daemon disconnects unexpectedly"
        );
    }
}
