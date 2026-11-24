//! `hyp wakeup` — Durable local wakeup scheduler & external OS trigger CLI.
//!
//! Subcommands:
//! - `hyp wakeup enable [--mcp-tool auto|always|never]`
//! - `hyp wakeup disable`
//! - `hyp wakeup set (--in <dur> | --at <rfc3339> | --cron <expr>) --label <label> ...`
//! - `hyp wakeup list [--all]`
//! - `hyp wakeup cancel <id>`
//! - `hyp wakeup fire [--id <id>] [--to <handle>] [--label <label>] [--note <text>] ...`
//! - `hyp wakeup emit` (reads bounded JSON <= 64 KiB strictly from stdin)

use crate::config_file::{
    default_node_id, ensure_dir, ensure_v2_node_json_defaults, read_json_object_or_empty,
    resolve_config_path_for_write, resolve_state_dir, write_atomic_json,
};
use crate::ui::{
    EXIT_ERROR, EXIT_OK, EXIT_USAGE, JsonEnvelope, emit_error, print_json, print_next_steps,
};
use clap::{Subcommand, ValueEnum};
use hyp_crypto::rfc3339::parse_rfc3339_millis;
use hyp_harness::sock::{
    DEFAULT_SOCKET_FILENAME, DaemonRpcResult, daemon_rpc_sync, default_socket_path,
};
use hyp_node::engine::NodeProfile;
use hyp_proto::address::{LOCAL_NODE_ID, is_valid_handle};
use hyp_proto::cron::{CronExpr, CronTimezone};
use hyp_store::{
    DEFAULT_WAKEUP_TTL_MS, NodeDb, StoreError, WakeupInsert, WakeupLimits, WakeupRecord,
    WakeupState, WakeupTriggerKind, WakeupUrgency, epoch_ms_to_rfc3339, now_ms, parse_address,
};
use serde_json::{Map, Value, json};
use std::io::{self, Read as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

const WAKEUP_RPC_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_EMIT_STDIN_BYTES: u64 = 64 * 1024;
const MAX_TIMER_IN_SECONDS: i64 = 2_592_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum CliWakeupMcpToolMode {
    Auto,
    Always,
    Never,
}

impl CliWakeupMcpToolMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Always => "always",
            Self::Never => "never",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum CliWakeupUrgency {
    Queue,
    Interrupt,
    Notify,
}

impl CliWakeupUrgency {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Queue => "queue",
            Self::Interrupt => "interrupt",
            Self::Notify => "notify",
        }
    }

    pub const fn to_store_urgency(self) -> WakeupUrgency {
        match self {
            Self::Queue => WakeupUrgency::Queue,
            Self::Interrupt => WakeupUrgency::Interrupt,
            Self::Notify => WakeupUrgency::Notify,
        }
    }
}

#[derive(Subcommand)]
pub enum WakeupCommand {
    /// Enable the opt-in durable wakeup scheduler in node.json
    Enable {
        /// Exposure mode for the conditional `hyp_wakeup` MCP tool (auto, always, or never)
        #[arg(long, value_enum, default_value_t = CliWakeupMcpToolMode::Auto)]
        mcp_tool: CliWakeupMcpToolMode,
        /// Explicit node.json path
        #[arg(long)]
        config: Option<PathBuf>,
        /// Explicit state directory
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Output structured JSON envelope
        #[arg(long)]
        json: bool,
    },
    /// Disable the durable wakeup scheduler in node.json
    Disable {
        /// Explicit node.json path
        #[arg(long)]
        config: Option<PathBuf>,
        /// Explicit state directory
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Output structured JSON envelope
        #[arg(long)]
        json: bool,
    },
    /// Create a durable one-shot timer or 5-field cron wakeup
    Set {
        /// Relative timer delay (e.g. 30s, 5m, 2h, 1d, 1h30m)
        #[arg(long = "in")]
        in_duration: Option<String>,
        /// Absolute RFC 3339 fire timestamp (e.g. 2026-12-01T09:00:00Z)
        #[arg(long)]
        at: Option<String>,
        /// 5-field cron expression (e.g. "0 9 * * 1-5")
        #[arg(long)]
        cron: Option<String>,
        /// Cron timezone interpretation (local or UTC)
        #[arg(long, default_value = "local")]
        timezone: String,
        /// Short human-readable label for the wakeup
        #[arg(long)]
        label: String,
        /// Delivery note carried into the wakeup event (defaults to label if omitted)
        #[arg(long)]
        note: Option<String>,
        /// Target local agent handle (defaults to local `wakeup` topic when omitted)
        #[arg(long)]
        to: Option<String>,
        /// Delivery urgency (queue, interrupt, or notify)
        #[arg(long, value_enum, default_value_t = CliWakeupUrgency::Queue)]
        urgency: CliWakeupUrgency,
        /// Mailbox TTL in seconds (default: 3600)
        #[arg(long)]
        ttl: Option<i64>,
        /// Maximum number of executions before auto-completing
        #[arg(long)]
        max_iterations: Option<u64>,
        /// Allowlisted Tier 4 cold-revival template name
        #[arg(long)]
        template: Option<String>,
        /// Explicit local daemon socket/address path
        #[arg(long)]
        socket: Option<PathBuf>,
        /// Explicit state directory containing node.sqlite
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Output structured JSON envelope
        #[arg(long)]
        json: bool,
    },
    /// List scheduled wakeups (active by default, or --all for all states)
    List {
        /// Include completed, cancelled, paused, and failed wakeups
        #[arg(long)]
        all: bool,
        /// Explicit local daemon socket/address path
        #[arg(long)]
        socket: Option<PathBuf>,
        /// Explicit state directory containing node.sqlite
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Output structured JSON envelope
        #[arg(long)]
        json: bool,
    },
    /// Cancel a scheduled wakeup by ID
    Cancel {
        /// Wakeup ID to cancel
        id: String,
        /// Explicit local daemon socket/address path
        #[arg(long)]
        socket: Option<PathBuf>,
        /// Explicit state directory containing node.sqlite
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Output structured JSON envelope
        #[arg(long)]
        json: bool,
    },
    /// One-line trigger for crontab, systemd --user, or launchd to fire a wakeup over local daemon IPC
    Fire {
        /// Optional persisted wakeup ID to trigger immediately
        #[arg(long)]
        id: Option<String>,
        /// Target local handle for ad-hoc wakeup fire
        #[arg(long)]
        to: Option<String>,
        /// Label for ad-hoc wakeup fire
        #[arg(long)]
        label: Option<String>,
        /// Note body for ad-hoc wakeup fire
        #[arg(long)]
        note: Option<String>,
        /// Delivery urgency (queue, interrupt, or notify)
        #[arg(long, value_enum, default_value_t = CliWakeupUrgency::Queue)]
        urgency: CliWakeupUrgency,
        /// Explicit local daemon socket/address path
        #[arg(long)]
        socket: Option<PathBuf>,
        /// Explicit state directory containing node.sqlite
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Output structured JSON envelope
        #[arg(long)]
        json: bool,
    },
    /// Read bounded JSON (<= 64 KiB CloudEvents v1.0 or compact object) from stdin and emit to local daemon
    Emit {
        /// Explicit local daemon socket/address path
        #[arg(long)]
        socket: Option<PathBuf>,
        /// Explicit state directory
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Output structured JSON envelope
        #[arg(long)]
        json: bool,
    },
}

pub fn run_wakeup(command: WakeupCommand) -> ExitCode {
    match command {
        WakeupCommand::Enable {
            mcp_tool,
            config,
            state_dir,
            json,
        } => run_wakeup_toggle(true, Some(mcp_tool), config, state_dir, json),
        WakeupCommand::Disable {
            config,
            state_dir,
            json,
        } => run_wakeup_toggle(false, None, config, state_dir, json),
        WakeupCommand::Set {
            in_duration,
            at,
            cron,
            timezone,
            label,
            note,
            to,
            urgency,
            ttl,
            max_iterations,
            template,
            socket,
            state_dir,
            json,
        } => run_wakeup_set(
            in_duration,
            at,
            cron,
            timezone,
            label,
            note,
            to,
            urgency,
            ttl,
            max_iterations,
            template,
            socket,
            state_dir,
            json,
        ),
        WakeupCommand::List {
            all,
            socket,
            state_dir,
            json,
        } => run_wakeup_list(all, socket, state_dir, json),
        WakeupCommand::Cancel {
            id,
            socket,
            state_dir,
            json,
        } => run_wakeup_cancel(id, socket, state_dir, json),
        WakeupCommand::Fire {
            id,
            to,
            label,
            note,
            urgency,
            socket,
            state_dir,
            json,
        } => run_wakeup_fire(id, to, label, note, urgency, socket, state_dir, json),
        WakeupCommand::Emit {
            socket,
            state_dir,
            json,
        } => run_wakeup_emit(socket, state_dir, json),
    }
}

/// Parses a human-friendly relative duration (`30s`, `5m`, `2h`, `1d`, `1h30m`, or bare seconds)
/// into whole positive seconds.
pub fn parse_duration_seconds(raw: &str) -> Result<i64, String> {
    let s = raw.trim();
    if s.is_empty() {
        return Err("duration cannot be empty".to_string());
    }
    if let Ok(secs) = s.parse::<i64>() {
        if secs <= 0 {
            return Err("duration must be positive (>= 1s)".to_string());
        }
        return Ok(secs);
    }

    let bytes = s.as_bytes();
    let mut i = 0usize;
    let mut total: i64 = 0;
    let mut parts = 0usize;

    while i < bytes.len() {
        let start = i;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
        if i == start {
            return Err(format!(
                "invalid duration '{raw}' (expected forms like 30s, 5m, 2h, 1d, or 1h30m)"
            ));
        }
        let num_str = &s[start..i];
        let val: i64 = num_str
            .parse()
            .map_err(|_| format!("duration number overflow in '{raw}'"))?;
        if i >= bytes.len() {
            return Err(format!(
                "missing duration unit in '{raw}' (use s, m, h, or d)"
            ));
        }
        let unit = bytes[i].to_ascii_lowercase();
        i += 1;
        let mult: i64 = match unit {
            b's' => 1,
            b'm' => 60,
            b'h' => 3_600,
            b'd' => 86_400,
            _ => {
                return Err(format!(
                    "unsupported duration unit '{}' in '{raw}' (use s, m, h, or d)",
                    unit as char
                ));
            }
        };
        let segment = val
            .checked_mul(mult)
            .ok_or_else(|| format!("duration overflow in '{raw}'"))?;
        total = total
            .checked_add(segment)
            .ok_or_else(|| format!("duration overflow in '{raw}'"))?;
        parts += 1;
    }

    if parts == 0 || total <= 0 {
        return Err(format!("duration '{raw}' must be >= 1s"));
    }
    Ok(total)
}

fn resolve_wakeup_socket(socket_arg: Option<&Path>, state_dir_arg: Option<&Path>) -> PathBuf {
    if let Some(s) = socket_arg {
        return s.to_path_buf();
    }
    if let Some(dir) = state_dir_arg {
        return dir.join(DEFAULT_SOCKET_FILENAME);
    }
    default_socket_path()
}

fn try_daemon_rpc_if_present(socket_path: &Path, packet: &Value) -> Option<DaemonRpcResult> {
    let addr_sibling = socket_path.with_file_name("connector.addr");
    let has_endpoint = socket_path.exists()
        || addr_sibling.exists()
        || socket_path
            .to_str()
            .is_some_and(|s| s.starts_with("tcp://") || s.parse::<std::net::SocketAddr>().is_ok());
    if !has_endpoint {
        return None;
    }
    let res = daemon_rpc_sync(socket_path, packet, WAKEUP_RPC_TIMEOUT);
    if res.ok || res.error.is_some() {
        Some(res)
    } else {
        None
    }
}

fn validate_local_target_handle(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("target handle cannot be empty".to_string());
    }
    if trimmed.starts_with('#') || trimmed.contains(':') {
        return Err(format!(
            "wakeup target '{raw}' must be a local handle, not a channel or bridge"
        ));
    }
    if trimmed.contains('/') {
        let Some((node_part, handle_part)) = parse_address(trimmed) else {
            return Err(format!("invalid target address '{raw}'"));
        };
        if node_part != LOCAL_NODE_ID {
            return Err(format!(
                "cross-node wakeup target '{raw}' is not permitted; use local handles only"
            ));
        }
        return Ok(handle_part.to_string());
    }
    if !is_valid_handle(trimmed) {
        return Err(format!(
            "invalid handle '{raw}' (expected /^[a-z0-9][a-z0-9._-]{{0,63}}$/)"
        ));
    }
    Ok(trimmed.to_string())
}

fn wakeup_record_to_json(rec: &WakeupRecord) -> Value {
    json!({
        "id": rec.id,
        "ownerSessionId": rec.owner_session_id,
        "targetSessionId": rec.target_session_id,
        "targetHandle": rec.target_handle,
        "targetTopic": rec.target_topic,
        "label": rec.label,
        "note": rec.note,
        "trigger": rec.trigger_kind.as_str(),
        "cron": rec.cron_expr,
        "timezone": rec.timezone.as_str(),
        "exact": rec.exact_timing,
        "urgency": rec.urgency.as_str(),
        "ttlMs": rec.ttl_ms,
        "coalesce": rec.coalesce,
        "nextFireAt": rec.next_fire_at,
        "nextFireAtRfc3339": epoch_ms_to_rfc3339(rec.next_fire_at),
        "lastFiredAt": rec.last_fired_at,
        "iteration": rec.iteration,
        "maxIterations": rec.max_iterations,
        "consecutiveFailures": rec.consecutive_failures,
        "coldRevivalTemplate": rec.cold_revival_template,
        "state": rec.state.as_str(),
        "lastError": rec.last_error,
    })
}

fn run_wakeup_toggle(
    enabled: bool,
    mcp_tool: Option<CliWakeupMcpToolMode>,
    config: Option<PathBuf>,
    state_dir: Option<PathBuf>,
    as_json: bool,
) -> ExitCode {
    let cmd = if enabled {
        "wakeup enable"
    } else {
        "wakeup disable"
    };
    let dir = resolve_state_dir(state_dir.as_deref(), config.as_deref(), None);
    let config_path = resolve_config_path_for_write(config.as_deref(), state_dir.as_deref(), None);

    let mut cfg_map = match read_json_object_or_empty(&config_path) {
        Ok(m) => m,
        Err(e) => return emit_error(cmd, as_json, EXIT_ERROR, "CONFIG_ERROR", e, None),
    };

    let node_id = cfg_map
        .get("nodeId")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .unwrap_or_else(default_node_id);
    ensure_v2_node_json_defaults(&mut cfg_map, &node_id, NodeProfile::Local, &dir);

    let sources_val = cfg_map
        .entry("sources".to_string())
        .or_insert_with(|| Value::Array(Vec::new()));
    let Some(sources) = sources_val.as_array_mut() else {
        return emit_error(
            cmd,
            as_json,
            EXIT_ERROR,
            "CONFIG_ERROR",
            format!("'sources' in {} must be a JSON array", config_path.display()),
            None,
        );
    };

    let mut effective_mcp_tool = mcp_tool.unwrap_or(CliWakeupMcpToolMode::Auto).as_str().to_string();
    let mut found = false;
    for entry in sources.iter_mut() {
        if let Some(obj) = entry.as_object_mut() {
            if obj.get("kind").and_then(Value::as_str) == Some("wakeup") {
                obj.insert("enabled".to_string(), Value::Bool(enabled));
                if let Some(mode) = mcp_tool {
                    obj.insert("mcpTool".to_string(), Value::String(mode.as_str().to_string()));
                } else if let Some(existing_mode) = obj.get("mcpTool").and_then(Value::as_str) {
                    effective_mcp_tool = existing_mode.to_string();
                }
                found = true;
                break;
            }
        }
    }

    if !found {
        sources.push(json!({
            "kind": "wakeup",
            "enabled": enabled,
            "mcpTool": effective_mcp_tool,
        }));
    }

    if let Err(e) = write_atomic_json(&config_path, &Value::Object(cfg_map), true) {
        return emit_error(cmd, as_json, EXIT_ERROR, "IO_ERROR", e, None);
    }

    let next = if enabled {
        vec![
            format!("hyp wakeup set --in 5m --label check-in --note \"review status\" --state-dir {}", dir.display()),
            "Restart `hyp node start` if already running so the daemon reloads wakeup settings.".to_string(),
        ]
    } else {
        vec!["Restart `hyp node start` if already running to apply the disabled state.".to_string()]
    };

    if as_json {
        let envelope = JsonEnvelope {
            ok: true,
            command: cmd.to_string(),
            summary: Some(if enabled {
                format!(
                    "Enabled wakeup source (mcpTool={effective_mcp_tool}) in {}",
                    config_path.display()
                )
            } else {
                format!("Disabled wakeup source in {}", config_path.display())
            }),
            data: Some(json!({
                "configPath": config_path.display().to_string(),
                "stateDir": dir.display().to_string(),
                "enabled": enabled,
                "mcpTool": effective_mcp_tool,
            })),
            warnings: Vec::new(),
            next,
            error: None,
        };
        print_json(&envelope);
    } else if enabled {
        println!(
            "OK    Enabled wakeup scheduler (mcpTool={effective_mcp_tool}) in {}",
            config_path.display()
        );
        print_next_steps(&next);
    } else {
        println!("OK    Disabled wakeup scheduler in {}", config_path.display());
        print_next_steps(&next);
    }

    ExitCode::from(EXIT_OK)
}

#[allow(clippy::too_many_arguments)]
fn run_wakeup_set(
    in_duration: Option<String>,
    at: Option<String>,
    cron: Option<String>,
    timezone_raw: String,
    label: String,
    note_arg: Option<String>,
    to: Option<String>,
    urgency: CliWakeupUrgency,
    ttl_secs: Option<i64>,
    max_iterations: Option<u64>,
    template: Option<String>,
    socket: Option<PathBuf>,
    state_dir: Option<PathBuf>,
    as_json: bool,
) -> ExitCode {
    let cmd = "wakeup set";

    let schedule_count =
        usize::from(in_duration.is_some()) + usize::from(at.is_some()) + usize::from(cron.is_some());
    if schedule_count != 1 {
        return emit_error(
            cmd,
            as_json,
            EXIT_USAGE,
            "INVALID_SCHEDULE",
            "Specify exactly one of --in <duration>, --at <rfc3339>, or --cron <expr>",
            Some("Example: hyp wakeup set --in 5m --label ci-watch --note \"check build\"".to_string()),
        );
    }

    let trimmed_label = label.trim();
    if trimmed_label.is_empty() {
        return emit_error(
            cmd,
            as_json,
            EXIT_USAGE,
            "INVALID_LABEL",
            "--label must be non-empty",
            None,
        );
    }

    let note = match note_arg {
        Some(n) => {
            if n.trim().is_empty() {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_USAGE,
                    "INVALID_NOTE",
                    "--note cannot be empty when specified",
                    None,
                );
            }
            n
        }
        None => format!("Wakeup: {trimmed_label}"),
    };

    let timezone = match CronTimezone::parse(&timezone_raw) {
        Ok(tz) => tz,
        Err(e) => {
            return emit_error(
                cmd,
                as_json,
                EXIT_USAGE,
                "INVALID_TIMEZONE",
                e.to_string(),
                Some("Use --timezone local or --timezone UTC.".to_string()),
            );
        }
    };

    let ttl_ms = match ttl_secs {
        Some(s) if s < 1 => {
            return emit_error(
                cmd,
                as_json,
                EXIT_USAGE,
                "INVALID_TTL",
                "--ttl must be >= 1 second",
                None,
            );
        }
        Some(s) => s.saturating_mul(1_000),
        None => DEFAULT_WAKEUP_TTL_MS,
    };

    if max_iterations == Some(0) {
        return emit_error(
            cmd,
            as_json,
            EXIT_USAGE,
            "INVALID_MAX_ITERATIONS",
            "--max-iterations must be >= 1",
            None,
        );
    }

    let target_handle = match to.as_deref() {
        Some(raw) => match validate_local_target_handle(raw) {
            Ok(h) => Some(h),
            Err(e) => return emit_error(cmd, as_json, EXIT_USAGE, "INVALID_TARGET", e, None),
        },
        None => None,
    };
    let target_topic = if target_handle.is_none() {
        Some("wakeup".to_string())
    } else {
        None
    };

    let now = now_ms();
    let limits = WakeupLimits::default();

    let (trigger_kind, in_secs_for_rpc, at_for_rpc, fire_at_ms, cron_expr) =
        if let Some(ref dur_str) = in_duration {
            let secs = match parse_duration_seconds(dur_str) {
                Ok(s) => s,
                Err(e) => return emit_error(cmd, as_json, EXIT_USAGE, "INVALID_DURATION", e, None),
            };
            if secs > MAX_TIMER_IN_SECONDS {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_USAGE,
                    "INVALID_DURATION",
                    format!("--in duration ({secs}s) exceeds maximum allowed {MAX_TIMER_IN_SECONDS}s (30 days)"),
                    None,
                );
            }
            (
                WakeupTriggerKind::Timer,
                Some(secs),
                None,
                Some(now.saturating_add(secs.saturating_mul(1_000))),
                None,
            )
        } else if let Some(ref at_str) = at {
            let ms = match parse_rfc3339_millis(at_str) {
                Ok(ms) => ms,
                Err(e) => {
                    return emit_error(
                        cmd,
                        as_json,
                        EXIT_USAGE,
                        "INVALID_TIMESTAMP",
                        format!("Invalid --at RFC 3339 timestamp '{at_str}': {e}"),
                        Some("Example: --at 2026-12-01T09:00:00Z".to_string()),
                    );
                }
            };
            if ms <= now {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_USAGE,
                    "INVALID_TIMESTAMP",
                    format!("--at timestamp '{at_str}' must be in the future"),
                    None,
                );
            }
            (
                WakeupTriggerKind::Timer,
                None,
                Some(at_str.clone()),
                Some(ms),
                None,
            )
        } else {
            let expr_raw = cron.as_deref().unwrap_or_default();
            let parsed = match CronExpr::parse(expr_raw) {
                Ok(c) => c,
                Err(e) => {
                    return emit_error(
                        cmd,
                        as_json,
                        EXIT_USAGE,
                        "INVALID_CRON",
                        format!("Invalid --cron expression '{expr_raw}': {e}"),
                        Some("Use standard 5-field cron: '<min> <hour> <dom> <month> <dow>'.".to_string()),
                    );
                }
            };
            if let Err(e) = parsed.validate_min_interval(limits.min_cron_interval_seconds) {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_USAGE,
                    "INVALID_CRON",
                    e.to_string(),
                    None,
                );
            }
            (
                WakeupTriggerKind::Cron,
                None,
                None,
                None,
                Some(parsed.as_str().to_string()),
            )
        };

    // 1. Try live local daemon IPC if socket is reachable.
    let sock_path = resolve_wakeup_socket(socket.as_deref(), state_dir.as_deref());
    let mut rpc = Map::new();
    rpc.insert("type".to_string(), json!("wakeup.set"));
    rpc.insert("label".to_string(), json!(trimmed_label));
    rpc.insert("note".to_string(), json!(note));
    rpc.insert("urgency".to_string(), json!(urgency.as_str()));
    rpc.insert("timezone".to_string(), json!(timezone.as_str()));
    rpc.insert("ttlSeconds".to_string(), json!(ttl_ms / 1_000));
    if let Some(secs) = in_secs_for_rpc {
        rpc.insert("inSeconds".to_string(), json!(secs));
    }
    if let Some(ref at_val) = at_for_rpc {
        rpc.insert("at".to_string(), json!(at_val));
    }
    if let Some(ref expr) = cron_expr {
        rpc.insert("cron".to_string(), json!(expr));
    }
    if let Some(ref h) = target_handle {
        rpc.insert("to".to_string(), json!(h));
    }
    if let Some(ref topic) = target_topic {
        rpc.insert("topic".to_string(), json!(topic));
    }
    if let Some(max_it) = max_iterations {
        rpc.insert("maxIterations".to_string(), json!(max_it));
    }
    if let Some(ref tpl) = template {
        rpc.insert("template".to_string(), json!(tpl));
    }

    if let Some(resp) = try_daemon_rpc_if_present(&sock_path, &Value::Object(rpc)) {
        if resp.ok {
            let rec_val = Value::Object(resp.result.unwrap_or_default());
            let id = rec_val
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_string();
            let next_fire = rec_val
                .get("nextFireAtRfc3339")
                .and_then(Value::as_str)
                .unwrap_or("-")
                .to_string();
            return emit_wakeup_set_ok(cmd, as_json, "daemon", &id, trimmed_label, &next_fire, rec_val);
        }
        let err_msg = resp
            .error
            .unwrap_or_else(|| "daemon rejected wakeup.set".to_string());
        let fix = if err_msg.contains("wakeup_disabled") {
            Some("Run `hyp wakeup enable` and restart `hyp node start`.".to_string())
        } else {
            None
        };
        return emit_error(cmd, as_json, EXIT_ERROR, "WAKEUP_SET_FAILED", err_msg, fix);
    }

    // 2. Fallback: persist directly into NodeDb.
    let dir = resolve_state_dir(state_dir.as_deref(), None, None);
    if let Err(e) = ensure_dir(&dir, true) {
        return emit_error(cmd, as_json, EXIT_ERROR, "IO_ERROR", e, None);
    }
    let db = match NodeDb::open(dir.join("node.sqlite")) {
        Ok(db) => db,
        Err(e) => return emit_error(cmd, as_json, EXIT_ERROR, "DB_ERROR", e.to_string(), None),
    };

    let insert = WakeupInsert {
        id: None,
        owner_session_id: None,
        target_session_id: None,
        target_handle,
        target_topic,
        label: trimmed_label.to_string(),
        note,
        trigger_kind,
        cron_expr,
        timezone,
        exact_timing: false,
        urgency: urgency.to_store_urgency(),
        ttl_ms,
        coalesce: true,
        fire_at: fire_at_ms,
        max_iterations,
        cold_revival_template: template,
    };

    match db.wakeups().create_wakeup(&insert, &limits, now) {
        Ok(rec) => {
            let next_fire = epoch_ms_to_rfc3339(rec.next_fire_at);
            let rec_val = wakeup_record_to_json(&rec);
            emit_wakeup_set_ok(cmd, as_json, "sqlite", &rec.id, &rec.label, &next_fire, rec_val)
        }
        Err(StoreError::InvalidInput(msg)) => {
            emit_error(cmd, as_json, EXIT_USAGE, "INVALID_WAKEUP", msg, None)
        }
        Err(e) => emit_error(cmd, as_json, EXIT_ERROR, "WAKEUP_SET_FAILED", e.to_string(), None),
    }
}

fn emit_wakeup_set_ok(
    cmd: &str,
    as_json: bool,
    source: &str,
    id: &str,
    label: &str,
    next_fire: &str,
    wakeup_val: Value,
) -> ExitCode {
    let next = vec![
        "hyp wakeup list".to_string(),
        format!("hyp wakeup cancel {id}"),
    ];
    if as_json {
        let envelope = JsonEnvelope {
            ok: true,
            command: cmd.to_string(),
            summary: Some(format!("Scheduled wakeup '{label}' ({id}) for {next_fire}")),
            data: Some(json!({
                "source": source,
                "wakeup": wakeup_val,
            })),
            warnings: Vec::new(),
            next,
            error: None,
        };
        print_json(&envelope);
    } else {
        println!("OK    Scheduled wakeup '{label}' (id={id}, via={source})");
        println!("      Next Fire: {next_fire}");
        print_next_steps(&next);
    }
    ExitCode::from(EXIT_OK)
}

fn run_wakeup_list(
    all: bool,
    socket: Option<PathBuf>,
    state_dir: Option<PathBuf>,
    as_json: bool,
) -> ExitCode {
    let cmd = "wakeup list";
    let sock_path = resolve_wakeup_socket(socket.as_deref(), state_dir.as_deref());
    let req = json!({
        "type": "wakeup.list",
        "state": if all { "all" } else { "active" },
    });

    let (source, items): (&str, Vec<Value>) =
        if let Some(resp) = try_daemon_rpc_if_present(&sock_path, &req) {
            if !resp.ok {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_ERROR,
                    "WAKEUP_LIST_FAILED",
                    resp.error.unwrap_or_else(|| "daemon wakeup.list failed".to_string()),
                    None,
                );
            }
            let list = resp
                .result
                .and_then(|mut m| m.remove("wakeups"))
                .and_then(|v| v.as_array().cloned())
                .unwrap_or_default();
            ("daemon", list)
        } else {
            let dir = resolve_state_dir(state_dir.as_deref(), None, None);
            let db_path = dir.join("node.sqlite");
            if !db_path.exists() {
                ("sqlite", Vec::new())
            } else {
                let db = match NodeDb::open(&db_path) {
                    Ok(db) => db,
                    Err(e) => {
                        return emit_error(cmd, as_json, EXIT_ERROR, "DB_ERROR", e.to_string(), None);
                    }
                };
                let filter = if all { None } else { Some(WakeupState::Active) };
                match db.wakeups().list_wakeups(None, filter) {
                    Ok(list) => ("sqlite", list.iter().map(wakeup_record_to_json).collect()),
                    Err(e) => {
                        return emit_error(cmd, as_json, EXIT_ERROR, "DB_ERROR", e.to_string(), None);
                    }
                }
            }
        };

    if as_json {
        let envelope = JsonEnvelope {
            ok: true,
            command: cmd.to_string(),
            summary: Some(format!("{} wakeup(s) listed ({source})", items.len())),
            data: Some(json!({
                "source": source,
                "includeAll": all,
                "count": items.len(),
                "wakeups": items,
            })),
            warnings: Vec::new(),
            next: if items.is_empty() {
                vec!["hyp wakeup set --in 5m --label check-in --note \"review status\"".to_string()]
            } else {
                Vec::new()
            },
            error: None,
        };
        print_json(&envelope);
    } else {
        println!(
            "Hyphae Wakeups ({} shown, source={source})",
            items.len()
        );
        if items.is_empty() {
            println!("  (none)");
        } else {
            println!();
            println!(
                "{:<22}  {:<10}  {:<7}  {:<16}  {:<14}  {:<16}  Next Fire",
                "ID", "State", "Trigger", "Schedule", "Target", "Label"
            );
            println!("{}", "-".repeat(110));
            for item in &items {
                let id = item.get("id").and_then(Value::as_str).unwrap_or("-");
                let state = item.get("state").and_then(Value::as_str).unwrap_or("-");
                let trigger = item.get("trigger").and_then(Value::as_str).unwrap_or("-");
                let sched = item
                    .get("cron")
                    .and_then(Value::as_str)
                    .unwrap_or("one-shot");
                let target = item
                    .get("targetHandle")
                    .and_then(Value::as_str)
                    .or_else(|| item.get("targetSessionId").and_then(Value::as_str))
                    .or_else(|| item.get("targetTopic").and_then(Value::as_str))
                    .unwrap_or("-");
                let label = item.get("label").and_then(Value::as_str).unwrap_or("-");
                let next_fire = item
                    .get("nextFireAtRfc3339")
                    .and_then(Value::as_str)
                    .unwrap_or("-");
                println!(
                    "{:<22}  {:<10}  {:<7}  {:<16}  {:<14}  {:<16}  {}",
                    truncate_col(id, 22),
                    state,
                    trigger,
                    truncate_col(sched, 16),
                    truncate_col(target, 14),
                    truncate_col(label, 16),
                    next_fire
                );
            }
        }
    }
    ExitCode::from(EXIT_OK)
}

fn run_wakeup_cancel(
    id: String,
    socket: Option<PathBuf>,
    state_dir: Option<PathBuf>,
    as_json: bool,
) -> ExitCode {
    let cmd = "wakeup cancel";
    let trimmed_id = id.trim();
    if trimmed_id.is_empty() {
        return emit_error(cmd, as_json, EXIT_USAGE, "INVALID_ID", "Wakeup ID cannot be empty", None);
    }

    let sock_path = resolve_wakeup_socket(socket.as_deref(), state_dir.as_deref());
    let req = json!({ "type": "wakeup.cancel", "id": trimmed_id });

    let (source, wakeup_val): (&str, Value) =
        if let Some(resp) = try_daemon_rpc_if_present(&sock_path, &req) {
            if !resp.ok {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_ERROR,
                    "WAKEUP_CANCEL_FAILED",
                    resp.error
                        .unwrap_or_else(|| format!("Failed to cancel wakeup '{trimmed_id}'")),
                    None,
                );
            }
            let val = resp
                .result
                .and_then(|mut m| m.remove("wakeup"))
                .unwrap_or_else(|| json!({ "id": trimmed_id, "state": "cancelled" }));
            ("daemon", val)
        } else {
            let dir = resolve_state_dir(state_dir.as_deref(), None, None);
            let db_path = dir.join("node.sqlite");
            if !db_path.exists() {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_ERROR,
                    "WAKEUP_NOT_FOUND",
                    format!("Wakeup '{trimmed_id}' not found (database does not exist yet)"),
                    None,
                );
            }
            let db = match NodeDb::open(&db_path) {
                Ok(db) => db,
                Err(e) => {
                    return emit_error(cmd, as_json, EXIT_ERROR, "DB_ERROR", e.to_string(), None);
                }
            };
            match db.wakeups().cancel_wakeup(trimmed_id, None, now_ms()) {
                Ok(rec) => ("sqlite", wakeup_record_to_json(&rec)),
                Err(StoreError::NotFound(m)) => {
                    return emit_error(cmd, as_json, EXIT_ERROR, "WAKEUP_NOT_FOUND", m, None);
                }
                Err(StoreError::InvalidState(m)) => {
                    return emit_error(cmd, as_json, EXIT_ERROR, "INVALID_WAKEUP_STATE", m, None);
                }
                Err(e) => {
                    return emit_error(
                        cmd,
                        as_json,
                        EXIT_ERROR,
                        "WAKEUP_CANCEL_FAILED",
                        e.to_string(),
                        None,
                    );
                }
            }
        };

    if as_json {
        let envelope = JsonEnvelope {
            ok: true,
            command: cmd.to_string(),
            summary: Some(format!("Cancelled wakeup '{trimmed_id}' ({source})")),
            data: Some(json!({
                "source": source,
                "cancelled": true,
                "wakeup": wakeup_val,
            })),
            warnings: Vec::new(),
            next: Vec::new(),
            error: None,
        };
        print_json(&envelope);
    } else {
        println!("OK    Cancelled wakeup '{trimmed_id}' (via={source})");
    }
    ExitCode::from(EXIT_OK)
}

#[allow(clippy::too_many_arguments)]
fn run_wakeup_fire(
    id: Option<String>,
    to: Option<String>,
    label: Option<String>,
    note: Option<String>,
    urgency: CliWakeupUrgency,
    socket: Option<PathBuf>,
    state_dir: Option<PathBuf>,
    as_json: bool,
) -> ExitCode {
    let cmd = "wakeup fire";
    if id.is_none() && to.is_none() && label.is_none() && note.is_none() {
        return emit_error(
            cmd,
            as_json,
            EXIT_USAGE,
            "MISSING_ARGS",
            "Pass --id <wakeup-id> or ad-hoc trigger fields (--label / --note / --to)",
            Some("Example: hyp wakeup fire --to dev --label deploy-done --note \"release finished\"".to_string()),
        );
    }

    let mut rpc = Map::new();
    if let Some(ref wid) = id {
        let trimmed_id = wid.trim();
        if trimmed_id.is_empty() {
            return emit_error(cmd, as_json, EXIT_USAGE, "INVALID_ID", "--id cannot be empty", None);
        }
        rpc.insert("type".to_string(), json!("wakeup.fire"));
        rpc.insert("id".to_string(), json!(trimmed_id));

        // Hydrate persisted fields from node.sqlite when caller only passes `--id`.
        let dir = resolve_state_dir(state_dir.as_deref(), None, None);
        let db_path = dir.join("node.sqlite");
        if db_path.exists() {
            if let Ok(db) = NodeDb::open(&db_path) {
                if let Ok(Some(rec)) = db.wakeups().get_wakeup(trimmed_id) {
                    rpc.insert("label".to_string(), json!(rec.label));
                    rpc.insert("note".to_string(), json!(rec.note));
                    rpc.insert("urgency".to_string(), json!(rec.urgency.as_str()));
                    rpc.insert("ttlSeconds".to_string(), json!((rec.ttl_ms / 1_000).max(1)));
                    if let Some(h) = rec.target_handle {
                        rpc.insert("to".to_string(), json!(h));
                    }
                    if let Some(s) = rec.target_session_id {
                        rpc.insert("targetSessionId".to_string(), json!(s));
                    }
                    if let Some(t) = rec.target_topic {
                        rpc.insert("topic".to_string(), json!(t));
                    }
                    if let Some(tpl) = rec.cold_revival_template {
                        rpc.insert("template".to_string(), json!(tpl));
                    }
                }
            }
        }

        if let Some(ref l) = label {
            rpc.insert("label".to_string(), json!(l.trim()));
        }
        if let Some(ref n) = note {
            rpc.insert("note".to_string(), json!(n));
        }
        if let Some(ref t) = to {
            match validate_local_target_handle(t) {
                Ok(h) => {
                    rpc.insert("to".to_string(), json!(h));
                }
                Err(e) => return emit_error(cmd, as_json, EXIT_USAGE, "INVALID_TARGET", e, None),
            }
        }
        if !rpc.contains_key("note") {
            let fallback_note = rpc
                .get("label")
                .and_then(Value::as_str)
                .map(|l| format!("Triggered wakeup '{l}' ({trimmed_id})"))
                .unwrap_or_else(|| format!("Triggered wakeup '{trimmed_id}'"));
            rpc.insert("note".to_string(), json!(fallback_note));
        }
        if !rpc.contains_key("to")
            && !rpc.contains_key("targetSessionId")
            && !rpc.contains_key("topic")
            && !rpc.contains_key("template")
        {
            rpc.insert("topic".to_string(), json!("wakeup"));
        }
    } else {
        rpc.insert("type".to_string(), json!("wakeup.emit"));
        let eff_label = label
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("external")
            .to_string();
        let eff_note = note
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| format!("Wakeup: {eff_label}"));
        rpc.insert("label".to_string(), json!(eff_label));
        rpc.insert("note".to_string(), json!(eff_note));
        rpc.insert("urgency".to_string(), json!(urgency.as_str()));
        if let Some(ref t) = to {
            match validate_local_target_handle(t) {
                Ok(h) => {
                    rpc.insert("to".to_string(), json!(h));
                }
                Err(e) => return emit_error(cmd, as_json, EXIT_USAGE, "INVALID_TARGET", e, None),
            }
        } else {
            rpc.insert("topic".to_string(), json!("wakeup"));
        }
    }

    let sock_path = resolve_wakeup_socket(socket.as_deref(), state_dir.as_deref());
    let Some(resp) = try_daemon_rpc_if_present(&sock_path, &Value::Object(rpc)) else {
        return emit_error(
            cmd,
            as_json,
            EXIT_ERROR,
            "DAEMON_OFFLINE",
            format!(
                "Local Hyphae daemon is not reachable at {}",
                sock_path.display()
            ),
            Some("hyp node start".to_string()),
        );
    };

    if !resp.ok {
        let msg = resp
            .error
            .unwrap_or_else(|| "daemon rejected wakeup trigger".to_string());
        let fix = if msg.contains("wakeup_disabled") {
            Some("Run `hyp wakeup enable` and restart `hyp node start`.".to_string())
        } else {
            None
        };
        return emit_error(cmd, as_json, EXIT_ERROR, "WAKEUP_FIRE_FAILED", msg, fix);
    }

    let res_val = Value::Object(resp.result.unwrap_or_default());
    let wid = res_val
        .get("wakeupId")
        .and_then(Value::as_str)
        .unwrap_or("-");
    if as_json {
        let envelope = JsonEnvelope {
            ok: true,
            command: cmd.to_string(),
            summary: Some(format!("Fired wakeup '{wid}' via local daemon")),
            data: Some(res_val),
            warnings: Vec::new(),
            next: Vec::new(),
            error: None,
        };
        print_json(&envelope);
    } else {
        println!("OK    Fired wakeup '{wid}'");
    }
    ExitCode::from(EXIT_OK)
}

fn run_wakeup_emit(
    socket: Option<PathBuf>,
    state_dir: Option<PathBuf>,
    as_json: bool,
) -> ExitCode {
    let cmd = "wakeup emit";
    let mut raw = String::new();
    if let Err(e) = io::stdin()
        .lock()
        .take(MAX_EMIT_STDIN_BYTES + 1)
        .read_to_string(&mut raw)
    {
        return emit_error(
            cmd,
            as_json,
            EXIT_ERROR,
            "STDIN_ERROR",
            format!("Failed to read wakeup payload from stdin: {e}"),
            None,
        );
    }
    if raw.len() as u64 > MAX_EMIT_STDIN_BYTES {
        return emit_error(
            cmd,
            as_json,
            EXIT_USAGE,
            "PAYLOAD_TOO_LARGE",
            format!("Wakeup stdin payload exceeds {MAX_EMIT_STDIN_BYTES} byte limit"),
            None,
        );
    }
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return emit_error(
            cmd,
            as_json,
            EXIT_USAGE,
            "EMPTY_STDIN",
            "Expected JSON wakeup payload on stdin (CloudEvents v1.0 or compact { label, note?, to?, urgency?, data? })",
            Some("Example: echo '{\"label\":\"ci\",\"note\":\"build green\"}' | hyp wakeup emit".to_string()),
        );
    }

    let parsed: Value = match serde_json::from_str(trimmed) {
        Ok(v) => v,
        Err(e) => {
            return emit_error(
                cmd,
                as_json,
                EXIT_USAGE,
                "INVALID_JSON",
                format!("Invalid JSON on stdin: {e}"),
                None,
            );
        }
    };
    let Some(mut obj) = parsed.as_object().cloned() else {
        return emit_error(
            cmd,
            as_json,
            EXIT_USAGE,
            "INVALID_PAYLOAD",
            "Wakeup stdin JSON must be an object",
            None,
        );
    };

    // Normalize compact payloads that carry `{ label, data: {...} }` without an explicit `note`,
    // or `{ label, note, data: {...} }` where `note` is at top-level rather than nested inside `data`.
    let is_cloudevent = obj.get("specversion").and_then(Value::as_str) == Some("1.0");
    if !is_cloudevent {
        if !obj.contains_key("note") {
            if let Some(lbl) = obj.get("label").and_then(Value::as_str) {
                if !lbl.trim().is_empty() {
                    obj.insert("note".to_string(), json!(format!("Wakeup: {}", lbl.trim())));
                }
            }
        }
        if let Some(data_obj) = obj.get("data").and_then(Value::as_object).cloned() {
            // Merge top-level compact fields into `data` if `daemon` will unpack `data`.
            let mut merged = data_obj;
            for key in ["label", "note", "to", "targetHandle", "urgency", "sessionId", "topic"] {
                if !merged.contains_key(key) {
                    if let Some(v) = obj.get(key) {
                        merged.insert(key.to_string(), v.clone());
                    }
                }
            }
            obj.insert("data".to_string(), Value::Object(merged));
        }
    }

    let mut rpc = Map::new();
    rpc.insert("type".to_string(), json!("wakeup.emit"));
    rpc.insert("payload".to_string(), Value::Object(obj.clone()));

    let has_target = obj.contains_key("to")
        || obj.contains_key("targetHandle")
        || obj.contains_key("sessionId")
        || obj.contains_key("targetSessionId")
        || obj.contains_key("topic")
        || obj.contains_key("targetTopic")
        || obj.contains_key("template")
        || obj.get("data").and_then(Value::as_object).is_some_and(|d| {
            d.contains_key("to")
                || d.contains_key("targetHandle")
                || d.contains_key("sessionId")
                || d.contains_key("targetSessionId")
                || d.contains_key("topic")
                || d.contains_key("targetTopic")
                || d.contains_key("template")
        });
    if !has_target {
        rpc.insert("topic".to_string(), json!("wakeup"));
    }

    let sock_path = resolve_wakeup_socket(socket.as_deref(), state_dir.as_deref());
    let Some(resp) = try_daemon_rpc_if_present(&sock_path, &Value::Object(rpc)) else {
        return emit_error(
            cmd,
            as_json,
            EXIT_ERROR,
            "DAEMON_OFFLINE",
            format!(
                "Local Hyphae daemon is not reachable at {}",
                sock_path.display()
            ),
            Some("hyp node start".to_string()),
        );
    };

    if !resp.ok {
        let msg = resp
            .error
            .unwrap_or_else(|| "daemon rejected wakeup.emit".to_string());
        let fix = if msg.contains("wakeup_disabled") {
            Some("Run `hyp wakeup enable` and restart `hyp node start`.".to_string())
        } else {
            None
        };
        return emit_error(cmd, as_json, EXIT_ERROR, "WAKEUP_EMIT_FAILED", msg, fix);
    }

    let res_val = Value::Object(resp.result.unwrap_or_default());
    let wid = res_val
        .get("wakeupId")
        .and_then(Value::as_str)
        .unwrap_or("-");
    if as_json {
        let envelope = JsonEnvelope {
            ok: true,
            command: cmd.to_string(),
            summary: Some(format!("Emitted wakeup '{wid}' via local daemon")),
            data: Some(res_val),
            warnings: Vec::new(),
            next: Vec::new(),
            error: None,
        };
        print_json(&envelope);
    } else {
        println!("OK    Emitted wakeup '{wid}'");
    }
    ExitCode::from(EXIT_OK)
}

fn truncate_col(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else if max > 1 {
        let mut out: String = s.chars().take(max - 1).collect();
        out.push('…');
        out
    } else {
        s.chars().take(max).collect()
    }
}
