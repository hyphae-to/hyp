//! `hyp session` quick-control CLI commands (`focus`, `mute`, `unmute`, `rule`, `unsubscribe`, `leave`).
//!
//! Calls Stream A's quick-control RPCs synchronously over `connector.sock` / `connector.addr`
//! and adheres strictly to the agent-first `crates/hyp-cli/src/ui.rs` JSON envelope contract.

use crate::statusline_cmd::sanitize_terminal_text;
use crate::ui::{EXIT_ERROR, EXIT_OK, EXIT_USAGE, JsonEnvelope, emit_error, print_json};
use clap::{Args, Subcommand, ValueEnum};
use hyp_harness::sock::{daemon_rpc_sync, default_socket_path};
use hyp_harness::wait::{infer_herdr_terminal_from_env, infer_session_id_from_env};
use serde_json::{Map, Value, json};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

const SESSION_RPC_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Debug, Clone, Args)]
pub struct SessionArgs {
    /// Target session ID (defaults to $HYPHAE_SESSION_ID if unset)
    #[arg(long, global = true)]
    pub session: Option<String>,
    /// Target Herdr terminal ID (defaults to $HC_TERMINAL_ID if unset)
    #[arg(long, global = true)]
    pub herdr_terminal: Option<String>,
    /// Optional Herdr terminal creation timestamp (ms) anti-recycle pin
    #[arg(long, global = true)]
    pub herdr_created_ms: Option<i64>,
    /// Target enrolled handle (e.g. alice or @alice)
    #[arg(long, global = true)]
    pub handle: Option<String>,
    /// Explicit connector.sock / connector.addr path
    #[arg(long, global = true)]
    pub socket: Option<PathBuf>,
    /// Output agent-first JSON envelope
    #[arg(long, global = true)]
    pub json: bool,
    #[command(subcommand)]
    pub command: SessionSubcommand,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum FocusToggle {
    #[value(alias = "true", alias = "enable")]
    On,
    #[value(alias = "false", alias = "disable")]
    Off,
}

impl FocusToggle {
    pub const fn as_bool(self) -> bool {
        matches!(self, Self::On)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum MuteScope {
    Session,
    Connector,
}

impl MuteScope {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Session => "session",
            Self::Connector => "connector",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum RuleUrgencyArg {
    Interrupt,
    Queue,
    Notify,
    Mute,
    Remove,
}

impl RuleUrgencyArg {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Interrupt => "interrupt",
            Self::Queue => "queue",
            Self::Notify => "notify",
            Self::Mute => "mute",
            Self::Remove => "remove",
        }
    }
}

#[derive(Debug, Clone, Subcommand)]
pub enum SessionSubcommand {
    /// Toggle Focus Mode (`on` or `off`) for the target session
    Focus {
        /// `on` or `off`
        #[arg(value_enum)]
        state: FocusToggle,
        /// Allow `interrupt`-urgency VIP senders to break through Focus Mode (`true` or `false`)
        #[arg(long, value_parser = clap::value_parser!(bool))]
        allow_vips: Option<bool>,
    },
    /// Mute messages/events matching a source pattern
    Mute {
        /// Source pattern to mute (e.g. `#noisy`, `bob/*`, `*`)
        pattern: String,
        /// Mute scope (`session` or `connector`)
        #[arg(long, value_enum, default_value_t = MuteScope::Session)]
        scope: MuteScope,
        /// Optional auto-unmute TTL in seconds
        #[arg(long)]
        ttl: Option<u64>,
    },
    /// Remove a mute rule matching a source pattern
    Unmute {
        /// Source pattern to unmute
        pattern: String,
        /// Mute scope (`session` or `connector`)
        #[arg(long, value_enum, default_value_t = MuteScope::Session)]
        scope: MuteScope,
    },
    /// Set or remove a per-source delivery urgency rule (`interrupt`, `queue`, `notify`, `mute`, `remove`)
    Rule {
        /// Source target pattern (e.g. `bob/rev`, `#ops`, `*`)
        target: String,
        /// Delivery urgency or `remove`
        #[arg(value_enum)]
        urgency: RuleUrgencyArg,
    },
    /// Unsubscribe from an active stream subscription owned by this session
    Unsubscribe {
        /// Subscription ID or key
        subscription_id: String,
    },
    /// Leave a mesh channel joined by this session's handle
    Leave {
        /// Channel name (e.g. `#ops`)
        channel: String,
    },
}

fn insert_session_selector(
    args: &SessionArgs,
    pkt: &mut Map<String, Value>,
    require_session: bool,
) -> Result<(), String> {
    let explicit_sid = args
        .session
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let explicit_tid = args
        .herdr_terminal
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let explicit_handle = args
        .handle
        .as_deref()
        .map(|s| s.trim().trim_start_matches('@'))
        .filter(|s| !s.is_empty());

    if let Some(sid) = explicit_sid {
        pkt.insert("sessionId".into(), json!(sid));
        if let Some(ms) = args.herdr_created_ms {
            pkt.insert("herdrCreatedMs".into(), json!(ms));
        }
        return Ok(());
    }
    if let Some(tid) = explicit_tid {
        pkt.insert("herdrTerminalId".into(), json!(tid));
        if let Some(ms) = args.herdr_created_ms {
            pkt.insert("herdrCreatedMs".into(), json!(ms));
        }
        return Ok(());
    }
    if let Some(h) = explicit_handle {
        pkt.insert("handle".into(), json!(h));
        return Ok(());
    }

    if let Some(env_sid) = infer_session_id_from_env() {
        pkt.insert("sessionId".into(), json!(env_sid));
        return Ok(());
    }
    if let Some(env_tid) = infer_herdr_terminal_from_env() {
        pkt.insert("herdrTerminalId".into(), json!(env_tid));
        if let Some(ms) = args.herdr_created_ms {
            pkt.insert("herdrCreatedMs".into(), json!(ms));
        }
        return Ok(());
    }

    if require_session {
        return Err(
            "No target session specified and neither HYPHAE_SESSION_ID nor HC_TERMINAL_ID is set"
                .to_string(),
        );
    }
    Ok(())
}

pub fn run_session(args: &SessionArgs) -> ExitCode {
    let socket_path = args.socket.clone().unwrap_or_else(default_socket_path);
    let mut pkt = Map::new();

    let (cmd_name, require_session) = match &args.command {
        SessionSubcommand::Focus { state, allow_vips } => {
            pkt.insert("type".into(), json!("session.focus"));
            pkt.insert("enabled".into(), json!(state.as_bool()));
            if let Some(v) = allow_vips {
                pkt.insert("allowVips".into(), json!(v));
            }
            ("session focus", true)
        }
        SessionSubcommand::Mute {
            pattern,
            scope,
            ttl,
        } => {
            pkt.insert("type".into(), json!("session.mute"));
            pkt.insert("source".into(), json!(pattern));
            pkt.insert("scope".into(), json!(scope.as_str()));
            if let Some(secs) = ttl {
                pkt.insert("ttlSeconds".into(), json!(secs));
            }
            ("session mute", *scope == MuteScope::Session)
        }
        SessionSubcommand::Unmute { pattern, scope } => {
            pkt.insert("type".into(), json!("session.unmute"));
            pkt.insert("source".into(), json!(pattern));
            pkt.insert("scope".into(), json!(scope.as_str()));
            ("session unmute", *scope == MuteScope::Session)
        }
        SessionSubcommand::Rule { target, urgency } => {
            pkt.insert("type".into(), json!("session.rule"));
            pkt.insert("source".into(), json!(target));
            pkt.insert("urgency".into(), json!(urgency.as_str()));
            if *urgency == RuleUrgencyArg::Remove {
                pkt.insert("remove".into(), json!(true));
            }
            ("session rule", true)
        }
        SessionSubcommand::Unsubscribe { subscription_id } => {
            pkt.insert("type".into(), json!("session.unsubscribe"));
            pkt.insert("subscriptionId".into(), json!(subscription_id));
            ("session unsubscribe", true)
        }
        SessionSubcommand::Leave { channel } => {
            pkt.insert("type".into(), json!("session.leave_channel"));
            pkt.insert("channel".into(), json!(channel));
            ("session leave", true)
        }
    };

    if let Err(msg) = insert_session_selector(args, &mut pkt, require_session) {
        return emit_error(
            cmd_name,
            args.json,
            EXIT_USAGE,
            "SESSION_REQUIRED",
            msg,
            Some("Pass --session <id>, --herdr-terminal <tid>, or --handle <name>".to_string()),
        );
    }

    let res = daemon_rpc_sync(&socket_path, &Value::Object(pkt), SESSION_RPC_TIMEOUT);
    if !res.ok {
        let msg = res.error.unwrap_or_else(|| {
            format!(
                "Local Hyphae daemon unreachable at {}",
                socket_path.display()
            )
        });
        return emit_error(
            cmd_name,
            args.json,
            EXIT_ERROR,
            "SESSION_RPC_FAILED",
            msg,
            Some("Verify the daemon is running (`hyp status`) and session ID is active (`hyp inspect --all`)".to_string()),
        );
    }

    let result_map = res.result.unwrap_or_default();
    let summary = build_human_summary(&args.command, &result_map);

    if args.json {
        let env = JsonEnvelope {
            ok: true,
            command: cmd_name.to_string(),
            summary: Some(summary),
            data: Some(Value::Object(result_map)),
            warnings: Vec::new(),
            next: Vec::new(),
            error: None,
        };
        print_json(&env);
    } else {
        println!("OK  {summary}");
    }

    ExitCode::from(EXIT_OK)
}

fn build_human_summary(sub: &SessionSubcommand, result: &Map<String, Value>) -> String {
    let sid = result
        .get("sessionId")
        .and_then(Value::as_str)
        .map(sanitize_terminal_text)
        .unwrap_or_else(|| "connector".into());
    match sub {
        SessionSubcommand::Focus { .. } => {
            let on = result
                .get("focusMode")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let vips = result
                .get("focusAllowInterruptVips")
                .and_then(Value::as_bool)
                .unwrap_or(true);
            let state = if on { "ON" } else { "OFF" };
            format!("Focus mode {state} for {sid} (allowVips={vips})")
        }
        SessionSubcommand::Mute { .. } => {
            let pat = result
                .get("pattern")
                .and_then(Value::as_str)
                .map(sanitize_terminal_text)
                .unwrap_or_default();
            let scope = result
                .get("scope")
                .and_then(Value::as_str)
                .map(sanitize_terminal_text)
                .unwrap_or_else(|| "session".into());
            match result.get("ttlSeconds").and_then(Value::as_u64) {
                Some(ttl) => format!("Muted '{pat}' (scope={scope}, ttl={ttl}s) on {sid}"),
                None => format!("Muted '{pat}' (scope={scope}) on {sid}"),
            }
        }
        SessionSubcommand::Unmute { .. } => {
            let pat = result
                .get("pattern")
                .and_then(Value::as_str)
                .map(sanitize_terminal_text)
                .unwrap_or_default();
            let scope = result
                .get("scope")
                .and_then(Value::as_str)
                .map(sanitize_terminal_text)
                .unwrap_or_else(|| "session".into());
            let removed = result
                .get("removed")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if removed {
                format!("Unmuted '{pat}' (scope={scope}) on {sid}")
            } else {
                format!("No active mute matched '{pat}' (scope={scope}) on {sid}")
            }
        }
        SessionSubcommand::Rule { .. } => {
            let target = result
                .get("target")
                .and_then(Value::as_str)
                .map(sanitize_terminal_text)
                .unwrap_or_default();
            if result.get("removed").and_then(Value::as_bool) == Some(true)
                || result.get("delivery").is_some_and(Value::is_null)
            {
                format!("Removed delivery rule for '{target}' on {sid}")
            } else {
                let del = result
                    .get("delivery")
                    .and_then(Value::as_str)
                    .map(sanitize_terminal_text)
                    .unwrap_or_default();
                format!("Set delivery rule '{target}' -> {del} on {sid}")
            }
        }
        SessionSubcommand::Unsubscribe { .. } => {
            let id = result
                .get("subscriptionId")
                .and_then(Value::as_str)
                .map(sanitize_terminal_text)
                .unwrap_or_default();
            format!("Unsubscribed '{id}' on {sid}")
        }
        SessionSubcommand::Leave { .. } => {
            let ch = result
                .get("channel")
                .and_then(Value::as_str)
                .map(sanitize_terminal_text)
                .unwrap_or_default();
            format!("Left channel '{ch}' on {sid}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_clean_human_summaries_with_sanitization() {
        let mut res = Map::new();
        res.insert("sessionId".into(), json!("claude:s1"));
        res.insert("focusMode".into(), json!(true));
        res.insert("focusAllowInterruptVips".into(), json!(false));
        let s = build_human_summary(
            &SessionSubcommand::Focus {
                state: FocusToggle::On,
                allow_vips: Some(false),
            },
            &res,
        );
        assert_eq!(s, "Focus mode ON for claude:s1 (allowVips=false)");

        let mut mute_res = Map::new();
        mute_res.insert("sessionId".into(), json!("claude:s1"));
        mute_res.insert("pattern".into(), json!("#noisy\x1b[31m"));
        mute_res.insert("scope".into(), json!("session"));
        mute_res.insert("ttlSeconds".into(), json!(600));
        let ms = build_human_summary(
            &SessionSubcommand::Mute {
                pattern: "#noisy".into(),
                scope: MuteScope::Session,
                ttl: Some(600),
            },
            &mute_res,
        );
        assert_eq!(ms, "Muted '#noisy' (scope=session, ttl=600s) on claude:s1");
        assert!(!ms.contains('\x1b'));
    }
}
