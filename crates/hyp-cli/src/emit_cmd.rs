//! `hyp emit` — Emit a CloudEvents v1.0 or compact JSON event into the local Hyphae node's
//! socket-only local ingest route (`<state_dir>/ingest.sock` on Unix, `<state_dir>/ingest.addr`
//! on Windows).
//!
//! Supports two input modes:
//! 1. **Flag mode** (ideal for 1-line `crontab` / `systemd-run --user` / `launchd` triggers):
//!    builds a normalized CloudEvent v1.0 (`to.hyphae.scheduled.v1` on `local.schedule` by default).
//! 2. **Stdin JSON mode** (when stdin is piped and non-empty, bounded `<= 64 KiB`):
//!    reads either a full CloudEvents v1.0 envelope or compact shorthand JSON and merges any
//!    explicit CLI flags cleanly.
//!
//! Optional `--sign` loads the local Ed25519 admin key from `SecretStore` (`human-admin-*`),
//! canonicalizes the event via `canonical_local_event_for_signing`, signs under
//! `LOCAL_EVENT_SIG_DOMAIN`, and attaches the `hyphaesig` CloudEvents extension attribute.

use crate::auth_cmd::select_local_signing_authority;
use crate::config_file::{
    load_node_or_legacy_config, open_secret_store, resolve_config_path_for_read, resolve_state_dir,
};
use crate::gate_cmd::{
    ConfirmError, emit_confirm_error, require_controlling_tty_confirmation, sanitize_tty_display,
};
use crate::ui::{EXIT_ERROR, EXIT_OK, EXIT_USAGE, JsonEnvelope, emit_error, print_json};
use clap::Args;
use hyp_crypto::human::sign_local_ingest_event;
use hyp_crypto::rfc3339::{format_rfc3339_millis, now_unix_ms};
use hyp_node::engine::{
    LocalIngestConfig, LocalIngestError, MAX_LOCAL_INGEST_LINE_BYTES,
    canonical_local_event_for_signing, send_local_ingest_event,
};
use hyp_proto::address::is_valid_topic;
use hyp_proto::cloudevent::{
    CONTENT_TYPE_JSON, CloudEvent, CloudEventLimits, EXT_LOCAL_EVENT_SIG, MAX_ATTRIBUTE_CHARS,
    TYPE_SCHEDULED_MESSAGE_V1, check_cloudevent_v2_with_limits, is_extension_name,
    is_valid_rfc3339_strict,
};
use hyp_store::{NodeDb, uuid_v4};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::io::{self, IsTerminal as _, Read as _};
use std::path::PathBuf;
use std::process::ExitCode;

const DEFAULT_EMIT_SOURCE: &str = "local-cli";
const MAX_TTL_SECONDS: u64 = 30 * 24 * 60 * 60;

#[derive(Args)]
pub struct EmitArgs {
    /// CloudEvent type (default in flag mode: to.hyphae.scheduled.v1)
    #[arg(long = "type")]
    pub event_type: Option<String>,
    /// Target local topic (default: schedule -> local.schedule)
    #[arg(long)]
    pub topic: Option<String>,
    /// CloudEvent source (default in flag mode: local-cli)
    #[arg(long)]
    pub source: Option<String>,
    /// Short label placed in event data and CloudEvents `label` extension for filter matching
    #[arg(long)]
    pub label: Option<String>,
    /// Human-readable note or payload message placed in event data
    #[arg(long)]
    pub note: Option<String>,
    /// Optional mailbox coalesce key to collapse repeated bursts
    #[arg(long)]
    pub coalesce_key: Option<String>,
    /// Optional mailbox TTL hint in seconds (1..=2592000)
    #[arg(long)]
    pub ttl: Option<u64>,
    /// Sign the CloudEvent with the local admin Ed25519 key (`hyphaesig` -> TrustTier::HumanVerified)
    #[arg(long)]
    pub sign: bool,
    /// Explicit local admin authority kid for `--sign` (defaults to first active admin key)
    #[arg(long, allow_hyphen_values = true)]
    pub kid: Option<String>,
    /// Explicit local ingest socket (`ingest.sock`) or loopback descriptor (`ingest.addr`) path
    #[arg(long)]
    pub socket: Option<PathBuf>,
    /// Explicit state directory containing node.sqlite, secrets/, and ingest.sock
    #[arg(long)]
    pub state_dir: Option<PathBuf>,
    /// Explicit node.json path
    #[arg(long)]
    pub config: Option<PathBuf>,
    /// Output structured JSON envelope
    #[arg(long)]
    pub json: bool,
}

pub fn run_emit(args: EmitArgs) -> ExitCode {
    let cmd = "emit";
    let as_json = args.json;

    if let Some(ttl) = args.ttl {
        if ttl == 0 || ttl > MAX_TTL_SECONDS {
            return emit_error(
                cmd,
                as_json,
                EXIT_USAGE,
                "INVALID_TTL",
                format!("--ttl must be in 1..={MAX_TTL_SECONDS} seconds"),
                None,
            );
        }
    }

    // P0: `hyp emit --sign` attaches a `HumanVerified` Ed25519 signature using the local admin
    // key and MUST require an interactive human controlling terminal (unsigned `hyp emit` for
    // cron/scripts remains completely non-interactive).
    if args.sign && !io::stderr().is_terminal() {
        return emit_confirm_error("emit --sign", as_json, ConfirmError::NotInteractiveTty);
    }

    let config_path =
        resolve_config_path_for_read(args.config.as_deref(), args.state_dir.as_deref(), None);
    let loaded = if config_path.exists() {
        match load_node_or_legacy_config(&config_path) {
            Ok(cfg) => Some(cfg),
            Err(e) => {
                return emit_error(cmd, as_json, EXIT_ERROR, "CONFIG_ERROR", e, None);
            }
        }
    } else {
        None
    };

    let state_dir = if let Some(ref sd) = args.state_dir {
        sd.clone()
    } else if let Some(ref cfg) = loaded {
        cfg.state_dir
            .clone()
            .unwrap_or_else(|| resolve_state_dir(None, Some(&cfg.path), None))
    } else {
        resolve_state_dir(None, None, None)
    };

    let local_ingest_cfg: LocalIngestConfig = match loaded
        .as_ref()
        .and_then(|c| c.raw.get("localIngest"))
    {
        Some(val) => match serde_json::from_value(val.clone()) {
            Ok(cfg) => cfg,
            Err(e) => {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_ERROR,
                    "CONFIG_ERROR",
                    format!("Invalid localIngest config in {}: {e}", config_path.display()),
                    None,
                );
            }
        },
        None => LocalIngestConfig::default(),
    };

    let stdin_json: Option<Map<String, Value>> = match read_optional_stdin_json() {
        Ok(opt) => opt,
        Err((code, msg)) => {
            return emit_error(cmd, as_json, EXIT_USAGE, code, msg, None);
        }
    };

    let BuiltEmitPayload {
        topic,
        mut event,
        coalesce_key,
        ttl_seconds,
    } = match build_emit_payload(&args, stdin_json.as_ref(), &local_ingest_cfg.default_topic) {
        Ok(built) => built,
        Err((code, msg)) => {
            return emit_error(cmd, as_json, EXIT_USAGE, code, msg, None);
        }
    };

    // Optional Ed25519 signature attachment (`--sign`).
    if args.sign {
        let db_path = state_dir.join("node.sqlite");
        if !db_path.exists() {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                "NOT_INITIALIZED",
                format!(
                    "Cannot sign event: node.sqlite not found at {}",
                    db_path.display()
                ),
                Some(format!("hyp auth init --state-dir {}", state_dir.display())),
            );
        }
        let db = match NodeDb::open(&db_path) {
            Ok(db) => db,
            Err(e) => {
                return emit_error(cmd, as_json, EXIT_ERROR, "DB_ERROR", e.to_string(), None);
            }
        };
        let secrets = open_secret_store(&state_dir, args.state_dir.is_some());
        let (admin_rec, admin_kp) =
            match select_local_signing_authority(&db, &secrets, args.kid.as_deref(), true) {
                Ok(pair) => pair,
                Err(e) => {
                    return emit_error(
                        cmd,
                        as_json,
                        EXIT_ERROR,
                        "ADMIN_KEY_UNAVAILABLE",
                        e,
                        Some(format!("hyp auth init --state-dir {}", state_dir.display())),
                    );
                }
            };
        let label_summary = event
            .extensions
            .get("label")
            .and_then(Value::as_str)
            .or_else(|| {
                event
                    .data
                    .as_ref()
                    .and_then(|d| d.get("label"))
                    .and_then(Value::as_str)
            })
            .or(args.label.as_deref())
            .unwrap_or("-");
        let raw_note = event
            .data
            .as_ref()
            .and_then(|d| d.get("note").or_else(|| d.get("text")))
            .and_then(Value::as_str)
            .or(args.note.as_deref())
            .unwrap_or("-");
        let clean_note_full = sanitize_tty_display(raw_note);
        let note_preview: String = clean_note_full.chars().take(160).collect();
        let note_suffix = if clean_note_full.chars().count() > 160 {
            "..."
        } else {
            ""
        };
        let confirm_summary = vec![
            "Signed Local Event Confirmation (HumanVerified)".to_string(),
            format!(
                "  Authority:  {} (kid: {})",
                sanitize_tty_display(&admin_rec.human_id),
                sanitize_tty_display(&admin_rec.kid)
            ),
            format!("  Topic:      local.{}", sanitize_tty_display(&topic)),
            format!("  Event Type: {}", sanitize_tty_display(&event.event_type)),
            format!("  Source:     {}", sanitize_tty_display(&event.source)),
            format!("  Label:      {}", sanitize_tty_display(label_summary)),
            format!("  Note:       {note_preview}{note_suffix}"),
        ];
        if let Err(err) = require_controlling_tty_confirmation(
            &confirm_summary,
            "Sign & emit this event as HumanVerified? [y/N]: ",
        ) {
            return emit_confirm_error("emit --sign", as_json, err);
        }
        let canonical = match canonical_local_event_for_signing(&event) {
            Ok(c) => c,
            Err(e) => {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_ERROR,
                    "SIGN_FAILED",
                    format!("Failed to canonicalize CloudEvent for signing: {e}"),
                    None,
                );
            }
        };
        let sig = sign_local_ingest_event(&admin_kp, &canonical);
        event.set_extension(EXT_LOCAL_EVENT_SIG, sig);
    }

    let mut wire_obj = match serde_json::to_value(&event) {
        Ok(Value::Object(map)) => map,
        Ok(_) => {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                "SERIALIZE_ERROR",
                "Serialized CloudEvent was not a JSON object",
                None,
            );
        }
        Err(e) => {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                "SERIALIZE_ERROR",
                format!("Failed to serialize CloudEvent: {e}"),
                None,
            );
        }
    };
    wire_obj.insert("topic".to_string(), Value::String(topic.clone()));
    if let Some(ck) = coalesce_key {
        wire_obj.insert("coalesceKey".to_string(), Value::String(ck));
    }
    if let Some(ttl_secs) = ttl_seconds {
        wire_obj.insert("ttlSeconds".to_string(), json!(ttl_secs));
    }
    let wire_json = Value::Object(wire_obj);

    let endpoint_path = args
        .socket
        .clone()
        .unwrap_or_else(|| local_ingest_cfg.resolved_socket_path(&state_dir));

    if !endpoint_path.exists() {
        return emit_error(
            cmd,
            as_json,
            EXIT_ERROR,
            "INGEST_OFFLINE",
            format!(
                "Local ingest socket not found at {} (is `hyp node start` running?)",
                endpoint_path.display()
            ),
            Some("hyp node start".to_string()),
        );
    }

    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                "RUNTIME_ERROR",
                format!("Failed to start async runtime: {e}"),
                None,
            );
        }
    };

    let receipt = match rt.block_on(send_local_ingest_event(&endpoint_path, &wire_json)) {
        Ok(r) => r,
        Err(LocalIngestError::Transport(msg)) => {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                "INGEST_OFFLINE",
                format!(
                    "Failed to reach local ingest endpoint {}: {msg}",
                    endpoint_path.display()
                ),
                Some("hyp node start".to_string()),
            );
        }
        Err(e) => {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                "EMIT_FAILED",
                e.to_string(),
                None,
            );
        }
    };

    if receipt.get("ok").and_then(Value::as_bool) != Some(true) {
        let err_code = receipt
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("EMIT_REJECTED")
            .to_ascii_uppercase();
        let err_msg = receipt
            .get("message")
            .or_else(|| receipt.get("reason"))
            .and_then(Value::as_str)
            .unwrap_or("Local ingest rejected event");
        return emit_error(cmd, as_json, EXIT_ERROR, &err_code, err_msg, None);
    }

    let ev_id = receipt
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or(event.id.as_str());
    let eff_topic = receipt
        .get("topic")
        .and_then(Value::as_str)
        .unwrap_or(&topic);
    let route = receipt
        .get("route")
        .and_then(Value::as_str)
        .unwrap_or("default-schedule");
    let trust_tier = receipt
        .get("trustTier")
        .and_then(Value::as_str)
        .unwrap_or("external-webhook");
    let decision = receipt
        .get("decision")
        .and_then(Value::as_str)
        .unwrap_or("allow");
    let matched = receipt
        .get("matchedSubscribers")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let delivered = receipt
        .get("deliveredSessions")
        .and_then(Value::as_u64)
        .unwrap_or(0);

    let summary = format!(
        "Emitted event {ev_id} to {eff_topic} (decision={decision}, trust={trust_tier}, matched={matched}, delivered={delivered})"
    );

    if as_json {
        let envelope = JsonEnvelope {
            ok: true,
            command: cmd.to_string(),
            summary: Some(summary),
            data: Some(receipt),
            warnings: Vec::new(),
            next: Vec::new(),
            error: None,
        };
        print_json(&envelope);
    } else {
        println!("OK    Emitted event {ev_id} -> {eff_topic}");
        println!("      Route:     {route} (decision={decision}, trust={trust_tier})");
        println!("      Delivery:  {matched} subscriber(s) matched, {delivered} session(s) woken");
        if let Some(human_id) = receipt.get("verifiedHumanId").and_then(Value::as_str) {
            let human_kid = receipt
                .get("verifiedHumanKid")
                .and_then(Value::as_str)
                .unwrap_or("-");
            println!("      Verified:  human={human_id} (kid={human_kid})");
        }
    }

    ExitCode::from(EXIT_OK)
}

struct BuiltEmitPayload {
    topic: String,
    event: CloudEvent,
    coalesce_key: Option<String>,
    ttl_seconds: Option<u64>,
}

fn read_optional_stdin_json() -> Result<Option<Map<String, Value>>, (&'static str, String)> {
    if io::stdin().is_terminal() {
        return Ok(None);
    }
    let mut raw = String::new();
    let max_bytes = MAX_LOCAL_INGEST_LINE_BYTES as u64;
    io::stdin()
        .lock()
        .take(max_bytes + 1)
        .read_to_string(&mut raw)
        .map_err(|e| ("STDIN_ERROR", format!("Failed to read stdin: {e}")))?;
    if (raw.len() as u64) > max_bytes {
        return Err((
            "PAYLOAD_TOO_LARGE",
            format!("Stdin JSON payload exceeds {max_bytes} byte safety cap"),
        ));
    }
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let parsed: Value = serde_json::from_str(trimmed)
        .map_err(|e| ("INVALID_JSON", format!("Invalid JSON on stdin: {e}")))?;
    let Some(obj) = parsed.as_object() else {
        return Err((
            "INVALID_JSON",
            "Stdin JSON payload must be a JSON object".to_string(),
        ));
    };
    Ok(Some(obj.clone()))
}

fn build_emit_payload(
    args: &EmitArgs,
    stdin_obj: Option<&Map<String, Value>>,
    default_topic: &str,
) -> Result<BuiltEmitPayload, (&'static str, String)> {
    let parse_limits = CloudEventLimits {
        max_data_bytes: MAX_LOCAL_INGEST_LINE_BYTES,
        max_event_bytes: MAX_LOCAL_INGEST_LINE_BYTES,
        max_attribute_chars: MAX_ATTRIBUTE_CHARS,
    };

    if let Some(root_map) = stdin_obj {
        // Optional wrapper `{ "topic"?: "...", "event": { ... } }`.
        let (outer_map, body_map) = if !root_map.contains_key("specversion") {
            if let Some(Value::Object(inner)) = root_map.get("event") {
                (Some(root_map), inner)
            } else {
                (None, root_map)
            }
        } else {
            (None, root_map)
        };

        let raw_topic = args
            .topic
            .as_deref()
            .or_else(|| outer_map.and_then(|m| m.get("topic")).and_then(Value::as_str))
            .or_else(|| body_map.get("topic").and_then(Value::as_str))
            .unwrap_or(default_topic)
            .trim();
        let topic = normalize_and_validate_topic(raw_topic)?;

        let coalesce_key = match args.coalesce_key.as_deref() {
            Some(k) => normalize_coalesce_key(k)?,
            None => extract_json_coalesce_key(outer_map, body_map)?,
        };
        let ttl_seconds = match args.ttl {
            Some(t) => Some(t),
            None => extract_json_ttl_seconds(outer_map, body_map)?,
        };

        let event = if body_map.get("specversion").and_then(Value::as_str) == Some("1.0") {
            let mut ce_map = body_map.clone();
            ce_map.remove("auth");
            ce_map.remove("topic");
            ce_map.remove("coalesceKey");
            ce_map.remove("coalesce_key");
            ce_map.remove("ttlSeconds");
            ce_map.remove("ttl_seconds");

            if let Some(ref ty) = args.event_type {
                let t = ty.trim();
                if t.is_empty() {
                    return Err(("INVALID_EVENT", "--type cannot be empty".to_string()));
                }
                ce_map.insert("type".to_string(), Value::String(t.to_string()));
            }
            if let Some(ref src) = args.source {
                let s = src.trim();
                if s.is_empty() {
                    return Err(("INVALID_EVENT", "--source cannot be empty".to_string()));
                }
                ce_map.insert("source".to_string(), Value::String(s.to_string()));
            }
            if args.label.is_some() || args.note.is_some() {
                let data_entry = ce_map
                    .entry("data".to_string())
                    .or_insert_with(|| Value::Object(Map::new()));
                if let Some(data_obj) = data_entry.as_object_mut() {
                    if let Some(ref lbl) = args.label {
                        data_obj.insert("label".to_string(), Value::String(lbl.clone()));
                    }
                    if let Some(ref n) = args.note {
                        data_obj.insert("note".to_string(), Value::String(n.clone()));
                    }
                }
            }
            if let Some(ref lbl) = args.label {
                if lbl.encode_utf16().count() <= MAX_ATTRIBUTE_CHARS {
                    ce_map.insert("label".to_string(), Value::String(lbl.clone()));
                }
            }

            let (ce, _) = check_cloudevent_v2_with_limits(&Value::Object(ce_map), parse_limits)
                .map_err(|e| ("INVALID_EVENT", e.to_string()))?;
            ce
        } else if body_map.contains_key("specversion") {
            return Err((
                "INVALID_EVENT",
                "specversion must be \"1.0\"".to_string(),
            ));
        } else {
            build_shorthand_cloudevent(args, body_map, parse_limits)?
        };

        return Ok(BuiltEmitPayload {
            topic,
            event,
            coalesce_key,
            ttl_seconds,
        });
    }

    // Pure flag mode.
    let raw_topic = args.topic.as_deref().unwrap_or(default_topic).trim();
    let topic = normalize_and_validate_topic(raw_topic)?;
    let coalesce_key = match args.coalesce_key.as_deref() {
        Some(k) => normalize_coalesce_key(k)?,
        None => None,
    };

    let event_type = match args.event_type.as_deref() {
        Some(t) => {
            let trimmed = t.trim();
            if trimmed.is_empty() {
                return Err(("INVALID_EVENT", "--type cannot be empty".to_string()));
            }
            trimmed.to_string()
        }
        None => TYPE_SCHEDULED_MESSAGE_V1.to_string(),
    };
    let source = match args.source.as_deref() {
        Some(s) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                return Err(("INVALID_EVENT", "--source cannot be empty".to_string()));
            }
            trimmed.to_string()
        }
        None => DEFAULT_EMIT_SOURCE.to_string(),
    };

    let mut data_obj = Map::new();
    let mut extensions = BTreeMap::new();
    if let Some(ref lbl) = args.label {
        data_obj.insert("label".to_string(), Value::String(lbl.clone()));
        if lbl.encode_utf16().count() <= MAX_ATTRIBUTE_CHARS {
            extensions.insert("label".to_string(), Value::String(lbl.clone()));
        }
    }
    if let Some(ref n) = args.note {
        data_obj.insert("note".to_string(), Value::String(n.clone()));
    }

    let ce = CloudEvent {
        specversion: "1.0".to_string(),
        id: format!("local-{}", uuid_v4()),
        source,
        event_type,
        datacontenttype: Some(CONTENT_TYPE_JSON.to_string()),
        dataschema: None,
        subject: None,
        time: Some(format_rfc3339_millis(now_unix_ms())),
        data: Some(Value::Object(data_obj)),
        data_base64: None,
        extensions,
    };

    let ce_val = serde_json::to_value(&ce)
        .map_err(|e| ("INVALID_EVENT", format!("failed to serialize CloudEvent: {e}")))?;
    let (validated, _) = check_cloudevent_v2_with_limits(&ce_val, parse_limits)
        .map_err(|e| ("INVALID_EVENT", e.to_string()))?;

    Ok(BuiltEmitPayload {
        topic,
        event: validated,
        coalesce_key,
        ttl_seconds: args.ttl,
    })
}

fn build_shorthand_cloudevent(
    args: &EmitArgs,
    map: &Map<String, Value>,
    parse_limits: CloudEventLimits,
) -> Result<CloudEvent, (&'static str, String)> {
    let event_type = if let Some(ref t) = args.event_type {
        let trimmed = t.trim();
        if trimmed.is_empty() {
            return Err(("INVALID_EVENT", "--type cannot be empty".to_string()));
        }
        trimmed.to_string()
    } else {
        match map.get("type") {
            None | Some(Value::Null) => TYPE_SCHEDULED_MESSAGE_V1.to_string(),
            Some(Value::String(s)) if !s.trim().is_empty() => s.trim().to_string(),
            _ => {
                return Err(("INVALID_EVENT", "type must be a non-empty string".to_string()));
            }
        }
    };

    let source = if let Some(ref s) = args.source {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Err(("INVALID_EVENT", "--source cannot be empty".to_string()));
        }
        trimmed.to_string()
    } else {
        match map.get("source") {
            None | Some(Value::Null) => DEFAULT_EMIT_SOURCE.to_string(),
            Some(Value::String(s)) if !s.trim().is_empty() => s.trim().to_string(),
            _ => {
                return Err((
                    "INVALID_EVENT",
                    "source must be a non-empty string".to_string(),
                ));
            }
        }
    };

    let id = match map.get("id") {
        None | Some(Value::Null) => format!("local-{}", uuid_v4()),
        Some(Value::String(s)) if !s.trim().is_empty() => s.trim().to_string(),
        _ => return Err(("INVALID_EVENT", "id must be a non-empty string".to_string())),
    };

    let time = match map.get("time") {
        None | Some(Value::Null) => format_rfc3339_millis(now_unix_ms()),
        Some(Value::String(t)) => {
            if !is_valid_rfc3339_strict(t) {
                return Err((
                    "INVALID_EVENT",
                    "time must be an RFC 3339 timestamp".to_string(),
                ));
            }
            t.clone()
        }
        _ => {
            return Err((
                "INVALID_EVENT",
                "time must be an RFC 3339 string".to_string(),
            ));
        }
    };

    let datacontenttype = match map.get("datacontenttype") {
        None | Some(Value::Null) => CONTENT_TYPE_JSON.to_string(),
        Some(Value::String(s)) if !s.trim().is_empty() => s.trim().to_string(),
        _ => {
            return Err((
                "INVALID_EVENT",
                "datacontenttype must be a non-empty string".to_string(),
            ));
        }
    };

    let subject = match map.get("subject") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.clone()),
        _ => return Err(("INVALID_EVENT", "subject must be a string".to_string())),
    };

    let label = if let Some(ref cli_lbl) = args.label {
        Some(cli_lbl.clone())
    } else {
        match map.get("label") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) => Some(s.clone()),
            _ => return Err(("INVALID_EVENT", "label must be a string".to_string())),
        }
    };

    let note = if let Some(ref cli_note) = args.note {
        Some(cli_note.clone())
    } else {
        match map.get("note") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) => Some(s.clone()),
            _ => return Err(("INVALID_EVENT", "note must be a string".to_string())),
        }
    };

    let text = match map.get("text") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.clone()),
        _ => return Err(("INVALID_EVENT", "text must be a string".to_string())),
    };

    let mut data_obj = match map.get("data") {
        None | Some(Value::Null) => Map::new(),
        Some(Value::Object(obj)) => obj.clone(),
        Some(other) => {
            let mut m = Map::new();
            m.insert("value".to_string(), other.clone());
            m
        }
    };
    if let Some(ref lbl) = label {
        if args.label.is_some() {
            data_obj.insert("label".to_string(), Value::String(lbl.clone()));
        } else {
            data_obj
                .entry("label".to_string())
                .or_insert_with(|| Value::String(lbl.clone()));
        }
    }
    if let Some(ref n) = note {
        if args.note.is_some() {
            data_obj.insert("note".to_string(), Value::String(n.clone()));
        } else {
            data_obj
                .entry("note".to_string())
                .or_insert_with(|| Value::String(n.clone()));
        }
    }
    if let Some(ref t) = text {
        data_obj
            .entry("text".to_string())
            .or_insert_with(|| Value::String(t.clone()));
    }

    let mut extensions = BTreeMap::new();
    if let Some(ref lbl) = label {
        if lbl.encode_utf16().count() <= MAX_ATTRIBUTE_CHARS {
            extensions.insert("label".to_string(), Value::String(lbl.clone()));
        }
    }

    if let Some(sig_val) = map.get(EXT_LOCAL_EVENT_SIG) {
        let Some(sig_str) = sig_val.as_str() else {
            return Err(("INVALID_EVENT", "hyphaesig must be a string".to_string()));
        };
        extensions.insert(
            EXT_LOCAL_EVENT_SIG.to_string(),
            Value::String(sig_str.to_string()),
        );
    }

    for (k, v) in map {
        if matches!(
            k.as_str(),
            "specversion"
                | "id"
                | "source"
                | "type"
                | "datacontenttype"
                | "dataschema"
                | "subject"
                | "time"
                | "data"
                | "data_base64"
                | "topic"
                | "auth"
                | "label"
                | "note"
                | "text"
                | "coalesceKey"
                | "coalesce_key"
                | "ttlSeconds"
                | "ttl_seconds"
                | "hyphaesig"
        ) {
            continue;
        }
        if is_extension_name(k) {
            if let Value::String(s) = v {
                extensions.insert(k.clone(), Value::String(s.clone()));
            }
        }
    }

    let ce = CloudEvent {
        specversion: "1.0".to_string(),
        id,
        source,
        event_type,
        datacontenttype: Some(datacontenttype),
        dataschema: map
            .get("dataschema")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        subject,
        time: Some(time),
        data: Some(Value::Object(data_obj)),
        data_base64: None,
        extensions,
    };

    let ce_val = serde_json::to_value(&ce)
        .map_err(|e| ("INVALID_EVENT", format!("failed to serialize CloudEvent: {e}")))?;
    let (validated, _) = check_cloudevent_v2_with_limits(&ce_val, parse_limits)
        .map_err(|e| ("INVALID_EVENT", e.to_string()))?;
    Ok(validated)
}

fn normalize_and_validate_topic(raw: &str) -> Result<String, (&'static str, String)> {
    let bare = raw.strip_prefix("local.").unwrap_or(raw).trim();
    if !is_valid_topic(bare) {
        return Err((
            "INVALID_TOPIC",
            format!("Invalid local topic '{raw}' (expected /^[a-z0-9][a-z0-9._-]{{0,63}}$/)"),
        ));
    }
    Ok(bare.to_string())
}

fn normalize_coalesce_key(raw: &str) -> Result<Option<String>, (&'static str, String)> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if trimmed.len() > 128 || trimmed.chars().any(char::is_control) {
        return Err((
            "INVALID_COALESCE_KEY",
            "coalesceKey must be <= 128 printable characters".to_string(),
        ));
    }
    Ok(Some(trimmed.to_string()))
}

fn extract_json_coalesce_key(
    outer: Option<&Map<String, Value>>,
    body: &Map<String, Value>,
) -> Result<Option<String>, (&'static str, String)> {
    let val = outer
        .and_then(|m| m.get("coalesceKey").or_else(|| m.get("coalesce_key")))
        .or_else(|| body.get("coalesceKey").or_else(|| body.get("coalesce_key")));
    match val {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => normalize_coalesce_key(s),
        _ => Err((
            "INVALID_COALESCE_KEY",
            "coalesceKey must be a string".to_string(),
        )),
    }
}

fn extract_json_ttl_seconds(
    outer: Option<&Map<String, Value>>,
    body: &Map<String, Value>,
) -> Result<Option<u64>, (&'static str, String)> {
    let val = outer
        .and_then(|m| m.get("ttlSeconds").or_else(|| m.get("ttl_seconds")))
        .or_else(|| body.get("ttlSeconds").or_else(|| body.get("ttl_seconds")));
    match val {
        None | Some(Value::Null) => Ok(None),
        Some(v) => {
            let Some(secs) = v.as_u64() else {
                return Err((
                    "INVALID_TTL",
                    "ttlSeconds must be a positive integer".to_string(),
                ));
            };
            if secs == 0 || secs > MAX_TTL_SECONDS {
                return Err((
                    "INVALID_TTL",
                    format!("ttlSeconds must be in 1..={MAX_TTL_SECONDS}"),
                ));
            }
            Ok(Some(secs))
        }
    }
}
