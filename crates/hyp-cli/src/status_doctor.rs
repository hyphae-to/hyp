//! `hyp status` & `hyp doctor` — Node identity, Peer Capabilities & Version Skew UX
//! (`docs/architecture-v2.md §3.3`), Security Gate policy verification, update notice, and
//! harness setup diagnostics.

use crate::config_file::{
    LoadedNodeFile, load_node_or_legacy_config, open_secret_store, profile_as_str,
    resolve_config_path_for_read, resolve_effective_node_id, resolve_home_dir, resolve_state_dir,
};
use crate::gate_cmd::inspect_gate_status;
use crate::setup::{HarnessDiagnostic, detect_harness_statuses};
use crate::ui::{
    CheckStatus, CliCheck, CliError, EXIT_ERROR, EXIT_OK, JsonEnvelope, emit_error, print_checks,
    print_json, print_next_steps, print_warnings,
};
use crate::update::read_cached_update_status;
use clap::Args;
use hyp_node::engine::{DEFAULT_HYPHAE_VERSION, NodeProfile};
use hyp_proto::manifest::{
    CapabilityToken, NodeManifestPayload, ProtocolRange, SignedNodeManifest,
};
use hyp_proto::{MIN_PROTOCOL_VERSION, PROTOCOL_VERSION};
use hyp_store::{CURRENT_SCHEMA_VERSION, NodeDb, PeerRecord, TrustTier, now_ms};
use serde::Serialize;
use serde_json::json;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Args)]
pub struct StatusArgs {
    /// Explicit state directory containing node.sqlite and secrets/
    #[arg(long)]
    pub state_dir: Option<PathBuf>,
    /// Explicit node.json (or legacy connector.json) path
    #[arg(long)]
    pub config: Option<PathBuf>,
    /// Override home directory for harness detection
    #[arg(long)]
    pub home: Option<PathBuf>,
    /// Output structured JSON envelope
    #[arg(long)]
    pub json: bool,
}

#[derive(Args)]
pub struct DoctorArgs {
    /// Explicit state directory containing node.sqlite and secrets/
    #[arg(long)]
    pub state_dir: Option<PathBuf>,
    /// Explicit node.json (or legacy connector.json) path
    #[arg(long)]
    pub config: Option<PathBuf>,
    /// Override home directory for harness detection
    #[arg(long)]
    pub home: Option<PathBuf>,
    /// Output structured JSON envelope
    #[arg(long)]
    pub json: bool,
}

/// Pre-migration SQLite backup inventory reported under `data.storage.migrationBackups`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MigrationBackupsReport {
    pub dir: String,
    pub count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<String>,
}

/// SQLite storage & schema migration status reported under `data.storage`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageStatusReport {
    pub path: String,
    pub exists: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub journal_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema_version: Option<i64>,
    pub supported_schema_version: i64,
    pub applied_migrations: usize,
    pub migration_backups: MigrationBackupsReport,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Single row in the Peer Capabilities & Version Skew table (`docs/architecture-v2.md §3.3`).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerSkewRow {
    pub status: CheckStatus,
    pub peer: String,
    pub version: String,
    pub proto: String,
    pub e2ee: String,
    pub streams: String,
    pub kv: String,
    pub notes: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upgrade_hint: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub missing_capabilities: Vec<String>,
}

pub fn run_status(args: StatusArgs) -> ExitCode {
    run_status_or_doctor(args.state_dir, args.config, args.home, args.json, false)
}

pub fn run_doctor(args: DoctorArgs) -> ExitCode {
    run_status_or_doctor(args.state_dir, args.config, args.home, args.json, true)
}

fn run_status_or_doctor(
    state_dir_arg: Option<PathBuf>,
    config_arg: Option<PathBuf>,
    home_arg: Option<PathBuf>,
    as_json: bool,
    is_doctor: bool,
) -> ExitCode {
    let cmd = if is_doctor { "doctor" } else { "status" };
    let state_dir = resolve_state_dir(
        state_dir_arg.as_deref(),
        config_arg.as_deref(),
        home_arg.as_deref(),
    );
    let config_path = resolve_config_path_for_read(
        config_arg.as_deref(),
        state_dir_arg.as_deref(),
        home_arg.as_deref(),
    );

    let mut checks: Vec<CliCheck> = Vec::new();
    let mut loaded_cfg: Option<LoadedNodeFile> = None;

    if config_path.exists() {
        match load_node_or_legacy_config(&config_path) {
            Ok(cfg) => {
                if cfg.is_legacy_v1 {
                    checks.push(CliCheck::warn(
                        "config",
                        format!("Loaded legacy v1 connector config at {}", cfg.path.display()),
                        Some("Run `hyp onboard` to write native v2 node.json.".to_string()),
                    ));
                } else {
                    checks.push(CliCheck::ok(
                        "config",
                        format!("Loaded {}", cfg.path.display()),
                    ));
                }
                loaded_cfg = Some(cfg);
            }
            Err(e) => {
                checks.push(CliCheck::fail(
                    "config",
                    e,
                    Some(format!("Fix JSON syntax in {}.", config_path.display())),
                ));
            }
        }
    } else {
        checks.push(CliCheck::warn(
            "config",
            format!("No node.json found at {}", config_path.display()),
            Some("Run `hyp onboard` to initialize node.json and keys.".to_string()),
        ));
    }

    // Open node.sqlite if it exists (avoid creating empty DB on read-only status when directory doesn't exist)
    let db_path = state_dir.join("node.sqlite");
    let backups_dir = state_dir.join("backups");
    let mut schema_downgrade = false;
    let (db, storage_status): (Option<NodeDb>, StorageStatusReport) = if db_path.exists() {
        match NodeDb::open(&db_path) {
            Ok(db) => {
                let wal = db.journal_mode().unwrap_or_else(|_| "unknown".to_string());
                let schema = db.schema_version().unwrap_or(0);
                let applied_migrations = db.applied_migrations().map(|v| v.len()).unwrap_or(0);
                let backups = db.list_migration_backups().unwrap_or_default();
                let backup_note = format_backup_note(backups.len());
                checks.push(CliCheck::ok(
                    "store.sqlite",
                    format!("node.sqlite schema v{schema}{backup_note}"),
                ));
                let backup_files: Vec<String> = backups
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect();
                let report = StorageStatusReport {
                    path: db_path.display().to_string(),
                    exists: true,
                    journal_mode: Some(wal),
                    schema_version: Some(schema),
                    supported_schema_version: CURRENT_SCHEMA_VERSION,
                    applied_migrations,
                    migration_backups: MigrationBackupsReport {
                        dir: backups_dir.display().to_string(),
                        count: backup_files.len(),
                        latest: backup_files.first().cloned(),
                        files: backup_files,
                    },
                    error: None,
                };
                (Some(db), report)
            }
            Err(e) => {
                let err_msg = e.to_string();
                let is_downgrade = err_msg.contains("is newer than supported version");
                schema_downgrade = is_downgrade;
                let disk_backups = scan_migration_backups(&backups_dir);
                let backup_files: Vec<String> = disk_backups
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect();
                let fix = if is_downgrade {
                    Some(format!(
                        "Run `hyp update` to upgrade this binary, or restore a pre-migration backup from {}/.",
                        backups_dir.display()
                    ))
                } else {
                    Some(format!(
                        "Verify permissions and integrity of {} (pre-migration backups in {}/).",
                        db_path.display(),
                        backups_dir.display()
                    ))
                };
                let detail = if is_downgrade {
                    format!(
                        "Schema downgrade blocked for {} (supported v{CURRENT_SCHEMA_VERSION}): {err_msg}",
                        db_path.display()
                    )
                } else {
                    format!("Failed to open {}: {err_msg}", db_path.display())
                };
                checks.push(CliCheck::fail("store.sqlite", detail.clone(), fix.clone()));
                if !is_doctor {
                    return emit_error(
                        cmd,
                        as_json,
                        EXIT_ERROR,
                        if is_downgrade {
                            "SCHEMA_TOO_NEW"
                        } else {
                            "DB_ERROR"
                        },
                        detail,
                        fix,
                    );
                }
                let report = StorageStatusReport {
                    path: db_path.display().to_string(),
                    exists: true,
                    journal_mode: None,
                    schema_version: None,
                    supported_schema_version: CURRENT_SCHEMA_VERSION,
                    applied_migrations: 0,
                    migration_backups: MigrationBackupsReport {
                        dir: backups_dir.display().to_string(),
                        count: backup_files.len(),
                        latest: backup_files.first().cloned(),
                        files: backup_files,
                    },
                    error: Some(err_msg),
                };
                (None, report)
            }
        }
    } else {
        let disk_backups = scan_migration_backups(&backups_dir);
        let backup_files: Vec<String> = disk_backups
            .iter()
            .map(|p| p.display().to_string())
            .collect();
        checks.push(CliCheck::warn(
            "store.sqlite",
            format!("Database not initialized yet at {}", db_path.display()),
            Some("Run `hyp onboard` or `hyp node start`.".to_string()),
        ));
        let report = StorageStatusReport {
            path: db_path.display().to_string(),
            exists: false,
            journal_mode: None,
            schema_version: None,
            supported_schema_version: CURRENT_SCHEMA_VERSION,
            applied_migrations: 0,
            migration_backups: MigrationBackupsReport {
                dir: backups_dir.display().to_string(),
                count: backup_files.len(),
                latest: backup_files.first().cloned(),
                files: backup_files,
            },
            error: None,
        };
        (None, report)
    };

    let node_id = resolve_effective_node_id(loaded_cfg.as_ref(), db.as_ref());
    let profile = loaded_cfg
        .as_ref()
        .and_then(|c| c.profile)
        .or_else(|| {
            db.as_ref()
                .and_then(|d| d.local().get_metadata("node_profile").ok().flatten())
                .and_then(|s| match s.as_str() {
                    "router" => Some(NodeProfile::Router),
                    "p2p" => Some(NodeProfile::P2p),
                    "local" => Some(NodeProfile::Local),
                    _ => None,
                })
        })
        .unwrap_or(NodeProfile::Local);
    let require_e2ee = loaded_cfg.as_ref().map(|c| c.require_e2ee).unwrap_or(true);

    // Load identity keys if already present (do not silently create brand new keys on status/doctor if dir missing).
    let explicit_state = state_dir_arg.is_some();
    let secrets = open_secret_store(&state_dir, explicit_state);
    let (kid, fingerprint) = if state_dir.join("secrets").exists() || !explicit_state {
        match secrets.load_or_create_node_keys(&node_id) {
            Ok(keys) => (Some(keys.kid()), Some(keys.fingerprint())),
            Err(_) => (None, None),
        }
    } else {
        (None, None)
    };

    // Daemon PID & local IPC socket status
    let pid_path = state_dir.join("node.pid");
    let running_pid: Option<u32> = fs::read_to_string(&pid_path)
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok());
    let status_path = state_dir.join("node.status.json");
    let socket_path: Option<String> = fs::read_to_string(&status_path)
        .ok()
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok())
        .and_then(|v| {
            v.get("socketPath")
                .and_then(serde_json::Value::as_str)
                .map(ToOwned::to_owned)
        });
    if let Some(ref sock) = socket_path {
        if std::path::Path::new(sock).exists() {
            checks.push(CliCheck::ok(
                "daemon.socket",
                format!("Local IPC ready at {sock}"),
            ));
        } else if running_pid.is_some() {
            checks.push(CliCheck::warn(
                "daemon.socket",
                format!("Recorded local IPC socket missing: {sock}"),
                Some("Restart `hyp node start` to recreate the local IPC socket.".to_string()),
            ));
        }
    }

    // Local runtime counts from node.sqlite
    let sessions_count = db
        .as_ref()
        .and_then(|d| d.local().list_sessions().ok())
        .map(|v| v.len())
        .unwrap_or(0);
    let subs_count = db
        .as_ref()
        .and_then(|d| d.events().list_subscriptions(None).ok())
        .map(|v| v.len())
        .unwrap_or(0);
    let kv_namespaces = db
        .as_ref()
        .and_then(|d| d.kv().list_namespaces("local", now_ms()).ok())
        .unwrap_or_default();
    let peers = db
        .as_ref()
        .and_then(|d| d.peers().list_peers(None).ok())
        .unwrap_or_default();

    // 1. Peer Capabilities & Version Skew table (§3.3)
    let mut skew_rows = Vec::with_capacity(peers.len() + 1);
    skew_rows.push(PeerSkewRow {
        status: CheckStatus::Ok,
        peer: "local".to_string(),
        version: DEFAULT_HYPHAE_VERSION.to_string(),
        proto: format!("v{PROTOCOL_VERSION}"),
        e2ee: "n/a".to_string(),
        streams: "pushdown".to_string(),
        kv: "kv.e2ee.v1".to_string(),
        notes: format!("local node ({node_id})"),
        upgrade_hint: None,
        missing_capabilities: Vec::new(),
    });

    for peer in &peers {
        let row = evaluate_peer_skew(peer, require_e2ee);
        let check_name = format!("peer:{}", row.peer);
        match row.status {
            CheckStatus::Ok => checks.push(CliCheck::ok(
                check_name,
                format!("{} ({}, e2ee={}, kv={})", row.version, row.proto, row.e2ee, row.kv),
            )),
            CheckStatus::Warn => checks.push(CliCheck::warn(
                check_name,
                row.notes.clone(),
                row.upgrade_hint.clone(),
            )),
            CheckStatus::Fail => checks.push(CliCheck::fail(
                check_name,
                row.notes.clone(),
                row.upgrade_hint.clone(),
            )),
        }
        skew_rows.push(row);
    }

    // 2. Security Gate Policy & Quarantine status
    let gate_status = inspect_gate_status(
        loaded_cfg.as_ref().map(|c| &c.raw),
        &secrets,
        db.as_ref(),
    );
    match gate_status.gate_policy_sig.as_str() {
        "OK" => checks.push(CliCheck::ok("gate.policy_sig", gate_status.detail.clone())),
        "FAIL" => checks.push(CliCheck::fail(
            "gate.policy_sig",
            gate_status.detail.clone(),
            Some(format!(
                "Inspect {} for unauthorized edits, then re-sign via `hyp gate lock --config {} --state-dir {}`.",
                config_path.display(),
                config_path.display(),
                state_dir.display()
            )),
        )),
        _ => {
            if gate_status.configured {
                checks.push(CliCheck::warn(
                    "gate.policy_sig",
                    gate_status.detail.clone(),
                    Some(format!(
                        "hyp gate lock --config {} --state-dir {}",
                        config_path.display(),
                        state_dir.display()
                    )),
                ));
            } else {
                checks.push(CliCheck::ok("gate.policy_sig", gate_status.detail.clone()));
            }
        }
    }
    if gate_status.quarantined_count > 0 {
        checks.push(CliCheck::warn(
            "gate.quarantine",
            format!(
                "{} quarantined item(s) awaiting human CLI review",
                gate_status.quarantined_count
            ),
            Some(format!("hyp gate review --state-dir {}", state_dir.display())),
        ));
    }

    // 3. Update channel & cached available update notice
    let update_status = read_cached_update_status(
        loaded_cfg.as_ref().and_then(|c| c.update_channel.as_deref()),
        db.as_ref(),
        now_ms(),
    );
    if update_status.should_notify {
        if let Some(ref avail) = update_status.available_version {
            checks.push(CliCheck::warn(
                "update",
                format!(
                    "New {} release available: {} (current: {})",
                    update_status.channel, avail, update_status.current_version
                ),
                Some(format!("hyp update --channel {}", update_status.channel)),
            ));
        }
    }

    // 4. Harness setup diagnostics
    let harnesses: Vec<HarnessDiagnostic> = resolve_home_dir(home_arg.as_deref())
        .map(|h| detect_harness_statuses(&h, loaded_cfg.as_ref().map(|c| c.path.as_path())))
        .unwrap_or_default();
    for h in &harnesses {
        if h.detected || h.configured {
            if h.configured {
                checks.push(CliCheck::ok(format!("harness:{}", h.harness), h.detail.clone()));
            } else {
                checks.push(CliCheck::warn(
                    format!("harness:{}", h.harness),
                    h.detail.clone(),
                    h.fix.clone(),
                ));
            }
        }
    }

    let fail_count = checks
        .iter()
        .filter(|c| c.status == CheckStatus::Fail)
        .count();
    let warn_count = checks
        .iter()
        .filter(|c| c.status == CheckStatus::Warn)
        .count();

    let warnings: Vec<String> = checks
        .iter()
        .filter(|c| c.status == CheckStatus::Warn)
        .map(|c| format!("{}: {}", c.name, c.detail))
        .collect();

    let mut next: Vec<String> = checks
        .iter()
        .filter(|c| matches!(c.status, CheckStatus::Fail | CheckStatus::Warn))
        .filter_map(|c| c.fix.clone())
        .collect();
    next.dedup();

    let ok = if is_doctor { fail_count == 0 } else { true };
    let summary = if is_doctor {
        if ok {
            format!(
                "Doctor passed for '{}' ({warn_count} warning(s), {} peer(s))",
                node_id,
                peers.len()
            )
        } else {
            format!(
                "Doctor found {fail_count} failure(s) and {warn_count} warning(s) for '{node_id}'"
            )
        }
    } else {
        format!(
            "Node '{}' ({}) · {} peer(s), {} session(s), {} quarantined",
            node_id,
            profile_as_str(profile),
            peers.len(),
            sessions_count,
            gate_status.quarantined_count
        )
    };

    let data = json!({
        "node": {
            "nodeId": node_id,
            "profile": profile_as_str(profile),
            "version": DEFAULT_HYPHAE_VERSION,
            "binaryVersion": env!("CARGO_PKG_VERSION"),
            "protocol": PROTOCOL_VERSION,
            "kid": kid,
            "fingerprint": fingerprint,
            "runningPid": running_pid,
            "socketPath": socket_path,
            "stateDir": state_dir.display().to_string(),
            "configPath": config_path.display().to_string(),
            "sessions": sessions_count,
            "subscriptions": subs_count,
            "kvNamespaces": kv_namespaces,
        },
        "storage": storage_status,
        "peers": skew_rows,
        "gate": gate_status,
        "update": update_status,
        "harnesses": harnesses,
        "checks": checks,
    });

    if as_json {
        let error = if ok {
            None
        } else {
            Some(CliError {
                code: if gate_status.tampered {
                    "GATE_POLICY_TAMPERED".to_string()
                } else if schema_downgrade {
                    "SCHEMA_TOO_NEW".to_string()
                } else {
                    "DOCTOR_FAILED".to_string()
                },
                message: summary.clone(),
                fix: next.first().cloned(),
            })
        };
        let envelope = JsonEnvelope {
            ok,
            command: cmd.to_string(),
            summary: Some(summary),
            data: Some(data),
            warnings,
            next,
            error,
        };
        print_json(&envelope);
    } else {
        println!(
            "Hyphae v2 {} — {} ({})",
            if is_doctor { "Doctor" } else { "Status" },
            node_id,
            profile_as_str(profile)
        );
        println!(
            "  Version:  {} (bin {}, proto v{})",
            DEFAULT_HYPHAE_VERSION,
            env!("CARGO_PKG_VERSION"),
            PROTOCOL_VERSION
        );
        if let Some(ref k) = kid {
            println!(
                "  Identity: kid={k} (fp={})",
                fingerprint.as_deref().unwrap_or("-")
            );
        }
        if let Some(ref sock) = socket_path {
            println!("  Local IPC: {sock}");
        }
        if let Some(v) = storage_status.schema_version {
            println!(
                "  Storage:  node.sqlite schema v{v}{}",
                format_backup_note(storage_status.migration_backups.count)
            );
        } else if let Some(ref err) = storage_status.error {
            println!("  Storage:  FAIL ({err})");
        }
        println!(
            "  Gate:     {} (filters={}, quarantined={})",
            gate_status.gate_policy_sig,
            gate_status.filters.len(),
            gate_status.quarantined_count
        );
        println!(
            "  Update:   channel={}{}",
            update_status.channel,
            update_status
                .available_version
                .as_deref()
                .map(|v| format!(" (available: {v})"))
                .unwrap_or_default()
        );
        println!();
        println!("Peer Capabilities & Version Skew");
        println!(
            "{:<6}  {:<18}  {:<10}  {:<5}  {:<10}  {:<10}  {:<10}  Notes",
            "Status", "Peer", "Version", "Proto", "E2EE", "Streams", "KV"
        );
        println!("{}", "-".repeat(102));
        for r in &skew_rows {
            println!(
                "{:<6}  {:<18}  {:<10}  {:<5}  {:<10}  {:<10}  {:<10}  {}",
                r.status.tag(),
                r.peer,
                r.version,
                r.proto,
                r.e2ee,
                r.streams,
                r.kv,
                r.notes
            );
        }
        if is_doctor {
            println!();
            println!("Diagnostics");
            print_checks(&checks);
        } else {
            print_warnings(&warnings);
        }
        print_next_steps(&next);
    }

    if ok {
        ExitCode::from(EXIT_OK)
    } else {
        ExitCode::from(EXIT_ERROR)
    }
}

/// Evaluates a paired peer's cached manifest (or legacy v1 fallback) into a `PeerSkewRow`
/// matching `docs/architecture-v2.md §3.2–§3.3`.
pub fn evaluate_peer_skew(peer: &PeerRecord, local_require_e2ee: bool) -> PeerSkewRow {
    let parsed_manifest = peer.manifest_json.as_deref().and_then(parse_cached_manifest);

    // Determine if this peer is a read-only public guest hub (e.g. public.hyphae.to) where DMs/KV are unused.
    let is_guest_ro = peer.trust_tier == TrustTier::Guest
        && !peer
            .scopes
            .iter()
            .any(|s| s.starts_with("dm:") || s.starts_with("messages:") || s == "*");

    let (version, proto_range, caps, is_legacy_v1) = match parsed_manifest {
        Some(m) => {
            let cap_set: BTreeSet<String> = m
                .capabilities
                .iter()
                .map(|c| c.as_str().to_string())
                .collect();
            let legacy = m.protocol_range.max <= 1 || m.hyphae_version == "legacy-v1";
            (m.hyphae_version, m.protocol_range, cap_set, legacy)
        }
        None => {
            let mut cap_set = BTreeSet::new();
            cap_set.insert("dm.v1".to_string());
            cap_set.insert("channel.v1".to_string());
            cap_set.insert("events.v1".to_string());
            (
                "1.1.0".to_string(),
                ProtocolRange { min: 1, max: 1 },
                cap_set,
                true,
            )
        }
    };

    // Protocol range intersection check
    let min_agreed = MIN_PROTOCOL_VERSION.max(proto_range.min);
    let max_agreed = PROTOCOL_VERSION.min(proto_range.max);
    let proto_label = if max_agreed >= min_agreed {
        format!("v{max_agreed}")
    } else {
        format!("v{}..{}", proto_range.min, proto_range.max)
    };

    let has_dm_e2ee = caps.contains(CapabilityToken::DmE2eeV1.as_str());
    let has_chan_e2ee = caps.contains(CapabilityToken::ChannelE2eeV1.as_str());
    let has_pushdown = caps.contains(CapabilityToken::SubPushdownV1.as_str());
    let has_events_v1 = caps.contains(CapabilityToken::EventsV1.as_str());
    let has_kv_e2ee = caps.contains(CapabilityToken::KvE2eeV1.as_str());
    let has_kv_v1 = caps.contains(CapabilityToken::KvV1.as_str());
    let has_transfer_v2 = caps.contains(CapabilityToken::TransferStreamV2.as_str());

    let e2ee_col = if is_guest_ro {
        "n/a (ro)".to_string()
    } else if has_dm_e2ee && has_chan_e2ee {
        "dm+chan".to_string()
    } else if has_dm_e2ee {
        "dm".to_string()
    } else {
        "missing".to_string()
    };

    let streams_col = if has_pushdown {
        "pushdown".to_string()
    } else if has_events_v1 {
        "events.v1".to_string()
    } else {
        "missing".to_string()
    };

    let kv_col = if has_kv_e2ee {
        "kv.e2ee.v1".to_string()
    } else if has_kv_v1 {
        "kv.v1".to_string()
    } else if is_guest_ro {
        "n/a".to_string()
    } else {
        "missing".to_string()
    };

    // 1. Disjoint protocol range -> FAIL
    if max_agreed < min_agreed {
        return PeerSkewRow {
            status: CheckStatus::Fail,
            peer: peer.peer_id.clone(),
            version,
            proto: proto_label,
            e2ee: e2ee_col,
            streams: streams_col,
            kv: kv_col,
            notes: format!(
                "Blocked: protocol_incompatible (local {}..={}, remote {}..={})",
                MIN_PROTOCOL_VERSION, PROTOCOL_VERSION, proto_range.min, proto_range.max
            ),
            upgrade_hint: Some(format!(
                "Upgrade '{}' or local hyp to a compatible major protocol version.",
                peer.peer_id
            )),
            missing_capabilities: vec!["protocol_incompatible".to_string()],
        };
    }

    // 2. Anti-downgrade check: previously observed E2EE capability vanished -> FAIL
    let dropped_e2ee: Vec<String> = peer
        .observed_e2ee_caps
        .iter()
        .filter(|c| !caps.contains(c.as_str()))
        .cloned()
        .collect();
    if !dropped_e2ee.is_empty() {
        return PeerSkewRow {
            status: CheckStatus::Fail,
            peer: peer.peer_id.clone(),
            version,
            proto: proto_label,
            e2ee: e2ee_col,
            streams: streams_col,
            kv: kv_col,
            notes: format!(
                "Blocked: capability_downgrade_detected (previously observed {} vanished)",
                dropped_e2ee.join(", ")
            ),
            upgrade_hint: Some(format!(
                "Verify '{}' integrity or override explicitly via `hyp peer trust --accept-downgrade {}`.",
                peer.peer_id, peer.peer_id
            )),
            missing_capabilities: dropped_e2ee,
        };
    }

    // 3. Required E2EE check (for non-guest-ro peers)
    if !is_guest_ro && local_require_e2ee && !has_dm_e2ee {
        return PeerSkewRow {
            status: CheckStatus::Fail,
            peer: peer.peer_id.clone(),
            version,
            proto: proto_label,
            e2ee: e2ee_col,
            streams: streams_col,
            kv: kv_col,
            notes: "Blocked: requireE2ee=true but peer lacks dm.e2ee.v1".to_string(),
            upgrade_hint: Some(format!(
                "Upgrade '{}' to Hyphae v2 (or run `hyp peer policy {} --e2ee prefer` if plaintext is acceptable).",
                peer.peer_id, peer.peer_id
            )),
            missing_capabilities: vec!["dm.e2ee.v1".to_string()],
        };
    }

    // 4. Optional degraded capabilities -> WARN
    let mut missing_optional = Vec::new();
    if !is_guest_ro {
        if !has_kv_v1 && !has_kv_e2ee {
            missing_optional.push("kv.v1".to_string());
            missing_optional.push("kv.e2ee.v1".to_string());
        } else if !has_kv_e2ee {
            missing_optional.push("kv.e2ee.v1".to_string());
        }
        if !has_transfer_v2 {
            missing_optional.push("transfer.stream.v2".to_string());
        }
        if !has_chan_e2ee {
            missing_optional.push("channel.e2ee.v1".to_string());
        }
    }
    if !has_pushdown {
        missing_optional.push("sub.pushdown.v1".to_string());
    }

    if is_legacy_v1 {
        return PeerSkewRow {
            status: CheckStatus::Warn,
            peer: peer.peer_id.clone(),
            version,
            proto: proto_label,
            e2ee: e2ee_col,
            streams: streams_col,
            kv: kv_col,
            notes: "Legacy v1 peer (plaintext DMs; will ratchet to E2EE on upgrade)".to_string(),
            upgrade_hint: Some(format!("Upgrade '{}' to hyp >= 2.2.0 for E2EE, pushdown, and Shared KV.", peer.peer_id)),
            missing_capabilities: missing_optional,
        };
    }

    if !missing_optional.is_empty() {
        let hint = format!(
            "Upgrade '{}' to hyp >= 2.2.0 for {}",
            peer.peer_id,
            missing_optional.join(" & ")
        );
        return PeerSkewRow {
            status: CheckStatus::Warn,
            peer: peer.peer_id.clone(),
            version,
            proto: proto_label,
            e2ee: e2ee_col,
            streams: streams_col,
            kv: kv_col,
            notes: format!(
                "Missing optional capabilities: {}",
                missing_optional.join(", ")
            ),
            upgrade_hint: Some(hint),
            missing_capabilities: missing_optional,
        };
    }

    let notes = if is_guest_ro {
        "guest read-only hub".to_string()
    } else {
        "full v2 parity".to_string()
    };

    PeerSkewRow {
        status: CheckStatus::Ok,
        peer: peer.peer_id.clone(),
        version,
        proto: proto_label,
        e2ee: e2ee_col,
        streams: streams_col,
        kv: kv_col,
        notes,
        upgrade_hint: None,
        missing_capabilities: Vec::new(),
    }
}

fn parse_cached_manifest(raw: &str) -> Option<NodeManifestPayload> {
    if let Ok(signed) = serde_json::from_str::<SignedNodeManifest>(raw) {
        if let Ok(payload) = serde_json::from_str::<NodeManifestPayload>(&signed.payload) {
            return Some(payload);
        }
    }
    serde_json::from_str::<NodeManifestPayload>(raw).ok()
}

fn format_backup_note(count: usize) -> String {
    match count {
        0 => String::new(),
        1 => " (1 pre-migration backup in backups/)".to_string(),
        n => format!(" ({n} pre-migration backups in backups/)"),
    }
}

fn scan_migration_backups(backups_dir: &Path) -> Vec<PathBuf> {
    let Ok(read_dir) = fs::read_dir(backups_dir) else {
        return Vec::new();
    };
    let mut entries: Vec<(u128, String, PathBuf)> = Vec::new();
    for entry in read_dir.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !name.starts_with("node.sqlite.v") || !name.ends_with(".bak") {
            continue;
        }
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        if !meta.is_file() {
            continue;
        }
        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        entries.push((mtime, name.to_string(), path));
    }
    entries.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1.cmp(&a.1)));
    entries.into_iter().map(|e| e.2).collect()
}
