//! `hyp status` & `hyp doctor` — Node identity, Peer Capabilities & Version Skew UX
//! (`docs/architecture-v2.md §3.3`), Security Gate policy verification, update notice, and
//! harness setup diagnostics.

use crate::config_file::{
    LoadedNodeFile, load_node_or_legacy_config, open_secret_store, profile_as_str,
    resolve_config_path_for_read, resolve_effective_node_id, resolve_home_dir, resolve_state_dir,
};
use crate::drop_cmd::validate_relay_url;
use crate::gate_cmd::{inspect_gate_status, sanitize_tty_display};
use crate::setup::{
    HarnessDiagnostic, StatusLineDiagnostic, detect_harness_statuses, detect_statusline_statuses,
};
use crate::ui::{
    CheckStatus, CliCheck, CliError, EXIT_ERROR, EXIT_OK, JsonEnvelope, emit_error, print_checks,
    print_json, print_next_steps, print_warnings,
};
use crate::update::read_cached_update_status;
use clap::Args;
use hyp_crypto::keystore::{SecretBackend, SecretStore};
use hyp_harness::sock::{DEFAULT_SOCKET_FILENAME, daemon_rpc_sync};
use hyp_node::engine::{DEFAULT_HYPHAE_VERSION, DropRelayConfig, LocalIngestConfig, NodeProfile};
use hyp_node::gates::policy::{FilterAdapterConfig, LlmProvider, SecurityGateConfig};
use hyp_node::gates::stage2::validate_classifier_endpoint_url;
use hyp_proto::manifest::{
    CapabilityToken, NodeManifestPayload, ProtocolRange, SignedNodeManifest,
};
use hyp_proto::{MIN_PROTOCOL_VERSION, PROTOCOL_VERSION};
use hyp_store::{
    CURRENT_SCHEMA_VERSION, KeyUse, NodeDb, PeerProfile, PeerRecord, PeerStatus, TrustTier, now_ms,
};
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

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
    /// Explicit Claude Code config profile directory (overrides $CLAUDE_CONFIG_DIR)
    #[arg(long, value_name = "DIR")]
    pub claude_config_dir: Option<PathBuf>,
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
    /// Explicit Claude Code config profile directory (overrides $CLAUDE_CONFIG_DIR)
    #[arg(long, value_name = "DIR")]
    pub claude_config_dir: Option<PathBuf>,
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

/// Live external plugin supervisor status parsed from `node.status.json` (`B5`).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimePluginStatus {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub status: String,
    pub restarts: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_path: Option<String>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
    pub notes: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub admitted_by_human_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub admitted_auth_epoch: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upgrade_hint: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub missing_capabilities: Vec<String>,
}

/// Tailscale Serve HTTPS route verification result (`tailscale serve status --json`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TailscaleServeStatus {
    pub checked: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exposed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_https_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix_command: Option<String>,
}

/// Non-invasive secret backend readiness diagnostic reported under `data.secretBackend`.
/// Never reads, unlocks, or exposes secret values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretBackendDiagnostic {
    pub backend: String,
    pub available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cli_bin: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_bin: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Smart operational Tailscale probe result reported under `data.tailscale`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TailscaleOperationalStatus {
    pub installed: bool,
    /// `"running"` | `"stopped"` | `"needs_login"` | `"not_installed"` | `"error"`
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backend_state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_name: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tailnet_ips: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub online: Option<bool>,
    pub has_ts_net_endpoints: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ts_net_endpoints: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serve: Option<TailscaleServeStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

const TAILSCALE_PROBE_TIMEOUT: Duration = Duration::from_millis(1_500);
const MAX_TAILSCALE_PROBE_BYTES: usize = 1024 * 1024;
const ENV_TAILSCALE_STATUS_JSON: &str = "HYPHAE_TAILSCALE_STATUS_JSON";
const ENV_TAILSCALE_SERVE_STATUS_JSON: &str = "HYPHAE_TAILSCALE_SERVE_STATUS_JSON";
const ENV_TAILSCALE_BIN: &str = "HYPHAE_TAILSCALE_BIN";

pub fn run_status(args: StatusArgs) -> ExitCode {
    run_status_or_doctor(
        args.state_dir,
        args.config,
        args.home,
        args.claude_config_dir,
        args.json,
        false,
    )
}

pub fn run_doctor(args: DoctorArgs) -> ExitCode {
    run_status_or_doctor(
        args.state_dir,
        args.config,
        args.home,
        args.claude_config_dir,
        args.json,
        true,
    )
}

fn run_status_or_doctor(
    state_dir_arg: Option<PathBuf>,
    config_arg: Option<PathBuf>,
    home_arg: Option<PathBuf>,
    claude_config_dir_arg: Option<PathBuf>,
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
                        format!(
                            "Loaded legacy v1 connector config at {}",
                            cfg.path.display()
                        ),
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
                let backup_files: Vec<String> =
                    backups.iter().map(|p| p.display().to_string()).collect();
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

    // Load identity keys if already present (do not silently create brand new keys on status/doctor
    // if dir missing, and NEVER touch external CLI password managers like 1Password/LastPass/pass
    // during read-only `status`/`doctor` checks).
    let explicit_state = state_dir_arg.is_some();
    let secrets = open_secret_store(&state_dir, explicit_state);
    let (secret_backend_status, secret_backend_check) = inspect_secret_backend(&secrets, is_doctor);
    checks.push(secret_backend_check);
    let is_external_cli_secret_backend = matches!(
        secrets.backend(),
        SecretBackend::OnePassword | SecretBackend::LastPass | SecretBackend::Pass
    );
    let (kid, fingerprint) = if !is_external_cli_secret_backend
        && (state_dir.join("secrets").exists() || !explicit_state)
    {
        match secrets.load_or_create_node_keys(&node_id) {
            Ok(keys) => (Some(keys.kid()), Some(keys.fingerprint())),
            Err(_) => (None, None),
        }
    } else {
        (None, None)
    };

    // Daemon PID, local IPC socket status, and live binary version skew check (`daemon.status`).
    let pid_path = state_dir.join("node.pid");
    let running_pid: Option<u32> = fs::read_to_string(&pid_path)
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok());
    let status_path = state_dir.join("node.status.json");
    let status_doc: Option<Value> = fs::read_to_string(&status_path)
        .ok()
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok());
    let mut socket_path: Option<String> = status_doc.as_ref().and_then(|v| {
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

    let probe_socket_candidate: Option<PathBuf> = socket_path
        .as_deref()
        .map(PathBuf::from)
        .filter(|p| p.exists())
        .or_else(|| {
            let default_sock = state_dir.join(DEFAULT_SOCKET_FILENAME);
            if default_sock.exists() {
                Some(default_sock)
            } else {
                None
            }
        });

    let mut daemon_binary_version: Option<String> = None;
    let mut daemon_pid: Option<u64> = None;
    if let Some(ref probe_sock) = probe_socket_candidate {
        let resp = daemon_rpc_sync(
            probe_sock,
            &json!({ "type": "daemon.status" }),
            Duration::from_millis(500),
        );
        if resp.ok {
            if socket_path.is_none() {
                socket_path = Some(probe_sock.display().to_string());
                checks.push(CliCheck::ok(
                    "daemon.socket",
                    format!("Local IPC ready at {}", probe_sock.display()),
                ));
            }
            if let Some(ref res) = resp.result {
                daemon_binary_version = res
                    .get("binaryVersion")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(ToOwned::to_owned);
                daemon_pid = res
                    .get("pid")
                    .and_then(Value::as_u64)
                    .or_else(|| running_pid.map(u64::from));
            }
        }
    }

    if let Some(ref daemon_ver) = daemon_binary_version {
        let cli_ver = env!("CARGO_PKG_VERSION");
        if daemon_ver != cli_ver {
            checks.push(CliCheck::warn(
                "DAEMON_VERSION_SKEW",
                format!(
                    "Running daemon binaryVersion ({daemon_ver}) differs from CLI binaryVersion ({cli_ver}); restart the daemon to activate the updated binary."
                ),
                Some("hyp service restart --json".to_string()),
            ));
        } else {
            checks.push(CliCheck::ok(
                "daemon.version",
                format!("Running daemon binaryVersion matches CLI ({daemon_ver})"),
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
    let kv_namespaces: BTreeSet<String> = db
        .as_ref()
        .into_iter()
        .flat_map(|d| {
            let now = now_ms();
            let kv = d.kv();
            kv.list_namespaces(&node_id, now)
                .unwrap_or_default()
                .into_iter()
                .chain(kv.list_namespaces("local", now).unwrap_or_default())
        })
        .collect();
    let peers: Vec<PeerRecord> = db
        .as_ref()
        .and_then(|d| d.peers().list_peers(None).ok())
        .unwrap_or_default()
        .into_iter()
        .filter(|p| p.status != PeerStatus::Revoked)
        .collect();

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
        transport: None,
        notes: format!("local node ({node_id})"),
        admitted_by_human_id: None,
        admitted_auth_epoch: None,
        upgrade_hint: None,
        missing_capabilities: Vec::new(),
    });

    for peer in &peers {
        let has_pinned_enc_key = db
            .as_ref()
            .and_then(|d| {
                d.peers()
                    .list_peer_keys(&peer.peer_id, Some(KeyUse::Encryption), true)
                    .ok()
            })
            .is_some_and(|keys| !keys.is_empty());
        let row = evaluate_peer_skew(peer, require_e2ee, has_pinned_enc_key);
        let check_name = format!("peer:{}", row.peer);
        match row.status {
            CheckStatus::Ok => checks.push(CliCheck::ok(
                check_name,
                format!(
                    "{} ({}, e2ee={}, kv={})",
                    row.version, row.proto, row.e2ee, row.kv
                ),
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
    let gate_status =
        inspect_gate_status(loaded_cfg.as_ref().map(|c| &c.raw), &secrets, db.as_ref());
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
            Some(format!(
                "hyp gate review --state-dir {}",
                state_dir.display()
            )),
        ));
    }

    // Warn (without failing daemon startup) if any *disabled* Stage 2 or filter plugin entry
    // configures a non-loopback `http://` or invalid classifier endpoint URL (`G17`).
    checks.extend(collect_disabled_insecure_gate_url_warnings(
        loaded_cfg.as_ref().map(|c| &c.raw),
    ));

    // 3. Local event ingest socket summary (`localIngest`, default enabled)
    let local_ingest_cfg: LocalIngestConfig = loaded_cfg
        .as_ref()
        .and_then(|c| c.raw.get("localIngest"))
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
    let recorded_ingest_socket: Option<PathBuf> = status_doc.as_ref().and_then(|v| {
        v.get("localIngestSocket")
            .and_then(serde_json::Value::as_str)
            .map(PathBuf::from)
    });
    let ingest_socket_path =
        recorded_ingest_socket.unwrap_or_else(|| local_ingest_cfg.resolved_socket_path(&state_dir));
    let ingest_socket_exists = ingest_socket_path.exists();
    let ingest_routes_count = local_ingest_cfg.effective_routes().len();
    if local_ingest_cfg.enabled {
        if ingest_socket_exists {
            checks.push(CliCheck::ok(
                "local_ingest",
                format!(
                    "ready at {} (defaultTopic={}, routes={ingest_routes_count})",
                    ingest_socket_path.display(),
                    local_ingest_cfg.default_topic
                ),
            ));
        } else if running_pid.is_some() {
            checks.push(CliCheck::warn(
                "local_ingest",
                format!(
                    "enabled in config but ingest socket missing at {}",
                    ingest_socket_path.display()
                ),
                Some("Restart `hyp node start` to recreate the local ingest socket.".to_string()),
            ));
        } else {
            checks.push(CliCheck::ok(
                "local_ingest",
                format!(
                    "enabled (defaultTopic={}, routes={ingest_routes_count}; starts with `hyp node start`)",
                    local_ingest_cfg.default_topic
                ),
            ));
        }
    } else {
        checks.push(CliCheck::ok("local_ingest", "disabled in node.json"));
    }
    let local_ingest_summary = json!({
        "enabled": local_ingest_cfg.enabled,
        "socketPath": ingest_socket_path.display().to_string(),
        "socketExists": ingest_socket_exists,
        "defaultTopic": local_ingest_cfg.default_topic,
        "routesCount": ingest_routes_count,
    });

    // 4. Verified Human Drops & Drop Relay summary
    let active_authority_rows = db
        .as_ref()
        .and_then(|d| d.human().list_authorities(false).ok())
        .unwrap_or_default();
    let active_authorities = active_authority_rows.len();
    let has_enc_jwk_count = active_authority_rows
        .iter()
        .filter(|a| a.enc_jwk_json.is_some())
        .count();
    let min_auth_epoch = db
        .as_ref()
        .and_then(|d| d.human().min_auth_epoch().ok())
        .unwrap_or(1);
    let has_node_cert = db
        .as_ref()
        .and_then(|d| d.human().get_latest_node_cert(&node_id).ok().flatten())
        .is_some();
    let drop_relay_cfg: DropRelayConfig = loaded_cfg
        .as_ref()
        .and_then(|c| c.raw.get("dropRelay"))
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
    let drop_relay_url = loaded_cfg
        .as_ref()
        .and_then(|c| c.raw.get("dropRelayUrl"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned);
    if let Some(ref url) = drop_relay_url {
        if let Err(e) = validate_relay_url(url) {
            checks.push(CliCheck::fail(
                "drops.relayUrl",
                format!("Invalid dropRelayUrl '{url}': {e}"),
                Some("Run `hyp relay set https://<your-drop-relay>`.".to_string()),
            ));
        }
    }
    if drop_relay_cfg
        .allowed_origins
        .iter()
        .any(|o| o.trim() == "*" || o.trim().eq_ignore_ascii_case("null"))
    {
        checks.push(CliCheck::fail(
            "drops.dropRelay",
            "dropRelay.allowedOrigins must not contain wildcard '*' or 'null'",
            Some("Set dropRelay.allowedOrigins to [\"https://hyphae.to\"].".to_string()),
        ));
    } else if active_authorities > 0 || drop_relay_cfg.enabled || drop_relay_url.is_some() {
        checks.push(CliCheck::ok(
            "drops",
            format!(
                "authorities={active_authorities}, encKeys={has_enc_jwk_count}, minAuthEpoch={min_auth_epoch}, nodeCert={}, dropRelay={}, url={}",
                if has_node_cert { "yes" } else { "no" },
                if drop_relay_cfg.enabled { "enabled" } else { "disabled" },
                drop_relay_url.as_deref().unwrap_or("-")
            ),
        ));
    }
    let human_drops_summary = json!({
        "activeAuthorities": active_authorities,
        "hasEncJwkCount": has_enc_jwk_count,
        "minAuthEpoch": min_auth_epoch,
        "hasNodeCert": has_node_cert,
        "dropRelayEnabled": drop_relay_cfg.enabled,
        "dropRelayMaxMemoryMb": drop_relay_cfg.max_memory_mb,
        "dropRelayUrl": drop_relay_url,
    });

    // 5. Update channel & cached available update notice
    let update_status = read_cached_update_status(
        loaded_cfg
            .as_ref()
            .and_then(|c| c.update_channel.as_deref()),
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
    let explicit_home = home_arg.is_some();
    let resolved_home = resolve_home_dir(home_arg.as_deref());
    let harnesses: Vec<HarnessDiagnostic> = resolved_home
        .as_deref()
        .map(|h| {
            detect_harness_statuses(
                h,
                explicit_home,
                claude_config_dir_arg.as_deref(),
                loaded_cfg.as_ref().map(|c| c.path.as_path()),
            )
        })
        .unwrap_or_default();
    for h in &harnesses {
        if h.detected || h.configured {
            if h.configured {
                checks.push(CliCheck::ok(
                    format!("harness:{}", h.harness),
                    h.detail.clone(),
                ));
            } else {
                checks.push(CliCheck::warn(
                    format!("harness:{}", h.harness),
                    h.detail.clone(),
                    h.fix.clone(),
                ));
            }
        }
    }

    // 5. StatusLine diagnostics for Claude Code & Antigravity CLI (non-failing info/warning checks)
    let status_lines: Vec<StatusLineDiagnostic> = resolved_home
        .as_deref()
        .map(|h| detect_statusline_statuses(h, explicit_home, claude_config_dir_arg.as_deref()))
        .unwrap_or_default();
    for sl in &status_lines {
        if sl.configured {
            let check_name = format!("statusline:{}", sl.harness);
            if sl.chained && sl.chain_file_exists == Some(false) {
                checks.push(CliCheck::warn(
                    check_name,
                    sl.detail.clone(),
                    Some(format!(
                        "hyp setup --harness {} --restore-statusline",
                        sl.harness
                    )),
                ));
            } else {
                checks.push(CliCheck::ok(check_name, sl.detail.clone()));
            }
        }
    }

    // 6. Native Herdr desktop mod (`hyphae-pane` + `hyphae-panel`) detection
    let herdr_mod_status: Value = resolved_home
        .as_deref()
        .and_then(|h| {
            let herdr_dir = if home_arg.is_none() {
                crate::herdr_mod::detect_herdr_app_dir(h)
            } else {
                let d = h.join(".config").join("herdr-app");
                if d.is_dir() { Some(d) } else { None }
            }?;
            let pane_installed = herdr_dir
                .join("mods")
                .join("hyphae-pane")
                .join("mod.json")
                .is_file();
            let panel_installed = herdr_dir
                .join("mods")
                .join("hyphae-panel")
                .join("mod.json")
                .is_file();
            let installed = pane_installed && panel_installed;
            if installed {
                checks.push(CliCheck::ok(
                    "herdr:mod",
                    format!(
                        "Native Herdr mods installed in {} (hyphae-pane + hyphae-panel)",
                        herdr_dir.join("mods").display()
                    ),
                ));
            }
            Some(json!({
                "detected": true,
                "installed": installed,
                "herdrHome": herdr_dir.display().to_string(),
                "paneInstalled": pane_installed,
                "panelInstalled": panel_installed,
            }))
        })
        .unwrap_or(Value::Null);

    // 7. Installed non-Rust plugins & harness mods integrity / drift checks
    let plugins_report = crate::plugin_cmd::inspect_plugins_for_doctor(
        &state_dir,
        resolved_home.as_deref(),
        explicit_home,
        claude_config_dir_arg.as_deref(),
    );
    checks.extend(plugins_report.checks.iter().cloned());

    // 8. Live runtime plugin supervisor health from `node.status.json` (`B5`)
    let runtime_plugins = extract_runtime_plugin_statuses(status_doc.as_ref());
    checks.extend(build_runtime_plugin_checks(&runtime_plugins));

    // 9. Smart Tailscale operational detection (non-blocking, bounded 1.5s timeout)
    let tailscale_status = probe_tailscale_operational(loaded_cfg.as_ref(), profile, &peers);
    checks.extend(build_tailscale_checks(&tailscale_status, is_doctor));

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
            "daemonBinaryVersion": daemon_binary_version,
            "daemonPid": daemon_pid,
            "protocol": PROTOCOL_VERSION,
            "kid": kid,
            "fingerprint": fingerprint,
            "runningPid": running_pid,
            "socketPath": socket_path,
            "stateDir": state_dir.display().to_string(),
            "configPath": config_path.display().to_string(),
            "secretBackend": secrets.backend().as_str(),
            "sessions": sessions_count,
            "subscriptions": subs_count,
            "kvNamespaces": kv_namespaces,
        },
        "secretBackend": secret_backend_status,
        "storage": storage_status,
        "peers": skew_rows,
        "gate": gate_status,
        "localIngest": local_ingest_summary,
        "humanDrops": human_drops_summary,
        "update": update_status,
        "harnesses": harnesses,
        "statusLines": status_lines,
        "herdrMod": herdr_mod_status,
        "plugins": plugins_report,
        "runtimePlugins": runtime_plugins,
        "tailscale": tailscale_status,
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
        println!(
            "  Secrets:  {}{}{}",
            secret_backend_status.backend,
            secret_backend_status
                .namespace
                .as_deref()
                .map(|ns| format!(" ({ns})"))
                .unwrap_or_default(),
            if secret_backend_status.available {
                ""
            } else {
                " [UNAVAILABLE]"
            }
        );
        if let Some(ref sock) = socket_path {
            println!("  Local IPC: {sock}");
        }
        if daemon_binary_version.is_some() || daemon_pid.is_some() {
            let pid_str = daemon_pid
                .map(|p| p.to_string())
                .unwrap_or_else(|| "-".to_string());
            let ver_str = daemon_binary_version.as_deref().unwrap_or("-");
            let skew_note = match daemon_binary_version.as_deref() {
                Some(v) if v != env!("CARGO_PKG_VERSION") => {
                    format!(" [WARN: skew vs CLI {}]", env!("CARGO_PKG_VERSION"))
                }
                _ => String::new(),
            };
            println!("  Daemon:   pid={pid_str}, bin={ver_str}{skew_note}");
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
            "  Ingest:   {} (topic=local.{}, routes={}, socket={}{})",
            if local_ingest_cfg.enabled {
                "enabled"
            } else {
                "disabled"
            },
            local_ingest_cfg.default_topic,
            ingest_routes_count,
            ingest_socket_path.display(),
            if ingest_socket_exists { " [ready]" } else { "" }
        );
        println!(
            "  Drops:    authorities={} (encKeys={}, minEpoch={}, cert={}, relay={}{})",
            active_authorities,
            has_enc_jwk_count,
            min_auth_epoch,
            if has_node_cert { "yes" } else { "no" },
            if drop_relay_cfg.enabled {
                "enabled"
            } else {
                "disabled"
            },
            drop_relay_url
                .as_deref()
                .map(|u| format!(", url={u}"))
                .unwrap_or_default()
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
        if plugins_report.installed_count > 0 {
            println!(
                "  Plugins:  {} installed ({} ok, {} outdated, {} modified, {} corrupt)",
                plugins_report.installed_count,
                plugins_report.up_to_date_count,
                plugins_report.outdated_count,
                plugins_report.modified_count,
                plugins_report.corrupt_count
            );
        }
        if tailscale_status.state == "running" {
            let mut ts_parts = Vec::new();
            if let Some(ref dns) = tailscale_status.dns_name {
                ts_parts.push(sanitize_tty_display(dns));
            }
            if let Some(first_ip) = tailscale_status.tailnet_ips.first() {
                ts_parts.push(sanitize_tty_display(first_ip));
            }
            let detail_parens = if ts_parts.is_empty() {
                String::new()
            } else {
                format!(" ({})", ts_parts.join(", "))
            };
            let serve_note = match tailscale_status.serve.as_ref() {
                Some(s) if s.exposed == Some(true) => " [serve: OK]".to_string(),
                Some(s) if s.exposed == Some(false) => " [serve: WARN missing route]".to_string(),
                _ => String::new(),
            };
            println!("  Tailscale: Running{detail_parens}{serve_note}");
        } else if tailscale_status.has_ts_net_endpoints {
            let sev = if is_doctor { "FAIL" } else { "WARN" };
            println!(
                "  Tailscale: {sev} ({}; required by {} *.ts.net endpoint(s))",
                sanitize_tty_display(&tailscale_status.state),
                tailscale_status.ts_net_endpoints.len().max(1)
            );
        }
        if !runtime_plugins.is_empty() {
            println!("  Runtime Plugins:");
            for rp in &runtime_plugins {
                let tag = match rp.status.as_str() {
                    "crash_loop_backoff" | "error" => "FAIL",
                    "degraded" => "WARN",
                    _ => "OK  ",
                };
                let mut extras = vec![format!("restarts={}", rp.restarts)];
                if let Some(ref err) = rp.last_error {
                    extras.push(format!("lastError=\"{err}\""));
                }
                if let Some(ref lp) = rp.log_path {
                    extras.push(format!("log={lp}"));
                }
                println!(
                    "    {tag}  {} [{}] ({})",
                    sanitize_tty_display(&rp.id),
                    sanitize_tty_display(&rp.status),
                    extras.join(", ")
                );
            }
        }
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

/// Evaluates a paired peer's capabilities into a `PeerSkewRow` matching
/// `docs/architecture-v2.md §3.2–§3.3`, additionally accounting for inbound-only Hyphae v2
/// `--profile local` clients (`endpoint: None`, `profile: Local`) that completed v2 pairing
/// (`POST /v1/pair`, `POST /v1/guest/pair`, or outbound-only P2P) and have a verified active
/// X25519 encryption key pinned in `peer_keys` (since local-profile nodes do not serve an
/// inbound HTTP `/v1/manifest`).
pub fn evaluate_peer_skew(
    peer: &PeerRecord,
    local_require_e2ee: bool,
    has_pinned_enc_key: bool,
) -> PeerSkewRow {
    let parsed_manifest = peer
        .manifest_json
        .as_deref()
        .and_then(parse_cached_manifest);

    // Determine if this peer is a read-only public guest hub (e.g. public.hyphae.to) where DMs/KV are unused.
    let is_guest_ro = peer.trust_tier == TrustTier::Guest
        && !peer
            .scopes
            .iter()
            .any(|s| s.starts_with("dm:") || s.starts_with("messages:") || s == "*");

    let is_inbound_local_v2 = parsed_manifest.is_none()
        && peer.endpoint.is_none()
        && peer.profile == PeerProfile::Local
        && has_pinned_enc_key;

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
        None if is_inbound_local_v2 => {
            let mut cap_set = BTreeSet::new();
            for tok in [
                CapabilityToken::DmV1,
                CapabilityToken::DmE2eeV1,
                CapabilityToken::ChannelV1,
                CapabilityToken::ChannelE2eeV1,
                CapabilityToken::EventsV1,
                CapabilityToken::SubPushdownV1,
                CapabilityToken::KvV1,
                CapabilityToken::KvE2eeV1,
                CapabilityToken::TransferStreamV2,
            ] {
                cap_set.insert(tok.as_str().to_string());
            }
            (
                "v2-client".to_string(),
                ProtocolRange { min: 2, max: 2 },
                cap_set,
                false,
            )
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

    let transport = detect_peer_transport(peer.endpoint.as_deref());

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
            transport,
            notes: format!(
                "Blocked: protocol_incompatible (local {}..={}, remote {}..={})",
                MIN_PROTOCOL_VERSION, PROTOCOL_VERSION, proto_range.min, proto_range.max
            ),
            admitted_by_human_id: peer.admitted_by_human_id.clone(),
            admitted_auth_epoch: peer.admitted_auth_epoch,
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
            transport,
            notes: format!(
                "Blocked: capability_downgrade_detected (previously observed {} vanished)",
                dropped_e2ee.join(", ")
            ),
            admitted_by_human_id: peer.admitted_by_human_id.clone(),
            admitted_auth_epoch: peer.admitted_auth_epoch,
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
            transport,
            notes: "Blocked: requireE2ee=true but peer lacks dm.e2ee.v1".to_string(),
            admitted_by_human_id: peer.admitted_by_human_id.clone(),
            admitted_auth_epoch: peer.admitted_auth_epoch,
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
            transport,
            notes: "Legacy v1 peer (plaintext DMs; will ratchet to E2EE on upgrade)".to_string(),
            admitted_by_human_id: peer.admitted_by_human_id.clone(),
            admitted_auth_epoch: peer.admitted_auth_epoch,
            upgrade_hint: Some(format!(
                "Upgrade '{}' to hyp >= 2.2.0 for E2EE, pushdown, and Shared KV.",
                peer.peer_id
            )),
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
            transport,
            notes: format!(
                "Missing optional capabilities: {}",
                missing_optional.join(", ")
            ),
            admitted_by_human_id: peer.admitted_by_human_id.clone(),
            admitted_auth_epoch: peer.admitted_auth_epoch,
            upgrade_hint: Some(hint),
            missing_capabilities: missing_optional,
        };
    }

    let base_notes = if let Some(ref hid) = peer.admitted_by_human_id {
        match peer.admitted_auth_epoch {
            Some(ep) => format!("admitted via human:{hid} (ep {ep})"),
            None => format!("admitted via human:{hid}"),
        }
    } else if is_inbound_local_v2 {
        if is_guest_ro {
            "inbound v2 guest client (read-only)".to_string()
        } else {
            "inbound v2 local client (X25519 E2EE key pinned)".to_string()
        }
    } else if is_guest_ro {
        "guest read-only hub".to_string()
    } else {
        "full v2 parity".to_string()
    };
    let notes = if transport.as_deref() == Some("ssh") {
        format!("{base_notes} (transport=ssh)")
    } else {
        base_notes
    };

    PeerSkewRow {
        status: CheckStatus::Ok,
        peer: peer.peer_id.clone(),
        version,
        proto: proto_label,
        e2ee: e2ee_col,
        streams: streams_col,
        kv: kv_col,
        transport,
        notes,
        admitted_by_human_id: peer.admitted_by_human_id.clone(),
        admitted_auth_epoch: peer.admitted_auth_epoch,
        upgrade_hint: None,
        missing_capabilities: Vec::new(),
    }
}

fn detect_peer_transport(endpoint: Option<&str>) -> Option<String> {
    let ep = endpoint?.trim();
    if ep.starts_with("ssh://") {
        Some("ssh".to_string())
    } else if ep.starts_with("https://") {
        Some("https".to_string())
    } else if ep.starts_with("http://") {
        Some("http".to_string())
    } else {
        None
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

/// Redacts common credential / token patterns and strips terminal control sequences before
/// surfacing `lastError` text from `node.status.json` in `hyp status` and `hyp doctor`.
fn redact_plugin_error(raw: &str) -> String {
    let clean = sanitize_tty_display(raw);
    let mut out = String::with_capacity(clean.len());
    let mut redact_next = false;
    for (idx, token) in clean.split_whitespace().enumerate() {
        if idx > 0 {
            out.push(' ');
        }
        let redacted = if redact_next {
            redact_next = false;
            "[REDACTED]".to_string()
        } else if token.eq_ignore_ascii_case("bearer") || token.eq_ignore_ascii_case("basic") {
            redact_next = true;
            token.to_string()
        } else if looks_sensitive_token(token) {
            "[REDACTED]".to_string()
        } else if let Some((prefix, val)) = token.split_once('=') {
            if !val.is_empty()
                && (looks_sensitive_token(val)
                    || prefix.to_ascii_lowercase().contains("token")
                    || prefix.to_ascii_lowercase().contains("secret")
                    || prefix.to_ascii_lowercase().contains("key")
                    || prefix.to_ascii_lowercase().contains("password"))
            {
                format!("{prefix}=[REDACTED]")
            } else {
                token.to_string()
            }
        } else {
            token.to_string()
        };
        out.push_str(&redacted);
    }
    let truncated: String = out.chars().take(240).collect();
    if out.chars().count() > 240 {
        format!("{truncated}...")
    } else {
        truncated
    }
}

fn looks_sensitive_token(tok: &str) -> bool {
    let trimmed = tok.trim_matches(|c: char| matches!(c, '"' | '\'' | ',' | ';' | ')' | '('));
    let prefixes = [
        "sk-", "ghp_", "gho_", "xoxb-", "xoxp-", "AIza", "AKIA", "am2_", "hp2p1_", "t3mp1_",
        "hdrop1_",
    ];
    if prefixes.iter().any(|p| trimmed.starts_with(p)) {
        return true;
    }
    // Telegram bot tokens: `<digits>:<secret>`
    if let Some((left, right)) = trimmed.split_once(':') {
        let digits = left.strip_prefix("bot").unwrap_or(left);
        if digits.len() >= 6 && digits.bytes().all(|b| b.is_ascii_digit()) && right.len() >= 16 {
            return true;
        }
    }
    false
}

fn extract_runtime_plugin_statuses(status_doc: Option<&Value>) -> Vec<RuntimePluginStatus> {
    let Some(arr) = status_doc
        .and_then(|v| v.get("plugins"))
        .and_then(Value::as_array)
    else {
        return Vec::new();
    };
    let mut out = Vec::with_capacity(arr.len());
    for entry in arr {
        let Some(obj) = entry.as_object() else {
            continue;
        };
        let id = obj
            .get("id")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("unknown")
            .to_string();
        let kind = obj
            .get("kind")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let status = obj
            .get("status")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("unknown")
            .to_string();
        let restarts = obj.get("restarts").and_then(Value::as_u64).unwrap_or(0);
        let last_error = obj
            .get("lastError")
            .or_else(|| obj.get("error"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(redact_plugin_error);
        let log_path = obj
            .get("logPath")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(sanitize_tty_display);
        out.push(RuntimePluginStatus {
            id,
            kind,
            status,
            restarts,
            last_error,
            log_path,
        });
    }
    out
}

fn build_runtime_plugin_checks(plugins: &[RuntimePluginStatus]) -> Vec<CliCheck> {
    let mut checks = Vec::new();
    for rp in plugins {
        let name = format!("plugin:runtime:{}", rp.id);
        let mut detail_parts = vec![
            format!("status={}", rp.status),
            format!("restarts={}", rp.restarts),
        ];
        if let Some(ref err) = rp.last_error {
            detail_parts.push(format!("lastError={err}"));
        }
        if let Some(ref lp) = rp.log_path {
            detail_parts.push(format!("logPath={lp}"));
        }
        let detail = detail_parts.join(", ");
        let fix = rp.log_path.as_ref().map(|lp| {
            format!("Inspect plugin log at {lp} and restart via `hyp service restart --json`.")
        }).or_else(|| {
            Some("Check plugin configuration in node.json and restart via `hyp service restart --json`.".to_string())
        });
        match rp.status.as_str() {
            "crash_loop_backoff" | "error" => {
                checks.push(CliCheck::fail(name, detail, fix));
            }
            "degraded" => {
                checks.push(CliCheck::warn(name, detail, fix));
            }
            "running" => {
                checks.push(CliCheck::ok(name, detail));
            }
            _ => {
                if rp.last_error.is_some() {
                    checks.push(CliCheck::warn(name, detail, fix));
                } else {
                    checks.push(CliCheck::ok(name, detail));
                }
            }
        }
    }
    checks
}

fn collect_disabled_insecure_gate_url_warnings(raw_config: Option<&Value>) -> Vec<CliCheck> {
    let Some(gate_val) = raw_config.and_then(|c| c.get("gate")) else {
        return Vec::new();
    };
    let Ok(gate_cfg) = serde_json::from_value::<SecurityGateConfig>(gate_val.clone()) else {
        return Vec::new();
    };

    let mut warnings = Vec::new();
    if !gate_cfg.stage2.enabled {
        if let Some(ref u) = gate_cfg.stage2.base_url_override {
            let trimmed = u.trim();
            if !trimmed.is_empty() {
                if let Err(err) = validate_classifier_endpoint_url(trimmed) {
                    warnings.push(CliCheck::warn(
                        "gate.stage2.disabled_insecure_url",
                        format!(
                            "Disabled gate.stage2 base_url_override '{}' is not https:// or loopback http:// ({err})",
                            sanitize_tty_display(trimmed)
                        ),
                        Some("Update gate.stage2.base_url_override to https:// (or loopback http://127.0.0.1) before enabling Stage 2.".to_string()),
                    ));
                }
            }
        }
        if let LlmProvider::OpenAiCompatible { ref base_url } = gate_cfg.stage2.provider {
            let trimmed = base_url.trim();
            if !trimmed.is_empty() {
                if let Err(err) = validate_classifier_endpoint_url(trimmed) {
                    warnings.push(CliCheck::warn(
                        "gate.stage2.disabled_insecure_url",
                        format!(
                            "Disabled gate.stage2 provider base_url '{}' is not https:// or loopback http:// ({err})",
                            sanitize_tty_display(trimmed)
                        ),
                        Some("Update gate.stage2.provider.base_url to https:// (or loopback http://127.0.0.1) before enabling Stage 2.".to_string()),
                    ));
                }
            }
        }
    }

    for f in &gate_cfg.filters {
        if f.enabled {
            continue;
        }
        let candidate_url: Option<&str> = match &f.adapter {
            FilterAdapterConfig::Anthropic { base_url, .. }
            | FilterAdapterConfig::Google { base_url, .. } => base_url.as_deref(),
            FilterAdapterConfig::OpenAiCompat { base_url, .. }
            | FilterAdapterConfig::LakeraGuard { base_url, .. } => Some(base_url.as_str()),
            FilterAdapterConfig::HttpClassifier { url, .. } => Some(url.as_str()),
            FilterAdapterConfig::Subprocess { .. } => None,
        };
        if let Some(raw_url) = candidate_url {
            let trimmed = raw_url.trim();
            if !trimmed.is_empty() {
                if let Err(err) = validate_classifier_endpoint_url(trimmed) {
                    warnings.push(CliCheck::warn(
                        format!("gate.filter.{}.disabled_insecure_url", f.id),
                        format!(
                            "Disabled gate filter '{}' endpoint URL '{}' is not https:// or loopback http:// ({err})",
                            sanitize_tty_display(&f.id),
                            sanitize_tty_display(trimmed)
                        ),
                        Some(format!(
                            "Update filter '{}' endpoint URL to https:// (or loopback http://127.0.0.1) before enabling it.",
                            sanitize_tty_display(&f.id)
                        )),
                    ));
                }
            }
        }
    }

    warnings
}

// ============================================================================
// Smart Tailscale Operational Detection (`hyp status` / `hyp doctor` / `hyp onboard`)
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedTailscaleStatus {
    state: String,
    backend_state: Option<String>,
    dns_name: Option<String>,
    tailnet_ips: Vec<String>,
    online: Option<bool>,
}

/// Returns `true` if `raw` is an HTTP(S) endpoint whose hostname falls under `*.ts.net`.
pub(crate) fn is_ts_net_endpoint(raw: &str) -> bool {
    let trimmed = raw.trim();
    let Some(rest) = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
    else {
        return false;
    };
    let authority = rest.split('/').next().unwrap_or("");
    let host_port = authority.rsplit('@').next().unwrap_or(authority);
    if host_port.starts_with('[') {
        return false;
    }
    let host = host_port
        .split(':')
        .next()
        .unwrap_or("")
        .trim_end_matches('.')
        .to_ascii_lowercase();
    host.len() > ".ts.net".len() && host.ends_with(".ts.net")
}

/// Extracts the HTTPS port from an `https://host[:port]` URL (defaulting to `443`).
pub(crate) fn parse_https_port_from_url(raw: &str) -> Option<u16> {
    let trimmed = raw.trim();
    let rest = trimmed.strip_prefix("https://")?;
    let authority = rest.split('/').next().unwrap_or("");
    if authority.is_empty() {
        return None;
    }
    if let Some(after_open) = authority.strip_prefix('[') {
        let (_ip, tail) = after_open.split_once(']')?;
        if tail.is_empty() {
            Some(443)
        } else {
            tail.strip_prefix(':')?
                .parse::<u16>()
                .ok()
                .filter(|&p| p > 0)
        }
    } else if let Some((_host, port_str)) = authority.split_once(':') {
        port_str.parse::<u16>().ok().filter(|&p| p > 0)
    } else {
        Some(443)
    }
}

fn parse_tailscale_status_json(bytes: &[u8]) -> Result<ParsedTailscaleStatus, String> {
    let parsed: Value =
        serde_json::from_slice(bytes).map_err(|e| format!("invalid tailscale status JSON: {e}"))?;
    let Some(root) = parsed.as_object() else {
        return Err("tailscale status JSON is not an object".to_string());
    };
    let backend_state = root
        .get("BackendState")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned);

    let self_obj = root.get("Self").and_then(Value::as_object);
    let online = self_obj
        .and_then(|s| s.get("Online"))
        .and_then(Value::as_bool);
    let dns_name = self_obj
        .and_then(|s| s.get("DNSName"))
        .and_then(Value::as_str)
        .map(|s| s.trim().trim_end_matches('.'))
        .filter(|s| !s.is_empty())
        .map(|s| sanitize_tty_display(&s.to_ascii_lowercase()));
    let tailnet_ips: Vec<String> = self_obj
        .and_then(|s| s.get("TailscaleIPs"))
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(sanitize_tty_display)
                .collect()
        })
        .unwrap_or_default();

    let state = match backend_state.as_deref() {
        Some("Running") => {
            if online == Some(false) {
                "stopped".to_string()
            } else {
                "running".to_string()
            }
        }
        Some("NeedsLogin") | Some("NoState") => "needs_login".to_string(),
        Some("Stopped") | Some("Starting") | Some("NeedsMachineAuth") => "stopped".to_string(),
        Some(_) => "error".to_string(),
        None => "error".to_string(),
    };

    Ok(ParsedTailscaleStatus {
        state,
        backend_state,
        dns_name,
        tailnet_ips,
        online,
    })
}

fn normalize_proxy_loopback_port(raw: &str) -> Option<(bool, String, u16)> {
    let trimmed = raw.trim().trim_end_matches('/');
    let rest = trimmed
        .strip_prefix("http://")
        .or_else(|| trimmed.strip_prefix("https://"))
        .unwrap_or(trimmed);
    let authority = rest.split('/').next().unwrap_or("");
    if authority.is_empty() {
        return None;
    }
    let (host, port) = if let Some(after_open) = authority.strip_prefix('[') {
        let (ip, tail) = after_open.split_once(']')?;
        let p = tail.strip_prefix(':')?.parse::<u16>().ok()?;
        (ip.to_ascii_lowercase(), p)
    } else {
        let (h, p_str) = authority.split_once(':')?;
        let p = p_str.parse::<u16>().ok()?;
        (h.to_ascii_lowercase(), p)
    };
    let is_loopback = matches!(
        host.as_str(),
        "127.0.0.1" | "localhost" | "::1" | "0.0.0.0" | "::"
    );
    Some((is_loopback, host, port))
}

fn proxy_matches_bind(proxy: &str, expected_bind: &str) -> bool {
    let Some((p_lo, p_host, p_port)) = normalize_proxy_loopback_port(proxy) else {
        return false;
    };
    let Some((e_lo, e_host, e_port)) = normalize_proxy_loopback_port(expected_bind) else {
        return false;
    };
    if p_port != e_port {
        return false;
    }
    (p_lo && e_lo) || p_host == e_host
}

pub(crate) fn parse_tailscale_serve_status_json(
    bytes: &[u8],
    expected_port: u16,
    expected_bind: &str,
) -> TailscaleServeStatus {
    let expected_target = format!("http://{expected_bind}");
    let fix_cmd = format!("tailscale serve --bg --https={expected_port} {expected_target}");
    let parsed: Value = match serde_json::from_slice(bytes) {
        Ok(v) => v,
        Err(e) => {
            return TailscaleServeStatus {
                checked: false,
                exposed: None,
                expected_https_port: Some(expected_port),
                expected_target: Some(expected_target),
                matched_target: None,
                detail: Some(format!("Could not parse tailscale serve status JSON: {e}")),
                fix_command: None,
            };
        }
    };

    let port_suffix = format!(":{expected_port}");
    if let Some(web) = parsed.get("Web").and_then(Value::as_object) {
        for (host_port, cfg) in web {
            if !host_port.ends_with(&port_suffix) {
                continue;
            }
            if let Some(handlers) = cfg.get("Handlers").and_then(Value::as_object) {
                if let Some(root_handler) = handlers.get("/") {
                    if let Some(proxy) = root_handler.get("Proxy").and_then(Value::as_str) {
                        if proxy_matches_bind(proxy, expected_bind) {
                            return TailscaleServeStatus {
                                checked: true,
                                exposed: Some(true),
                                expected_https_port: Some(expected_port),
                                expected_target: Some(expected_target),
                                matched_target: Some(sanitize_tty_display(proxy)),
                                detail: Some(format!(
                                    "Tailscale Serve HTTPS :{expected_port} -> {}",
                                    sanitize_tty_display(proxy)
                                )),
                                fix_command: None,
                            };
                        }
                    }
                }
            }
        }
    }

    TailscaleServeStatus {
        checked: true,
        exposed: Some(false),
        expected_https_port: Some(expected_port),
        expected_target: Some(expected_target.clone()),
        matched_target: None,
        detail: Some(format!(
            "No Tailscale Serve route found exposing HTTPS :{expected_port} -> {expected_target}"
        )),
        fix_command: Some(fix_cmd),
    }
}

fn find_tailscale_binary() -> Option<String> {
    if let Ok(explicit) = std::env::var(ENV_TAILSCALE_BIN) {
        let trimmed = explicit.trim();
        if trimmed.is_empty()
            || trimmed.eq_ignore_ascii_case("none")
            || trimmed.eq_ignore_ascii_case("disabled")
        {
            return None;
        }
        return Some(trimmed.to_string());
    }

    if let Some(path_var) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path_var) {
            if dir.as_os_str().is_empty() {
                continue;
            }
            let direct = dir.join("tailscale");
            if direct.is_file() {
                return Some(direct.display().to_string());
            }
            #[cfg(windows)]
            {
                let exe = dir.join("tailscale.exe");
                if exe.is_file() {
                    return Some(exe.display().to_string());
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        let mac_bin = "/Applications/Tailscale.app/Contents/MacOS/Tailscale";
        if Path::new(mac_bin).is_file() {
            return Some(mac_bin.to_string());
        }
    }

    None
}

fn run_bounded_probe_command(
    bin: &str,
    args: &[&str],
    timeout: Duration,
) -> Result<(bool, Vec<u8>, Vec<u8>), String> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("failed to create probe runtime: {e}"))?;
    rt.block_on(async {
        use tokio::io::AsyncReadExt;
        use tokio::process::Command;

        let mut cmd = Command::new(bin);
        cmd.args(args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        let mut child = cmd
            .spawn()
            .map_err(|e| format!("failed to spawn '{bin}': {e}"))?;
        let mut out_pipe = child
            .stdout
            .take()
            .ok_or_else(|| "probe missing stdout".to_string())?;
        let mut err_pipe = child
            .stderr
            .take()
            .ok_or_else(|| "probe missing stderr".to_string())?;

        let fut = async {
            let mut out_buf = Vec::new();
            let mut err_buf = Vec::new();
            let out_fut = async {
                let mut lim = (&mut out_pipe).take((MAX_TAILSCALE_PROBE_BYTES + 1) as u64);
                lim.read_to_end(&mut out_buf).await
            };
            let err_fut = async {
                let mut lim = (&mut err_pipe).take(16 * 1024);
                lim.read_to_end(&mut err_buf).await
            };
            let (out_res, _err_res) = tokio::join!(out_fut, err_fut);
            out_res.map_err(|e| format!("failed reading probe stdout: {e}"))?;
            if out_buf.len() > MAX_TAILSCALE_PROBE_BYTES {
                let _ = child.kill().await;
                return Err("tailscale probe output exceeded 1 MiB safety limit".to_string());
            }
            let status = child
                .wait()
                .await
                .map_err(|e| format!("failed waiting on probe process: {e}"))?;
            Ok((status.success(), out_buf, err_buf))
        };

        match tokio::time::timeout(timeout, fut).await {
            Ok(res) => res,
            Err(_) => {
                let _ = child.kill().await;
                Err(format!(
                    "tailscale probe timed out after {}ms",
                    timeout.as_millis()
                ))
            }
        }
    })
}

fn collect_ts_net_endpoints(
    loaded_cfg: Option<&LoadedNodeFile>,
    peers: &[PeerRecord],
) -> (Vec<String>, bool) {
    let mut set = BTreeSet::new();
    let mut uses_tailscale_provider = false;

    if let Some(cfg) = loaded_cfg {
        if let Some(ref pub_url) = cfg.public_url {
            if is_ts_net_endpoint(pub_url) {
                set.insert(pub_url.trim().to_string());
                uses_tailscale_provider = true;
            }
        }
        let provider_str = cfg
            .raw
            .get("deploymentProvider")
            .and_then(Value::as_str)
            .or_else(|| {
                cfg.raw
                    .get("deployment")
                    .and_then(|d| d.get("provider"))
                    .and_then(Value::as_str)
            });
        if provider_str.is_some_and(|p| p.trim().eq_ignore_ascii_case("tailscale")) {
            uses_tailscale_provider = true;
        }
        if let Some(arr) = cfg.raw.get("peers").and_then(Value::as_array) {
            for p in arr {
                if let Some(ep) = p.get("endpoint").and_then(Value::as_str) {
                    if is_ts_net_endpoint(ep) {
                        set.insert(ep.trim().to_string());
                    }
                }
            }
        }
    }

    for p in peers {
        if let Some(ref ep) = p.endpoint {
            if is_ts_net_endpoint(ep) {
                set.insert(ep.trim().to_string());
            }
        }
    }

    (set.into_iter().collect(), uses_tailscale_provider)
}

/// Probes Tailscale operational status and (for `Router | P2p` nodes serving `*.ts.net`)
/// verifies `tailscale serve status --json` within a strict 1.5s non-blocking budget.
pub(crate) fn probe_tailscale_operational(
    loaded_cfg: Option<&LoadedNodeFile>,
    profile: NodeProfile,
    peers: &[PeerRecord],
) -> TailscaleOperationalStatus {
    let (ts_net_endpoints, uses_tailscale_provider) = collect_ts_net_endpoints(loaded_cfg, peers);
    let has_ts_net_endpoints = !ts_net_endpoints.is_empty() || uses_tailscale_provider;

    let should_check_serve = matches!(profile, NodeProfile::Router | NodeProfile::P2p)
        && (uses_tailscale_provider
            || loaded_cfg
                .and_then(|c| c.public_url.as_deref())
                .is_some_and(is_ts_net_endpoint));
    let expected_port = loaded_cfg
        .and_then(|c| c.public_url.as_deref())
        .and_then(parse_https_port_from_url)
        .unwrap_or(443);
    let expected_bind = loaded_cfg
        .and_then(|c| c.bind_addr)
        .map(|a| a.to_string())
        .unwrap_or_else(|| "127.0.0.1:8790".to_string());

    // Fast test override via `HYPHAE_TAILSCALE_STATUS_JSON` (zero subprocesses, 100% isolated).
    if let Ok(raw_env) = std::env::var(ENV_TAILSCALE_STATUS_JSON) {
        let trimmed = raw_env.trim();
        if trimmed.eq_ignore_ascii_case("not_installed")
            || trimmed.eq_ignore_ascii_case("none")
            || trimmed.eq_ignore_ascii_case("disabled")
        {
            return TailscaleOperationalStatus {
                installed: false,
                state: "not_installed".to_string(),
                backend_state: None,
                dns_name: None,
                tailnet_ips: Vec::new(),
                online: None,
                has_ts_net_endpoints,
                ts_net_endpoints,
                serve: None,
                error: None,
            };
        }
        return match parse_tailscale_status_json(trimmed.as_bytes()) {
            Ok(parsed) => {
                let serve = if parsed.state == "running" && should_check_serve {
                    probe_tailscale_serve_from_env_or_bin(None, expected_port, &expected_bind)
                } else {
                    None
                };
                TailscaleOperationalStatus {
                    installed: true,
                    state: parsed.state,
                    backend_state: parsed.backend_state,
                    dns_name: parsed.dns_name,
                    tailnet_ips: parsed.tailnet_ips,
                    online: parsed.online,
                    has_ts_net_endpoints,
                    ts_net_endpoints,
                    serve,
                    error: None,
                }
            }
            Err(err) => TailscaleOperationalStatus {
                installed: true,
                state: "error".to_string(),
                backend_state: None,
                dns_name: None,
                tailnet_ips: Vec::new(),
                online: None,
                has_ts_net_endpoints,
                ts_net_endpoints,
                serve: None,
                error: Some(err),
            },
        };
    }

    let Some(bin) = find_tailscale_binary() else {
        return TailscaleOperationalStatus {
            installed: false,
            state: "not_installed".to_string(),
            backend_state: None,
            dns_name: None,
            tailnet_ips: Vec::new(),
            online: None,
            has_ts_net_endpoints,
            ts_net_endpoints,
            serve: None,
            error: None,
        };
    };

    match run_bounded_probe_command(&bin, &["status", "--json"], TAILSCALE_PROBE_TIMEOUT) {
        Ok((ok, stdout, stderr)) => {
            // Tailscale CLI often exits non-zero when Stopped / NeedsLogin while still emitting
            // valid JSON status on stdout — parse stdout whenever present!
            if !stdout.is_empty() {
                if let Ok(parsed) = parse_tailscale_status_json(&stdout) {
                    let serve = if parsed.state == "running" && should_check_serve {
                        probe_tailscale_serve_from_env_or_bin(
                            Some(&bin),
                            expected_port,
                            &expected_bind,
                        )
                    } else {
                        None
                    };
                    return TailscaleOperationalStatus {
                        installed: true,
                        state: parsed.state,
                        backend_state: parsed.backend_state,
                        dns_name: parsed.dns_name,
                        tailnet_ips: parsed.tailnet_ips,
                        online: parsed.online,
                        has_ts_net_endpoints,
                        ts_net_endpoints,
                        serve,
                        error: None,
                    };
                }
            }
            let err_text = String::from_utf8_lossy(&stderr).trim().to_string();
            let err_lower = err_text.to_ascii_lowercase();
            let inferred_state =
                if err_lower.contains("stopped") || err_lower.contains("not running") {
                    "stopped"
                } else if err_lower.contains("logged out") || err_lower.contains("needs login") {
                    "needs_login"
                } else {
                    "error"
                };
            TailscaleOperationalStatus {
                installed: true,
                state: inferred_state.to_string(),
                backend_state: None,
                dns_name: None,
                tailnet_ips: Vec::new(),
                online: None,
                has_ts_net_endpoints,
                ts_net_endpoints,
                serve: None,
                error: if ok {
                    Some("tailscale status --json returned empty output".to_string())
                } else if !err_text.is_empty() {
                    Some(sanitize_tty_display(&err_text))
                } else {
                    Some("tailscale status --json exited with non-zero status".to_string())
                },
            }
        }
        Err(err) => TailscaleOperationalStatus {
            installed: true,
            state: "error".to_string(),
            backend_state: None,
            dns_name: None,
            tailnet_ips: Vec::new(),
            online: None,
            has_ts_net_endpoints,
            ts_net_endpoints,
            serve: None,
            error: Some(err),
        },
    }
}

fn probe_tailscale_serve_from_env_or_bin(
    bin: Option<&str>,
    expected_port: u16,
    expected_bind: &str,
) -> Option<TailscaleServeStatus> {
    if let Ok(raw_env) = std::env::var(ENV_TAILSCALE_SERVE_STATUS_JSON) {
        let trimmed = raw_env.trim();
        if trimmed.eq_ignore_ascii_case("permission_denied")
            || trimmed.eq_ignore_ascii_case("error")
        {
            return Some(TailscaleServeStatus {
                checked: false,
                exposed: None,
                expected_https_port: Some(expected_port),
                expected_target: Some(format!("http://{expected_bind}")),
                matched_target: None,
                detail: Some(
                    "Could not inspect `tailscale serve status --json` (permission denied or unavailable)"
                        .to_string(),
                ),
                fix_command: None,
            });
        }
        return Some(parse_tailscale_serve_status_json(
            trimmed.as_bytes(),
            expected_port,
            expected_bind,
        ));
    }

    let bin_path = bin?;
    match run_bounded_probe_command(
        bin_path,
        &["serve", "status", "--json"],
        TAILSCALE_PROBE_TIMEOUT,
    ) {
        Ok((true, stdout, _stderr)) if !stdout.is_empty() => Some(
            parse_tailscale_serve_status_json(&stdout, expected_port, expected_bind),
        ),
        Ok((_ok, _stdout, stderr)) => {
            let err_snippet = sanitize_tty_display(String::from_utf8_lossy(&stderr).trim());
            Some(TailscaleServeStatus {
                checked: false,
                exposed: None,
                expected_https_port: Some(expected_port),
                expected_target: Some(format!("http://{expected_bind}")),
                matched_target: None,
                detail: Some(if err_snippet.is_empty() {
                    "Could not inspect `tailscale serve status --json` (insufficient permissions or serve unavailable)".to_string()
                } else {
                    format!("Could not inspect `tailscale serve status --json`: {err_snippet}")
                }),
                fix_command: None,
            })
        }
        Err(err) => Some(TailscaleServeStatus {
            checked: false,
            exposed: None,
            expected_https_port: Some(expected_port),
            expected_target: Some(format!("http://{expected_bind}")),
            matched_target: None,
            detail: Some(format!(
                "Could not inspect `tailscale serve status --json`: {err}"
            )),
            fix_command: None,
        }),
    }
}

/// Lightweight Tailscale operational probe used during `hyp onboard`.
pub(crate) fn probe_tailscale_for_onboarding() -> TailscaleOperationalStatus {
    probe_tailscale_operational(None, NodeProfile::Local, &[])
}

pub(crate) fn build_tailscale_checks(
    ts: &TailscaleOperationalStatus,
    is_doctor: bool,
) -> Vec<CliCheck> {
    let mut out = Vec::new();
    if ts.state == "running" {
        let mut parts = Vec::new();
        if let Some(ref dns) = ts.dns_name {
            parts.push(dns.clone());
        }
        if let Some(first_ip) = ts.tailnet_ips.first() {
            parts.push(first_ip.clone());
        }
        let detail = if parts.is_empty() {
            "Running".to_string()
        } else {
            format!("Running ({})", parts.join(", "))
        };
        out.push(CliCheck::ok("tailscale", detail));

        if let Some(ref serve) = ts.serve {
            if serve.checked {
                match serve.exposed {
                    Some(true) => {
                        out.push(CliCheck::ok(
                            "tailscale.serve",
                            serve.detail.clone().unwrap_or_else(|| {
                                "Tailscale Serve HTTPS route matches listen.bind".to_string()
                            }),
                        ));
                    }
                    Some(false) => {
                        out.push(CliCheck::warn(
                            "tailscale.serve",
                            serve.detail.clone().unwrap_or_else(|| {
                                "Configured *.ts.net URL is not exposed via Tailscale Serve"
                                    .to_string()
                            }),
                            serve.fix_command.clone(),
                        ));
                    }
                    None => {}
                }
            }
        }
        return out;
    }

    if ts.has_ts_net_endpoints {
        let count = ts.ts_net_endpoints.len();
        let endpoint_summary = if count > 0 {
            format!("{count} *.ts.net endpoint(s) configured")
        } else {
            "deploymentProvider=tailscale configured".to_string()
        };
        let (detail, fix) = if !ts.installed {
            (
                format!("Tailscale is not installed, but {endpoint_summary}"),
                "Install Tailscale and run `tailscale up` (or Open Tailscale app and connect)."
                    .to_string(),
            )
        } else if ts.state == "needs_login" {
            (
                format!("Tailscale requires login (NeedsLogin), but {endpoint_summary}"),
                "tailscale up  # or open the Tailscale app and connect".to_string(),
            )
        } else {
            (
                format!(
                    "Tailscale is {} (offline), but {endpoint_summary}",
                    ts.state
                ),
                "tailscale up  # or open the Tailscale app and connect".to_string(),
            )
        };
        if is_doctor {
            out.push(CliCheck::fail("tailscale", detail, Some(fix)));
        } else {
            out.push(CliCheck::warn("tailscale", detail, Some(fix)));
        }
    }

    out
}

fn is_executable_file(path: &Path) -> bool {
    if !path.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(path)
            .map(|m| (m.permissions().mode() & 0o111) != 0)
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn find_executable_in_dir(dir: &Path, name: &Path) -> Option<PathBuf> {
    let direct = dir.join(name);
    if is_executable_file(&direct) {
        return Some(direct);
    }
    #[cfg(windows)]
    {
        if name.extension().is_none() {
            for ext in ["exe", "cmd", "bat"] {
                let with_ext = direct.with_extension(ext);
                if is_executable_file(&with_ext) {
                    return Some(with_ext);
                }
            }
        }
    }
    None
}

/// Pure filesystem/PATH executable lookup — never spawns the target CLI or touches secrets.
pub(crate) fn find_executable_path(bin: &Path) -> Option<PathBuf> {
    let raw = bin.to_string_lossy();
    if raw.trim().is_empty() {
        return None;
    }
    let has_path_sep = raw.contains('/') || raw.contains('\\') || bin.components().count() > 1;
    if has_path_sep {
        if is_executable_file(bin) {
            return Some(bin.to_path_buf());
        }
        #[cfg(windows)]
        {
            if bin.extension().is_none() {
                for ext in ["exe", "cmd", "bat"] {
                    let with_ext = bin.with_extension(ext);
                    if is_executable_file(&with_ext) {
                        return Some(with_ext);
                    }
                }
            }
        }
        return None;
    }
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        if dir.as_os_str().is_empty() {
            continue;
        }
        if let Some(found) = find_executable_in_dir(&dir, bin) {
            return Some(found);
        }
    }
    None
}

/// Checks secret backend configuration and CLI binary availability cleanly without touching secrets.
pub(crate) fn inspect_secret_backend(
    store: &SecretStore,
    is_doctor: bool,
) -> (SecretBackendDiagnostic, CliCheck) {
    let backend_name = store.backend().as_str().to_string();
    let fail_or_warn = |detail: String, fix: String| {
        if is_doctor {
            CliCheck::fail("secrets.backend", detail, Some(fix))
        } else {
            CliCheck::warn("secrets.backend", detail, Some(fix))
        }
    };

    match store.backend() {
        SecretBackend::File => {
            let detail = format!("file (0600 store at {})", store.secrets_dir().display());
            (
                SecretBackendDiagnostic {
                    backend: backend_name,
                    available: true,
                    cli_bin: None,
                    resolved_bin: None,
                    namespace: None,
                    error: None,
                },
                CliCheck::ok("secrets.backend", detail),
            )
        }
        SecretBackend::Keychain => {
            let sec_bin = Path::new("/usr/bin/security");
            let available = cfg!(target_os = "macos") && is_executable_file(sec_bin);
            let check = if available {
                CliCheck::ok("secrets.backend", "keychain (/usr/bin/security)")
            } else {
                CliCheck::warn(
                    "secrets.backend",
                    "macOS Keychain CLI (/usr/bin/security) is unavailable on this platform",
                    Some(
                        "Set HYPHAE_SECRET_BACKEND=file (or secret-service on Linux).".to_string(),
                    ),
                )
            };
            (
                SecretBackendDiagnostic {
                    backend: backend_name,
                    available,
                    cli_bin: Some("/usr/bin/security".to_string()),
                    resolved_bin: available.then(|| "/usr/bin/security".to_string()),
                    namespace: None,
                    error: (!available).then(|| "macOS Keychain binary unavailable".to_string()),
                },
                check,
            )
        }
        SecretBackend::SecretService => {
            let resolved = find_executable_path(Path::new("secret-tool"));
            let available = cfg!(target_os = "linux") && resolved.is_some();
            let check = if available {
                CliCheck::ok(
                    "secrets.backend",
                    format!(
                        "secret-service ({})",
                        resolved
                            .as_ref()
                            .map(|p| p.display().to_string())
                            .unwrap_or_else(|| "secret-tool".to_string())
                    ),
                )
            } else {
                CliCheck::warn(
                    "secrets.backend",
                    "Linux Secret Service CLI (`secret-tool`) not found or unsupported platform",
                    Some(
                        "Install `libsecret-tools` or set HYPHAE_SECRET_BACKEND=file.".to_string(),
                    ),
                )
            };
            (
                SecretBackendDiagnostic {
                    backend: backend_name,
                    available,
                    cli_bin: Some("secret-tool".to_string()),
                    resolved_bin: resolved.map(|p| p.display().to_string()),
                    namespace: None,
                    error: (!available).then(|| "secret-tool CLI unavailable".to_string()),
                },
                check,
            )
        }
        SecretBackend::OnePassword => {
            let vault = match store.resolved_op_vault() {
                Ok(v) => v,
                Err(e) => {
                    let msg = e.to_string();
                    let fix = "Set a valid HYPHAE_1PASSWORD_VAULT (no control chars or leading '-') or switch to HYPHAE_SECRET_BACKEND=file.".to_string();
                    return (
                        SecretBackendDiagnostic {
                            backend: backend_name,
                            available: false,
                            cli_bin: None,
                            resolved_bin: None,
                            namespace: None,
                            error: Some(msg.clone()),
                        },
                        fail_or_warn(format!("1password config invalid: {msg}"), fix),
                    );
                }
            };
            let bin = match store.resolved_op_bin() {
                Ok(b) => b,
                Err(e) => {
                    let msg = e.to_string();
                    let fix =
                        "Set a valid HYPHAE_OP_BIN path or switch to HYPHAE_SECRET_BACKEND=file."
                            .to_string();
                    return (
                        SecretBackendDiagnostic {
                            backend: backend_name,
                            available: false,
                            cli_bin: None,
                            resolved_bin: None,
                            namespace: Some(vault),
                            error: Some(msg.clone()),
                        },
                        fail_or_warn(format!("1password CLI path invalid: {msg}"), fix),
                    );
                }
            };
            let bin_str = bin.display().to_string();
            if let Some(resolved) = find_executable_path(&bin) {
                let resolved_str = resolved.display().to_string();
                let detail = format!("1password (bin={resolved_str}, vault={vault})");
                (
                    SecretBackendDiagnostic {
                        backend: backend_name,
                        available: true,
                        cli_bin: Some(bin_str),
                        resolved_bin: Some(resolved_str),
                        namespace: Some(vault),
                        error: None,
                    },
                    CliCheck::ok("secrets.backend", detail),
                )
            } else {
                let err = format!("1Password CLI '{bin_str}' not found (vault={vault})");
                let fix = "Install 1Password CLI (`op`), set HYPHAE_OP_BIN, or switch to HYPHAE_SECRET_BACKEND=file.".to_string();
                (
                    SecretBackendDiagnostic {
                        backend: backend_name,
                        available: false,
                        cli_bin: Some(bin_str),
                        resolved_bin: None,
                        namespace: Some(vault),
                        error: Some(err.clone()),
                    },
                    fail_or_warn(err, fix),
                )
            }
        }
        SecretBackend::LastPass => {
            let prefix = match store.resolved_lpass_prefix() {
                Ok(p) => p,
                Err(e) => {
                    let msg = e.to_string();
                    let fix = "Set a valid HYPHAE_LASTPASS_PREFIX (no '..', control chars, or leading '-') or switch to HYPHAE_SECRET_BACKEND=file.".to_string();
                    return (
                        SecretBackendDiagnostic {
                            backend: backend_name,
                            available: false,
                            cli_bin: None,
                            resolved_bin: None,
                            namespace: None,
                            error: Some(msg.clone()),
                        },
                        fail_or_warn(format!("lastpass config invalid: {msg}"), fix),
                    );
                }
            };
            let bin = match store.resolved_lpass_bin() {
                Ok(b) => b,
                Err(e) => {
                    let msg = e.to_string();
                    let fix = "Set a valid HYPHAE_LPASS_BIN path or switch to HYPHAE_SECRET_BACKEND=file.".to_string();
                    return (
                        SecretBackendDiagnostic {
                            backend: backend_name,
                            available: false,
                            cli_bin: None,
                            resolved_bin: None,
                            namespace: Some(prefix),
                            error: Some(msg.clone()),
                        },
                        fail_or_warn(format!("lastpass CLI path invalid: {msg}"), fix),
                    );
                }
            };
            let bin_str = bin.display().to_string();
            if let Some(resolved) = find_executable_path(&bin) {
                let resolved_str = resolved.display().to_string();
                let detail = format!("lastpass (bin={resolved_str}, prefix={prefix})");
                (
                    SecretBackendDiagnostic {
                        backend: backend_name,
                        available: true,
                        cli_bin: Some(bin_str),
                        resolved_bin: Some(resolved_str),
                        namespace: Some(prefix),
                        error: None,
                    },
                    CliCheck::ok("secrets.backend", detail),
                )
            } else {
                let err = format!("LastPass CLI '{bin_str}' not found (prefix={prefix})");
                let fix = "Install LastPass CLI (`lpass`), set HYPHAE_LPASS_BIN, or switch to HYPHAE_SECRET_BACKEND=file.".to_string();
                (
                    SecretBackendDiagnostic {
                        backend: backend_name,
                        available: false,
                        cli_bin: Some(bin_str),
                        resolved_bin: None,
                        namespace: Some(prefix),
                        error: Some(err.clone()),
                    },
                    fail_or_warn(err, fix),
                )
            }
        }
        SecretBackend::Pass => {
            let prefix = match store.resolved_pass_prefix() {
                Ok(p) => p,
                Err(e) => {
                    let msg = e.to_string();
                    let fix = "Set a valid HYPHAE_PASS_PREFIX (alphanumeric path segments, no '..' or leading '/') or switch to HYPHAE_SECRET_BACKEND=file.".to_string();
                    return (
                        SecretBackendDiagnostic {
                            backend: backend_name,
                            available: false,
                            cli_bin: None,
                            resolved_bin: None,
                            namespace: None,
                            error: Some(msg.clone()),
                        },
                        fail_or_warn(format!("pass config invalid: {msg}"), fix),
                    );
                }
            };
            let bin = match store.resolved_pass_bin() {
                Ok(b) => b,
                Err(e) => {
                    let msg = e.to_string();
                    let fix =
                        "Set a valid HYPHAE_PASS_BIN path or switch to HYPHAE_SECRET_BACKEND=file."
                            .to_string();
                    return (
                        SecretBackendDiagnostic {
                            backend: backend_name,
                            available: false,
                            cli_bin: None,
                            resolved_bin: None,
                            namespace: Some(prefix),
                            error: Some(msg.clone()),
                        },
                        fail_or_warn(format!("pass CLI path invalid: {msg}"), fix),
                    );
                }
            };
            let bin_str = bin.display().to_string();
            if let Some(resolved) = find_executable_path(&bin) {
                let resolved_str = resolved.display().to_string();
                let detail = format!("pass (bin={resolved_str}, prefix={prefix})");
                (
                    SecretBackendDiagnostic {
                        backend: backend_name,
                        available: true,
                        cli_bin: Some(bin_str),
                        resolved_bin: Some(resolved_str),
                        namespace: Some(prefix),
                        error: None,
                    },
                    CliCheck::ok("secrets.backend", detail),
                )
            } else {
                let err = format!("pass CLI '{bin_str}' not found (prefix={prefix})");
                let fix = "Install `pass` (password-store), set HYPHAE_PASS_BIN, or switch to HYPHAE_SECRET_BACKEND=file.".to_string();
                (
                    SecretBackendDiagnostic {
                        backend: backend_name,
                        available: false,
                        cli_bin: Some(bin_str),
                        resolved_bin: None,
                        namespace: Some(prefix),
                        error: Some(err.clone()),
                    },
                    fail_or_warn(err, fix),
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tailscale_status_and_serve_parsers_handle_running_stopped_and_missing_routes() {
        let running = br#"{
            "BackendState": "Running",
            "Self": {
                "DNSName": "alice-mbp.tail9f3a.ts.net.",
                "TailscaleIPs": ["100.64.0.12", "fd7a:115c:a1e0::12"],
                "Online": true
            }
        }"#;
        let parsed = parse_tailscale_status_json(running).unwrap();
        assert_eq!(parsed.state, "running");
        assert_eq!(
            parsed.dns_name.as_deref(),
            Some("alice-mbp.tail9f3a.ts.net")
        );
        assert_eq!(parsed.tailnet_ips[0], "100.64.0.12");
        assert_eq!(parsed.online, Some(true));

        let stopped = br#"{
            "BackendState": "Stopped",
            "Self": {
                "DNSName": "alice-mbp.tail9f3a.ts.net.",
                "TailscaleIPs": ["100.64.0.12"],
                "Online": false
            }
        }"#;
        assert_eq!(
            parse_tailscale_status_json(stopped).unwrap().state,
            "stopped"
        );

        let needs_login = br#"{ "BackendState": "NeedsLogin", "Self": { "Online": false } }"#;
        assert_eq!(
            parse_tailscale_status_json(needs_login).unwrap().state,
            "needs_login"
        );

        let serve_matched = br#"{
            "TCP": { "443": { "HTTPS": true } },
            "Web": {
                "alice-mbp.tail9f3a.ts.net:443": {
                    "Handlers": {
                        "/": { "Proxy": "http://127.0.0.1:8790" }
                    }
                }
            }
        }"#;
        let s_ok = parse_tailscale_serve_status_json(serve_matched, 443, "127.0.0.1:8790");
        assert!(s_ok.checked);
        assert_eq!(s_ok.exposed, Some(true));
        assert!(s_ok.fix_command.is_none());

        let serve_empty = br#"{}"#;
        let s_miss = parse_tailscale_serve_status_json(serve_empty, 443, "127.0.0.1:8790");
        assert!(s_miss.checked);
        assert_eq!(s_miss.exposed, Some(false));
        assert_eq!(
            s_miss.fix_command.as_deref(),
            Some("tailscale serve --bg --https=443 http://127.0.0.1:8790")
        );
    }

    #[test]
    fn tailscale_checks_match_operational_severity_rules() {
        // 1. Running + serve matched -> OK
        let ts_running = TailscaleOperationalStatus {
            installed: true,
            state: "running".to_string(),
            backend_state: Some("Running".to_string()),
            dns_name: Some("alice.tail.ts.net".to_string()),
            tailnet_ips: vec!["100.64.0.5".to_string()],
            online: Some(true),
            has_ts_net_endpoints: true,
            ts_net_endpoints: vec!["https://alice.tail.ts.net".to_string()],
            serve: Some(TailscaleServeStatus {
                checked: true,
                exposed: Some(true),
                expected_https_port: Some(443),
                expected_target: Some("http://127.0.0.1:8790".to_string()),
                matched_target: Some("http://127.0.0.1:8790".to_string()),
                detail: Some("Tailscale Serve HTTPS :443 -> http://127.0.0.1:8790".to_string()),
                fix_command: None,
            }),
            error: None,
        };
        let checks = build_tailscale_checks(&ts_running, true);
        assert_eq!(checks.len(), 2);
        assert_eq!(checks[0].status, CheckStatus::Ok);
        assert!(checks[0].detail.contains("alice.tail.ts.net"));
        assert!(checks[0].detail.contains("100.64.0.5"));
        assert_eq!(checks[1].status, CheckStatus::Ok);

        // 2. Stopped with *.ts.net peer -> FAIL in doctor, WARN in status, with `tailscale up` fix
        let ts_stopped = TailscaleOperationalStatus {
            installed: true,
            state: "stopped".to_string(),
            backend_state: Some("Stopped".to_string()),
            dns_name: Some("alice.tail.ts.net".to_string()),
            tailnet_ips: vec![],
            online: Some(false),
            has_ts_net_endpoints: true,
            ts_net_endpoints: vec!["https://bob.tail.ts.net".to_string()],
            serve: None,
            error: None,
        };
        let doc_checks = build_tailscale_checks(&ts_stopped, true);
        assert_eq!(doc_checks.len(), 1);
        assert_eq!(doc_checks[0].status, CheckStatus::Fail);
        assert!(
            doc_checks[0]
                .fix
                .as_deref()
                .unwrap_or("")
                .contains("tailscale up")
        );
        let status_checks = build_tailscale_checks(&ts_stopped, false);
        assert_eq!(status_checks.len(), 1);
        assert_eq!(status_checks[0].status, CheckStatus::Warn);

        // 3. Not installed without *.ts.net endpoints -> silent (0 checks)
        let ts_none = TailscaleOperationalStatus {
            installed: false,
            state: "not_installed".to_string(),
            backend_state: None,
            dns_name: None,
            tailnet_ips: vec![],
            online: None,
            has_ts_net_endpoints: false,
            ts_net_endpoints: vec![],
            serve: None,
            error: None,
        };
        assert!(build_tailscale_checks(&ts_none, true).is_empty());
        assert!(build_tailscale_checks(&ts_none, false).is_empty());
    }

    #[test]
    fn is_ts_net_endpoint_and_port_parsing() {
        assert!(is_ts_net_endpoint("https://alice.tail9f3a.ts.net"));
        assert!(is_ts_net_endpoint(
            "https://alice.tail9f3a.ts.net:8443/v1/manifest"
        ));
        assert!(!is_ts_net_endpoint("https://ts.net"));
        assert!(!is_ts_net_endpoint("https://public.hyphae.to"));
        assert!(!is_ts_net_endpoint("ssh://ops@alice.tail9f3a.ts.net"));
        assert_eq!(parse_https_port_from_url("https://alice.ts.net"), Some(443));
        assert_eq!(
            parse_https_port_from_url("https://alice.ts.net:8443/path"),
            Some(8443)
        );
    }

    #[test]
    fn inspect_secret_backend_checks_cli_availability_without_touching_secrets() {
        let tmp = tempfile::tempdir().unwrap();
        let fake_bin = tmp.path().join("mock-cli");
        fs::write(&fake_bin, "#!/bin/sh\nexit 99\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&fake_bin, fs::Permissions::from_mode(0o755)).unwrap();
        }

        // 1Password available -> OK
        let op_ok = SecretStore::new(tmp.path(), SecretBackend::OnePassword)
            .with_op_bin(&fake_bin)
            .with_op_vault("TeamVault");
        let (diag, check) = inspect_secret_backend(&op_ok, true);
        assert!(diag.available);
        assert_eq!(diag.backend, "1password");
        assert_eq!(diag.namespace.as_deref(), Some("TeamVault"));
        assert_eq!(check.status, CheckStatus::Ok);

        // LastPass missing -> Fail in doctor, Warn in status
        let lp_missing = SecretStore::new(tmp.path(), SecretBackend::LastPass)
            .with_lpass_bin("/nonexistent/mock-lpass")
            .with_lpass_prefix("hyphae");
        let (diag_doc, check_doc) = inspect_secret_backend(&lp_missing, true);
        assert!(!diag_doc.available);
        assert_eq!(check_doc.status, CheckStatus::Fail);
        let (_, check_status) = inspect_secret_backend(&lp_missing, false);
        assert_eq!(check_status.status, CheckStatus::Warn);

        // Pass path-traversal prefix -> Fail closed
        let pass_bad = SecretStore::new(tmp.path(), SecretBackend::Pass)
            .with_pass_bin(&fake_bin)
            .with_pass_prefix("../etc");
        let (diag_bad, check_bad) = inspect_secret_backend(&pass_bad, true);
        assert!(!diag_bad.available);
        assert_eq!(check_bad.status, CheckStatus::Fail);
    }
}
