//! `hyp node start` (alias `hyp daemon`) — Unified Hyphae v2 Rust Node runtime.
//!
//! Loads v2 `node.json` (or auto-reads legacy v1 `connector.json`), initializes `UnifiedNode`
//! (`node.sqlite` WAL + persistent Ed25519/X25519 keys + exact zero-polling deadline scheduler),
//! optionally starts the HTTP/SSE Peer Server (`router`/`p2p` or explicit `--bind`), writes
//! `node.pid` + `node.status.json`, and shuts down gracefully on `SIGINT`/`SIGTERM`.

use crate::config_file::{
    default_node_id, ensure_dir, load_node_or_legacy_config, open_secret_store, profile_as_str,
    resolve_config_path_for_read, resolve_state_dir, write_atomic_file, write_atomic_json,
};
use crate::drop_cmd::validate_relay_url;
use crate::ui::{EXIT_ERROR, EXIT_OK, EXIT_USAGE, JsonEnvelope, emit_error, print_json};
use clap::{Args, Subcommand, ValueEnum};
use hyp_crypto::CryptoError;
use hyp_crypto::keys::OkpJwk as CryptoOkpJwk;
use hyp_crypto::keystore::{SecretBackend, validate_secret_name};
use hyp_crypto::rfc3339::{format_rfc3339_millis, now_unix_ms};
use hyp_harness::daemon::{
    BoxFuture as DaemonBoxFuture, DEFAULT_PEERS_RELOAD_TIMEOUT, DaemonError, DeliveryRetryConfig,
    LocalDaemon, LocalDaemonConfig, PeersReloader, WakeRecoveryConfig,
};
use hyp_harness::sock::{DEFAULT_SOCKET_FILENAME, daemon_rpc_sync};
use hyp_node::adapters::github_public::normalize_repo_token_pattern;
use hyp_node::adapters::supervisor::is_secret_like_env_key;
use hyp_node::adapters::{
    AdapterKind, GenericWebhookAdapter, GenericWebhookConfig, GitHubPublicAdapter,
    GitHubPublicConfig, GitHubWebhookAdapter, GitHubWebhookConfig, HelloMode,
    PrometheusWebhookAdapter, PrometheusWebhookConfig, SubprocessConfig,
};
use hyp_node::engine::config::{ForwardingPolicy, validate_trusted_proxy_cidr};
use hyp_node::engine::{
    DEFAULT_PEER_SOCKET_FILENAME, DEFAULT_WAKE_CHECK_INTERVAL_SECS, DropRelayConfig, E2eePolicy,
    EscalationConfig, GuestPairingConfig, LocalIngestConfig, LocalIngestServer, NodeConfig,
    NodeProfile, PeerReconcileReport, TopicConfig, UnifiedNode, normalize_drop_portal_url,
    spawn_wake_watcher,
};
use hyp_node::gates::{SecurityGateConfig, SecurityGatePipeline};
use hyp_proto::address::{
    LOCAL_NODE_ID, NodeId, is_valid_handle, is_valid_node_id, is_valid_topic,
};
use hyp_proto::manifest::{OkpCurve as ProtoOkpCurve, OkpJwk as ProtoOkpJwk};
use hyp_proto::scopes::ScopePreset;
use hyp_store::NodeDb;
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io::Write as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum CliNodeProfile {
    Local,
    Router,
    P2p,
}

impl CliNodeProfile {
    pub const fn to_node_profile(self) -> NodeProfile {
        match self {
            Self::Local => NodeProfile::Local,
            Self::Router => NodeProfile::Router,
            Self::P2p => NodeProfile::P2p,
        }
    }
}

#[derive(Subcommand)]
pub enum NodeCommand {
    /// Start the unified Hyphae v2 Node daemon (exact deadline scheduler + optional HTTP/SSE peer server)
    Start(NodeStartArgs),
}

#[derive(Args)]
pub struct NodeStartArgs {
    /// Optional positional config path (v1 `hyp daemon <config.json>` compatibility)
    pub config_pos: Option<PathBuf>,
    /// Path to node.json (or legacy v1 connector.json)
    #[arg(long)]
    pub config: Option<PathBuf>,
    /// Node profile override (local, router, or p2p)
    #[arg(long, value_enum)]
    pub profile: Option<CliNodeProfile>,
    /// HTTP/SSE peer listener address (e.g. 127.0.0.1:8790, or 'none' for SSH-only peer.sock mode)
    #[arg(long)]
    pub bind: Option<String>,
    /// Explicit Unix domain socket path for `hyp connect` / `ssh://` peer transport (also opts in on --profile local)
    #[arg(long)]
    pub peer_socket: Option<PathBuf>,
    /// Disable automatic `<state_dir>/peer.sock` listener on router/p2p profiles
    #[arg(long)]
    pub no_peer_socket: bool,
    /// Canonical Hyphae nodeId override (e.g. alice@macbook, acme-team)
    #[arg(long)]
    pub node_id: Option<String>,
    /// Explicit state directory for node.sqlite, secrets/, and node.pid
    #[arg(long)]
    pub state_dir: Option<PathBuf>,
    /// Explicit local Unix socket (connector.sock) or Windows loopback address file (connector.addr) path
    #[arg(long)]
    pub socket: Option<PathBuf>,
    /// Disable local harness IPC listener (e.g. for pure headless router containers)
    #[arg(long)]
    pub no_local_socket: bool,
    /// Enable the opt-in RAM-only Blind Drop Relay (/v1/drops) on this node
    #[arg(long)]
    pub enable_drop_relay: bool,
    /// Override Drop Relay maximum RAM budget in MiB (default: 256)
    #[arg(long = "drop-max-memory-mb", alias = "max-memory-mb")]
    pub drop_max_memory_mb: Option<usize>,
    /// Exit cleanly (code 0) if a healthy Hyphae daemon is already running on the target socket
    #[arg(long)]
    pub if_not_running: bool,
    /// Output structured JSON envelope on startup
    #[arg(long)]
    pub json: bool,
}

const ALREADY_RUNNING_PROBE_TIMEOUT: Duration = Duration::from_millis(250);

enum NodeStartOutcome {
    Stopped,
    AlreadyRunning { socket: PathBuf },
}

fn emit_already_running(
    cmd: &str,
    as_json: bool,
    socket: &Path,
    state_dir: &Path,
    probe_result: Option<&serde_json::Map<String, Value>>,
) -> ExitCode {
    let summary = format!(
        "Hyphae daemon already running at {}; exiting cleanly (--if-not-running).",
        socket.display()
    );
    if as_json {
        let node_id = probe_result
            .and_then(|m| m.get("nodeId").or_else(|| m.get("connectorId")))
            .and_then(Value::as_str);
        let pid = probe_result
            .and_then(|m| m.get("pid"))
            .and_then(Value::as_u64)
            .or_else(|| {
                fs::read_to_string(state_dir.join("node.pid"))
                    .ok()
                    .and_then(|raw| raw.trim().parse::<u64>().ok())
            });
        let envelope = JsonEnvelope {
            ok: true,
            command: cmd.to_string(),
            summary: Some(summary),
            data: Some(json!({
                "alreadyRunning": true,
                "socketPath": socket.display().to_string(),
                "nodeId": node_id,
                "pid": pid,
            })),
            warnings: Vec::new(),
            next: Vec::new(),
            error: None,
        };
        print_json(&envelope);
    } else {
        println!("OK    {summary}");
        let _ = std::io::stdout().flush();
    }
    ExitCode::from(EXIT_OK)
}

pub fn run_node(command: NodeCommand) -> ExitCode {
    match command {
        NodeCommand::Start(args) => run_node_start(args),
    }
}

pub fn run_node_start(args: NodeStartArgs) -> ExitCode {
    let cmd = "node start";
    let as_json = args.json;
    let explicit_config = args.config.or(args.config_pos);
    let has_explicit_config = explicit_config.is_some();
    let config_path =
        resolve_config_path_for_read(explicit_config.as_deref(), args.state_dir.as_deref(), None);

    let loaded = if config_path.exists() {
        match load_node_or_legacy_config(&config_path) {
            Ok(cfg) => Some(cfg),
            Err(e) => {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_ERROR,
                    "CONFIG_ERROR",
                    e,
                    Some("Verify node.json syntax or run `hyp onboard`.".to_string()),
                );
            }
        }
    } else if explicit_config.is_some() {
        return emit_error(
            cmd,
            as_json,
            EXIT_ERROR,
            "CONFIG_NOT_FOUND",
            format!("Config file does not exist: {}", config_path.display()),
            Some("Check --config path or run `hyp onboard`.".to_string()),
        );
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

    let profile = args
        .profile
        .map(CliNodeProfile::to_node_profile)
        .or_else(|| loaded.as_ref().and_then(|c| c.profile))
        .unwrap_or(NodeProfile::Local);

    let node_id_raw = args
        .node_id
        .or_else(|| loaded.as_ref().and_then(|c| c.node_id.clone()))
        .unwrap_or_else(default_node_id);

    if node_id_raw == LOCAL_NODE_ID || !is_valid_node_id(&node_id_raw) {
        return emit_error(
            cmd,
            as_json,
            EXIT_USAGE,
            "INVALID_NODE_ID",
            format!(
                "Invalid nodeId '{node_id_raw}': must match /^[a-z0-9][a-z0-9@._-]{{0,63}}$/ and not be 'local'"
            ),
            Some("Pass --node-id <user@host> or fix nodeId in node.json.".to_string()),
        );
    }
    let node_id = match NodeId::new(&node_id_raw) {
        Ok(id) => id,
        Err(e) => {
            return emit_error(
                cmd,
                as_json,
                EXIT_USAGE,
                "INVALID_NODE_ID",
                e.to_string(),
                None,
            );
        }
    };

    let explicit_ssh_only_config = loaded.as_ref().is_some_and(|c| {
        let bind_explicitly_disabled = c
            .raw
            .get("listen")
            .and_then(|l| l.get("bind"))
            .is_some_and(|v| v.is_null() || v.as_str().is_some_and(|s| s.trim().is_empty()));
        let ssh_public_url = c
            .public_url
            .as_deref()
            .is_some_and(|u| u.trim().starts_with("ssh://"));
        bind_explicitly_disabled || (ssh_public_url && c.bind_addr.is_none())
    });

    let bind_addr: Option<SocketAddr> = match args.bind {
        Some(ref raw)
            if raw.trim().eq_ignore_ascii_case("none")
                || raw.trim().eq_ignore_ascii_case("off") =>
        {
            None
        }
        Some(ref raw) => {
            match raw.parse::<SocketAddr>() {
                Ok(a) => Some(a),
                Err(e) => {
                    return emit_error(
                    cmd,
                    as_json,
                    EXIT_USAGE,
                    "INVALID_BIND",
                    format!("Invalid --bind '{raw}': {e}"),
                    Some("Use <ip>:<port>, e.g. 127.0.0.1:8790 (or 'none' for SSH-only peer.sock)".to_string()),
                );
                }
            }
        }
        None => loaded.as_ref().and_then(|c| c.bind_addr).or_else(|| {
            if !explicit_ssh_only_config
                && matches!(profile, NodeProfile::Router | NodeProfile::P2p)
            {
                Some("127.0.0.1:8790".parse().expect("valid default bind"))
            } else {
                None
            }
        }),
    };

    let (peer_socket_path, peer_socket_required): (Option<PathBuf>, bool) = if args.no_peer_socket {
        (None, false)
    } else if let Some(ref explicit_ps) = args.peer_socket {
        (Some(explicit_ps.clone()), true)
    } else {
        let cfg_ps = loaded
            .as_ref()
            .and_then(|c| c.raw.get("listen").and_then(|l| l.get("peerSocket")));
        match cfg_ps {
            Some(Value::Bool(false)) => (None, false),
            Some(Value::Bool(true)) => (Some(state_dir.join(DEFAULT_PEER_SOCKET_FILENAME)), true),
            Some(Value::String(s)) if !s.trim().is_empty() => {
                let p = PathBuf::from(s.trim());
                let resolved = if p.is_absolute() {
                    p
                } else if let Some(parent) = loaded.as_ref().and_then(|c| c.path.parent()) {
                    parent.join(p)
                } else {
                    p
                };
                (Some(resolved), true)
            }
            _ if matches!(profile, NodeProfile::Router | NodeProfile::P2p)
                || explicit_ssh_only_config =>
            {
                (
                    Some(state_dir.join(DEFAULT_PEER_SOCKET_FILENAME)),
                    bind_addr.is_none(),
                )
            }
            _ => (None, false),
        }
    };

    let start_local_daemon = !args.no_local_socket
        && (matches!(profile, NodeProfile::Local | NodeProfile::P2p) || args.socket.is_some());
    let explicit_socket = args.socket.clone();
    let if_not_running = args.if_not_running;

    if if_not_running && start_local_daemon {
        let target_socket = explicit_socket
            .clone()
            .unwrap_or_else(|| state_dir.join(DEFAULT_SOCKET_FILENAME));
        let probe = daemon_rpc_sync(
            &target_socket,
            &json!({ "type": "daemon.status" }),
            ALREADY_RUNNING_PROBE_TIMEOUT,
        );
        if probe.ok {
            return emit_already_running(
                cmd,
                as_json,
                &target_socket,
                &state_dir,
                probe.result.as_ref(),
            );
        }
    }

    if let Err(e) = ensure_dir(&state_dir, true) {
        return emit_error(cmd, as_json, EXIT_ERROR, "IO_ERROR", e, None);
    }

    let mut node_cfg = NodeConfig::new(node_id, profile, &state_dir);
    node_cfg.bind_addr = bind_addr;
    node_cfg.public_endpoint = loaded.as_ref().and_then(|c| c.public_url.clone());
    let explicit_state = args.state_dir.is_some();
    if explicit_state && std::env::var_os("HYPHAE_SECRET_BACKEND").is_none() {
        node_cfg.secret_backend = Some(SecretBackend::File);
    }

    let mut startup_warnings: Vec<String> = Vec::new();
    let mut github_public_cfg: Option<GitHubPublicConfig> = None;
    let mut webhook_sources = ParsedWebhookSources::default();
    let mut delivery_retry_cfg = DeliveryRetryConfig::default();
    let mut wake_recovery_cfg = WakeRecoveryConfig::default();
    let mut parsed_plugins: Vec<ParsedPlugin> = Vec::new();
    let mut skipped_plugin_statuses: Vec<Value> = Vec::new();

    if let Some(ref cfg) = loaded {
        node_cfg.require_pairing = cfg.require_pairing;
        node_cfg.e2ee_policy = if cfg.require_e2ee {
            E2eePolicy::Required
        } else {
            E2eePolicy::Prefer
        };

        if let Err(e) = parse_node_runtime_policies(&cfg.raw, &mut node_cfg) {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                "CONFIG_ERROR",
                format!("Invalid runtime policy in {}: {e}", cfg.path.display()),
                None,
            );
        }

        // Parse optional `localIngest` policy (default enabled: true!).
        if let Some(li_val) = cfg.raw.get("localIngest") {
            match serde_json::from_value::<LocalIngestConfig>(li_val.clone()) {
                Ok(li) => {
                    let bare_default = li
                        .default_topic
                        .strip_prefix("local.")
                        .unwrap_or(li.default_topic.as_str());
                    if !is_valid_topic(bare_default) {
                        return emit_error(
                            cmd,
                            as_json,
                            EXIT_ERROR,
                            "CONFIG_ERROR",
                            format!(
                                "Invalid localIngest.defaultTopic '{}' in {}",
                                li.default_topic,
                                cfg.path.display()
                            ),
                            None,
                        );
                    }
                    node_cfg.local_ingest = li;
                }
                Err(e) => {
                    return emit_error(
                        cmd,
                        as_json,
                        EXIT_ERROR,
                        "CONFIG_ERROR",
                        format!("Invalid localIngest config in {}: {e}", cfg.path.display()),
                        None,
                    );
                }
            }
        }

        // Parse optional `deliveryRetry` (with legacy fallbacks `codexResume`, `herdrSpawnAllowlist`).
        match parse_delivery_retry_config(&cfg.raw) {
            Ok(dr_cfg) => delivery_retry_cfg = dr_cfg,
            Err(e) => {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_ERROR,
                    "CONFIG_ERROR",
                    format!(
                        "Invalid deliveryRetry config in {}: {e}",
                        cfg.path.display()
                    ),
                    None,
                );
            }
        }

        // Parse optional `wakeRecovery` sleep/wake detector & recovery settings.
        match parse_wake_recovery_config(&cfg.raw) {
            Ok(wr_cfg) => wake_recovery_cfg = wr_cfg,
            Err(e) => {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_ERROR,
                    "CONFIG_ERROR",
                    format!("Invalid wakeRecovery config in {}: {e}", cfg.path.display()),
                    None,
                );
            }
        }

        // Parse optional `dropRelay` (RAM-only Blind Drop Relay) and `dropRelayUrl`.
        if let Some(dr_val) = cfg.raw.get("dropRelay") {
            match serde_json::from_value::<DropRelayConfig>(dr_val.clone()) {
                Ok(dr) => {
                    if dr.max_memory_mb == 0 {
                        return emit_error(
                            cmd,
                            as_json,
                            EXIT_ERROR,
                            "CONFIG_ERROR",
                            format!(
                                "dropRelay.maxMemoryMb in {} must be >= 1",
                                cfg.path.display()
                            ),
                            None,
                        );
                    }
                    if dr
                        .allowed_origins
                        .iter()
                        .any(|o| o.trim() == "*" || o.trim().eq_ignore_ascii_case("null"))
                    {
                        return emit_error(
                            cmd,
                            as_json,
                            EXIT_ERROR,
                            "CONFIG_ERROR",
                            format!(
                                "dropRelay.allowedOrigins in {} must not contain wildcard '*' or 'null'",
                                cfg.path.display()
                            ),
                            Some("Set allowedOrigins to [\"https://hyphae.to\"].".to_string()),
                        );
                    }
                    node_cfg.drop_relay = dr;
                }
                Err(e) => {
                    return emit_error(
                        cmd,
                        as_json,
                        EXIT_ERROR,
                        "CONFIG_ERROR",
                        format!("Invalid dropRelay config in {}: {e}", cfg.path.display()),
                        None,
                    );
                }
            }
        }
        if let Some(raw_url) = cfg
            .raw
            .get("dropRelayUrl")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            match validate_relay_url(raw_url) {
                Ok(valid_url) => node_cfg.drop_relay_url = Some(valid_url),
                Err(e) => {
                    return emit_error(
                        cmd,
                        as_json,
                        EXIT_ERROR,
                        "CONFIG_ERROR",
                        format!("Invalid dropRelayUrl in {}: {e}", cfg.path.display()),
                        None,
                    );
                }
            }
        }

        // Parse optional `dropPortalUrl` (fail closed on invalid URLs).
        if let Some(dp_val) = cfg.raw.get("dropPortalUrl") {
            if !dp_val.is_null() {
                let Some(raw_url) = dp_val.as_str() else {
                    return emit_error(
                        cmd,
                        as_json,
                        EXIT_ERROR,
                        "CONFIG_ERROR",
                        format!(
                            "Invalid dropPortalUrl in {}: must be a string",
                            cfg.path.display()
                        ),
                        Some(
                            "Set dropPortalUrl to an https:// URL (e.g. \"https://hyphae.to/drop\") or loopback http://127.0.0.1."
                                .to_string(),
                        ),
                    );
                };
                match normalize_drop_portal_url(raw_url) {
                    Ok(valid_url) => node_cfg.drop_portal_url = Some(valid_url),
                    Err(e) => {
                        return emit_error(
                            cmd,
                            as_json,
                            EXIT_ERROR,
                            "CONFIG_ERROR",
                            format!("Invalid dropPortalUrl in {}: {e}", cfg.path.display()),
                            Some(
                                "Set dropPortalUrl to an https:// URL (e.g. \"https://hyphae.to/drop\") or loopback http://127.0.0.1."
                                    .to_string(),
                            ),
                        );
                    }
                }
            }
        }

        // Parse optional `escalation` hints (default + byScope).
        if let Some(esc_val) = cfg.raw.get("escalation") {
            match serde_json::from_value::<EscalationConfig>(esc_val.clone()) {
                Ok(esc) => node_cfg.escalation = esc,
                Err(e) => {
                    return emit_error(
                        cmd,
                        as_json,
                        EXIT_ERROR,
                        "CONFIG_ERROR",
                        format!("Invalid escalation config in {}: {e}", cfg.path.display()),
                        None,
                    );
                }
            }
        }

        // Parse opt-in `guestPairing` policy (matching `hyp deploy init public-node`).
        if let Some(gp_val) = cfg.raw.get("guestPairing") {
            match parse_guest_pairing_config(gp_val, cfg.raw.get("rateLimits")) {
                Ok(gp) => node_cfg.guest_pairing = gp,
                Err(e) => {
                    return emit_error(
                        cmd,
                        as_json,
                        EXIT_ERROR,
                        "CONFIG_ERROR",
                        format!("Invalid guestPairing config in {}: {e}", cfg.path.display()),
                        None,
                    );
                }
            }
        }

        let secrets = open_secret_store(&state_dir, explicit_state);

        // Parse optional `pairing.adminKey` (OKP Ed25519 JWK object, 43-char base64url raw pubkey,
        // or `{ "secret": "<name>" }` reference) so `POST /v1/pair` can verify Org Admin-CA `am2_` grants.
        if let Some(admin_key_val) = cfg.raw.get("pairing").and_then(|p| p.get("adminKey")) {
            match parse_pairing_admin_key(admin_key_val, &secrets, &mut startup_warnings) {
                Ok(maybe_jwk) => node_cfg.admin_jwk = maybe_jwk,
                Err(e) => {
                    return emit_error(
                        cmd,
                        as_json,
                        EXIT_ERROR,
                        "CONFIG_ERROR",
                        format!("Invalid pairing.adminKey in {}: {e}", cfg.path.display()),
                        Some(
                            "Set pairing.adminKey to a public OKP Ed25519 JWK object, a 43-char base64url Ed25519 public key, or { \"secret\": \"hyphae-admin-pubkey\" }."
                                .to_string(),
                        ),
                    );
                }
            }
        }

        // Parse `sources` entries (`github-public`, `github-webhook`, `prometheus-webhook`, `webhook-stream`).
        if let Some(sources_val) = cfg.raw.get("sources") {
            let public_read_only = cfg
                .raw
                .get("publicReadOnly")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            match parse_github_public_source(
                sources_val,
                &secrets,
                public_read_only,
                &mut startup_warnings,
            ) {
                Ok(Some(gh_cfg)) => {
                    if !node_cfg.topics.iter().any(|t| t.topic == gh_cfg.topic) {
                        node_cfg.topics.push(TopicConfig {
                            topic: gh_cfg.topic.clone(),
                            kind: Some("github-public".to_string()),
                            description: Some(
                                "Public GitHub repository events (demand-driven ETag polling)"
                                    .to_string(),
                            ),
                            metadata: None,
                            has_provisioned_publisher: true,
                        });
                    }
                    github_public_cfg = Some(gh_cfg);
                }
                Ok(None) => {}
                Err(e) => {
                    return emit_error(
                        cmd,
                        as_json,
                        EXIT_ERROR,
                        "CONFIG_ERROR",
                        format!("Invalid github-public source in {}: {e}", cfg.path.display()),
                        Some(
                            "Verify sources[] in node.json uses { \"secret\": \"<name>\" } references, never plaintext tokens."
                                .to_string(),
                        ),
                    );
                }
            }

            match parse_webhook_sources(sources_val, &secrets) {
                Ok(mut parsed) => {
                    filter_colliding_webhook_sources(
                        &mut parsed,
                        node_cfg.guest_pairing.enabled,
                        github_public_cfg.as_ref().map(|g| g.topic.as_str()),
                        &mut startup_warnings,
                    );
                    for gh in &parsed.github {
                        if !node_cfg.topics.iter().any(|t| t.topic == gh.topic) {
                            node_cfg.topics.push(TopicConfig {
                                topic: gh.topic.clone(),
                                kind: Some("github-webhook".to_string()),
                                description: Some("GitHub webhook CloudEvents stream".to_string()),
                                metadata: None,
                                has_provisioned_publisher: true,
                            });
                        }
                    }
                    for prom in &parsed.prometheus {
                        if !node_cfg.topics.iter().any(|t| t.topic == prom.topic) {
                            node_cfg.topics.push(TopicConfig {
                                topic: prom.topic.clone(),
                                kind: Some("prometheus-webhook".to_string()),
                                description: Some(
                                    "Prometheus Alertmanager webhook CloudEvents stream"
                                        .to_string(),
                                ),
                                metadata: None,
                                has_provisioned_publisher: true,
                            });
                        }
                    }
                    for gen_wh in &parsed.generic {
                        if !node_cfg.topics.iter().any(|t| t.topic == gen_wh.topic) {
                            node_cfg.topics.push(TopicConfig {
                                topic: gen_wh.topic.clone(),
                                kind: Some("webhook-stream".to_string()),
                                description: Some(
                                    "Generic signed webhook CloudEvents stream".to_string(),
                                ),
                                metadata: None,
                                has_provisioned_publisher: true,
                            });
                        }
                    }
                    webhook_sources = parsed;
                }
                Err(e) => {
                    return emit_error(
                        cmd,
                        as_json,
                        EXIT_ERROR,
                        "CONFIG_ERROR",
                        format!("Invalid webhook source in {}: {e}", cfg.path.display()),
                        Some(
                            "Verify webhook sources[] in node.json use { \"secret\": \"<name>\" } references stored via `hyp secret set <name>`, never plaintext secrets."
                                .to_string(),
                        ),
                    );
                }
            }
        }

        // Collect any explicitly configured top-level `topics[]` names from `node.json`.
        // Both subprocess bridge plugins AND subprocess source plugins default to strictly
        // local-only (`exposeTopic: false`) so paired remote peers with `stream:subscribe=*`
        // (`member`/`observer`/`full`) never silently read private local chat DMs or personal
        // subprocess event sources unless explicitly opted in via `plugins[].exposeTopic: true`.
        let explicit_topics = parse_explicit_topic_names(cfg.raw.get("topics"));

        // Parse optional `plugins[]` external bridge/source subprocess entries.
        // Fault isolation: individual malformed/misconfigured plugin entries or missing secrets
        // emit startup warnings and record their status without aborting `hyp node start`.
        if let Some(plugins_val) = cfg.raw.get("plugins") {
            if !plugins_val.is_null() {
                let plugins = parse_plugins_config(
                    plugins_val,
                    cfg.path.parent(),
                    &state_dir,
                    &explicit_topics,
                    &secrets,
                    &mut startup_warnings,
                    &mut skipped_plugin_statuses,
                );
                for p in &plugins {
                    match p.config.kind {
                        AdapterKind::Bridge => {
                            if p.expose_topic {
                                if !node_cfg.topics.iter().any(|t| t.topic == p.config.id) {
                                    node_cfg.topics.push(TopicConfig {
                                        topic: p.config.id.clone(),
                                        kind: Some("bridge".to_string()),
                                        description: Some(format!(
                                            "External bridge plugin '{}'",
                                            p.config.id
                                        )),
                                        metadata: None,
                                        has_provisioned_publisher: true,
                                    });
                                }
                            } else if is_valid_topic(&p.config.id) {
                                node_cfg.local_only_topics.insert(p.config.id.clone());
                            }
                        }
                        AdapterKind::Source => {
                            let mut has_invalid_target = false;
                            for target in &p.config.targets {
                                if is_valid_topic(target) {
                                    if !node_cfg.topics.iter().any(|t| t.topic == *target) {
                                        node_cfg.topics.push(TopicConfig {
                                            topic: target.clone(),
                                            kind: Some("source".to_string()),
                                            description: Some(format!(
                                                "External source plugin '{}'",
                                                p.config.id
                                            )),
                                            metadata: None,
                                            has_provisioned_publisher: true,
                                        });
                                    }
                                    if !p.expose_topic {
                                        node_cfg.local_only_topics.insert(target.clone());
                                    }
                                } else {
                                    has_invalid_target = true;
                                }
                            }
                            if has_invalid_target && is_valid_topic(&p.config.id) {
                                if !node_cfg.topics.iter().any(|t| t.topic == p.config.id) {
                                    node_cfg.topics.push(TopicConfig {
                                        topic: p.config.id.clone(),
                                        kind: Some("source".to_string()),
                                        description: Some(format!(
                                            "External source plugin '{}'",
                                            p.config.id
                                        )),
                                        metadata: None,
                                        has_provisioned_publisher: true,
                                    });
                                }
                                if !p.expose_topic {
                                    node_cfg.local_only_topics.insert(p.config.id.clone());
                                }
                            }
                        }
                        _ => {}
                    }
                }
                parsed_plugins = plugins;
            }
        }
    }

    if args.enable_drop_relay {
        node_cfg.drop_relay.enabled = true;
    }
    if let Some(max_mb) = args.drop_max_memory_mb {
        if max_mb == 0 {
            return emit_error(
                cmd,
                as_json,
                EXIT_USAGE,
                "INVALID_DROP_MEMORY",
                "--drop-max-memory-mb must be >= 1",
                None,
            );
        }
        node_cfg.drop_relay.max_memory_mb = max_mb;
    }

    let drop_relay_enabled = node_cfg.drop_relay.enabled;
    let drop_relay_url = node_cfg.drop_relay_url.clone();

    let start_local_ingest = node_cfg.local_ingest.enabled && !args.no_local_socket;

    let rt = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
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
                format!("Failed to start Tokio runtime: {e}"),
                None,
            );
        }
    };

    let legacy_warning = loaded.as_ref().filter(|c| c.is_legacy_v1).map(|c| {
        format!(
            "Loaded legacy v1 config {}; consider migrating to node.json.",
            c.path.display()
        )
    });

    let state_dir_for_probe = state_dir.clone();
    let res = rt.block_on(async move {
        let node = UnifiedNode::open(node_cfg)
            .map_err(|e| format!("Failed to initialize UnifiedNode: {e}"))?;

        {
            let db = node.db();
            let _ = db
                .local()
                .set_metadata("node_profile", profile_as_str(profile));
            let _ = db
                .local()
                .set_metadata("node_version", env!("CARGO_PKG_VERSION"));
        }

        // Attach and start demand-driven `github-public` adapter BEFORE serving HTTP!
        let (github_public_enabled, github_public_token_scopes) =
            if let Some(gh_cfg) = github_public_cfg {
                let scopes = gh_cfg.configured_token_scopes();
                let adapter = Arc::new(
                    GitHubPublicAdapter::new(gh_cfg)
                        .map_err(|e| format!("Failed to initialize github-public adapter: {e}"))?,
                );
                node.attach_github_public(adapter)
                    .await
                    .map_err(|e| format!("Failed to attach github-public adapter: {e}"))?;
                (true, scopes)
            } else {
                (false, Vec::new())
            };

        // Attach compiled-in pure-Rust webhook adapters BEFORE serving HTTP!
        for gh_cfg in webhook_sources.github {
            let adapter = Arc::new(GitHubWebhookAdapter::new(gh_cfg));
            node.attach_github_webhook(adapter)
                .await
                .map_err(|e| format!("Failed to attach github-webhook adapter: {e}"))?;
        }
        for prom_cfg in webhook_sources.prometheus {
            let adapter = Arc::new(PrometheusWebhookAdapter::new(prom_cfg));
            node.attach_prometheus_webhook(adapter)
                .await
                .map_err(|e| format!("Failed to attach prometheus-webhook adapter: {e}"))?;
        }
        for gen_cfg in webhook_sources.generic {
            let adapter = Arc::new(GenericWebhookAdapter::new(gen_cfg));
            node.attach_generic_webhook(adapter)
                .await
                .map_err(|e| format!("Failed to attach webhook-stream adapter: {e}"))?;
        }

        let guest_pairing_enabled = node.config().guest_pairing.enabled;

        let has_gate_cfg = loaded
            .as_ref()
            .and_then(|c| c.raw.get("gate"))
            .is_some();
        let (gate_pipeline, gate_db_shared) =
            if start_local_daemon || start_local_ingest || has_gate_cfg {
            let gate_cfg: SecurityGateConfig = match loaded.as_ref().and_then(|c| c.raw.get("gate"))
            {
                Some(gate_val) => serde_json::from_value(gate_val.clone())
                    .map_err(|e| format!("Invalid gate configuration in node.json: {e}"))?,
                None => SecurityGateConfig::default(),
            };
            let gate_db = Arc::new(Mutex::new(
                NodeDb::open(state_dir.join("node.sqlite"))
                    .map_err(|e| format!("Failed to open SecurityGate NodeDb: {e}"))?,
            ));
            let gate_secrets = Arc::new(open_secret_store(&state_dir, explicit_state));
            let pipeline = Arc::new(
                SecurityGatePipeline::new(gate_cfg, Arc::clone(&gate_db), Some(gate_secrets))
                    .map_err(|e| format!("Failed to initialize SecurityGatePipeline: {e}"))?,
            );
            if pipeline.is_policy_tampered() {
                startup_warnings.push(
                    "gate_policy_tampered: gate policy signature verification failed; all non-self-host inbound items will fail closed to quarantine until re-locked via `hyp gate lock`."
                        .to_string(),
                );
            }
            (Some(pipeline), Some(gate_db))
        } else {
            (None, None)
        };

        let status_doc_state: Arc<Mutex<Option<(PathBuf, Value)>>> = Arc::new(Mutex::new(None));

        let local_daemon = if start_local_daemon {
            let local_cfg = LocalDaemonConfig {
                socket_path: explicit_socket,
                auto_detect_transports: true,
                delivery_retry: delivery_retry_cfg,
                wake_recovery: wake_recovery_cfg.clone(),
                ..Default::default()
            };
            match LocalDaemon::start(Arc::clone(&node), gate_pipeline.clone(), local_cfg).await {
                Ok(daemon) => {
                    daemon.set_peers_reloader(Arc::new(NodeCmdPeersReloader {
                        node: Arc::clone(&node),
                        status_doc: Arc::clone(&status_doc_state),
                    }));
                    if let Some(ref gate_db) = gate_db_shared {
                        let reload_config_path = config_path.clone();
                        let reload_state_dir = state_dir.clone();
                        let reload_db = Arc::clone(gate_db);
                        daemon.set_gate_reloader(Arc::new(move || {
                            reload_gate_pipeline_from_disk(
                                &reload_config_path,
                                has_explicit_config,
                                &reload_state_dir,
                                explicit_state,
                                Arc::clone(&reload_db),
                            )
                        }));
                    }
                    Some(Arc::new(daemon))
                }
                Err(DaemonError::AlreadyRunning(sock)) if if_not_running => {
                    node.shutdown_adapters().await;
                    node.shutdown();
                    return Ok(NodeStartOutcome::AlreadyRunning { socket: sock });
                }
                Err(e) => return Err(format!("Failed to start local harness IPC daemon: {e}")),
            }
        } else {
            None
        };

        // Wire live SecurityGatePipeline into `UnifiedNode` (shares `LocalDaemon`'s hot-reloadable
        // gate slot when present) for stage-before-unpack transfer gating and remote bridge DLP.
        if let Some(ref daemon) = local_daemon {
            node.set_shared_security_gate(daemon.gate_slot());
        } else if let Some(ref pipeline) = gate_pipeline {
            node.set_security_gate(Some(Arc::clone(pipeline)));
        }

        let local_ingest_server = if start_local_ingest {
            let srv = if let Some(ref daemon) = local_daemon {
                LocalIngestServer::start_with_shared_gate(
                    Arc::clone(&node),
                    daemon.gate_slot(),
                    node.config().local_ingest.clone(),
                )
                .await
                .map_err(|e| format!("Failed to start local ingest server: {e}"))?
            } else {
                LocalIngestServer::start(
                    Arc::clone(&node),
                    gate_pipeline.clone(),
                    node.config().local_ingest.clone(),
                )
                .await
                .map_err(|e| format!("Failed to start local ingest server: {e}"))?
            };
            Some(srv)
        } else {
            None
        };

        // Start configured external bridge/source plugins (Unix fd-3 on Unix, authenticated
        // loopback-TCP on Windows) and wire bridge targets + outbound BridgePosters into
        // `LocalDaemon`.
        let (running_plugins, plugin_registry) = plugin_runtime::start_plugins(
            parsed_plugins,
            skipped_plugin_statuses,
            Arc::clone(&status_doc_state),
            &node,
            local_daemon.as_ref(),
            &mut startup_warnings,
        )
        .await;

        // Wire best-effort `system.wake` JSON-RPC notifications into running external plugins.
        // When `LocalDaemon` is active, its built-in wake watcher invokes this hook; for headless
        // nodes without `LocalDaemon`, spawn a lightweight node-only wake watcher.
        let mut headless_wake_shutdown: Option<tokio::sync::watch::Sender<bool>> = None;
        let mut headless_wake_task = None;
        if let Some(ref daemon) = local_daemon {
            if !running_plugins.is_empty() {
                let wake_plugins = running_plugins.clone();
                daemon.on_system_wake(move |slept_for| {
                    let plugins = wake_plugins.clone();
                    async move {
                        plugin_runtime::notify_plugins_wake(&plugins, slept_for).await;
                    }
                });
            }
        } else if wake_recovery_cfg.enabled {
            let (tx, rx) = tokio::sync::watch::channel(false);
            let wake_node = Arc::clone(&node);
            let wake_plugins = running_plugins.clone();
            headless_wake_task = Some(spawn_wake_watcher(
                Duration::from_secs(DEFAULT_WAKE_CHECK_INTERVAL_SECS),
                wake_recovery_cfg.min_sleep_duration(),
                rx,
                move |ev| {
                    let n = Arc::clone(&wake_node);
                    let plugins = wake_plugins.clone();
                    async move {
                        n.notify_system_wake(ev.slept_for);
                        plugin_runtime::notify_plugins_wake(&plugins, ev.slept_for).await;
                    }
                },
            ));
            headless_wake_shutdown = Some(tx);
        }

        let plugin_statuses = plugin_registry.snapshot();

        let mut bound_addr: Option<SocketAddr> = None;
        let mut server_handle = None;
        if let Some(addr) = bind_addr {
            let (actual, handle) = Arc::clone(&node)
                .serve(addr)
                .await
                .map_err(|e| format!("Failed to bind HTTP/SSE peer server on {addr}: {e}"))?;
            bound_addr = Some(actual);
            server_handle = Some(handle);
        }

        #[cfg(unix)]
        let mut bound_peer_socket: Option<PathBuf> = None;
        #[cfg(not(unix))]
        let bound_peer_socket: Option<PathBuf> = None;
        #[cfg(unix)]
        let mut unix_server_handle = None;
        #[cfg(unix)]
        if let Some(ps_path) = peer_socket_path {
            match Arc::clone(&node).serve_unix(ps_path.clone()).await {
                Ok((actual_sock, handle)) => {
                    bound_peer_socket = Some(actual_sock);
                    unix_server_handle = Some(handle);
                }
                Err(e) if !peer_socket_required => {
                    startup_warnings.push(format!(
                        "Could not bind optional peer.sock at {}: {e}",
                        ps_path.display()
                    ));
                }
                Err(e) => {
                    return Err(format!(
                        "Failed to bind peer Unix socket {}: {e}",
                        ps_path.display()
                    ));
                }
            }
        }
        #[cfg(not(unix))]
        let _ = (peer_socket_path, peer_socket_required);

        // Auto-connect persisted active peers with a configured endpoint so restarted
        // daemons immediately restore PeerLinks and background SSE `/v1/inbox` streams.
        // Never fail startup if a remote peer is temporarily offline — record a warning instead.
        let initial_reconcile = node.reconcile_peers(Duration::from_secs(5)).await;
        startup_warnings.extend(initial_reconcile.warnings);
        let connected_peers = initial_reconcile.connected_peers;

        // Wake the node scheduler and run a non-blocking post-bootstrap mailbox/topic flush
        // now that plugins and peer links are online (strictly at-most-once, never blocks startup).
        node.wake_scheduler();
        if let Some(ref daemon) = local_daemon {
            let flush_daemon = Arc::clone(daemon);
            tokio::spawn(async move {
                flush_daemon.flush_pending_sessions().await;
            });
        }

        let pid = std::process::id();
        let pid_path = state_dir.join("node.pid");
        let status_path = state_dir.join("node.status.json");
        let started_at = format_rfc3339_millis(now_unix_ms());
        let kid = node.identity().kid();
        let fingerprint = node.identity().fingerprint();
        let endpoint = bound_addr.map(|a| format!("http://{a}")).or_else(|| {
            node.config().public_endpoint.clone()
        });
        let socket_path_str = local_daemon
            .as_ref()
            .map(|d| d.socket_path().display().to_string());
        let local_ingest_socket_str = local_ingest_server
            .as_ref()
            .map(|s| s.endpoint_path().display().to_string());
        let peer_socket_str = bound_peer_socket
            .as_ref()
            .map(|p| p.display().to_string());

        write_atomic_file(&pid_path, format!("{pid}\n").as_bytes(), true)?;
        let status_doc = json!({
            "pid": pid,
            "nodeId": node.node_id().as_str(),
            "profile": profile_as_str(profile),
            "version": env!("CARGO_PKG_VERSION"),
            "kid": kid,
            "fingerprint": fingerprint,
            "bind": bound_addr.map(|a| a.to_string()),
            "endpoint": endpoint,
            "peerSocket": peer_socket_str,
            "socketPath": socket_path_str,
            "localIngestEnabled": local_ingest_server.is_some(),
            "localIngestSocket": local_ingest_socket_str,
            "stateDir": state_dir.display().to_string(),
            "configPath": loaded.as_ref().map(|c| c.path.display().to_string()),
            "guestPairingEnabled": guest_pairing_enabled,
            "githubPublicEnabled": github_public_enabled,
            "githubPublicTokenScopes": github_public_token_scopes,
            "dropRelayEnabled": drop_relay_enabled,
            "dropRelayUrl": drop_relay_url,
            "connectedPeers": connected_peers,
            "plugins": plugin_statuses,
            "startedAt": started_at,
        });
        write_atomic_json(&status_path, &status_doc, true)?;
        {
            let mut guard = status_doc_state.lock().expect("status_doc lock poisoned");
            *guard = Some((status_path.clone(), status_doc.clone()));
        }
        plugin_registry.flush_to_status_doc();

        let mut warnings = startup_warnings;
        if let Some(w) = legacy_warning {
            warnings.push(w);
        }

        if as_json {
            let envelope = JsonEnvelope {
                ok: true,
                command: cmd.to_string(),
                summary: Some(format!(
                    "Hyphae v2 Node '{}' ({}) started (pid {})",
                    node.node_id().as_str(),
                    profile_as_str(profile),
                    pid
                )),
                data: Some(status_doc),
                warnings,
                next: vec![
                    format!("hyp status --state-dir {}", state_dir.display()),
                    format!("hyp doctor --state-dir {}", state_dir.display()),
                ],
                error: None,
            };
            let line = serde_json::to_string(&envelope)
                .map_err(|e| format!("Failed to serialize startup JSON envelope: {e}"))?;
            println!("{line}");
            let _ = std::io::stdout().flush();
        } else {
            println!(
                "OK    Hyphae v2 Node '{}' started (profile={}, pid={})",
                node.node_id().as_str(),
                profile_as_str(profile),
                pid
            );
            println!("      State Dir:   {}", state_dir.display());
            println!("      JWK kid:     {kid}");
            println!("      Fingerprint: {fingerprint}");
            if let Some(ref sock) = socket_path_str {
                println!("      Local IPC:   {sock}");
            } else {
                println!("      Local IPC:   disabled");
            }
            if let Some(ref ingest_sock) = local_ingest_socket_str {
                println!("      Local Ingest: {ingest_sock}");
            } else {
                println!("      Local Ingest: disabled");
            }
            if let Some(addr) = bound_addr {
                println!("      Peer HTTP:   http://{addr} (GET /v1/manifest, GET /v1/health)");
            } else if peer_socket_str.is_some() {
                println!("      Peer HTTP:   disabled (SSH-only peer.sock mode)");
            } else {
                println!("      Peer HTTP:   disabled (local profile)");
            }
            if let Some(ref ps) = peer_socket_str {
                println!("      Peer Socket: {ps} (0600, hyp connect / ssh://)");
            }
            if guest_pairing_enabled {
                println!("      Guest Pair:  enabled (POST /v1/guest/pair -> guest-ro)");
            }
            if github_public_enabled {
                if github_public_token_scopes.is_empty() {
                    println!(
                        "      GitHub Pub:  enabled (demand-driven ETag poller, unauthenticated)"
                    );
                } else {
                    println!(
                        "      GitHub Pub:  enabled (demand-driven ETag poller, tokenScopes=[{}])",
                        github_public_token_scopes.join(", ")
                    );
                }
            }
            if drop_relay_enabled {
                println!(
                    "      Drop Relay:  enabled (RAM cap {} MiB)",
                    node.config().drop_relay.max_memory_mb
                );
            }
            if !connected_peers.is_empty() {
                println!(
                    "      Peers:       {} connected ({})",
                    connected_peers.len(),
                    connected_peers.join(", ")
                );
            }
            if !plugin_statuses.is_empty() {
                let labels: Vec<String> = plugin_statuses
                    .iter()
                    .filter_map(|p| {
                        let id = p.get("id")?.as_str()?;
                        let kind = p.get("kind").and_then(Value::as_str).unwrap_or("bridge");
                        let status = p.get("status").and_then(Value::as_str).unwrap_or("unknown");
                        Some(format!("{id}[{kind}:{status}]"))
                    })
                    .collect();
                println!(
                    "      Plugins:     {} configured ({})",
                    plugin_statuses.len(),
                    labels.join(", ")
                );
            }
            for w in &warnings {
                println!("WARN  {w}");
            }
            let _ = std::io::stdout().flush();
        }

        wait_for_shutdown_signal().await;

        if let Some(tx) = headless_wake_shutdown {
            let _ = tx.send(true);
        }
        if let Some(handle) = headless_wake_task {
            handle.abort();
            let _ = handle.await;
        }

        plugin_runtime::stop_plugins(running_plugins).await;

        if let Some(ingest_srv) = local_ingest_server {
            ingest_srv.stop().await;
        }

        if let Some(daemon) = local_daemon {
            match Arc::try_unwrap(daemon) {
                Ok(d) => d.stop().await,
                Err(arc) => arc.shutdown(),
            }
        }
        node.shutdown_adapters().await;
        node.shutdown();
        if let Some(handle) = server_handle {
            handle.abort();
            let _ = handle.await;
        }
        #[cfg(unix)]
        if let Some(handle) = unix_server_handle {
            handle.abort();
            let _ = handle.await;
        }
        #[cfg(unix)]
        if let Some(ref ps) = bound_peer_socket {
            let _ = fs::remove_file(ps);
        }
        let _ = fs::remove_file(&pid_path);
        let _ = fs::remove_file(&status_path);

        if !as_json {
            eprintln!("OK    Hyphae v2 Node '{}' stopped cleanly", node.node_id().as_str());
        }
        Ok::<NodeStartOutcome, String>(NodeStartOutcome::Stopped)
    });

    match res {
        Ok(NodeStartOutcome::Stopped) => ExitCode::from(EXIT_OK),
        Ok(NodeStartOutcome::AlreadyRunning { socket }) => {
            let probe = daemon_rpc_sync(
                &socket,
                &json!({ "type": "daemon.status" }),
                ALREADY_RUNNING_PROBE_TIMEOUT,
            );
            emit_already_running(
                cmd,
                as_json,
                &socket,
                &state_dir_for_probe,
                probe.result.as_ref(),
            )
        }
        Err(e) => emit_error(cmd, as_json, EXIT_ERROR, "NODE_START_FAILED", e, None),
    }
}

struct NodeCmdPeersReloader {
    node: Arc<UnifiedNode>,
    status_doc: Arc<Mutex<Option<(PathBuf, Value)>>>,
}

impl PeersReloader for NodeCmdPeersReloader {
    fn reload_peers<'a>(&'a self) -> DaemonBoxFuture<'a, Result<PeerReconcileReport, String>> {
        Box::pin(async move {
            let report = self
                .node
                .reconcile_peers(DEFAULT_PEERS_RELOAD_TIMEOUT)
                .await;
            {
                let mut guard = self.status_doc.lock().expect("status_doc lock poisoned");
                if let Some((ref path, ref mut doc)) = *guard {
                    if let Some(obj) = doc.as_object_mut() {
                        obj.insert("connectedPeers".to_string(), json!(report.connected_peers));
                    }
                    let _ = write_atomic_json(path, doc, true);
                }
            }
            Ok(report)
        })
    }
}

/// Re-reads `node.json` (or legacy `connector.json`), opens a fresh `SecretStore`, validates all
/// Stage 1/Stage 2/filter rules, and verifies `gate_policy_sig` + `human_authorities_digest`
/// fail-closed for the live `gate.reload` IPC RPC.
fn reload_gate_pipeline_from_disk(
    config_path: &Path,
    has_explicit_config: bool,
    state_dir: &Path,
    explicit_state: bool,
    gate_db: Arc<Mutex<NodeDb>>,
) -> Result<Option<Arc<SecurityGatePipeline>>, String> {
    let target_path = if has_explicit_config {
        config_path.to_path_buf()
    } else {
        let v2 = state_dir.join("node.json");
        if v2.exists() {
            v2
        } else {
            config_path.to_path_buf()
        }
    };

    let gate_cfg: SecurityGateConfig = if target_path.exists() {
        let loaded = load_node_or_legacy_config(&target_path).map_err(|e| {
            format!(
                "Failed to reload gate config from {}: {e}",
                target_path.display()
            )
        })?;
        match loaded.raw.get("gate") {
            Some(gate_val) => serde_json::from_value(gate_val.clone()).map_err(|e| {
                format!(
                    "Invalid gate configuration in {}: {e}",
                    target_path.display()
                )
            })?,
            None => SecurityGateConfig::default(),
        }
    } else {
        SecurityGateConfig::default()
    };

    let gate_secrets = Arc::new(open_secret_store(state_dir, explicit_state));
    let pipeline = SecurityGatePipeline::new(gate_cfg, gate_db, Some(gate_secrets))
        .map_err(|e| format!("Failed to initialize SecurityGatePipeline: {e}"))?;
    pipeline
        .verify_policy_integrity()
        .map_err(|e| format!("gate_policy_tampered: {e}"))?;
    if pipeline.is_policy_tampered() {
        return Err("gate_policy_tampered: gate policy signature verification failed".to_string());
    }
    Ok(Some(Arc::new(pipeline)))
}

async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sigterm = signal(SignalKind::terminate()).ok();
        let mut sigint = signal(SignalKind::interrupt()).ok();
        match (sigterm.as_mut(), sigint.as_mut()) {
            (Some(t), Some(i)) => {
                tokio::select! {
                    _ = t.recv() => {}
                    _ = i.recv() => {}
                }
            }
            (Some(t), None) => {
                let _ = t.recv().await;
            }
            _ => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

fn parse_guest_pairing_config(
    gp_val: &Value,
    rate_limits_val: Option<&Value>,
) -> Result<GuestPairingConfig, String> {
    let obj = gp_val
        .as_object()
        .ok_or_else(|| "guestPairing must be a JSON object".to_string())?;
    let mut cfg = GuestPairingConfig::default();

    if let Some(enabled) = obj.get("enabled").and_then(Value::as_bool) {
        cfg.enabled = enabled;
    }
    if let Some(max_repos) = obj.get("maxReposPerGuest").and_then(Value::as_u64) {
        if max_repos == 0 {
            return Err("guestPairing.maxReposPerGuest must be > 0".to_string());
        }
        cfg.max_repos_per_guest = max_repos as usize;
    }
    if let Some(max_batches) = obj.get("maxBatchesPerHour").and_then(Value::as_u64) {
        if max_batches == 0 {
            return Err("guestPairing.maxBatchesPerHour must be > 0".to_string());
        }
        cfg.max_batches_per_hour = max_batches.min(u32::MAX as u64) as u32;
    }
    if let Some(max_joins) = obj
        .get("maxJoinsPerMinute")
        .and_then(Value::as_u64)
        .or_else(|| {
            rate_limits_val
                .and_then(|rl| rl.get("guestJoinRequestsPerMinute"))
                .and_then(Value::as_u64)
        })
    {
        cfg.max_joins_per_minute = max_joins.min(u32::MAX as u64) as u32;
    }
    if let Some(scopes_val) = obj.get("scopes") {
        let arr = scopes_val
            .as_array()
            .ok_or_else(|| "guestPairing.scopes must be an array of scope strings".to_string())?;
        let mut parsed = Vec::with_capacity(arr.len());
        for item in arr {
            let s = item
                .as_str()
                .ok_or_else(|| "guestPairing.scopes entries must be strings".to_string())?;
            parsed.push(s.to_string());
        }
        if !parsed.is_empty() {
            cfg.scopes = parsed;
        }
    } else {
        cfg.scopes = if cfg.max_repos_per_guest == 10 && cfg.max_batches_per_hour == 60 {
            ScopePreset::GuestRo.expand()
        } else {
            vec![format!(
                "stream:subscribe=github[require=exact.repo;maxValues={};maxBatchesPerHour={}]",
                cfg.max_repos_per_guest, cfg.max_batches_per_hour
            )]
        };
    }

    Ok(cfg)
}

fn parse_ed25519_jwk_str_or_b64(raw: &str, context: &str) -> Result<ProtoOkpJwk, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(format!("{context} cannot be empty"));
    }
    if trimmed.starts_with('{') {
        let val: Value =
            serde_json::from_str(trimmed).map_err(|e| format!("invalid JSON in {context}: {e}"))?;
        return parse_ed25519_jwk_object(&val, context);
    }
    if trimmed.len() != 43 {
        return Err(format!(
            "{context} string must be a 43-character unpadded base64url Ed25519 public key (got {} chars)",
            trimmed.len()
        ));
    }
    let crypto_jwk = CryptoOkpJwk {
        kty: "OKP".to_string(),
        crv: "Ed25519".to_string(),
        x: trimmed.to_string(),
    };
    crypto_jwk
        .to_ed25519()
        .map_err(|e| format!("invalid Ed25519 public key in {context}: {e}"))?;
    let proto_jwk = ProtoOkpJwk {
        kty: "OKP".to_string(),
        crv: ProtoOkpCurve::Ed25519,
        x: trimmed.to_string(),
    };
    proto_jwk
        .validate(Some(ProtoOkpCurve::Ed25519))
        .map_err(|e| format!("invalid Ed25519 public key in {context}: {e}"))?;
    Ok(proto_jwk)
}

fn parse_ed25519_jwk_object(val: &Value, context: &str) -> Result<ProtoOkpJwk, String> {
    let obj = val.as_object().ok_or_else(|| {
        format!("{context} must be an OKP Ed25519 JWK object or 43-char base64url string")
    })?;
    if obj.contains_key("d") {
        return Err(format!(
            "{context} must be a public OKP Ed25519 JWK (private key field 'd' is forbidden in node.json)"
        ));
    }
    let crypto_jwk: CryptoOkpJwk = serde_json::from_value(val.clone())
        .map_err(|e| format!("malformed OKP Ed25519 JWK in {context}: {e}"))?;
    if crypto_jwk.kty != "OKP" || crypto_jwk.crv != "Ed25519" {
        return Err(format!(
            "{context} must have kty=\"OKP\" and crv=\"Ed25519\", got kty={:?} crv={:?}",
            crypto_jwk.kty, crypto_jwk.crv
        ));
    }
    crypto_jwk
        .to_ed25519()
        .map_err(|e| format!("invalid Ed25519 public key in {context}: {e}"))?;
    let proto_jwk = ProtoOkpJwk {
        kty: "OKP".to_string(),
        crv: ProtoOkpCurve::Ed25519,
        x: crypto_jwk.x,
    };
    proto_jwk
        .validate(Some(ProtoOkpCurve::Ed25519))
        .map_err(|e| format!("invalid Ed25519 public key in {context}: {e}"))?;
    Ok(proto_jwk)
}

fn parse_pairing_admin_key(
    val: &Value,
    secrets: &hyp_crypto::SecretStore,
    warnings: &mut Vec<String>,
) -> Result<Option<ProtoOkpJwk>, String> {
    if val.is_null() {
        return Ok(None);
    }
    if let Some(s) = val.as_str() {
        return parse_ed25519_jwk_str_or_b64(s, "pairing.adminKey").map(Some);
    }
    if let Some(obj) = val.as_object() {
        if obj.len() == 1 && obj.contains_key("secret") {
            let secret_name = obj
                .get("secret")
                .and_then(Value::as_str)
                .ok_or_else(|| "pairing.adminKey.secret must be a string".to_string())?;
            validate_secret_name(secret_name).map_err(|e| {
                format!("invalid secret name '{secret_name}' in pairing.adminKey: {e}")
            })?;
            return match secrets.get(secret_name) {
                Ok(secret) => parse_ed25519_jwk_str_or_b64(
                    &secret,
                    &format!("pairing.adminKey (secret '{secret_name}')"),
                )
                .map(Some),
                Err(CryptoError::SecretNotFound(_)) => {
                    warnings.push(format!(
                        "Secret '{secret_name}' referenced by pairing.adminKey is not set; am2_ Admin-CA pairing disabled until `hyp secret set {secret_name}` is configured."
                    ));
                    Ok(None)
                }
                Err(e) => Err(format!(
                    "failed to load pairing.adminKey secret '{secret_name}': {e}"
                )),
            };
        }
        return parse_ed25519_jwk_object(val, "pairing.adminKey").map(Some);
    }
    Err("pairing.adminKey must be an OKP Ed25519 JWK object, a 43-char base64url public key string, or { \"secret\": \"<name>\" }".to_string())
}

fn parse_secret_ref_name(val: &Value, field_name: &str) -> Result<Option<String>, String> {
    if val.is_null() {
        return Ok(None);
    }
    if val.is_string() {
        return Err(format!(
            "'{field_name}' must use {{ \"secret\": \"<name>\" }} (plaintext credentials are forbidden in node.json)"
        ));
    }
    let obj = val
        .as_object()
        .ok_or_else(|| format!("'{field_name}' must be an object {{ \"secret\": \"<name>\" }}"))?;
    let name = obj
        .get("secret")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("'{field_name}' missing string 'secret' reference"))?;
    validate_secret_name(name)
        .map_err(|e| format!("invalid secret name '{name}' in '{field_name}': {e}"))?;
    Ok(Some(name.to_string()))
}

#[derive(Default)]
struct ParsedWebhookSources {
    github: Vec<GitHubWebhookConfig>,
    prometheus: Vec<PrometheusWebhookConfig>,
    generic: Vec<GenericWebhookConfig>,
}

/// Guest topic collision guard: refuses (with a clear startup warning + skip) wiring any webhook
/// adapter onto topic `"github"` when `guestPairing.enabled == true` or onto any topic already
/// owned by a `github-public` source.
fn filter_colliding_webhook_sources(
    parsed: &mut ParsedWebhookSources,
    guest_pairing_enabled: bool,
    github_public_topic: Option<&str>,
    warnings: &mut Vec<String>,
) {
    let collision_reason = |topic: &str| -> Option<&'static str> {
        if topic == "github" && guest_pairing_enabled {
            return Some("guestPairing is enabled on topic 'github'");
        }
        if let Some(gh_pub_topic) = github_public_topic {
            if topic == gh_pub_topic {
                return Some("a github-public source already owns this topic");
            }
        }
        None
    };

    parsed.github.retain(|cfg| {
        if let Some(reason) = collision_reason(&cfg.topic) {
            warnings.push(format!(
                "Skipping github-webhook source '{}' on topic '{}': {reason}; configure a distinct private topic.",
                cfg.id, cfg.topic
            ));
            false
        } else {
            true
        }
    });
    parsed.prometheus.retain(|cfg| {
        if let Some(reason) = collision_reason(&cfg.topic) {
            warnings.push(format!(
                "Skipping prometheus-webhook source '{}' on topic '{}': {reason}; configure a distinct private topic.",
                cfg.id, cfg.topic
            ));
            false
        } else {
            true
        }
    });
    parsed.generic.retain(|cfg| {
        if let Some(reason) = collision_reason(&cfg.topic) {
            warnings.push(format!(
                "Skipping webhook-stream source '{}' on topic '{}': {reason}; configure a distinct private topic.",
                cfg.id, cfg.topic
            ));
            false
        } else {
            true
        }
    });
}

fn parse_trusted_proxies_array(val: &Value, field: &str) -> Result<Vec<String>, String> {
    let arr = val
        .as_array()
        .ok_or_else(|| format!("{field} must be an array of IP/CIDR strings"))?;
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let s = item
            .as_str()
            .ok_or_else(|| format!("{field} entries must be IP/CIDR strings"))?
            .trim();
        let _ =
            validate_trusted_proxy_cidr(s).map_err(|e| format!("invalid entry in {field}: {e}"))?;
        out.push(s.to_string());
    }
    Ok(out)
}

fn parse_node_runtime_policies(raw: &Value, node_cfg: &mut NodeConfig) -> Result<(), String> {
    if let Some(fwd_val) = raw.get("forwarding") {
        if !fwd_val.is_null() {
            if fwd_val.get("maxHops").and_then(Value::as_u64) == Some(0) {
                return Err(
                    "invalid forwarding policy: forwarding.maxHops must be >= 1 (default 2, max 4)"
                        .to_string(),
                );
            }
            let fp: ForwardingPolicy = serde_json::from_value(fwd_val.clone())
                .map_err(|e| format!("invalid forwarding policy: {e}"))?;
            if fp.max_hops == 0 {
                return Err(
                    "invalid forwarding policy: forwarding.maxHops must be >= 1 (default 2, max 4)"
                        .to_string(),
                );
            }
            node_cfg.forwarding = fp;
        }
    }

    // H7: Prefer explicit `trustedProxies` CIDR list (top-level overrides `listen.trustedProxies`).
    // For backwards compatibility with existing configs that only set `behindReverseProxy: true`,
    // map strictly to loopback-only `["127.0.0.1/32", "::1/128"]` (NEVER trusting RFC1918/VPC peers).
    let listen_trusted = match raw.get("listen").and_then(|l| l.get("trustedProxies")) {
        Some(v) if !v.is_null() => Some(parse_trusted_proxies_array(v, "listen.trustedProxies")?),
        _ => None,
    };
    let top_trusted = match raw.get("trustedProxies") {
        Some(v) if !v.is_null() => Some(parse_trusted_proxies_array(v, "trustedProxies")?),
        _ => None,
    };

    if let Some(list) = top_trusted.or(listen_trusted) {
        node_cfg.trusted_proxies = list;
    } else {
        let listen_proxy = match raw.get("listen").and_then(|l| l.get("behindReverseProxy")) {
            Some(v) if !v.is_null() => Some(
                v.as_bool()
                    .ok_or_else(|| "listen.behindReverseProxy must be a boolean".to_string())?,
            ),
            _ => None,
        };
        let top_proxy = match raw.get("behindReverseProxy") {
            Some(v) if !v.is_null() => Some(
                v.as_bool()
                    .ok_or_else(|| "behindReverseProxy must be a boolean".to_string())?,
            ),
            _ => None,
        };
        if let Some(val) = top_proxy.or(listen_proxy) {
            node_cfg.trusted_proxies = if val {
                vec!["127.0.0.1/32".to_string(), "::1/128".to_string()]
            } else {
                Vec::new()
            };
        }
    }

    Ok(())
}

fn validate_webhook_source_id(id: &str, field: &str) -> Result<String, String> {
    let trimmed = id.trim();
    if trimmed.is_empty()
        || trimmed.len() > 64
        || trimmed.contains('/')
        || trimmed.contains('\\')
        || trimmed.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(format!("invalid {field} '{id}'"));
    }
    Ok(trimmed.to_string())
}

fn parse_optional_string_vec(
    obj: &serde_json::Map<String, Value>,
    key: &str,
    field: &str,
) -> Result<Vec<String>, String> {
    let Some(val) = obj.get(key) else {
        return Ok(Vec::new());
    };
    if val.is_null() {
        return Ok(Vec::new());
    }
    let arr = val
        .as_array()
        .ok_or_else(|| format!("{field} must be an array of strings"))?;
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let s = item
            .as_str()
            .ok_or_else(|| format!("{field} entries must be strings"))?
            .trim();
        if !s.is_empty() {
            out.push(s.to_string());
        }
    }
    Ok(out)
}

fn parse_webhook_sources(
    sources_val: &Value,
    secrets: &hyp_crypto::SecretStore,
) -> Result<ParsedWebhookSources, String> {
    let arr = sources_val
        .as_array()
        .ok_or_else(|| "sources must be a JSON array".to_string())?;

    let mut out = ParsedWebhookSources::default();
    let mut gh_ids: HashSet<String> = HashSet::new();
    let mut prom_ids: HashSet<String> = HashSet::new();
    let mut gen_ids: HashSet<String> = HashSet::new();

    for entry in arr {
        let Some(obj) = entry.as_object() else {
            continue;
        };
        if obj.get("enabled").and_then(Value::as_bool) == Some(false) {
            continue;
        }
        let Some(kind) = obj.get("kind").and_then(Value::as_str) else {
            continue;
        };

        match kind {
            "github-webhook" => {
                let raw_id = obj.get("id").and_then(Value::as_str).unwrap_or("github");
                let id = validate_webhook_source_id(raw_id, "sources[github-webhook].id")?;
                if !gh_ids.insert(id.clone()) {
                    return Err(format!("duplicate github-webhook source id '{id}'"));
                }
                let topic = obj
                    .get("topic")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .unwrap_or("github")
                    .to_string();
                if !is_valid_topic(&topic) {
                    return Err(format!(
                        "invalid topic '{topic}' in github-webhook source '{id}'"
                    ));
                }
                let secret_val = obj
                    .get("secret")
                    .or_else(|| obj.get("webhookSecret"))
                    .ok_or_else(|| {
                        format!(
                            "sources[github-webhook:'{id}'] requires 'secret': {{ \"secret\": \"<name>\" }}"
                        )
                    })?;
                let secret_name = parse_secret_ref_name(
                    secret_val,
                    &format!("sources[github-webhook:'{id}'].secret"),
                )?
                .ok_or_else(|| {
                    format!(
                        "sources[github-webhook:'{id}'] requires non-null 'secret': {{ \"secret\": \"<name>\" }}"
                    )
                })?;
                let secret = secrets.get(&secret_name).map_err(|e| {
                    format!("failed to load secret '{secret_name}' for github-webhook '{id}': {e}")
                })?;
                if secret.is_empty() {
                    return Err(format!(
                        "secret '{secret_name}' for github-webhook '{id}' must not be empty"
                    ));
                }
                let mut cfg = GitHubWebhookConfig::new(id.clone(), topic, secret.as_str());
                cfg.allowed_repos = parse_optional_string_vec(
                    obj,
                    "allowedRepos",
                    &format!("sources[github-webhook:'{id}'].allowedRepos"),
                )?;
                cfg.allowed_orgs = parse_optional_string_vec(
                    obj,
                    "allowedOrgs",
                    &format!("sources[github-webhook:'{id}'].allowedOrgs"),
                )?;
                if let Some(max_b) = obj.get("maxBodyBytes").and_then(Value::as_u64) {
                    if max_b == 0 {
                        return Err(format!(
                            "sources[github-webhook:'{id}'].maxBodyBytes must be >= 1"
                        ));
                    }
                    cfg.max_body_bytes = usize::try_from(max_b).unwrap_or(usize::MAX);
                }
                out.github.push(cfg);
            }
            "prometheus-webhook" => {
                let raw_id = obj
                    .get("id")
                    .and_then(Value::as_str)
                    .unwrap_or("prometheus");
                let id = validate_webhook_source_id(raw_id, "sources[prometheus-webhook].id")?;
                if !prom_ids.insert(id.clone()) {
                    return Err(format!("duplicate prometheus-webhook source id '{id}'"));
                }
                let topic = obj
                    .get("topic")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .unwrap_or("alerts")
                    .to_string();
                if !is_valid_topic(&topic) {
                    return Err(format!(
                        "invalid topic '{topic}' in prometheus-webhook source '{id}'"
                    ));
                }
                let mut cfg = PrometheusWebhookConfig::new(id.clone(), topic);

                if let Some(tok_val) = obj.get("bearerToken").or_else(|| obj.get("token")) {
                    if let Some(secret_name) = parse_secret_ref_name(
                        tok_val,
                        &format!("sources[prometheus-webhook:'{id}'].bearerToken"),
                    )? {
                        let val = secrets.get(&secret_name).map_err(|e| {
                            format!(
                                "failed to load bearerToken secret '{secret_name}' for prometheus-webhook '{id}': {e}"
                            )
                        })?;
                        if val.is_empty() {
                            return Err(format!(
                                "bearerToken secret '{secret_name}' for prometheus-webhook '{id}' must not be empty"
                            ));
                        }
                        cfg.bearer_token = Some(val);
                    }
                }

                if let Some(sec_val) = obj.get("secret").or_else(|| obj.get("webhookSecret")) {
                    if let Some(secret_name) = parse_secret_ref_name(
                        sec_val,
                        &format!("sources[prometheus-webhook:'{id}'].webhookSecret"),
                    )? {
                        let val = secrets.get(&secret_name).map_err(|e| {
                            format!(
                                "failed to load webhookSecret '{secret_name}' for prometheus-webhook '{id}': {e}"
                            )
                        })?;
                        if val.is_empty() {
                            return Err(format!(
                                "webhookSecret '{secret_name}' for prometheus-webhook '{id}' must not be empty"
                            ));
                        }
                        cfg.webhook_secret = Some(val);
                    }
                }

                if let Some(basic_val) = obj.get("basicAuth") {
                    if !basic_val.is_null() {
                        let b_obj = basic_val.as_object().ok_or_else(|| {
                            format!(
                                "sources[prometheus-webhook:'{id}'].basicAuth must be an object with 'username' and 'password': {{ \"secret\": \"<name>\" }}"
                            )
                        })?;
                        let username = b_obj
                            .get("username")
                            .or_else(|| b_obj.get("user"))
                            .and_then(Value::as_str)
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                            .ok_or_else(|| {
                                format!(
                                    "sources[prometheus-webhook:'{id}'].basicAuth requires non-empty 'username'"
                                )
                            })?;
                        let pass_val = b_obj
                            .get("password")
                            .or_else(|| b_obj.get("pass"))
                            .ok_or_else(|| {
                                format!(
                                    "sources[prometheus-webhook:'{id}'].basicAuth requires 'password': {{ \"secret\": \"<name>\" }}"
                                )
                            })?;
                        let pass_name = parse_secret_ref_name(
                            pass_val,
                            &format!("sources[prometheus-webhook:'{id}'].basicAuth.password"),
                        )?
                        .ok_or_else(|| {
                            format!(
                                "sources[prometheus-webhook:'{id}'].basicAuth.password must be {{ \"secret\": \"<name>\" }}"
                            )
                        })?;
                        let pass = secrets.get(&pass_name).map_err(|e| {
                            format!(
                                "failed to load basicAuth password secret '{pass_name}' for prometheus-webhook '{id}': {e}"
                            )
                        })?;
                        if pass.is_empty() {
                            return Err(format!(
                                "basicAuth password secret '{pass_name}' for prometheus-webhook '{id}' must not be empty"
                            ));
                        }
                        cfg.basic_auth = Some((username.to_string(), pass));
                    }
                }

                if !cfg.has_auth_configured() {
                    return Err(format!(
                        "sources[prometheus-webhook:'{id}'] requires bearerToken, basicAuth, or webhookSecret via {{ \"secret\": \"<name>\" }}"
                    ));
                }

                if let Some(max_b) = obj.get("maxBodyBytes").and_then(Value::as_u64) {
                    if max_b == 0 {
                        return Err(format!(
                            "sources[prometheus-webhook:'{id}'].maxBodyBytes must be >= 1"
                        ));
                    }
                    cfg.max_body_bytes = usize::try_from(max_b).unwrap_or(usize::MAX);
                }
                out.prometheus.push(cfg);
            }
            "webhook-stream" => {
                let fallback_id = obj
                    .get("topic")
                    .and_then(Value::as_str)
                    .unwrap_or("webhook");
                let raw_id = obj.get("id").and_then(Value::as_str).unwrap_or(fallback_id);
                let id = validate_webhook_source_id(raw_id, "sources[webhook-stream].id")?;
                if !gen_ids.insert(id.clone()) {
                    return Err(format!("duplicate webhook-stream source id '{id}'"));
                }
                let topic = obj
                    .get("topic")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .unwrap_or(id.as_str())
                    .to_string();
                if !is_valid_topic(&topic) {
                    return Err(format!(
                        "invalid topic '{topic}' in webhook-stream source '{id}'"
                    ));
                }
                let secret_val = obj
                    .get("secret")
                    .or_else(|| obj.get("webhookSecret"))
                    .ok_or_else(|| {
                        format!(
                            "sources[webhook-stream:'{id}'] requires 'secret': {{ \"secret\": \"<name>\" }}"
                        )
                    })?;
                let secret_name = parse_secret_ref_name(
                    secret_val,
                    &format!("sources[webhook-stream:'{id}'].secret"),
                )?
                .ok_or_else(|| {
                    format!(
                        "sources[webhook-stream:'{id}'] requires non-null 'secret': {{ \"secret\": \"<name>\" }}"
                    )
                })?;
                let secret = secrets.get(&secret_name).map_err(|e| {
                    format!("failed to load secret '{secret_name}' for webhook-stream '{id}': {e}")
                })?;
                if secret.is_empty() {
                    return Err(format!(
                        "secret '{secret_name}' for webhook-stream '{id}' must not be empty"
                    ));
                }
                let mut cfg = GenericWebhookConfig::new(id.clone(), topic);
                cfg.secret = Some(secret);
                if let Some(hdr) = obj
                    .get("signatureHeader")
                    .or_else(|| obj.get("header"))
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                {
                    cfg.signature_header = hdr.to_ascii_lowercase();
                }
                if let Some(src) = obj
                    .get("defaultSource")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                {
                    cfg.default_source = src.to_string();
                }
                if let Some(ty) = obj
                    .get("defaultType")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                {
                    cfg.default_type = ty.to_string();
                }
                if let Some(max_b) = obj.get("maxBodyBytes").and_then(Value::as_u64) {
                    if max_b == 0 {
                        return Err(format!(
                            "sources[webhook-stream:'{id}'].maxBodyBytes must be >= 1"
                        ));
                    }
                    cfg.max_body_bytes = usize::try_from(max_b).unwrap_or(usize::MAX);
                }
                out.generic.push(cfg);
            }
            _ => {}
        }
    }

    Ok(out)
}

fn parse_github_public_source(
    sources_val: &Value,
    secrets: &hyp_crypto::SecretStore,
    public_read_only: bool,
    warnings: &mut Vec<String>,
) -> Result<Option<GitHubPublicConfig>, String> {
    let arr = sources_val
        .as_array()
        .ok_or_else(|| "sources must be a JSON array".to_string())?;

    let mut active_cfg: Option<GitHubPublicConfig> = None;
    let mut extra_enabled = 0usize;

    for entry in arr {
        let Some(obj) = entry.as_object() else {
            continue;
        };
        if obj.get("kind").and_then(Value::as_str) != Some("github-public") {
            continue;
        }
        if obj.get("enabled").and_then(Value::as_bool) == Some(false) {
            continue;
        }

        if active_cfg.is_some() {
            extra_enabled += 1;
            continue;
        }

        let mut cfg = GitHubPublicConfig::default();
        if let Some(id) = obj.get("id").and_then(Value::as_str) {
            if !id.trim().is_empty() {
                cfg.id = id.trim().to_string();
            }
        }
        if let Some(topic) = obj.get("topic").and_then(Value::as_str) {
            if !topic.trim().is_empty() {
                cfg.topic = topic.trim().to_string();
            }
        }
        if let Some(api_base) = obj.get("apiBaseUrl").and_then(Value::as_str) {
            if !api_base.trim().is_empty() {
                cfg.api_base_url = api_base.trim().to_string();
            }
        }
        if let Some(min_poll) = obj.get("minPollIntervalSeconds").and_then(Value::as_u64) {
            let dur = Duration::from_secs(min_poll);
            cfg.min_poll_interval = dur;
            if cfg.base_poll_interval > dur {
                cfg.base_poll_interval = dur;
            }
        }
        if let Some(base_poll) = obj.get("basePollIntervalSeconds").and_then(Value::as_u64) {
            cfg.base_poll_interval = Duration::from_secs(base_poll);
        }
        if let Some(grace) = obj.get("graceWindowSeconds").and_then(Value::as_u64) {
            cfg.teardown_grace = Duration::from_secs(grace);
        }
        if let Some(max_pollers_val) = obj.get("maxActivePollers") {
            if !max_pollers_val.is_null() {
                let Some(n) = max_pollers_val.as_u64() else {
                    return Err("sources[].maxActivePollers must be a positive integer".to_string());
                };
                if n == 0 {
                    return Err("sources[].maxActivePollers must be >= 1".to_string());
                }
                cfg.max_active_pollers = usize::try_from(n).unwrap_or(usize::MAX);
            }
        }
        if !public_read_only {
            if let Some(allow_priv) = obj.get("allowPrivateWithToken").and_then(Value::as_bool) {
                cfg.allow_private_with_token = allow_priv;
            }
        }

        if let Some(tok_val) = obj.get("githubToken") {
            if let Some(secret_name) = parse_secret_ref_name(tok_val, "sources[].githubToken")? {
                match secrets.get(&secret_name) {
                    Ok(secret) => cfg.github_token = Some(secret),
                    Err(CryptoError::SecretNotFound(_)) => {
                        warnings.push(format!(
                            "Secret '{secret_name}' is not set; starting github-public in unauthenticated public GitHub mode (60 req/hr). Run `hyp secret set {secret_name}` for 5,000 req/hr."
                        ));
                    }
                    Err(e) => {
                        return Err(format!(
                            "failed to load GitHub token secret '{secret_name}': {e}"
                        ));
                    }
                }
            }
        }

        if let Some(repo_tokens_val) = obj.get("repoTokens") {
            if !repo_tokens_val.is_null() {
                let repo_tokens_obj = repo_tokens_val.as_object().ok_or_else(|| {
                    "sources[].repoTokens must be a JSON object mapping \"owner/*\" or \"owner/repo\" to { \"secret\": \"<name>\" }".to_string()
                })?;
                let mut seen_patterns: HashSet<String> = HashSet::new();
                for (raw_pattern, secret_val) in repo_tokens_obj {
                    let canonical = normalize_repo_token_pattern(raw_pattern).map_err(|e| {
                        format!("invalid sources[].repoTokens pattern '{raw_pattern}': {e}")
                    })?;
                    if !seen_patterns.insert(canonical.clone()) {
                        return Err(format!(
                            "duplicate normalized sources[].repoTokens pattern '{canonical}' (from '{raw_pattern}')"
                        ));
                    }
                    let field_label = format!("sources[].repoTokens['{raw_pattern}']");
                    if let Some(secret_name) = parse_secret_ref_name(secret_val, &field_label)? {
                        match secrets.get(&secret_name) {
                            Ok(secret) => {
                                cfg.repo_tokens.insert(canonical, secret);
                            }
                            Err(CryptoError::SecretNotFound(_)) => {
                                warnings.push(format!(
                                    "Secret '{secret_name}' for github-public repoTokens['{canonical}'] is not set; repos matching '{canonical}' will fall back to default/unauthenticated mode until `hyp secret set {secret_name} --web` is configured."
                                ));
                            }
                            Err(e) => {
                                return Err(format!(
                                    "failed to load GitHub token secret '{secret_name}' for {field_label}: {e}"
                                ));
                            }
                        }
                    }
                }
            }
        }

        if let Some(app_sec_val) = obj.get("appWebhookSecret") {
            if let Some(secret_name) =
                parse_secret_ref_name(app_sec_val, "sources[].appWebhookSecret")?
            {
                match secrets.get(&secret_name) {
                    Ok(secret) => cfg.app_webhook_secret = Some(secret),
                    Err(CryptoError::SecretNotFound(_)) => {
                        warnings.push(format!(
                            "Secret '{secret_name}' is not set; POST /v1/webhooks/github-app disabled until `hyp secret set {secret_name}` is configured."
                        ));
                    }
                    Err(e) => {
                        return Err(format!(
                            "failed to load GitHub App webhook secret '{secret_name}': {e}"
                        ));
                    }
                }
            }
        }

        active_cfg = Some(cfg);
    }

    if extra_enabled > 0 {
        warnings.push(
            "Multiple enabled github-public sources found; only the first is active. Consolidate multiple GitHub tokens into sources[0].repoTokens (e.g. { \"owner/*\": { \"secret\": \"...\" } })."
                .to_string(),
        );
    }

    Ok(active_cfg)
}

fn parse_delivery_retry_fields(
    obj: &serde_json::Map<String, Value>,
    cfg: &mut DeliveryRetryConfig,
) -> Result<(), String> {
    if let Some(arr) = obj
        .get("holdRetryBackoffMs")
        .or_else(|| obj.get("hold_retry_backoff_ms"))
        .and_then(Value::as_array)
    {
        let mut backoff = Vec::with_capacity(arr.len());
        for item in arr {
            let ms = item.as_u64().ok_or_else(|| {
                "deliveryRetry.holdRetryBackoffMs entries must be non-negative integers".to_string()
            })?;
            backoff.push(ms);
        }
        if !backoff.is_empty() {
            cfg.hold_retry_backoff_ms = backoff;
        }
    }
    if let Some(max_att) = obj
        .get("holdRetryMaxAttempts")
        .or_else(|| obj.get("hold_retry_max_attempts"))
        .and_then(Value::as_u64)
    {
        cfg.hold_retry_max_attempts = max_att.min(u32::MAX as u64) as u32;
    }
    if let Some(resume) = obj
        .get("codexResume")
        .or_else(|| obj.get("codex_resume"))
        .and_then(Value::as_bool)
    {
        cfg.codex_resume = resume;
    }
    if let Some(arr) = obj
        .get("herdrSpawnAllowlist")
        .or_else(|| obj.get("herdr_spawn_allowlist"))
        .and_then(Value::as_array)
    {
        let mut allow = Vec::with_capacity(arr.len());
        for item in arr {
            let s = item.as_str().ok_or_else(|| {
                "deliveryRetry.herdrSpawnAllowlist entries must be strings".to_string()
            })?;
            allow.push(s.to_string());
        }
        cfg.herdr_spawn_allowlist = allow;
    }
    Ok(())
}

fn parse_delivery_retry_config(raw: &Value) -> Result<DeliveryRetryConfig, String> {
    let mut cfg = DeliveryRetryConfig::default();
    let Some(root) = raw.as_object() else {
        return Ok(cfg);
    };

    // Legacy fallback: honor retry/revival fields from older `sources[kind="wakeup"]` entries.
    if let Some(sources) = root.get("sources").and_then(Value::as_array) {
        for entry in sources {
            if let Some(obj) = entry.as_object() {
                if obj.get("kind").and_then(Value::as_str) == Some("wakeup") {
                    parse_delivery_retry_fields(obj, &mut cfg)?;
                }
            }
        }
    }

    // Legacy fallback: top-level `codexResume` / `herdrSpawnAllowlist` / retry keys.
    parse_delivery_retry_fields(root, &mut cfg)?;

    // Primary v0.5.0 `deliveryRetry` object takes precedence.
    if let Some(dr_val) = root.get("deliveryRetry") {
        let obj = dr_val
            .as_object()
            .ok_or_else(|| "deliveryRetry must be a JSON object".to_string())?;
        parse_delivery_retry_fields(obj, &mut cfg)?;
    }

    Ok(cfg)
}

fn parse_wake_recovery_config(raw: &Value) -> Result<WakeRecoveryConfig, String> {
    let mut cfg = WakeRecoveryConfig::default();
    let Some(wr_val) = raw.as_object().and_then(|o| o.get("wakeRecovery")) else {
        return Ok(cfg);
    };
    let obj = wr_val
        .as_object()
        .ok_or_else(|| "wakeRecovery must be a JSON object".to_string())?;
    if let Some(raw_enabled) = obj.get("enabled") {
        cfg.enabled = raw_enabled
            .as_bool()
            .ok_or_else(|| "wakeRecovery.enabled must be a boolean".to_string())?;
    }
    if let Some(raw_secs) = obj
        .get("minSleepSeconds")
        .or_else(|| obj.get("min_sleep_seconds"))
    {
        let secs = raw_secs
            .as_u64()
            .filter(|&v| v >= 1)
            .ok_or_else(|| "wakeRecovery.minSleepSeconds must be an integer >= 1".to_string())?;
        cfg.min_sleep_seconds = secs;
    }
    if let Some(raw_active) = obj
        .get("notifyInterruptedActive")
        .or_else(|| obj.get("notify_interrupted_active"))
    {
        cfg.notify_interrupted_active = raw_active
            .as_bool()
            .ok_or_else(|| "wakeRecovery.notifyInterruptedActive must be a boolean".to_string())?;
    }
    if let Some(raw_all) = obj
        .get("notifyAllEnrolled")
        .or_else(|| obj.get("notify_all_enrolled"))
    {
        cfg.notify_all_enrolled = raw_all
            .as_bool()
            .ok_or_else(|| "wakeRecovery.notifyAllEnrolled must be a boolean".to_string())?;
    }
    Ok(cfg)
}

const fn plugin_kind_str(kind: AdapterKind) -> &'static str {
    match kind {
        AdapterKind::Bridge => "bridge",
        AdapterKind::Source => "source",
        AdapterKind::Harness => "harness",
        AdapterKind::PeerLink => "peer_link",
    }
}

struct ParsedPlugin {
    config: SubprocessConfig,
    expose_topic: bool,
    has_webhook_post_url: bool,
}

fn parse_explicit_topic_names(topics_val: Option<&Value>) -> HashSet<String> {
    let mut out = HashSet::new();
    let Some(arr) = topics_val.and_then(Value::as_array) else {
        return out;
    };
    for item in arr {
        if let Some(s) = item.as_str() {
            let trimmed = s.trim().to_ascii_lowercase();
            if !trimmed.is_empty() {
                out.insert(trimmed);
            }
        } else if let Some(s) = item
            .as_object()
            .and_then(|o| o.get("topic"))
            .and_then(Value::as_str)
        {
            let trimmed = s.trim().to_ascii_lowercase();
            if !trimmed.is_empty() {
                out.insert(trimmed);
            }
        }
    }
    out
}

/// Official event-source plugins whose `plugins[]` entry defaults to `kind: "source"` (1-to-many
/// `hyp_stream` topic) when `kind` is omitted. An explicit `kind` always wins.
const OFFICIAL_SOURCE_PLUGIN_IDS: &[&str] = &[
    "agentmail",
    "sentry",
    "gmail",
    "google-calendar",
    "vercel",
    "notion",
];

fn push_plugin_error(
    id: &str,
    kind: Option<AdapterKind>,
    targets: Option<&[String]>,
    reason: String,
    warnings: &mut Vec<String>,
    skipped_statuses: &mut Vec<Value>,
) {
    warnings.push(format!(
        "Skipping misconfigured plugin '{id}' (daemon continuing): {reason}"
    ));
    let mut entry = serde_json::Map::new();
    entry.insert("id".to_string(), json!(id));
    if let Some(k) = kind {
        entry.insert("kind".to_string(), json!(plugin_kind_str(k)));
    }
    if let Some(t) = targets {
        entry.insert("targets".to_string(), json!(t));
    }
    entry.insert("status".to_string(), json!("error"));
    entry.insert("error".to_string(), json!(reason));
    entry.insert("lastError".to_string(), json!(reason));
    skipped_statuses.push(Value::Object(entry));
}

/// Parses and validates `plugins[]` from `node.json`, accepting both `"exec"` and `"command"`,
/// resolving `{ "secret": "<name>" }` references via `SecretStore`, warning on plaintext
/// secret-like env values, and isolating individual malformed/misconfigured plugin entries into
/// startup warnings + error/skipped statuses so a single bad plugin never aborts `hyp node start`.
fn parse_plugins_config(
    plugins_val: &Value,
    config_dir: Option<&Path>,
    state_dir: &Path,
    explicit_topics: &HashSet<String>,
    secrets: &hyp_crypto::SecretStore,
    warnings: &mut Vec<String>,
    skipped_statuses: &mut Vec<Value>,
) -> Vec<ParsedPlugin> {
    let Some(arr) = plugins_val.as_array() else {
        let reason = "plugins must be a JSON array".to_string();
        warnings.push(format!(
            "Skipping 'plugins' configuration (daemon continuing): {reason}"
        ));
        skipped_statuses.push(json!({
            "id": "plugins",
            "status": "error",
            "error": reason,
            "lastError": reason,
        }));
        return Vec::new();
    };

    let mut seen_ids: HashSet<String> = HashSet::new();
    let mut configs: Vec<ParsedPlugin> = Vec::new();

    for (idx, entry) in arr.iter().enumerate() {
        let fallback_id = format!("plugins[{idx}]");
        let Some(obj) = entry.as_object() else {
            push_plugin_error(
                &fallback_id,
                None,
                None,
                format!("plugins[{idx}] must be a JSON object"),
                warnings,
                skipped_statuses,
            );
            continue;
        };

        if obj.get("enabled").and_then(Value::as_bool) == Some(false) {
            continue;
        }

        let Some(raw_id) = obj
            .get("id")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
        else {
            push_plugin_error(
                &fallback_id,
                None,
                None,
                format!("plugins[{idx}].id must be a non-empty string"),
                warnings,
                skipped_statuses,
            );
            continue;
        };
        let id = raw_id.to_ascii_lowercase();
        if !is_valid_handle(&id) {
            push_plugin_error(
                raw_id,
                None,
                None,
                format!(
                    "plugins[{idx}].id '{raw_id}' is not a valid identifier (expected /^[a-z0-9][a-z0-9._-]{{0,63}}$/)"
                ),
                warnings,
                skipped_statuses,
            );
            continue;
        }
        if !seen_ids.insert(id.clone()) {
            push_plugin_error(
                &id,
                None,
                None,
                format!("duplicate plugin id '{id}' in plugins[]"),
                warnings,
                skipped_statuses,
            );
            continue;
        }

        let explicit_kind = match obj.get("kind") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) if s == "bridge" => Some(AdapterKind::Bridge),
            Some(Value::String(s)) if s == "source" => Some(AdapterKind::Source),
            Some(other) => {
                push_plugin_error(
                    &id,
                    None,
                    None,
                    format!(
                        "plugins[{id}].kind {other} is invalid (expected 'bridge' or 'source')"
                    ),
                    warnings,
                    skipped_statuses,
                );
                continue;
            }
        };

        let exec_opt = match obj.get("exec") {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(s)) if !s.trim().is_empty() => Ok(Some(s.trim().to_string())),
            Some(_) => Err(format!("plugins[{id}].exec must be a non-empty string")),
        };
        let command_opt = match obj.get("command") {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(s)) if !s.trim().is_empty() => Ok(Some(s.trim().to_string())),
            Some(_) => Err(format!("plugins[{id}].command must be a non-empty string")),
        };
        let exec = match (exec_opt, command_opt) {
            (Ok(Some(e)), Ok(Some(c))) => {
                if e != c {
                    warnings.push(format!(
                        "plugins[{id}] defines both 'exec' and 'command' with different values; preferring 'exec'."
                    ));
                }
                e
            }
            (Ok(Some(e)), Ok(None)) => e,
            (Ok(None), Ok(Some(c))) => c,
            (Err(e), _) | (_, Err(e)) => {
                push_plugin_error(&id, explicit_kind, None, e, warnings, skipped_statuses);
                continue;
            }
            (Ok(None), Ok(None)) => {
                push_plugin_error(
                    &id,
                    explicit_kind,
                    None,
                    format!("plugins[{id}] must specify a non-empty 'exec' or 'command' string"),
                    warnings,
                    skipped_statuses,
                );
                continue;
            }
        };

        let args = match obj.get("args") {
            None | Some(Value::Null) => Ok(Vec::new()),
            Some(val) => match val.as_array() {
                Some(raw_args) => {
                    let mut out = Vec::with_capacity(raw_args.len());
                    let mut err = None;
                    for (aidx, item) in raw_args.iter().enumerate() {
                        if let Some(s) = item.as_str() {
                            out.push(s.to_string());
                        } else {
                            err = Some(format!("plugins[{id}].args[{aidx}] must be a string"));
                            break;
                        }
                    }
                    match err {
                        Some(e) => Err(e),
                        None => Ok(out),
                    }
                }
                None => Err(format!("plugins[{id}].args must be an array of strings")),
            },
        };
        let args = match args {
            Ok(v) => v,
            Err(e) => {
                push_plugin_error(&id, explicit_kind, None, e, warnings, skipped_statuses);
                continue;
            }
        };

        let cwd = match obj.get("cwd") {
            None | Some(Value::Null) => Ok(None),
            Some(val) => match val.as_str().map(str::trim).filter(|s| !s.is_empty()) {
                Some(raw_cwd) => {
                    let path = PathBuf::from(raw_cwd);
                    if path.is_absolute() {
                        Ok(Some(path))
                    } else if let Some(base) = config_dir {
                        Ok(Some(base.join(path)))
                    } else {
                        Ok(Some(path))
                    }
                }
                None => Err(format!("plugins[{id}].cwd must be a non-empty string")),
            },
        };
        let cwd = match cwd {
            Ok(v) => v,
            Err(e) => {
                push_plugin_error(&id, explicit_kind, None, e, warnings, skipped_statuses);
                continue;
            }
        };

        let explicit_targets_res = match obj.get("targets") {
            None | Some(Value::Null) => {
                if id == "telegram" {
                    Ok(None)
                } else {
                    Err(format!(
                        "plugins[{id}].targets must be a non-empty array of strings"
                    ))
                }
            }
            Some(val) => match val.as_array() {
                Some(raw_targets) => {
                    let mut out = Vec::with_capacity(raw_targets.len());
                    let mut err = None;
                    for (tidx, item) in raw_targets.iter().enumerate() {
                        if let Some(s) = item.as_str().map(str::trim).filter(|t| !t.is_empty()) {
                            if !out.iter().any(|existing: &String| existing == s) {
                                out.push(s.to_string());
                            }
                        } else {
                            err = Some(format!(
                                "plugins[{id}].targets[{tidx}] must be a non-empty string"
                            ));
                            break;
                        }
                    }
                    match err {
                        Some(e) => Err(e),
                        None if out.is_empty() => {
                            if id == "telegram" {
                                Ok(None)
                            } else {
                                Err(format!(
                                    "plugins[{id}].targets must contain at least one target"
                                ))
                            }
                        }
                        None => Ok(Some(out)),
                    }
                }
                None => Err(format!(
                    "plugins[{id}].targets must be a non-empty array of strings"
                )),
            },
        };
        let explicit_targets = match explicit_targets_res {
            Ok(v) => v,
            Err(e) => {
                push_plugin_error(&id, explicit_kind, None, e, warnings, skipped_statuses);
                continue;
            }
        };

        let mut env_map: BTreeMap<String, String> = BTreeMap::new();
        let mut secret_env_refs: Vec<(String, String)> = Vec::new();
        let mut redacted_values: Vec<String> = Vec::new();
        let mut secret_skip_reason: Option<String> = None;
        let mut config_error_reason: Option<String> = None;
        let mut plaintext_warnings: Vec<String> = Vec::new();

        if let Some(env_val) = obj.get("env") {
            if !env_val.is_null() {
                match env_val.as_object() {
                    None => {
                        config_error_reason =
                            Some(format!("plugins[{id}].env must be a JSON object"));
                    }
                    Some(env_obj) => {
                        for (env_key, val) in env_obj {
                            if env_key.trim().is_empty() {
                                config_error_reason = Some(format!(
                                    "plugins[{id}].env contains an empty variable name"
                                ));
                                break;
                            }
                            match val {
                                Value::String(s) => {
                                    if !s.trim().is_empty() && is_secret_like_env_key(env_key) {
                                        plaintext_warnings.push(format!(
                                            "plugins[{id}].env.{env_key} uses a plaintext secret value in node.json; store it with `hyp secret set <name>` and reference {{ \"secret\": \"<name>\" }} instead."
                                        ));
                                        redacted_values.push(s.clone());
                                    }
                                    env_map.insert(env_key.clone(), s.clone());
                                }
                                Value::Object(ref_obj) => {
                                    let Some(secret_name) = ref_obj
                                        .get("secret")
                                        .and_then(Value::as_str)
                                        .filter(|_| ref_obj.len() == 1)
                                    else {
                                        config_error_reason = Some(format!(
                                            "plugins[{id}].env.{env_key} must be a string or {{ \"secret\": \"<name>\" }}"
                                        ));
                                        break;
                                    };
                                    if let Err(e) = validate_secret_name(secret_name) {
                                        config_error_reason = Some(format!(
                                            "invalid secret name '{secret_name}' in plugins[{id}].env.{env_key}: {e}"
                                        ));
                                        break;
                                    }
                                    match secrets.get(secret_name) {
                                        Ok(secret) => {
                                            redacted_values.push((*secret).clone());
                                            env_map.insert(env_key.clone(), (*secret).clone());
                                            secret_env_refs
                                                .push((env_key.clone(), secret_name.to_string()));
                                        }
                                        Err(CryptoError::SecretNotFound(_)) => {
                                            secret_skip_reason = Some(format!(
                                                "plugins[{id}].env.{env_key} references missing secret '{secret_name}'; run `hyp secret set {secret_name}`"
                                            ));
                                            break;
                                        }
                                        Err(e) => {
                                            secret_skip_reason = Some(format!(
                                                "failed to load secret '{secret_name}' for plugins[{id}].env.{env_key}: {e}"
                                            ));
                                            break;
                                        }
                                    }
                                }
                                _ => {
                                    config_error_reason = Some(format!(
                                        "plugins[{id}].env.{env_key} must be a string or {{ \"secret\": \"<name>\" }}"
                                    ));
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }

        let has_webhook_post_url = env_map
            .get("WEBHOOK_POST_URL")
            .is_some_and(|v| !v.trim().is_empty());
        let kind = match explicit_kind {
            Some(k) => k,
            None => {
                if id == "prometheus"
                    || OFFICIAL_SOURCE_PLUGIN_IDS.contains(&id.as_str())
                    || (id == "webhook" && !has_webhook_post_url)
                {
                    AdapterKind::Source
                } else {
                    AdapterKind::Bridge
                }
            }
        };

        let status_targets_fallback = [crate::plugin_cmd::DEFAULT_TELEGRAM_TARGET.to_string()];
        let status_targets_slice = explicit_targets
            .as_deref()
            .unwrap_or(&status_targets_fallback);

        if let Some(reason) = config_error_reason {
            push_plugin_error(
                &id,
                Some(kind),
                Some(status_targets_slice),
                reason,
                warnings,
                skipped_statuses,
            );
            continue;
        }

        if let Some(reason) = secret_skip_reason {
            warnings.push(format!(
                "Skipping plugin '{id}' (daemon continuing): {reason}"
            ));
            skipped_statuses.push(json!({
                "id": id,
                "kind": plugin_kind_str(kind),
                "targets": status_targets_slice,
                "status": "skipped",
                "error": reason,
                "lastError": reason,
            }));
            continue;
        }

        let targets = match explicit_targets {
            Some(explicit) => explicit,
            None => {
                // Only `id == "telegram"` reaches here when `targets` is omitted/empty:
                // resolve bot username via Telegram `getMe` with fail-safe fallback to `"personal"`.
                let resolved = match env_map.get("TELEGRAM_BOT_TOKEN").map(String::as_str) {
                    Some(token) if !token.trim().is_empty() => {
                        let api_base = env_map
                            .get("TELEGRAM_API_BASE")
                            .map(String::as_str)
                            .map(str::trim)
                            .filter(|s| !s.is_empty());
                        crate::plugin_cmd::resolve_telegram_default_target_with_token(
                            token, api_base,
                        )
                    }
                    _ => crate::plugin_cmd::TelegramTargetResolution {
                        target: crate::plugin_cmd::DEFAULT_TELEGRAM_TARGET.to_string(),
                        source: "fallback",
                        warning: None,
                    },
                };
                if let Some(w) = resolved.warning {
                    warnings.push(w);
                }
                vec![resolved.target]
            }
        };

        warnings.extend(plaintext_warnings);

        // Issue #25 (B6): Default `exposeTopic` strictly to `false` for BOTH `bridge` and `source`
        // subprocess plugins unless the user explicitly opts in via `"exposeTopic": true`
        // (or lists a bridge's topic in top-level `topics[]`).
        let explicit_expose = match obj.get("exposeTopic") {
            None | Some(Value::Null) => None,
            Some(Value::Bool(b)) => Some(*b),
            Some(_) => {
                warnings.push(format!(
                    "plugins[{id}].exposeTopic must be a boolean; defaulting to local-only (false)."
                ));
                Some(false)
            }
        };
        let expose_topic = match explicit_expose {
            Some(explicit) => explicit,
            None => match kind {
                AdapterKind::Bridge => explicit_topics.contains(&id),
                AdapterKind::Source => false,
                _ => false,
            },
        };

        let mut cfg = SubprocessConfig::new(id.clone(), kind, exec, args, targets);
        cfg.cwd = cwd;
        cfg.env = env_map;
        // Plugins keep small private cursors (polling offsets, dedupe sets) under the node's state
        // dir so a restart resumes instead of re-baselining. An explicit plugins[].env value wins.
        cfg.env
            .entry("HYPHAE_STATE_DIR".to_string())
            .or_insert_with(|| state_dir.display().to_string());
        if !secret_env_refs.is_empty() {
            let store_for_respawn = secrets.clone();
            let plugin_id_for_err = id.clone();
            cfg.env_resolver = Some(Arc::new(move || {
                let mut resolved = BTreeMap::new();
                for (env_key, secret_name) in &secret_env_refs {
                    let val = store_for_respawn.get(secret_name).map_err(|e| {
                        format!(
                            "plugins[{plugin_id_for_err}].env.{env_key} failed to load secret '{secret_name}': {e}"
                        )
                    })?;
                    resolved.insert(env_key.clone(), (*val).clone());
                }
                Ok(resolved)
            }));
        }
        cfg.hello_mode = HelloMode::Auto;
        cfg.stderr_log_path = Some(state_dir.join("logs").join(format!("plugin-{id}.log")));
        cfg.redacted_values = redacted_values;
        configs.push(ParsedPlugin {
            config: cfg,
            expose_topic,
            has_webhook_post_url,
        });
    }

    configs
}

mod plugin_runtime {
    use super::{ParsedPlugin, plugin_kind_str};
    use crate::config_file::write_atomic_json;
    use hyp_harness::daemon::{BoxFuture as DaemonBoxFuture, BridgePoster, LocalDaemon};
    use hyp_node::adapters::webhooks::{EXT_SOURCE_KIND, SOURCE_KIND_EXTERNAL_WEBHOOK};
    use hyp_node::adapters::{
        AdapterError, AdapterHealth, AdapterKind, BoxFuture as AdapterBoxFuture, NodeAdapter,
        NodeAdapterHost, PublishErrorCode, PublishOutcome, PublishStatus, SubprocessSupervisor,
    };
    use hyp_node::engine::{NodeError, UnifiedNode};
    use hyp_proto::address::{LOCAL_NODE_ID, is_valid_topic};
    use hyp_proto::cloudevent::CloudEvent as ProtoCloudEvent;
    use hyp_proto::rpc::EventKeyRef;
    use serde_json::{Map, Value, json};
    use std::collections::{BTreeMap, HashSet, VecDeque};
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex, Weak};
    use std::time::Duration;

    const DEFAULT_PLUGIN_POST_TIMEOUT: Duration = Duration::from_secs(15);
    const LOCAL_BRIDGE_DEDUP_CAPACITY: usize = 4096;

    /// Bounded local `(source, id)` deduplicator used for local-only bridge plugins so duplicate
    /// inbound bridge deliveries return `PublishStatus::Duplicate` without publishing private
    /// messages onto remote-subscribable `EventStore` topics.
    struct LocalEventDedup {
        order: VecDeque<(String, String)>,
        seen: HashSet<(String, String)>,
    }

    impl LocalEventDedup {
        fn new() -> Self {
            Self {
                order: VecDeque::new(),
                seen: HashSet::new(),
            }
        }

        fn contains(&self, source: &str, id: &str) -> bool {
            self.seen.contains(&(source.to_string(), id.to_string()))
        }

        /// Returns `true` if `(source, id)` is newly inserted; `false` if already seen.
        fn insert(&mut self, source: String, id: String) -> bool {
            let key = (source, id);
            if !self.seen.insert(key.clone()) {
                return false;
            }
            self.order.push_back(key);
            while self.order.len() > LOCAL_BRIDGE_DEDUP_CAPACITY {
                if let Some(evicted) = self.order.pop_front() {
                    self.seen.remove(&evicted);
                }
            }
            true
        }
    }

    /// Shared live plugin status registry wired into `NodePluginHost::update_status` so health
    /// transitions, restart counts, crash loops, and redacted `lastError` values immediately
    /// update `node.status.json` for `hyp status` and `hyp doctor`.
    pub(super) struct PluginStatusRegistry {
        entries: Mutex<Vec<Value>>,
        status_doc: Arc<Mutex<Option<(PathBuf, Value)>>>,
    }

    struct PluginHealthUpdate<'a> {
        plugin_id: &'a str,
        kind: AdapterKind,
        targets: &'a [String],
        health: &'a AdapterHealth,
        restarts: u64,
        crash_loop_backoff: bool,
        log_path: Option<&'a PathBuf>,
    }

    impl PluginStatusRegistry {
        fn new(
            initial_entries: Vec<Value>,
            status_doc: Arc<Mutex<Option<(PathBuf, Value)>>>,
        ) -> Self {
            Self {
                entries: Mutex::new(initial_entries),
                status_doc,
            }
        }

        pub(super) fn snapshot(&self) -> Vec<Value> {
            self.entries
                .lock()
                .expect("plugin status registry lock poisoned")
                .clone()
        }

        pub(super) fn flush_to_status_doc(&self) {
            let latest = self.snapshot();
            let mut guard = self.status_doc.lock().expect("status_doc lock poisoned");
            if let Some((ref path, ref mut doc)) = *guard {
                if let Some(obj) = doc.as_object_mut() {
                    obj.insert("plugins".to_string(), Value::Array(latest));
                }
                let _ = write_atomic_json(path, doc, true);
            }
        }

        fn upsert_entry(&self, entry: Value) {
            let entry_id = entry
                .get("id")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned);
            {
                let mut entries = self
                    .entries
                    .lock()
                    .expect("plugin status registry lock poisoned");
                if let Some(ref id) = entry_id {
                    if let Some(existing) = entries
                        .iter_mut()
                        .find(|e| e.get("id").and_then(Value::as_str) == Some(id.as_str()))
                    {
                        *existing = entry;
                    } else {
                        entries.push(entry);
                    }
                } else {
                    entries.push(entry);
                }
            }
            self.flush_to_status_doc();
        }

        fn update_health(&self, update: PluginHealthUpdate<'_>) {
            let (status_str, last_error) = match update.health {
                AdapterHealth::Starting => ("starting", None),
                AdapterHealth::Healthy => ("running", None),
                AdapterHealth::Degraded(reason) => (
                    if update.crash_loop_backoff {
                        "crash_loop_backoff"
                    } else {
                        "degraded"
                    },
                    Some(reason.as_str()),
                ),
                AdapterHealth::Stopped => ("stopped", None),
            };
            let mut map = serde_json::Map::new();
            map.insert("id".to_string(), json!(update.plugin_id));
            map.insert("kind".to_string(), json!(plugin_kind_str(update.kind)));
            map.insert("targets".to_string(), json!(update.targets));
            map.insert("status".to_string(), json!(status_str));
            map.insert("restarts".to_string(), json!(update.restarts));
            if let Some(err) = last_error {
                map.insert("lastError".to_string(), json!(err));
                map.insert("error".to_string(), json!(err));
            }
            if let Some(lp) = update.log_path {
                map.insert("logPath".to_string(), json!(lp.display().to_string()));
            }
            self.upsert_entry(Value::Object(map));
        }
    }

    struct NodePluginHost {
        plugin_id: String,
        kind: AdapterKind,
        targets: Vec<String>,
        expose_topic: bool,
        node: Weak<UnifiedNode>,
        daemon: Option<Weak<LocalDaemon>>,
        supervisor: Weak<SubprocessSupervisor>,
        registry: Arc<PluginStatusRegistry>,
        local_dedup: Mutex<LocalEventDedup>,
    }

    impl NodeAdapterHost for NodePluginHost {
        fn publish_event<'a>(
            &'a self,
            to: &'a str,
            event: ProtoCloudEvent,
        ) -> AdapterBoxFuture<'a, Result<PublishOutcome, AdapterError>> {
            Box::pin(async move {
                // Keep private local chat bridge messages strictly local-only unless the user
                // explicitly exposed the bridge topic in `node.json` (`topics[]` or `exposeTopic: true`).
                if self.kind == AdapterKind::Bridge && !self.expose_topic {
                    let already_seen = self
                        .local_dedup
                        .lock()
                        .expect("local bridge dedup lock poisoned")
                        .contains(&event.source, &event.id);
                    if already_seen {
                        return Ok(PublishOutcome {
                            status: PublishStatus::Duplicate,
                            matched: 0,
                        });
                    }
                    let Some(daemon) = self.daemon.as_ref().and_then(Weak::upgrade) else {
                        return Err(AdapterError::PublishFailed {
                            code: PublishErrorCode::Unavailable,
                            message: format!(
                                "local daemon unavailable for bridge '{}:{}'",
                                self.plugin_id, to
                            ),
                        });
                    };
                    let rendered = render_bridge_cloudevent(&event);
                    let delivered = daemon
                        .deliver_bridge_inbound(&self.plugin_id, to, &event.id, &rendered)
                        .await
                        .map_err(|err| AdapterError::PublishFailed {
                            code: PublishErrorCode::Unavailable,
                            message: format!(
                                "bridge inbound delivery failed for '{}:{}': {err}",
                                self.plugin_id, to
                            ),
                        })?;
                    if delivered == 0 {
                        return Err(AdapterError::PublishFailed {
                            code: PublishErrorCode::Unavailable,
                            message: format!(
                                "no local session is linked to bridge '{}:{}'; refusing to drop inbound message",
                                self.plugin_id, to
                            ),
                        });
                    }
                    self.local_dedup
                        .lock()
                        .expect("local bridge dedup lock poisoned")
                        .insert(event.source.clone(), event.id.clone());
                    return Ok(PublishOutcome {
                        status: PublishStatus::Stored,
                        matched: delivered,
                    });
                }

                let Some(node) = self.node.upgrade() else {
                    return Err(AdapterError::NotRunning("unified-node".to_string()));
                };

                let mut event = event;
                if self.kind == AdapterKind::Source {
                    // Issue #38: Enforce `hyphaesourcekind = "external-webhook"` server-side on
                    // every CloudEvent emitted by a subprocess `kind: "source"` plugin (overwriting
                    // any missing or forged value) so Security Gate ALWAYS caps trust tier to
                    // `GateTrustTier::ExternalWebhook` (including across Hub fan-out).
                    event.set_extension(EXT_SOURCE_KIND, SOURCE_KIND_EXTERNAL_WEBHOOK);
                }

                let topic = match self.kind {
                    AdapterKind::Bridge => self.plugin_id.as_str(),
                    _ => {
                        if is_valid_topic(to) {
                            to
                        } else {
                            self.plugin_id.as_str()
                        }
                    }
                };
                let qualified = format!("{LOCAL_NODE_ID}.{topic}");
                let res = node
                    .publish_event(&qualified, event.clone())
                    .await
                    .map_err(|err| {
                        let code = match &err {
                            NodeError::PayloadTooLarge(_) => PublishErrorCode::TooLarge,
                            NodeError::CloudEvent(_) | NodeError::BadRequest(_) => {
                                PublishErrorCode::InvalidEvent
                            }
                            NodeError::Conflict(_) => PublishErrorCode::IdConflict,
                            _ => PublishErrorCode::Unavailable,
                        };
                        AdapterError::PublishFailed {
                            code,
                            message: err.to_string(),
                        }
                    })?;

                let mut matched = res.matched;
                // Issue #39 (B1): Hand freshly stored subprocess source events to matching
                // same-node session mailboxes immediately (`coalesceSeconds: 0` + backlog drain),
                // matching compiled-in adapters and `LocalIngestServer`.
                if !res.deduplicated && res.matched > 0 && self.kind == AdapterKind::Source {
                    if let Err(err) =
                        hyp_node::adapters::deliver_source_topic_to_local_sessions(&node, topic)
                    {
                        eprintln!(
                            "WARN  plugin '{}' event stored but local delivery on topic '{topic}' failed: {err}",
                            self.plugin_id
                        );
                    }
                }
                if !res.deduplicated && self.kind == AdapterKind::Bridge {
                    if let Some(daemon) = self.daemon.as_ref().and_then(Weak::upgrade) {
                        let rendered = render_bridge_cloudevent(&event);
                        if let Ok(delivered) = daemon
                            .deliver_bridge_inbound(&self.plugin_id, to, &event.id, &rendered)
                            .await
                        {
                            matched = matched.saturating_add(delivered);
                        }
                    }
                }

                let status = if res.deduplicated {
                    PublishStatus::Duplicate
                } else {
                    PublishStatus::Stored
                };
                Ok(PublishOutcome { status, matched })
            })
        }

        fn update_status<'a>(
            &'a self,
            _adapter_id: &'a str,
            health: AdapterHealth,
        ) -> AdapterBoxFuture<'a, ()> {
            Box::pin(async move {
                let (restarts, crash_loop_backoff, log_path) = match self.supervisor.upgrade() {
                    Some(sup) => (
                        sup.restart_count(),
                        sup.is_crash_loop_backoff(),
                        sup.stderr_log_path(),
                    ),
                    None => (0, false, None),
                };
                self.registry.update_health(PluginHealthUpdate {
                    plugin_id: &self.plugin_id,
                    kind: self.kind,
                    targets: &self.targets,
                    health: &health,
                    restarts,
                    crash_loop_backoff,
                    log_path: log_path.as_ref(),
                });
            })
        }

        fn report_delivery_failed<'a>(
            &'a self,
            adapter_id: &'a str,
            target: &'a str,
            events: Vec<EventKeyRef>,
            reason: &'a str,
        ) -> AdapterBoxFuture<'a, ()> {
            Box::pin(async move {
                eprintln!(
                    "WARN  plugin '{adapter_id}' delivery_failed target={target} count={} reason={reason}",
                    events.len()
                );
            })
        }
    }

    struct SupervisorBridgePoster {
        supervisor: Arc<SubprocessSupervisor>,
    }

    impl BridgePoster for SupervisorBridgePoster {
        fn post<'a>(
            &'a self,
            _plugin: &'a str,
            target: &'a str,
            text: &'a str,
            meta: &'a Map<String, Value>,
        ) -> DaemonBoxFuture<'a, Result<Value, (String, String)>> {
            Box::pin(async move {
                let mut params: BTreeMap<String, Value> = BTreeMap::new();
                for (k, v) in meta {
                    if k != "text" {
                        params.insert(k.clone(), v.clone());
                    }
                }
                params.insert("text".to_string(), Value::String(text.to_string()));
                self.supervisor
                    .post(target, params, DEFAULT_PLUGIN_POST_TIMEOUT)
                    .await
                    .map_err(|err| match err {
                        AdapterError::NotRunning(m) => ("plugin_not_running".to_string(), m),
                        AdapterError::Timeout(m) => ("plugin_timeout".to_string(), m),
                        AdapterError::RequestFailed(m) => ("plugin_post_failed".to_string(), m),
                        other => ("plugin_error".to_string(), other.to_string()),
                    })
            })
        }
    }

    /// Renders an inbound bridge CloudEvent body without repeating `[plugin:target]`
    /// (which the delivery packer already puts in the `[hyphae · plugin:target]` header).
    fn render_bridge_cloudevent(event: &ProtoCloudEvent) -> String {
        let obj = event.data.as_ref().and_then(Value::as_object);
        let msg_ref = obj
            .and_then(|o| o.get("message_id"))
            .and_then(|v| match v {
                Value::Number(n) => Some(format!("#{n}")),
                Value::String(s) if !s.trim().is_empty() => Some(format!("#{}", s.trim())),
                _ => None,
            })
            .or_else(|| {
                event.subject.as_deref().and_then(|subj| {
                    let trimmed = subj.trim();
                    if trimmed.is_empty() {
                        return None;
                    }
                    match trimmed.rsplit_once('/') {
                        Some((_, tail)) if !tail.is_empty() => Some(format!("#{tail}")),
                        _ => Some(trimmed.to_string()),
                    }
                })
            });

        if let Some(obj) = obj {
            if let Some(text) = obj.get("text").and_then(Value::as_str) {
                let sender = obj
                    .get("from_username")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(|u| format!("@{}", u.trim_start_matches('@')))
                    .or_else(|| {
                        obj.get("from_name")
                            .or_else(|| obj.get("from"))
                            .or_else(|| obj.get("sender"))
                            .or_else(|| obj.get("author"))
                            .or_else(|| obj.get("user"))
                            .and_then(Value::as_str)
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                            .map(ToString::to_string)
                    });

                return match (sender, msg_ref) {
                    (Some(s), Some(m)) => format!("{s} ({m}): {text}"),
                    (Some(s), None) => format!("{s}: {text}"),
                    (None, Some(m)) => format!("({m}) {text}"),
                    (None, None) => text.to_string(),
                };
            }
        }

        if let Some(ref data) = event.data {
            if let Some(s) = data.as_str() {
                return match msg_ref {
                    Some(m) => format!("({m}) {s}"),
                    None => s.to_string(),
                };
            }
            if let Ok(compact) = serde_json::to_string(data) {
                return match msg_ref {
                    Some(m) => format!("({m}) {compact}"),
                    None => compact,
                };
            }
        }
        match msg_ref {
            Some(m) => format!("({m}) {} ({})", event.event_type, event.source),
            None => format!("{} ({})", event.event_type, event.source),
        }
    }

    pub(super) async fn start_plugins(
        plugins: Vec<ParsedPlugin>,
        skipped_statuses: Vec<Value>,
        status_doc: Arc<Mutex<Option<(PathBuf, Value)>>>,
        node: &Arc<UnifiedNode>,
        local_daemon: Option<&Arc<LocalDaemon>>,
        startup_warnings: &mut Vec<String>,
    ) -> (Vec<Arc<SubprocessSupervisor>>, Arc<PluginStatusRegistry>) {
        let registry = Arc::new(PluginStatusRegistry::new(skipped_statuses, status_doc));
        let mut started: Vec<Arc<SubprocessSupervisor>> = Vec::with_capacity(plugins.len());

        for parsed in plugins {
            let cfg = parsed.config;
            let plugin_id = cfg.id.clone();
            let kind = cfg.kind;
            let targets = cfg.targets.clone();
            let log_path = cfg.stderr_log_path.clone();
            let sup = Arc::new(SubprocessSupervisor::new(cfg));
            let host: Arc<dyn NodeAdapterHost> = Arc::new(NodePluginHost {
                plugin_id: plugin_id.clone(),
                kind,
                targets: targets.clone(),
                expose_topic: parsed.expose_topic,
                node: Arc::downgrade(node),
                daemon: local_daemon.map(Arc::downgrade),
                supervisor: Arc::downgrade(&sup),
                registry: Arc::clone(&registry),
                local_dedup: Mutex::new(LocalEventDedup::new()),
            });

            if let Err(err) = sup.start(host).await {
                startup_warnings.push(format!(
                    "Plugin '{plugin_id}' failed to start and was skipped (daemon continuing): {err}"
                ));
                registry.upsert_entry(json!({
                    "id": plugin_id,
                    "kind": plugin_kind_str(kind),
                    "targets": targets,
                    "status": "failed",
                    "restarts": 0,
                    "error": err.to_string(),
                    "lastError": err.to_string(),
                    "logPath": log_path.map(|p| p.display().to_string()),
                }));
                continue;
            }

            let register_poster = kind == AdapterKind::Bridge
                || (plugin_id == "webhook" && parsed.has_webhook_post_url);
            if register_poster {
                if let Some(daemon) = local_daemon {
                    daemon.register_bridge_poster_with_targets(
                        &plugin_id,
                        targets.clone(),
                        Arc::new(SupervisorBridgePoster {
                            supervisor: Arc::clone(&sup),
                        }),
                    );
                } else {
                    startup_warnings.push(format!(
                        "Bridge plugin '{plugin_id}' started without local IPC socket; local sessions require local socket."
                    ));
                }
            }

            let live_health = sup.health();
            let live_log = sup.stderr_log_path();
            registry.update_health(PluginHealthUpdate {
                plugin_id: &plugin_id,
                kind,
                targets: &targets,
                health: &live_health,
                restarts: sup.restart_count(),
                crash_loop_backoff: sup.is_crash_loop_backoff(),
                log_path: live_log.as_ref(),
            });
            started.push(sup);
        }

        (started, registry)
    }

    pub(super) async fn notify_plugins_wake(
        plugins: &[Arc<SubprocessSupervisor>],
        slept_for: Duration,
    ) {
        let mut join_set = tokio::task::JoinSet::new();
        for sup in plugins {
            let sup = Arc::clone(sup);
            join_set.spawn(async move {
                let _ = sup.send_system_wake(slept_for).await;
            });
        }
        while join_set.join_next().await.is_some() {}
    }

    pub(super) async fn stop_plugins(plugins: Vec<Arc<SubprocessSupervisor>>) {
        for sup in plugins {
            let _ = sup.stop().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyp_crypto::keystore::{SecretBackend, SecretStore};

    #[test]
    fn parse_webhook_sources_resolves_secret_refs_and_rejects_plaintext() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let secrets = SecretStore::new(tmp.path(), SecretBackend::File);
        secrets.set("gh-hook-sec", "gh-secret-value").unwrap();
        secrets.set("prom-pass", "prom-basic-pass").unwrap();
        secrets.set("ci-hook-sec", "ci-hmac-secret").unwrap();

        let sources = json!([
            {
                "kind": "github-webhook",
                "id": "gh-main",
                "topic": "github",
                "secret": { "secret": "gh-hook-sec" },
                "allowedRepos": ["acme/app"]
            },
            {
                "kind": "prometheus-webhook",
                "id": "prom-ops",
                "topic": "alerts",
                "basicAuth": {
                    "username": "alertmanager",
                    "password": { "secret": "prom-pass" }
                }
            },
            {
                "kind": "webhook-stream",
                "id": "ci-events",
                "topic": "ci",
                "secret": { "secret": "ci-hook-sec" },
                "signatureHeader": "X-CI-Sig-256"
            }
        ]);
        let parsed = parse_webhook_sources(&sources, &secrets).expect("valid webhook sources");
        assert_eq!(parsed.github.len(), 1);
        assert_eq!(parsed.github[0].id, "gh-main");
        assert_eq!(parsed.github[0].allowed_repos, vec!["acme/app"]);
        assert_eq!(parsed.prometheus.len(), 1);
        assert!(parsed.prometheus[0].has_auth_configured());
        assert_eq!(parsed.generic.len(), 1);
        assert_eq!(parsed.generic[0].signature_header, "x-ci-sig-256");

        // Plaintext secret MUST fail closed.
        let plaintext = json!([
            {
                "kind": "github-webhook",
                "id": "gh-bad",
                "topic": "github",
                "secret": "hardcoded-plaintext-secret"
            }
        ]);
        assert!(parse_webhook_sources(&plaintext, &secrets).is_err());

        // Unauthenticated Prometheus webhook MUST fail closed.
        let unauth_prom = json!([
            {
                "kind": "prometheus-webhook",
                "id": "prom-bad",
                "topic": "alerts"
            }
        ]);
        assert!(parse_webhook_sources(&unauth_prom, &secrets).is_err());
    }

    #[test]
    fn parse_wake_recovery_config_handles_defaults_camel_snake_and_rejects_invalid() {
        let def = parse_wake_recovery_config(&json!({})).expect("defaults");
        assert_eq!(def, WakeRecoveryConfig::default());

        let camel = parse_wake_recovery_config(&json!({
            "wakeRecovery": {
                "enabled": false,
                "minSleepSeconds": 45,
                "notifyInterruptedActive": false,
                "notifyAllEnrolled": true
            }
        }))
        .expect("camelCase");
        assert!(!camel.enabled);
        assert_eq!(camel.min_sleep_seconds, 45);
        assert!(!camel.notify_interrupted_active);
        assert!(camel.notify_all_enrolled);

        let snake = parse_wake_recovery_config(&json!({
            "wakeRecovery": {
                "min_sleep_seconds": 30,
                "notify_interrupted_active": true,
                "notify_all_enrolled": false
            }
        }))
        .expect("snake_case");
        assert!(snake.enabled);
        assert_eq!(snake.min_sleep_seconds, 30);

        // Fail closed on invalid shapes/types.
        assert!(parse_wake_recovery_config(&json!({ "wakeRecovery": [] })).is_err());
        assert!(
            parse_wake_recovery_config(&json!({ "wakeRecovery": { "enabled": "yes" } })).is_err()
        );
        assert!(
            parse_wake_recovery_config(&json!({ "wakeRecovery": { "minSleepSeconds": 0 } }))
                .is_err()
        );
        assert!(
            parse_wake_recovery_config(&json!({ "wakeRecovery": { "notifyAllEnrolled": 1 } }))
                .is_err()
        );
    }

    #[test]
    fn parse_node_runtime_policies_loads_forwarding_trusted_proxies_and_guest_collision_guard() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut cfg = NodeConfig::router(NodeId::new("hub-1").unwrap(), tmp.path());
        let raw = json!({
            "forwarding": {
                "mode": "allowlist",
                "rules": [
                    { "fromPeer": "alice@laptop", "toPeer": "bob@server", "topic": "dm" }
                ]
            },
            "listen": { "behindReverseProxy": true }
        });
        parse_node_runtime_policies(&raw, &mut cfg).expect("valid policies");
        assert!(cfg.forwarding.permits("alice@laptop", "bob@server", "dm"));
        assert!(!cfg.forwarding.permits("eve@other", "bob@server", "dm"));
        // H7: backwards-compat behindReverseProxy=true maps STRICTLY to loopback-only CIDRs!
        assert_eq!(cfg.trusted_proxies, vec!["127.0.0.1/32", "::1/128"]);

        // Explicit trustedProxies overrides behindReverseProxy and supports IPv4/IPv6 CIDRs.
        let raw_cidr = json!({
            "trustedProxies": ["10.0.0.1/32", "fd00::1/128"],
            "listen": { "behindReverseProxy": false }
        });
        parse_node_runtime_policies(&raw_cidr, &mut cfg).expect("explicit trustedProxies");
        assert_eq!(cfg.trusted_proxies, vec!["10.0.0.1/32", "fd00::1/128"]);

        // Invalid CIDR fails closed!
        let bad_cidr = json!({
            "trustedProxies": ["10.0.0.1/99"]
        });
        assert!(parse_node_runtime_policies(&bad_cidr, &mut cfg).is_err());

        // forwarding.maxHops: 0 fails closed!
        let bad_hops = json!({
            "forwarding": { "maxHops": 0 }
        });
        assert!(parse_node_runtime_policies(&bad_hops, &mut cfg).is_err());

        // Top-level behindReverseProxy: false clears loopback fallback when trustedProxies omitted.
        let raw_override = json!({
            "behindReverseProxy": false,
            "listen": { "behindReverseProxy": true }
        });
        parse_node_runtime_policies(&raw_override, &mut cfg).expect("override");
        assert!(cfg.trusted_proxies.is_empty());

        // Guest topic collision guard skips webhook adapters colliding with guestPairing / github-public!
        let mut parsed = ParsedWebhookSources {
            github: vec![
                GitHubWebhookConfig::new("gh-public-collide", "github", "sec1"),
                GitHubWebhookConfig::new("gh-private", "github-private", "sec2"),
            ],
            prometheus: vec![PrometheusWebhookConfig::new("prom-collide", "github")],
            generic: vec![GenericWebhookConfig::new("gen-ok", "ci")],
        };
        let mut warnings = Vec::new();
        filter_colliding_webhook_sources(&mut parsed, true, Some("github"), &mut warnings);
        assert_eq!(parsed.github.len(), 1);
        assert_eq!(parsed.github[0].id, "gh-private");
        assert!(parsed.prometheus.is_empty());
        assert_eq!(parsed.generic.len(), 1);
        assert_eq!(warnings.len(), 2);
    }

    #[test]
    fn parse_github_public_source_repo_tokens_missing_secret_isolation_and_duplicate_warning() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let secrets = SecretStore::new(tmp.path(), SecretBackend::File);
        secrets
            .set("github-bowd-token", "hyphae_gh_tok_bowd_1")
            .unwrap();
        secrets
            .set("github-bayfold-special", "hyphae_gh_tok_special_2")
            .unwrap();
        // Intentionally omit `github-missing-org-token` to test startup warning isolation!

        let sources = json!([
            {
                "id": "github-public",
                "kind": "github-public",
                "topic": "github",
                "enabled": true,
                "allowPrivateWithToken": true,
                "maxActivePollers": 42,
                "repoTokens": {
                    "Bowd": { "secret": "github-bowd-token" },
                    "bayfold/Special": { "secret": "github-bayfold-special" },
                    "missing-org/*": { "secret": "github-missing-org-token" }
                }
            },
            {
                "id": "github-public-extra",
                "kind": "github-public",
                "topic": "github",
                "enabled": true,
                "githubToken": { "secret": "github-bowd-token" }
            }
        ]);

        let mut warnings = Vec::new();
        let cfg = parse_github_public_source(&sources, &secrets, false, &mut warnings)
            .expect("valid repoTokens with missing secondary secret should succeed")
            .expect("expected active github-public config");

        assert!(cfg.allow_private_with_token);
        assert_eq!(cfg.max_active_pollers, 42);
        assert_eq!(cfg.token_for_repo("bowd/app"), Some("hyphae_gh_tok_bowd_1"));
        assert_eq!(
            cfg.token_for_repo("bayfold/special"),
            Some("hyphae_gh_tok_special_2")
        );
        assert_eq!(cfg.token_for_repo("missing-org/repo"), None);
        assert_eq!(cfg.token_for_repo("oss/public"), None);
        assert_eq!(
            cfg.configured_token_scopes(),
            vec!["bayfold/special".to_string(), "bowd/*".to_string()]
        );

        assert!(
            warnings
                .iter()
                .any(|w| w.contains("github-missing-org-token") && w.contains("missing-org/*")),
            "expected isolated missing-secret warning, got {warnings:?}"
        );
        assert!(
            warnings.iter().any(
                |w| w.contains("Multiple enabled github-public sources found")
                    && w.contains("sources[0].repoTokens")
            ),
            "expected duplicate github-public source warning, got {warnings:?}"
        );
        // Never leak raw secret material into warnings.
        for w in &warnings {
            assert!(!w.contains("hyphae_gh_tok_"));
        }
    }

    #[test]
    fn parse_github_public_source_rejects_plaintext_and_invalid_repo_token_patterns() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let secrets = SecretStore::new(tmp.path(), SecretBackend::File);

        // 1. Plaintext token string in repoTokens MUST fail closed!
        let plaintext_sources = json!([
            {
                "kind": "github-public",
                "enabled": true,
                "repoTokens": {
                    "bayfold/*": "hyphae_gh_tok_plaintext_forbidden"
                }
            }
        ]);
        let mut warnings = Vec::new();
        let err = parse_github_public_source(&plaintext_sources, &secrets, false, &mut warnings)
            .expect_err("plaintext repoTokens value must fail closed");
        assert!(
            err.contains("plaintext credentials are forbidden"),
            "unexpected error: {err}"
        );

        // 2. Global wildcards & traversal patterns MUST fail closed!
        for bad_pat in ["*", "*/*", "../bad", "owner/..", ""] {
            let bad_sources = json!([
                {
                    "kind": "github-public",
                    "enabled": true,
                    "repoTokens": {
                        bad_pat: { "secret": "github-bowd-token" }
                    }
                }
            ]);
            let err = parse_github_public_source(&bad_sources, &secrets, false, &mut warnings)
                .expect_err("invalid repoTokens pattern must fail closed");
            assert!(
                err.contains("invalid sources[].repoTokens pattern"),
                "pattern {bad_pat:?} error: {err}"
            );
        }

        // 3. Invalid maxActivePollers (0) fails closed.
        let bad_cap = json!([
            {
                "kind": "github-public",
                "enabled": true,
                "maxActivePollers": 0
            }
        ]);
        assert!(parse_github_public_source(&bad_cap, &secrets, false, &mut warnings).is_err());
    }

    fn extract_json_fences_with_plugins(markdown: &str) -> Vec<Value> {
        let mut out = Vec::new();
        let mut in_json = false;
        let mut buf = String::new();
        for line in markdown.lines() {
            let trimmed = line.trim();
            if !in_json {
                if trimmed == "```json" {
                    in_json = true;
                    buf.clear();
                }
            } else if trimmed == "```" {
                in_json = false;
                if let Ok(val) = serde_json::from_str::<Value>(&buf) {
                    if val.get("plugins").is_some() {
                        out.push(val);
                    }
                }
            } else {
                buf.push_str(line);
                buf.push('\n');
            }
        }
        out
    }

    #[test]
    fn parse_plugins_config_accepts_command_alias_isolates_errors_warns_plaintext_and_infers_webhook_kind()
     {
        let tmp = tempfile::tempdir().expect("tempdir");
        let secrets = SecretStore::new(tmp.path(), SecretBackend::File);
        secrets
            .set("tg-secret", "123456:REAL_BOT_SECRET_VAL")
            .unwrap();

        let plugins = json!([
            // 1. Documented "command" alias (no "exec")
            {
                "id": "telegram",
                "command": "/usr/bin/env",
                "args": ["node", "/tmp/tg.mjs"],
                "targets": ["personal"],
                "env": {
                    "TELEGRAM_BOT_TOKEN": { "secret": "tg-secret" },
                    "TELEGRAM_ALLOWED_USERS": "12345"
                }
            },
            // 2. Both "exec" and "command" differing -> warn & prefer "exec"
            {
                "id": "slack",
                "exec": "/usr/local/bin/node",
                "command": "/opt/homebrew/bin/node",
                "args": ["/tmp/slack.mjs"],
                "targets": ["pm"],
                "env": {
                    "SLACK_BOT_TOKEN": "xoxb-plaintext-should-warn-9999",
                    "SLACK_APP_TOKEN_FILE": "/tmp/app.token"
                }
            },
            // 3. Webhook with omitted kind + WEBHOOK_POST_URL -> Bridge; without -> Source
            {
                "id": "webhook",
                "command": "node",
                "args": ["/tmp/wh.mjs"],
                "targets": ["ops"],
                "env": {
                    "WEBHOOK_POST_URL": "http://127.0.0.1:9999/cb"
                }
            },
            // 4. Malformed entry (missing exec & command) -> isolated as status: "error"
            {
                "id": "broken-no-cmd",
                "targets": ["ops"]
            },
            // 5. Malformed entry (invalid id) -> isolated as status: "error"
            {
                "id": "../escape",
                "command": "node",
                "targets": ["ops"]
            },
            // 6. Malformed entry (bad env ref) -> isolated as status: "error"
            {
                "id": "broken-env",
                "command": "node",
                "targets": ["ops"],
                "env": { "BAD_VAR": 42 }
            },
            // 7. Missing secret -> isolated as status: "skipped"
            {
                "id": "missing-sec",
                "command": "node",
                "targets": ["ops"],
                "env": { "MY_TOKEN": { "secret": "does-not-exist" } }
            },
            // 8. Non-object entry -> isolated as status: "error"
            "not-an-object"
        ]);

        let mut warnings = Vec::new();
        let mut skipped = Vec::new();
        let explicit_topics = HashSet::new();
        let parsed = parse_plugins_config(
            &plugins,
            None,
            tmp.path(),
            &explicit_topics,
            &secrets,
            &mut warnings,
            &mut skipped,
        );

        assert_eq!(
            parsed.len(),
            3,
            "expected 3 valid plugins, got {}",
            parsed.len()
        );
        assert_eq!(parsed[0].config.id, "telegram");
        assert_eq!(parsed[0].config.exec, "/usr/bin/env");
        assert_eq!(parsed[0].config.kind, AdapterKind::Bridge);
        assert!(
            !parsed[0].expose_topic,
            "bridge topics must default local-only"
        );
        assert!(
            parsed[0]
                .config
                .redacted_values
                .iter()
                .any(|v| v == "123456:REAL_BOT_SECRET_VAL")
        );

        assert_eq!(parsed[1].config.id, "slack");
        assert_eq!(parsed[1].config.exec, "/usr/local/bin/node");
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("both 'exec' and 'command'") && w.contains("preferring 'exec'")),
            "expected warning when exec & command differ: {warnings:?}"
        );
        assert!(
            warnings.iter().any(|w| w.contains("SLACK_BOT_TOKEN")
                && w.contains("plaintext")
                && w.contains("secret")),
            "expected plaintext secret warning for SLACK_BOT_TOKEN: {warnings:?}"
        );
        assert!(
            !warnings.iter().any(|w| w.contains("SLACK_APP_TOKEN_FILE")),
            "*_FILE env var must NOT trigger plaintext warning: {warnings:?}"
        );
        for w in &warnings {
            assert!(
                !w.contains("xoxb-plaintext-should-warn-9999")
                    && !w.contains("123456:REAL_BOT_SECRET_VAL"),
                "warning leaked secret value: {w}"
            );
        }

        assert_eq!(parsed[2].config.id, "webhook");
        assert_eq!(parsed[2].config.kind, AdapterKind::Bridge);
        assert!(parsed[2].has_webhook_post_url);

        // Verify isolated errors vs skipped missing secret
        assert_eq!(
            skipped.len(),
            5,
            "expected 5 skipped/error entries: {skipped:?}"
        );
        let by_id = |id: &str| {
            skipped
                .iter()
                .find(|v| v.get("id").and_then(Value::as_str) == Some(id))
                .cloned()
        };
        assert_eq!(by_id("broken-no-cmd").unwrap()["status"], "error");
        assert_eq!(by_id("../escape").unwrap()["status"], "error");
        assert_eq!(by_id("broken-env").unwrap()["status"], "error");
        assert_eq!(by_id("missing-sec").unwrap()["status"], "skipped");
        assert_eq!(by_id("plugins[7]").unwrap()["status"], "error");
    }

    #[test]
    fn parse_plugins_config_parses_actual_documented_snippets_from_docs_and_skill() {
        let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .expect("repo root");
        let tmp = tempfile::tempdir().expect("tempdir");
        let secrets = SecretStore::new(tmp.path(), SecretBackend::File);
        for name in [
            "telegram-bot-token",
            "slack-app-token",
            "slack-bot-token",
            "sentry-auth-token",
            "google-client-secret",
            "google-refresh-token",
        ] {
            secrets.set(name, &format!("test-val-{name}")).unwrap();
        }

        let explicit_topics = HashSet::new();
        for rel in ["docs/plugins.md", "skills/hyphae-setup/SKILL.md"] {
            let content = fs::read_to_string(repo_root.join(rel))
                .unwrap_or_else(|e| panic!("failed reading {rel}: {e}"));
            let snippets = extract_json_fences_with_plugins(&content);
            assert!(
                !snippets.is_empty(),
                "expected at least one plugins[] JSON snippet in {rel}"
            );
            for (idx, snippet) in snippets.iter().enumerate() {
                let mut warnings = Vec::new();
                let mut skipped = Vec::new();
                let parsed = parse_plugins_config(
                    &snippet["plugins"],
                    None,
                    tmp.path(),
                    &explicit_topics,
                    &secrets,
                    &mut warnings,
                    &mut skipped,
                );
                assert!(
                    skipped.is_empty(),
                    "{rel} snippet #{idx} had skipped/errored plugins: {skipped:?} warnings={warnings:?}"
                );
                assert!(
                    !parsed.is_empty(),
                    "{rel} snippet #{idx} parsed zero plugins"
                );
            }
        }
    }

    #[test]
    fn parse_plugins_config_telegram_omitted_targets_resolves_via_getme_and_falls_back_safely() {
        use std::io::{Read as _, Write as _};
        use std::net::TcpListener;

        let ok_tok = "20001:NODE_CMD_OK_TOKEN_NEVER_LEAK";
        let fail_tok = "20002:NODE_CMD_500_TOKEN_NEVER_LEAK";

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        let server = std::thread::spawn(move || {
            for _ in 0..2 {
                let Ok((mut stream, _)) = listener.accept() else {
                    break;
                };
                let mut buf = [0u8; 2048];
                let n = stream.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);
                let path = req
                    .lines()
                    .next()
                    .and_then(|l| l.split_whitespace().nth(1))
                    .unwrap_or("");
                if path == format!("/bot{ok_tok}/getMe") {
                    let body = r#"{"ok":true,"result":{"username":"Moneypenny0_Bot"}}"#;
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes());
                } else {
                    let body = r#"{"ok":false,"description":"upstream error"}"#;
                    let resp = format!(
                        "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes());
                }
            }
        });

        let tmp = tempfile::tempdir().expect("tempdir");
        let secrets = SecretStore::new(tmp.path(), SecretBackend::File);
        secrets.set("tg-ok-tok", ok_tok).unwrap();
        secrets.set("tg-fail-tok", fail_tok).unwrap();
        let api_base = format!("http://{addr}");
        let explicit_topics = HashSet::new();

        // 1. Omitted targets on id="telegram" resolves bot username via getMe!
        let mut warnings_ok = Vec::new();
        let mut skipped_ok = Vec::new();
        let parsed_ok = parse_plugins_config(
            &json!([{
                "id": "telegram",
                "command": "node",
                "args": ["/tmp/tg.mjs"],
                "env": {
                    "TELEGRAM_BOT_TOKEN": { "secret": "tg-ok-tok" },
                    "TELEGRAM_API_BASE": api_base,
                    "TELEGRAM_ALLOWED_USERS": "42"
                }
            }]),
            None,
            tmp.path(),
            &explicit_topics,
            &secrets,
            &mut warnings_ok,
            &mut skipped_ok,
        );
        assert!(skipped_ok.is_empty(), "skipped: {skipped_ok:?}");
        assert_eq!(parsed_ok.len(), 1);
        assert_eq!(parsed_ok[0].config.targets, vec!["moneypenny0_bot"]);
        assert!(warnings_ok.is_empty(), "warnings: {warnings_ok:?}");

        // 2. HTTP 500 from getMe falls back to ["personal"] without blocking startup or leaking token!
        let mut warnings_fail = Vec::new();
        let mut skipped_fail = Vec::new();
        let parsed_fail = parse_plugins_config(
            &json!([{
                "id": "telegram",
                "command": "node",
                "args": ["/tmp/tg.mjs"],
                "targets": [],
                "env": {
                    "TELEGRAM_BOT_TOKEN": { "secret": "tg-fail-tok" },
                    "TELEGRAM_API_BASE": api_base,
                    "TELEGRAM_ALLOWED_USERS": "42"
                }
            }]),
            None,
            tmp.path(),
            &explicit_topics,
            &secrets,
            &mut warnings_fail,
            &mut skipped_fail,
        );
        assert!(skipped_fail.is_empty(), "skipped: {skipped_fail:?}");
        assert_eq!(parsed_fail.len(), 1);
        assert_eq!(parsed_fail[0].config.targets, vec!["personal"]);
        assert!(
            warnings_fail.iter().any(|w| w.contains("personal")),
            "expected fallback warning: {warnings_fail:?}"
        );
        for w in &warnings_fail {
            assert!(!w.contains(fail_tok), "token leaked in warning: {w}");
        }

        let _ = server.join();
    }

    #[test]
    fn parse_plugins_config_source_defaults_local_only_and_respects_explicit_expose_topic() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let secrets = SecretStore::new(tmp.path(), SecretBackend::File);
        let mut explicit_topics = HashSet::new();
        // Even if top-level `topics[]` lists a source plugin's target, `kind: "source"` MUST
        // require explicit `"exposeTopic": true` to expose remotely (Issue #25 / B6).
        explicit_topics.insert("personal-mail".to_string());
        explicit_topics.insert("tg-listed".to_string());

        let plugins = json!([
            {
                "id": "mailfeed",
                "kind": "source",
                "command": "python3",
                "args": ["/tmp/mailfeed.py"],
                "targets": ["personal-mail"]
            },
            {
                "id": "mailfeed-explicit-false",
                "kind": "source",
                "command": "python3",
                "args": ["/tmp/mailfeed.py"],
                "targets": ["personal-cal"],
                "exposeTopic": false
            },
            {
                "id": "ci-exposed",
                "kind": "source",
                "command": "python3",
                "args": ["/tmp/ci.py"],
                "targets": ["builds"],
                "exposeTopic": true
            },
            {
                "id": "malformed-expose",
                "kind": "source",
                "command": "python3",
                "args": ["/tmp/bad.py"],
                "targets": ["private-notes"],
                "exposeTopic": "yes"
            },
            {
                "id": "tg-listed",
                "kind": "bridge",
                "command": "node",
                "args": ["/tmp/tg.mjs"],
                "targets": ["ops"]
            },
            {
                "id": "tg-explicit-false",
                "kind": "bridge",
                "command": "node",
                "args": ["/tmp/tg.mjs"],
                "targets": ["ops"],
                "exposeTopic": false
            }
        ]);

        let mut warnings = Vec::new();
        let mut skipped = Vec::new();
        let parsed = parse_plugins_config(
            &plugins,
            None,
            tmp.path(),
            &explicit_topics,
            &secrets,
            &mut warnings,
            &mut skipped,
        );

        assert!(
            skipped.is_empty(),
            "unexpected skipped entries: {skipped:?}"
        );
        assert_eq!(parsed.len(), 6);

        // Source plugin with omitted `exposeTopic` defaults local-only (`false`).
        assert_eq!(parsed[0].config.id, "mailfeed");
        assert_eq!(parsed[0].config.kind, AdapterKind::Source);
        assert!(
            !parsed[0].expose_topic,
            "source plugins must default to exposeTopic: false (local-only)"
        );

        // Source plugin with explicit `exposeTopic: false` stays local-only.
        assert_eq!(parsed[1].config.id, "mailfeed-explicit-false");
        assert!(!parsed[1].expose_topic);

        // Source plugin with explicit `exposeTopic: true` is exposed.
        assert_eq!(parsed[2].config.id, "ci-exposed");
        assert!(parsed[2].expose_topic);

        // Non-boolean `exposeTopic` fails closed to `false` with a warning.
        assert_eq!(parsed[3].config.id, "malformed-expose");
        assert!(
            !parsed[3].expose_topic,
            "malformed non-bool exposeTopic must fail closed to false"
        );
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("malformed-expose") && w.contains("exposeTopic")),
            "expected warning for non-bool exposeTopic: {warnings:?}"
        );

        // Bridge listed in top-level `topics[]` remains backward-compatibly exposed when omitted.
        assert_eq!(parsed[4].config.id, "tg-listed");
        assert!(parsed[4].expose_topic);

        // Bridge with explicit `exposeTopic: false` stays local-only.
        assert_eq!(parsed[5].config.id, "tg-explicit-false");
        assert!(!parsed[5].expose_topic);
    }
}
