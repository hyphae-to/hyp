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
use crate::ui::{EXIT_ERROR, EXIT_OK, EXIT_USAGE, JsonEnvelope, emit_error};
use clap::{Args, Subcommand, ValueEnum};
use hyp_crypto::CryptoError;
use hyp_crypto::keys::OkpJwk as CryptoOkpJwk;
use hyp_crypto::keystore::{SecretBackend, validate_secret_name};
use hyp_crypto::rfc3339::{format_rfc3339_millis, now_unix_ms};
use hyp_harness::daemon::{DeliveryRetryConfig, LocalDaemon, LocalDaemonConfig};
use hyp_node::adapters::github_public::normalize_repo_token_pattern;
use hyp_node::adapters::{
    AdapterKind, GitHubPublicAdapter, GitHubPublicConfig, HelloMode, SubprocessConfig,
};
use hyp_node::engine::{
    DropRelayConfig, E2eePolicy, EscalationConfig, GuestPairingConfig, LocalIngestConfig,
    LocalIngestServer, NodeConfig, NodeProfile, TopicConfig, UnifiedNode,
    normalize_drop_portal_url,
};
use hyp_node::gates::{SecurityGateConfig, SecurityGatePipeline};
use hyp_proto::address::{
    LOCAL_NODE_ID, NodeId, is_valid_handle, is_valid_node_id, is_valid_topic,
};
use hyp_proto::manifest::{OkpCurve as ProtoOkpCurve, OkpJwk as ProtoOkpJwk};
use hyp_proto::scopes::ScopePreset;
use hyp_store::{NodeDb, PeerStatus};
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
    /// HTTP/SSE peer listener address (e.g. 127.0.0.1:8790)
    #[arg(long)]
    pub bind: Option<String>,
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
    /// Output structured JSON envelope on startup
    #[arg(long)]
    pub json: bool,
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
            return emit_error(cmd, as_json, EXIT_USAGE, "INVALID_NODE_ID", e.to_string(), None);
        }
    };

    let bind_addr: Option<SocketAddr> = match args.bind {
        Some(ref raw) => match raw.parse::<SocketAddr>() {
            Ok(a) => Some(a),
            Err(e) => {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_USAGE,
                    "INVALID_BIND",
                    format!("Invalid --bind '{raw}': {e}"),
                    Some("Use <ip>:<port>, e.g. 127.0.0.1:8790".to_string()),
                );
            }
        },
        None => loaded.as_ref().and_then(|c| c.bind_addr).or_else(|| {
            if matches!(profile, NodeProfile::Router | NodeProfile::P2p) {
                Some("127.0.0.1:8790".parse().expect("valid default bind"))
            } else {
                None
            }
        }),
    };

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
    let mut delivery_retry_cfg = DeliveryRetryConfig::default();
    let mut parsed_plugins: Vec<SubprocessConfig> = Vec::new();
    let mut skipped_plugin_statuses: Vec<Value> = Vec::new();

    if let Some(ref cfg) = loaded {
        node_cfg.require_pairing = cfg.require_pairing;
        node_cfg.e2ee_policy = if cfg.require_e2ee {
            E2eePolicy::Required
        } else {
            E2eePolicy::Prefer
        };

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
                    format!("Invalid deliveryRetry config in {}: {e}", cfg.path.display()),
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
                            format!("dropRelay.maxMemoryMb in {} must be >= 1", cfg.path.display()),
                            None,
                        );
                    }
                    if dr.allowed_origins.iter().any(|o| o.trim() == "*" || o.trim().eq_ignore_ascii_case("null")) {
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
        if let Some(admin_key_val) = cfg
            .raw
            .get("pairing")
            .and_then(|p| p.get("adminKey"))
        {
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

        // Parse `sources` entries (currently `kind == "github-public"`).
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
        }

        // Parse optional `plugins[]` external bridge/source subprocess entries.
        // Fault isolation: if a single plugin references a missing secret, emit a warning and
        // skip that plugin instead of aborting the entire daemon.
        if let Some(plugins_val) = cfg.raw.get("plugins") {
            if !plugins_val.is_null() {
                match parse_plugins_config(
                    plugins_val,
                    cfg.path.parent(),
                    &secrets,
                    &mut startup_warnings,
                    &mut skipped_plugin_statuses,
                ) {
                    Ok(plugins) => {
                        for p in &plugins {
                            match p.kind {
                                AdapterKind::Bridge => {
                                    if !node_cfg.topics.iter().any(|t| t.topic == p.id) {
                                        node_cfg.topics.push(TopicConfig {
                                            topic: p.id.clone(),
                                            kind: Some("bridge".to_string()),
                                            description: Some(format!(
                                                "External bridge plugin '{}'",
                                                p.id
                                            )),
                                            metadata: None,
                                            has_provisioned_publisher: true,
                                        });
                                    }
                                }
                                AdapterKind::Source => {
                                    for target in &p.targets {
                                        if is_valid_topic(target)
                                            && !node_cfg.topics.iter().any(|t| t.topic == *target)
                                        {
                                            node_cfg.topics.push(TopicConfig {
                                                topic: target.clone(),
                                                kind: Some("source".to_string()),
                                                description: Some(format!(
                                                    "External source plugin '{}'",
                                                    p.id
                                                )),
                                                metadata: None,
                                                has_provisioned_publisher: true,
                                            });
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                        parsed_plugins = plugins;
                    }
                    Err(e) => {
                        return emit_error(
                            cmd,
                            as_json,
                            EXIT_ERROR,
                            "CONFIG_ERROR",
                            format!("Invalid plugins config in {}: {e}", cfg.path.display()),
                            Some(
                                "Verify plugins[] schema in node.json.".to_string(),
                            ),
                        );
                    }
                }
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

    let start_local_daemon = !args.no_local_socket
        && (matches!(profile, NodeProfile::Local | NodeProfile::P2p) || args.socket.is_some());
    let start_local_ingest = node_cfg.local_ingest.enabled && !args.no_local_socket;
    let explicit_socket = args.socket.clone();

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

    let legacy_warning = loaded
        .as_ref()
        .filter(|c| c.is_legacy_v1)
        .map(|c| format!("Loaded legacy v1 config {}; consider migrating to node.json.", c.path.display()));

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
        let guest_pairing_enabled = node.config().guest_pairing.enabled;

        let gate_pipeline = if start_local_daemon || start_local_ingest {
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
                SecurityGatePipeline::new(gate_cfg, gate_db, Some(gate_secrets))
                    .map_err(|e| format!("Failed to initialize SecurityGatePipeline: {e}"))?,
            );
            if pipeline.is_policy_tampered() {
                startup_warnings.push(
                    "gate_policy_tampered: gate policy signature verification failed; all non-self-host inbound items will fail closed to quarantine until re-locked via `hyp gate lock`."
                        .to_string(),
                );
            }
            Some(pipeline)
        } else {
            None
        };

        let local_daemon = if start_local_daemon {
            let local_cfg = LocalDaemonConfig {
                socket_path: explicit_socket,
                auto_detect_transports: true,
                delivery_retry: delivery_retry_cfg,
                ..Default::default()
            };
            let daemon = LocalDaemon::start(Arc::clone(&node), gate_pipeline.clone(), local_cfg)
                .await
                .map_err(|e| format!("Failed to start local harness IPC daemon: {e}"))?;
            Some(Arc::new(daemon))
        } else {
            None
        };

        let local_ingest_server = if start_local_ingest {
            let srv = LocalIngestServer::start(
                Arc::clone(&node),
                gate_pipeline.clone(),
                node.config().local_ingest.clone(),
            )
            .await
            .map_err(|e| format!("Failed to start local ingest server: {e}"))?;
            Some(srv)
        } else {
            None
        };

        // Start configured external fd-3 bridge/source plugins on Unix and wire bridge targets
        // + outbound BridgePosters into `LocalDaemon`. On non-Unix platforms (e.g. Windows),
        // warn cleanly without breaking compilation or startup.
        #[cfg(unix)]
        let (running_plugins, mut plugin_statuses) = plugin_runtime::start_plugins(
            parsed_plugins,
            &node,
            local_daemon.as_ref(),
            &mut startup_warnings,
        )
        .await;

        #[cfg(not(unix))]
        let mut plugin_statuses: Vec<Value> = {
            let mut statuses = Vec::with_capacity(parsed_plugins.len());
            if !parsed_plugins.is_empty() {
                let ids: Vec<String> = parsed_plugins.iter().map(|p| p.id.clone()).collect();
                startup_warnings.push(format!(
                    "External fd-3 plugins require Unix; skipping configured plugin(s): {}",
                    ids.join(", ")
                ));
                for p in &parsed_plugins {
                    statuses.push(json!({
                        "id": p.id,
                        "kind": plugin_kind_str(p.kind),
                        "targets": p.targets,
                        "status": "unsupported_platform",
                    }));
                }
            }
            statuses
        };
        if !skipped_plugin_statuses.is_empty() {
            skipped_plugin_statuses.extend(plugin_statuses);
            plugin_statuses = skipped_plugin_statuses;
        }

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

        // Auto-connect persisted active peers with a configured endpoint so restarted
        // daemons immediately restore PeerLinks and background SSE `/v1/inbox` streams.
        // Never fail startup if a remote peer is temporarily offline — record a warning instead.
        let active_peers = {
            let db = node.db();
            db.peers()
                .list_peers(Some(PeerStatus::Active))
                .unwrap_or_default()
        };
        let mut connected_peers: Vec<String> = Vec::new();
        for peer in active_peers {
            if peer.peer_id == node.node_id().as_str() {
                continue;
            }
            let Some(ep) = peer
                .endpoint
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            else {
                continue;
            };
            match tokio::time::timeout(
                Duration::from_secs(5),
                node.connect_peer(&peer.peer_id, ep),
            )
            .await
            {
                Ok(Ok(_)) => connected_peers.push(peer.peer_id),
                Ok(Err(e)) => {
                    startup_warnings.push(format!(
                        "Peer '{}' ({ep}) could not be auto-connected on startup: {e}",
                        peer.peer_id
                    ));
                }
                Err(_) => {
                    startup_warnings.push(format!(
                        "Peer '{}' ({ep}) timed out during startup auto-connect",
                        peer.peer_id
                    ));
                }
            }
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
            } else {
                println!("      Peer HTTP:   disabled (local profile)");
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

        #[cfg(unix)]
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
        let _ = fs::remove_file(&pid_path);
        let _ = fs::remove_file(&status_path);

        if !as_json {
            eprintln!("OK    Hyphae v2 Node '{}' stopped cleanly", node.node_id().as_str());
        }
        Ok::<(), String>(())
    });

    match res {
        Ok(()) => ExitCode::from(EXIT_OK),
        Err(e) => emit_error(cmd, as_json, EXIT_ERROR, "NODE_START_FAILED", e, None),
    }
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
        let val: Value = serde_json::from_str(trimmed)
            .map_err(|e| format!("invalid JSON in {context}: {e}"))?;
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
                    return Err(
                        "sources[].maxActivePollers must be a positive integer".to_string()
                    );
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
                    let canonical =
                        normalize_repo_token_pattern(raw_pattern).map_err(|e| {
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

const fn plugin_kind_str(kind: AdapterKind) -> &'static str {
    match kind {
        AdapterKind::Bridge => "bridge",
        AdapterKind::Source => "source",
        AdapterKind::Harness => "harness",
        AdapterKind::PeerLink => "peer_link",
    }
}

/// Parses and validates `plugins[]` from `node.json`, resolving any `{ "secret": "<name>" }`
/// references in `env` via `SecretStore` (isolating per-plugin missing secrets to warnings so a
/// single misconfigured chat bridge never aborts the entire daemon, and never exposing resolved
/// secret values in error messages).
fn parse_plugins_config(
    plugins_val: &Value,
    config_dir: Option<&Path>,
    secrets: &hyp_crypto::SecretStore,
    warnings: &mut Vec<String>,
    skipped_statuses: &mut Vec<Value>,
) -> Result<Vec<SubprocessConfig>, String> {
    let arr = plugins_val
        .as_array()
        .ok_or_else(|| "plugins must be a JSON array".to_string())?;

    let mut seen_ids: HashSet<String> = HashSet::new();
    let mut configs: Vec<SubprocessConfig> = Vec::new();

    for (idx, entry) in arr.iter().enumerate() {
        let obj = entry
            .as_object()
            .ok_or_else(|| format!("plugins[{idx}] must be a JSON object"))?;

        if obj.get("enabled").and_then(Value::as_bool) == Some(false) {
            continue;
        }

        let raw_id = obj
            .get("id")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| format!("plugins[{idx}].id must be a non-empty string"))?;
        let id = raw_id.to_ascii_lowercase();
        if !is_valid_handle(&id) {
            return Err(format!(
                "plugins[{idx}].id '{raw_id}' is not a valid identifier (expected /^[a-z0-9][a-z0-9._-]{{0,63}}$/)"
            ));
        }
        if !seen_ids.insert(id.clone()) {
            return Err(format!("duplicate plugin id '{id}' in plugins[]"));
        }

        let kind = match obj.get("kind").and_then(Value::as_str) {
            None | Some("bridge") => AdapterKind::Bridge,
            Some("source") => AdapterKind::Source,
            Some(other) => {
                return Err(format!(
                    "plugins[{id}].kind '{other}' is invalid (expected 'bridge' or 'source')"
                ));
            }
        };

        let exec = obj
            .get("exec")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| format!("plugins[{id}].exec must be a non-empty string"))?
            .to_string();

        let args = match obj.get("args") {
            None | Some(Value::Null) => Vec::new(),
            Some(val) => {
                let raw_args = val
                    .as_array()
                    .ok_or_else(|| format!("plugins[{id}].args must be an array of strings"))?;
                let mut out = Vec::with_capacity(raw_args.len());
                for (aidx, item) in raw_args.iter().enumerate() {
                    let s = item.as_str().ok_or_else(|| {
                        format!("plugins[{id}].args[{aidx}] must be a string")
                    })?;
                    out.push(s.to_string());
                }
                out
            }
        };

        let cwd = match obj.get("cwd") {
            None | Some(Value::Null) => None,
            Some(val) => {
                let raw_cwd = val
                    .as_str()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| format!("plugins[{id}].cwd must be a non-empty string"))?;
                let path = PathBuf::from(raw_cwd);
                if path.is_absolute() {
                    Some(path)
                } else if let Some(base) = config_dir {
                    Some(base.join(path))
                } else {
                    Some(path)
                }
            }
        };

        let targets = {
            let raw_targets = obj
                .get("targets")
                .and_then(Value::as_array)
                .ok_or_else(|| {
                    format!("plugins[{id}].targets must be a non-empty array of strings")
                })?;
            let mut out = Vec::with_capacity(raw_targets.len());
            for (tidx, item) in raw_targets.iter().enumerate() {
                let s = item
                    .as_str()
                    .map(str::trim)
                    .filter(|t| !t.is_empty())
                    .ok_or_else(|| {
                        format!("plugins[{id}].targets[{tidx}] must be a non-empty string")
                    })?;
                if !out.iter().any(|existing: &String| existing == s) {
                    out.push(s.to_string());
                }
            }
            if out.is_empty() {
                return Err(format!(
                    "plugins[{id}].targets must contain at least one target"
                ));
            }
            out
        };

        let mut env_map: BTreeMap<String, String> = BTreeMap::new();
        let mut secret_skip_reason: Option<String> = None;
        if let Some(env_val) = obj.get("env") {
            if !env_val.is_null() {
                let env_obj = env_val
                    .as_object()
                    .ok_or_else(|| format!("plugins[{id}].env must be a JSON object"))?;
                for (env_key, val) in env_obj {
                    if env_key.trim().is_empty() {
                        return Err(format!(
                            "plugins[{id}].env contains an empty variable name"
                        ));
                    }
                    match val {
                        Value::String(s) => {
                            env_map.insert(env_key.clone(), s.clone());
                        }
                        Value::Object(ref_obj) => {
                            let secret_name = ref_obj
                                .get("secret")
                                .and_then(Value::as_str)
                                .filter(|_| ref_obj.len() == 1)
                                .ok_or_else(|| {
                                    format!(
                                        "plugins[{id}].env.{env_key} must be a string or {{ \"secret\": \"<name>\" }}"
                                    )
                                })?;
                            validate_secret_name(secret_name).map_err(|e| {
                                format!(
                                    "invalid secret name '{secret_name}' in plugins[{id}].env.{env_key}: {e}"
                                )
                            })?;
                            match secrets.get(secret_name) {
                                Ok(secret) => {
                                    env_map.insert(env_key.clone(), (*secret).clone());
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
                            return Err(format!(
                                "plugins[{id}].env.{env_key} must be a string or {{ \"secret\": \"<name>\" }}"
                            ));
                        }
                    }
                }
            }
        }

        if let Some(reason) = secret_skip_reason {
            warnings.push(format!(
                "Skipping plugin '{id}' (daemon continuing): {reason}"
            ));
            skipped_statuses.push(json!({
                "id": id,
                "kind": plugin_kind_str(kind),
                "targets": targets,
                "status": "skipped",
                "error": reason,
            }));
            continue;
        }

        let mut cfg = SubprocessConfig::new(id, kind, exec, args, targets);
        cfg.cwd = cwd;
        cfg.env = env_map;
        cfg.hello_mode = HelloMode::Auto;
        configs.push(cfg);
    }

    Ok(configs)
}

#[cfg(unix)]
mod plugin_runtime {
    use super::plugin_kind_str;
    use hyp_harness::daemon::{BoxFuture as DaemonBoxFuture, BridgePoster, LocalDaemon};
    use hyp_node::adapters::{
        AdapterError, AdapterHealth, AdapterKind, BoxFuture as AdapterBoxFuture, NodeAdapter,
        NodeAdapterHost, PublishErrorCode, PublishOutcome, PublishStatus, SubprocessConfig,
        SubprocessSupervisor,
    };
    use hyp_node::engine::{NodeError, UnifiedNode};
    use hyp_proto::address::{LOCAL_NODE_ID, is_valid_topic};
    use hyp_proto::cloudevent::CloudEvent as ProtoCloudEvent;
    use hyp_proto::rpc::EventKeyRef;
    use serde_json::{Map, Value, json};
    use std::collections::BTreeMap;
    use std::sync::{Arc, Weak};
    use std::time::Duration;

    const DEFAULT_PLUGIN_POST_TIMEOUT: Duration = Duration::from_secs(15);

    struct NodePluginHost {
        plugin_id: String,
        kind: AdapterKind,
        node: Weak<UnifiedNode>,
        daemon: Option<Weak<LocalDaemon>>,
    }

    impl NodeAdapterHost for NodePluginHost {
        fn publish_event<'a>(
            &'a self,
            to: &'a str,
            event: ProtoCloudEvent,
        ) -> AdapterBoxFuture<'a, Result<PublishOutcome, AdapterError>> {
            Box::pin(async move {
                let Some(node) = self.node.upgrade() else {
                    return Err(AdapterError::NotRunning("unified-node".to_string()));
                };

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
                if !res.deduplicated && self.kind == AdapterKind::Bridge {
                    if let Some(daemon) = self.daemon.as_ref().and_then(Weak::upgrade) {
                        let rendered = render_bridge_cloudevent(&self.plugin_id, to, &event);
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
            _health: AdapterHealth,
        ) -> AdapterBoxFuture<'a, ()> {
            Box::pin(async {})
        }

        fn report_delivery_failed<'a>(
            &'a self,
            _adapter_id: &'a str,
            _target: &'a str,
            _events: Vec<EventKeyRef>,
            _reason: &'a str,
        ) -> AdapterBoxFuture<'a, ()> {
            Box::pin(async {})
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

    fn render_bridge_cloudevent(plugin_id: &str, target: &str, event: &ProtoCloudEvent) -> String {
        let mut header = format!("[{plugin_id}:{target}]");
        if let Some(ref subj) = event.subject {
            let trimmed = subj.trim();
            if !trimmed.is_empty() {
                header.push_str(&format!(" ({trimmed})"));
            }
        }
        if let Some(ref data) = event.data {
            if let Some(obj) = data.as_object() {
                if let Some(text) = obj.get("text").and_then(Value::as_str) {
                    if let Some(sender) = obj
                        .get("from")
                        .or_else(|| obj.get("sender"))
                        .or_else(|| obj.get("author"))
                        .or_else(|| obj.get("user"))
                        .and_then(Value::as_str)
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                    {
                        return format!("{header} {sender}: {text}");
                    }
                    return format!("{header} {text}");
                }
            }
            if let Some(s) = data.as_str() {
                return format!("{header} {s}");
            }
            if let Ok(compact) = serde_json::to_string(data) {
                return format!("{header} {compact}");
            }
        }
        format!("{header} {} ({})", event.event_type, event.source)
    }

    pub(super) async fn start_plugins(
        configs: Vec<SubprocessConfig>,
        node: &Arc<UnifiedNode>,
        local_daemon: Option<&Arc<LocalDaemon>>,
        startup_warnings: &mut Vec<String>,
    ) -> (Vec<Arc<SubprocessSupervisor>>, Vec<Value>) {
        let mut started: Vec<Arc<SubprocessSupervisor>> = Vec::with_capacity(configs.len());
        let mut statuses: Vec<Value> = Vec::with_capacity(configs.len());

        for cfg in configs {
            let plugin_id = cfg.id.clone();
            let kind = cfg.kind;
            let targets = cfg.targets.clone();
            let sup = Arc::new(SubprocessSupervisor::new(cfg));
            let host: Arc<dyn NodeAdapterHost> = Arc::new(NodePluginHost {
                plugin_id: plugin_id.clone(),
                kind,
                node: Arc::downgrade(node),
                daemon: local_daemon.map(Arc::downgrade),
            });

            if let Err(err) = sup.start(host).await {
                startup_warnings.push(format!(
                    "Plugin '{plugin_id}' failed to start and was skipped (daemon continuing): {err}"
                ));
                statuses.push(json!({
                    "id": plugin_id,
                    "kind": plugin_kind_str(kind),
                    "targets": targets,
                    "status": "failed",
                    "error": err.to_string(),
                }));
                continue;
            }

            if kind == AdapterKind::Bridge {
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
                        "Bridge plugin '{plugin_id}' started without local IPC socket; sessions cannot link bridge targets until local socket is enabled."
                    ));
                }
            }

            statuses.push(json!({
                "id": plugin_id,
                "kind": plugin_kind_str(kind),
                "targets": targets,
                "status": "running",
            }));
            started.push(sup);
        }

        (started, statuses)
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
            warnings.iter().any(|w| w.contains("Multiple enabled github-public sources found")
                && w.contains("sources[0].repoTokens")),
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
}
