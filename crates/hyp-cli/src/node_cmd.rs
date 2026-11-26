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
use hyp_crypto::keystore::SecretBackend;
use hyp_crypto::rfc3339::{format_rfc3339_millis, now_unix_ms};
use hyp_harness::daemon::{
    BoxFuture as DaemonBoxFuture, DEFAULT_PEERS_RELOAD_TIMEOUT, DaemonError, DeliveryRetryConfig,
    LocalDaemon, LocalDaemonConfig, PeersReloader, WakeRecoveryConfig,
};
use hyp_harness::node_config::parse_plugins_config;
use hyp_harness::plugin_runtime::{self, ParsedPlugin};
use hyp_harness::sock::{DEFAULT_SOCKET_FILENAME, daemon_rpc_sync};
use hyp_node::adapters::{GitHubPublicAdapter, GitHubPublicConfig, GitHubWebhookAdapter};
use hyp_node::engine::{
    DEFAULT_PEER_SOCKET_FILENAME, DEFAULT_WAKE_CHECK_INTERVAL_SECS, E2eePolicy, LocalIngestServer,
    NodeConfig, NodeProfile, PeerReconcileReport, TopicConfig, UnifiedNode,
    normalize_drop_portal_url, spawn_wake_watcher,
};
use hyp_node::gates::{SecurityGateConfig, SecurityGatePipeline};
use hyp_node::node_file::runtime::{
    filter_colliding_webhook_sources, parse_github_public_source, parse_pairing_admin_key,
    parse_webhook_sources,
};
use hyp_proto::address::{LOCAL_NODE_ID, NodeId, is_valid_node_id, is_valid_topic};
use hyp_store::NodeDb;
use serde_json::{Value, json};
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
    let mut webhook_sources = Vec::new();
    let mut enable_kv = None;
    let mut delivery_retry_cfg = DeliveryRetryConfig::default();
    let mut wake_recovery_cfg = WakeRecoveryConfig::default();
    let mut midturn_queue_digest_seconds = hyp_node::delivery::DEFAULT_MIDTURN_QUEUE_DIGEST_SECONDS;
    let mut parsed_plugins: Vec<ParsedPlugin> = Vec::new();
    let mut skipped_plugin_statuses: Vec<Value> = Vec::new();

    if let Some(ref cfg) = loaded {
        node_cfg.require_pairing = cfg.require_pairing;
        node_cfg.e2ee_policy = if cfg.require_e2ee {
            E2eePolicy::Required
        } else {
            E2eePolicy::Prefer
        };

        if let Err(e) = cfg.file.apply_runtime_policies(&mut node_cfg) {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                "CONFIG_ERROR",
                format!("Invalid runtime policy in {}: {e}", cfg.path.display()),
                None,
            );
        }

        enable_kv = match cfg.file.kv_tool_override() {
            Ok(enable_kv) => enable_kv,
            Err(e) => {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_ERROR,
                    "CONFIG_ERROR",
                    format!("Invalid KV tool setting in {}: {e}", cfg.path.display()),
                    None,
                );
            }
        };

        // Parse optional `kvNamespaces[]` (simple strings or structured objects) into
        // `NodeConfig.kv_namespaces` so `/v1/manifest` and `LocalDaemon::has_kv_capability()`
        // advertise `hyp_kv` accurately.
        match cfg.file.kv_namespaces(&mut startup_warnings) {
            Ok(namespaces) => node_cfg.kv_namespaces = namespaces,
            Err(e) => {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_ERROR,
                    "CONFIG_ERROR",
                    format!("Invalid kvNamespaces config in {}: {e}", cfg.path.display()),
                    Some(
                        "Use strings like [\"shared\"] or objects like { \"namespace\": \"shared\", \"mode\": \"e2ee\", \"writeModel\": \"shared\" }."
                            .to_string(),
                    ),
                );
            }
        }

        // Parse optional `localIngest` policy (default enabled: true!).
        if let Some(local_ingest) = &cfg.file.local_ingest {
            match local_ingest {
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
                    node_cfg.local_ingest = li.clone();
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
        match cfg.file.delivery_retry() {
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
        match cfg.file.wake_recovery() {
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

        // Parse optional RFC 0004 `delivery.midturnQueueDigestSeconds`.
        match cfg.file.midturn_queue_digest_seconds() {
            Ok(secs) => midturn_queue_digest_seconds = secs,
            Err(e) => {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_ERROR,
                    "CONFIG_ERROR",
                    format!("Invalid delivery config in {}: {e}", cfg.path.display()),
                    None,
                );
            }
        }

        // Parse optional `dropRelay` (RAM-only Blind Drop Relay) and `dropRelayUrl`.
        if let Some(drop_relay) = &cfg.file.drop_relay {
            match drop_relay {
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
                    node_cfg.drop_relay = dr.clone();
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
        if let Some(raw_url) = cfg.file.drop_relay_url.as_deref() {
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
        if let Some(drop_portal) = &cfg.file.drop_portal_url {
            match drop_portal
                .as_deref()
                .map_err(|e| e.to_string())
                .and_then(normalize_drop_portal_url)
            {
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

        // Parse optional `escalation` hints (default + byScope).
        if let Some(escalation) = &cfg.file.escalation {
            match escalation {
                Ok(esc) => node_cfg.escalation = esc.clone(),
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
        match cfg.file.guest_pairing() {
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

        let secrets = open_secret_store(&state_dir, explicit_state);

        // Parse optional `pairing.adminKey` (OKP Ed25519 JWK object, 43-char base64url raw pubkey,
        // or `{ "secret": "<name>" }` reference) so `POST /v1/pair` can verify Org Admin-CA `am2_` grants.
        if let Some(admin_key_val) = cfg.file.pairing.as_ref().and_then(|p| p.admin_key.as_ref()) {
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

        // Parse GitHub polling and repository webhook sources.
        if let Some(sources) = cfg.file.source_entries().transpose() {
            let public_read_only = cfg.file.public_read_only.unwrap_or(false);
            match sources.map_err(str::to_owned).and_then(|entries| {
                parse_github_public_source(
                    entries,
                    &secrets,
                    public_read_only,
                    &mut startup_warnings,
                )
            }) {
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

            match parse_webhook_sources(
                sources.unwrap_or_default(),
                &secrets,
                &mut startup_warnings,
            ) {
                Ok(mut parsed) => {
                    filter_colliding_webhook_sources(
                        &mut parsed,
                        node_cfg.guest_pairing.enabled,
                        github_public_cfg.as_ref().map(|g| g.topic.as_str()),
                        &mut startup_warnings,
                    );
                    for gh in &parsed {
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
                    webhook_sources = parsed;
                }
                Err(e) => {
                    return emit_error(
                        cmd,
                        as_json,
                        EXIT_ERROR,
                        "CONFIG_ERROR",
                        format!("Invalid webhook source in {}: {e}", cfg.path.display()),
                        Some("Use SecretStore references for GitHub webhook sources.".to_string()),
                    );
                }
            }
        }

        // Collect any explicitly configured top-level `topics[]` names from `node.json`.
        // Both subprocess bridge plugins AND subprocess source plugins default to strictly
        // local-only (`exposeTopic: false`) so paired remote peers with `stream:subscribe=*`
        // (`member`/`observer`/`full`) never silently read private local chat DMs or personal
        // subprocess event sources unless explicitly opted in via `plugins[].exposeTopic: true`.
        let explicit_topics = &cfg.file.explicit_topics;

        // Parse optional `plugins[]` external bridge/source subprocess entries.
        // Fault isolation: individual malformed/misconfigured plugin entries or missing secrets
        // emit startup warnings and record their status without aborting `hyp node start`.
        if let Some(plugins) = &cfg.file.plugins {
            parsed_plugins = parse_plugins_config(
                plugins,
                cfg.path.parent(),
                &state_dir,
                explicit_topics,
                &secrets,
                &mut startup_warnings,
                &mut skipped_plugin_statuses,
            );
            plugin_runtime::configure_plugin_topics(&mut node_cfg, &parsed_plugins);
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
        for gh_cfg in webhook_sources {
            let adapter = Arc::new(GitHubWebhookAdapter::new(gh_cfg));
            node.attach_github_webhook(adapter)
                .await
                .map_err(|e| format!("Failed to attach github-webhook adapter: {e}"))?;
        }

        let guest_pairing_enabled = node.config().guest_pairing.enabled;

        let has_gate_cfg = loaded
            .as_ref()
            .and_then(|c| c.file.gate.as_ref())
            .is_some();
        let has_gate_seal = crate::approval::has_gate_lock_seal(&state_dir);
        let (gate_pipeline, gate_db_shared) =
            if start_local_daemon || start_local_ingest || has_gate_cfg || has_gate_seal {
            let gate_cfg: SecurityGateConfig = match loaded.as_ref().and_then(|c| c.file.gate.as_ref())
            {
                Some(gate) => gate.clone()
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
                    "gate_policy_tampered: gate policy signature verification failed; all non-self-host inbound items will fail closed to quarantine until re-locked via `hyp gate apply`."
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
                enable_kv,
                delivery_retry: delivery_retry_cfg,
                wake_recovery: wake_recovery_cfg.clone(),
                midturn_queue_digest_seconds,
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
        match loaded.file.gate {
            Some(gate) => gate.map_err(|e| {
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
        .verify_policy_change_approval()
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

#[cfg(test)]
mod tests {
    use super::*;
    use hyp_crypto::keystore::{SecretBackend, SecretStore};
    use hyp_node::adapters::{AdapterKind, GitHubWebhookConfig};
    use hyp_node::engine::KvNamespaceConfig;
    use hyp_proto::manifest::{KvMode, KvWriteModel};
    use std::collections::HashSet;

    fn parse_plugins_fixture(
        plugins: &Value,
        config_dir: Option<&Path>,
        state_dir: &Path,
        explicit_topics: &HashSet<String>,
        secrets: &SecretStore,
        warnings: &mut Vec<String>,
        skipped_statuses: &mut Vec<Value>,
    ) -> Vec<ParsedPlugin> {
        let file: hyp_node::node_file::NodeFile =
            serde_json::from_value(json!({ "plugins": plugins })).unwrap();
        parse_plugins_config(
            &file.plugins.unwrap(),
            config_dir,
            state_dir,
            explicit_topics,
            secrets,
            warnings,
            skipped_statuses,
        )
    }

    fn parse_webhook_fixture(
        sources: &Value,
        secrets: &SecretStore,
        warnings: &mut Vec<String>,
    ) -> Result<Vec<GitHubWebhookConfig>, String> {
        let file: hyp_node::node_file::NodeFile =
            serde_json::from_value(json!({ "sources": sources })).unwrap();
        parse_webhook_sources(
            file.source_entries()?.unwrap_or_default(),
            secrets,
            warnings,
        )
    }

    #[test]
    fn parse_webhook_sources_resolves_secret_refs_and_rejects_plaintext() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let secrets = SecretStore::new(tmp.path(), SecretBackend::File);
        secrets.set("gh-hook-sec", "gh-secret-value").unwrap();

        let sources = json!([
            {
                "kind": "github-webhook",
                "id": "gh-main",
                "topic": "github",
                "secret": { "secret": "gh-hook-sec" },
                "allowedRepos": ["acme/app"]
            }
        ]);
        let mut warnings = Vec::new();
        let parsed = parse_webhook_fixture(&sources, &secrets, &mut warnings)
            .expect("valid webhook sources");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].id, "gh-main");
        assert_eq!(parsed[0].allowed_repos, vec!["acme/app"]);
        // Plaintext secret MUST fail closed.
        let plaintext = json!([
            {
                "kind": "github-webhook",
                "id": "gh-bad",
                "topic": "github",
                "secret": "hardcoded-plaintext-secret"
            }
        ]);
        assert!(parse_webhook_fixture(&plaintext, &secrets, &mut warnings).is_err());

        for (kind, plugin) in [
            ("prometheus-webhook", "prometheus"),
            ("webhook-stream", "webhook"),
        ] {
            let enabled = json!([{ "kind": kind, "id": "configured" }]);
            warnings.clear();
            assert!(
                parse_webhook_fixture(&enabled, &secrets, &mut warnings)
                    .unwrap()
                    .is_empty()
            );
            assert_eq!(warnings.len(), 1);
            assert!(warnings[0].contains(&format!("hyp plugin install {plugin} --json")));
            let disabled = json!([{ "kind": kind, "id": "configured", "enabled": false }]);
            warnings.clear();
            assert!(parse_webhook_fixture(&disabled, &secrets, &mut warnings).is_ok());
            assert!(warnings.is_empty());
        }
    }

    #[test]
    fn parse_wake_recovery_config_handles_defaults_camel_snake_and_rejects_invalid() {
        let parse_wake_recovery_config = |doc: &Value| {
            serde_json::from_value::<hyp_node::node_file::NodeFile>(doc.clone())
                .unwrap()
                .wake_recovery()
        };
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
        let parse_node_runtime_policies = |raw: &Value, config: &mut NodeConfig| {
            serde_json::from_value::<hyp_node::node_file::NodeFile>(raw.clone())
                .unwrap()
                .apply_runtime_policies(config)
        };
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
        let mut parsed = vec![
            GitHubWebhookConfig::new("gh-public-collide", "github", "sec1"),
            GitHubWebhookConfig::new("gh-private", "github-private", "sec2"),
        ];
        let mut warnings = Vec::new();
        filter_colliding_webhook_sources(&mut parsed, true, Some("github"), &mut warnings);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].id, "gh-private");
        assert_eq!(warnings.len(), 1);
    }

    #[test]
    fn parse_kv_namespaces_supports_strings_objects_dedup_and_fail_closed_validation() {
        let parse_kv_namespaces = |raw: &Value, warnings: &mut Vec<String>| {
            serde_json::from_value::<hyp_node::node_file::NodeFile>(raw.clone())
                .unwrap()
                .kv_namespaces(warnings)
        };

        // 1. Absent / null -> empty vec, zero warnings.
        let mut warnings = Vec::new();
        assert!(
            parse_kv_namespaces(&json!({}), &mut warnings)
                .unwrap()
                .is_empty()
        );
        assert!(
            parse_kv_namespaces(&json!({ "kvNamespaces": null }), &mut warnings)
                .unwrap()
                .is_empty()
        );
        assert!(warnings.is_empty());

        // 2. Simple string entries + structured objects (`namespace` and `name`, `cas` alias) + dedup!
        let mixed = json!({
            "kvNamespaces": [
                "shared",
                "deploy-state",
                { "namespace": "ops", "mode": "e2ee", "writeModel": "cas" },
                { "name": "public-meta", "mode": "plaintext", "writeModel": "owner" },
                { "namespace": "restricted", "writeModel": "allowlist" },
                "shared"
            ]
        });
        let parsed = parse_kv_namespaces(&mixed, &mut warnings).expect("valid kvNamespaces");
        assert_eq!(
            parsed,
            vec![
                KvNamespaceConfig {
                    name: "shared".to_string(),
                    mode: KvMode::E2ee,
                    write_model: KvWriteModel::Shared,
                },
                KvNamespaceConfig {
                    name: "deploy-state".to_string(),
                    mode: KvMode::E2ee,
                    write_model: KvWriteModel::Shared,
                },
                KvNamespaceConfig {
                    name: "ops".to_string(),
                    mode: KvMode::E2ee,
                    write_model: KvWriteModel::Shared,
                },
                KvNamespaceConfig {
                    name: "public-meta".to_string(),
                    mode: KvMode::Plaintext,
                    write_model: KvWriteModel::Owner,
                },
                KvNamespaceConfig {
                    name: "restricted".to_string(),
                    mode: KvMode::E2ee,
                    write_model: KvWriteModel::Allowlist,
                },
            ]
        );
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("shared"));

        // 3. Fail-closed on invalid shapes, invalid names, conflicting keys, and unknown enums.
        for bad in [
            json!({ "kvNamespaces": "shared" }),
            json!({ "kvNamespaces": [""] }),
            json!({ "kvNamespaces": ["UPPERCASE"] }),
            json!({ "kvNamespaces": ["../escape"] }),
            json!({ "kvNamespaces": ["bad/slash"] }),
            json!({ "kvNamespaces": [42] }),
            json!({ "kvNamespaces": [{}] }),
            json!({ "kvNamespaces": [{ "name": "a", "namespace": "b" }] }),
            json!({ "kvNamespaces": [{ "namespace": "shared", "mode": "rot13" }] }),
            json!({ "kvNamespaces": [{ "namespace": "shared", "writeModel": "bogus" }] }),
        ] {
            let mut w = Vec::new();
            assert!(
                parse_kv_namespaces(&bad, &mut w).is_err(),
                "must fail closed for invalid kvNamespaces: {bad}"
            );
        }
    }

    fn parse_github_public_fixture(
        sources: &Value,
        secrets: &SecretStore,
        public_read_only: bool,
        warnings: &mut Vec<String>,
    ) -> Result<Option<GitHubPublicConfig>, String> {
        let file: hyp_node::node_file::NodeFile =
            serde_json::from_value(json!({ "sources": sources })).unwrap();
        parse_github_public_source(
            file.source_entries()?.unwrap_or_default(),
            secrets,
            public_read_only,
            warnings,
        )
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
        let cfg = parse_github_public_fixture(&sources, &secrets, false, &mut warnings)
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
        let err = parse_github_public_fixture(&plaintext_sources, &secrets, false, &mut warnings)
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
            let err = parse_github_public_fixture(&bad_sources, &secrets, false, &mut warnings)
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
        assert!(parse_github_public_fixture(&bad_cap, &secrets, false, &mut warnings).is_err());
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
        let parsed = parse_plugins_fixture(
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
            "ci-webhook-secret",
            "prometheus-bearer-token",
            "google-client-secret",
            "google-refresh-token",
        ] {
            secrets.set(name, &format!("test-val-{name}")).unwrap();
        }

        let explicit_topics = HashSet::new();
        for rel in ["docs/plugins.md", "skills/hyp-setup/SKILL.md"] {
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
                let parsed = parse_plugins_fixture(
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
        let parsed_ok = parse_plugins_fixture(
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
        let parsed_fail = parse_plugins_fixture(
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
        let parsed = parse_plugins_fixture(
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

    #[test]
    fn parse_midturn_queue_digest_seconds_defaults_accepts_zero_and_rejects_bad_types() {
        let parse = |v: Value| {
            serde_json::from_value::<hyp_node::node_file::NodeFile>(v)
                .unwrap()
                .midturn_queue_digest_seconds()
        };
        assert_eq!(
            parse(json!({})).unwrap(),
            hyp_node::delivery::DEFAULT_MIDTURN_QUEUE_DIGEST_SECONDS
        );
        let nested = |v: Value| parse(json!({ "delivery": { "midturnQueueDigestSeconds": v } }));
        assert_eq!(nested(json!(600)).unwrap(), 600);
        assert_eq!(nested(json!(0)).unwrap(), 0);
        assert!(nested(json!(-5)).is_err());
        assert!(nested(json!("30m")).is_err());
    }
}
