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
use crate::ui::{EXIT_ERROR, EXIT_OK, EXIT_USAGE, JsonEnvelope, emit_error};
use clap::{Args, Subcommand, ValueEnum};
use hyp_crypto::CryptoError;
use hyp_crypto::keystore::{SecretBackend, validate_secret_name};
use hyp_crypto::rfc3339::{format_rfc3339_millis, now_unix_ms};
use hyp_harness::daemon::{LocalDaemon, LocalDaemonConfig};
use hyp_node::adapters::{GitHubPublicAdapter, GitHubPublicConfig};
use hyp_node::engine::{
    E2eePolicy, EscalationConfig, GuestPairingConfig, NodeConfig, NodeProfile, TopicConfig,
    UnifiedNode,
};
use hyp_node::gates::{SecurityGateConfig, SecurityGatePipeline};
use hyp_proto::address::{LOCAL_NODE_ID, NodeId, is_valid_node_id};
use hyp_proto::scopes::ScopePreset;
use hyp_store::{NodeDb, PeerStatus};
use serde_json::{Value, json};
use std::fs;
use std::io::Write as _;
use std::net::SocketAddr;
use std::path::PathBuf;
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

    if let Some(ref cfg) = loaded {
        node_cfg.require_pairing = cfg.require_pairing;
        node_cfg.e2ee_policy = if cfg.require_e2ee {
            E2eePolicy::Required
        } else {
            E2eePolicy::Prefer
        };

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

        // Parse `sources` entries (currently `kind == "github-public"`).
        if let Some(sources_val) = cfg.raw.get("sources") {
            let secrets = open_secret_store(&state_dir, explicit_state);
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
    }

    let start_local_daemon = !args.no_local_socket
        && (matches!(profile, NodeProfile::Local | NodeProfile::P2p) || args.socket.is_some());
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
        let github_public_enabled = if let Some(gh_cfg) = github_public_cfg {
            let adapter = Arc::new(
                GitHubPublicAdapter::new(gh_cfg)
                    .map_err(|e| format!("Failed to initialize github-public adapter: {e}"))?,
            );
            node.attach_github_public(adapter)
                .await
                .map_err(|e| format!("Failed to attach github-public adapter: {e}"))?;
            true
        } else {
            false
        };
        let guest_pairing_enabled = node.config().guest_pairing.enabled;

        let local_daemon = if start_local_daemon {
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
            let local_cfg = LocalDaemonConfig {
                socket_path: explicit_socket,
                ..Default::default()
            };
            let daemon = LocalDaemon::start(Arc::clone(&node), Some(pipeline), local_cfg)
                .await
                .map_err(|e| format!("Failed to start local harness IPC daemon: {e}"))?;
            Some(daemon)
        } else {
            None
        };

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
            "stateDir": state_dir.display().to_string(),
            "configPath": loaded.as_ref().map(|c| c.path.display().to_string()),
            "guestPairingEnabled": guest_pairing_enabled,
            "githubPublicEnabled": github_public_enabled,
            "connectedPeers": connected_peers,
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
            if let Some(addr) = bound_addr {
                println!("      Peer HTTP:   http://{addr} (GET /v1/manifest, GET /v1/health)");
            } else {
                println!("      Peer HTTP:   disabled (local profile)");
            }
            if guest_pairing_enabled {
                println!("      Guest Pair:  enabled (POST /v1/guest/pair -> guest-ro)");
            }
            if github_public_enabled {
                println!("      GitHub Pub:  enabled (demand-driven ETag poller)");
            }
            if !connected_peers.is_empty() {
                println!(
                    "      Peers:       {} connected ({})",
                    connected_peers.len(),
                    connected_peers.join(", ")
                );
            }
            for w in &warnings {
                println!("WARN  {w}");
            }
            let _ = std::io::stdout().flush();
        }

        wait_for_shutdown_signal().await;

        if let Some(daemon) = local_daemon {
            daemon.stop().await;
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

        return Ok(Some(cfg));
    }

    Ok(None)
}
