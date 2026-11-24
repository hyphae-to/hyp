//! `hyp-rs node start` (alias `hyp-rs daemon`) — Unified Hyphae v2 Rust Node runtime.
//!
//! Loads v2 `node.json` (or auto-reads legacy v1 `connector.json`), initializes `UnifiedNode`
//! (`node.sqlite` WAL + persistent Ed25519/X25519 keys + exact zero-polling deadline scheduler),
//! optionally starts the HTTP/SSE Peer Server (`router`/`p2p` or explicit `--bind`), writes
//! `node.pid` + `node.status.json`, and shuts down gracefully on `SIGINT`/`SIGTERM`.

use crate::config_file::{
    default_node_id, ensure_dir, load_node_or_legacy_config, profile_as_str,
    resolve_config_path_for_read, resolve_state_dir, write_atomic_file, write_atomic_json,
};
use crate::ui::{EXIT_ERROR, EXIT_OK, EXIT_USAGE, JsonEnvelope, emit_error, print_json};
use clap::{Args, Subcommand, ValueEnum};
use hyp_crypto::keystore::SecretBackend;
use hyp_crypto::rfc3339::{format_rfc3339_millis, now_unix_ms};
use hyp_node::engine::{E2eePolicy, NodeConfig, NodeProfile, UnifiedNode};
use hyp_proto::address::{LOCAL_NODE_ID, NodeId, is_valid_node_id};
use serde_json::json;
use std::fs;
use std::io::Write as _;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

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
                    Some("Verify node.json syntax or run `hyp-rs onboard`.".to_string()),
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
            Some("Check --config path or run `hyp-rs onboard`.".to_string()),
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
    if let Some(ref cfg) = loaded {
        node_cfg.require_pairing = cfg.require_pairing;
        node_cfg.e2ee_policy = if cfg.require_e2ee {
            E2eePolicy::Required
        } else {
            E2eePolicy::Prefer
        };
    }
    if args.state_dir.is_some() && std::env::var_os("HYPHAE_SECRET_BACKEND").is_none() {
        node_cfg.secret_backend = Some(SecretBackend::File);
    }

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

        let pid = std::process::id();
        let pid_path = state_dir.join("node.pid");
        let status_path = state_dir.join("node.status.json");
        let started_at = format_rfc3339_millis(now_unix_ms());
        let kid = node.identity().kid();
        let fingerprint = node.identity().fingerprint();
        let endpoint = bound_addr.map(|a| format!("http://{a}")).or_else(|| {
            node.config().public_endpoint.clone()
        });

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
            "stateDir": state_dir.display().to_string(),
            "configPath": loaded.as_ref().map(|c| c.path.display().to_string()),
            "startedAt": started_at,
        });
        write_atomic_json(&status_path, &status_doc, true)?;

        let mut warnings = Vec::new();
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
                    format!("hyp-rs status --state-dir {}", state_dir.display()),
                    format!("hyp-rs doctor --state-dir {}", state_dir.display()),
                ],
                error: None,
            };
            print_json(&envelope);
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
            if let Some(addr) = bound_addr {
                println!("      Peer HTTP:   http://{addr} (GET /v1/manifest)");
            } else {
                println!("      Peer HTTP:   disabled (local profile)");
            }
            for w in &warnings {
                println!("WARN  {w}");
            }
            let _ = std::io::stdout().flush();
        }

        wait_for_shutdown_signal().await;

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
