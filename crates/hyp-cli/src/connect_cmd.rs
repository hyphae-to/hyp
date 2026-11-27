//! `hyp connect` — zero-banner bidirectional stdio bridge (`stdin` <-> `stdout`) to a local
//! Hyphae v2 node's `peer.sock` Unix domain socket (or loopback `listen.bind` TCP fallback).
//!
//! Designed to be invoked as the remote command of `ssh://` peer links:
//! `ssh -o BatchMode=yes -T -- <target> "command -v hyp >/dev/null 2>&1 && exec hyp connect || exec \"$HOME/.local/bin/hyp\" connect"`
//!
//! Protocol invariant: NEVER write banners, logs, or error text to `stdout` — `stdout` carries
//! raw HTTP/1.1 + SSE wire bytes exclusively. All diagnostics go strictly to `stderr`.

use crate::config_file::{
    load_node_or_legacy_config, resolve_config_path_for_read, resolve_state_dir,
};
use crate::ui::{CliError, EXIT_OK};
use clap::Args;
use hyp_node::engine::DEFAULT_PEER_SOCKET_FILENAME;
use serde_json::Value;
use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
#[cfg(unix)]
use std::path::Path;
use std::path::PathBuf;
use std::process::ExitCode;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

#[derive(Args)]
pub struct ConnectArgs {
    /// Explicit state directory containing peer.sock, node.status.json, and node.json
    #[arg(long)]
    pub state_dir: Option<PathBuf>,
    /// Explicit node.json (or legacy connector.json) path
    #[arg(long)]
    pub config: Option<PathBuf>,
    /// Explicit peer.sock Unix domain socket path
    #[arg(long)]
    pub socket: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ConnectTarget {
    #[cfg(unix)]
    Unix(PathBuf),
    LoopbackTcp(SocketAddr),
}

fn normalize_loopback_target(addr: SocketAddr) -> Option<SocketAddr> {
    let ip = match addr.ip() {
        IpAddr::V4(v4) if v4.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(v6) if v6.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        other => other,
    };
    if ip.is_loopback() && addr.port() > 0 {
        Some(SocketAddr::new(ip, addr.port()))
    } else {
        None
    }
}

#[cfg(unix)]
fn resolve_path_relative(raw: &str, base_dir: Option<&Path>) -> PathBuf {
    let p = PathBuf::from(raw);
    if p.is_absolute() {
        p
    } else if let Some(base) = base_dir {
        base.join(p)
    } else {
        p
    }
}

fn resolve_connect_target(args: &ConnectArgs) -> Result<ConnectTarget, String> {
    if let Some(ref sock) = args.socket {
        #[cfg(unix)]
        {
            return Ok(ConnectTarget::Unix(sock.clone()));
        }
        #[cfg(not(unix))]
        {
            let _ = sock;
            return Err("`hyp connect --socket` requires Unix domain sockets".to_string());
        }
    }

    let config_path =
        resolve_config_path_for_read(args.config.as_deref(), args.state_dir.as_deref(), None);
    let loaded = if config_path.exists() {
        load_node_or_legacy_config(&config_path).ok()
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

    let status_doc: Option<Value> = fs::read_to_string(state_dir.join("node.status.json"))
        .ok()
        .and_then(|raw| serde_json::from_str::<Value>(&raw).ok());

    #[cfg(unix)]
    {
        let mut candidates: Vec<PathBuf> = Vec::new();
        if let Some(ps) = status_doc
            .as_ref()
            .and_then(|v| v.get("peerSocket"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            candidates.push(PathBuf::from(ps));
        }
        if let Some(cfg) = loaded.as_ref() {
            if let Some(ps) = cfg
                .raw
                .get("listen")
                .and_then(|l| l.get("peerSocket"))
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                candidates.push(resolve_path_relative(ps, cfg.path.parent()));
            }
        }
        candidates.push(state_dir.join(DEFAULT_PEER_SOCKET_FILENAME));

        for candidate in candidates {
            if candidate.exists() {
                return Ok(ConnectTarget::Unix(candidate));
            }
        }
    }

    // Loopback TCP fallback: check active bind recorded in node.status.json first, then node.json.
    if let Some(bind_str) = status_doc
        .as_ref()
        .and_then(|v| v.get("bind"))
        .and_then(Value::as_str)
    {
        if let Ok(addr) = bind_str.parse::<SocketAddr>() {
            if let Some(loopback) = normalize_loopback_target(addr) {
                return Ok(ConnectTarget::LoopbackTcp(loopback));
            }
        }
    }
    if let Some(addr) = loaded.as_ref().and_then(|c| c.bind_addr) {
        if let Some(loopback) = normalize_loopback_target(addr) {
            return Ok(ConnectTarget::LoopbackTcp(loopback));
        }
    }

    let expected_sock = state_dir.join(DEFAULT_PEER_SOCKET_FILENAME);
    Err(format!(
        "No reachable Hyphae peer socket ({}) or loopback listen.bind found in {}. Start the node with `hyp node start --profile p2p` (or `--peer-socket`).",
        expected_sock.display(),
        state_dir.display()
    ))
}

fn is_benign_close_error(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::NotConnected
            | io::ErrorKind::UnexpectedEof
    )
}

async fn bridge_stdio<S>(stream: S) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut stream_rd, mut stream_wr) = tokio::io::split(stream);
    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();

    let to_peer = async {
        let res = tokio::io::copy(&mut stdin, &mut stream_wr).await;
        let _ = stream_wr.shutdown().await;
        res
    };
    let from_peer = async {
        let res = tokio::io::copy(&mut stream_rd, &mut stdout).await;
        let _ = stdout.flush().await;
        res
    };

    tokio::pin!(to_peer);
    tokio::pin!(from_peer);

    let outcome = tokio::select! {
        res = &mut from_peer => {
            // Peer closed response stream (e.g. Connection: close or shutdown) and stdout is flushed.
            // Exit promptly without hanging on blocking stdin.
            res.map(|_| ())
        }
        res = &mut to_peer => {
            // Client closed stdin (EOF -> half-closed stream_wr). Drain remaining peer response bytes!
            let from_res = from_peer.await;
            match (res, from_res) {
                (Ok(_), Ok(_)) => Ok(()),
                (_, Err(e)) if !is_benign_close_error(&e) => Err(e),
                (Err(e), _) if !is_benign_close_error(&e) => Err(e),
                _ => Ok(()),
            }
        }
    };

    match outcome {
        Ok(()) => Ok(()),
        Err(e) if is_benign_close_error(&e) => Ok(()),
        Err(e) => Err(e),
    }
}

pub fn run_connect(args: ConnectArgs) -> crate::ui::CommandResult {
    crate::ui::CommandResult::new("connect", false, connect(args))
}

fn connect(args: ConnectArgs) -> Result<ExitCode, CliError> {
    let target = resolve_connect_target(&args)
        .map_err(|message| CliError::error("CONNECT_TARGET", message).plain())?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| {
            CliError::error(
                "RUNTIME_ERROR",
                format!("Failed to start async runtime: {error}"),
            )
            .plain()
        })?;

    let res: Result<(), String> = rt.block_on(async move {
        match target {
            #[cfg(unix)]
            ConnectTarget::Unix(path) => {
                let stream = tokio::net::UnixStream::connect(&path).await.map_err(|e| {
                    format!(
                        "Failed to connect to Hyphae peer socket {}: {e}",
                        path.display()
                    )
                })?;
                bridge_stdio(stream)
                    .await
                    .map_err(|e| format!("Peer socket stdio bridge error: {e}"))
            }
            ConnectTarget::LoopbackTcp(addr) => {
                let stream = tokio::net::TcpStream::connect(addr).await.map_err(|e| {
                    format!("Failed to connect to Hyphae loopback peer server {addr}: {e}")
                })?;
                let _ = stream.set_nodelay(true);
                bridge_stdio(stream)
                    .await
                    .map_err(|e| format!("Loopback TCP stdio bridge error: {e}"))
            }
        }
    });

    // Shut down runtime in the background so a blocked stdin `spawn_blocking` read never
    // delays process exit after the peer stream closes cleanly.
    rt.shutdown_background();

    res.map_err(|message| CliError::error("CONNECT_FAILED", message).plain())?;
    Ok(ExitCode::from(EXIT_OK))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn normalize_loopback_maps_wildcard_and_rejects_public_ips() {
        assert_eq!(
            normalize_loopback_target("0.0.0.0:8790".parse().unwrap()),
            Some("127.0.0.1:8790".parse().unwrap())
        );
        assert_eq!(
            normalize_loopback_target("[::]:8790".parse().unwrap()),
            Some("[::1]:8790".parse().unwrap())
        );
        assert_eq!(
            normalize_loopback_target("127.0.0.1:8790".parse().unwrap()),
            Some("127.0.0.1:8790".parse().unwrap())
        );
        assert_eq!(
            normalize_loopback_target("192.168.1.10:8790".parse().unwrap()),
            None
        );
        assert_eq!(
            normalize_loopback_target("127.0.0.1:0".parse().unwrap()),
            None
        );
    }

    #[test]
    fn resolve_connect_target_prefers_peer_sock_then_falls_back_to_loopback_tcp() {
        let dir = tempfile::tempdir().unwrap();
        let cfg_path = dir.path().join("node.json");
        fs::write(
            &cfg_path,
            serde_json::to_vec_pretty(&json!({
                "v": 2,
                "nodeId": "maple-relay",
                "profile": "p2p",
                "listen": { "bind": "127.0.0.1:8799" }
            }))
            .unwrap(),
        )
        .unwrap();

        // Without peer.sock, falls back cleanly to loopback TCP bind from node.json.
        let args = ConnectArgs {
            state_dir: Some(dir.path().to_path_buf()),
            config: Some(cfg_path.clone()),
            socket: None,
        };
        assert_eq!(
            resolve_connect_target(&args).unwrap(),
            ConnectTarget::LoopbackTcp("127.0.0.1:8799".parse().unwrap())
        );

        // When peer.sock exists on Unix, peer.sock takes precedence over TCP.
        #[cfg(unix)]
        {
            let sock_path = dir.path().join(DEFAULT_PEER_SOCKET_FILENAME);
            let _listener = std::os::unix::net::UnixListener::bind(&sock_path).unwrap();
            assert_eq!(
                resolve_connect_target(&args).unwrap(),
                ConnectTarget::Unix(sock_path)
            );
        }
    }
}
