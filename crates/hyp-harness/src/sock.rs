//! Local daemon NDJSON client for `connector.sock` (Unix domain sockets) and
//! `connector.addr` / loopback TCP (`127.0.0.1:<port>`) on Windows.
//!
//! Provides BOTH:
//! - A **zero-Tokio synchronous fast-path** (`std::os::unix::net::UnixStream` on Unix,
//!   loopback `std::net::TcpStream` on Windows) for `hyp hook`, keeping cold-start
//!   latency at 1–3 ms.
//! - An **async Tokio client** (`tokio::net::UnixStream` on Unix, loopback
//!   `tokio::net::TcpStream` on Windows) with bounded NDJSON line reading for
//!   `hyp mcp`, `hyp wait`, and `hyp watch`.

use serde_json::{Map, Value};
use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::SocketAddr;
#[cfg(unix)]
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::pin::Pin;
#[cfg(unix)]
use std::task::{Context, Poll};
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};
#[cfg(unix)]
use tokio::io::{AsyncRead, ReadBuf};
#[cfg(unix)]
use tokio::net::UnixStream as TokioUnixStream;

/// Platform-native default daemon socket/address filename inside `<state_dir>`.
#[cfg(unix)]
pub const DEFAULT_SOCKET_FILENAME: &str = "connector.sock";
#[cfg(not(unix))]
pub const DEFAULT_SOCKET_FILENAME: &str = "connector.addr";

/// Platform-native async read half for local daemon NDJSON streams
/// (supports both Unix domain sockets and loopback TCP `connector.addr` on Unix).
#[cfg(unix)]
#[derive(Debug)]
pub enum DaemonReadHalf {
    Unix(tokio::net::unix::OwnedReadHalf),
    Tcp(tokio::net::tcp::OwnedReadHalf),
}

/// Platform-native async write half for local daemon NDJSON streams
/// (supports both Unix domain sockets and loopback TCP `connector.addr` on Unix).
#[cfg(unix)]
#[derive(Debug)]
pub enum DaemonWriteHalf {
    Unix(tokio::net::unix::OwnedWriteHalf),
    Tcp(tokio::net::tcp::OwnedWriteHalf),
}

#[cfg(unix)]
impl AsyncRead for DaemonReadHalf {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Unix(u) => Pin::new(u).poll_read(cx, buf),
            Self::Tcp(t) => Pin::new(t).poll_read(cx, buf),
        }
    }
}

#[cfg(unix)]
impl AsyncWrite for DaemonWriteHalf {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Unix(u) => Pin::new(u).poll_write(cx, buf),
            Self::Tcp(t) => Pin::new(t).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Unix(u) => Pin::new(u).poll_flush(cx),
            Self::Tcp(t) => Pin::new(t).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Unix(u) => Pin::new(u).poll_shutdown(cx),
            Self::Tcp(t) => Pin::new(t).poll_shutdown(cx),
        }
    }
}

/// Platform-native async read half for local daemon NDJSON streams (Windows TCP loopback).
#[cfg(not(unix))]
pub type DaemonReadHalf = tokio::net::tcp::OwnedReadHalf;
/// Platform-native async write half for local daemon NDJSON streams (Windows TCP loopback).
#[cfg(not(unix))]
pub type DaemonWriteHalf = tokio::net::tcp::OwnedWriteHalf;

/// Maximum NDJSON line size on `connector.sock` (matches `MAX_SOCKET_LINE_BYTES` in `src/daemon.ts`).
pub const MAX_SOCKET_LINE_BYTES: usize = 1024 * 1024;

/// Maximum plugin fd-3 NDJSON frame size (64 KiB).
pub const MAX_FRAME_BYTES: usize = 64 * 1024;

/// Default synchronous RPC timeout for hooks (matches `daemonRpc` in `src/hooks.ts`).
pub const DEFAULT_HOOK_TIMEOUT: Duration = Duration::from_millis(2_000);

#[derive(Debug, Error)]
pub enum SockError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("NDJSON line exceeded maximum size of {max} bytes")]
    LineTooLarge { max: usize },
    #[error("Invalid UTF-8 in NDJSON frame")]
    InvalidUtf8,
    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Timed out after {0:?}")]
    Timeout(Duration),
}

/// Result of a single-shot `connector.sock` RPC call (matches `DaemonRpcResult` in `src/hooks.ts`).
#[derive(Debug, Clone, PartialEq)]
pub struct DaemonRpcResult {
    pub ok: bool,
    pub result: Option<Map<String, Value>>,
    pub error: Option<String>,
}

impl DaemonRpcResult {
    pub fn fail() -> Self {
        Self {
            ok: false,
            result: None,
            error: None,
        }
    }

    pub fn err(msg: impl Into<String>) -> Self {
        Self {
            ok: false,
            result: None,
            error: Some(msg.into()),
        }
    }

    pub fn ok(result: Map<String, Value>) -> Self {
        Self {
            ok: true,
            result: Some(result),
            error: None,
        }
    }
}

/// Resolves the default `connector.sock` (or `connector.addr` on Windows) path matching
/// `hyp daemon` (`config_file.rs:resolve_state_dir`) while preserving legacy v1 compatibility:
/// 1. `HYPHAE_SOCKET` or `AGENTS_MESH_SOCKET` -> exact path
/// 2. `HYPHAE_STATE_DIR` -> `<dir>/<DEFAULT_SOCKET_FILENAME>`
/// 3. `HYPHAE_CONFIG_DIR` -> `<dir>/<DEFAULT_SOCKET_FILENAME>` (falls back to
///    `<dir>/state/<DEFAULT_SOCKET_FILENAME>` only when v2 socket & `node.json` are absent
///    and the legacy v1 `state/` socket exists)
/// 4. `$XDG_CONFIG_HOME` (or `$HOME/.config` / `$USERPROFILE/.config`) ->
///    `hyphae/<DEFAULT_SOCKET_FILENAME>` (with legacy fallbacks for
///    `hyphae/state/<DEFAULT_SOCKET_FILENAME>` and `agents-mesh/state/<DEFAULT_SOCKET_FILENAME>`).
pub fn default_socket_path() -> PathBuf {
    resolve_socket_path_with(|k| std::env::var(k).ok(), |p| p.exists())
}

/// Pure, testable socket path resolver.
pub fn resolve_socket_path_with<F, E>(get_env: F, path_exists: E) -> PathBuf
where
    F: Fn(&str) -> Option<String>,
    E: Fn(&Path) -> bool,
{
    let non_empty = |k: &str| get_env(k).filter(|v| !v.is_empty());

    if let Some(sock) = non_empty("HYPHAE_SOCKET").or_else(|| non_empty("AGENTS_MESH_SOCKET")) {
        return PathBuf::from(sock);
    }
    if let Some(state_dir) = non_empty("HYPHAE_STATE_DIR") {
        return PathBuf::from(state_dir).join(DEFAULT_SOCKET_FILENAME);
    }
    if let Some(config_dir) = non_empty("HYPHAE_CONFIG_DIR") {
        let cfg_dir = PathBuf::from(config_dir);
        let v2_sock = cfg_dir.join(DEFAULT_SOCKET_FILENAME);
        let v1_sock = cfg_dir.join("state").join(DEFAULT_SOCKET_FILENAME);
        if path_exists(&v2_sock) || path_exists(&cfg_dir.join("node.json")) {
            return v2_sock;
        }
        if path_exists(&v1_sock) {
            return v1_sock;
        }
        return v2_sock;
    }

    let base = non_empty("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            if let Some(home) = non_empty("HOME") {
                PathBuf::from(home).join(".config")
            } else if let Some(user_profile) = non_empty("USERPROFILE") {
                PathBuf::from(user_profile).join(".config")
            } else if cfg!(windows) {
                if let Some(local_app_data) = non_empty("LOCALAPPDATA") {
                    PathBuf::from(local_app_data)
                } else {
                    PathBuf::from(".").join(".config")
                }
            } else {
                PathBuf::from(".").join(".config")
            }
        });

    let primary = base.join("hyphae");
    let legacy = base.join("agents-mesh");
    let primary_v2 = primary.join(DEFAULT_SOCKET_FILENAME);
    let primary_v1 = primary.join("state").join(DEFAULT_SOCKET_FILENAME);
    let legacy_v1 = legacy.join("state").join(DEFAULT_SOCKET_FILENAME);

    if path_exists(&primary_v2) || path_exists(&primary.join("node.json")) {
        return primary_v2;
    }
    if path_exists(&primary_v1) {
        return primary_v1;
    }
    if !path_exists(&primary.join("connector.json"))
        && (path_exists(&legacy_v1) || path_exists(&legacy.join("connector.json")))
    {
        return legacy_v1;
    }
    primary_v2
}

/// Convenience helper for testing with an explicit env map.
pub fn resolve_socket_path_from_map(
    env: &HashMap<String, String>,
    path_exists: impl Fn(&Path) -> bool,
) -> PathBuf {
    resolve_socket_path_with(|k| env.get(k).cloned(), path_exists)
}

/// Reads a single `\n`-terminated line up to `max_bytes` synchronously without unbounded allocation.
/// Returns `Ok(None)` on clean EOF with zero trailing bytes.
pub fn read_bounded_line_sync(
    reader: &mut impl BufRead,
    max_bytes: usize,
) -> Result<Option<String>, SockError> {
    let mut buf = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            if buf.is_empty() {
                return Ok(None);
            }
            break;
        }
        if let Some(pos) = available.iter().position(|&b| b == b'\n') {
            if buf.len() + pos > max_bytes {
                return Err(SockError::LineTooLarge { max: max_bytes });
            }
            buf.extend_from_slice(&available[..pos]);
            reader.consume(pos + 1);
            if buf.last() == Some(&b'\r') {
                buf.pop();
            }
            break;
        }
        let len = available.len();
        if buf.len() + len > max_bytes {
            return Err(SockError::LineTooLarge { max: max_bytes });
        }
        buf.extend_from_slice(available);
        reader.consume(len);
    }
    String::from_utf8(buf)
        .map(Some)
        .map_err(|_| SockError::InvalidUtf8)
}

/// Reads a single `\n`-terminated line up to `max_bytes` asynchronously without unbounded allocation.
/// Returns `Ok(None)` on clean EOF with zero trailing bytes.
pub async fn read_bounded_line_async(
    reader: &mut (impl AsyncBufRead + Unpin),
    max_bytes: usize,
) -> Result<Option<String>, SockError> {
    let mut buf = Vec::new();
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            if buf.is_empty() {
                return Ok(None);
            }
            break;
        }
        if let Some(pos) = available.iter().position(|&b| b == b'\n') {
            if buf.len() + pos > max_bytes {
                return Err(SockError::LineTooLarge { max: max_bytes });
            }
            buf.extend_from_slice(&available[..pos]);
            reader.consume(pos + 1);
            if buf.last() == Some(&b'\r') {
                buf.pop();
            }
            break;
        }
        let len = available.len();
        if buf.len() + len > max_bytes {
            return Err(SockError::LineTooLarge { max: max_bytes });
        }
        buf.extend_from_slice(available);
        reader.consume(len);
    }
    String::from_utf8(buf)
        .map(Some)
        .map_err(|_| SockError::InvalidUtf8)
}

/// Serializes `packet` as one compact NDJSON line and flushes it to an async writer.
pub async fn write_ndjson_line_async(
    writer: &mut (impl AsyncWrite + Unpin),
    packet: &Value,
) -> Result<(), SockError> {
    let mut bytes = serde_json::to_vec(packet)?;
    bytes.push(b'\n');
    writer.write_all(&bytes).await?;
    writer.flush().await?;
    Ok(())
}

/// Parses a single-shot daemon RPC response line into `DaemonRpcResult`.
pub fn parse_rpc_response_line(line: &str) -> DaemonRpcResult {
    let Ok(Value::Object(mut obj)) = serde_json::from_str::<Value>(line) else {
        return DaemonRpcResult::fail();
    };
    match obj.get("ok").and_then(Value::as_bool) {
        Some(true) => match obj.remove("result") {
            Some(Value::Object(res)) => DaemonRpcResult::ok(res),
            _ => DaemonRpcResult::fail(),
        },
        Some(false) => match obj.remove("error") {
            Some(Value::String(err)) => DaemonRpcResult::err(err),
            _ => DaemonRpcResult::fail(),
        },
        None => DaemonRpcResult::fail(),
    }
}

fn parse_loopback_addr(raw: &str) -> io::Result<SocketAddr> {
    let trimmed = raw.trim();
    let stripped = trimmed.strip_prefix("tcp://").unwrap_or(trimmed);
    let addr: SocketAddr = stripped.parse().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid daemon loopback address: {trimmed:?}"),
        )
    })?;
    if !addr.ip().is_loopback() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("refusing non-loopback daemon address: {addr}"),
        ));
    }
    Ok(addr)
}

fn read_small_addr_file(path: &Path) -> io::Result<String> {
    let file = std::fs::File::open(path)?;
    let mut buf = String::new();
    file.take(256).read_to_string(&mut buf)?;
    Ok(buf)
}

/// Resolves a loopback TCP `SocketAddr` (`127.0.0.1:<port>` or `[::1]:<port>`) for Windows
/// local daemon transport from:
/// 1. Direct address string in `socket_path` (e.g. `HYPHAE_SOCKET=127.0.0.1:41234`)
/// 2. Contents of `socket_path` (e.g. `.../state/connector.addr`)
/// 3. Sibling `connector.addr` alongside `socket_path` (e.g. when `.../state/connector.sock` is passed)
///
/// Fails closed if the parsed IP is not loopback.
pub fn resolve_loopback_addr(socket_path: &Path) -> io::Result<SocketAddr> {
    if let Some(raw) = socket_path.to_str() {
        let trimmed = raw.trim();
        let stripped = trimmed.strip_prefix("tcp://").unwrap_or(trimmed);
        if trimmed.starts_with("tcp://") || stripped.parse::<SocketAddr>().is_ok() {
            return parse_loopback_addr(trimmed);
        }
    }

    if let Ok(contents) = read_small_addr_file(socket_path) {
        return parse_loopback_addr(&contents);
    }

    let sibling = socket_path.with_file_name("connector.addr");
    if sibling != socket_path {
        if let Ok(contents) = read_small_addr_file(&sibling) {
            return parse_loopback_addr(&contents);
        }
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!(
            "no loopback daemon address found at {} or {}",
            socket_path.display(),
            sibling.display()
        ),
    ))
}

/// Auto-detects whether `socket_path` on Unix targets a loopback TCP endpoint
/// (`127.0.0.1:<port>`, `[::1]:<port>`, `tcp://...`, `connector.addr` / `*.addr`,
/// regular addr file, or sibling `connector.addr` when `connector.sock` is absent).
///
/// Strictly fails closed (`PermissionDenied` / `InvalidInput`) on any non-loopback IP.
#[cfg(unix)]
fn detect_loopback_tcp_target(socket_path: &Path) -> io::Result<Option<SocketAddr>> {
    if let Some(raw) = socket_path.to_str() {
        let trimmed = raw.trim();
        if trimmed.starts_with("tcp://") || trimmed.parse::<SocketAddr>().is_ok() {
            return parse_loopback_addr(trimmed).map(Some);
        }
    }

    let is_addr_name = socket_path
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n == "connector.addr")
        || socket_path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("addr"));
    if is_addr_name {
        let contents = read_small_addr_file(socket_path)?;
        return parse_loopback_addr(&contents).map(Some);
    }

    if let Ok(meta) = std::fs::metadata(socket_path) {
        if meta.is_file() {
            let contents = read_small_addr_file(socket_path)?;
            return parse_loopback_addr(&contents).map(Some);
        }
        return Ok(None);
    }

    let sibling = socket_path.with_file_name("connector.addr");
    if sibling != socket_path && sibling.is_file() {
        let contents = read_small_addr_file(&sibling)?;
        return parse_loopback_addr(&contents).map(Some);
    }

    Ok(None)
}

/// Connects asynchronously to the local daemon (auto-detecting Unix domain socket vs loopback TCP
/// on Unix; loopback TCP on Windows). Strictly fails closed on any non-loopback IP.
#[cfg(unix)]
pub async fn connect_daemon_async(
    socket_path: &Path,
) -> io::Result<(DaemonReadHalf, DaemonWriteHalf)> {
    if let Some(addr) = detect_loopback_tcp_target(socket_path)? {
        let stream = tokio::net::TcpStream::connect(addr).await?;
        let (r, w) = stream.into_split();
        return Ok((DaemonReadHalf::Tcp(r), DaemonWriteHalf::Tcp(w)));
    }
    let stream = TokioUnixStream::connect(socket_path).await?;
    let (r, w) = stream.into_split();
    Ok((DaemonReadHalf::Unix(r), DaemonWriteHalf::Unix(w)))
}

/// Connects asynchronously to the local daemon over loopback TCP on Windows.
#[cfg(not(unix))]
pub async fn connect_daemon_async(
    socket_path: &Path,
) -> io::Result<(DaemonReadHalf, DaemonWriteHalf)> {
    let addr = resolve_loopback_addr(socket_path)?;
    let stream = tokio::net::TcpStream::connect(addr).await?;
    Ok(stream.into_split())
}

fn daemon_rpc_sync_on_stream<S: Read + Write>(mut stream: S, packet: &Value) -> DaemonRpcResult {
    let Ok(mut payload) = serde_json::to_vec(packet) else {
        return DaemonRpcResult::fail();
    };
    payload.push(b'\n');
    if stream.write_all(&payload).is_err() {
        return DaemonRpcResult::fail();
    }

    let mut reader = BufReader::new(stream);
    match read_bounded_line_sync(&mut reader, MAX_SOCKET_LINE_BYTES) {
        Ok(Some(line)) => parse_rpc_response_line(&line),
        _ => DaemonRpcResult::fail(),
    }
}

/// Ultra-fast synchronous single-shot daemon RPC for hooks (zero Tokio overhead!).
/// Uses `std::os::unix::net::UnixStream` or loopback `std::net::TcpStream` (`connector.addr` /
/// `tcp://127.0.0.1:<port>`) on Unix, and loopback `std::net::TcpStream` on Windows.
/// Always fails closed on non-loopback IPs and fails open (`ok: false`) when daemon is offline,
/// timed out, or returns malformed data.
#[cfg(unix)]
pub fn daemon_rpc_sync(socket_path: &Path, packet: &Value, timeout: Duration) -> DaemonRpcResult {
    match detect_loopback_tcp_target(socket_path) {
        Ok(Some(addr)) => {
            let Ok(stream) = std::net::TcpStream::connect_timeout(&addr, timeout) else {
                return DaemonRpcResult::fail();
            };
            let _ = stream.set_read_timeout(Some(timeout));
            let _ = stream.set_write_timeout(Some(timeout));
            daemon_rpc_sync_on_stream(stream, packet)
        }
        Ok(None) => {
            let Ok(stream) = StdUnixStream::connect(socket_path) else {
                return DaemonRpcResult::fail();
            };
            let _ = stream.set_read_timeout(Some(timeout));
            let _ = stream.set_write_timeout(Some(timeout));
            daemon_rpc_sync_on_stream(stream, packet)
        }
        Err(_) => DaemonRpcResult::fail(),
    }
}

/// Ultra-fast synchronous single-shot loopback TCP RPC for hooks on Windows (zero Tokio overhead!).
#[cfg(not(unix))]
pub fn daemon_rpc_sync(socket_path: &Path, packet: &Value, timeout: Duration) -> DaemonRpcResult {
    let Ok(addr) = resolve_loopback_addr(socket_path) else {
        return DaemonRpcResult::fail();
    };
    let Ok(stream) = std::net::TcpStream::connect_timeout(&addr, timeout) else {
        return DaemonRpcResult::fail();
    };
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
    daemon_rpc_sync_on_stream(stream, packet)
}

/// Async single-shot daemon RPC (Unix domain socket on Unix, loopback TCP on Windows).
pub async fn daemon_rpc_async(
    socket_path: &Path,
    packet: &Value,
    timeout: Duration,
) -> DaemonRpcResult {
    let fut = async {
        let (read_half, mut write_half) = connect_daemon_async(socket_path).await.ok()?;
        write_ndjson_line_async(&mut write_half, packet)
            .await
            .ok()?;
        let mut reader = tokio::io::BufReader::new(read_half);
        let line = read_bounded_line_async(&mut reader, MAX_SOCKET_LINE_BYTES)
            .await
            .ok()??;
        Some(parse_rpc_response_line(&line))
    };
    tokio::time::timeout(timeout, fut)
        .await
        .ok()
        .flatten()
        .unwrap_or_else(DaemonRpcResult::fail)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn socket_path_resolution_matches_v2_default_and_legacy_v1_fallbacks() {
        let mut env = HashMap::new();
        env.insert("HOME".into(), "/home/alice".into());

        // v2 default (matching `hyp daemon` -> `~/.config/hyphae/connector.sock`)
        assert_eq!(
            resolve_socket_path_from_map(&env, |_| false),
            PathBuf::from("/home/alice/.config/hyphae").join(DEFAULT_SOCKET_FILENAME)
        );

        // v2 node.json or v2 socket takes precedence even if legacy state/ socket also exists
        assert_eq!(
            resolve_socket_path_from_map(&env, |p| {
                p.ends_with("hyphae/node.json")
                    || p.ends_with(format!("hyphae/state/{DEFAULT_SOCKET_FILENAME}"))
            }),
            PathBuf::from("/home/alice/.config/hyphae").join(DEFAULT_SOCKET_FILENAME)
        );
        assert_eq!(
            resolve_socket_path_from_map(&env, |p| {
                p.ends_with(format!("hyphae/{DEFAULT_SOCKET_FILENAME}"))
                    || p.ends_with(format!("hyphae/state/{DEFAULT_SOCKET_FILENAME}"))
            }),
            PathBuf::from("/home/alice/.config/hyphae").join(DEFAULT_SOCKET_FILENAME)
        );

        // Legacy v1 `hyphae/state/connector.sock` fallback when v2 files absent
        assert_eq!(
            resolve_socket_path_from_map(&env, |p| {
                p.ends_with(format!("hyphae/state/{DEFAULT_SOCKET_FILENAME}"))
            }),
            PathBuf::from("/home/alice/.config/hyphae/state").join(DEFAULT_SOCKET_FILENAME)
        );

        // Legacy v1 `agents-mesh/state/connector.sock` fallback when hyphae config absent
        assert_eq!(
            resolve_socket_path_from_map(&env, |p| p.ends_with("agents-mesh/connector.json")),
            PathBuf::from("/home/alice/.config/agents-mesh/state").join(DEFAULT_SOCKET_FILENAME)
        );
        assert_eq!(
            resolve_socket_path_from_map(&env, |p| {
                p.ends_with(format!("agents-mesh/state/{DEFAULT_SOCKET_FILENAME}"))
            }),
            PathBuf::from("/home/alice/.config/agents-mesh/state").join(DEFAULT_SOCKET_FILENAME)
        );

        // XDG_CONFIG_HOME overrides HOME/.config (v2 default)
        env.insert("XDG_CONFIG_HOME".into(), "/xdg".into());
        assert_eq!(
            resolve_socket_path_from_map(&env, |_| false),
            PathBuf::from("/xdg/hyphae").join(DEFAULT_SOCKET_FILENAME)
        );

        // HYPHAE_CONFIG_DIR overrides XDG (v2 default + legacy state/ fallback)
        env.insert("HYPHAE_CONFIG_DIR".into(), "/cfg".into());
        assert_eq!(
            resolve_socket_path_from_map(&env, |_| false),
            PathBuf::from("/cfg").join(DEFAULT_SOCKET_FILENAME)
        );
        assert_eq!(
            resolve_socket_path_from_map(&env, |p| {
                p.ends_with(format!("cfg/state/{DEFAULT_SOCKET_FILENAME}"))
            }),
            PathBuf::from("/cfg/state").join(DEFAULT_SOCKET_FILENAME)
        );
        assert_eq!(
            resolve_socket_path_from_map(&env, |p| {
                p.ends_with("cfg/node.json")
                    || p.ends_with(format!("cfg/state/{DEFAULT_SOCKET_FILENAME}"))
            }),
            PathBuf::from("/cfg").join(DEFAULT_SOCKET_FILENAME)
        );

        // HYPHAE_STATE_DIR overrides HYPHAE_CONFIG_DIR
        env.insert("HYPHAE_STATE_DIR".into(), "/state".into());
        assert_eq!(
            resolve_socket_path_from_map(&env, |_| false),
            PathBuf::from("/state").join(DEFAULT_SOCKET_FILENAME)
        );

        // AGENTS_MESH_SOCKET overrides state dir
        env.insert("AGENTS_MESH_SOCKET".into(), "/tmp/legacy.sock".into());
        assert_eq!(
            resolve_socket_path_from_map(&env, |_| false),
            PathBuf::from("/tmp/legacy.sock")
        );

        // HYPHAE_SOCKET wins over everything
        env.insert("HYPHAE_SOCKET".into(), "/tmp/explicit.sock".into());
        assert_eq!(
            resolve_socket_path_from_map(&env, |_| false),
            PathBuf::from("/tmp/explicit.sock")
        );

        // Windows parity: USERPROFILE/.config takes precedence over LOCALAPPDATA when HOME & XDG unset
        let mut win_env = HashMap::new();
        win_env.insert("USERPROFILE".into(), "/Users/bob".into());
        win_env.insert("LOCALAPPDATA".into(), "/Users/bob/AppData/Local".into());
        assert_eq!(
            resolve_socket_path_from_map(&win_env, |_| false),
            PathBuf::from("/Users/bob/.config/hyphae").join(DEFAULT_SOCKET_FILENAME)
        );
    }

    #[test]
    fn resolve_loopback_addr_supports_direct_file_sibling_and_rejects_non_loopback() {
        let dir = tempfile::tempdir().unwrap();

        // Direct loopback addresses (IPv4, IPv6, tcp:// prefix)
        assert_eq!(
            resolve_loopback_addr(Path::new("127.0.0.1:41234")).unwrap(),
            "127.0.0.1:41234".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            resolve_loopback_addr(Path::new("tcp://127.0.0.1:41235")).unwrap(),
            "127.0.0.1:41235".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            resolve_loopback_addr(Path::new("[::1]:41236")).unwrap(),
            "[::1]:41236".parse::<SocketAddr>().unwrap()
        );

        // Non-loopback IP rejected fail-closed!
        assert_eq!(
            resolve_loopback_addr(Path::new("192.168.1.5:41234"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            resolve_loopback_addr(Path::new("0.0.0.0:41234"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );

        // Direct connector.addr file and sibling lookup from connector.sock
        let addr_file = dir.path().join("connector.addr");
        std::fs::write(&addr_file, "127.0.0.1:52345\n").unwrap();
        assert_eq!(
            resolve_loopback_addr(&addr_file).unwrap(),
            "127.0.0.1:52345".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            resolve_loopback_addr(&dir.path().join("connector.sock")).unwrap(),
            "127.0.0.1:52345".parse::<SocketAddr>().unwrap()
        );

        // File containing non-loopback IP fails closed
        let bad_file = dir.path().join("bad.addr");
        std::fs::write(&bad_file, "10.0.0.1:52345\n").unwrap();
        assert_eq!(
            resolve_loopback_addr(&bad_file).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn bounded_line_reader_enforces_max_bytes() {
        let mut cursor = Cursor::new(b"hello\nworld\r\n".to_vec());
        assert_eq!(
            read_bounded_line_sync(&mut cursor, 64).unwrap(),
            Some("hello".into())
        );
        assert_eq!(
            read_bounded_line_sync(&mut cursor, 64).unwrap(),
            Some("world".into())
        );
        assert_eq!(read_bounded_line_sync(&mut cursor, 64).unwrap(), None);

        let oversized = vec![b'a'; MAX_FRAME_BYTES + 10];
        let mut over_cursor = Cursor::new(oversized);
        let err = read_bounded_line_sync(&mut over_cursor, MAX_FRAME_BYTES).unwrap_err();
        assert!(matches!(err, SockError::LineTooLarge { max } if max == MAX_FRAME_BYTES));
    }

    #[test]
    fn daemon_rpc_sync_fails_open_when_socket_missing() {
        let res = daemon_rpc_sync(
            Path::new("/nonexistent/hyphae-missing.sock"),
            &serde_json::json!({"type": "session.status", "sessionId": "claude:1"}),
            Duration::from_millis(100),
        );
        assert!(!res.ok);
    }

    #[tokio::test]
    async fn tcp_loopback_sync_and_async_rpc_roundtrip_and_non_loopback_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let addr_file = dir.path().join("connector.addr");
        std::fs::write(&addr_file, format!("{addr}\n")).unwrap();

        let server = tokio::spawn(async move {
            for _ in 0..3 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let (r, mut w) = stream.split();
                let mut reader = tokio::io::BufReader::new(r);
                let line = read_bounded_line_async(&mut reader, MAX_SOCKET_LINE_BYTES)
                    .await
                    .unwrap()
                    .unwrap();
                let req: Value = serde_json::from_str(&line).unwrap();
                let resp = serde_json::json!({
                    "ok": true,
                    "result": { "echoType": req["type"] }
                });
                write_ndjson_line_async(&mut w, &resp).await.unwrap();
            }
        });

        // 1. Async RPC via connector.addr file
        let async_res = daemon_rpc_async(
            &addr_file,
            &serde_json::json!({"type": "async.ping"}),
            Duration::from_secs(2),
        )
        .await;
        assert!(async_res.ok);
        assert_eq!(async_res.result.unwrap()["echoType"], "async.ping");

        // 2. Sync RPC via direct HYPHAE_SOCKET=127.0.0.1:<port> string
        let direct_path = PathBuf::from(addr.to_string());
        let sync_res = tokio::task::spawn_blocking(move || {
            daemon_rpc_sync(
                &direct_path,
                &serde_json::json!({"type": "sync.ping"}),
                Duration::from_secs(2),
            )
        })
        .await
        .unwrap();
        assert!(sync_res.ok);
        assert_eq!(sync_res.result.unwrap()["echoType"], "sync.ping");

        // 3. Async RPC via tcp://127.0.0.1:<port> string
        let tcp_url_path = PathBuf::from(format!("tcp://{addr}"));
        let tcp_url_res = daemon_rpc_async(
            &tcp_url_path,
            &serde_json::json!({"type": "tcp_url.ping"}),
            Duration::from_secs(2),
        )
        .await;
        assert!(tcp_url_res.ok);
        assert_eq!(tcp_url_res.result.unwrap()["echoType"], "tcp_url.ping");

        // 4. Non-loopback IPs MUST strictly fail closed on ALL platforms!
        assert_eq!(
            connect_daemon_async(Path::new("192.168.1.5:41234"))
                .await
                .expect_err("non-loopback direct IP must fail closed")
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            connect_daemon_async(Path::new("tcp://10.0.0.1:41234"))
                .await
                .expect_err("non-loopback tcp:// URL must fail closed")
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        let bad_addr_file = dir.path().join("bad.addr");
        std::fs::write(&bad_addr_file, "10.0.0.1:41234\n").unwrap();
        assert_eq!(
            connect_daemon_async(&bad_addr_file)
                .await
                .expect_err("non-loopback .addr file must fail closed")
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        let bad_sync = daemon_rpc_sync(
            &bad_addr_file,
            &serde_json::json!({"type": "bad.ping"}),
            Duration::from_millis(200),
        );
        assert!(!bad_sync.ok);

        server.await.unwrap();
    }
}
