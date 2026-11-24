//! Unix domain socket NDJSON client for `connector.sock`.
//!
//! Provides BOTH:
//! - A **zero-Tokio synchronous fast-path** (`std::os::unix::net::UnixStream`) for `hyp-rs hook`,
//!   keeping cold-start latency at 1–3 ms.
//! - An **async Tokio client** (`tokio::net::UnixStream`) with bounded NDJSON line reading for
//!   `hyp-rs mcp`, `hyp-rs wait`, and `hyp-rs watch`.

use serde_json::{Map, Value};
use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UnixStream as TokioUnixStream;

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

/// Resolves the default `connector.sock` path matching `src/cli-fast.ts` and `src/cli-full.ts`:
/// 1. `HYPHAE_SOCKET` or `AGENTS_MESH_SOCKET`
/// 2. `HYPHAE_STATE_DIR` -> `<dir>/connector.sock`
/// 3. `HYPHAE_CONFIG_DIR` -> `<dir>/state/connector.sock`
/// 4. `$XDG_CONFIG_HOME` (or `$HOME/.config`) -> `hyphae/state/connector.sock`
///    (falls back to `agents-mesh/state/connector.sock` if `hyphae/connector.json` is absent
///    and `agents-mesh/connector.json` exists).
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
        return PathBuf::from(state_dir).join("connector.sock");
    }
    if let Some(config_dir) = non_empty("HYPHAE_CONFIG_DIR") {
        return PathBuf::from(config_dir)
            .join("state")
            .join("connector.sock");
    }

    let base = non_empty("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let home = non_empty("HOME").unwrap_or_else(|| ".".to_string());
            PathBuf::from(home).join(".config")
        });

    let primary = base.join("hyphae");
    let legacy = base.join("agents-mesh");
    let dir = if !path_exists(&primary.join("connector.json"))
        && path_exists(&legacy.join("connector.json"))
    {
        legacy
    } else {
        primary
    };
    dir.join("state").join("connector.sock")
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

/// Ultra-fast synchronous single-shot Unix socket RPC for hooks (zero Tokio overhead!).
/// Always fails open (returns `DaemonRpcResult { ok: false, .. }`) when daemon is offline,
/// timed out, or returns malformed data.
pub fn daemon_rpc_sync(socket_path: &Path, packet: &Value, timeout: Duration) -> DaemonRpcResult {
    let Ok(mut stream) = StdUnixStream::connect(socket_path) else {
        return DaemonRpcResult::fail();
    };
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

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

/// Async single-shot Unix socket RPC over `tokio::net::UnixStream`.
pub async fn daemon_rpc_async(
    socket_path: &Path,
    packet: &Value,
    timeout: Duration,
) -> DaemonRpcResult {
    let fut = async {
        let mut stream = TokioUnixStream::connect(socket_path).await.ok()?;
        write_ndjson_line_async(&mut stream, packet).await.ok()?;
        let mut reader = tokio::io::BufReader::new(stream);
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
    fn socket_path_resolution_matches_ts_precedence() {
        let mut env = HashMap::new();
        env.insert("HOME".into(), "/home/alice".into());
        assert_eq!(
            resolve_socket_path_from_map(&env, |_| false),
            PathBuf::from("/home/alice/.config/hyphae/state/connector.sock")
        );

        // Legacy agents-mesh fallback when hyphae/connector.json missing & legacy exists
        assert_eq!(
            resolve_socket_path_from_map(&env, |p| p.ends_with("agents-mesh/connector.json")),
            PathBuf::from("/home/alice/.config/agents-mesh/state/connector.sock")
        );

        // XDG_CONFIG_HOME overrides HOME/.config
        env.insert("XDG_CONFIG_HOME".into(), "/xdg".into());
        assert_eq!(
            resolve_socket_path_from_map(&env, |_| false),
            PathBuf::from("/xdg/hyphae/state/connector.sock")
        );

        // HYPHAE_CONFIG_DIR overrides XDG
        env.insert("HYPHAE_CONFIG_DIR".into(), "/cfg".into());
        assert_eq!(
            resolve_socket_path_from_map(&env, |_| false),
            PathBuf::from("/cfg/state/connector.sock")
        );

        // HYPHAE_STATE_DIR overrides HYPHAE_CONFIG_DIR
        env.insert("HYPHAE_STATE_DIR".into(), "/state".into());
        assert_eq!(
            resolve_socket_path_from_map(&env, |_| false),
            PathBuf::from("/state/connector.sock")
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
}
