//! Zero-polling blocking waiter (`hyp wait`) and streaming watcher (`hyp watch`)
//! on `connector.sock`, matching `src/wait.ts` flags, timeouts, formatting, and signal handling.

use crate::sock::{
    MAX_SOCKET_LINE_BYTES, connect_daemon_async, read_bounded_line_async, write_ndjson_line_async,
};
use serde_json::{Map, Value, json};
use std::collections::HashMap;
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::Duration;
use thiserror::Error;
use tokio::io::BufReader;

#[cfg(unix)]
struct ShutdownSignal {
    sigint: tokio::signal::unix::Signal,
    sigterm: tokio::signal::unix::Signal,
}

#[cfg(unix)]
impl ShutdownSignal {
    fn new() -> io::Result<Self> {
        use tokio::signal::unix::{SignalKind, signal};
        Ok(Self {
            sigint: signal(SignalKind::interrupt())?,
            sigterm: signal(SignalKind::terminate())?,
        })
    }

    async fn recv(&mut self) {
        tokio::select! {
            _ = self.sigint.recv() => {}
            _ = self.sigterm.recv() => {}
        }
    }
}

#[cfg(not(unix))]
struct ShutdownSignal;

#[cfg(not(unix))]
impl ShutdownSignal {
    fn new() -> io::Result<Self> {
        Ok(Self)
    }

    async fn recv(&mut self) {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitMode {
    Once,
    Stream,
}

impl WaitMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            WaitMode::Once => "once",
            WaitMode::Stream => "stream",
        }
    }
}

#[derive(Debug, Clone)]
pub struct WaitOptions {
    pub socket_path: PathBuf,
    pub mode: WaitMode,
    pub session_id: Option<String>,
    pub handle: Option<String>,
    pub timeout_seconds: Option<f64>,
    pub json: bool,
}

#[derive(Debug, Error)]
pub enum WaitError {
    #[error("Could not infer session ID. Pass --session <id> or --handle <handle>.")]
    MissingSession,
    #[error("Could not connect to hyp daemon at {path}: {source}")]
    Connect {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("{0}")]
    Daemon(String),
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

/// Resolves the session ID automatically from harness environment variables:
/// 1. `ANTIGRAVITY_SOURCE_METADATA` (`tool.conversationId` -> `antigravity:<id>`)
/// 2. `CLAUDE_SESSION_ID` (`claude:<id>`)
/// 3. `CODEX_THREAD_ID` (`codex:<id>`)
pub fn infer_session_id_from_env() -> Option<String> {
    infer_session_id_with(|k| std::env::var(k).ok())
}

pub fn infer_session_id_with<F>(get_env: F) -> Option<String>
where
    F: Fn(&str) -> Option<String>,
{
    if let Some(raw) = get_env("ANTIGRAVITY_SOURCE_METADATA").filter(|v| !v.is_empty()) {
        if let Ok(Value::Object(parsed)) = serde_json::from_str::<Value>(&raw) {
            if let Some(conv_id) = parsed
                .get("tool")
                .and_then(Value::as_object)
                .and_then(|t| t.get("conversationId"))
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
            {
                return Some(format!("antigravity:{conv_id}"));
            }
        }
    }
    if let Some(id) = get_env("CLAUDE_SESSION_ID").filter(|v| !v.is_empty()) {
        return Some(format!("claude:{id}"));
    }
    if let Some(id) = get_env("CODEX_THREAD_ID").filter(|v| !v.is_empty()) {
        return Some(format!("codex:{id}"));
    }
    None
}

pub fn infer_session_id_from_map(env: &HashMap<String, String>) -> Option<String> {
    infer_session_id_with(|k| env.get(k).cloned())
}

/// Formats `wait.items` payload for `mode: once` (plain text or `--json` agent-first envelope).
pub fn format_once_output(items: &[Map<String, Value>], as_json: bool) -> String {
    if as_json {
        let envelope = json!({
            "ok": true,
            "command": "wait",
            "data": { "items": items }
        });
        return format!(
            "{}\n",
            serde_json::to_string(&envelope).unwrap_or_else(|_| "{}".into())
        );
    }
    let formatted = items
        .iter()
        .filter_map(|item| item.get("text").and_then(Value::as_str))
        .filter(|text| !text.is_empty())
        .collect::<Vec<_>>()
        .join("\n\n---\n\n");
    format!("{formatted}\n")
}

/// Formats a single item line for `mode: stream` (`hyp watch`), matching `src/wait.ts`.
pub fn format_stream_item(item: &Map<String, Value>) -> String {
    let mut obj = Map::new();
    if let Some(router) = item.get("router") {
        obj.insert("router".into(), router.clone());
    }
    if let Some(received) = item.get("received") {
        obj.insert("received".into(), received.clone());
    }
    if let Some(text) = item.get("text") {
        obj.insert("text".into(), text.clone());
    }
    format!(
        "{}\n",
        serde_json::to_string(&Value::Object(obj)).unwrap_or_else(|_| "{}".into())
    )
}

/// Runs the blocking zero-CPU waiter/watcher until items arrive (`Once`), timeout, EOF, or signal.
pub async fn run_wait(options: WaitOptions) -> Result<i32, WaitError> {
    let mut stdout = io::stdout();
    run_wait_to_writer(options, &mut stdout).await
}

/// Testable implementation writing formatted output to any `Write` sink.
pub async fn run_wait_to_writer<W: Write>(
    options: WaitOptions,
    out: &mut W,
) -> Result<i32, WaitError> {
    let session_id = match (&options.session_id, &options.handle) {
        (Some(sid), _) => Some(sid.clone()),
        (None, Some(_)) => None,
        (None, None) => infer_session_id_from_env(),
    };
    if session_id.is_none() && options.handle.is_none() {
        return Err(WaitError::MissingSession);
    }

    let (read_half, mut write_half) = connect_daemon_async(&options.socket_path)
        .await
        .map_err(|source| WaitError::Connect {
            path: options.socket_path.display().to_string(),
            source,
        })?;
    let mut reader = BufReader::new(read_half);

    let mut sub = Map::new();
    sub.insert("type".into(), json!("wait.subscribe"));
    sub.insert("mode".into(), json!(options.mode.as_str()));
    if let Some(sid) = session_id {
        sub.insert("sessionId".into(), json!(sid));
    }
    if let Some(handle) = options.handle {
        sub.insert("handle".into(), json!(handle));
    }
    write_ndjson_line_async(&mut write_half, &Value::Object(sub))
        .await
        .map_err(|e| WaitError::Daemon(e.to_string()))?;

    let mut shutdown = ShutdownSignal::new()?;

    let timeout_sleep = options
        .timeout_seconds
        .filter(|&secs| secs.is_finite() && secs > 0.0)
        .map(|secs| tokio::time::sleep(Duration::from_secs_f64(secs)));
    tokio::pin!(timeout_sleep);

    loop {
        let line_opt = tokio::select! {
            _ = shutdown.recv() => return Ok(0),
            _ = async {
                if let Some(sleep) = timeout_sleep.as_mut().as_pin_mut() {
                    sleep.await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => return Ok(0),
            res = read_bounded_line_async(&mut reader, MAX_SOCKET_LINE_BYTES) => {
                match res {
                    Ok(Some(line)) => line,
                    Ok(None) => return Ok(0),
                    Err(_) => return Ok(0),
                }
            }
        };

        let Ok(Value::Object(packet)) = serde_json::from_str::<Value>(&line_opt) else {
            continue;
        };

        match packet.get("type").and_then(Value::as_str) {
            Some("wait.error") => {
                let msg = packet
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("Wait failed")
                    .to_string();
                return Err(WaitError::Daemon(msg));
            }
            Some("wait.items") => {
                let Some(raw_items) = packet.get("items").and_then(Value::as_array) else {
                    continue;
                };
                let items: Vec<Map<String, Value>> = raw_items
                    .iter()
                    .filter_map(|v| v.as_object().cloned())
                    .collect();

                if options.mode == WaitMode::Once {
                    let rendered = format_once_output(&items, options.json);
                    out.write_all(rendered.as_bytes())?;
                    out.flush()?;
                    return Ok(0);
                } else {
                    for item in &items {
                        let rendered = format_stream_item(item);
                        out.write_all(rendered.as_bytes())?;
                    }
                    out.flush()?;
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn infers_session_ids_from_antigravity_claude_and_codex_env() {
        let mut ag = HashMap::new();
        ag.insert(
            "ANTIGRAVITY_SOURCE_METADATA".into(),
            json!({"tool": {"conversationId": "abc-123"}}).to_string(),
        );
        assert_eq!(
            infer_session_id_from_map(&ag).as_deref(),
            Some("antigravity:abc-123")
        );

        let mut claude = HashMap::new();
        claude.insert("CLAUDE_SESSION_ID".into(), "sess-9".into());
        assert_eq!(
            infer_session_id_from_map(&claude).as_deref(),
            Some("claude:sess-9")
        );

        let mut codex = HashMap::new();
        codex.insert("CODEX_THREAD_ID".into(), "thr-7".into());
        assert_eq!(
            infer_session_id_from_map(&codex).as_deref(),
            Some("codex:thr-7")
        );

        assert_eq!(infer_session_id_from_map(&HashMap::new()), None);
    }

    #[test]
    fn formats_once_and_stream_outputs_identically_to_ts() {
        let items = vec![
            json!({"router": "primary", "received": 1700000000, "text": "msg 1"})
                .as_object()
                .unwrap()
                .clone(),
            json!({"router": "primary", "received": 1700000001, "text": "msg 2"})
                .as_object()
                .unwrap()
                .clone(),
        ];

        assert_eq!(format_once_output(&items, false), "msg 1\n\n---\n\nmsg 2\n");

        let json_out: Value = serde_json::from_str(&format_once_output(&items, true)).unwrap();
        assert_eq!(json_out["ok"], true);
        assert_eq!(json_out["command"], "wait");
        assert_eq!(json_out["data"]["items"].as_array().unwrap().len(), 2);

        let stream_line: Value = serde_json::from_str(&format_stream_item(&items[0])).unwrap();
        assert_eq!(
            stream_line,
            json!({"router": "primary", "received": 1700000000, "text": "msg 1"})
        );
    }

    #[cfg(not(unix))]
    #[tokio::test]
    async fn windows_tcp_loopback_wait_once_receives_items() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (r, mut w) = stream.split();
            let mut reader = BufReader::new(r);
            let sub_line = read_bounded_line_async(&mut reader, MAX_SOCKET_LINE_BYTES)
                .await
                .unwrap()
                .unwrap();
            let sub: Value = serde_json::from_str(&sub_line).unwrap();
            assert_eq!(sub["type"], "wait.subscribe");
            assert_eq!(sub["mode"], "once");
            assert_eq!(sub["sessionId"], "claude:win-1");

            write_ndjson_line_async(
                &mut w,
                &json!({
                    "type": "wait.items",
                    "items": [{"router": "primary", "received": 1, "text": "hello windows"}]
                }),
            )
            .await
            .unwrap();
        });

        let mut buf = Vec::new();
        let code = run_wait_to_writer(
            WaitOptions {
                socket_path: PathBuf::from(addr.to_string()),
                mode: WaitMode::Once,
                session_id: Some("claude:win-1".into()),
                handle: None,
                timeout_seconds: Some(3.0),
                json: false,
            },
            &mut buf,
        )
        .await
        .unwrap();
        assert_eq!(code, 0);
        assert_eq!(String::from_utf8(buf).unwrap(), "hello windows\n");
        server.await.unwrap();
    }
}
