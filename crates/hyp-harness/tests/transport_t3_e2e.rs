//! End-to-end tests for the native Rust T3 Code transport (`crates/hyp-harness/transport/src/transport/t3.rs`):
//! - Read-only `statev2.sqlite` resolution across v2 (`orchestration_v2_projection_*`) and v1
//!   (`projection_thread_*`) schemas, deleted/archived exclusion, fail-closed `CallerAmbiguous`,
//!   missing DB `CallerNotFound`, `verify_t3_thread_exists`, and `resolve_t3_caller_by_call_id`.
//! - Strict URL origin validation (`normalize_t3_server_url`).
//! - Full in-process Tokio loopback HTTP + real RFC 6455 WebSocket mock T3 server verifying:
//!   - `probe_t3_server` (authenticated & unauthenticated & error status)
//!   - `SecretStore` (file backend in `TempDir`) primary `"t3-auth-token"` & fallback `"t3-session-token"`
//!   - `PushMode::Queue` (idle -> `start_immediately`, active -> `queue_after_active`)
//!   - `PushMode::Interrupt` (active + steering -> `steer_active`, active + no steering -> `restart_active`)
//!   - `401` / `403` auth failure -> `PushOutcome::Hold { reason: "t3_auth_failed", .. }`
//!   - Missing secret -> `PushOutcome::Hold { reason: "t3_auth_missing", .. }`
//!   - Unreachable server -> `PushOutcome::Hold { reason: "t3_server_unreachable", .. }`
//!   - Effect `Exit` failure responses (`ProjectionStoreThreadNotFoundError`, generic projection error,
//!     deleted thread, `Die` defect, `dispatchCommand` failure)
//!   - Protocol robustness (interleaved Ping/Pong, fragmented `Exit` frame, unrelated server push events,
//!     and fail-closed rejection of tampered `Sec-WebSocket-Accept`).

mod common;

use common::test_digest;

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use hyp_crypto::{SecretBackend, SecretStore};
use hyp_harness::call_registry::CallerErrorCode;
use hyp_harness::transport::t3::{
    DEFAULT_T3_TOKEN_SECRET, FALLBACK_T3_TOKEN_SECRET, T3DispatchMode, T3LookupError,
    T3ProbeResult, T3Target, T3Transport, normalize_t3_server_url, probe_t3_server,
    resolve_t3_caller_by_call_id, resolve_t3_thread_by_provider_session, t3_state_db_path,
    verify_t3_thread_exists,
};
use hyp_harness::transport::{PushMode, PushOutcome, PushTransport};
use ring::digest::{SHA1_FOR_LEGACY_USE_ONLY, digest};
use rusqlite::Connection;
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

// ============================================================================
// SQLite Fixtures
// ============================================================================

fn create_t3_sqlite(base_dir: &Path) -> Connection {
    let db_path = t3_state_db_path(base_dir);
    fs::create_dir_all(db_path.parent().expect("userdata parent")).unwrap();
    let conn = Connection::open(&db_path).unwrap();
    conn.execute_batch(
        "
        CREATE TABLE orchestration_v2_projection_threads (
            thread_id TEXT PRIMARY KEY,
            deleted_at TEXT,
            archived_at TEXT
        );
        CREATE TABLE orchestration_v2_projection_provider_session_bindings (
            provider_session_id TEXT NOT NULL,
            thread_id TEXT NOT NULL,
            PRIMARY KEY (provider_session_id, thread_id)
        );
        CREATE TABLE orchestration_v2_projection_provider_threads (
            provider_thread_id TEXT PRIMARY KEY,
            thread_id TEXT,
            provider_session_id TEXT
        );
        CREATE TABLE orchestration_v2_projection_turn_items (
            turn_item_id TEXT PRIMARY KEY,
            thread_id TEXT NOT NULL,
            status TEXT NOT NULL,
            payload_json TEXT NOT NULL
        );
        CREATE TABLE projection_threads (
            thread_id TEXT PRIMARY KEY,
            deleted_at TEXT,
            archived_at TEXT
        );
        CREATE TABLE projection_thread_sessions (
            thread_id TEXT PRIMARY KEY,
            provider_session_id TEXT,
            provider_thread_id TEXT
        );
        CREATE TABLE projection_thread_activities (
            activity_id TEXT PRIMARY KEY,
            thread_id TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        ",
    )
    .unwrap();
    conn
}

// ============================================================================
// In-Process Loopback HTTP + RFC 6455 Mock T3 Code Server
// ============================================================================

#[derive(Clone)]
struct MockT3Config {
    expected_token: String,
    issued_ticket: String,
    projections: HashMap<String, Value>,
    /// Optional forced HTTP status code for `POST /api/auth/websocket-ticket`.
    ticket_status_override: Option<u16>,
    /// Optional forced `Exit` Failure response for `orchestration.getThreadProjection`.
    projection_error_override: Option<Value>,
    /// Optional forced `Exit` Failure response for `orchestration.dispatchCommand`.
    dispatch_error_override: Option<Value>,
    /// Send fragmented WS response + interleaved Ping + decoy push event before `Exit`.
    stress_ws_framing: bool,
    /// Tamper `Sec-WebSocket-Accept` header in 101 response to verify client fails closed.
    bad_ws_accept: bool,
}

impl MockT3Config {
    fn standard(expected_token: &str) -> Self {
        let mut projections = HashMap::new();
        projections.insert(
            "thr-idle".to_string(),
            json!({
                "thread": { "id": "thr-idle", "deletedAt": null },
                "runs": [],
                "providerThreads": [],
                "providerSessions": []
            }),
        );
        projections.insert(
            "thr-steer".to_string(),
            json!({
                "thread": { "id": "thr-steer", "deletedAt": null },
                "runs": [{ "id": "run-1", "status": "running", "providerThreadId": "pt-1" }],
                "providerThreads": [{ "id": "pt-1", "providerSessionId": "ps-1" }],
                "providerSessions": [{
                    "id": "ps-1",
                    "capabilities": { "turns": { "supportsActiveSteering": true } }
                }]
            }),
        );
        projections.insert(
            "thr-restart".to_string(),
            json!({
                "thread": { "id": "thr-restart", "deletedAt": null },
                "runs": [{ "id": "run-2", "status": "waiting", "providerThreadId": "pt-2" }],
                "providerThreads": [{ "id": "pt-2", "providerSessionId": "ps-2" }],
                "providerSessions": [{
                    "id": "ps-2",
                    "capabilities": {
                        "turns": {
                            "supportsActiveSteering": false,
                            "supportsSteeringByInterruptRestart": true
                        }
                    }
                }]
            }),
        );
        projections.insert(
            "thr-deleted".to_string(),
            json!({
                "thread": { "id": "thr-deleted", "deletedAt": "2026-11-24T00:00:00Z" },
                "runs": [],
                "providerThreads": [],
                "providerSessions": []
            }),
        );
        projections.insert(
            "thr-archived".to_string(),
            json!({
                "thread": {
                    "id": "thr-archived",
                    "deletedAt": null,
                    "archivedAt": "2026-11-26T00:00:00Z"
                },
                "runs": [],
                "providerThreads": [],
                "providerSessions": []
            }),
        );
        projections.insert(
            "thr-archived-empty".to_string(),
            json!({
                "thread": {
                    "id": "thr-archived-empty",
                    "deletedAt": null,
                    "archivedAt": ""
                },
                "runs": [],
                "providerThreads": [],
                "providerSessions": []
            }),
        );
        Self {
            expected_token: expected_token.to_string(),
            issued_ticket: "ws-ticket+ok/123=".to_string(),
            projections,
            ticket_status_override: None,
            projection_error_override: None,
            dispatch_error_override: None,
            stress_ws_framing: false,
            bad_ws_accept: false,
        }
    }
}

struct MockT3Server {
    url: String,
    received_commands: Arc<Mutex<Vec<Value>>>,
    saw_pong: Arc<Mutex<bool>>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    handle: tokio::task::JoinHandle<()>,
}

impl MockT3Server {
    async fn start(cfg: MockT3Config) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://127.0.0.1:{}", addr.port());
        let received_commands = Arc::new(Mutex::new(Vec::new()));
        let saw_pong = Arc::new(Mutex::new(false));
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();

        let cmds_bg = Arc::clone(&received_commands);
        let pong_bg = Arc::clone(&saw_pong);
        let cfg = Arc::new(cfg);

        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => break,
                    accept_res = listener.accept() => {
                        let Ok((stream, _)) = accept_res else { break };
                        let cfg = Arc::clone(&cfg);
                        let cmds = Arc::clone(&cmds_bg);
                        let pong = Arc::clone(&pong_bg);
                        tokio::spawn(async move {
                            let _ = handle_mock_conn(stream, cfg, cmds, pong).await;
                        });
                    }
                }
            }
        });

        Self {
            url,
            received_commands,
            saw_pong,
            shutdown_tx: Some(shutdown_tx),
            handle,
        }
    }

    fn commands(&self) -> Vec<Value> {
        self.received_commands.lock().unwrap().clone()
    }

    fn saw_pong(&self) -> bool {
        *self.saw_pong.lock().unwrap()
    }

    async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        let _ = self.handle.await;
    }
}

fn encode_ws_unmasked_frame(fin: bool, opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(10 + payload.len());
    out.push((if fin { 0x80 } else { 0x00 }) | (opcode & 0x0f));
    let len = payload.len();
    if len < 126 {
        out.push(len as u8);
    } else if len <= u16::MAX as usize {
        out.push(126);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(127);
        out.extend_from_slice(&(len as u64).to_be_bytes());
    }
    out.extend_from_slice(payload);
    out
}

async fn read_ws_client_frame(stream: &mut TcpStream) -> Option<(u8, Vec<u8>)> {
    let mut hdr = [0u8; 2];
    stream.read_exact(&mut hdr).await.ok()?;
    let opcode = hdr[0] & 0x0f;
    let masked = (hdr[1] & 0x80) != 0;
    assert!(
        masked,
        "client WS frames MUST always be masked per RFC 6455"
    );
    let len_code = hdr[1] & 0x7f;
    let len: usize = match len_code {
        0..=125 => len_code as usize,
        126 => {
            let mut b = [0u8; 2];
            stream.read_exact(&mut b).await.ok()?;
            u16::from_be_bytes(b) as usize
        }
        127 => {
            let mut b = [0u8; 8];
            stream.read_exact(&mut b).await.ok()?;
            u64::from_be_bytes(b) as usize
        }
        _ => unreachable!(),
    };
    let mut mask = [0u8; 4];
    stream.read_exact(&mut mask).await.ok()?;
    let mut payload = vec![0u8; len];
    if len > 0 {
        stream.read_exact(&mut payload).await.ok()?;
        for (i, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[i & 3];
        }
    }
    Some((opcode, payload))
}

fn percent_decode(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(s) = std::str::from_utf8(&bytes[i + 1..i + 3]) {
                if let Ok(val) = u8::from_str_radix(s, 16) {
                    out.push(val);
                    i += 3;
                    continue;
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn parse_query_params(path_and_query: &str) -> (&str, HashMap<String, String>) {
    let mut map = HashMap::new();
    let Some((path, query)) = path_and_query.split_once('?') else {
        return (path_and_query, map);
    };
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            map.insert(percent_decode(k), percent_decode(v));
        }
    }
    (path, map)
}

async fn write_http_json(stream: &mut TcpStream, status: u16, reason: &str, body: &Value) {
    let body_bytes = serde_json::to_vec(body).unwrap();
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body_bytes.len()
    );
    let _ = stream.write_all(header.as_bytes()).await;
    let _ = stream.write_all(&body_bytes).await;
    let _ = stream.flush().await;
}

async fn handle_mock_conn(
    mut stream: TcpStream,
    cfg: Arc<MockT3Config>,
    received_commands: Arc<Mutex<Vec<Value>>>,
    saw_pong: Arc<Mutex<bool>>,
) -> Result<(), String> {
    // Read HTTP request headers up to \r\n\r\n.
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 1024];
    let header_end = loop {
        let n = stream.read(&mut tmp).await.map_err(|e| e.to_string())?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        if buf.len() > 16 * 1024 {
            return Err("headers too large".into());
        }
    };

    let head_str = String::from_utf8_lossy(&buf[..header_end]);
    let mut lines = head_str.split("\r\n");
    let req_line = lines.next().unwrap_or_default();
    let mut parts = req_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();

    let mut headers: HashMap<String, String> = HashMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }

    let expected_auth = format!("Bearer {}", cfg.expected_token);
    let auth = headers.get("authorization").map(String::as_str);

    // 1. GET /api/auth/session
    if method == "GET" && target == "/api/auth/session" {
        let authenticated = auth == Some(expected_auth.as_str());
        write_http_json(
            &mut stream,
            200,
            "OK",
            &json!({ "authenticated": authenticated }),
        )
        .await;
        return Ok(());
    }

    // 2. POST /api/auth/websocket-ticket
    if method == "POST" && target == "/api/auth/websocket-ticket" {
        if let Some(code) = cfg.ticket_status_override {
            write_http_json(&mut stream, code, "Override", &json!({ "error": "forced" })).await;
            return Ok(());
        }
        if auth != Some(expected_auth.as_str()) {
            write_http_json(
                &mut stream,
                401,
                "Unauthorized",
                &json!({ "error": "unauthorized" }),
            )
            .await;
            return Ok(());
        }
        write_http_json(
            &mut stream,
            200,
            "OK",
            &json!({ "ticket": cfg.issued_ticket }),
        )
        .await;
        return Ok(());
    }

    // 3. GET /ws?wsTicket=...&orchestrationProtocol=2 (RFC 6455 upgrade)
    let (path, query) = parse_query_params(target);
    if method == "GET" && path == "/ws" {
        let valid_upgrade = headers
            .get("upgrade")
            .is_some_and(|v| v.eq_ignore_ascii_case("websocket"))
            && headers.get("sec-websocket-version").map(String::as_str) == Some("13")
            && query.get("wsTicket").map(String::as_str) == Some(cfg.issued_ticket.as_str())
            && query.get("orchestrationProtocol").map(String::as_str) == Some("2");

        if !valid_upgrade {
            let _ = stream
                .write_all(b"HTTP/1.1 426 Upgrade Required\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await;
            return Ok(());
        }

        let ws_key = headers
            .get("sec-websocket-key")
            .map(String::as_str)
            .unwrap_or_default();
        let accept = if cfg.bad_ws_accept {
            "AAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string()
        } else {
            let mut input = Vec::with_capacity(ws_key.len() + WS_GUID.len());
            input.extend_from_slice(ws_key.as_bytes());
            input.extend_from_slice(WS_GUID.as_bytes());
            BASE64_STANDARD.encode(digest(&SHA1_FOR_LEGACY_USE_ONLY, &input).as_ref())
        };

        let resp = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
        );
        stream
            .write_all(resp.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        stream.flush().await.map_err(|e| e.to_string())?;

        while let Some((opcode, payload)) = read_ws_client_frame(&mut stream).await {
            if opcode == 0x8 {
                let _ = stream
                    .write_all(&encode_ws_unmasked_frame(true, 0x8, &1000u16.to_be_bytes()))
                    .await;
                break;
            }
            if opcode == 0xA {
                if payload == b"keepalive" {
                    *saw_pong.lock().unwrap() = true;
                }
                continue;
            }
            if opcode != 0x1 {
                continue;
            }

            let req_msg: Value = serde_json::from_slice(&payload).map_err(|e| e.to_string())?;
            assert_eq!(req_msg.get("_tag").and_then(Value::as_str), Some("Request"));
            let req_id = req_msg["id"].as_str().unwrap().to_string();
            let tag = req_msg["tag"].as_str().unwrap();
            let req_payload = &req_msg["payload"];

            let reply = match tag {
                "orchestration.getThreadProjection" => {
                    if let Some(ref forced_err) = cfg.projection_error_override {
                        json!({
                            "_tag": "Exit",
                            "requestId": req_id,
                            "exit": forced_err,
                        })
                    } else {
                        let tid = req_payload["threadId"].as_str().unwrap_or_default();
                        if let Some(proj) = cfg.projections.get(tid) {
                            json!({
                                "_tag": "Exit",
                                "requestId": req_id,
                                "exit": { "_tag": "Success", "value": proj }
                            })
                        } else {
                            json!({
                                "_tag": "Exit",
                                "requestId": req_id,
                                "exit": {
                                    "_tag": "Failure",
                                    "cause": [{
                                        "_tag": "Fail",
                                        "error": {
                                            "_tag": "OrchestrationV2GetThreadProjectionError",
                                            "message": format!("No orchestration projection exists for thread {tid}."),
                                            "cause": { "cause": { "name": "ProjectionStoreThreadNotFoundError" } }
                                        }
                                    }]
                                }
                            })
                        }
                    }
                }
                "orchestration.dispatchCommand" => {
                    if let Some(ref forced_err) = cfg.dispatch_error_override {
                        json!({
                            "_tag": "Exit",
                            "requestId": req_id,
                            "exit": forced_err,
                        })
                    } else {
                        let mut guard = received_commands.lock().unwrap();
                        guard.push(req_payload.clone());
                        let seq = guard.len();
                        json!({
                            "_tag": "Exit",
                            "requestId": req_id,
                            "exit": { "_tag": "Success", "value": { "sequence": seq } }
                        })
                    }
                }
                _ => json!({
                    "_tag": "Exit",
                    "requestId": req_id,
                    "exit": {
                        "_tag": "Failure",
                        "cause": [{ "_tag": "Die", "defect": format!("unknown tag {tag}") }]
                    }
                }),
            };

            let reply_bytes = serde_json::to_vec(&reply).unwrap();
            if cfg.stress_ws_framing && reply_bytes.len() > 20 {
                // Send unrelated push notification frame first.
                let decoy = br#"{"_tag":"Event","topic":"heartbeat"}"#;
                stream
                    .write_all(&encode_ws_unmasked_frame(true, 0x1, decoy))
                    .await
                    .map_err(|e| e.to_string())?;
                // Split real reply across 2 fragments with an interleaved Ping frame.
                let mid = reply_bytes.len() / 2;
                stream
                    .write_all(&encode_ws_unmasked_frame(false, 0x1, &reply_bytes[..mid]))
                    .await
                    .map_err(|e| e.to_string())?;
                stream
                    .write_all(&encode_ws_unmasked_frame(true, 0x9, b"keepalive"))
                    .await
                    .map_err(|e| e.to_string())?;
                stream
                    .write_all(&encode_ws_unmasked_frame(true, 0x0, &reply_bytes[mid..]))
                    .await
                    .map_err(|e| e.to_string())?;
            } else {
                stream
                    .write_all(&encode_ws_unmasked_frame(true, 0x1, &reply_bytes))
                    .await
                    .map_err(|e| e.to_string())?;
            }
            stream.flush().await.map_err(|e| e.to_string())?;
        }
        return Ok(());
    }

    write_http_json(
        &mut stream,
        404,
        "Not Found",
        &json!({ "error": "not_found" }),
    )
    .await;
    Ok(())
}

// ============================================================================
// 1. Read-Only SQLite Thread & Caller Resolution E2E Tests
// ============================================================================

#[tokio::test]
async fn sqlite_resolves_v2_and_v1_schemas_ignores_deleted_archived_and_fails_closed_on_ambiguous()
{
    let tmp = TempDir::new().unwrap();
    let base_dir = tmp.path();

    // Missing DB -> fail closed CallerNotFound, and MUST NOT create statev2.sqlite.
    let missing = resolve_t3_thread_by_provider_session("claude-sess-1", base_dir);
    assert!(matches!(missing, Err(T3LookupError::CallerNotFound(_))));
    assert_eq!(missing.unwrap_err().code(), CallerErrorCode::CallerNotFound);
    assert!(!verify_t3_thread_exists("t3-thread-live", base_dir));
    assert!(!t3_state_db_path(base_dir).exists());

    // Seed both v2 (orchestration_v2_projection_*) and v1 (projection_thread_*) schemas.
    {
        let conn = create_t3_sqlite(base_dir);
        conn.execute_batch(
            "
            INSERT INTO orchestration_v2_projection_threads (thread_id, deleted_at, archived_at) VALUES
                ('t3-v2-live', NULL, NULL),
                ('t3-v2-deleted', '2026-01-01T00:00:00Z', NULL),
                ('t3-v2-archived', NULL, '2026-01-02T00:00:00Z'),
                ('t3-v2-ambig-1', NULL, NULL),
                ('t3-v2-ambig-2', NULL, NULL);

            INSERT INTO orchestration_v2_projection_provider_session_bindings (provider_session_id, thread_id) VALUES
                ('claude-sess-live', 't3-v2-live'),
                ('claude-sess-deleted', 't3-v2-deleted'),
                ('claude-sess-archived', 't3-v2-archived'),
                ('claude-sess-ambig', 't3-v2-ambig-1'),
                ('claude-sess-ambig', 't3-v2-ambig-2'),
                ('claude-sess-live-plus-deleted', 't3-v2-live'),
                ('claude-sess-live-plus-deleted', 't3-v2-deleted');

            INSERT INTO orchestration_v2_projection_provider_threads (provider_thread_id, thread_id, provider_session_id) VALUES
                ('codex-thr-99', 't3-v2-live', 'codex-sess-99');

            INSERT INTO orchestration_v2_projection_turn_items (turn_item_id, thread_id, status, payload_json) VALUES
                ('item-live', 't3-v2-live', 'in_progress', '{\"callId\":\"call_live_123\",\"tool\":\"mcp__hyphae__hyp_send\"}'),
                ('item-done', 't3-v2-live', 'completed', '{\"callId\":\"call_done_456\",\"tool\":\"hyp_send\"}'),
                ('item-ambig-1', 't3-v2-ambig-1', 'running', '{\"callId\":\"call_ambig_789\",\"tool\":\"hyp_mesh\"}'),
                ('item-ambig-2', 't3-v2-ambig-2', 'running', '{\"callId\":\"call_ambig_789\",\"tool\":\"hyp_mesh\"}');

            INSERT INTO projection_threads (thread_id, deleted_at, archived_at) VALUES
                ('t3-v1-live', NULL, NULL),
                ('t3-v1-archived', NULL, '2026-01-03T00:00:00Z');

            INSERT INTO projection_thread_sessions (thread_id, provider_session_id, provider_thread_id) VALUES
                ('t3-v1-live', 'legacy-sess-1', 'legacy-thr-1'),
                ('t3-v1-archived', 'legacy-sess-archived', 'legacy-thr-archived');

            INSERT INTO projection_thread_activities (activity_id, thread_id, payload_json, created_at) VALUES
                ('act-1', 't3-v1-live', '{\"callId\":\"call_v1_act\",\"tool\":\"hyphae:hyp_inbox\"}', '2026-11-24T12:00:00Z');
            ",
        )
        .unwrap();
    }

    // verify_t3_thread_exists checks active v2 & v1 threads and rejects deleted/archived/missing.
    assert!(verify_t3_thread_exists("t3-v2-live", base_dir));
    assert!(verify_t3_thread_exists("t3-v1-live", base_dir));
    assert!(!verify_t3_thread_exists("t3-v2-deleted", base_dir));
    assert!(!verify_t3_thread_exists("t3-v2-archived", base_dir));
    assert!(!verify_t3_thread_exists("t3-v1-archived", base_dir));
    assert!(!verify_t3_thread_exists("nonexistent", base_dir));

    // Single active match across v2 bindings, v2 provider_threads, and v1 thread_sessions.
    assert_eq!(
        resolve_t3_thread_by_provider_session("claude-sess-live", base_dir),
        Ok("t3-v2-live".to_string())
    );
    assert_eq!(
        resolve_t3_thread_by_provider_session("codex-thr-99", base_dir),
        Ok("t3-v2-live".to_string())
    );
    assert_eq!(
        resolve_t3_thread_by_provider_session("codex-sess-99", base_dir),
        Ok("t3-v2-live".to_string())
    );
    assert_eq!(
        resolve_t3_thread_by_provider_session("legacy-sess-1", base_dir),
        Ok("t3-v1-live".to_string())
    );
    assert_eq!(
        resolve_t3_thread_by_provider_session("legacy-thr-1", base_dir),
        Ok("t3-v1-live".to_string())
    );
    // Deleted sibling is ignored so the sole active thread resolves cleanly.
    assert_eq!(
        resolve_t3_thread_by_provider_session("claude-sess-live-plus-deleted", base_dir),
        Ok("t3-v2-live".to_string())
    );

    // Deleted / archived / unknown -> CallerNotFound.
    assert!(matches!(
        resolve_t3_thread_by_provider_session("claude-sess-deleted", base_dir),
        Err(T3LookupError::CallerNotFound(_))
    ));
    assert!(matches!(
        resolve_t3_thread_by_provider_session("claude-sess-archived", base_dir),
        Err(T3LookupError::CallerNotFound(_))
    ));
    assert!(matches!(
        resolve_t3_thread_by_provider_session("legacy-sess-archived", base_dir),
        Err(T3LookupError::CallerNotFound(_))
    ));

    // Multiple active threads -> fail closed CallerAmbiguous!
    let ambig = resolve_t3_thread_by_provider_session("claude-sess-ambig", base_dir);
    assert!(matches!(ambig, Err(T3LookupError::CallerAmbiguous(_))));
    assert_eq!(ambig.unwrap_err().code(), CallerErrorCode::CallerAmbiguous);

    // In-flight call verification (v2 turn_items + v1 projection_thread_activities).
    assert_eq!(
        resolve_t3_caller_by_call_id(
            "call_live_123",
            "hyp_send",
            base_dir,
            Duration::from_millis(100)
        )
        .await,
        Ok("t3-v2-live".to_string())
    );
    assert_eq!(
        resolve_t3_caller_by_call_id(
            "call_v1_act",
            "hyp_inbox",
            base_dir,
            Duration::from_millis(100)
        )
        .await,
        Ok("t3-v1-live".to_string())
    );
    // Completed turn item and mismatched tool name MUST fail closed.
    assert!(matches!(
        resolve_t3_caller_by_call_id(
            "call_done_456",
            "hyp_send",
            base_dir,
            Duration::from_millis(80)
        )
        .await,
        Err(T3LookupError::CallerNotFound(_))
    ));
    assert!(matches!(
        resolve_t3_caller_by_call_id(
            "call_live_123",
            "hyp_inbox",
            base_dir,
            Duration::from_millis(80)
        )
        .await,
        Err(T3LookupError::CallerNotFound(_))
    ));
    // Ambiguous in-flight call across 2 active threads -> fail closed CallerAmbiguous.
    assert!(matches!(
        resolve_t3_caller_by_call_id(
            "call_ambig_789",
            "hyp_mesh",
            base_dir,
            Duration::from_millis(80)
        )
        .await,
        Err(T3LookupError::CallerAmbiguous(_))
    ));
    // Unknown tool -> CallerUnverifiable.
    assert!(matches!(
        resolve_t3_caller_by_call_id(
            "call_live_123",
            "not_a_mesh_tool",
            base_dir,
            Duration::from_millis(80)
        )
        .await,
        Err(T3LookupError::CallerUnverifiable(_))
    ));
}

// ============================================================================
// 2. URL Security Validation E2E Tests
// ============================================================================

#[test]
fn url_validation_enforces_strict_https_or_loopback_http_origin() {
    assert_eq!(
        normalize_t3_server_url("http://127.0.0.1:3773").unwrap(),
        "http://127.0.0.1:3773"
    );
    assert_eq!(
        normalize_t3_server_url("http://localhost:3773").unwrap(),
        "http://localhost:3773"
    );
    assert_eq!(
        normalize_t3_server_url("http://[::1]:3773").unwrap(),
        "http://[::1]:3773"
    );
    assert_eq!(
        normalize_t3_server_url("https://t3.example.com").unwrap(),
        "https://t3.example.com"
    );
    assert_eq!(
        normalize_t3_server_url("https://t3.example.com/").unwrap(),
        "https://t3.example.com"
    );

    // Reject non-loopback HTTP, credentials, paths, query, fragments.
    for rejected in [
        "http://10.0.0.1:3773",
        "http://example.com",
        "http://192.168.1.50:3773",
        "https://u:p@example.com",
        "http://u:p@127.0.0.1:3773",
        "https://t3.example.com/extra/path",
        "http://127.0.0.1:3773/api",
        "https://t3.example.com?token=leak",
        "http://127.0.0.1:3773#frag",
        "ws://127.0.0.1:3773",
    ] {
        assert!(
            normalize_t3_server_url(rejected).is_err(),
            "URL must be rejected: {rejected}"
        );
    }
}

// ============================================================================
// 3. Full Loopback HTTP + Real RFC 6455 WebSocket Mock T3 Server E2E Tests
// ============================================================================

#[tokio::test]
async fn probe_t3_server_reports_authenticated_unauthenticated_and_unreachable() {
    let server = MockT3Server::start(MockT3Config::standard("t3-probe-secret-xyz")).await;

    let authed = probe_t3_server(
        &server.url,
        Some("t3-probe-secret-xyz"),
        Duration::from_secs(2),
    )
    .await;
    assert_eq!(
        authed,
        T3ProbeResult {
            ok: true,
            authenticated: Some(true),
            error: None,
        }
    );

    let unauthed = probe_t3_server(&server.url, None, Duration::from_secs(2)).await;
    assert_eq!(
        unauthed,
        T3ProbeResult {
            ok: true,
            authenticated: Some(false),
            error: None,
        }
    );

    let wrong_tok = probe_t3_server(&server.url, Some("wrong-token"), Duration::from_secs(2)).await;
    assert_eq!(
        wrong_tok,
        T3ProbeResult {
            ok: true,
            authenticated: Some(false),
            error: None,
        }
    );

    // Non-loopback HTTP is rejected before making any network request.
    let insecure = probe_t3_server(
        "http://10.0.0.1:3773",
        Some("t3-probe-secret-xyz"),
        Duration::from_secs(1),
    )
    .await;
    assert!(!insecure.ok);
    assert!(insecure.error.is_some());

    let dead_url = server.url.clone();
    server.shutdown().await;

    // Stopped server -> probe reports ok: false with error.
    let dead = probe_t3_server(
        &dead_url,
        Some("t3-probe-secret-xyz"),
        Duration::from_secs(1),
    )
    .await;
    assert!(!dead.ok);
    assert!(dead.error.is_some());
}

#[tokio::test]
async fn push_transport_secret_store_queue_interrupt_and_fallback_secret_e2e() {
    let state_dir = TempDir::new().unwrap();
    let store = SecretStore::new(state_dir.path(), SecretBackend::File);
    store
        .set(DEFAULT_T3_TOKEN_SECRET, "t3-secret-token-xyz")
        .unwrap();

    let server = MockT3Server::start(MockT3Config::standard("t3-secret-token-xyz")).await;

    let make_transport = |thread_id: &str| {
        T3Transport::new(T3Target {
            thread_id: thread_id.to_string(),
            server_url: server.url.clone(),
            base_dir: None,
            token_secret: None,
            state_dir: Some(state_dir.path().to_path_buf()),
            secret_backend: Some(SecretBackend::File),
            token_override: None,
        })
    };

    // Trait metadata invariants.
    let idle_t = make_transport("thr-idle");
    assert_eq!(idle_t.kind(), "t3");
    assert!(idle_t.supports_interrupt());

    // 1. Idle thread + Queue -> start_immediately, PushOutcome::Delivered
    let digest = common::source_digest(hyp_store::MailboxKind::Message, "peer@box/dev");
    let idle_outcome = idle_t.deliver(&digest, PushMode::Queue).await;
    assert_eq!(idle_outcome, PushOutcome::Delivered);
    let last = server.commands().pop().unwrap();
    assert_eq!(last["type"], "message.dispatch");
    assert_eq!(last["createdBy"], "system");
    assert_eq!(last["creationSource"], "mcp");
    assert_eq!(last["threadId"], "thr-idle");
    assert_eq!(last["text"], digest.as_str());
    assert_eq!(last["attachments"], json!([]));
    assert_eq!(last["dispatchMode"], json!({ "type": "start_immediately" }));
    assert!(last["commandId"].as_str().is_some_and(|s| !s.is_empty()));
    assert!(last["messageId"].as_str().is_some_and(|s| !s.is_empty()));

    // 2. Active thread + Queue -> queue_after_active, PushOutcome::Delivered
    let steer_t = make_transport("thr-steer");
    let queue_detail = steer_t
        .deliver_detailed(&test_digest(), PushMode::Queue)
        .await;
    assert_eq!(queue_detail.outcome, PushOutcome::Delivered);
    assert!(!queue_detail.interrupted);
    assert_eq!(
        queue_detail.dispatch_mode,
        Some(T3DispatchMode::QueueAfterActive)
    );
    assert_eq!(
        server.commands().last().unwrap()["dispatchMode"],
        json!({ "type": "queue_after_active" })
    );

    // 3. Active thread + Interrupt + supportsActiveSteering=true -> steer_active
    let steer_detail = steer_t
        .deliver_detailed(&test_digest(), PushMode::Interrupt)
        .await;
    assert_eq!(steer_detail.outcome, PushOutcome::Delivered);
    assert!(steer_detail.interrupted);
    assert_eq!(
        steer_detail.dispatch_mode,
        Some(T3DispatchMode::SteerActive {
            target_run_id: "run-1".to_string()
        })
    );
    assert_eq!(
        server.commands().last().unwrap()["dispatchMode"],
        json!({ "type": "steer_active", "targetRunId": "run-1" })
    );

    // 4. Active thread + Interrupt + supportsActiveSteering=false -> restart_active
    let restart_t = make_transport("thr-restart");
    let restart_detail = restart_t
        .deliver_detailed(&test_digest(), PushMode::Interrupt)
        .await;
    assert_eq!(restart_detail.outcome, PushOutcome::Delivered);
    assert!(restart_detail.interrupted);
    assert_eq!(
        restart_detail.dispatch_mode,
        Some(T3DispatchMode::RestartActive {
            target_run_id: "run-2".to_string()
        })
    );
    assert_eq!(
        server.commands().last().unwrap()["dispatchMode"],
        json!({ "type": "restart_active", "targetRunId": "run-2" })
    );

    // 5. Fallback secret name ("t3-session-token") when primary "t3-auth-token" is absent.
    let fallback_dir = TempDir::new().unwrap();
    let fallback_store = SecretStore::new(fallback_dir.path(), SecretBackend::File);
    fallback_store
        .set(FALLBACK_T3_TOKEN_SECRET, "t3-secret-token-xyz")
        .unwrap();
    let fallback_t = T3Transport::new(T3Target {
        thread_id: "thr-idle".to_string(),
        server_url: server.url.clone(),
        base_dir: None,
        token_secret: None,
        state_dir: Some(fallback_dir.path().to_path_buf()),
        secret_backend: Some(SecretBackend::File),
        token_override: None,
    });
    assert_eq!(
        fallback_t.deliver(&test_digest(), PushMode::Queue).await,
        PushOutcome::Delivered
    );

    server.shutdown().await;
}

#[tokio::test]
async fn error_mapping_covers_auth_failed_missing_secret_unreachable_and_effect_exit_failures() {
    let server = MockT3Server::start(MockT3Config::standard("good-t3-token")).await;

    // 1. 401 on /api/auth/websocket-ticket -> Hold("t3_auth_failed")
    let mut bad_auth_target = T3Target::new("thr-idle", &server.url);
    bad_auth_target.token_override = Some("wrong-t3-token".into());
    let bad_auth = T3Transport::new(bad_auth_target)
        .deliver(&test_digest(), PushMode::Queue)
        .await;
    assert_eq!(bad_auth, PushOutcome::hold("t3_auth_failed"));

    // 2. Missing secret in empty SecretStore -> Hold("t3_auth_missing")
    let empty_state = TempDir::new().unwrap();
    let missing_secret_t = T3Transport::new(T3Target {
        thread_id: "thr-idle".to_string(),
        server_url: server.url.clone(),
        base_dir: None,
        token_secret: None,
        state_dir: Some(empty_state.path().to_path_buf()),
        secret_backend: Some(SecretBackend::File),
        token_override: None,
    });
    assert_eq!(
        missing_secret_t
            .deliver(&test_digest(), PushMode::Queue)
            .await,
        PushOutcome::hold("t3_auth_missing")
    );

    // 3. Effect Exit failure: ProjectionStoreThreadNotFoundError -> Reject("t3_thread_not_found")
    let mut missing_thr_target = T3Target::new("thr-missing", &server.url);
    missing_thr_target.token_override = Some("good-t3-token".into());
    assert_eq!(
        T3Transport::new(missing_thr_target)
            .deliver(&test_digest(), PushMode::Queue)
            .await,
        PushOutcome::reject("t3_thread_not_found")
    );

    // 4. Soft-deleted thread in projection -> Reject("t3_thread_deleted")
    let mut deleted_thr_target = T3Target::new("thr-deleted", &server.url);
    deleted_thr_target.token_override = Some("good-t3-token".into());
    assert_eq!(
        T3Transport::new(deleted_thr_target)
            .deliver(&test_digest(), PushMode::Queue)
            .await,
        PushOutcome::reject("t3_thread_deleted")
    );

    // 4b. Archived thread in projection (`deletedAt: null, archivedAt != null`) ->
    //     Reject("t3_thread_archived") and NEVER dispatch a message into the archived thread!
    let cmds_before_archived = server.commands().len();
    let mut archived_thr_target = T3Target::new("thr-archived", &server.url);
    archived_thr_target.token_override = Some("good-t3-token".into());
    assert_eq!(
        T3Transport::new(archived_thr_target)
            .deliver(&test_digest(), PushMode::Queue)
            .await,
        PushOutcome::reject("t3_thread_archived")
    );
    assert_eq!(
        server.commands().len(),
        cmds_before_archived,
        "archived thread MUST fail closed before orchestration.dispatchCommand"
    );

    // 4c. Empty string `archivedAt: ""` is treated as unset (unarchived) and delivers normally.
    let mut archived_empty_target = T3Target::new("thr-archived-empty", &server.url);
    archived_empty_target.token_override = Some("good-t3-token".into());
    assert_eq!(
        T3Transport::new(archived_empty_target)
            .deliver(&test_digest(), PushMode::Queue)
            .await,
        PushOutcome::Delivered
    );

    // 5. Insecure non-loopback HTTP URL -> Reject("t3_invalid_server_url")
    let mut bad_url_target = T3Target::new("thr-idle", "http://10.0.0.1:3773");
    bad_url_target.token_override = Some("good-t3-token".into());
    assert_eq!(
        T3Transport::new(bad_url_target)
            .deliver(&test_digest(), PushMode::Queue)
            .await,
        PushOutcome::reject("t3_invalid_server_url")
    );

    let dead_url = server.url.clone();
    server.shutdown().await;

    // 6. Unreachable port (server shut down) -> Hold("t3_server_unreachable")
    let mut dead_target = T3Target::new("thr-idle", &dead_url);
    dead_target.token_override = Some("good-t3-token".into());
    let unreachable = T3Transport::with_timeouts(
        dead_target,
        Duration::from_secs(2),
        Duration::from_secs(2),
        Duration::from_secs(2),
    )
    .deliver(&test_digest(), PushMode::Queue)
    .await;
    assert_eq!(unreachable, PushOutcome::hold("t3_server_unreachable"));

    // 7. 500 on /api/auth/websocket-ticket -> Hold("t3_server_unreachable")
    let mut cfg_500 = MockT3Config::standard("good-t3-token");
    cfg_500.ticket_status_override = Some(500);
    let srv_500 = MockT3Server::start(cfg_500).await;
    let mut t500 = T3Target::new("thr-idle", &srv_500.url);
    t500.token_override = Some("good-t3-token".into());
    assert_eq!(
        T3Transport::new(t500)
            .deliver(&test_digest(), PushMode::Queue)
            .await,
        PushOutcome::hold("t3_server_unreachable")
    );
    srv_500.shutdown().await;

    // 8. Generic Effect Exit failure on getThreadProjection (Die) -> Hold("t3_projection_unavailable")
    let mut cfg_proj_die = MockT3Config::standard("good-t3-token");
    cfg_proj_die.projection_error_override = Some(json!({
        "_tag": "Failure",
        "cause": [{ "_tag": "Die", "defect": "projection store busy" }]
    }));
    let srv_proj_die = MockT3Server::start(cfg_proj_die).await;
    let mut t_proj_die = T3Target::new("thr-idle", &srv_proj_die.url);
    t_proj_die.token_override = Some("good-t3-token".into());
    assert_eq!(
        T3Transport::new(t_proj_die)
            .deliver(&test_digest(), PushMode::Queue)
            .await,
        PushOutcome::hold("t3_projection_unavailable")
    );
    srv_proj_die.shutdown().await;

    // 9. Effect Exit failure on dispatchCommand -> Reject("t3_dispatch_failed")
    let mut cfg_dispatch_err = MockT3Config::standard("good-t3-token");
    cfg_dispatch_err.dispatch_error_override = Some(json!({
        "_tag": "Failure",
        "cause": [{
            "_tag": "Fail",
            "error": { "_tag": "DispatchRejectedError", "message": "queue full" }
        }]
    }));
    let srv_dispatch_err = MockT3Server::start(cfg_dispatch_err).await;
    let mut t_dispatch_err = T3Target::new("thr-idle", &srv_dispatch_err.url);
    t_dispatch_err.token_override = Some("good-t3-token".into());
    assert_eq!(
        T3Transport::new(t_dispatch_err)
            .deliver(&test_digest(), PushMode::Queue)
            .await,
        PushOutcome::reject("t3_dispatch_failed")
    );
    srv_dispatch_err.shutdown().await;
}

#[tokio::test]
async fn websocket_handles_fragmented_exit_interleaved_ping_pong_and_rejects_bad_accept() {
    // 1. Stress framing: decoy event frame + fragmented Exit + interleaved Ping -> must deliver & send Pong!
    let mut cfg = MockT3Config::standard("stress-token");
    cfg.stress_ws_framing = true;
    let server = MockT3Server::start(cfg).await;

    let mut target = T3Target::new("thr-idle", &server.url);
    target.token_override = Some("stress-token".into());
    let outcome = T3Transport::new(target)
        .deliver(&test_digest(), PushMode::Queue)
        .await;
    assert_eq!(outcome, PushOutcome::Delivered);
    assert!(
        server.saw_pong(),
        "client must reply with masked Pong to server Ping"
    );
    assert_eq!(
        server.commands().last().unwrap()["text"],
        test_digest().as_str()
    );
    server.shutdown().await;

    // 2. Tampered Sec-WebSocket-Accept header -> client MUST fail closed!
    let mut bad_cfg = MockT3Config::standard("stress-token");
    bad_cfg.bad_ws_accept = true;
    let bad_server = MockT3Server::start(bad_cfg).await;

    let mut bad_target = T3Target::new("thr-idle", &bad_server.url);
    bad_target.token_override = Some("stress-token".into());
    let outcome = T3Transport::new(bad_target)
        .deliver(&test_digest(), PushMode::Queue)
        .await;
    assert_eq!(outcome, PushOutcome::hold("t3_server_unreachable"));
    assert!(bad_server.commands().is_empty());
    bad_server.shutdown().await;
}

#[tokio::test]
async fn archived_t3_thread_mid_session_rejects_and_detaches_daemon_transport() {
    hyp_harness::enable_test_env_isolation();
    let dir = TempDir::new().unwrap();
    let state_dir = dir.path().join("state");

    let server = MockT3Server::start(MockT3Config::standard("detach-t3-tok")).await;

    let mut cfg = hyp_node::engine::NodeConfig::local(
        hyp_proto::address::NodeId::new("t3@local").unwrap(),
        &state_dir,
    );
    cfg.secret_backend = Some(SecretBackend::File);
    let node = hyp_node::engine::UnifiedNode::open(cfg).unwrap();
    let daemon = hyp_harness::daemon::LocalDaemon::start(
        Arc::clone(&node),
        None,
        hyp_harness::daemon::LocalDaemonConfig::default(),
    )
    .await
    .unwrap();
    let sock_path = daemon.socket_path().to_path_buf();

    // Register session + enroll handle + attach T3Transport pointing to an archived thread
    // (simulating a T3 thread that was archived mid-session after enrollment).
    let session_id = "claude:t3-archived-sess";
    let now = hyp_store::now_ms();
    {
        let db = node.db();
        db.local()
            .register_session(session_id, r#"{"kind":"claude"}"#, now)
            .unwrap();
        db.local()
            .set_session_handle(session_id, Some("worker"), now)
            .unwrap();
    }

    let mut target = T3Target::new("thr-archived", &server.url);
    target.token_override = Some("detach-t3-tok".into());
    daemon.register_session_transport(session_id, Arc::new(T3Transport::new(target)));

    // Confirm transport is attached before delivery attempt.
    let status_before = hyp_harness::sock::daemon_rpc_async(
        &sock_path,
        &json!({ "type": "daemon.status" }),
        Duration::from_secs(5),
    )
    .await;
    assert!(status_before.ok, "daemon.status failed: {status_before:?}");
    let sessions_before = status_before.result.as_ref().unwrap()["sessions"]
        .as_array()
        .unwrap();
    let sess_before = sessions_before
        .iter()
        .find(|s| s["id"] == session_id)
        .expect("session in daemon.status");
    assert_eq!(sess_before["hasLiveTransport"], true);
    assert_eq!(sess_before["transportKind"], "t3");

    // Queue an inbound DM into the session mailbox and trigger flush.
    {
        let db = node.db();
        db.local()
            .put_in_mailbox(
                &hyp_store::MailboxInsert {
                    session_id: session_id.to_string(),
                    origin_node: "t3@local".to_string(),
                    item_id: "dm-archived-1".to_string(),
                    text: "[hyphae · DM from @alice] please check build".to_string(),
                    kind: hyp_store::MailboxKind::Message,
                    source: "t3@local/alice".to_string(),
                    gate_state: hyp_store::GateState::Pending,
                    gate_reason: None,
                    traceparent: None,
                },
                now + 10,
            )
            .unwrap();
    }
    daemon.flush_pending_sessions().await;

    // 1. ZERO `message.dispatch` commands were sent into the archived T3 thread!
    assert!(
        server.commands().is_empty(),
        "archived thread must never receive <hyphae-wake> dispatchCommand: {:?}",
        server.commands()
    );

    // 2. LocalDaemon MUST detach the archived T3 transport cleanly (matching `t3_thread_deleted`).
    let status_after = hyp_harness::sock::daemon_rpc_async(
        &sock_path,
        &json!({ "type": "daemon.status" }),
        Duration::from_secs(5),
    )
    .await;
    assert!(status_after.ok, "daemon.status failed: {status_after:?}");
    let sessions_after = status_after.result.as_ref().unwrap()["sessions"]
        .as_array()
        .unwrap();
    let sess_after = sessions_after
        .iter()
        .find(|s| s["id"] == session_id)
        .expect("session in daemon.status");
    assert_eq!(
        sess_after["hasLiveTransport"], false,
        "LocalDaemon must detach archived T3 transport cleanly: {sess_after}"
    );
    assert!(
        sess_after["transportKind"].is_null(),
        "LocalDaemon must clear archived T3 transportKind cleanly: {sess_after}"
    );

    // 3. Unread DM remains safely queued in SQLite mailbox (zero message loss).
    assert_eq!(node.db().local().pending_count(session_id).unwrap(), 1);

    daemon.shutdown();
    node.shutdown();
    server.shutdown().await;
}
