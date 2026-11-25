//! Wave 3C Full Harness Parity E2E Test Suite (`#16`: `X2`, `X5`, `X6`, `X8`, `X9`).
//!
//! Strictly hermetic: `TempDir`, `127.0.0.1:0`, `SecretBackend::File`, zero live Keychain or
//! host config mutations, deterministic synchronization.

mod common;

use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
#[cfg(unix)]
use std::time::Instant;

use common::{TestMcpClient, run_hook, run_hook_with_hints, session_status};
use hyp_crypto::{SecretBackend, SecretStore};
use hyp_harness::daemon::{InboundItem, LocalDaemon, LocalDaemonConfig};
use hyp_harness::hooks::{
    HandleHookOptions, HookEvent, HookTransportHints, handle_hook_payload_with_session_token,
};
use hyp_harness::mcp::McpOptions;
use hyp_harness::protocol::HarnessKind;
use hyp_harness::sock::{
    DaemonRpcResult, MAX_SOCKET_LINE_BYTES, connect_daemon_async, daemon_rpc_async,
    daemon_rpc_sync, read_bounded_line_async, write_ndjson_line_async,
};
use hyp_harness::transport::codex::{is_valid_codex_uuid, verify_codex_rollout_thread};
use hyp_harness::transport::openclaw::{
    DEFAULT_OPENCLAW_TOKEN_SECRET, OpenClawEndpointMode, OpenClawTarget, OpenClawTransport,
    REASON_OPENCLAW_AUTH_FAILED, REASON_OPENCLAW_GATEWAY_UNAVAILABLE,
    REASON_OPENCLAW_HOOKS_DISABLED, REASON_OPENCLAW_INVALID_URL, REASON_OPENCLAW_RATE_LIMITED,
    probe_openclaw_gateway,
};
use hyp_harness::transport::t3::t3_state_db_path;
use hyp_harness::transport::{PushMode, PushOutcome, PushTransport};
use hyp_harness::wait::{WaitMode, WaitOptions, run_wait_to_writer_with_token};
use hyp_node::engine::{NodeConfig, UnifiedNode};
use hyp_node::gates::TrustTier as GateTrustTier;
use hyp_proto::address::NodeId;
use hyp_store::MailboxKind;
use rusqlite::Connection;
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

fn open_local_node(node_id: &str, dir: &Path) -> Arc<UnifiedNode> {
    let mut cfg = NodeConfig::local(NodeId::new(node_id).unwrap(), dir);
    cfg.secret_backend = Some(SecretBackend::File);
    UnifiedNode::open(cfg).expect("open UnifiedNode")
}

async fn rpc(sock: &Path, pkt: &Value) -> DaemonRpcResult {
    daemon_rpc_async(sock, pkt, Duration::from_secs(5)).await
}

#[derive(Debug, Clone)]
struct RecordedHttpRequest {
    method: String,
    path: String,
    authorization: Option<String>,
    content_type: Option<String>,
    idempotency_key: Option<String>,
    body: String,
}

async fn read_http_request(stream: &mut tokio::net::TcpStream) -> Option<RecordedHttpRequest> {
    let mut raw = Vec::new();
    let mut chunk = [0u8; 4096];
    let mut header_end = None;
    let mut content_len = 0usize;

    loop {
        let n = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut chunk))
            .await
            .ok()?
            .ok()?;
        if n == 0 {
            break;
        }
        raw.extend_from_slice(&chunk[..n]);
        if header_end.is_none() {
            if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                header_end = Some(pos + 4);
                let hdr_str = String::from_utf8_lossy(&raw[..pos]);
                for line in hdr_str.lines().skip(1) {
                    if let Some((k, v)) = line.split_once(':') {
                        if k.trim().eq_ignore_ascii_case("content-length") {
                            content_len = v.trim().parse::<usize>().unwrap_or(0);
                        }
                    }
                }
            }
        }
        if let Some(end) = header_end {
            if raw.len() >= end + content_len {
                break;
            }
        }
        if raw.len() > 128 * 1024 {
            break;
        }
    }

    let end = header_end?;
    let hdr_str = String::from_utf8_lossy(&raw[..end - 4]);
    let mut lines = hdr_str.lines();
    let req_line = lines.next()?;
    let mut parts = req_line.split_whitespace();
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();

    let mut authorization = None;
    let mut content_type = None;
    let mut idempotency_key = None;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_ascii_lowercase();
            let val = v.trim().to_string();
            match key.as_str() {
                "authorization" => authorization = Some(val),
                "content-type" => content_type = Some(val),
                "idempotency-key" => idempotency_key = Some(val),
                _ => {}
            }
        }
    }

    let body_slice = &raw[end..raw.len().min(end + content_len)];
    let body = String::from_utf8_lossy(body_slice).into_owned();
    Some(RecordedHttpRequest {
        method,
        path,
        authorization,
        content_type,
        idempotency_key,
        body,
    })
}

async fn spawn_mock_openclaw_gateway(
    expected_token: String,
    post_status: Arc<AtomicU16>,
    unauth_probe_status: Arc<AtomicU16>,
) -> (
    String,
    Arc<Mutex<Vec<RecordedHttpRequest>>>,
    Arc<Mutex<Vec<RecordedHttpRequest>>>,
    tokio::task::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let recorded: Arc<Mutex<Vec<RecordedHttpRequest>>> = Arc::new(Mutex::new(Vec::new()));
    let probes: Arc<Mutex<Vec<RecordedHttpRequest>>> = Arc::new(Mutex::new(Vec::new()));
    let rec_srv = Arc::clone(&recorded);
    let probe_srv = Arc::clone(&probes);

    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let tok = expected_token.clone();
            let p_status = Arc::clone(&post_status);
            let u_status = Arc::clone(&unauth_probe_status);
            let rec = Arc::clone(&rec_srv);
            let pr = Arc::clone(&probe_srv);
            tokio::spawn(async move {
                let Some(req) = read_http_request(&mut stream).await else {
                    return;
                };
                let code = if req.authorization.is_none() {
                    // Unauthenticated probe request — record separately and return configured status!
                    pr.lock().unwrap().push(req);
                    u_status.load(Ordering::SeqCst)
                } else {
                    let auth_ok = req.authorization.as_deref() == Some(&format!("Bearer {tok}"));
                    let status = if !auth_ok {
                        401
                    } else {
                        p_status.load(Ordering::SeqCst)
                    };
                    if req.method == "POST" {
                        rec.lock().unwrap().push(req);
                    }
                    status
                };
                let reason = match code {
                    200 => "OK",
                    202 => "Accepted",
                    204 => "No Content",
                    400 => "Bad Request",
                    401 => "Unauthorized",
                    403 => "Forbidden",
                    404 => "Not Found",
                    405 => "Method Not Allowed",
                    429 => "Too Many Requests",
                    503 => "Service Unavailable",
                    _ => "Status",
                };
                let body = if code == 204 { "" } else { "{\"ok\":true}" };
                let resp = format!(
                    "HTTP/1.1 {code} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes()).await;
            });
        }
    });

    (format!("http://{addr}"), recorded, probes, handle)
}

fn seed_t3_state_db(t3_base: &Path, provider_session_id: &str, thread_id: &str) {
    let db_path = t3_state_db_path(t3_base);
    fs::create_dir_all(db_path.parent().unwrap()).unwrap();
    let conn = Connection::open(&db_path).unwrap();
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS orchestration_v2_projection_threads (
             thread_id TEXT PRIMARY KEY,
             deleted_at TEXT,
             archived_at TEXT
         );
         CREATE TABLE IF NOT EXISTS orchestration_v2_projection_provider_session_bindings (
             provider_session_id TEXT NOT NULL,
             thread_id TEXT NOT NULL
         );",
    )
    .unwrap();
    conn.execute(
        "INSERT OR REPLACE INTO orchestration_v2_projection_threads (thread_id, deleted_at, archived_at)
         VALUES (?1, NULL, NULL)",
        [thread_id],
    )
    .unwrap();
    conn.execute(
        "INSERT OR REPLACE INTO orchestration_v2_projection_provider_session_bindings (provider_session_id, thread_id)
         VALUES (?1, ?2)",
        [provider_session_id, thread_id],
    )
    .unwrap();
}

async fn spawn_mock_t3_auth_server(
    expected_token: String,
) -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let expected = expected_token.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let n = stream.read(&mut buf).await.unwrap_or(0);
                let req_str = String::from_utf8_lossy(&buf[..n]);
                let auth_ok = req_str.lines().any(|line| {
                    line.eq_ignore_ascii_case(&format!("authorization: Bearer {expected}"))
                });
                let body = format!("{{\"authenticated\":{auth_ok}}}");
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes()).await;
            });
        }
    });
    (format!("http://{addr}"), handle)
}

// ============================================================================
// 1. X2 (P1): Native OpenClaw Gateway Push Transport + Fail-Closed + Detach
// ============================================================================

#[tokio::test]
async fn x2_openclaw_transport_delivers_metadata_nudge_enforces_auth_and_detaches_on_401_404() {
    let post_status = Arc::new(AtomicU16::new(200));
    let unauth_probe_status = Arc::new(AtomicU16::new(401)); // OpenClaw `/hooks/*` challenges unauthenticated POST with 401!
    let token_val = "oc-hooks-secret-token-7788";
    let (gw_url, recorded, probes, gw_srv) = spawn_mock_openclaw_gateway(
        token_val.to_string(),
        Arc::clone(&post_status),
        Arc::clone(&unauth_probe_status),
    )
    .await;

    // ---- Part A: Direct OpenClawTransport `/hooks/agent` & `/hooks/wake` + zero body leak ----
    let tmp = TempDir::new().unwrap();
    let secrets_dir = tmp.path().join("direct-secrets");
    fs::create_dir_all(&secrets_dir).unwrap();
    let store = SecretStore::new(&secrets_dir, SecretBackend::File);
    store.set(DEFAULT_OPENCLAW_TOKEN_SECRET, token_val).unwrap();
    store.set("exfil-other-secret", "TOP_SECRET_OTHER_KEY").unwrap();

    // Reject non-loopback HTTP AND non-loopback HTTPS (by default) fail-closed!
    for bad_url in ["http://192.168.1.99:18789", "https://evil.example.com"] {
        let bad_target = OpenClawTarget::new()
            .with_base_url(bad_url)
            .with_state_dir(&secrets_dir)
            .with_secret_backend(SecretBackend::File);
        let bad_transport = OpenClawTransport::new(bad_target);
        assert_eq!(
            bad_transport.deliver("ignored", PushMode::Queue).await,
            PushOutcome::reject(REASON_OPENCLAW_INVALID_URL),
            "expected non-loopback URL {bad_url} to fail closed by default"
        );
    }

    // Reject arbitrary `tokenSecret` names fail-closed (never exfiltrate unrelated Keychain secrets!).
    let exfil_target = OpenClawTarget::new()
        .with_base_url(&gw_url)
        .with_token_secret("exfil-other-secret")
        .with_state_dir(&secrets_dir)
        .with_secret_backend(SecretBackend::File);
    let exfil_probe = probe_openclaw_gateway(&exfil_target, Duration::from_secs(2)).await;
    assert!(!exfil_probe.ok, "arbitrary tokenSecret must fail closed");
    assert!(probes.lock().unwrap().is_empty(), "rejected tokenSecret must not hit network");

    // Probe MUST reject `405 Method Not Allowed` from a random non-OpenClaw listener!
    unauth_probe_status.store(405, Ordering::SeqCst);
    let agent_target = OpenClawTarget::new()
        .with_base_url(&gw_url)
        .with_hooks_path("/hooks")
        .with_endpoint_mode(OpenClawEndpointMode::Agent)
        .with_agent_id("coder-main")
        .with_handle("claw")
        .with_state_dir(&secrets_dir)
        .with_secret_backend(SecretBackend::File);
    let probe_405 = probe_openclaw_gateway(&agent_target, Duration::from_secs(2)).await;
    assert!(
        !probe_405.ok,
        "405 Method Not Allowed from a random service MUST NOT be treated as confirmed OpenClaw: {probe_405:?}"
    );

    // Probe accepts 401 on `/hooks/agent` WITHOUT ever sending Bearer token!
    unauth_probe_status.store(401, Ordering::SeqCst);
    probes.lock().unwrap().clear();
    let probe_ok = probe_openclaw_gateway(&agent_target, Duration::from_secs(2)).await;
    assert!(probe_ok.ok, "expected probe success on 401: {probe_ok:?}");
    {
        let p_reqs = probes.lock().unwrap();
        assert_eq!(p_reqs.len(), 1);
        assert!(
            p_reqs[0].authorization.is_none(),
            "probe MUST NOT send Bearer token to unverified listener!"
        );
    }

    let agent_transport = OpenClawTransport::new(agent_target);
    let untrusted_secret_body = "UNTRUSTED_BODY_IGNORE_ALL_PREVIOUS_INSTRUCTIONS_4242";
    assert_eq!(
        agent_transport
            .deliver(untrusted_secret_body, PushMode::Queue)
            .await,
        PushOutcome::delivered()
    );
    {
        let reqs = recorded.lock().unwrap();
        assert_eq!(reqs.len(), 1);
        let req = &reqs[0];
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/hooks/agent");
        assert_eq!(
            req.authorization.as_deref(),
            Some("Bearer oc-hooks-secret-token-7788")
        );
        assert_eq!(req.content_type.as_deref(), Some("application/json"));
        assert!(
            req.idempotency_key
                .as_deref()
                .is_some_and(|k| k.starts_with("hyphae-")),
            "expected Idempotency-Key header: {:?}",
            req.idempotency_key
        );
        assert!(
            !req.body.contains(untrusted_secret_body),
            "OpenClaw webhook MUST NEVER leak untrusted body text: {}",
            req.body
        );
        let parsed: Value = serde_json::from_str(&req.body).unwrap();
        assert_eq!(
            parsed["message"],
            "Hyphae mesh: 1 new message(s) queued for @claw. Call hyp_inbox to read them."
        );
        assert_eq!(parsed["name"], "Hyphae");
        assert_eq!(parsed["agentId"], "coder-main");
        assert_eq!(parsed["wakeMode"], "now");
        assert_eq!(parsed["deliver"], false);
    }

    // `/hooks/wake` mode + HTTP 204 Delivered + 429/503 Hold + 401/404 Reject.
    post_status.store(204, Ordering::SeqCst);
    let wake_target = OpenClawTarget::new()
        .with_base_url(&gw_url)
        .with_hooks_path("/hooks")
        .with_endpoint_mode(OpenClawEndpointMode::Wake)
        .with_handle("claw")
        .with_state_dir(&secrets_dir)
        .with_secret_backend(SecretBackend::File);
    let wake_transport = OpenClawTransport::new(wake_target);
    assert_eq!(
        wake_transport
            .deliver_nudge(3, Some("claw"), "batch-wake-1", PushMode::Queue)
            .await,
        PushOutcome::delivered()
    );
    {
        let reqs = recorded.lock().unwrap();
        let req = reqs.last().unwrap();
        assert_eq!(req.path, "/hooks/wake");
        assert_eq!(req.idempotency_key.as_deref(), Some("hyphae-batch-wake-1"));
        let parsed: Value = serde_json::from_str(&req.body).unwrap();
        assert_eq!(
            parsed["text"],
            "Hyphae mesh: 3 new message(s) queued for @claw. Call hyp_inbox to read them."
        );
        assert_eq!(parsed["mode"], "now");
    }

    post_status.store(429, Ordering::SeqCst);
    assert_eq!(
        wake_transport.deliver("x", PushMode::Queue).await,
        PushOutcome::hold(REASON_OPENCLAW_RATE_LIMITED)
    );
    post_status.store(503, Ordering::SeqCst);
    assert_eq!(
        wake_transport.deliver("x", PushMode::Queue).await,
        PushOutcome::hold(REASON_OPENCLAW_GATEWAY_UNAVAILABLE)
    );
    post_status.store(401, Ordering::SeqCst);
    assert_eq!(
        wake_transport.deliver("x", PushMode::Queue).await,
        PushOutcome::reject(REASON_OPENCLAW_AUTH_FAILED)
    );
    post_status.store(404, Ordering::SeqCst);
    assert_eq!(
        wake_transport.deliver("x", PushMode::Queue).await,
        PushOutcome::reject(REASON_OPENCLAW_HOOKS_DISABLED)
    );

    // ---- Part B: LocalDaemon fail-closed without token, auto-attach with node.json + SecretStore,
    //              nudge-only unread preservation for hyp_inbox, and detach on 401 & 404 ----
    post_status.store(200, Ordering::SeqCst);
    recorded.lock().unwrap().clear();

    // 1. Without `openclaw-hooks-token` in SecretStore -> MUST NOT attach!
    let no_tok_dir = tmp.path().join("daemon-no-token");
    fs::create_dir_all(&no_tok_dir).unwrap();
    fs::write(
        no_tok_dir.join("node.json"),
        serde_json::to_string_pretty(&json!({
            "v": 2,
            "nodeId": "oc-notok@box",
            "openclaw": {
                "url": gw_url,
                "hooksPath": "/custom-hooks",
                "agentId": "gw-main",
                "mode": "agent",
                "tokenSecret": "openclaw-hooks-token"
            }
        }))
        .unwrap(),
    )
    .unwrap();
    let node_no_tok = open_local_node("oc-notok@box", &no_tok_dir);
    let daemon_no_tok = LocalDaemon::start(
        Arc::clone(&node_no_tok),
        None,
        LocalDaemonConfig {
            auto_detect_transports: true,
            herdr_bin: Some(tmp.path().join("no-hc").display().to_string()),
            t3_default_base_dir: Some(tmp.path().join("no-t3")),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let sock_no_tok = daemon_no_tok.socket_path().to_path_buf();
    let mut oc_no_tok_opts = McpOptions::new(sock_no_tok.clone());
    oc_no_tok_opts.backend = Some(HarnessKind::Openclaw);
    oc_no_tok_opts.ephemeral = true;
    let mut oc_no_tok_mcp = TestMcpClient::spawn(oc_no_tok_opts);
    oc_no_tok_mcp.initialize().await;
    let (join_no_tok, err_no_tok) = oc_no_tok_mcp
        .call_tool("hyp_mesh", json!({ "action": "join", "handle": "claw" }), None)
        .await;
    assert!(!err_no_tok, "openclaw join without token failed: {join_no_tok}");
    let join_no_tok_val: Value = serde_json::from_str(&join_no_tok).unwrap();
    assert_eq!(
        join_no_tok_val["hasLiveTransport"], false,
        "OpenClaw MUST NOT claim live transport when openclaw-hooks-token is absent: {join_no_tok_val}"
    );
    oc_no_tok_mcp.close().await;
    daemon_no_tok.stop().await;
    node_no_tok.shutdown();

    // 2. With locked `openclaw-hooks-token` + `node.json` `"openclaw"` block -> auto-attaches cleanly!
    let authed_dir = tmp.path().join("daemon-authed");
    fs::create_dir_all(&authed_dir).unwrap();
    fs::write(
        authed_dir.join("node.json"),
        serde_json::to_string_pretty(&json!({
            "v": 2,
            "nodeId": "oc-live@box",
            "openclaw": {
                "url": gw_url,
                "hooksPath": "/custom-hooks",
                "agentId": "gw-main",
                "mode": "agent",
                "tokenSecret": "openclaw-hooks-token"
            }
        }))
        .unwrap(),
    )
    .unwrap();
    let authed_store = SecretStore::new(&authed_dir, SecretBackend::File);
    authed_store
        .set(DEFAULT_OPENCLAW_TOKEN_SECRET, token_val)
        .unwrap();

    let node_live = open_local_node("oc-live@box", &authed_dir);
    let daemon_live = LocalDaemon::start(
        Arc::clone(&node_live),
        None,
        LocalDaemonConfig {
            auto_detect_transports: true,
            herdr_bin: Some(tmp.path().join("no-hc").display().to_string()),
            t3_default_base_dir: Some(tmp.path().join("no-t3-2")),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let sock_live = daemon_live.socket_path().to_path_buf();
    let ui_state_path = daemon_live.ui_state_path();

    let mut oc_opts = McpOptions::new(sock_live.clone());
    oc_opts.backend = Some(HarnessKind::Openclaw);
    oc_opts.ephemeral = true;
    let mut oc_mcp = TestMcpClient::spawn(oc_opts);
    oc_mcp.initialize().await;

    let (join_txt, join_err) = oc_mcp
        .call_tool("hyp_mesh", json!({ "action": "join", "handle": "claw" }), None)
        .await;
    assert!(!join_err, "openclaw live join failed: {join_txt}");
    let join_val: Value = serde_json::from_str(&join_txt).unwrap();
    assert_eq!(join_val["hasLiveTransport"], true, "join={join_val}");
    assert_eq!(join_val["transport"]["kind"], "openclaw");

    let oc_session_id = node_live
        .db()
        .local()
        .session_by_handle("claw")
        .unwrap()
        .expect("claw session")
        .id;

    // Ingest DM -> OpenClaw receives metadata-only nudge, while DM stays unread for hyp_inbox!
    let _ = daemon_live
        .ingest_inbound(InboundItem {
            session_id: oc_session_id.clone(),
            origin_node: "peer@box".into(),
            item_id: "oc-dm-1".into(),
            source: "peer@box/dev".into(),
            text: "PRIVATE_DM_MUST_NOT_ENTER_GATEWAY_HOOK_PROMPT".into(),
            kind: MailboxKind::Message,
            trust_tier: GateTrustTier::Peer,
        })
        .await
        .unwrap();

    {
        let reqs = recorded.lock().unwrap();
        assert_eq!(reqs.len(), 1, "expected exactly 1 OpenClaw webhook nudge");
        assert_eq!(reqs[0].path, "/custom-hooks/agent");
        assert!(
            !reqs[0]
                .body
                .contains("PRIVATE_DM_MUST_NOT_ENTER_GATEWAY_HOOK_PROMPT"),
            "OpenClaw webhook body MUST NOT leak raw DM text: {}",
            reqs[0].body
        );
        let body_json: Value = serde_json::from_str(&reqs[0].body).unwrap();
        assert_eq!(
            body_json["message"],
            "Hyphae mesh: 1 new message(s) queued for @claw. Call hyp_inbox to read them."
        );
        assert_eq!(body_json["agentId"], "gw-main");
    }

    // Message MUST still be unread so OpenClaw's `hyp_inbox` call actually reads it!
    let (inbox_txt, inbox_err) = oc_mcp
        .call_tool("hyp_inbox", json!({ "ack": true }), None)
        .await;
    assert!(!inbox_err, "hyp_inbox failed: {inbox_txt}");
    assert!(
        inbox_txt.contains("PRIVATE_DM_MUST_NOT_ENTER_GATEWAY_HOOK_PROMPT"),
        "OpenClaw hyp_inbox must return the unread DM preserved after wake nudge: {inbox_txt}"
    );

    // 3. Gateway returns 401 -> LocalDaemon detaches OpenClawTransport cleanly!
    post_status.store(401, Ordering::SeqCst);
    let _ = daemon_live
        .ingest_inbound(InboundItem {
            session_id: oc_session_id.clone(),
            origin_node: "peer@box".into(),
            item_id: "oc-dm-401".into(),
            source: "peer@box/dev".into(),
            text: "PRESERVED_ON_401_DETACH".into(),
            kind: MailboxKind::Message,
            trust_tier: GateTrustTier::Peer,
        })
        .await
        .unwrap();
    assert_eq!(
        daemon_live.session_transport_kind(&oc_session_id),
        None,
        "HTTP 401 must detach OpenClawTransport immediately"
    );
    let ui_401: Value = serde_json::from_str(&fs::read_to_string(&ui_state_path).unwrap()).unwrap();
    let sess_401 = ui_401["sessions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["sessionId"] == oc_session_id)
        .unwrap();
    assert_eq!(sess_401["hasLiveTransport"], false);

    // 4. Re-attach and verify HTTP 404 (`openclaw_hooks_disabled`) also detaches cleanly!
    let (ack_401, _) = oc_mcp
        .call_tool("hyp_inbox", json!({ "ack": true }), None)
        .await;
    assert!(ack_401.contains("PRESERVED_ON_401_DETACH"));
    let reattach_target = OpenClawTarget::new()
        .with_base_url(&gw_url)
        .with_hooks_path("/custom-hooks")
        .with_token_override(token_val)
        .with_handle("claw");
    daemon_live.register_session_transport(
        oc_session_id.clone(),
        Arc::new(OpenClawTransport::new(reattach_target)),
    );
    assert_eq!(
        daemon_live.session_transport_kind(&oc_session_id),
        Some("openclaw")
    );
    post_status.store(404, Ordering::SeqCst);
    let _ = daemon_live
        .ingest_inbound(InboundItem {
            session_id: oc_session_id.clone(),
            origin_node: "peer@box".into(),
            item_id: "oc-dm-404".into(),
            source: "peer@box/dev".into(),
            text: "PRESERVED_ON_404_DETACH".into(),
            kind: MailboxKind::Message,
            trust_tier: GateTrustTier::Peer,
        })
        .await
        .unwrap();
    assert_eq!(
        daemon_live.session_transport_kind(&oc_session_id),
        None,
        "HTTP 404 must detach OpenClawTransport immediately"
    );

    oc_mcp.close().await;
    daemon_live.stop().await;
    node_live.shutdown();
    gw_srv.abort();
}

// ============================================================================
// 2. X8 (P1): Codex Rollout JSONL Verification + Automatic UUID Queue Wiring
// ============================================================================

#[test]
fn x8_verify_codex_rollout_thread_handles_nested_files_and_rejects_traversal_and_symlinks() {
    let tmp = TempDir::new().unwrap();
    let codex_home = tmp.path().join("codex-home");
    let nested_dir = codex_home.join("sessions/2026/11/25");
    fs::create_dir_all(&nested_dir).unwrap();

    let valid_uuid = "0196a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";
    let missing_uuid = "0196a1b2-c3d4-7e5f-8a9b-ffffffffffff";
    assert!(is_valid_codex_uuid(valid_uuid));
    assert!(!is_valid_codex_uuid("thr-not-a-uuid"));
    assert!(!is_valid_codex_uuid("../escape"));

    fs::write(
        nested_dir.join(format!("rollout-2026-11-25T10-00-00-{valid_uuid}.jsonl")),
        "{}\n",
    )
    .unwrap();
    // Non-JSONL file must NOT match!
    fs::write(
        nested_dir.join(format!("rollout-{missing_uuid}.txt")),
        "not jsonl\n",
    )
    .unwrap();

    assert!(verify_codex_rollout_thread(&codex_home, valid_uuid));
    assert!(verify_codex_rollout_thread(
        &codex_home,
        &valid_uuid.to_uppercase()
    ));
    assert!(!verify_codex_rollout_thread(&codex_home, missing_uuid));

    // Path traversal & flag injection MUST fail closed!
    for bad in [
        "",
        "..",
        "../outside",
        "2026/11/25/rollout",
        "a\\b",
        "--evil",
        "id\0nul",
    ] {
        assert!(
            !verify_codex_rollout_thread(&codex_home, bad),
            "expected unsafe thread_id {bad:?} to be rejected"
        );
    }

    // Symlink escape outside `$CODEX_HOME/sessions/` MUST NOT match!
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let outside = tmp.path().join("outside");
        fs::create_dir_all(&outside).unwrap();
        let escaped_uuid = "0196a1b2-c3d4-7e5f-8a9b-111111111111";
        let escaped_file = outside.join(format!("rollout-{escaped_uuid}.jsonl"));
        fs::write(&escaped_file, "{}\n").unwrap();
        symlink(
            &escaped_file,
            nested_dir.join(format!("rollout-{escaped_uuid}.jsonl")),
        )
        .unwrap();
        assert!(
            !verify_codex_rollout_thread(&codex_home, escaped_uuid),
            "symlinked rollout file must be ignored fail-closed"
        );
    }
}

#[cfg(unix)]
#[tokio::test]
async fn x8_codex_uuid_session_auto_attaches_queue_transport_when_rollout_exists() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = TempDir::new().unwrap();
    let state_dir = tmp.path().join("state");
    let codex_home = tmp.path().join("codex-home");
    let sessions_dir = codex_home.join("sessions/2026/11/25");
    fs::create_dir_all(&state_dir).unwrap();
    fs::create_dir_all(&sessions_dir).unwrap();

    let live_uuid = "0196b2c3-d4e5-7f60-9a1b-2c3d4e5f6071";
    let missing_uuid = "0196b2c3-d4e5-7f60-9a1b-deadbeef0000";
    fs::write(
        sessions_dir.join(format!("rollout-2026-11-25-{live_uuid}.jsonl")),
        "{\"type\":\"session_meta\"}\n",
    )
    .unwrap();

    let log_path = tmp.path().join("codex-queue.log");
    let fake_codex = tmp.path().join("fake-codex");
    fs::write(
        &fake_codex,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"{}\"\nexit 0\n",
            log_path.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&fake_codex, fs::Permissions::from_mode(0o755)).unwrap();

    let node = open_local_node("codex-auto@box", &state_dir);
    let daemon = LocalDaemon::start(
        Arc::clone(&node),
        None,
        LocalDaemonConfig {
            auto_detect_transports: true,
            herdr_bin: Some(tmp.path().join("no-hc").display().to_string()),
            codex_bin: Some(fake_codex.display().to_string()),
            t3_default_base_dir: Some(tmp.path().join("no-t3")),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let sock = daemon.socket_path().to_path_buf();

    let mut mcp = TestMcpClient::spawn(McpOptions::new(sock.clone()));
    mcp.initialize().await;

    // 1. UUID with NO matching rollout JSONL in `$CODEX_HOME/sessions/` MUST NOT auto-attach!
    let pre_miss = run_hook_with_hints(
        &sock,
        HarnessKind::Codex,
        HookEvent::PreToolUse,
        json!({
            "thread_id": missing_uuid,
            "tool_name": "mcp__hyphae__hyp_mesh",
            "tool_use_id": "call-cx-miss",
            "tool_input": { "action": "join", "handle": "missing-cx" }
        }),
        HookTransportHints {
            codex_home: Some(codex_home.display().to_string()),
            ..Default::default()
        },
    )
    .await;
    assert_eq!(pre_miss, json!({}));
    let (j_miss_txt, j_miss_err) = mcp
        .call_tool(
            "hyp_mesh",
            json!({ "action": "join", "handle": "missing-cx" }),
            Some(json!({ "callId": "call-cx-miss" })),
        )
        .await;
    assert!(!j_miss_err, "{j_miss_txt}");
    let j_miss: Value = serde_json::from_str(&j_miss_txt).unwrap();
    assert_eq!(
        j_miss["hasLiveTransport"], false,
        "missing rollout JSONL must NOT auto-attach CodexQueueTransport: {j_miss}"
    );

    // 2. Valid UUID WITH rollout JSONL auto-attaches `codex_queue` purely from PreToolUse (zero `--thread` flag)!
    let pre_ok = run_hook_with_hints(
        &sock,
        HarnessKind::Codex,
        HookEvent::PreToolUse,
        json!({
            "thread_id": live_uuid,
            "tool_name": "mcp__hyphae__hyp_mesh",
            "tool_use_id": "call-cx-ok",
            "tool_input": { "action": "join", "handle": "live-cx" }
        }),
        HookTransportHints {
            codex_home: Some(codex_home.display().to_string()),
            ..Default::default()
        },
    )
    .await;
    assert_eq!(pre_ok, json!({}));
    let (j_ok_txt, j_ok_err) = mcp
        .call_tool(
            "hyp_mesh",
            json!({ "action": "join", "handle": "live-cx" }),
            Some(json!({ "callId": "call-cx-ok" })),
        )
        .await;
    assert!(!j_ok_err, "{j_ok_txt}");
    let j_ok: Value = serde_json::from_str(&j_ok_txt).unwrap();
    assert_eq!(j_ok["hasLiveTransport"], true, "{j_ok}");
    assert_eq!(j_ok["transport"]["kind"], "codex_queue");

    // Stop hook stays silent because live `codex_queue` transport is attached!
    let stop_out = run_hook(
        &sock,
        HarnessKind::Codex,
        HookEvent::Stop,
        json!({ "thread_id": live_uuid }),
    )
    .await;
    assert_eq!(stop_out, json!({}));

    // Deliver inbound DM -> `fake-codex queue --thread <live_uuid> --message ...` runs!
    let _ = daemon
        .ingest_inbound(InboundItem {
            session_id: format!("codex:{live_uuid}"),
            origin_node: "peer@box".into(),
            item_id: "cx-dm-1".into(),
            source: "peer@box/dev".into(),
            text: "AUTO_WIRED_CODEX_QUEUE_WAKEUP".into(),
            kind: MailboxKind::Message,
            trust_tier: GateTrustTier::Peer,
        })
        .await
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(3);
    let mut logged = String::new();
    while Instant::now() < deadline {
        logged = fs::read_to_string(&log_path).unwrap_or_default();
        if logged.contains("AUTO_WIRED_CODEX_QUEUE_WAKEUP") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        logged.contains(&format!("queue --thread {live_uuid} --message"))
            && logged.contains("AUTO_WIRED_CODEX_QUEUE_WAKEUP"),
        "expected fake-codex queue invocation, got:\n{logged}"
    );
    assert_eq!(
        session_status(&sock, &format!("codex:{live_uuid}")).await["pending"],
        0
    );

    mcp.close().await;
    daemon.stop().await;
    node.shutdown();

    // 3. Plain Codex CLI WITHOUT `codex queue` subcommand (`queue --help` exits non-zero) MUST
    //    NOT falsely attach `codex_queue` and MUST preserve the Stop-hook waiter arm prompt!
    let plain_codex = tmp.path().join("plain-codex");
    fs::write(
        &plain_codex,
        "#!/bin/sh\necho 'error: unrecognized subcommand queue' >&2\nexit 2\n",
    )
    .unwrap();
    fs::set_permissions(&plain_codex, fs::Permissions::from_mode(0o755)).unwrap();

    let plain_state = tmp.path().join("state-plain-codex");
    fs::create_dir_all(&plain_state).unwrap();
    let plain_node = open_local_node("codex-plain@box", &plain_state);
    let plain_daemon = LocalDaemon::start(
        Arc::clone(&plain_node),
        None,
        LocalDaemonConfig {
            auto_detect_transports: true,
            herdr_bin: Some(tmp.path().join("no-hc").display().to_string()),
            codex_bin: Some(plain_codex.display().to_string()),
            t3_default_base_dir: Some(tmp.path().join("no-t3-plain")),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let plain_sock = plain_daemon.socket_path().to_path_buf();
    let mut plain_mcp = TestMcpClient::spawn(McpOptions::new(plain_sock.clone()));
    plain_mcp.initialize().await;

    let _ = run_hook_with_hints(
        &plain_sock,
        HarnessKind::Codex,
        HookEvent::PreToolUse,
        json!({
            "thread_id": live_uuid,
            "tool_name": "mcp__hyphae__hyp_mesh",
            "tool_use_id": "call-cx-plain",
            "tool_input": { "action": "join", "handle": "plain-cx" }
        }),
        HookTransportHints {
            codex_home: Some(codex_home.display().to_string()),
            ..Default::default()
        },
    )
    .await;
    let (j_plain_txt, j_plain_err) = plain_mcp
        .call_tool(
            "hyp_mesh",
            json!({ "action": "join", "handle": "plain-cx" }),
            Some(json!({ "callId": "call-cx-plain" })),
        )
        .await;
    assert!(!j_plain_err, "{j_plain_txt}");
    let j_plain: Value = serde_json::from_str(&j_plain_txt).unwrap();
    assert_eq!(
        j_plain["hasLiveTransport"], false,
        "plain Codex CLI without `codex queue` MUST NOT claim live transport: {j_plain}"
    );
    let plain_stop = run_hook(
        &plain_sock,
        HarnessKind::Codex,
        HookEvent::Stop,
        json!({ "thread_id": live_uuid }),
    )
    .await;
    assert_eq!(plain_stop["decision"], "block");
    assert!(
        plain_stop["reason"]
            .as_str()
            .unwrap()
            .contains(&format!("hyp wait --session codex:{live_uuid}")),
        "plain Codex Stop hook must still prompt to arm hyp wait: {plain_stop}"
    );

    plain_mcp.close().await;
    plain_daemon.stop().await;
    plain_node.shutdown();
}

// ============================================================================
// 3. X9 (P2): LocalDaemon Honors `node.json` `"t3"` Block + Explicit Precedence
// ============================================================================

#[tokio::test]
async fn x9_daemon_honors_node_json_t3_block_and_explicit_hint_precedence() {
    let tmp = TempDir::new().unwrap();
    let state_dir = tmp.path().join("state");
    let custom_t3_base = tmp.path().join("custom-t3-home");
    fs::create_dir_all(&state_dir).unwrap();
    seed_t3_state_db(&custom_t3_base, "sess-nodejson-t3", "thr-nodejson-t3");

    let custom_secret_val = "node-json-t3-secret-555";
    let (t3_url, t3_srv) = spawn_mock_t3_auth_server(custom_secret_val.to_string()).await;

    // Persist `"t3"` block directly inside `<state_dir>/node.json` with allowed `t3-session-token`!
    fs::write(
        state_dir.join("node.json"),
        serde_json::to_string_pretty(&json!({
            "v": 2,
            "nodeId": "t3-nodejson@box",
            "t3": {
                "url": t3_url,
                "baseDir": custom_t3_base.display().to_string(),
                "tokenSecret": "t3-session-token"
            }
        }))
        .unwrap(),
    )
    .unwrap();
    let store = SecretStore::new(&state_dir, SecretBackend::File);
    store
        .set("t3-session-token", custom_secret_val)
        .unwrap();

    // Start LocalDaemon with NO `t3_default_url` / `t3_default_base_dir` overrides so it MUST read `node.json`!
    let node = open_local_node("t3-nodejson@box", &state_dir);
    let daemon = LocalDaemon::start(
        Arc::clone(&node),
        None,
        LocalDaemonConfig {
            auto_detect_transports: true,
            herdr_bin: Some(tmp.path().join("no-hc").display().to_string()),
            t3_default_base_dir: None,
            t3_default_url: None,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let sock = daemon.socket_path().to_path_buf();

    let mut mcp = TestMcpClient::spawn(McpOptions::new(sock.clone()));
    mcp.initialize().await;

    // Send PreToolUse WITHOUT any t3_url or t3_base_dir hints -> daemon resolves from `node.json` `"t3"`!
    let pre = run_hook(
        &sock,
        HarnessKind::Claude,
        HookEvent::PreToolUse,
        json!({
            "session_id": "sess-nodejson-t3",
            "tool_name": "mcp__hyphae__hyp_mesh",
            "tool_use_id": "call-x9-1",
            "tool_input": { "action": "join", "handle": "t3-agent" }
        }),
    )
    .await;
    assert_eq!(pre, json!({}));

    let (join_txt, join_err) = mcp
        .call_tool(
            "hyp_mesh",
            json!({ "action": "join", "handle": "t3-agent" }),
            Some(json!({ "claudecode/toolUseId": "call-x9-1" })),
        )
        .await;
    assert!(!join_err, "join failed: {join_txt}");
    let join_val: Value = serde_json::from_str(&join_txt).unwrap();
    assert_eq!(
        join_val["hasLiveTransport"], true,
        "daemon must honor node.json 't3' block (url, baseDir, tokenSecret): {join_val}"
    );
    assert_eq!(join_val["transport"]["kind"], "t3");

    // Precedence check: explicit hook `t3_url` pointing at an unauthenticated server overrides `node.json`!
    let (bad_t3_url, bad_t3_srv) = spawn_mock_t3_auth_server("different-secret".into()).await;
    seed_t3_state_db(&custom_t3_base, "sess-override-t3", "thr-override-t3");
    let _ = run_hook_with_hints(
        &sock,
        HarnessKind::Claude,
        HookEvent::PreToolUse,
        json!({
            "session_id": "sess-override-t3",
            "tool_name": "mcp__hyphae__hyp_mesh",
            "tool_use_id": "call-x9-2",
            "tool_input": { "action": "join", "handle": "t3-override" }
        }),
        HookTransportHints {
            t3_url: Some(bad_t3_url),
            ..Default::default()
        },
    )
    .await;
    let (join2_txt, join2_err) = mcp
        .call_tool(
            "hyp_mesh",
            json!({ "action": "join", "handle": "t3-override" }),
            Some(json!({ "claudecode/toolUseId": "call-x9-2" })),
        )
        .await;
    assert!(!join2_err, "{join2_txt}");
    let join2_val: Value = serde_json::from_str(&join2_txt).unwrap();
    assert_eq!(
        join2_val["hasLiveTransport"], false,
        "explicit t3_url hint must take precedence over node.json 't3.url': {join2_val}"
    );

    mcp.close().await;
    daemon.stop().await;

    // Security check: arbitrary `tokenSecret` in `node.json` `"t3"` MUST fail closed (no exfil)!
    let exfil_dir = tmp.path().join("state-t3-exfil");
    fs::create_dir_all(&exfil_dir).unwrap();
    fs::write(
        exfil_dir.join("node.json"),
        serde_json::to_string_pretty(&json!({
            "v": 2,
            "nodeId": "t3-exfil@box",
            "t3": {
                "url": t3_url,
                "baseDir": custom_t3_base.display().to_string(),
                "tokenSecret": "other-unrelated-secret"
            }
        }))
        .unwrap(),
    )
    .unwrap();
    let exfil_store = SecretStore::new(&exfil_dir, SecretBackend::File);
    exfil_store
        .set("other-unrelated-secret", custom_secret_val)
        .unwrap();
    let exfil_node = open_local_node("t3-exfil@box", &exfil_dir);
    let exfil_daemon = LocalDaemon::start(
        Arc::clone(&exfil_node),
        None,
        LocalDaemonConfig {
            auto_detect_transports: true,
            herdr_bin: Some(tmp.path().join("no-hc").display().to_string()),
            t3_default_base_dir: None,
            t3_default_url: None,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let exfil_sock = exfil_daemon.socket_path().to_path_buf();
    let mut exfil_mcp = TestMcpClient::spawn(McpOptions::new(exfil_sock.clone()));
    exfil_mcp.initialize().await;
    let _ = run_hook(
        &exfil_sock,
        HarnessKind::Claude,
        HookEvent::PreToolUse,
        json!({
            "session_id": "sess-nodejson-t3",
            "tool_name": "mcp__hyphae__hyp_mesh",
            "tool_use_id": "call-x9-exfil",
            "tool_input": { "action": "join", "handle": "t3-exfil" }
        }),
    )
    .await;
    let (exfil_txt, exfil_err) = exfil_mcp
        .call_tool(
            "hyp_mesh",
            json!({ "action": "join", "handle": "t3-exfil" }),
            Some(json!({ "claudecode/toolUseId": "call-x9-exfil" })),
        )
        .await;
    assert!(!exfil_err, "{exfil_txt}");
    let exfil_val: Value = serde_json::from_str(&exfil_txt).unwrap();
    assert_eq!(
        exfil_val["hasLiveTransport"], false,
        "arbitrary T3 tokenSecret MUST fail closed and NEVER attach: {exfil_val}"
    );
    exfil_mcp.close().await;
    exfil_daemon.stop().await;
    exfil_node.shutdown();

    t3_srv.abort();
    bad_t3_srv.abort();
    node.shutdown();
}

// ============================================================================
// 4. X5 & X6 (P1): Per-Session `sessionToken` Auth & `--ephemeral` Fail-Closed
// ============================================================================

async fn expect_wait_error(sock: &Path, sub_packet: Value) -> Value {
    let (r, mut w) = connect_daemon_async(sock).await.unwrap();
    let mut reader = BufReader::new(r);
    write_ndjson_line_async(&mut w, &sub_packet).await.unwrap();
    let line = read_bounded_line_async(&mut reader, MAX_SOCKET_LINE_BYTES)
        .await
        .unwrap()
        .expect("expected wait.error line");
    serde_json::from_str(&line).unwrap()
}

#[tokio::test]
async fn x5_x6_session_token_blocks_cross_session_hijack_and_ephemeral_never_bypasses_bad_token() {
    let tmp = TempDir::new().unwrap();
    let node = open_local_node("sec-x5x6@box", tmp.path());
    let daemon = LocalDaemon::start(Arc::clone(&node), None, LocalDaemonConfig::default())
        .await
        .unwrap();
    let sock = daemon.socket_path().to_path_buf();

    // ---- Part A (Wave 4B P0): Deterministic HMAC `sessionToken`, zero first-caller hijack,
    //              Claude hook compatibility (omitted token OK, forged token rejected), and
    //              strict `wait.subscribe` enforcement across daemon restarts! ----
    let victim_sid = "claude:victim-x5";
    let attacker_sid = "claude:attacker-x5";
    let unexported_sid = "codex:other-no-env";

    // 1. `session.register`, `session.hint{requestSessionToken:true}`, and
    //    `call.start{requestSessionToken:true}` MUST NEVER mint/return `sessionToken`!
    let reg_res = rpc(
        &sock,
        &json!({
            "type": "session.register",
            "harness": "claude",
            "sessionId": victim_sid,
            "requestSessionToken": true,
        }),
    )
    .await;
    assert!(reg_res.ok, "session.register failed: {reg_res:?}");
    assert!(
        reg_res.result.as_ref().unwrap().get("sessionToken").is_none(),
        "session.register MUST NOT return sessionToken: {reg_res:?}"
    );

    let hint_res = rpc(
        &sock,
        &json!({
            "type": "session.hint",
            "harness": "claude",
            "sessionId": victim_sid,
            "requestSessionToken": true,
        }),
    )
    .await;
    assert!(hint_res.ok);
    assert!(
        hint_res
            .result
            .as_ref()
            .unwrap()
            .get("sessionToken")
            .is_none(),
        "session.hint MUST NOT return sessionToken: {hint_res:?}"
    );

    let cs_req_res = rpc(
        &sock,
        &json!({
            "type": "call.start",
            "harness": "claude",
            "sessionId": victim_sid,
            "tool": "hyp_session",
            "callId": "call-no-mint",
            "requestSessionToken": true,
        }),
    )
    .await;
    assert!(cs_req_res.ok);
    assert!(
        cs_req_res
            .result
            .as_ref()
            .unwrap()
            .get("sessionToken")
            .is_none(),
        "call.start MUST NOT return sessionToken: {cs_req_res:?}"
    );

    // 2. ONLY `session.start` (`SessionStart` hook path) derives & returns `sessionToken`!
    let start_victim = rpc(
        &sock,
        &json!({
            "type": "session.start",
            "harness": "claude",
            "sessionId": victim_sid,
            "envFileExported": true,
        }),
    )
    .await;
    assert!(start_victim.ok, "session.start failed: {start_victim:?}");
    let victim_token = start_victim.result.unwrap()["sessionToken"]
        .as_str()
        .expect("derived sessionToken")
        .to_string();
    assert!(victim_token.starts_with("st_") && victim_token.len() >= 40);

    let start_attacker = rpc(
        &sock,
        &json!({
            "type": "session.start",
            "harness": "claude",
            "sessionId": attacker_sid,
            "envFileExported": true,
        }),
    )
    .await;
    assert!(start_attacker.ok);
    let attacker_token = start_attacker.result.unwrap()["sessionToken"]
        .as_str()
        .unwrap()
        .to_string();
    assert_ne!(victim_token, attacker_token);

    // Passing a mismatched token on `session.start` fails closed!
    let bad_start = rpc(
        &sock,
        &json!({
            "type": "session.start",
            "harness": "claude",
            "sessionId": victim_sid,
            "sessionToken": attacker_token,
        }),
    )
    .await;
    assert!(!bad_start.ok);
    assert_eq!(bad_start.error.as_deref(), Some("session_token_invalid"));

    // 3. CRITICAL FOR REAL CLAUDE CODE: `PreToolUse` (`call.start`) and `PostToolUse`
    //    (`mailbox.drain`) OMITTING `sessionToken` MUST SUCCEED cleanly (because Claude Code
    //    does NOT source `$CLAUDE_ENV_FILE` for hook subprocesses!), while providing a WRONG
    //    `sessionToken` MUST FAIL CLOSED!
    let mut victim_mcp = TestMcpClient::spawn(McpOptions::new(sock.clone()));
    victim_mcp.initialize().await;
    let join_start_no_tok = rpc(
        &sock,
        &json!({
            "type": "call.start",
            "harness": "claude",
            "sessionId": victim_sid,
            "tool": "hyp_session",
            "callId": "call-victim-join"
        }),
    )
    .await;
    assert!(
        join_start_no_tok.ok,
        "Claude PreToolUse hook omitting sessionToken MUST succeed: {join_start_no_tok:?}"
    );
    let (join_txt, join_err) = victim_mcp
        .call_tool(
            "hyp_mesh",
            json!({ "action": "join", "handle": "victim" }),
            Some(json!({ "claudecode/toolUseId": "call-victim-join" })),
        )
        .await;
    assert!(!join_err, "{join_txt}");

    // Register a non-env-exported session too so we test cross-session token mismatch on it!
    node.register_session(unexported_sid, "{\"kind\":\"codex\"}")
        .unwrap();

    // Verify `ui/state.json` keeps `sessionId` for UI controls and NEVER leaks `sessionToken`!
    tokio::time::sleep(Duration::from_millis(150)).await;
    let ui_raw = fs::read_to_string(daemon.ui_state_path()).unwrap();
    assert!(ui_raw.contains(victim_sid));
    assert!(
        !ui_raw.contains(&victim_token) && !ui_raw.contains(&attacker_token),
        "ui/state.json MUST NEVER leak any sessionToken!"
    );

    // Ingest private DM into victim's mailbox.
    let _ = daemon
        .ingest_inbound(InboundItem {
            session_id: victim_sid.into(),
            origin_node: "boss@mac".into(),
            item_id: "x5-secret-1".into(),
            source: "boss@mac/lead".into(),
            text: "TOP_SECRET_VICTIM_DM_X5".into(),
            kind: MailboxKind::Message,
            trust_tier: GateTrustTier::Peer,
        })
        .await
        .unwrap();

    // Wrong/forged tokens on `call.start` and `mailbox.drain` MUST fail closed!
    for wrong_tok in [attacker_token.as_str(), "st_forged_wrong", ""] {
        let d_res = rpc(
            &sock,
            &json!({ "type": "mailbox.drain", "sessionId": victim_sid, "sessionToken": wrong_tok }),
        )
        .await;
        assert!(!d_res.ok, "mailbox.drain must fail for wrong_tok={wrong_tok:?}");
        assert_eq!(d_res.error.as_deref(), Some("session_token_invalid"));

        let c_res = rpc(
            &sock,
            &json!({
                "type": "call.start",
                "harness": "claude",
                "sessionId": victim_sid,
                "tool": "hyp_send",
                "callId": "call-hijack-attempt",
                "sessionToken": wrong_tok,
            }),
        )
        .await;
        assert!(!c_res.ok, "call.start must fail for wrong_tok={wrong_tok:?}");
        assert_eq!(c_res.error.as_deref(), Some("session_token_invalid"));
    }

    // `wait.subscribe` / `inbox.wait` / `inbox.watch` against victim (which has `envFileExported: true`):
    // BOTH missing token (`env -u HYPHAE_SESSION_TOKEN`) AND wrong/attacker token MUST FAIL CLOSED!
    for bad_tok in [None, Some(attacker_token.as_str()), Some("st_forged_wrong")] {
        let mut wait_pkt = json!({ "type": "inbox.wait", "sessionId": victim_sid });
        if let Some(t) = bad_tok {
            wait_pkt["sessionToken"] = json!(t);
        }
        let w_err = expect_wait_error(&sock, wait_pkt).await;
        assert_eq!(w_err["type"], "wait.error");
        assert_eq!(w_err["code"], "session_token_invalid");

        let mut wait_handle_pkt = json!({ "type": "inbox.watch", "handle": "victim" });
        if let Some(t) = bad_tok {
            wait_handle_pkt["sessionToken"] = json!(t);
        }
        let wh_err = expect_wait_error(&sock, wait_handle_pkt).await;
        assert_eq!(wh_err["type"], "wait.error");
        assert_eq!(wh_err["code"], "session_token_invalid");
    }

    // Even targeting a non-exported session with Session A's `HYPHAE_SESSION_TOKEN(A)` fails closed!
    let cross_unexported_err = expect_wait_error(
        &sock,
        json!({
            "type": "wait.subscribe",
            "mode": "once",
            "sessionId": unexported_sid,
            "sessionToken": attacker_token,
        }),
    )
    .await;
    assert_eq!(cross_unexported_err["type"], "wait.error");
    assert_eq!(cross_unexported_err["code"], "session_token_invalid");

    // `run_wait_to_writer_with_token` without token OR with attacker token MUST fail closed!
    for bad_opt in [None, Some(attacker_token.clone())] {
        let mut attacker_buf = Vec::new();
        let bad_wait = run_wait_to_writer_with_token(
            WaitOptions {
                socket_path: sock.clone(),
                mode: WaitMode::Once,
                session_id: Some(victim_sid.into()),
                handle: None,
                timeout_seconds: Some(2.0),
                json: false,
            },
            bad_opt,
            &mut attacker_buf,
        )
        .await;
        assert!(
            bad_wait.is_err(),
            "hyp wait without matching token MUST be rejected"
        );
        assert!(attacker_buf.is_empty());
    }

    // Victim's private DM is STILL untouched and pending!
    assert_eq!(session_status(&sock, victim_sid).await["pending"], 1);

    // ---- DAEMON RESTART PERSISTENCE CHECK ----
    // Stop daemon #1, reopen UnifiedNode + start daemon #2 on the SAME `state_dir`!
    victim_mcp.close().await;
    daemon.stop().await;
    node.shutdown();

    let node2 = open_local_node("sec-x5x6@box", tmp.path());
    let daemon2 = LocalDaemon::start(Arc::clone(&node2), None, LocalDaemonConfig::default())
        .await
        .unwrap();
    let sock2 = daemon2.socket_path().to_path_buf();

    // `session.start` (e.g. `claude --resume`) derives the EXACT SAME deterministic HMAC token!
    let resumed_start = rpc(
        &sock2,
        &json!({
            "type": "session.start",
            "harness": "claude",
            "sessionId": victim_sid,
            "envFileExported": true,
        }),
    )
    .await;
    assert!(resumed_start.ok);
    assert_eq!(
        resumed_start.result.unwrap()["sessionToken"].as_str(),
        Some(victim_token.as_str()),
        "deterministic HMAC sessionToken MUST survive daemon restarts!"
    );

    // After restart, missing token on `wait.subscribe` STILL fails closed (envFileExported persisted)!
    let post_restart_missing = expect_wait_error(
        &sock2,
        json!({ "type": "inbox.wait", "sessionId": victim_sid }),
    )
    .await;
    assert_eq!(post_restart_missing["code"], "session_token_invalid");

    // Legitimate `run_wait_to_writer_with_token` with the pre-restart `victim_token` SUCCEEDS!
    let mut victim_buf = Vec::new();
    let ok_wait = run_wait_to_writer_with_token(
        WaitOptions {
            socket_path: sock2.clone(),
            mode: WaitMode::Once,
            session_id: Some(victim_sid.into()),
            handle: None,
            timeout_seconds: Some(2.0),
            json: false,
        },
        Some(victim_token.clone()),
        &mut victim_buf,
    )
    .await
    .expect("wait with persisted HMAC sessionToken must succeed after daemon restart");
    assert_eq!(ok_wait, 0);
    assert!(
        String::from_utf8(victim_buf)
            .unwrap()
            .contains("TOP_SECRET_VICTIM_DM_X5")
    );

    // Real Claude Code `PostToolUse` hook OMITTING `sessionToken` drains cleanly too!
    let _ = daemon2
        .ingest_inbound(InboundItem {
            session_id: victim_sid.into(),
            origin_node: "boss@mac".into(),
            item_id: "x5-secret-2".into(),
            source: "boss@mac/lead".into(),
            text: "SECOND_VICTIM_DM_X5".into(),
            kind: MailboxKind::Message,
            trust_tier: GateTrustTier::Peer,
        })
        .await
        .unwrap();
    let hook_opts = HandleHookOptions {
        harness: HarnessKind::Claude,
        event: HookEvent::PostToolUse,
        socket_path: sock2.clone(),
        cli_path: Some("hyp".into()),
        explicit_socket: None,
        transport_hints: HookTransportHints::default(),
    };
    let post_no_tok = tokio::task::spawn_blocking(move || {
        handle_hook_payload_with_session_token(
            json!({ "session_id": "victim-x5", "tool_name": "Bash", "tool_use_id": "tu-ok" })
                .as_object()
                .unwrap(),
            &hook_opts,
            None,
            |s, p| daemon_rpc_sync(s, p, Duration::from_secs(2)),
        )
    })
    .await
    .unwrap();
    assert!(
        post_no_tok.to_string().contains("SECOND_VICTIM_DM_X5"),
        "Claude PostToolUse hook omitting sessionToken MUST drain cleanly: {post_no_tok}"
    );

    // ---- Part B (X6): `--ephemeral` MUST NEVER bypass an invalid/replayed `_meshCall` token,
    //              AND one forged `call.start{harness:"openclaw"}` MUST NOT poison all OpenClaw sessions! ----
    let forged_oc_hook = rpc(
        &sock2,
        &json!({
            "type": "call.start",
            "harness": "openclaw",
            "sessionId": "openclaw:forged-attacker",
            "tool": "hyp_session",
            "callId": "forged-oc-call-1"
        }),
    )
    .await;
    assert!(forged_oc_hook.ok);

    let mut eph_opts = McpOptions::new(sock2.clone());
    eph_opts.backend = Some(HarnessKind::Openclaw);
    eph_opts.ephemeral = true;
    let mut eph_mcp = TestMcpClient::spawn(eph_opts);
    eph_mcp.initialize().await;

    // 1. Plain call AND unregistered `_meta.callId` on hookless OpenClaw `--ephemeral` STILL succeed
    //    (NOT globally poisoned by the forged `call.start{harness:"openclaw"}` above!).
    let (ok_txt, ok_err) = eph_mcp
        .call_tool("hyp_mesh", json!({ "action": "status" }), None)
        .await;
    assert!(!ok_err, "hookless openclaw ephemeral status failed: {ok_txt}");
    let (ok_meta_txt, ok_meta_err) = eph_mcp
        .call_tool(
            "hyp_mesh",
            json!({ "action": "status" }),
            Some(json!({ "callId": "unrelated-openclaw-call-id" })),
        )
        .await;
    assert!(
        !ok_meta_err,
        "X6: forged call.start{{harness:\"openclaw\"}} MUST NOT globally poison unrelated OpenClaw sessions: {ok_meta_txt}"
    );

    // 2. Forged/invalid `_meshCall` on `--ephemeral` MUST FAIL CLOSED (never fall back to ephemeral!).
    let (forged_txt, forged_err) = eph_mcp
        .call_tool(
            "hyp_mesh",
            json!({ "action": "status", "_meshCall": "ct_forged_invalid_token_999" }),
            None,
        )
        .await;
    assert!(
        forged_err,
        "X6: --ephemeral MUST NOT bypass an invalid _meshCall token: {forged_txt}"
    );

    // 3. Replayed single-use `_meshCall` token on `--ephemeral` MUST FAIL CLOSED!
    let mut victim_mcp2 = TestMcpClient::spawn(McpOptions::new(sock2.clone()));
    victim_mcp2.initialize().await;
    let legit_call = rpc(
        &sock2,
        &json!({
            "type": "call.start",
            "harness": "claude",
            "sessionId": victim_sid,
            "sessionToken": victim_token,
            "tool": "hyp_session",
            "callId": "call-replay-src"
        }),
    )
    .await;
    assert!(legit_call.ok);
    let real_call_tok = legit_call.result.unwrap()["callToken"]
        .as_str()
        .unwrap()
        .to_string();
    let (_first_txt, first_err) = victim_mcp2
        .call_tool(
            "hyp_mesh",
            json!({ "action": "status", "_meshCall": real_call_tok }),
            None,
        )
        .await;
    assert!(!first_err);
    let (replay_txt, replay_err) = eph_mcp
        .call_tool(
            "hyp_mesh",
            json!({ "action": "status", "_meshCall": real_call_tok }),
            None,
        )
        .await;
    assert!(
        replay_err,
        "X6: --ephemeral MUST NOT bypass a replayed _meshCall token: {replay_txt}"
    );

    // 4. Native-hook harness (`Claude`) `--ephemeral` client presenting an unregistered `_meta.callId`
    //    MUST fail closed!
    let mut eph_claude_opts = McpOptions::new(sock2.clone());
    eph_claude_opts.backend = Some(HarnessKind::Claude);
    eph_claude_opts.ephemeral = true;
    let mut eph_claude_mcp = TestMcpClient::spawn(eph_claude_opts);
    eph_claude_mcp.initialize().await;
    let (unreg_txt, unreg_err) = eph_claude_mcp
        .call_tool(
            "hyp_mesh",
            json!({ "action": "status" }),
            Some(json!({ "claudecode/toolUseId": "toolu_unregistered_999" })),
        )
        .await;
    assert!(
        unreg_err,
        "X6: --ephemeral claude client with unregistered callId must fail closed: {unreg_txt}"
    );

    eph_claude_mcp.close().await;
    eph_mcp.close().await;
    victim_mcp2.close().await;
    daemon2.stop().await;
    node2.shutdown();
}
