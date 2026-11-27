//! Wave 2 Daemon Hardening, Persistent Mute TTL, Session Pruning, Drop Watcher Reconnect &
//! Gate Polish E2E Test Suite (`X3`, `X4`, `U4`, `U6`, `G16`, `H6`, `H9`, `G8`, `G10`, `G12`, `G14`, `R5`).
//!
//! Strictly hermetic: `TempDir`, `127.0.0.1:0`, `SecretBackend::File`, zero live Keychain or host
//! mutations, deterministic synchronization.

mod common;

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::{TestMcpClient, run_hook, run_hook_with_hints, session_status};
use hyp_crypto::human::{HumanAudience, HumanClaimV1, HumanDropKind, seal_human_drop};
use hyp_crypto::rfc3339::format_rfc3339_millis;
use hyp_crypto::{Ed25519KeyPair, SecretBackend, SecretStore};
use hyp_harness::daemon::{InboundItem, LocalDaemon, LocalDaemonConfig};
use hyp_harness::hooks::{HookEvent, HookTransportHints};
use hyp_harness::mcp::McpOptions;
use hyp_harness::protocol::HarnessKind;
use hyp_harness::sock::{DaemonRpcResult, daemon_rpc_async};
use hyp_harness::transport::t3::{
    DEFAULT_T3_TOKEN_SECRET, T3Target, T3Transport, t3_state_db_path,
};
use hyp_harness::transport::{InboxDigest, PushMode, PushOutcome, PushTransport, TransportFuture};
use hyp_node::delivery::{DeliveryError, InboxQuery, InboxStateFilter, query_inbox};
use hyp_node::engine::{LocalIngestServer, NodeConfig, UnifiedNode, send_local_ingest_event};
use hyp_node::gates::SecurityGatePipeline;
use hyp_node::gates::policy::{
    GateDecision, InboundContext, SecurityGateConfig, Stage1DenyAction, TrustTier as GateTrustTier,
    sign_gate_policy,
};
use hyp_proto::address::NodeId;
use hyp_proto::cloudevent::{CONTENT_TYPE_JSON, CloudEvent, TYPE_SCHEDULED_MESSAGE_V1};
use hyp_store::{
    GateState, HumanAuthorityInput, HumanAuthorityRole, MailboxInsert, MailboxKind,
    MailboxPutResult, NodeDb, now_ms, uuid_v4,
};
use rusqlite::Connection;
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Notify;

fn open_local_node(node_id: &str, dir: &Path) -> Arc<UnifiedNode> {
    let mut cfg = NodeConfig::local(NodeId::new(node_id).unwrap(), dir);
    cfg.secret_backend = Some(SecretBackend::File);
    UnifiedNode::open(cfg).expect("open UnifiedNode")
}

async fn rpc(sock: &Path, pkt: &Value) -> DaemonRpcResult {
    daemon_rpc_async(sock, pkt, Duration::from_secs(5)).await
}

struct ScriptedTransport {
    kind: &'static str,
    outcomes: Mutex<VecDeque<PushOutcome>>,
    default_outcome: PushOutcome,
    attempts: AtomicUsize,
    delivered: Mutex<Vec<(String, PushMode)>>,
    notify: Notify,
}

impl ScriptedTransport {
    fn new(
        kind: &'static str,
        scripted: Vec<PushOutcome>,
        default_outcome: PushOutcome,
    ) -> Arc<Self> {
        Arc::new(Self {
            kind,
            outcomes: Mutex::new(scripted.into()),
            default_outcome,
            attempts: AtomicUsize::new(0),
            delivered: Mutex::new(Vec::new()),
            notify: Notify::new(),
        })
    }

    fn attempts(&self) -> usize {
        self.attempts.load(Ordering::SeqCst)
    }

    fn delivered_texts(&self) -> Vec<String> {
        self.delivered
            .lock()
            .unwrap()
            .iter()
            .map(|(t, _)| t.clone())
            .collect()
    }

    async fn wait_for_delivered(&self, expected: usize, timeout: Duration) -> Vec<String> {
        let deadline = Instant::now() + timeout;
        loop {
            let cur = self.delivered_texts();
            if cur.len() >= expected {
                return cur;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                panic!(
                    "timed out waiting for {expected} deliveries on {} (got {}): {cur:?}",
                    self.kind,
                    cur.len()
                );
            }
            let _ = tokio::time::timeout(
                remaining.min(Duration::from_millis(50)),
                self.notify.notified(),
            )
            .await;
        }
    }
}

impl PushTransport for ScriptedTransport {
    fn kind(&self) -> &'static str {
        self.kind
    }

    fn supports_interrupt(&self) -> bool {
        true
    }

    fn deliver<'a>(
        &'a self,
        prompt: &'a InboxDigest,
        mode: PushMode,
    ) -> TransportFuture<'a, PushOutcome> {
        let text = prompt.as_str().to_string();
        Box::pin(async move {
            self.attempts.fetch_add(1, Ordering::SeqCst);
            let outcome = self
                .outcomes
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| self.default_outcome.clone());
            if outcome.is_delivered() {
                self.delivered.lock().unwrap().push((text, mode));
            }
            self.notify.notify_waiters();
            outcome
        })
    }
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

/// Minimal HTTP/1.1 loopback T3 `/api/auth/session` probe mock supporting configurable auth check.
async fn spawn_mock_t3_auth_server(
    expected_token: Option<String>,
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
                let auth_ok = match expected {
                    Some(tok) => req_str.lines().any(|line| {
                        line.eq_ignore_ascii_case(&format!("authorization: Bearer {tok}"))
                    }),
                    None => false,
                };
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

fn enroll_human_authority(
    node: &UnifiedNode,
    human_id: &str,
    kp: &Ed25519KeyPair,
    role: HumanAuthorityRole,
) {
    let jwk_json = serde_json::to_string(&kp.to_jwk()).unwrap();
    node.db()
        .human()
        .upsert_authority(
            &HumanAuthorityInput {
                human_id: human_id.to_string(),
                kid: kp.kid(),
                label: format!("Test Human {human_id}"),
                role,
                jwk_json,
                enc_jwk_json: None,
                prf_salt: None,
                auth_epoch: 1,
            },
            now_ms(),
        )
        .unwrap();
}

// ============================================================================
// 1. X3 (P1): Attach T3 Transport ONLY When Authenticated + Detach on t3_auth_missing
// ============================================================================

#[tokio::test]
async fn x3_unauthenticated_t3_never_attaches_and_t3_auth_missing_detaches_cleanly() {
    // Part A: Unauthenticated T3 server (returns HTTP 200 {"authenticated":false}) MUST NOT attach!
    let tmp = TempDir::new().unwrap();
    let state_dir = tmp.path().join("state-unauth");
    let t3_base = tmp.path().join("t3-home");
    fs::create_dir_all(&state_dir).unwrap();
    seed_t3_state_db(&t3_base, "sess-t3-unauth", "thr-t3-unauth");

    let (t3_url, t3_srv) = spawn_mock_t3_auth_server(Some("real-t3-secret".into())).await;
    let node = open_local_node("x3-unauth@box", &state_dir);
    let daemon = LocalDaemon::start(
        Arc::clone(&node),
        None,
        LocalDaemonConfig {
            auto_detect_transports: true,
            t3_default_base_dir: Some(t3_base.clone()),
            t3_default_url: Some(t3_url.clone()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let sock = daemon.socket_path().to_path_buf();

    let mut mcp = TestMcpClient::spawn(McpOptions::new(sock.clone()));
    mcp.initialize().await;

    let pre = run_hook_with_hints(
        &sock,
        HarnessKind::Claude,
        HookEvent::PreToolUse,
        json!({
            "session_id": "sess-t3-unauth",
            "tool_name": "mcp__hyphae__hyp_mesh",
            "tool_use_id": "call-x3-1",
            "tool_input": { "action": "join", "handle": "agent" }
        }),
        HookTransportHints {
            t3_base_dir: Some(t3_base.display().to_string()),
            t3_url: Some(t3_url.clone()),
            ..Default::default()
        },
    )
    .await;
    assert_eq!(pre, json!({}));

    let (join_txt, join_err) = mcp
        .call_tool(
            "hyp_mesh",
            json!({ "action": "join", "handle": "agent" }),
            Some(json!({ "claudecode/toolUseId": "call-x3-1" })),
        )
        .await;
    assert!(!join_err, "join failed: {join_txt}");
    let join_val: Value = serde_json::from_str(&join_txt).unwrap();
    assert_eq!(
        join_val["hasLiveTransport"], false,
        "unauthenticated T3 server MUST NOT attach as live transport: {join_val}"
    );
    assert_eq!(join_val["transport"]["kind"], "none");

    // Part B: With valid bearer token in SecretStore, authenticated T3 server DOES attach!
    let store = SecretStore::new(&state_dir, SecretBackend::File);
    store
        .set(DEFAULT_T3_TOKEN_SECRET, "real-t3-secret")
        .unwrap();
    seed_t3_state_db(&t3_base, "sess-t3-authed", "thr-t3-authed");

    let pre2 = run_hook_with_hints(
        &sock,
        HarnessKind::Claude,
        HookEvent::PreToolUse,
        json!({
            "session_id": "sess-t3-authed",
            "tool_name": "mcp__hyphae__hyp_mesh",
            "tool_use_id": "call-x3-2",
            "tool_input": { "action": "join", "handle": "authed-agent" }
        }),
        HookTransportHints {
            t3_base_dir: Some(t3_base.display().to_string()),
            t3_url: Some(t3_url.clone()),
            ..Default::default()
        },
    )
    .await;
    assert_eq!(pre2, json!({}));
    let (join2_txt, join2_err) = mcp
        .call_tool(
            "hyp_mesh",
            json!({ "action": "join", "handle": "authed-agent" }),
            Some(json!({ "claudecode/toolUseId": "call-x3-2" })),
        )
        .await;
    assert!(!join2_err, "authed join failed: {join2_txt}");
    let join2_val: Value = serde_json::from_str(&join2_txt).unwrap();
    assert_eq!(join2_val["hasLiveTransport"], true);
    assert_eq!(join2_val["transport"]["kind"], "t3");

    // Part C: If the T3 token disappears and delivery fails with `t3_auth_missing`,
    // `flush_session` MUST detach the T3Transport immediately so fallback hooks resume!
    let empty_secrets_dir = tmp.path().join("empty-secrets");
    fs::create_dir_all(&empty_secrets_dir).unwrap();
    let sid_missing = "claude:sess-t3-missing-tok";
    node.register_session(sid_missing, "{\"kind\":\"claude\"}")
        .unwrap();
    daemon.register_session_transport(
        sid_missing,
        Arc::new(T3Transport::new(T3Target {
            thread_id: "thr-missing-tok".into(),
            server_url: t3_url.clone(),
            base_dir: None,
            token_secret: None,
            state_dir: Some(empty_secrets_dir),
            secret_backend: Some(SecretBackend::File),
            token_override: None,
        })),
    );
    assert_eq!(daemon.session_transport_kind(sid_missing), Some("t3"));

    let _ = daemon
        .ingest_inbound(InboundItem {
            session_id: sid_missing.into(),
            origin_node: "peer@box".into(),
            item_id: "x3-fallback-msg".into(),
            source: "peer@box/dev".into(),
            text: "WAKEUP_AFTER_T3_DETACH".into(),
            kind: MailboxKind::Message,
            trust_tier: GateTrustTier::Peer,
        })
        .await
        .unwrap();

    // T3 transport must now be detached, and unread message preserved for Stop/PostToolUse fallback!
    assert_eq!(
        daemon.session_transport_kind(sid_missing),
        None,
        "t3_auth_missing must detach T3Transport immediately"
    );
    let st = session_status(&sock, sid_missing).await;
    assert_eq!(st["hasLiveTransport"], false);
    assert_eq!(st["pending"], 1);

    // Fallback TurnEnd (Stop) hook now emits metadata-only XML digest for the preserved Queue message!
    let post = run_hook(
        &sock,
        HarnessKind::Claude,
        HookEvent::Stop,
        json!({ "session_id": "sess-t3-missing-tok" }),
    )
    .await;
    let post_reason = post["reason"]
        .as_str()
        .expect("fallback Stop hook must emit XML digest after T3 detach");
    assert!(
        post_reason.starts_with("<hyphae-inbox unread=\"1\" urgency=\"queue\">")
            && post_reason.contains("<dm from=\"peer@box/dev\" count=\"1\"/>"),
        "fallback hook must emit metadata-only XML digest after T3 detach: {post}"
    );
    assert!(
        !post_reason.contains("WAKEUP_AFTER_T3_DETACH"),
        "RFC 0004: fallback Stop hook must NEVER include raw DM body: {post}"
    );

    mcp.close().await;
    daemon.stop().await;
    t3_srv.abort();
    node.shutdown();
}

// ============================================================================
// 2. X4 (P1): Detach Dead Push Transports on Terminal Errors + Refresh ui/state.json
// ============================================================================

#[tokio::test]
async fn x4_terminal_transport_errors_detach_and_immediately_refresh_ui_state() {
    let tmp = TempDir::new().unwrap();
    let node = open_local_node("x4-detach@box", tmp.path());
    let daemon = LocalDaemon::start(Arc::clone(&node), None, LocalDaemonConfig::default())
        .await
        .unwrap();
    let sock = daemon.socket_path().to_path_buf();
    let ui_state_path = daemon.ui_state_path();

    for (sid, kind, outcome, msg_text) in [
        (
            "claude:herdr-dead",
            "herdr",
            PushOutcome::hold("herdr_target_unavailable"),
            "HERDR_PRESERVED_PAYLOAD",
        ),
        (
            "claude:t3-deleted",
            "t3",
            PushOutcome::reject("t3_thread_deleted"),
            "T3_DELETED_PRESERVED_PAYLOAD",
        ),
    ] {
        node.register_session(sid, "{\"kind\":\"claude\"}").unwrap();
        let dead_transport = ScriptedTransport::new(kind, vec![outcome.clone()], outcome);
        daemon.register_session_transport(sid, dead_transport.clone());
        assert_eq!(daemon.session_transport_kind(sid), Some(kind));

        let _ = daemon
            .ingest_inbound(InboundItem {
                session_id: sid.into(),
                origin_node: "bob@lap".into(),
                item_id: format!("x4-item-{kind}"),
                source: "bob@lap/dev".into(),
                text: msg_text.into(),
                kind: MailboxKind::Message,
                trust_tier: GateTrustTier::Peer,
            })
            .await
            .unwrap();

        assert_eq!(dead_transport.attempts(), 1);
        assert_eq!(
            daemon.session_transport_kind(sid),
            None,
            "{kind} terminal error must detach transport via unregister_session_transport"
        );

        // ui/state.json MUST immediately reflect `hasLiveTransport == false`!
        let ui_raw = fs::read_to_string(&ui_state_path).expect("read ui/state.json");
        let ui_json: Value = serde_json::from_str(&ui_raw).expect("parse ui/state.json");
        let sess_entry = ui_json["sessions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["sessionId"] == sid)
            .expect("session in ui/state.json");
        assert_eq!(
            sess_entry["hasLiveTransport"], false,
            "ui/state.json must immediately clear hasLiveTransport for {sid}: {sess_entry}"
        );
        assert!(sess_entry["transportKind"].is_null());

        // Fallback TurnEnd (Stop) hook resumes and emits metadata-only XML digest for preserved Queue message!
        let raw_sid = sid.strip_prefix("claude:").unwrap();
        let hook_out = run_hook(
            &sock,
            HarnessKind::Claude,
            HookEvent::Stop,
            json!({ "session_id": raw_sid }),
        )
        .await;
        let reason = hook_out["reason"]
            .as_str()
            .expect("fallback Stop hook must emit XML digest after detach");
        assert!(
            reason.starts_with("<hyphae-inbox unread=\"1\" urgency=\"queue\">")
                && reason.contains("<dm from=\"bob@lap/dev\" count=\"1\"/>"),
            "fallback hook must emit metadata-only XML digest after {kind} detach: {hook_out}"
        );
        assert!(
            !reason.contains(msg_text),
            "RFC 0004: fallback hook must NEVER include raw body after {kind} detach: {hook_out}"
        );
    }

    daemon.stop().await;
    node.shutdown();
}

// ============================================================================
// 3. U4 (P1): Persistent Mute `--ttl` Across SQLite Reopen & Daemon Restarts
// ============================================================================

#[tokio::test]
async fn u4_mute_ttl_persists_across_reopen_and_daemon_restart_and_expires() {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("u4-store.sqlite");
    let t0 = 1_800_000_000_000i64;
    let exp = t0 + 30_000;

    // 1. Store-level persistence across close & reopen + deterministic expiry check
    {
        let db = NodeDb::open(&db_path).unwrap();
        db.local()
            .register_session("claude:s-u4", "{}", t0)
            .unwrap();
        let rule = db
            .local()
            .add_mute_with_expiry("claude:s-u4", "noisy@peer/*", "human", t0, Some(exp))
            .unwrap();
        assert_eq!(rule.expires_at, Some(exp));
        assert!(
            db.local()
                .is_muted_at("claude:s-u4", &["noisy@peer/bot"], t0 + 10_000)
                .unwrap()
                .is_some()
        );
    }
    {
        let db = NodeDb::open(&db_path).unwrap();
        let before = db
            .local()
            .list_mutes_at(Some("claude:s-u4"), t0 + 29_999)
            .unwrap();
        assert_eq!(before.len(), 1);
        assert_eq!(before[0].expires_at, Some(exp));

        // At/after expiry deadline: treated as unmuted immediately even before sweep!
        assert_eq!(
            db.local()
                .is_muted_at("claude:s-u4", &["noisy@peer/bot"], exp)
                .unwrap(),
            None
        );
        assert!(
            db.local()
                .list_mutes_at(Some("claude:s-u4"), exp)
                .unwrap()
                .is_empty()
        );
        // Sweep deletes expired row cleanly and returns its (scope, pattern).
        let swept = db.local().sweep_expired_mutes(exp).unwrap();
        assert_eq!(
            swept,
            vec![("claude:s-u4".to_string(), "noisy@peer/*".to_string())]
        );
        assert!(db.local().sweep_expired_mutes(exp).unwrap().is_empty());
    }

    // 2. Live LocalDaemon persistence across daemon restart + `expiresAt` in session.summary + auto-expiry!
    let daemon_dir = tmp.path().join("daemon-state");
    fs::create_dir_all(&daemon_dir).unwrap();
    let sid = "claude:u4-live";

    let first_expires_at: i64;
    {
        let node1 = open_local_node("u4-daemon@box", &daemon_dir);
        node1
            .register_session(sid, "{\"kind\":\"claude\"}")
            .unwrap();
        let daemon1 = LocalDaemon::start(Arc::clone(&node1), None, LocalDaemonConfig::default())
            .await
            .unwrap();
        let sock1 = daemon1.socket_path().to_path_buf();

        let mute_res = rpc(
            &sock1,
            &json!({
                "type": "session.mute",
                "sessionId": sid,
                "source": "spam@ext/*",
                "ttlSeconds": 2
            }),
        )
        .await;
        assert!(mute_res.ok, "session.mute failed: {mute_res:?}");
        first_expires_at = mute_res.result.unwrap()["expiresAt"]
            .as_i64()
            .expect("session.mute must return expiresAt");

        // Verify `session.summary` exposes `expiresAt` on the mute rule.
        let sum = rpc(
            &sock1,
            &json!({ "type": "session.summary", "sessionId": sid, "detail": "full" }),
        )
        .await;
        assert!(sum.ok);
        let mutes = sum.result.unwrap()["session"]["details"]["mutes"]
            .as_array()
            .unwrap()
            .clone();
        assert_eq!(mutes.len(), 1);
        assert_eq!(mutes[0]["pattern"], "spam@ext/*");
        assert_eq!(mutes[0]["expiresAt"], first_expires_at);

        daemon1.stop().await;
        node1.shutdown();
    }

    // Restart a brand-new LocalDaemon on the same state_dir!
    let node2 = open_local_node("u4-daemon@box", &daemon_dir);
    let daemon2 = LocalDaemon::start(Arc::clone(&node2), None, LocalDaemonConfig::default())
        .await
        .unwrap();
    let sock2 = daemon2.socket_path().to_path_buf();

    // Immediately after restart (before 2s TTL elapses), the mute MUST still be active in SQLite!
    let active_mutes = node2.db().local().list_mutes(Some(sid)).unwrap();
    assert_eq!(active_mutes.len(), 1);
    assert_eq!(active_mutes[0].expires_at, Some(first_expires_at));

    // Wait past the 2s TTL deadline -> maintenance sweep + summary MUST auto-expire it cleanly!
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let sum2 = rpc(
            &sock2,
            &json!({ "type": "session.summary", "sessionId": sid, "detail": "full" }),
        )
        .await;
        assert!(sum2.ok);
        let sess = &sum2.result.unwrap()["session"];
        let mute_count = sess["counts"]["mutedRules"].as_u64().unwrap_or(99);
        let rule_count = sess["details"]["rules"].as_array().unwrap().len();
        if mute_count == 0 && rule_count == 0 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "persisted TTL mute failed to expire after restart: {sess}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    daemon2.stop().await;
    node2.shutdown();
}

// ============================================================================
// 4. U6 (P1) & G16 (P2): Safe Periodic Session Pruning Preserving Quarantined Items
// ============================================================================

#[tokio::test]
async fn u6_g16_prune_sessions_removes_stale_idle_and_preserves_quarantined_and_live() {
    let tmp = TempDir::new().unwrap();
    let node = open_local_node("u6-prune@box", tmp.path());
    let now = now_ms();
    let stale_ts = now - (10 * 24 * 60 * 60 * 1_000); // 10 days ago

    // 1. Seed 4 sessions: stale-clean, stale-pending (UR1), stale-quarantined, fresh-idle.
    {
        let db = node.db();
        db.local()
            .register_session("claude:stale-clean", "{}", stale_ts)
            .unwrap();
        db.local()
            .register_session("claude:stale-pending", "{}", stale_ts)
            .unwrap();
        db.local()
            .register_session("claude:stale-quarantined", "{}", stale_ts)
            .unwrap();
        db.local()
            .register_session("claude:fresh-idle", "{}", now)
            .unwrap();

        let p_res = db
            .local()
            .put_in_mailbox(
                &MailboxInsert {
                    session_id: "claude:stale-pending".into(),
                    origin_node: "bob@lap".into(),
                    item_id: "p-preserve-1".into(),
                    text: "Unread pending DM that UR1 must NEVER delete".into(),
                    kind: MailboxKind::Message,
                    source: "bob@lap/dev".into(),
                    gate_state: GateState::Pending,
                    gate_reason: None,
                    traceparent: None,
                },
                stale_ts,
            )
            .unwrap();
        assert!(matches!(p_res, MailboxPutResult::Stored { .. }));

        let q_res = db
            .local()
            .put_in_mailbox(
                &MailboxInsert {
                    session_id: "claude:stale-quarantined".into(),
                    origin_node: "untrusted@ext".into(),
                    item_id: "q-preserve-1".into(),
                    text: "Quarantined item awaiting human review".into(),
                    kind: MailboxKind::Message,
                    source: "untrusted@ext/bot".into(),
                    gate_state: GateState::Quarantined,
                    gate_reason: Some("prompt_injection".into()),
                    traceparent: None,
                },
                stale_ts,
            )
            .unwrap();
        assert!(matches!(q_res, MailboxPutResult::Stored { .. }));
    }

    // 2. Start LocalDaemon (runs startup prune with default 7-day threshold + periodic prune).
    let daemon = LocalDaemon::start(
        Arc::clone(&node),
        None,
        LocalDaemonConfig {
            session_prune_after_ms: 7 * 24 * 60 * 60 * 1_000,
            session_prune_interval: Duration::from_millis(300),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    // `stale-clean` MUST be pruned on startup; `stale-pending`, `stale-quarantined`, and `fresh-idle` MUST survive!
    {
        let db = node.db();
        assert!(
            db.local()
                .get_session("claude:stale-clean")
                .unwrap()
                .is_none()
        );
        assert!(
            db.local()
                .get_session("claude:stale-pending")
                .unwrap()
                .is_some(),
            "UR1: stale session holding unread pending items MUST NOT be pruned"
        );
        assert_eq!(db.local().pending_count("claude:stale-pending").unwrap(), 1);
        assert!(
            db.local()
                .get_session("claude:stale-quarantined")
                .unwrap()
                .is_some(),
            "G16: stale session holding quarantined items MUST NOT be pruned"
        );
        assert_eq!(
            db.local()
                .list_quarantined(Some("claude:stale-quarantined"), 10)
                .unwrap()
                .len(),
            1
        );
        assert!(
            db.local()
                .get_session("claude:fresh-idle")
                .unwrap()
                .is_some()
        );
    }

    // 3. Also verify periodic prune protects a stale session with a live attached transport,
    //    then prunes an unprotected stale session added after startup!
    node.db()
        .local()
        .register_session("claude:stale-live-transport", "{}", stale_ts)
        .unwrap();
    let live_t = ScriptedTransport::new("herdr", vec![], PushOutcome::delivered());
    daemon.register_session_transport("claude:stale-live-transport", live_t);
    node.db()
        .local()
        .register_session("claude:stale-later", "{}", stale_ts)
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if node
            .db()
            .local()
            .get_session("claude:stale-later")
            .unwrap()
            .is_none()
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "periodic pruning failed to prune claude:stale-later"
        );
        tokio::time::sleep(Duration::from_millis(40)).await;
    }

    // Active connected session + quarantined session STILL preserved after periodic prune!
    assert!(
        node.db()
            .local()
            .get_session("claude:stale-live-transport")
            .unwrap()
            .is_some()
    );
    assert!(
        node.db()
            .local()
            .get_session("claude:stale-quarantined")
            .unwrap()
            .is_some()
    );

    // Direct store-level check: once the quarantined item is rejected, `prune_sessions` CAN prune it!
    let q_rcpt = node
        .db()
        .local()
        .list_quarantined(Some("claude:stale-quarantined"), 10)
        .unwrap()[0]
        .receipt
        .clone();
    node.db()
        .local()
        .reject_quarantined(&q_rcpt, "human@cli", "confirmed spam", None, now)
        .unwrap();
    let report = node
        .db()
        .local()
        .prune_sessions(now - 1_000, &HashSet::new())
        .unwrap();
    assert!(
        report
            .pruned_sessions
            .iter()
            .any(|s| s == "claude:stale-quarantined"),
        "once quarantined items are resolved, stale session should be prunable: {report:?}"
    );

    daemon.stop().await;
    node.shutdown();
}

// ============================================================================
// 5. H6 (P1): Drop Watcher Reconnects with Last-Event-ID + Unrecoverable Notice
// ============================================================================

#[tokio::test]
async fn h6_drop_watcher_reconnects_with_last_event_id_and_surfaces_unrecoverable_notice() {
    let tmp = TempDir::new().unwrap();
    let node = open_local_node("h6-drop@box", tmp.path());

    let human_kp = Ed25519KeyPair::generate().unwrap();
    enroll_human_authority(&node, "riley", &human_kp, HumanAuthorityRole::Admin);

    // Build a genuine sealed verified directive drop envelope for `h6-drop@box/dev`.
    let now = now_ms();
    let claim = HumanClaimV1 {
        v: 1,
        claim_id: format!("claim-h6-{}", uuid_v4()),
        kind: HumanDropKind::Directive,
        human_id: "riley".into(),
        human_kid: human_kp.kid(),
        auth_epoch: 1,
        issued_at: format_rfc3339_millis(now),
        expires_at: format_rfc3339_millis(now + 300_000),
        drop_id: "drop-h6-1".into(),
        audience: HumanAudience {
            node_id: "h6-drop@box".into(),
            node_enc_kid: node.identity().encryption.kid(),
            handle: Some("dev".into()),
        },
        secret_spec: None,
        body: "H6_RECONNECTED_DIRECTIVE_PAYLOAD_77".into(),
    };
    let env = seal_human_drop(&claim, &human_kp, &node.identity().encryption.public_key()).unwrap();
    let env_json = serde_json::to_string(&env).unwrap();

    // Mock external Blind Drop Relay:
    // - POST /v1/drops -> returns drop_id + sub_cap + post_cap
    // - GET /v1/drops/<id>/stream #1 -> emits `id: 1\nevent: ready\ndata: {}\n\n` then ABRUPTLY DROPS!
    // - GET /v1/drops/<id>/stream #2 -> captures `Last-Event-ID`, emits `id: 2\ndata: <env_json>\n\n`!
    // - POST /v1/drops/<id>/ack -> records ack!
    let stream_hits = Arc::new(AtomicUsize::new(0));
    let seen_last_event_ids: Arc<Mutex<Vec<Option<String>>>> = Arc::new(Mutex::new(Vec::new()));
    let ack_count = Arc::new(AtomicUsize::new(0));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = listener.local_addr().unwrap();
    let relay_url = format!("http://{relay_addr}");

    let hits_srv = Arc::clone(&stream_hits);
    let ids_srv = Arc::clone(&seen_last_event_ids);
    let (release_part_a_tx, release_part_a_rx) = tokio::sync::watch::channel(false);
    let ack_srv = Arc::clone(&ack_count);
    let env_srv = env_json.clone();
    let relay_task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let hits = Arc::clone(&hits_srv);
            let ids = Arc::clone(&ids_srv);
            let acks = Arc::clone(&ack_srv);
            let env_payload = env_srv.clone();
            let mut release_rx = release_part_a_rx.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let n = stream.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);
                let first_line = req.lines().next().unwrap_or_default();

                if first_line.starts_with("POST /v1/drops ") {
                    let exp_ms = now_ms() + 300_000;
                    let body = json!({
                        "dropId": "drop-h6-1",
                        "postCap": "post-cap-h6",
                        "subCap": "sub-cap-h6",
                        "expiresAt": format_rfc3339_millis(exp_ms),
                        "expiresAtMs": exp_ms,
                        "maxPayloadBytes": 65536,
                        "maxItems": 4,
                    })
                    .to_string();
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                } else if first_line.starts_with("GET /v1/drops/drop-h6-1/stream") {
                    let last_id = req.lines().find_map(|l| {
                        let (k, v) = l.split_once(':')?;
                        if k.trim().eq_ignore_ascii_case("last-event-id") {
                            Some(v.trim().to_string())
                        } else {
                            None
                        }
                    });
                    ids.lock().unwrap().push(last_id);
                    let attempt = hits.fetch_add(1, Ordering::SeqCst);
                    if attempt == 0 {
                        // First stream connection: send `id: 1` ready event then drop TCP connection!
                        let hdr = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n";
                        let _ = stream.write_all(hdr.as_bytes()).await;
                        let _ = stream.write_all(b"id: 1\nevent: ready\ndata: {}\n\n").await;
                        let _ = stream.flush().await;
                        // Abrupt EOF!
                    } else {
                        // Wait until the setup turn's Stop hook has marked `claude:h6-sess` idle so
                        // the drop event deterministically pushes via ScriptedTransport (not Stop).
                        let _ = release_rx.wait_for(|&go| go).await;
                        // Second connection after reconnect: emit the actual sealed drop event!
                        let hdr = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n";
                        let _ = stream.write_all(hdr.as_bytes()).await;
                        let ev_bytes = format!("id: 2\ndata: {env_payload}\n\n");
                        let _ = stream.write_all(ev_bytes.as_bytes()).await;
                        let _ = stream.flush().await;
                    }
                } else if first_line.starts_with("POST /v1/drops/drop-h6-1/ack") {
                    acks.fetch_add(1, Ordering::SeqCst);
                    let body = "{\"ok\":true}";
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                }
            });
        }
    });

    let daemon = LocalDaemon::start(
        Arc::clone(&node),
        None,
        LocalDaemonConfig {
            drop_watcher_backoff_ms: vec![40, 80, 160],
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let sock = daemon.socket_path().to_path_buf();

    let mut mcp = TestMcpClient::spawn(McpOptions::new(sock.clone()));
    mcp.initialize().await;

    let (_, j_err) = mcp
        .call_verified_claude(
            &sock,
            "h6-sess",
            "hyp_mesh",
            json!({ "action": "join", "handle": "dev" }),
        )
        .await;
    assert!(!j_err);

    let transport = ScriptedTransport::new("herdr", vec![], PushOutcome::delivered());
    daemon.register_session_transport("claude:h6-sess", transport.clone());

    let (drop_txt, drop_err) = mcp
        .call_verified_claude(
            &sock,
            "h6-sess",
            "hyp_mesh",
            json!({
                "action": "drop_link",
                "kind": "directive",
                "relay": relay_url,
            }),
        )
        .await;
    assert!(!drop_err, "drop_link failed: {drop_txt}");
    // Mark setup turn idle via Stop so idle PushTransport delivers immediately.
    let _ = run_hook(
        &sock,
        HarnessKind::Claude,
        HookEvent::Stop,
        json!({ "session_id": "h6-sess" }),
    )
    .await;
    let _ = release_part_a_tx.send(true);

    // Wait for reconnect + ingest + live metadata-only XML digest delivery to `claude:h6-sess`!
    let delivered = transport
        .wait_for_delivered(1, Duration::from_secs(5))
        .await;
    assert!(
        delivered[0].starts_with("<hyphae-inbox handle=\"dev\" unread=\"1\" urgency=\"queue\">")
            && delivered[0].contains("human:riley:")
            && delivered[0].contains("verified=\"true\""),
        "H9/RFC 0004: reconnected human directive must deliver verified XML digest: {:?}",
        delivered
    );
    assert!(
        !delivered[0].contains("H6_RECONNECTED_DIRECTIVE_PAYLOAD_77"),
        "RFC 0004: push digest must NEVER include raw directive text: {}",
        delivered[0]
    );
    assert!(
        node.db()
            .local()
            .peek_inbox("claude:h6-sess", 10)
            .unwrap()
            .iter()
            .any(|m| m.text.contains("H6_RECONNECTED_DIRECTIVE_PAYLOAD_77")),
        "full reconnected human directive must remain stored in mailbox for hyp_inbox"
    );

    // Wait briefly for POST /ack
    let ack_deadline = Instant::now() + Duration::from_secs(2);
    while ack_count.load(Ordering::SeqCst) == 0 && Instant::now() < ack_deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    assert!(
        stream_hits.load(Ordering::SeqCst) >= 2,
        "watcher must reconnect after first mid-stream disconnect"
    );
    let ids = seen_last_event_ids.lock().unwrap().clone();
    assert_eq!(ids[0], None);
    assert_eq!(
        ids[1].as_deref(),
        Some("1"),
        "H6: reconnect MUST send Last-Event-ID from prior event: {ids:?}"
    );
    assert!(
        ack_count.load(Ordering::SeqCst) >= 1,
        "must ack burned drop"
    );

    // Part B: Unrecoverable relay error (HTTP 410 Gone) delivers a safe metadata-only notice!
    let gone_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gone_url = format!("http://{}", gone_listener.local_addr().unwrap());
    let (release_part_b_tx, release_part_b_rx) = tokio::sync::watch::channel(false);
    let gone_task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = gone_listener.accept().await else {
                break;
            };
            let mut release_rx = release_part_b_rx.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let n = stream.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);
                let first_line = req.lines().next().unwrap_or_default();
                if first_line.starts_with("POST /v1/drops ") {
                    let exp_ms = now_ms() + 300_000;
                    let body = json!({
                        "dropId": "drop-gone-410",
                        "postCap": "post-410",
                        "subCap": "sub-410",
                        "expiresAt": format_rfc3339_millis(exp_ms),
                        "expiresAtMs": exp_ms,
                        "maxPayloadBytes": 65536,
                        "maxItems": 4,
                    })
                    .to_string();
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                } else {
                    // Hold HTTP 410 Gone until the Stop hook has marked `claude:h6-sess` idle so
                    // the watcher's system notice pushes via ScriptedTransport instead of being
                    // drained synchronously by Stop before ScriptedTransport sees it.
                    let _ = release_rx.wait_for(|&go| go).await;
                    let resp =
                        "HTTP/1.1 410 Gone\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    let _ = stream.write_all(resp.as_bytes()).await;
                }
            });
        }
    });

    let (_, gone_err) = mcp
        .call_verified_claude(
            &sock,
            "h6-sess",
            "hyp_mesh",
            json!({
                "action": "drop_link",
                "kind": "directive",
                "relay": gone_url,
            }),
        )
        .await;
    assert!(!gone_err);
    let _ = run_hook(
        &sock,
        HarnessKind::Claude,
        HookEvent::Stop,
        json!({ "session_id": "h6-sess" }),
    )
    .await;
    let _ = release_part_b_tx.send(true);

    let delivered_after_gone = transport
        .wait_for_delivered(2, Duration::from_secs(5))
        .await;
    assert!(
        delivered_after_gone[1].starts_with("<hyphae-inbox handle=\"dev\" ")
            && delivered_after_gone[1].contains("<system from=\"hyphae:system\" count=\"1\"/>"),
        "H6/RFC 0004: unrecoverable relay 410 must deliver safe metadata-only system XML digest: {:?}",
        delivered_after_gone[1]
    );
    assert!(
        node.db()
            .local()
            .peek_inbox("claude:h6-sess", 10)
            .unwrap()
            .iter()
            .any(|m| m.text.contains("drop-gone-410") && m.text.contains("410")),
        "H6: full unrecoverable relay 410 notice must be stored in mailbox for hyp_inbox"
    );

    mcp.close().await;
    daemon.stop().await;
    relay_task.abort();
    gone_task.abort();
    node.shutdown();
}

// ============================================================================
// 6. H9 (P1): `hyp_inbox` & Packed Context Expose Structured `humanVerified`
// ============================================================================

#[tokio::test]
async fn h9_human_verified_metadata_exposed_in_hyp_inbox_and_packed_headers() {
    let tmp = TempDir::new().unwrap();
    let node = open_local_node("h9-node@box", tmp.path());

    let human_kp = Ed25519KeyPair::generate().unwrap();
    enroll_human_authority(&node, "alice-admin", &human_kp, HumanAuthorityRole::Admin);

    let daemon = LocalDaemon::start(Arc::clone(&node), None, LocalDaemonConfig::default())
        .await
        .unwrap();
    let sock = daemon.socket_path().to_path_buf();

    let mut mcp = TestMcpClient::spawn(McpOptions::new(sock.clone()));
    mcp.initialize().await;

    let (_, j_err) = mcp
        .call_verified_claude(
            &sock,
            "h9-sess",
            "hyp_mesh",
            json!({ "action": "join", "handle": "worker" }),
        )
        .await;
    assert!(!j_err);

    // 1. Ingest a cryptographically verified human directive via `ingest_human_drop`.
    let now = now_ms();
    let claim = HumanClaimV1 {
        v: 1,
        claim_id: format!("claim-h9-{}", uuid_v4()),
        kind: HumanDropKind::Directive,
        human_id: "alice-admin".into(),
        human_kid: human_kp.kid(),
        auth_epoch: 1,
        issued_at: format_rfc3339_millis(now),
        expires_at: format_rfc3339_millis(now + 300_000),
        drop_id: "drop-h9-1".into(),
        audience: HumanAudience {
            node_id: "h9-node@box".into(),
            node_enc_kid: node.identity().encryption.kid(),
            handle: Some("worker".into()),
        },
        secret_spec: None,
        body: "APPROVE_PROD_RELEASE_H9".into(),
    };
    let env = seal_human_drop(&claim, &human_kp, &node.identity().encryption.public_key()).unwrap();
    node.ingest_human_drop(&env, None, false).await.unwrap();

    // 2. Also insert an ordinary untrusted peer DM (must NOT have `humanVerified: true`).
    let _ = daemon
        .ingest_inbound(InboundItem {
            session_id: "claude:h9-sess".into(),
            origin_node: "ext@peer".into(),
            item_id: "h9-untrusted-dm".into(),
            source: "ext@peer/guest".into(),
            text: "UNTRUSTED_PEER_DM_H9".into(),
            kind: MailboxKind::Message,
            trust_tier: GateTrustTier::Peer,
        })
        .await
        .unwrap();

    // 3. Query `hyp_inbox` (without ack) -> inspect structured `humanVerified` fields!
    let (inbox_txt, inbox_err) = mcp
        .call_verified_claude(
            &sock,
            "h9-sess",
            "hyp_inbox",
            json!({ "state": "unread", "ack": false }),
        )
        .await;
    assert!(!inbox_err, "hyp_inbox failed: {inbox_txt}");
    let inbox_val: Value = serde_json::from_str(&inbox_txt).unwrap();
    let items = inbox_val["items"].as_array().unwrap();
    assert_eq!(
        items.len(),
        2,
        "expected 1 verified + 1 peer DM: {inbox_val}"
    );

    let verified_item = items
        .iter()
        .find(|i| {
            i["text"]
                .as_str()
                .unwrap_or("")
                .contains("APPROVE_PROD_RELEASE_H9")
        })
        .expect("verified human item present");
    assert_eq!(verified_item["humanVerified"], true);
    assert_eq!(verified_item["verifiedHumanId"], "alice-admin");
    assert_eq!(verified_item["verifiedHumanKid"], human_kp.kid());

    let peer_item = items
        .iter()
        .find(|i| {
            i["text"]
                .as_str()
                .unwrap_or("")
                .contains("UNTRUSTED_PEER_DM_H9")
        })
        .expect("peer item present");
    assert!(
        peer_item.get("humanVerified").is_none() || peer_item["humanVerified"] == false,
        "untrusted peer DM MUST NOT claim humanVerified: {peer_item}"
    );
    assert!(peer_item.get("verifiedHumanId").is_none());

    // 4. Drain packed context (`mailbox.drain`) -> verify packed header distinguishes human-verified!
    let drain = rpc(
        &sock,
        &json!({ "type": "mailbox.drain", "sessionId": "claude:h9-sess" }),
    )
    .await;
    assert!(drain.ok);
    let rendered = drain.result.unwrap()["items"][0]["text"]
        .as_str()
        .unwrap()
        .to_string();
    let kid8: String = human_kp.kid().chars().take(8).collect();
    assert!(
        rendered.starts_with("<hyphae-inbox handle=\"worker\" unread=\"2\" urgency=\"queue\">")
            && rendered.contains(&format!(
                "<dm from=\"human:alice-admin:{kid8}\" count=\"1\" verified=\"true\"/>"
            ))
            && rendered.contains("<dm from=\"ext@peer/guest\" count=\"1\"/>"),
        "H9/RFC 0004: XML digest must distinguish verified human authority (verified=\"true\" + humanId + kid8) from unverified peer: {rendered}"
    );
    assert!(
        !rendered.contains("APPROVE_PROD_RELEASE_H9"),
        "RFC 0004: digest must NEVER include raw body text: {rendered}"
    );

    mcp.close().await;
    daemon.stop().await;
    node.shutdown();
}

// ============================================================================
// 7. G8 (P1): Approving Quarantined `local-ingest:<topic>` Fans Out to Subscribers
// ============================================================================

#[tokio::test]
async fn g8_approving_quarantined_local_ingest_fans_out_to_subscribed_sessions() {
    let tmp = TempDir::new().unwrap();
    let state_dir = tmp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap();

    let node = open_local_node("g8-ingest@box", &state_dir);
    let gate_db = Arc::new(Mutex::new(
        NodeDb::open(state_dir.join("node.sqlite")).unwrap(),
    ));

    // Gate rule that quarantines unsigned local-ingest events matching `HOLD_FOR_APPROVAL`.
    let mut gate_cfg = SecurityGateConfig::default();
    gate_cfg
        .stage1
        .inbound_regex_denylist
        .push("HOLD_FOR_APPROVAL".into());
    gate_cfg.stage1.regex_deny_action = Stage1DenyAction::Quarantine;
    let pipeline =
        Arc::new(SecurityGatePipeline::new(gate_cfg, Arc::clone(&gate_db), None).unwrap());

    let daemon = LocalDaemon::start(
        Arc::clone(&node),
        Some(Arc::clone(&pipeline)),
        LocalDaemonConfig::default(),
    )
    .await
    .unwrap();
    let sock = daemon.socket_path().to_path_buf();

    let ingest_srv = LocalIngestServer::start_with_shared_gate(
        Arc::clone(&node),
        daemon.gate_slot(),
        node.config().local_ingest.clone(),
    )
    .await
    .unwrap();

    // Enroll a local session subscribed to `local.schedule` with an attached live PushTransport.
    let mut mcp = TestMcpClient::spawn(McpOptions::new(sock.clone()));
    mcp.initialize().await;
    let (_, j_err) = mcp
        .call_verified_claude(
            &sock,
            "g8-sub",
            "hyp_mesh",
            json!({ "action": "join", "handle": "sched" }),
        )
        .await;
    assert!(!j_err);
    let (sub_txt, sub_err) = mcp
        .call_verified_claude(
            &sock,
            "g8-sub",
            "hyp_stream",
            json!({ "action": "subscribe", "topic": "local.schedule", "coalesceSeconds": 0 }),
        )
        .await;
    assert!(!sub_err, "subscribe failed: {sub_txt}");

    let transport = ScriptedTransport::new("herdr", vec![], PushOutcome::delivered());
    daemon.register_session_transport("claude:g8-sub", transport.clone());

    // 1. Emit unsigned local-ingest event -> quarantined under `session_id = "local-ingest:schedule"`!
    let emit_res = send_local_ingest_event(
        ingest_srv.endpoint_path(),
        &json!({
            "type": TYPE_SCHEDULED_MESSAGE_V1,
            "topic": "local.schedule",
            "data": { "text": "HOLD_FOR_APPROVAL nightly backup summary #42" }
        }),
    )
    .await
    .unwrap();
    assert_eq!(emit_res["ok"], false, "expected quarantine: {emit_res}");
    assert_eq!(emit_res["error"], "gate_quarantined");
    let q_receipt = emit_res["receipt"]
        .as_str()
        .expect("quarantined receipt")
        .to_string();
    assert!(
        transport.delivered_texts().is_empty(),
        "quarantined local-ingest event must NOT deliver before approval"
    );

    // 2. Human operator approves the quarantined `local-ingest:schedule` receipt and sends `inbox.wake`!
    let approved = node
        .db()
        .local()
        .approve_quarantined(&q_receipt, "human@cli", now_ms())
        .unwrap();
    assert_eq!(approved.session_id, "local-ingest:schedule");
    assert_eq!(approved.gate_state, GateState::Pending);

    let wake_res = rpc(
        &sock,
        &json!({ "type": "inbox.wake", "receipt": q_receipt }),
    )
    .await;
    assert!(wake_res.ok, "inbox.wake failed: {wake_res:?}");
    assert_eq!(
        wake_res.result.as_ref().unwrap()["woken"],
        true,
        "G8: inbox.wake must fan out approved local-ingest event and wake subscriber: {wake_res:?}"
    );

    // 3. Subscribed session's live transport MUST receive metadata-only XML digest without re-quarantine!
    let delivered = transport
        .wait_for_delivered(1, Duration::from_secs(3))
        .await;
    assert!(
        delivered[0].starts_with("<hyphae-inbox handle=\"sched\" unread=\"1\" urgency=\"queue\">")
            && delivered[0].contains("<stream topic=\"local.schedule\" count=\"1\"/>"),
        "subscribed session must receive metadata-only XML digest for approved local-ingest event: {:?}",
        delivered
    );
    assert!(
        !delivered[0].contains("HOLD_FOR_APPROVAL nightly backup summary #42"),
        "RFC 0004: push digest must NEVER include raw event payload: {:?}",
        delivered
    );
    assert!(
        node.db()
            .local()
            .peek_inbox("claude:g8-sub", 10)
            .unwrap()
            .iter()
            .any(|m| m
                .text
                .contains("HOLD_FOR_APPROVAL nightly backup summary #42")),
        "approved local-ingest payload must be readable in subscriber mailbox"
    );
    assert_eq!(
        node.db().local().quarantined_count(None).unwrap(),
        0,
        "approved local-ingest item must not be re-quarantined on fanout"
    );

    mcp.close().await;
    ingest_srv.stop().await;
    daemon.stop().await;
    node.shutdown();
}

// ============================================================================
// 8. G10 (P2): Coalesced Metadata-Only Quarantine Notices (Zero Body Leak)
// ============================================================================

#[tokio::test]
async fn g10_reconcile_quarantine_surfaces_coalesced_metadata_only_notice() {
    let tmp = TempDir::new().unwrap();
    let state_dir = tmp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap();

    let node = open_local_node("g10-notice@box", &state_dir);
    let gate_db = Arc::new(Mutex::new(
        NodeDb::open(state_dir.join("node.sqlite")).unwrap(),
    ));
    let mut gate_cfg = SecurityGateConfig::default();
    gate_cfg
        .stage1
        .inbound_regex_denylist
        .push("SECRET_EXFIL_BODY_G10".into());
    gate_cfg.stage1.regex_deny_action = Stage1DenyAction::Quarantine;
    let pipeline =
        Arc::new(SecurityGatePipeline::new(gate_cfg, Arc::clone(&gate_db), None).unwrap());

    let daemon = LocalDaemon::start(
        Arc::clone(&node),
        Some(Arc::clone(&pipeline)),
        LocalDaemonConfig::default(),
    )
    .await
    .unwrap();
    let sock = daemon.socket_path().to_path_buf();

    let mut mcp = TestMcpClient::spawn(McpOptions::new(sock.clone()));
    mcp.initialize().await;
    let (_, j_err) = mcp
        .call_verified_claude(
            &sock,
            "g10-s1",
            "hyp_mesh",
            json!({ "action": "join", "handle": "agent" }),
        )
        .await;
    assert!(!j_err);

    // Insert a raw pending row that will be quarantined by `reconcile_session_inbox`.
    let q_rcpt = match node
        .db()
        .local()
        .put_in_mailbox(
            &MailboxInsert {
                session_id: "claude:g10-s1".into(),
                origin_node: "evil@ext".into(),
                item_id: "g10-evil-1".into(),
                text: "DO NOT LEAK SECRET_EXFIL_BODY_G10".into(),
                kind: MailboxKind::Message,
                source: "evil@ext/bot".into(),
                gate_state: GateState::Pending,
                gate_reason: None,
                traceparent: None,
            },
            now_ms(),
        )
        .unwrap()
    {
        MailboxPutResult::Stored { receipt } => receipt,
        other => panic!("unexpected put result: {other:?}"),
    };

    // Query `hyp_inbox` (triggers reconcile -> quarantines item & records metadata-only notice!).
    let (inbox_txt, inbox_err) = mcp
        .call_verified_claude(&sock, "g10-s1", "hyp_inbox", json!({ "state": "all" }))
        .await;
    assert!(!inbox_err);
    assert!(
        !inbox_txt.contains("SECRET_EXFIL_BODY_G10"),
        "G10 MUST NEVER leak quarantined body text: {inbox_txt}"
    );
    let inbox_val: Value = serde_json::from_str(&inbox_txt).unwrap();
    assert_eq!(inbox_val["items"].as_array().unwrap().len(), 0);
    assert_eq!(inbox_val["unread"], 0);
    let notices = inbox_val["quarantinedNotices"]
        .as_array()
        .expect("quarantinedNotices metadata array");
    assert_eq!(notices.len(), 1, "coalesced to 1 notice per receipt");
    assert_eq!(notices[0]["receipt"], q_rcpt);
    assert_eq!(notices[0]["source"], "evil@ext/bot");
    assert_eq!(notices[0]["trustTier"], "peer");
    assert!(notices[0].get("text").is_none());

    // A benign delivery batch piggybacks the metadata-only notice ONCE (coalesced, zero body leak).
    let _ = daemon
        .ingest_inbound(InboundItem {
            session_id: "claude:g10-s1".into(),
            origin_node: "g10-notice@box".into(),
            item_id: "g10-benign-1".into(),
            source: "g10-notice@box/self".into(),
            text: "BENIGN_MSG_1".into(),
            kind: MailboxKind::Message,
            trust_tier: GateTrustTier::SelfHost,
        })
        .await
        .unwrap();
    let d1 = rpc(
        &sock,
        &json!({ "type": "mailbox.drain", "sessionId": "claude:g10-s1" }),
    )
    .await;
    let rendered1 = d1.result.unwrap()["items"][0]["text"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        rendered1.starts_with("<hyphae-inbox handle=\"agent\" unread=\"1\" urgency=\"queue\">")
    );
    assert!(rendered1.contains("<dm from=\"g10-notice@box/self\" count=\"1\"/>"));
    assert!(!rendered1.contains("BENIGN_MSG_1"));
    assert!(
        rendered1.contains("<quarantined count=\"1\"/>")
            && !rendered1.contains(&q_rcpt)
            && !rendered1.contains("evil@ext/bot"),
        "G10: digest must carry only a quarantined count: {rendered1}"
    );
    assert!(!rendered1.contains("SECRET_EXFIL_BODY_G10"));

    // Second benign message MUST NOT re-spam the already-surfaced quarantine receipt!
    let _ = daemon
        .ingest_inbound(InboundItem {
            session_id: "claude:g10-s1".into(),
            origin_node: "g10-notice@box".into(),
            item_id: "g10-benign-2".into(),
            source: "g10-notice@box/self".into(),
            text: "BENIGN_MSG_2".into(),
            kind: MailboxKind::Message,
            trust_tier: GateTrustTier::SelfHost,
        })
        .await
        .unwrap();
    let d2 = rpc(
        &sock,
        &json!({ "type": "mailbox.drain", "sessionId": "claude:g10-s1" }),
    )
    .await;
    let rendered2 = d2.result.unwrap()["items"][0]["text"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        rendered2.starts_with("<hyphae-inbox handle=\"agent\" unread=\"2\" urgency=\"queue\">")
    );
    assert!(rendered2.contains("<dm from=\"g10-notice@box/self\" count=\"2\"/>"));
    assert!(!rendered2.contains("BENIGN_MSG_2"));
    assert!(
        !rendered2.contains("<quarantined"),
        "quarantine notice must be coalesced and never spam subsequent batches: {rendered2}"
    );

    mcp.close().await;
    daemon.stop().await;
    node.shutdown();
}

// ============================================================================
// 9. G12 (P2): `hyp_inbox({ state: "all", ids: [...] })` Never Leaks Quarantined/Rejected/Blocked
// ============================================================================

#[tokio::test]
async fn g12_query_inbox_and_mcp_never_leak_quarantined_rejected_or_blocked_items() {
    let tmp = TempDir::new().unwrap();
    let node = open_local_node("g12-iso@box", tmp.path());
    let now = now_ms();
    let sid = "claude:g12-s1";
    node.db().local().register_session(sid, "{}", now).unwrap();

    // Forbidden states fail closed at parser level!
    for forbidden in ["quarantined", "quarantine", "rejected", "blocked", "block"] {
        assert!(
            matches!(
                InboxStateFilter::parse(forbidden),
                Err(DeliveryError::ForbiddenState(_))
            ),
            "expected ForbiddenState for {forbidden:?}"
        );
    }

    let put = |item_id: &str, text: &str, state: GateState| -> String {
        match node
            .db()
            .local()
            .put_in_mailbox(
                &MailboxInsert {
                    session_id: sid.into(),
                    origin_node: "ext@peer".into(),
                    item_id: item_id.into(),
                    text: text.into(),
                    kind: MailboxKind::Message,
                    source: "ext@peer/bot".into(),
                    gate_state: state,
                    gate_reason: None,
                    traceparent: None,
                },
                now,
            )
            .unwrap()
        {
            MailboxPutResult::Stored { receipt } => receipt,
            other => panic!("unexpected put: {other:?}"),
        }
    };

    let r_valid = put("g12-ok", "VISIBLE_ALLOWED_BODY", GateState::Pending);
    let r_quar = put(
        "g12-q",
        "HIDDEN_QUARANTINED_BODY_999",
        GateState::Quarantined,
    );
    let r_rej = put("g12-r", "HIDDEN_REJECTED_BODY_888", GateState::Rejected);

    // Direct `query_inbox({ state: All, ids: [r_quar, r_rej, r_valid] })` returns ONLY `r_valid`!
    let res = query_inbox(
        &node.db(),
        sid,
        &InboxQuery {
            state: InboxStateFilter::All,
            ids: vec![r_quar.clone(), r_rej.clone(), r_valid.clone()],
            ..InboxQuery::default()
        },
        now,
    )
    .unwrap();
    assert_eq!(res.items.len(), 1);
    assert_eq!(res.items[0].receipt, r_valid);
    let serialized = serde_json::to_string(&res).unwrap();
    assert!(!serialized.contains("HIDDEN_QUARANTINED_BODY_999"));
    assert!(!serialized.contains("HIDDEN_REJECTED_BODY_888"));

    // Full MCP `hyp_inbox({ state: "all", ids: [r_quar, r_rej] })` returns 0 items and 0 leaked bytes!
    let daemon = LocalDaemon::start(Arc::clone(&node), None, LocalDaemonConfig::default())
        .await
        .unwrap();
    let sock = daemon.socket_path().to_path_buf();
    let mut mcp = TestMcpClient::spawn(McpOptions::new(sock.clone()));
    mcp.initialize().await;

    let (id_txt, id_err) = mcp
        .call_verified_claude(
            &sock,
            "g12-s1",
            "hyp_inbox",
            json!({ "state": "all", "ids": [r_quar, r_rej], "ack": true }),
        )
        .await;
    assert!(!id_err, "ids query failed: {id_txt}");
    let id_val: Value = serde_json::from_str(&id_txt).unwrap();
    assert_eq!(id_val["items"].as_array().unwrap().len(), 0);
    assert!(!id_txt.contains("HIDDEN_QUARANTINED_BODY_999"));
    assert!(!id_txt.contains("HIDDEN_REJECTED_BODY_888"));

    let (_, blk_err) = mcp
        .call_verified_claude(&sock, "g12-s1", "hyp_inbox", json!({ "state": "blocked" }))
        .await;
    assert!(blk_err, "hyp_inbox(state:'blocked') MUST fail closed");

    mcp.close().await;
    daemon.stop().await;
    node.shutdown();
}

// ============================================================================
// 10. G14 (P2): Cached `gate_policy_sig` Verification + Live Digest Tamper Invalidation
// ============================================================================

#[tokio::test]
async fn g14_locked_policy_sig_caches_secret_store_and_invalidates_on_digest_change() {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("node.sqlite");
    let gate_db = Arc::new(Mutex::new(NodeDb::open(&db_path).unwrap()));
    let secrets = Arc::new(SecretStore::new(tmp.path(), SecretBackend::File));

    // Seed an initial human authority and pin `human_authorities_digest` into the signed policy!
    let admin_kp = Ed25519KeyPair::generate().unwrap();
    let initial_digest = {
        let db = gate_db.lock().unwrap();
        db.human()
            .upsert_authority(
                &HumanAuthorityInput {
                    human_id: "riley".into(),
                    kid: admin_kp.kid(),
                    label: "Admin".into(),
                    role: HumanAuthorityRole::Admin,
                    jwk_json: serde_json::to_string(&admin_kp.to_jwk()).unwrap(),
                    enc_jwk_json: None,
                    prf_salt: None,
                    auth_epoch: 1,
                },
                now_ms(),
            )
            .unwrap();
        db.human().authorities_digest().unwrap()
    };

    let mut cfg = SecurityGateConfig {
        require_signed_policy: true,
        human_authorities_digest: Some(initial_digest),
        ..SecurityGateConfig::default()
    };
    cfg.policy_signature = Some(sign_gate_policy(&cfg, &secrets).unwrap());

    let pipeline = SecurityGatePipeline::new(cfg, Arc::clone(&gate_db), Some(Arc::clone(&secrets)))
        .expect("build locked SecurityGatePipeline");

    let make_ctx = |id: &str| InboundContext {
        session_id: "claude:g14".into(),
        origin_node: "bob@lap".into(),
        sender: "bob@lap/dev".into(),
        trust_tier: GateTrustTier::Peer,
        e2ee_verified: true,
        identity_verified: true,
        kind: MailboxKind::Message,
        channel: None,
        topic: None,
        bridge: None,
        event: CloudEvent {
            specversion: "1.0".into(),
            id: id.into(),
            source: "bob@lap/dev".into(),
            event_type: "to.hyphae.message.v1".into(),
            datacontenttype: Some(CONTENT_TYPE_JSON.into()),
            dataschema: None,
            subject: None,
            time: None,
            data: Some(json!({ "text": format!("benign message {id}") })),
            data_base64: None,
            extensions: BTreeMap::new(),
        },
        transfer_paths: Vec::new(),
        rendered_text: Some(format!("benign message {id}")),
        human_auth: None,
    };

    // 1. First evaluation verifies against SecretStore and warms the cache!
    let ev1 = pipeline
        .evaluate_inbound(&make_ctx("g14-msg-1"), now_ms())
        .await
        .unwrap();
    assert!(matches!(ev1.decision, GateDecision::Allow { .. }));

    // 2. Delete the HMAC signing key from SecretStore on disk while leaving `human_authorities` unchanged!
    secrets.delete("gate-policy-hmac-key").unwrap();

    // Repeated verification + inbound evaluation MUST hit the in-memory cache (NOT re-invoke SecretStore)!
    assert!(
        !pipeline.is_policy_tampered(),
        "G14: cached signature check must not re-read SecretStore when digest is unchanged"
    );
    let ev2 = pipeline
        .evaluate_inbound(&make_ctx("g14-msg-2"), now_ms())
        .await
        .unwrap();
    assert!(
        matches!(ev2.decision, GateDecision::Allow { .. }),
        "G14: second message with unchanged digest must succeed via cache: {ev2:?}"
    );

    // 3. Mutate `human_authorities` in SQLite (changing `human_authorities_digest`) ->
    //    MUST invalidate cache and fail closed IMMEDIATELY!
    let rogue_kp = Ed25519KeyPair::generate().unwrap();
    {
        let db = gate_db.lock().unwrap();
        db.human()
            .upsert_authority(
                &HumanAuthorityInput {
                    human_id: "rogue".into(),
                    kid: rogue_kp.kid(),
                    label: "Injected".into(),
                    role: HumanAuthorityRole::Admin,
                    jwk_json: serde_json::to_string(&rogue_kp.to_jwk()).unwrap(),
                    enc_jwk_json: None,
                    prf_salt: None,
                    auth_epoch: 1,
                },
                now_ms(),
            )
            .unwrap();
    }

    assert!(
        pipeline.is_policy_tampered(),
        "G14: digest change in SQLite MUST immediately fail closed"
    );
    let ev3 = pipeline
        .evaluate_inbound(&make_ctx("g14-msg-3"), now_ms())
        .await
        .unwrap();
    assert!(
        matches!(
            ev3.decision,
            GateDecision::Quarantine { ref reason, .. } if reason == "gate_policy_tampered"
        ),
        "G14: inbound message after digest tamper must quarantine fail-closed: {ev3:?}"
    );
}

// ============================================================================
// 11. R5: `daemon.status` Exposes `binaryVersion` and `pid`
// ============================================================================

#[tokio::test]
async fn r5_daemon_status_exposes_binary_version_and_pid() {
    let tmp = TempDir::new().unwrap();
    let node = open_local_node("r5-status@box", tmp.path());
    let daemon = LocalDaemon::start(Arc::clone(&node), None, LocalDaemonConfig::default())
        .await
        .unwrap();
    let sock = daemon.socket_path().to_path_buf();

    let res = rpc(&sock, &json!({ "type": "daemon.status" })).await;
    assert!(res.ok, "daemon.status failed: {res:?}");
    let body = res.result.unwrap();
    assert_eq!(body["nodeId"], "r5-status@box");
    assert_eq!(body["binaryVersion"], env!("CARGO_PKG_VERSION"));
    assert_eq!(body["pid"], std::process::id());
    assert!(body.get("version").is_some());
    assert!(body.get("quarantinedCount").is_some());

    daemon.stop().await;
    node.shutdown();
}

// ============================================================================
// 12. Wave 4B: `B3` Bridge Target Enforcement, `U2` Leave Channel, `H18` Junk Drop, `G8` Sweep
// ============================================================================

#[tokio::test]
async fn b3_bridge_enforces_configured_targets_on_link_handoff_and_send() {
    use hyp_harness::daemon::{BoxFuture, BridgePoster};
    use serde_json::Map;

    struct CountingPoster(Arc<AtomicUsize>);
    impl BridgePoster for CountingPoster {
        fn post<'a>(
            &'a self,
            plugin: &'a str,
            target: &'a str,
            _text: &'a str,
            _meta: &'a Map<String, Value>,
        ) -> BoxFuture<'a, Result<Value, (String, String)>> {
            let p = plugin.to_string();
            let t = target.to_string();
            let c = Arc::clone(&self.0);
            Box::pin(async move {
                c.fetch_add(1, Ordering::SeqCst);
                Ok(json!({ "ok": true, "plugin": p, "target": t }))
            })
        }
    }

    let tmp = TempDir::new().unwrap();
    let node = open_local_node("b3-bridge@box", tmp.path());
    let daemon = LocalDaemon::start(Arc::clone(&node), None, LocalDaemonConfig::default())
        .await
        .unwrap();
    let original_count = Arc::new(AtomicUsize::new(0));
    let sent_count = Arc::new(AtomicUsize::new(0));
    daemon.register_bridge_poster_with_targets(
        "telegram",
        vec!["allowed-chat".to_string()],
        Arc::new(CountingPoster(Arc::clone(&original_count))),
    );
    // Re-registering a poster without targets must preserve the configured allowlist.
    daemon.register_bridge_poster(
        " Telegram ",
        Arc::new(CountingPoster(Arc::clone(&sent_count))),
    );
    let sock = daemon.socket_path().to_path_buf();

    let mut mcp = TestMcpClient::spawn(McpOptions::new(sock.clone()));
    mcp.initialize().await;
    let (_, j_err) = mcp
        .call_verified_claude(
            &sock,
            "b3-sess",
            "hyp_mesh",
            json!({ "action": "join", "handle": "ops" }),
        )
        .await;
    assert!(!j_err);

    // 1. Link, handoff, and send to unconfigured target OR wildcard `*` MUST ALL fail closed!
    for bad_target in ["unconfigured-chat", "*"] {
        let (l_txt, l_err) = mcp
            .call_verified_claude(
                &sock,
                "b3-sess",
                "hyp_bridge",
                json!({ "action": "link", "plugin": "telegram", "target": bad_target }),
            )
            .await;
        assert!(
            l_err && l_txt.contains("bridge_target_not_configured"),
            "B3: link to {bad_target} must fail closed: {l_txt}"
        );

        let (h_txt, h_err) = mcp
            .call_verified_claude(
                &sock,
                "b3-sess",
                "hyp_bridge",
                json!({ "action": "handoff", "plugin": "telegram", "target": bad_target }),
            )
            .await;
        assert!(
            h_err && h_txt.contains("bridge_target_not_configured"),
            "B3: handoff to {bad_target} must fail closed: {h_txt}"
        );
    }

    // Even if a stale `plugin_targets` row existed in SQLite for an unconfigured target,
    // `hyp_send` MUST STILL fail closed with `bridge_target_not_configured`!
    node.db()
        .local()
        .set_plugin_target(&hyp_store::PluginTargetHandoff {
            plugin: "telegram".into(),
            target: "stale-unconfigured".into(),
            session_id: "claude:b3-sess".into(),
            set_at: now_ms(),
            set_by: "claude:b3-sess".into(),
        })
        .unwrap();
    let (s_bad_txt, s_bad_err) = mcp
        .call_verified_claude(
            &sock,
            "b3-sess",
            "hyp_send",
            json!({ "to": "telegram:stale-unconfigured", "text": "must be blocked" }),
        )
        .await;
    assert!(
        s_bad_err && s_bad_txt.contains("bridge_target_not_configured"),
        "B3: send to unconfigured target must fail closed even with stale DB holder: {s_bad_txt}"
    );
    assert_eq!(sent_count.load(Ordering::SeqCst), 0);

    // 2. Configured target `telegram:allowed-chat` links, hands off, and sends cleanly!
    let (l_ok_txt, l_ok_err) = mcp
        .call_verified_claude(
            &sock,
            "b3-sess",
            "hyp_bridge",
            json!({ "action": "link", "plugin": "telegram", "target": "allowed-chat" }),
        )
        .await;
    assert!(!l_ok_err, "configured target link failed: {l_ok_txt}");
    let (s_ok_txt, s_ok_err) = mcp
        .call_verified_claude(
            &sock,
            "b3-sess",
            "hyp_send",
            json!({ "to": "telegram:allowed-chat", "text": "hello allowed" }),
        )
        .await;
    assert!(!s_ok_err, "configured target send failed: {s_ok_txt}");
    assert_eq!(original_count.load(Ordering::SeqCst), 0);
    assert_eq!(sent_count.load(Ordering::SeqCst), 1);

    mcp.close().await;
    daemon.stop().await;
    node.shutdown();
}

#[tokio::test]
async fn u2_session_leave_channel_returns_error_when_not_a_member() {
    let tmp = TempDir::new().unwrap();
    let node = open_local_node("u2-leave@box", tmp.path());
    let daemon = LocalDaemon::start(Arc::clone(&node), None, LocalDaemonConfig::default())
        .await
        .unwrap();
    let sock = daemon.socket_path().to_path_buf();

    let mut mcp = TestMcpClient::spawn(McpOptions::new(sock.clone()));
    mcp.initialize().await;
    let (_, j_err) = mcp
        .call_verified_claude(
            &sock,
            "u2-sess",
            "hyp_mesh",
            json!({ "action": "join", "handle": "alice" }),
        )
        .await;
    assert!(!j_err);

    // Leaving a channel the session NEVER joined MUST return `ok: false`!
    let leave_missing = rpc(
        &sock,
        &json!({
            "type": "session.leave_channel",
            "sessionId": "claude:u2-sess",
            "channel": "#never-joined"
        }),
    )
    .await;
    assert!(
        !leave_missing.ok,
        "U2: session.leave_channel must return ok=false when left==false: {leave_missing:?}"
    );

    // Joining and then leaving `#ops` returns `ok: true` once, then `ok: false` on second leave!
    let (_, ch_err) = mcp
        .call_verified_claude(
            &sock,
            "u2-sess",
            "hyp_mesh",
            json!({ "action": "join", "channel": "#ops" }),
        )
        .await;
    assert!(!ch_err);

    let leave_ok = rpc(
        &sock,
        &json!({
            "type": "session.leave_channel",
            "sessionId": "claude:u2-sess",
            "channel": "#ops"
        }),
    )
    .await;
    assert!(
        leave_ok.ok,
        "first leave_channel should succeed: {leave_ok:?}"
    );

    let leave_twice = rpc(
        &sock,
        &json!({
            "type": "session.leave_channel",
            "sessionId": "claude:u2-sess",
            "channel": "#ops"
        }),
    )
    .await;
    assert!(
        !leave_twice.ok,
        "second leave_channel after already leaving must fail closed: {leave_twice:?}"
    );

    mcp.close().await;
    daemon.stop().await;
    node.shutdown();
}

#[tokio::test]
async fn h18_drop_watcher_ignores_junk_envelope_and_delivers_subsequent_valid_drop() {
    let tmp = TempDir::new().unwrap();
    let node = open_local_node("h18-drop@box", tmp.path());

    let human_kp = Ed25519KeyPair::generate().unwrap();
    enroll_human_authority(&node, "riley", &human_kp, HumanAuthorityRole::Admin);

    let wrong_kp = Ed25519KeyPair::generate().unwrap();
    let now = now_ms();
    let build_env = |kp: &Ed25519KeyPair, body: &str| {
        let claim = HumanClaimV1 {
            v: 1,
            claim_id: format!("claim-h18-{}", uuid_v4()),
            kind: HumanDropKind::Directive,
            human_id: "riley".into(),
            human_kid: kp.kid(),
            auth_epoch: 1,
            issued_at: format_rfc3339_millis(now),
            expires_at: format_rfc3339_millis(now + 300_000),
            drop_id: "drop-h18-1".into(),
            audience: HumanAudience {
                node_id: "h18-drop@box".into(),
                node_enc_kid: node.identity().encryption.kid(),
                handle: Some("dev".into()),
            },
            secret_spec: None,
            body: body.into(),
        };
        serde_json::to_string(
            &seal_human_drop(&claim, kp, &node.identity().encryption.public_key()).unwrap(),
        )
        .unwrap()
    };

    // Event 1: signed by an UNENROLLED attacker key (fails verification!).
    let junk_env = build_env(&wrong_kp, "FORGED_JUNK_DROP_H18");
    // Event 2: signed by the REAL enrolled human authority!
    let valid_env = build_env(&human_kp, "REAL_HUMAN_DROP_AFTER_JUNK_H18");

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_url = format!("http://{}", listener.local_addr().unwrap());
    let relay_task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let junk = junk_env.clone();
            let valid = valid_env.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let n = stream.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);
                let first_line = req.lines().next().unwrap_or_default();
                if first_line.starts_with("POST /v1/drops ") {
                    let exp_ms = now_ms() + 300_000;
                    let body = json!({
                        "dropId": "drop-h18-1",
                        "postCap": "post-h18",
                        "subCap": "sub-h18",
                        "expiresAt": format_rfc3339_millis(exp_ms),
                        "expiresAtMs": exp_ms,
                        "maxPayloadBytes": 65536,
                        "maxItems": 4,
                    })
                    .to_string();
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                } else if first_line.starts_with("GET /v1/drops/drop-h18-1/stream") {
                    let hdr = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n";
                    let _ = stream.write_all(hdr.as_bytes()).await;
                    let ev1 = format!("id: 1\ndata: {junk}\n\n");
                    let _ = stream.write_all(ev1.as_bytes()).await;
                    let _ = stream.flush().await;
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    let ev2 = format!("id: 2\ndata: {valid}\n\n");
                    let _ = stream.write_all(ev2.as_bytes()).await;
                    let _ = stream.flush().await;
                } else {
                    let body = "{\"ok\":true}";
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                }
            });
        }
    });

    let daemon = LocalDaemon::start(Arc::clone(&node), None, LocalDaemonConfig::default())
        .await
        .unwrap();
    let sock = daemon.socket_path().to_path_buf();

    let mut mcp = TestMcpClient::spawn(McpOptions::new(sock.clone()));
    mcp.initialize().await;
    let (_, j_err) = mcp
        .call_verified_claude(
            &sock,
            "h18-sess",
            "hyp_mesh",
            json!({ "action": "join", "handle": "dev" }),
        )
        .await;
    assert!(!j_err);

    let transport = ScriptedTransport::new("herdr", vec![], PushOutcome::delivered());
    daemon.register_session_transport("claude:h18-sess", transport.clone());

    let (_, drop_err) = mcp
        .call_verified_claude(
            &sock,
            "h18-sess",
            "hyp_mesh",
            json!({ "action": "drop_link", "kind": "directive", "relay": relay_url }),
        )
        .await;
    assert!(!drop_err);
    // Mark setup turn idle via Stop so idle PushTransport delivers immediately.
    let _ = run_hook(
        &sock,
        HarnessKind::Claude,
        HookEvent::Stop,
        json!({ "session_id": "h18-sess" }),
    )
    .await;

    let delivered = transport
        .wait_for_delivered(1, Duration::from_secs(5))
        .await;
    assert!(
        delivered[0].starts_with("<hyphae-inbox handle=\"dev\" unread=\"1\" urgency=\"queue\">")
            && delivered[0].contains("human:riley:")
            && delivered[0].contains("verified=\"true\""),
        "H18: drop watcher must survive junk envelope and deliver valid verified XML digest: {delivered:?}"
    );
    assert!(
        !delivered[0].contains("REAL_HUMAN_DROP_AFTER_JUNK_H18")
            && !delivered[0].contains("FORGED_JUNK_DROP_H18"),
        "RFC 0004: push digest must NEVER include raw drop body (and junk drop must never be stored)"
    );
    let rows = node.db().local().peek_inbox("claude:h18-sess", 10).unwrap();
    assert!(
        rows.iter()
            .any(|m| m.text.contains("REAL_HUMAN_DROP_AFTER_JUNK_H18"))
    );
    assert!(!rows.iter().any(|m| m.text.contains("FORGED_JUNK_DROP_H18")));

    mcp.close().await;
    daemon.stop().await;
    relay_task.abort();
    node.shutdown();
}

#[tokio::test]
async fn g8_approval_never_blanket_approves_unrelated_batches_and_sweeps_on_startup() {
    let tmp = TempDir::new().unwrap();
    let state_dir = tmp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap();

    let node = open_local_node("g8-strict@box", &state_dir);
    let gate_db = Arc::new(Mutex::new(
        NodeDb::open(state_dir.join("node.sqlite")).unwrap(),
    ));

    let mut gate_cfg = SecurityGateConfig::default();
    gate_cfg
        .stage1
        .inbound_regex_denylist
        .push("BLOCK_UNRELATED_G8".into());
    gate_cfg.stage1.regex_deny_action = Stage1DenyAction::Quarantine;
    let pipeline =
        Arc::new(SecurityGatePipeline::new(gate_cfg, Arc::clone(&gate_db), None).unwrap());

    let daemon = LocalDaemon::start(
        Arc::clone(&node),
        Some(Arc::clone(&pipeline)),
        LocalDaemonConfig::default(),
    )
    .await
    .unwrap();
    let sock = daemon.socket_path().to_path_buf();

    let mut mcp = TestMcpClient::spawn(McpOptions::new(sock.clone()));
    mcp.initialize().await;
    let (_, j_err) = mcp
        .call_verified_claude(
            &sock,
            "g8-strict-sub",
            "hyp_mesh",
            json!({ "action": "join", "handle": "worker" }),
        )
        .await;
    assert!(!j_err);
    let (_, sub_err) = mcp
        .call_verified_claude(
            &sock,
            "g8-strict-sub",
            "hyp_stream",
            json!({ "action": "subscribe", "topic": "local.schedule", "coalesceSeconds": 0 }),
        )
        .await;
    assert!(!sub_err);

    // 1. Seed an UNRELATED malicious due batch in EventStore on the exact same `schedule` topic!
    let now = now_ms();
    let mut unrelated_ev = hyp_store::CloudEvent::new(
        "unrelated-malicious-ev-1",
        "local:schedule",
        TYPE_SCHEDULED_MESSAGE_V1,
        json!({ "text": "BLOCK_UNRELATED_G8 sneaky payload" }),
    );
    unrelated_ev.subject = Some("schedule".into());
    unrelated_ev.time = Some(format_rfc3339_millis(now));
    node.db()
        .events()
        .ingest("g8-strict@box", "schedule", "p", &unrelated_ev, now - 10)
        .unwrap();

    // 2. Seed a quarantined `local-ingest:schedule` staging row and approve ONLY that receipt!
    let q_rcpt = match node
        .db()
        .local()
        .put_in_mailbox(
            &MailboxInsert {
                session_id: "local-ingest:schedule".into(),
                origin_node: "g8-strict@box".into(),
                item_id: "approved-only-ev-1".into(),
                text: json!({ "text": "BLOCK_UNRELATED_G8 explicitly human approved" }).to_string(),
                kind: MailboxKind::Event,
                source: "local:schedule".into(),
                gate_state: GateState::Quarantined,
                gate_reason: Some("regex_deny".into()),
                traceparent: None,
            },
            now,
        )
        .unwrap()
    {
        MailboxPutResult::Stored { receipt } => receipt,
        other => panic!("unexpected put: {other:?}"),
    };
    node.db()
        .local()
        .approve_quarantined(&q_rcpt, "human@cli", now + 1)
        .unwrap();

    let transport = ScriptedTransport::new("herdr", vec![], PushOutcome::delivered());
    daemon.register_session_transport("claude:g8-strict-sub", transport.clone());

    let wake = rpc(&sock, &json!({ "type": "inbox.wake", "receipt": q_rcpt })).await;
    assert!(wake.ok);

    let delivered = transport
        .wait_for_delivered(1, Duration::from_secs(3))
        .await;
    let combined = delivered.join("\n");
    assert!(
        combined.starts_with("<hyphae-inbox handle=\"worker\" unread=\"1\" urgency=\"queue\">")
            && combined.contains("<stream topic=\"local.schedule\" count=\"1\"/>"),
        "approved event must surface in metadata-only XML digest: {combined}"
    );
    assert!(
        !combined.contains("explicitly human approved") && !combined.contains("sneaky payload"),
        "RFC 0004 / G8: digest must NEVER expose raw event bodies: {combined}"
    );
    let cleared = node
        .db()
        .local()
        .peek_inbox_with_visibility(
            "claude:g8-strict-sub",
            10,
            hyp_store::MailboxVisibility::GateCleared,
        )
        .unwrap();
    assert!(
        cleared
            .iter()
            .any(|m| m.text.contains("explicitly human approved")),
        "approved event must be in gate-cleared mailbox: {cleared:?}"
    );
    assert!(
        !cleared.iter().any(|m| m.text.contains("sneaky payload")),
        "G8 VIOLATION: unrelated due batch on same topic was blanket-approved! {cleared:?}"
    );
    assert_eq!(
        node.db()
            .local()
            .quarantined_count(Some("claude:g8-strict-sub"))
            .unwrap(),
        1,
        "unrelated malicious event must be quarantined by Security Gate"
    );

    // 3. Startup sweep test: stop daemon, approve a quarantined `local-ingest:schedule` row while
    //    daemon is STOPPED, then restart daemon -> startup sweep fans it out to subscriber!
    mcp.close().await;
    daemon.stop().await;

    let offline_rcpt = match node
        .db()
        .local()
        .put_in_mailbox(
            &MailboxInsert {
                session_id: "local-ingest:schedule".into(),
                origin_node: "g8-strict@box".into(),
                item_id: "approved-offline-ev-2".into(),
                text: json!({ "text": "OFFLINE_APPROVED_STARTUP_SWEEP_G8" }).to_string(),
                kind: MailboxKind::Event,
                source: "local:schedule".into(),
                gate_state: GateState::Quarantined,
                gate_reason: Some("regex_deny".into()),
                traceparent: None,
            },
            now + 50,
        )
        .unwrap()
    {
        MailboxPutResult::Stored { receipt } => receipt,
        other => panic!("unexpected offline put: {other:?}"),
    };
    node.db()
        .local()
        .approve_quarantined(&offline_rcpt, "human@cli", now + 51)
        .unwrap();

    let daemon2 = LocalDaemon::start(
        Arc::clone(&node),
        Some(Arc::clone(&pipeline)),
        LocalDaemonConfig::default(),
    )
    .await
    .unwrap();
    let sock2 = daemon2.socket_path().to_path_buf();

    // Subscriber's mailbox MUST now contain the offline-approved event (gate-cleared)!
    let drain2 = rpc(
        &sock2,
        &json!({ "type": "mailbox.drain", "sessionId": "claude:g8-strict-sub" }),
    )
    .await;
    assert!(drain2.ok);
    let rendered2 = serde_json::to_string(&drain2.result).unwrap();
    assert!(
        rendered2.contains("<hyphae-inbox") && rendered2.contains("local.schedule"),
        "G8 startup sweep must emit metadata-only XML digest for offline-approved local-ingest row: {rendered2}"
    );
    assert!(!rendered2.contains("OFFLINE_APPROVED_STARTUP_SWEEP_G8"));
    assert!(
        node.db()
            .local()
            .peek_inbox_with_visibility(
                "claude:g8-strict-sub",
                20,
                hyp_store::MailboxVisibility::GateCleared
            )
            .unwrap()
            .iter()
            .any(|m| m.text.contains("OFFLINE_APPROVED_STARTUP_SWEEP_G8")),
        "G8 startup sweep must fan out offline-approved local-ingest row into subscriber mailbox"
    );

    daemon2.stop().await;
    node.shutdown();
}
