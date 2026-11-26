//! End-to-end integration tests for Hyphae v0.5.0 `hyp-harness`:
//! - Strictly 4 core MCP tools across all 9 harnesses (zero `hyp_wakeup` bloat)
//! - Tier 3 bounded `Hold` retry queue + immediate `PostToolUse` / `leave` cancellation
//! - Default socket-only `LocalIngestServer` (`ingest.sock` / loopback `.addr`) ->
//!   `hyp_stream` (`local.schedule`) live session wakeup (unsigned & Ed25519 `hyphaesig`-signed)
//! - `hyp_mesh({ action: "drop_link" })` HPKE-encrypted directive prefill (`encDraft` ONLY),
//!   fail-closed security guards, `X-Hyphae-Public-Key` external relay header, zero-leak secret
//!   drop + RAM burn, offline fallback, and `drop.ingest` IPC
//! - Tier 4 allowlisted Herdr cold-spawn (`hc run <template> <prompt>`) & mutated security guards.

use std::collections::BTreeMap;
use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http::header::CONTENT_TYPE;
use http::{Method, Request, StatusCode};
use hyp_crypto::human::{
    EncryptedHumanDraftV1, HUMAN_DRAFT_SUITE, HumanAudience, HumanClaimV1, HumanDropKind,
    SecretDropSpec, decode_hcert1, derive_prf_ed25519_keypair, derive_prf_x25519_keypair,
    encode_hdrop1, open_human_draft, seal_human_drop, sign_local_ingest_event, verify_node_cert,
};
use hyp_crypto::jcs::to_canonical_json;
use hyp_crypto::rfc3339::format_rfc3339_millis;
use hyp_crypto::{Ed25519KeyPair, SecretBackend};
use hyp_harness::daemon::{DeliveryRetryConfig, InboundItem, LocalDaemon, LocalDaemonConfig};
use hyp_harness::hooks::{HandleHookOptions, HookEvent, HookTransportHints, handle_hook_payload};
use hyp_harness::mcp::{McpOptions, run_mcp_io};
use hyp_harness::protocol::{HarnessKind, UNTRUSTED_PROVENANCE};
use hyp_harness::sock::{DaemonRpcResult, daemon_rpc_async};
use hyp_harness::transport::{PushMode, PushOutcome, PushTransport, TransportFuture};
use hyp_node::engine::http_util::{HttpClient, full_body};
use hyp_node::engine::{
    DROP_CAP_HEADER, DropRelayConfig, LocalIngestServer, NodeConfig, UnifiedNode,
    canonical_local_event_for_signing, send_local_ingest_event,
};
use hyp_node::gates::TrustTier as GateTrustTier;
use hyp_proto::address::NodeId;
use hyp_proto::cloudevent::{
    CONTENT_TYPE_JSON, CloudEvent, EXT_LOCAL_EVENT_SIG, TYPE_HUMAN_SECRET_STORED_V1,
    TYPE_SCHEDULED_MESSAGE_V1,
};
use hyp_store::{
    GateAuditQuery, HumanAuthorityInput, HumanAuthorityRole, MailboxKind, now_ms, uuid_v4,
};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, DuplexStream};
use tokio::sync::Notify;

fn open_local_node(node_id: &str, dir: &Path) -> Arc<UnifiedNode> {
    let mut cfg = NodeConfig::local(NodeId::new(node_id).unwrap(), dir);
    cfg.secret_backend = Some(SecretBackend::File);
    UnifiedNode::open(cfg).expect("open UnifiedNode")
}

async fn rpc(sock: &Path, pkt: &Value) -> DaemonRpcResult {
    daemon_rpc_async(sock, pkt, Duration::from_secs(5)).await
}

fn hook_opts(harness: HarnessKind, event: HookEvent, sock: &Path) -> HandleHookOptions {
    HandleHookOptions {
        harness,
        event,
        socket_path: sock.to_path_buf(),
        cli_path: Some("hyp".into()),
        explicit_socket: None,
        transport_hints: HookTransportHints::default(),
    }
}

struct TestMcpClient {
    writer: DuplexStream,
    reader: tokio::io::Lines<BufReader<DuplexStream>>,
    next_id: u64,
    task: tokio::task::JoinHandle<()>,
}

impl TestMcpClient {
    fn spawn(options: McpOptions) -> Self {
        let (client_w, server_r) = tokio::io::duplex(65_536);
        let (server_w, client_r) = tokio::io::duplex(65_536);
        let task = tokio::spawn(async move {
            let _ = run_mcp_io(BufReader::new(server_r), server_w, options).await;
        });
        Self {
            writer: client_w,
            reader: BufReader::new(client_r).lines(),
            next_id: 0,
            task,
        }
    }

    async fn send_json(&mut self, msg: &Value) {
        let line = format!("{msg}\n");
        self.writer.write_all(line.as_bytes()).await.unwrap();
        self.writer.flush().await.unwrap();
    }

    async fn next_message(&mut self) -> Value {
        let line = tokio::time::timeout(Duration::from_secs(10), self.reader.next_line())
            .await
            .expect("MCP read timed out")
            .expect("MCP read I/O error")
            .expect("MCP stream closed unexpectedly");
        serde_json::from_str(&line).expect("valid JSON-RPC line")
    }

    async fn request(&mut self, method: &str, params: Value) -> Value {
        self.next_id += 1;
        let id = self.next_id;
        self.send_json(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params
        }))
        .await;
        loop {
            let msg = self.next_message().await;
            if msg.get("id").and_then(Value::as_u64) == Some(id) {
                return msg;
            }
        }
    }

    async fn initialize(&mut self) -> Value {
        let res = self
            .request(
                "initialize",
                json!({
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "v050-e2e", "version": "1"}
                }),
            )
            .await;
        self.send_json(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
            .await;
        res
    }

    async fn list_tool_names(&mut self) -> Vec<String> {
        let res = self.request("tools/list", json!({})).await;
        res["result"]["tools"]
            .as_array()
            .expect("tools array")
            .iter()
            .map(|t| t["name"].as_str().unwrap().to_string())
            .collect()
    }

    async fn call_tool(
        &mut self,
        name: &str,
        arguments: Value,
        meta: Option<Value>,
    ) -> (String, bool) {
        let mut params = json!({ "name": name, "arguments": arguments });
        if let Some(m) = meta {
            params["_meta"] = m;
        }
        let res = self.request("tools/call", params).await;
        let result = &res["result"];
        let text = result["content"][0]["text"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        let is_error = result["isError"].as_bool() == Some(true);
        (text, is_error)
    }

    async fn call_verified_claude(
        &mut self,
        sock: &Path,
        session_raw: &str,
        tool_name: &str,
        arguments: Value,
    ) -> (String, bool) {
        let call_id = format!("toolu_{}_{}", session_raw, self.next_id + 1);
        let sock_owned = sock.to_path_buf();
        let sess_owned = session_raw.to_string();
        let tool_owned = format!("mcp__hyphae__{tool_name}");
        let args_clone = arguments.clone();
        let cid_clone = call_id.clone();

        tokio::task::spawn_blocking(move || {
            handle_hook_payload(
                json!({
                    "session_id": sess_owned,
                    "tool_use_id": cid_clone,
                    "tool_name": tool_owned,
                    "tool_input": args_clone
                })
                .as_object()
                .unwrap(),
                &hook_opts(HarnessKind::Claude, HookEvent::PreToolUse, &sock_owned),
            )
        })
        .await
        .unwrap();

        self.call_tool(
            tool_name,
            arguments,
            Some(json!({ "claudecode/toolUseId": call_id })),
        )
        .await
    }

    async fn close(self) {
        drop(self.writer);
        let _ = tokio::time::timeout(Duration::from_secs(3), self.task).await;
    }
}

/// Scripted in-process `PushTransport` returning a sequence of [`PushOutcome`] values,
/// recording delivered payloads + `PushMode`, and notifying callers on each attempt.
struct ScriptedPushTransport {
    kind: &'static str,
    outcomes: Mutex<std::collections::VecDeque<PushOutcome>>,
    default_outcome: Mutex<PushOutcome>,
    attempts: AtomicUsize,
    delivered: Mutex<Vec<(String, PushMode)>>,
    notify: Notify,
}

impl ScriptedPushTransport {
    fn new(kind: &'static str, scripted: Vec<PushOutcome>, default_outcome: PushOutcome) -> Self {
        Self {
            kind,
            outcomes: Mutex::new(scripted.into()),
            default_outcome: Mutex::new(default_outcome),
            attempts: AtomicUsize::new(0),
            delivered: Mutex::new(Vec::new()),
            notify: Notify::new(),
        }
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

    fn delivered_entries(&self) -> Vec<(String, PushMode)> {
        self.delivered.lock().unwrap().clone()
    }
}

impl PushTransport for ScriptedPushTransport {
    fn kind(&self) -> &'static str {
        self.kind
    }

    fn supports_interrupt(&self) -> bool {
        true
    }

    fn deliver<'a>(&'a self, text: &'a str, mode: PushMode) -> TransportFuture<'a, PushOutcome> {
        let text_owned = text.to_string();
        Box::pin(async move {
            self.attempts.fetch_add(1, Ordering::SeqCst);
            let outcome = self
                .outcomes
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| self.default_outcome.lock().unwrap().clone());
            if outcome.is_delivered() {
                self.delivered.lock().unwrap().push((text_owned, mode));
            }
            self.notify.notify_waiters();
            outcome
        })
    }
}

// =========================================================================
// Test 1: Strictly 4 core MCP tools across ALL 9 harnesses (ZERO hyp_wakeup)
// =========================================================================

#[tokio::test]
async fn test1_four_core_tools_no_hyp_wakeup_tool() {
    let dir = TempDir::new().unwrap();
    let node = open_local_node("caps-v050@box", dir.path());

    let daemon = LocalDaemon::start(Arc::clone(&node), None, LocalDaemonConfig::default())
        .await
        .expect("start daemon");
    let sock = daemon.socket_path().to_path_buf();

    // Every single harness MUST receive strictly the 4 core tools and ZERO `hyp_wakeup`.
    for backend in HarnessKind::ALL {
        let mut opts = McpOptions::new(sock.clone());
        opts.backend = Some(backend);
        let mut client = TestMcpClient::spawn(opts);
        let init_res = client.initialize().await;
        let instructions = init_res["result"]["instructions"]
            .as_str()
            .expect("initialize instructions");
        assert!(
            !instructions.contains("hyp_wakeup"),
            "backend {backend:?} instructions must never reference removed hyp_wakeup: {instructions}"
        );

        let names = client.list_tool_names().await;
        assert_eq!(
            names,
            vec!["hyp_send", "hyp_inbox", "hyp_mesh", "hyp_stream"],
            "backend {backend:?} must receive strictly 4 core tools (ZERO hyp_wakeup bloat!)"
        );
        client.close().await;
    }

    // Calling removed `hyp_wakeup` tool directly MUST fail closed as unknown_tool.
    let mut opts = McpOptions::new(sock.clone());
    opts.backend = Some(HarnessKind::Claude);
    opts.ephemeral = true;
    let mut client = TestMcpClient::spawn(opts);
    client.initialize().await;
    let (err_txt, is_err) = client
        .call_tool("hyp_wakeup", json!({ "action": "list" }), None)
        .await;
    assert!(is_err, "removed hyp_wakeup tool must fail closed");
    assert!(
        err_txt.contains("unknown_tool"),
        "expected unknown_tool for hyp_wakeup, got: {err_txt}"
    );
    client.close().await;

    daemon.stop().await;
    node.shutdown();
}

// =========================================================================
// Test 2: Tier 3 Bounded `Hold` Retry Queue + Hook & Leave Cancellation
// =========================================================================

#[tokio::test]
async fn test2_tier3_bounded_hold_retry_queue_and_hook_cancellation() {
    let dir = TempDir::new().unwrap();
    let node = open_local_node("retry@box", dir.path());

    let cfg = LocalDaemonConfig {
        delivery_retry: DeliveryRetryConfig {
            hold_retry_backoff_ms: vec![25, 25, 25],
            hold_retry_max_attempts: 6,
            ..Default::default()
        },
        ..Default::default()
    };
    let daemon = LocalDaemon::start(Arc::clone(&node), None, cfg)
        .await
        .expect("start daemon");

    // ---- 2a: Mock PushTransport returns Hold("herdr_working") twice, then Delivered on #3 ----
    let sid_retry = "claude:retry-session";
    node.register_session(sid_retry, "{\"kind\":\"claude\"}")
        .unwrap();
    let transport_retry = Arc::new(ScriptedPushTransport::new(
        "herdr",
        vec![
            PushOutcome::hold("herdr_working"),
            PushOutcome::hold("herdr_working"),
            PushOutcome::delivered(),
        ],
        PushOutcome::delivered(),
    ));
    daemon.register_session_transport(
        sid_retry,
        Arc::clone(&transport_retry) as Arc<dyn PushTransport>,
    );

    let ingested = daemon
        .ingest_inbound(InboundItem {
            session_id: sid_retry.to_string(),
            origin_node: node.node_id().to_string(),
            item_id: format!("retry-item-{}", uuid_v4()),
            source: "local.schedule".to_string(),
            text: format!("{UNTRUSTED_PROVENANCE}\nAuto-deliver after transient busy Hold"),
            kind: MailboxKind::Event,
            trust_tier: GateTrustTier::SelfHost,
        })
        .await
        .expect("ingest inbound for retry");
    assert!(ingested.is_some());

    // Wait for bounded Tier 3 retry backoff to complete delivery on attempt #3.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while transport_retry.delivered_texts().is_empty() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for Tier 3 retry auto-delivery (attempts={})",
            transport_retry.attempts()
        );
        let _ = tokio::time::timeout(
            Duration::from_millis(200),
            transport_retry.notify.notified(),
        )
        .await;
    }

    assert_eq!(
        transport_retry.attempts(),
        3,
        "expected exactly 3 attempts (2 Hold + 1 Delivered)"
    );
    let delivered = transport_retry.delivered_texts();
    assert_eq!(delivered.len(), 1);
    assert!(delivered[0].contains(UNTRUSTED_PROVENANCE));
    assert!(delivered[0].contains("Auto-deliver after transient busy Hold"));
    assert_eq!(node.db().local().pending_count(sid_retry).unwrap(), 0);

    // ---- 2b: PostToolUse `mailbox.drain` cancels pending Tier 3 retry immediately (0 extra calls!) ----
    let dir2 = TempDir::new().unwrap();
    let node2 = open_local_node("retry-cancel@box", dir2.path());
    let cfg2 = LocalDaemonConfig {
        delivery_retry: DeliveryRetryConfig {
            hold_retry_backoff_ms: vec![200, 200, 200],
            hold_retry_max_attempts: 6,
            ..Default::default()
        },
        ..Default::default()
    };
    let daemon2 = LocalDaemon::start(Arc::clone(&node2), None, cfg2)
        .await
        .expect("start daemon2");
    let sock2 = daemon2.socket_path().to_path_buf();

    let sid_cancel = "claude:cancel-session";
    node2
        .register_session(sid_cancel, "{\"kind\":\"claude\"}")
        .unwrap();
    let transport_cancel = Arc::new(ScriptedPushTransport::new(
        "herdr",
        vec![PushOutcome::hold("herdr_working")],
        PushOutcome::hold("herdr_working"),
    ));
    daemon2.register_session_transport(
        sid_cancel,
        Arc::clone(&transport_cancel) as Arc<dyn PushTransport>,
    );

    daemon2
        .ingest_inbound(InboundItem {
            session_id: sid_cancel.to_string(),
            origin_node: node2.node_id().to_string(),
            item_id: format!("cancel-item-{}", uuid_v4()),
            source: "local.schedule".to_string(),
            text: "Drained by PostToolUse before retry timer fires".to_string(),
            kind: MailboxKind::Event,
            trust_tier: GateTrustTier::SelfHost,
        })
        .await
        .expect("ingest inbound for hook cancel");
    assert_eq!(transport_cancel.attempts(), 1);

    // Simulate `Stop` (TurnEnd) hook draining the queued event BEFORE the 200 ms retry fires.
    let sock2_clone = sock2.clone();
    let hook_out = tokio::task::spawn_blocking(move || {
        handle_hook_payload(
            json!({
                "session_id": "cancel-session"
            })
            .as_object()
            .unwrap(),
            &hook_opts(HarnessKind::Claude, HookEvent::Stop, &sock2_clone),
        )
    })
    .await
    .unwrap();
    let injected = hook_out["reason"]
        .as_str()
        .expect("Stop TurnEnd hook must inject queued event");
    assert!(injected.contains("Drained by PostToolUse before retry timer fires"));
    assert_eq!(node2.db().local().pending_count(sid_cancel).unwrap(), 0);

    // Wait well past the 200 ms backoff window and assert ZERO additional transport calls!
    tokio::time::sleep(Duration::from_millis(350)).await;
    assert_eq!(
        transport_cancel.attempts(),
        1,
        "PostToolUse drain must cancel pending Tier 3 retry with 0 extra push attempts"
    );

    daemon2.stop().await;
    daemon.stop().await;
    node2.shutdown();
    node.shutdown();
}

// =========================================================================
// Test 3: Default `LocalIngestServer` (`ingest.sock` / `.addr`) wakes
//         `hyp_stream` (`local.schedule`) subscriber end-to-end
// =========================================================================

#[tokio::test]
async fn test3_local_ingest_socket_wakes_hyp_stream_subscriber_end_to_end() {
    let dir = TempDir::new().unwrap();
    let node = open_local_node("ingest-e2e@box", dir.path());

    // Enroll an active human signing key so Ed25519 `hyphaesig`-signed local events verify.
    let human_signer = Ed25519KeyPair::generate().unwrap();
    let human_id = "alice@phone";
    {
        let db = node.db();
        db.human()
            .upsert_authority(
                &HumanAuthorityInput {
                    human_id: human_id.to_string(),
                    kid: human_signer.kid(),
                    label: "Alice Signer".to_string(),
                    role: HumanAuthorityRole::Admin,
                    jwk_json: serde_json::to_string(&human_signer.to_jwk()).unwrap(),
                    enc_jwk_json: None,
                    prf_salt: None,
                    auth_epoch: 1,
                },
                now_ms(),
            )
            .unwrap();
    }

    let ingest_server = LocalIngestServer::start_default(Arc::clone(&node), None)
        .await
        .expect("start default LocalIngestServer");
    let ingest_endpoint = ingest_server.endpoint_path().to_path_buf();

    let daemon = LocalDaemon::start(Arc::clone(&node), None, LocalDaemonConfig::default())
        .await
        .expect("start LocalDaemon");
    let sock = daemon.socket_path().to_path_buf();

    let mut client_opts = McpOptions::new(sock.clone());
    client_opts.backend = Some(HarnessKind::Claude);
    let mut client = TestMcpClient::spawn(client_opts);
    client.initialize().await;

    // Enroll two sessions: `morning-s1` subscribes to `local.schedule` (`label == "morning-check"`),
    // while `other-s1` subscribes with a non-matching filter (`label == "nightly-audit"`).
    let (_, join_err) = client
        .call_verified_claude(
            &sock,
            "morning-s1",
            "hyp_mesh",
            json!({ "action": "join", "handle": "morning" }),
        )
        .await;
    assert!(!join_err);
    let (_, join2_err) = client
        .call_verified_claude(
            &sock,
            "other-s1",
            "hyp_mesh",
            json!({ "action": "join", "handle": "other" }),
        )
        .await;
    assert!(!join2_err);

    let morning_sid = "claude:morning-s1";
    let other_sid = "claude:other-s1";

    let morning_transport = Arc::new(ScriptedPushTransport::new(
        "herdr",
        Vec::new(),
        PushOutcome::delivered(),
    ));
    let other_transport = Arc::new(ScriptedPushTransport::new(
        "herdr",
        Vec::new(),
        PushOutcome::delivered(),
    ));
    daemon.register_session_transport(
        morning_sid,
        Arc::clone(&morning_transport) as Arc<dyn PushTransport>,
    );
    daemon.register_session_transport(
        other_sid,
        Arc::clone(&other_transport) as Arc<dyn PushTransport>,
    );

    // Subscribe via `hyp_stream` with `topic: "local.schedule"`, filter, and `urgency: "interrupt"`.
    let (sub_txt, sub_err) = client
        .call_verified_claude(
            &sock,
            "morning-s1",
            "hyp_stream",
            json!({
                "action": "subscribe",
                "topic": "local.schedule",
                "filters": [{ "exact": { "label": "morning-check" } }],
                "urgency": "interrupt"
            }),
        )
        .await;
    assert!(!sub_err, "hyp_stream subscribe failed: {sub_txt}");
    let sub_val: Value = serde_json::from_str(&sub_txt).unwrap();
    assert_eq!(sub_val["topic"], "schedule");
    assert_eq!(sub_val["mode"], "interrupt");
    assert_eq!(sub_val["reachable"], json!(true));

    let (sub2_txt, sub2_err) = client
        .call_verified_claude(
            &sock,
            "other-s1",
            "hyp_stream",
            json!({
                "action": "subscribe",
                "topic": "local.schedule",
                "filters": [{ "exact": { "label": "nightly-audit" } }],
                "mode": "queue"
            }),
        )
        .await;
    assert!(!sub2_err, "other hyp_stream subscribe failed: {sub2_txt}");

    // 3a. Send an UNSIGNED compact shorthand event over `ingest.sock` / `.addr`.
    let unsigned_receipt = send_local_ingest_event(
        &ingest_endpoint,
        &json!({
            "label": "morning-check",
            "note": "Check canary dashboards and open PRs",
            "ttlSeconds": 300
        }),
    )
    .await
    .expect("send unsigned local ingest event");
    assert_eq!(
        unsigned_receipt["ok"],
        json!(true),
        "receipt: {unsigned_receipt}"
    );
    assert_eq!(unsigned_receipt["topic"], "local.schedule");
    assert_eq!(unsigned_receipt["trustTier"], "external-webhook");
    assert_eq!(unsigned_receipt["matchedSubscribers"], json!(1));
    assert_eq!(unsigned_receipt["deliveredSessions"], json!(1));

    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while morning_transport.delivered_entries().is_empty() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for unsigned local.schedule event wakeup"
        );
        let _ = tokio::time::timeout(
            Duration::from_millis(200),
            morning_transport.notify.notified(),
        )
        .await;
    }

    let first_entries = morning_transport.delivered_entries();
    assert_eq!(first_entries.len(), 1);
    assert!(
        first_entries[0]
            .0
            .contains("Check canary dashboards and open PRs"),
        "woken payload missing note: {}",
        first_entries[0].0
    );
    assert_eq!(
        first_entries[0].1,
        PushMode::Interrupt,
        "urgency: 'interrupt' subscription must wake transport in Interrupt mode"
    );
    assert!(
        other_transport.delivered_entries().is_empty(),
        "non-matching subscriber must receive nothing"
    );

    // 3b. Send an Ed25519 `hyphaesig`-SIGNED CloudEvents v1.0 event over `ingest.sock` / `.addr`.
    let mut signed_ce = CloudEvent {
        specversion: "1.0".to_string(),
        id: format!("ce-signed-{}", uuid_v4()),
        source: "cron:human-ops".to_string(),
        event_type: TYPE_SCHEDULED_MESSAGE_V1.to_string(),
        datacontenttype: Some(CONTENT_TYPE_JSON.to_string()),
        dataschema: None,
        subject: Some("morning-check".to_string()),
        time: Some(format_rfc3339_millis(now_ms())),
        data: Some(json!({
            "label": "morning-check",
            "note": "Human-signed canary release verification"
        })),
        data_base64: None,
        extensions: BTreeMap::from([("label".to_string(), json!("morning-check"))]),
    };
    let canon = canonical_local_event_for_signing(&signed_ce).expect("canonicalize CE");
    let sig_attr = sign_local_ingest_event(&human_signer, &canon);
    signed_ce.extensions.insert(
        EXT_LOCAL_EVENT_SIG.to_string(),
        Value::String(sig_attr.clone()),
    );

    let mut signed_wire = serde_json::to_value(&signed_ce).unwrap();
    signed_wire
        .as_object_mut()
        .unwrap()
        .insert("topic".to_string(), json!("local.schedule"));

    let signed_receipt = send_local_ingest_event(&ingest_endpoint, &signed_wire)
        .await
        .expect("send signed local ingest event");
    assert_eq!(
        signed_receipt["ok"],
        json!(true),
        "signed receipt: {signed_receipt}"
    );
    assert_eq!(signed_receipt["trustTier"], "human-verified");
    assert_eq!(signed_receipt["verifiedHumanKid"], human_signer.kid());
    assert_eq!(signed_receipt["verifiedHumanId"], human_id);
    assert_eq!(signed_receipt["matchedSubscribers"], json!(1));
    assert_eq!(signed_receipt["deliveredSessions"], json!(1));

    let deadline2 = tokio::time::Instant::now() + Duration::from_secs(3);
    while morning_transport.delivered_entries().len() < 2 {
        assert!(
            tokio::time::Instant::now() < deadline2,
            "timed out waiting for signed local.schedule event wakeup"
        );
        let _ = tokio::time::timeout(
            Duration::from_millis(200),
            morning_transport.notify.notified(),
        )
        .await;
    }

    let entries = morning_transport.delivered_entries();
    assert_eq!(entries.len(), 2);
    assert!(
        entries[1]
            .0
            .contains("Human-signed canary release verification"),
        "second woken payload missing signed note: {}",
        entries[1].0
    );
    assert_eq!(entries[1].1, PushMode::Interrupt);

    // 3c. Tampered `hyphaesig` MUST fail closed and never wake the subscriber!
    let mut bad_wire = signed_wire.clone();
    let bad_sig = if sig_attr.ends_with('A') {
        format!("{}B", &sig_attr[..sig_attr.len() - 1])
    } else {
        format!("{}A", &sig_attr[..sig_attr.len() - 1])
    };
    bad_wire
        .as_object_mut()
        .unwrap()
        .insert(EXT_LOCAL_EVENT_SIG.to_string(), Value::String(bad_sig));
    bad_wire.as_object_mut().unwrap().insert(
        "id".to_string(),
        json!(format!("ce-tampered-{}", uuid_v4())),
    );

    let bad_receipt = send_local_ingest_event(&ingest_endpoint, &bad_wire)
        .await
        .expect("send tampered local ingest event");
    assert_eq!(bad_receipt["ok"], json!(false));
    assert_eq!(bad_receipt["error"], "invalid_signature");

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        morning_transport.delivered_entries().len(),
        2,
        "tampered signature must never wake subscriber"
    );

    client.close().await;
    ingest_server.stop().await;
    daemon.stop().await;
    node.shutdown();
}

// =========================================================================
// Test 4: `hyp_mesh({ action: "drop_link" })` Encrypted Draft (`encDraft`)
//         Roundtrip, Fail-Closed Security Guards, & `X-Hyphae-Public-Key`
// =========================================================================

#[tokio::test]
async fn test4_mesh_drop_link_encrypted_draft_roundtrip_and_fail_closed_guards() {
    let dir = TempDir::new().unwrap();
    let node = open_local_node("draft-e2e@box", dir.path());

    // Derive Passkey-PRF Ed25519 + companion X25519 keypair and enroll WITH `enc_jwk_json`.
    let human_id = "bogdan@phone";
    let prf_out = [0x42u8; 32];
    let human_sign_kp = derive_prf_ed25519_keypair(&prf_out, human_id, 1).unwrap();
    let human_enc_kp = derive_prf_x25519_keypair(&prf_out, human_id, 1).unwrap();
    {
        let db = node.db();
        db.human()
            .upsert_authority(
                &HumanAuthorityInput {
                    human_id: human_id.to_string(),
                    kid: human_sign_kp.kid(),
                    label: "iPhone Passkey v0.5".to_string(),
                    role: HumanAuthorityRole::Admin,
                    jwk_json: serde_json::to_string(&human_sign_kp.to_jwk()).unwrap(),
                    enc_jwk_json: Some(serde_json::to_string(&human_enc_kp.to_jwk()).unwrap()),
                    prf_salt: Some("salt-prf-v050".to_string()),
                    auth_epoch: 1,
                },
                now_ms(),
            )
            .unwrap();
    }

    let daemon = LocalDaemon::start(Arc::clone(&node), None, LocalDaemonConfig::default())
        .await
        .expect("start LocalDaemon");
    let sock = daemon.socket_path().to_path_buf();

    let mut client_opts = McpOptions::new(sock.clone());
    client_opts.backend = Some(HarnessKind::Claude);
    let mut client = TestMcpClient::spawn(client_opts);
    client.initialize().await;

    let (_, join_err) = client
        .call_verified_claude(
            &sock,
            "deploy-s1",
            "hyp_mesh",
            json!({ "action": "join", "handle": "deployer" }),
        )
        .await;
    assert!(!join_err);

    // 4a. Happy path: directive drop_link with `draft` + `context` seals into `encDraft` ONLY!
    let draft_text = "Approve deploy of checkout-api v2.4.1";
    let context_label = "PR #412";
    let (link_txt, link_err) = client
        .call_verified_claude(
            &sock,
            "deploy-s1",
            "hyp_mesh",
            json!({
                "action": "drop_link",
                "kind": "directive",
                "draft": draft_text,
                "context": context_label
            }),
        )
        .await;
    assert!(!link_err, "encrypted draft drop_link failed: {link_txt}");
    let link_val: Value = serde_json::from_str(&link_txt).unwrap();
    assert_eq!(link_val["ok"], json!(true));
    assert_eq!(link_val["kind"], "directive");
    assert_eq!(link_val["hasEncryptedDraft"], json!(true));

    let url = link_val["url"].as_str().expect("drop URL");
    assert!(
        !url.contains("checkout-api")
            && !url.contains("Approve deploy")
            && !url.contains("PR #412"),
        "ZERO-LEAK VIOLATION: plaintext draft appeared in drop URL!"
    );

    let frag_b64 = url
        .strip_prefix("https://hyphae.to/drop#drop=")
        .expect("URL must start with https://hyphae.to/drop#drop=");
    let frag_bytes = URL_SAFE_NO_PAD
        .decode(frag_b64)
        .expect("valid base64url fragment");
    let frag_raw = std::str::from_utf8(&frag_bytes).expect("utf8 fragment");
    assert!(
        !frag_raw.contains("checkout-api")
            && !frag_raw.contains("Approve deploy")
            && !frag_raw.contains("PR #412"),
        "ZERO-LEAK VIOLATION: plaintext draft appeared inside decoded #drop= JSON!"
    );

    let frag: Value = serde_json::from_slice(&frag_bytes).expect("valid fragment JSON");
    assert!(
        frag.get("draft").is_none()
            && frag.get("proposedText").is_none()
            && frag.get("body").is_none()
            && frag.get("context").is_none(),
        "fragment MUST ONLY contain encDraft, never plaintext draft/proposedText/body/context"
    );
    assert_eq!(frag["humanId"], human_id);
    assert_eq!(frag["prfSalt"], "salt-prf-v050");
    assert_eq!(frag["authEpoch"], json!(1));

    let enc_draft: EncryptedHumanDraftV1 =
        serde_json::from_value(frag["encDraft"].clone()).expect("valid EncryptedHumanDraftV1");
    assert_eq!(enc_draft.v, 1);
    assert_eq!(enc_draft.suite, HUMAN_DRAFT_SUITE);
    assert_eq!(enc_draft.recipient_kid, human_enc_kp.kid());

    let opened = open_human_draft(&enc_draft, &human_enc_kp, "draft-e2e@box")
        .expect("open_human_draft must decrypt cleanly with Passkey-PRF X25519 key");
    assert_eq!(opened.v, 1);
    assert_eq!(opened.node_id, "draft-e2e@box");
    assert_eq!(opened.text, draft_text);
    assert_eq!(opened.context.as_deref(), Some(context_label));

    // 4b. Fail-closed guard: `kind: "secret"` with `draft` or `context` MUST fail closed!
    let (sec_draft_txt, sec_draft_err) = client
        .call_verified_claude(
            &sock,
            "deploy-s1",
            "hyp_mesh",
            json!({
                "action": "drop_link",
                "kind": "secret",
                "secretName": "prod-api-key",
                "draft": "sk-forbidden-prefill"
            }),
        )
        .await;
    assert!(sec_draft_err, "kind=secret with draft must fail closed");
    assert!(
        sec_draft_txt.to_ascii_lowercase().contains("forbidden"),
        "expected forbidden error for secret draft, got: {sec_draft_txt}"
    );

    let (sec_ctx_txt, sec_ctx_err) = client
        .call_verified_claude(
            &sock,
            "deploy-s1",
            "hyp_mesh",
            json!({
                "action": "drop_link",
                "kind": "secret",
                "secretName": "prod-api-key",
                "context": "PR #412"
            }),
        )
        .await;
    assert!(sec_ctx_err, "kind=secret with context must fail closed");
    assert!(
        sec_ctx_txt.to_ascii_lowercase().contains("forbidden"),
        "expected forbidden error for secret context, got: {sec_ctx_txt}"
    );

    // 4c. Fail-closed guard: BiDi override (`\u{202E}`), empty draft, oversized draft, orphan context!
    let (bidi_txt, bidi_err) = client
        .call_verified_claude(
            &sock,
            "deploy-s1",
            "hyp_mesh",
            json!({
                "action": "drop_link",
                "kind": "directive",
                "draft": "\u{202E}evil"
            }),
        )
        .await;
    assert!(
        bidi_err,
        "BiDi override in draft must fail closed: {bidi_txt}"
    );

    let (_, empty_err) = client
        .call_verified_claude(
            &sock,
            "deploy-s1",
            "hyp_mesh",
            json!({
                "action": "drop_link",
                "kind": "directive",
                "draft": "   "
            }),
        )
        .await;
    assert!(empty_err, "whitespace-only draft must fail closed");

    let (_, over_err) = client
        .call_verified_claude(
            &sock,
            "deploy-s1",
            "hyp_mesh",
            json!({
                "action": "drop_link",
                "kind": "directive",
                "draft": "a".repeat(513)
            }),
        )
        .await;
    assert!(over_err, ">512 char draft must fail closed");

    let (_, orphan_ctx_err) = client
        .call_verified_claude(
            &sock,
            "deploy-s1",
            "hyp_mesh",
            json!({
                "action": "drop_link",
                "kind": "directive",
                "context": "orphan context without draft"
            }),
        )
        .await;
    assert!(orphan_ctx_err, "context without draft must fail closed");

    // 4d. External relay `POST /v1/drops` includes `X-Hyphae-Public-Key: <signing_jwk().x>`
    //     for public Cloudflare Worker (`spore.hyphae.to`) open-mode compatibility!
    let mock_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mock_addr = mock_listener.local_addr().unwrap();
    let expected_pubkey_x = node.identity().signing_jwk().x;
    let captured_headers: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));
    let cap_clone = Arc::clone(&captured_headers);
    let mock_server = tokio::spawn(async move {
        if let Ok((mut stream, _)) = mock_listener.accept().await {
            let mut buf = vec![0u8; 8192];
            let n = stream.read(&mut buf).await.unwrap_or(0);
            let req_text = String::from_utf8_lossy(&buf[..n]).to_string();
            *cap_clone.lock().unwrap() = req_text;
            let body = serde_json::to_string(&json!({
                "dropId": "drp-mock-01",
                "postCap": "hdcap1_post_mock",
                "subCap": "hdcap1_sub_mock",
                "expiresAtMs": now_ms() + 300_000,
                "maxPayloadBytes": 65536,
                "maxItems": 4
            }))
            .unwrap();
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(resp.as_bytes()).await;
            let _ = stream.shutdown().await;
        }
    });

    let (ext_txt, ext_err) = client
        .call_verified_claude(
            &sock,
            "deploy-s1",
            "hyp_mesh",
            json!({
                "action": "drop_link",
                "kind": "directive",
                "relay": format!("http://{mock_addr}")
            }),
        )
        .await;
    assert!(!ext_err, "external relay drop_link failed: {ext_txt}");
    let _ = tokio::time::timeout(Duration::from_secs(2), mock_server).await;
    let raw_req = captured_headers.lock().unwrap().clone();
    let raw_req_lower = raw_req.to_ascii_lowercase();
    assert!(
        raw_req_lower.contains("authorization: hyphae-ed25519 "),
        "external relay POST must send Hyphae-Ed25519 Authorization header: {raw_req}"
    );
    assert!(
        raw_req_lower.contains(&format!(
            "x-hyphae-public-key: {}",
            expected_pubkey_x.to_ascii_lowercase()
        )),
        "external relay POST must send X-Hyphae-Public-Key header matching signing_jwk().x ({expected_pubkey_x}): {raw_req}"
    );

    client.close().await;
    daemon.stop().await;
    node.shutdown();

    // 4e. Fail-closed guard: authority WITHOUT `enc_jwk_json` MUST fail closed (NEVER downgrade!)
    let dir_no_enc = TempDir::new().unwrap();
    let node_no_enc = open_local_node("no-enc@box", dir_no_enc.path());
    let legacy_human = Ed25519KeyPair::generate().unwrap();
    {
        let db = node_no_enc.db();
        db.human()
            .upsert_authority(
                &HumanAuthorityInput {
                    human_id: "legacy@phone".to_string(),
                    kid: legacy_human.kid(),
                    label: "Ed25519-only Key".to_string(),
                    role: HumanAuthorityRole::Admin,
                    jwk_json: serde_json::to_string(&legacy_human.to_jwk()).unwrap(),
                    enc_jwk_json: None,
                    prf_salt: None,
                    auth_epoch: 1,
                },
                now_ms(),
            )
            .unwrap();
    }

    let daemon_no_enc =
        LocalDaemon::start(Arc::clone(&node_no_enc), None, LocalDaemonConfig::default())
            .await
            .expect("start no-enc daemon");
    let sock_no_enc = daemon_no_enc.socket_path().to_path_buf();
    let mut no_enc_opts = McpOptions::new(sock_no_enc.clone());
    no_enc_opts.backend = Some(HarnessKind::Claude);
    let mut no_enc_client = TestMcpClient::spawn(no_enc_opts);
    no_enc_client.initialize().await;

    let (missing_txt, missing_err) = no_enc_client
        .call_verified_claude(
            &sock_no_enc,
            "noenc-s1",
            "hyp_mesh",
            json!({
                "action": "drop_link",
                "kind": "directive",
                "draft": "Must NEVER downgrade to plaintext"
            }),
        )
        .await;
    assert!(
        missing_err,
        "missing enc_jwk_json MUST fail closed, never downgrade: {missing_txt}"
    );
    assert!(
        missing_txt.contains("human_enc_key_missing")
            && missing_txt.contains("X25519")
            && !missing_txt.contains("https://hyphae.to/drop"),
        "expected human_enc_key_missing error without URL, got: {missing_txt}"
    );

    // Omitting `draft` on the same Ed25519-only authority still works cleanly for fresh input!
    let (fresh_txt, fresh_err) = no_enc_client
        .call_verified_claude(
            &sock_no_enc,
            "noenc-s1",
            "hyp_mesh",
            json!({
                "action": "drop_link",
                "kind": "directive"
            }),
        )
        .await;
    assert!(
        !fresh_err,
        "fresh directive drop_link without draft failed: {fresh_txt}"
    );
    let fresh_val: Value = serde_json::from_str(&fresh_txt).unwrap();
    assert_eq!(fresh_val["hasEncryptedDraft"], json!(false));

    no_enc_client.close().await;
    daemon_no_enc.stop().await;
    node_no_enc.shutdown();
}

// =========================================================================
// Test 5: `hyp_mesh({ action: "drop_link" })` Secret Roundtrip + Zero-Leak
//         + Burn + Offline Fallback + IPC `drop.ingest`
// =========================================================================

fn assert_zero_bytes_in_sqlite_files(state_dir: &Path, needle: &str) {
    let needle_bytes = needle.as_bytes();
    for name in ["node.sqlite", "node.sqlite-wal", "node.sqlite-shm"] {
        let p = state_dir.join(name);
        if p.exists() {
            let bytes = fs::read(&p).expect("read sqlite file");
            assert!(
                !bytes.windows(needle_bytes.len()).any(|w| w == needle_bytes),
                "ZERO-LEAK VIOLATION: secret found in {}",
                p.display()
            );
        }
    }
}

#[tokio::test]
async fn test_mesh_drop_link_secret_zero_leak_and_burn() {
    let dir = TempDir::new().unwrap();
    let mut node_cfg = NodeConfig::router(NodeId::new("drop-e2e@box").unwrap(), dir.path());
    node_cfg.secret_backend = Some(SecretBackend::File);
    node_cfg.drop_relay = DropRelayConfig {
        enabled: true,
        ..DropRelayConfig::default()
    };
    let node = UnifiedNode::open(node_cfg).expect("open UnifiedNode");
    let (http_addr, _server_handle) = Arc::clone(&node)
        .serve("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .await
        .expect("bind drop relay HTTP server");

    // Enroll an active human admin authority + sign & persist a NodeCertV1 (`hcert1_`).
    let human_admin = Ed25519KeyPair::generate().unwrap();
    let human_id = "bogdan@phone";
    {
        let db = node.db();
        db.human()
            .upsert_authority(
                &HumanAuthorityInput {
                    human_id: human_id.to_string(),
                    kid: human_admin.kid(),
                    label: "iPhone Passkey".to_string(),
                    role: HumanAuthorityRole::Admin,
                    jwk_json: serde_json::to_string(&human_admin.to_jwk()).unwrap(),
                    enc_jwk_json: None,
                    prf_salt: Some("salt-e2e-01".to_string()),
                    auth_epoch: 1,
                },
                now_ms(),
            )
            .unwrap();
    }
    let (_, expected_hcert1) = node
        .issue_node_cert(&human_admin, &human_admin.kid(), 30)
        .expect("issue NodeCertV1");

    let daemon = LocalDaemon::start(Arc::clone(&node), None, LocalDaemonConfig::default())
        .await
        .expect("start LocalDaemon");
    let sock = daemon.socket_path().to_path_buf();

    let mut client_opts = McpOptions::new(sock.clone());
    client_opts.backend = Some(HarnessKind::Claude);
    let mut client = TestMcpClient::spawn(client_opts);
    client.initialize().await;

    let (_, join_err) = client
        .call_verified_claude(
            &sock,
            "ops-s1",
            "hyp_mesh",
            json!({ "action": "join", "handle": "ops" }),
        )
        .await;
    assert!(!join_err);
    let sid = "claude:ops-s1";

    // 1. Fail-closed guards: reserved secret names & insecure remote http:// relay MUST fail!
    for reserved in [
        "gate-policy-hmac-key",
        "node-sign-primary",
        "human-admin-root",
    ] {
        let (err_txt, is_err) = client
            .call_verified_claude(
                &sock,
                "ops-s1",
                "hyp_mesh",
                json!({
                    "action": "drop_link",
                    "kind": "secret",
                    "secretName": reserved
                }),
            )
            .await;
        assert!(
            is_err,
            "reserved secret '{reserved}' must fail closed: {err_txt}"
        );
        assert!(
            err_txt.to_ascii_lowercase().contains("reserved"),
            "expected reserved error for '{reserved}', got: {err_txt}"
        );
    }

    let (bad_relay_txt, bad_relay_err) = client
        .call_verified_claude(
            &sock,
            "ops-s1",
            "hyp_mesh",
            json!({
                "action": "drop_link",
                "kind": "directive",
                "relay": "http://evil.example.com"
            }),
        )
        .await;
    assert!(
        bad_relay_err,
        "remote http:// relay must fail closed: {bad_relay_txt}"
    );

    // 2. Request a Verified Secret Drop link via `hyp_mesh({ action: "drop_link" })`.
    let (link_txt, link_err) = client
        .call_verified_claude(
            &sock,
            "ops-s1",
            "hyp_mesh",
            json!({
                "action": "drop_link",
                "kind": "secret",
                "secretName": "prod-api-key"
            }),
        )
        .await;
    assert!(!link_err, "drop_link failed: {link_txt}");
    let link_val: Value = serde_json::from_str(&link_txt).unwrap();
    assert_eq!(link_val["ok"], json!(true));
    assert_eq!(link_val["offline"], json!(false));
    assert_eq!(link_val["kind"], "secret");
    assert_eq!(link_val["secretName"], "prod-api-key");
    assert_eq!(link_val["handle"], "ops");
    assert_eq!(link_val["hasNodeCert"], json!(true));
    assert_eq!(link_val["hasEncryptedDraft"], json!(false));

    // Parse the returned `https://hyphae.to/drop#drop=<base64url>` URL matching `site/drop/drop.js`!
    let url = link_val["url"].as_str().expect("drop URL");
    let frag_b64 = url
        .strip_prefix("https://hyphae.to/drop#drop=")
        .expect("URL must start with https://hyphae.to/drop#drop=");
    let frag_bytes = URL_SAFE_NO_PAD
        .decode(frag_b64)
        .expect("valid base64url fragment");
    let frag: Value = serde_json::from_slice(&frag_bytes).expect("valid JSON fragment");

    assert_eq!(frag["v"], json!(1));
    assert_eq!(frag["kind"], "secret");
    assert_eq!(frag["secretName"], "prod-api-key");
    assert_eq!(frag["nodeId"], "drop-e2e@box");
    assert_eq!(frag["handle"], "ops");
    assert_eq!(frag["encJwk"]["kty"], "OKP");
    assert_eq!(frag["encJwk"]["crv"], "X25519");
    assert_eq!(frag["encJwk"]["x"], node.identity().encryption_jwk().x);
    assert_eq!(frag["relay"], format!("http://{http_addr}"));
    assert_eq!(frag["humanId"], human_id);
    assert_eq!(frag["prfSalt"], "salt-e2e-01");
    assert_eq!(frag["authEpoch"], json!(1));
    assert!(frag["expiresAt"].as_str().is_some_and(|s| !s.is_empty()));
    assert!(
        frag.get("proposedText").is_none()
            && frag.get("body").is_none()
            && frag.get("encDraft").is_none(),
        "secret drop fragment MUST NEVER contain proposedText, body, or encDraft"
    );

    let frag_cert = frag["nodeCert"].as_str().expect("nodeCert in fragment");
    assert_eq!(frag_cert, expected_hcert1);
    let decoded_cert = decode_hcert1(frag_cert).expect("decode hcert1_");
    let verified_cert = verify_node_cert(&decoded_cert, &human_admin.public_key(), now_ms(), 1)
        .expect("verify NodeCertV1");
    assert_eq!(verified_cert.node_id, "drop-e2e@box");

    let relay_url = frag["relay"].as_str().unwrap();
    let drop_id = frag["dropId"].as_str().unwrap();
    let post_cap = frag["postCap"].as_str().unwrap();
    assert!(!drop_id.is_empty());
    assert!(post_cap.starts_with("hdcap1_"));

    // 3. Seal a secret HumanDropEnvelopeV1 and POST it to `<relay>/v1/drops/<dropId>` with `postCap`.
    let secret_canary = "sk-live-super-secret-xyz-999";
    let now = now_ms();
    let claim = HumanClaimV1 {
        v: 1,
        kind: HumanDropKind::Secret,
        claim_id: format!("clm-{}", uuid_v4()),
        human_id: human_id.to_string(),
        human_kid: human_admin.kid(),
        auth_epoch: 1,
        issued_at: format_rfc3339_millis(now),
        expires_at: format_rfc3339_millis(now + 300_000),
        drop_id: drop_id.to_string(),
        audience: HumanAudience {
            node_id: "drop-e2e@box".to_string(),
            node_enc_kid: node.identity().encryption.kid(),
            handle: Some("ops".to_string()),
        },
        secret_spec: Some(SecretDropSpec {
            name: "prod-api-key".to_string(),
            overwrite: false,
        }),
        body: secret_canary.to_string(),
    };
    let envelope = seal_human_drop(
        &claim,
        &human_admin,
        &node.identity().encryption.public_key(),
    )
    .expect("seal secret drop");
    let body_json = to_canonical_json(&envelope).unwrap();

    let http_client = HttpClient::new().unwrap();
    let post_req = Request::builder()
        .method(Method::POST)
        .uri(format!("{relay_url}/v1/drops/{drop_id}"))
        .header(CONTENT_TYPE, "application/json")
        .header(DROP_CAP_HEADER, post_cap)
        .body(full_body(body_json.into_bytes()))
        .unwrap();
    let (status, _, _) = HttpClient::collect(
        http_client.request(post_req).await.expect("POST drop"),
        64 * 1024,
    )
    .await
    .unwrap();
    assert!(
        status == StatusCode::OK || status == StatusCode::CREATED || status == StatusCode::ACCEPTED,
        "unexpected POST /v1/drops status: {status}"
    );

    // 4. Bounded wait (up to 3s) for background watcher to ingest secret & burn relay RAM.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        let secret_ready = node.secret_store().get("prod-api-key").is_ok();
        let burned = node.drop_relay().health(now_ms()).buffered_bytes == 0;
        let has_notice = !node.db().local().peek_inbox(sid, 10).unwrap().is_empty();
        if secret_ready && burned && has_notice {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for drop ingestion & burn (secret_ready={secret_ready}, burned={burned}, has_notice={has_notice})"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    // 5. Assert SecretStore value, ZERO leak in SQLite & mailbox, metadata-only notice, and RAM burn!
    assert_eq!(
        node.secret_store().get("prod-api-key").unwrap().as_str(),
        secret_canary
    );
    assert_zero_bytes_in_sqlite_files(dir.path(), secret_canary);

    let mailbox = node.db().local().peek_inbox(sid, 10).unwrap();
    assert_eq!(mailbox.len(), 1);
    assert!(
        !mailbox[0].text.contains(secret_canary),
        "ZERO-LEAK VIOLATION: secret value appeared in session mailbox!"
    );
    assert!(
        mailbox[0].text.contains("prod-api-key"),
        "expected metadata-only notice referencing prod-api-key, got: {}",
        mailbox[0].text
    );

    let audits = node
        .db()
        .local()
        .query_gate_audit(&GateAuditQuery {
            session_id: Some(sid.to_string()),
            limit: Some(10),
            ..Default::default()
        })
        .unwrap();
    assert!(
        audits
            .iter()
            .any(|a| a.event_type.as_deref() == Some(TYPE_HUMAN_SECRET_STORED_V1)),
        "expected audit record for {TYPE_HUMAN_SECRET_STORED_V1}"
    );

    assert_eq!(
        node.drop_relay().health(now_ms()).buffered_bytes,
        0,
        "drop relay RAM buffer must be burned immediately on ingest"
    );

    // 6. Verify IPC `drop.ingest` ingests an offline `hdrop1_` directive cleanly!
    let now2 = now_ms();
    let dir_claim = HumanClaimV1 {
        v: 1,
        kind: HumanDropKind::Directive,
        claim_id: format!("clm-{}", uuid_v4()),
        human_id: human_id.to_string(),
        human_kid: human_admin.kid(),
        auth_epoch: 1,
        issued_at: format_rfc3339_millis(now2),
        expires_at: format_rfc3339_millis(now2 + 300_000),
        drop_id: String::new(),
        audience: HumanAudience {
            node_id: "drop-e2e@box".to_string(),
            node_enc_kid: node.identity().encryption.kid(),
            handle: Some("ops".to_string()),
        },
        secret_spec: None,
        body: "Proceed with production rollout v0.5.0".to_string(),
    };
    let dir_env = seal_human_drop(
        &dir_claim,
        &human_admin,
        &node.identity().encryption.public_key(),
    )
    .expect("seal directive");
    let hdrop1 = encode_hdrop1(&dir_env).unwrap();
    let ingest_res = rpc(
        &sock,
        &json!({
            "type": "drop.ingest",
            "token": hdrop1
        }),
    )
    .await;
    assert!(
        ingest_res.ok,
        "drop.ingest IPC failed: {:?}",
        ingest_res.error
    );
    let ingested = ingest_res.result.unwrap();
    assert_eq!(ingested["kind"], "directive");
    assert_eq!(ingested["humanId"], human_id);

    client.close().await;
    daemon.stop().await;
    node.shutdown();

    // 7. Verify offline fallback when local drop_relay is disabled and no drop_relay_url is set.
    let dir_off = TempDir::new().unwrap();
    let node_off = open_local_node("offline-drop@box", dir_off.path());
    let daemon_off = LocalDaemon::start(Arc::clone(&node_off), None, LocalDaemonConfig::default())
        .await
        .expect("start offline daemon");
    let sock_off = daemon_off.socket_path().to_path_buf();
    let mut off_opts = McpOptions::new(sock_off.clone());
    off_opts.backend = Some(HarnessKind::Claude);
    let mut off_client = TestMcpClient::spawn(off_opts);
    off_client.initialize().await;

    let (off_txt, off_err) = off_client
        .call_verified_claude(
            &sock_off,
            "off-s1",
            "hyp_mesh",
            json!({ "action": "drop_link", "kind": "directive" }),
        )
        .await;
    assert!(!off_err, "offline drop_link failed: {off_txt}");
    let off_val: Value = serde_json::from_str(&off_txt).unwrap();
    assert_eq!(off_val["ok"], json!(true));
    assert_eq!(off_val["offline"], json!(true));
    let off_url = off_val["url"].as_str().unwrap();
    let off_b64 = off_url
        .strip_prefix("https://hyphae.to/drop#drop=")
        .unwrap();
    let off_frag: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(off_b64).unwrap()).unwrap();
    assert_eq!(off_frag["v"], json!(1));
    assert_eq!(off_frag["nodeId"], "offline-drop@box");
    assert_eq!(off_frag["kind"], "directive");
    assert!(off_frag.get("relay").is_none());
    assert!(off_frag.get("proposedText").is_none());

    off_client.close().await;
    daemon_off.stop().await;
    node_off.shutdown();
}

// =========================================================================
// Test 6 (#[cfg(unix)]): Tier 4 Allowlisted Herdr Cold-Spawn & Mutated Security Guards
// =========================================================================

#[cfg(unix)]
mod unix_tier4_tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    use hyp_harness::transport::herdr::{DEFAULT_SPAWN_TIMEOUT, spawn_herdr_template};

    use super::*;

    struct FakeHcSpawn {
        _dir: TempDir,
        bin_path: PathBuf,
        state_dir: PathBuf,
        calls_dir: PathBuf,
    }

    impl FakeHcSpawn {
        fn new() -> Self {
            let dir = TempDir::new().unwrap();
            let state_dir = dir.path().join("state");
            let calls_dir = dir.path().join("calls");
            fs::create_dir_all(&state_dir).unwrap();
            fs::create_dir_all(&calls_dir).unwrap();

            let script = format!(
                r#"#!/bin/sh
set -eu
STATE_DIR="{state}"
CALLS_DIR="{calls}"

N=0
if [ -f "$CALLS_DIR/count" ]; then
  N=$(cat "$CALLS_DIR/count")
fi
N=$((N + 1))
printf '%s' "$N" > "$CALLS_DIR/count"

I=0
for arg in "$@"; do
  printf '%s' "$arg" > "$CALLS_DIR/call_${{N}}_arg_${{I}}.txt"
  I=$((I + 1))
done
printf '%s' "$I" > "$CALLS_DIR/call_${{N}}_argc"

if [ -f "$STATE_DIR/sleep_ms" ]; then
  sleep 0.25
fi
exit 0
"#,
                state = state_dir.display(),
                calls = calls_dir.display(),
            );

            let tmp_path = dir.path().join("hc.tmp");
            let bin_path = dir.path().join("hc");
            fs::write(&tmp_path, script).unwrap();
            fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o755)).unwrap();
            fs::rename(&tmp_path, &bin_path).unwrap();

            Self {
                _dir: dir,
                bin_path,
                state_dir,
                calls_dir,
            }
        }

        fn bin(&self) -> String {
            self.bin_path.to_string_lossy().to_string()
        }

        fn call_count(&self) -> usize {
            fs::read_to_string(self.calls_dir.join("count"))
                .ok()
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(0)
        }

        fn call_args(&self, call_num: usize) -> Vec<String> {
            let argc: usize =
                fs::read_to_string(self.calls_dir.join(format!("call_{call_num}_argc")))
                    .unwrap()
                    .trim()
                    .parse()
                    .unwrap();
            (0..argc)
                .map(|i| {
                    fs::read_to_string(self.calls_dir.join(format!("call_{call_num}_arg_{i}.txt")))
                        .unwrap()
                })
                .collect()
        }

        fn set_slow(&self, enabled: bool) {
            let p = self.state_dir.join("sleep_ms");
            if enabled {
                fs::write(p, "250").unwrap();
            } else {
                let _ = fs::remove_file(p);
            }
        }
    }

    #[tokio::test]
    async fn test_tier4_allowlisted_herdr_cold_spawn_and_mutated_security_guards() {
        let fake_hc = FakeHcSpawn::new();
        let dir = TempDir::new().unwrap();
        let node = open_local_node("tier4@box", dir.path());

        let cfg = LocalDaemonConfig {
            herdr_bin: Some(fake_hc.bin()),
            delivery_retry: DeliveryRetryConfig {
                herdr_spawn_allowlist: vec!["ci-triage".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let daemon = LocalDaemon::start(Arc::clone(&node), None, cfg)
            .await
            .expect("start tier4 daemon");

        let prompt = format!("{UNTRUSTED_PROVENANCE}\nInvestigate failed workflow on main");

        // 6a: Allowlisted template invokes `hc run ci-triage <prompt>` cleanly!
        let out = daemon
            .try_herdr_cold_spawn("wk-ci-triage", "ci-triage", &prompt)
            .await;
        assert_eq!(out, PushOutcome::Delivered);
        assert_eq!(fake_hc.call_count(), 1);
        let args = fake_hc.call_args(1);
        assert_eq!(args.len(), 3);
        assert_eq!(args[0], "run");
        assert_eq!(args[1], "ci-triage");
        assert!(args[2].starts_with(UNTRUSTED_PROVENANCE));
        assert!(args[2].contains("Investigate failed workflow on main"));

        // 6b: `maxConcurrentSpawns: 1` blocks overlapping spawns for the SAME key!
        fake_hc.set_slow(true);
        let (r1, r2) = tokio::join!(
            daemon.try_herdr_cold_spawn("wk-ci-triage", "ci-triage", &prompt),
            daemon.try_herdr_cold_spawn("wk-ci-triage", "ci-triage", &prompt),
        );
        let outcomes = [r1, r2];
        assert!(
            outcomes.contains(&PushOutcome::Delivered)
                && outcomes.contains(&PushOutcome::hold("herdr_spawn_already_active")),
            "exactly one concurrent spawn may succeed (maxConcurrentSpawns: 1), got {outcomes:?}"
        );
        assert_eq!(
            fake_hc.call_count(),
            2,
            "concurrency guard must prevent second overlapping hc process"
        );
        fake_hc.set_slow(false);

        // 6c: Mutated Security Guards — non-allowlisted template, `--flag`, shell metacharacters, NUL prompt!
        let rejected = daemon
            .try_herdr_cold_spawn("wk-ci-triage", "unlisted-template", &prompt)
            .await;
        assert_eq!(
            rejected,
            PushOutcome::reject("herdr_template_not_allowlisted"),
            "non-allowlisted template must fail closed"
        );

        let hostile_allowlist = vec![
            "ci-triage".to_string(),
            "--flag".to_string(),
            "ci;rm -rf /".to_string(),
            "ci$(id)".to_string(),
            "ci`id`".to_string(),
        ];
        for bad_tpl in ["unlisted", "--flag", "ci;rm -rf /", "ci$(id)", "ci`id`"] {
            let out = spawn_herdr_template(
                &fake_hc.bin(),
                bad_tpl,
                "Check CI",
                &hostile_allowlist,
                DEFAULT_SPAWN_TIMEOUT,
            )
            .await;
            assert_eq!(
                out,
                PushOutcome::reject("herdr_template_not_allowlisted"),
                "mutated template {bad_tpl:?} must fail closed"
            );
        }

        let nul_out = spawn_herdr_template(
            &fake_hc.bin(),
            "ci-triage",
            "Check CI\0injected",
            &hostile_allowlist,
            DEFAULT_SPAWN_TIMEOUT,
        )
        .await;
        assert_eq!(nul_out, PushOutcome::reject("herdr_invalid_prompt"));

        // Verify ZERO additional `hc` subprocesses were spawned by any rejected guard test!
        assert_eq!(
            fake_hc.call_count(),
            2,
            "all mutated security guard rejections must fail closed BEFORE spawning hc"
        );

        daemon.stop().await;
        node.shutdown();
    }
}

// =========================================================================
// Test 7: Unified Hook State Machine (Interrupt MidTurn + Grace Fallback,
//         Queue TurnEnd + Lease Fallback, OpenClaw agent_end, Notify Passive)
// =========================================================================

struct NudgeRecordingTransport {
    kind: &'static str,
    supports_interrupt: bool,
    nudges: Arc<Mutex<Vec<(PushMode, String)>>>,
}

impl NudgeRecordingTransport {
    fn new(kind: &'static str, supports_interrupt: bool) -> Self {
        Self {
            kind,
            supports_interrupt,
            nudges: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn take(&self) -> Vec<(PushMode, String)> {
        std::mem::take(&mut *self.nudges.lock().unwrap())
    }
}

impl PushTransport for NudgeRecordingTransport {
    fn kind(&self) -> &'static str {
        self.kind
    }

    fn supports_interrupt(&self) -> bool {
        self.supports_interrupt
    }

    fn is_nudge_only(&self) -> bool {
        true
    }

    fn deliver<'a>(&'a self, text: &'a str, mode: PushMode) -> TransportFuture<'a, PushOutcome> {
        let nudges = Arc::clone(&self.nudges);
        let msg = text.to_string();
        Box::pin(async move {
            nudges.lock().unwrap().push((mode, msg));
            PushOutcome::delivered()
        })
    }

    fn deliver_nudge<'a>(
        &'a self,
        message_count: usize,
        handle: Option<&'a str>,
        _batch_id: &'a str,
        mode: PushMode,
    ) -> TransportFuture<'a, PushOutcome> {
        let nudges = Arc::clone(&self.nudges);
        let msg = hyp_harness::transport::format_push_wake_nudge(message_count, handle, mode);
        Box::pin(async move {
            nudges.lock().unwrap().push((mode, msg));
            PushOutcome::delivered()
        })
    }
}

#[tokio::test]
async fn test7_unified_hook_state_machine_interrupt_queue_notify_and_activity_leases() {
    let dir = TempDir::new().unwrap();
    let node = open_local_node("fsm@box", dir.path());
    let cfg = LocalDaemonConfig {
        interrupt_hook_grace: Duration::from_millis(90),
        queue_activity_lease: Duration::from_millis(180),
        ..Default::default()
    };
    let daemon = LocalDaemon::start(Arc::clone(&node), None, cfg)
        .await
        .expect("start daemon");
    let sock = daemon.socket_path().to_path_buf();

    let run_h = |harness: HarnessKind, event: HookEvent, payload: Value| {
        let sock_c = sock.clone();
        async move {
            tokio::task::spawn_blocking(move || {
                handle_hook_payload(
                    payload.as_object().unwrap(),
                    &hook_opts(harness, event, &sock_c),
                )
            })
            .await
            .unwrap()
        }
    };

    // Register Claude session `@worker` with VIP `@vip` -> interrupt, `@fyi` -> notify.
    let sid = "claude:fsm-1";
    node.register_session(sid, "{\"kind\":\"claude\"}").unwrap();
    node.db()
        .local()
        .set_session_handle(sid, Some("worker"), now_ms())
        .unwrap();
    {
        let db = node.db();
        let mut pol = daemon.delivery().policy(&db, sid).unwrap();
        pol.overrides = vec![
            hyp_node::delivery::DeliveryRule {
                target: "peer@net/vip".into(),
                delivery: hyp_node::delivery::DeliveryUrgency::Interrupt,
            },
            hyp_node::delivery::DeliveryRule {
                target: "peer@net/fyi".into(),
                delivery: hyp_node::delivery::DeliveryUrgency::Notify,
            },
        ];
        daemon.delivery().set_policy(&db, sid, pol).unwrap();
    }

    let nudge_xport = Arc::new(NudgeRecordingTransport::new("herdr", true));
    daemon.register_session_transport(sid, Arc::clone(&nudge_xport) as Arc<dyn PushTransport>);

    // 1. ACTIVE + INTERRUPT drained by PostToolUse within 90ms grace -> ZERO L2 nudges!
    let _ = run_h(
        HarnessKind::Claude,
        HookEvent::PreInvocation,
        json!({ "session_id": "fsm-1" }),
    )
    .await;
    daemon
        .ingest_inbound(InboundItem {
            session_id: sid.into(),
            origin_node: "peer@net".into(),
            item_id: "fsm-int-hook".into(),
            source: "peer@net/vip".into(),
            text: "URGENT_VIA_POST_TOOL".into(),
            kind: MailboxKind::Message,
            trust_tier: GateTrustTier::Peer,
        })
        .await
        .unwrap();
    assert!(
        nudge_xport.take().is_empty(),
        "Active session must defer Interrupt nudge during tool-hook grace"
    );
    let post_int = run_h(
        HarnessKind::Claude,
        HookEvent::PostToolUse,
        json!({ "session_id": "fsm-1", "tool_name": "Bash", "tool_use_id": "t1" }),
    )
    .await;
    assert!(
        post_int.to_string().contains("URGENT_VIA_POST_TOOL"),
        "PostToolUse must drain Interrupt mid-turn: {post_int}"
    );
    tokio::time::sleep(Duration::from_millis(130)).await;
    assert!(
        nudge_xport.take().is_empty(),
        "PostToolUse drain must cancel Interrupt grace fallback (0 nudges)"
    );

    // 2. ACTIVE + INTERRUPT with NO PostToolUse -> grace expires (90ms) -> falls back to XML Interrupt nudge!
    let _ = run_h(
        HarnessKind::Claude,
        HookEvent::PreInvocation,
        json!({ "session_id": "fsm-1" }),
    )
    .await;
    daemon
        .ingest_inbound(InboundItem {
            session_id: sid.into(),
            origin_node: "peer@net".into(),
            item_id: "fsm-int-fallback".into(),
            source: "peer@net/vip".into(),
            text: "URGENT_FALLBACK_BODY".into(),
            kind: MailboxKind::Message,
            trust_tier: GateTrustTier::Peer,
        })
        .await
        .unwrap();
    assert!(nudge_xport.take().is_empty());
    tokio::time::sleep(Duration::from_millis(140)).await;
    let int_nudges = nudge_xport.take();
    assert_eq!(
        int_nudges.len(),
        1,
        "Interrupt grace expiry must fire L2 fallback"
    );
    assert_eq!(int_nudges[0].0, PushMode::Interrupt);
    assert!(
        int_nudges[0]
            .1
            .starts_with("<hyphae-wake count=\"1\" handle=\"worker\" urgency=\"interrupt\">")
    );
    assert!(!int_nudges[0].1.contains("URGENT_FALLBACK_BODY"));

    // TurnStart (`UserPromptSubmit`) drains the `NudgePending` Interrupt cleanly -> 0 unread!
    let pre_nudge = run_h(
        HarnessKind::Claude,
        HookEvent::PreInvocation,
        json!({ "session_id": "fsm-1" }),
    )
    .await;
    assert!(
        pre_nudge.to_string().contains("URGENT_FALLBACK_BODY"),
        "TurnStart must drain NudgePending item: {pre_nudge}"
    );
    assert_eq!(node.db().local().pending_count(sid).unwrap(), 0);

    // 3. ACTIVE + QUEUE held across PostToolUse -> drained cleanly by TurnEnd (`Stop`) with 0 nudges!
    daemon
        .ingest_inbound(InboundItem {
            session_id: sid.into(),
            origin_node: "peer@net".into(),
            item_id: "fsm-q-stop".into(),
            source: "peer@net/dev".into(),
            text: "QUEUED_FOR_TURN_END".into(),
            kind: MailboxKind::Message,
            trust_tier: GateTrustTier::Peer,
        })
        .await
        .unwrap();
    let post_q = run_h(
        HarnessKind::Claude,
        HookEvent::PostToolUse,
        json!({ "session_id": "fsm-1", "tool_name": "Read", "tool_use_id": "t2" }),
    )
    .await;
    assert_eq!(post_q, json!({}), "PostToolUse must hold Queue DM mid-turn");
    assert!(
        nudge_xport.take().is_empty(),
        "Active lease must defer Queue nudge"
    );
    let stop_q = run_h(
        HarnessKind::Claude,
        HookEvent::Stop,
        json!({ "session_id": "fsm-1" }),
    )
    .await;
    assert!(
        stop_q.to_string().contains("QUEUED_FOR_TURN_END"),
        "Stop TurnEnd must drain held Queue DM: {stop_q}"
    );
    assert_eq!(node.db().local().pending_count(sid).unwrap(), 0);
    tokio::time::sleep(Duration::from_millis(220)).await;
    assert!(
        nudge_xport.take().is_empty(),
        "Stop drain must leave 0 nudges"
    );

    // 4. ACTIVE + QUEUE with missed Stop -> activity lease expires (180ms) -> fires XML Queue nudge!
    let _ = run_h(
        HarnessKind::Claude,
        HookEvent::PreInvocation,
        json!({ "session_id": "fsm-1" }),
    )
    .await;
    daemon
        .ingest_inbound(InboundItem {
            session_id: sid.into(),
            origin_node: "peer@net".into(),
            item_id: "fsm-q-lease".into(),
            source: "peer@net/dev".into(),
            text: "QUEUED_LEASE_FALLBACK".into(),
            kind: MailboxKind::Message,
            trust_tier: GateTrustTier::Peer,
        })
        .await
        .unwrap();
    assert!(nudge_xport.take().is_empty());
    tokio::time::sleep(Duration::from_millis(240)).await;
    let q_nudges = nudge_xport.take();
    assert_eq!(
        q_nudges.len(),
        1,
        "Activity lease expiry must fire Queue fallback nudge"
    );
    assert_eq!(q_nudges[0].0, PushMode::Queue);
    assert!(
        q_nudges[0]
            .1
            .starts_with("<hyphae-wake count=\"1\" handle=\"worker\" urgency=\"queue\">")
    );
    // Drain it via TurnStart so inbox is clean for Notify test.
    let pre_q = run_h(
        HarnessKind::Claude,
        HookEvent::PreInvocation,
        json!({ "session_id": "fsm-1" }),
    )
    .await;
    assert!(pre_q.to_string().contains("QUEUED_LEASE_FALLBACK"));
    // End turn cleanly -> Idle.
    assert_eq!(
        run_h(
            HarnessKind::Claude,
            HookEvent::Stop,
            json!({ "session_id": "fsm-1" })
        )
        .await,
        json!({})
    );

    // 5. NOTIFY -> NEVER fires L2 nudge (even while Idle!), NEVER drains on PostToolUse,
    //    NEVER blocks Stop, surfaces 1-line digest on TurnStart (`UserPromptSubmit`)!
    daemon
        .ingest_inbound(InboundItem {
            session_id: sid.into(),
            origin_node: "peer@net".into(),
            item_id: "fsm-notify-1".into(),
            source: "peer@net/fyi".into(),
            text: "FYI_LOW_PRIORITY_SECRET_BODY".into(),
            kind: MailboxKind::Message,
            trust_tier: GateTrustTier::Peer,
        })
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert!(
        nudge_xport.take().is_empty(),
        "Notify-only FYI MUST NEVER wake idle L2 transport"
    );
    assert_eq!(
        run_h(
            HarnessKind::Claude,
            HookEvent::PostToolUse,
            json!({ "session_id": "fsm-1", "tool_name": "Read", "tool_use_id": "t3" })
        )
        .await,
        json!({}),
        "PostToolUse must stay silent on Notify"
    );
    assert_eq!(
        run_h(
            HarnessKind::Claude,
            HookEvent::Stop,
            json!({ "session_id": "fsm-1" })
        )
        .await,
        json!({}),
        "Stop must NEVER force a continuation turn for a Notify-only digest"
    );
    let pre_notify = run_h(
        HarnessKind::Claude,
        HookEvent::PreInvocation,
        json!({ "session_id": "fsm-1" }),
    )
    .await;
    let notify_ctx = pre_notify["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .expect("TurnStart must emit 1-line Notify digest");
    assert!(notify_ctx.contains("hyphae notify · 1 unread"));
    assert!(!notify_ctx.contains("FYI_LOW_PRIORITY_SECRET_BODY"));

    // 6. OpenClaw observational `agent_end` flips Active -> Idle immediately and flushes held Queue nudge!
    let oc_sid = "openclaw:oc-fsm";
    node.register_session(oc_sid, "{\"kind\":\"openclaw\"}")
        .unwrap();
    node.db()
        .local()
        .set_session_handle(oc_sid, Some("claw"), now_ms())
        .unwrap();
    let oc_xport = Arc::new(NudgeRecordingTransport::new("openclaw", false));
    daemon.register_session_transport(oc_sid, Arc::clone(&oc_xport) as Arc<dyn PushTransport>);

    // TurnStart marks OpenClaw Active (180ms lease)
    let _ = run_h(
        HarnessKind::Openclaw,
        HookEvent::PreInvocation,
        json!({ "session_id": "oc-fsm" }),
    )
    .await;
    daemon
        .ingest_inbound(InboundItem {
            session_id: oc_sid.into(),
            origin_node: "peer@net".into(),
            item_id: "oc-q-1".into(),
            source: "peer@net/dev".into(),
            text: "OPENCLAW_HELD_UNTIL_AGENT_END".into(),
            kind: MailboxKind::Message,
            trust_tier: GateTrustTier::Peer,
        })
        .await
        .unwrap();
    assert!(
        oc_xport.take().is_empty(),
        "Active OpenClaw defers Queue during turn"
    );

    // Observational `agent_end` flips Idle immediately (well before 180ms lease) and flushes!
    let end_res = run_h(
        HarnessKind::Openclaw,
        HookEvent::Stop,
        json!({ "session_id": "oc-fsm" }),
    )
    .await;
    assert_eq!(end_res, json!({}));
    let mut oc_nudges = Vec::new();
    for _ in 0..20 {
        oc_nudges = oc_xport.take();
        if !oc_nudges.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        oc_nudges.len(),
        1,
        "OpenClaw agent_end must immediately flush deferred Queue wake nudge"
    );
    assert!(
        oc_nudges[0]
            .1
            .starts_with("<hyphae-wake count=\"1\" handle=\"claw\" urgency=\"queue\">")
    );

    daemon.stop().await;
    node.shutdown();
}

// =========================================================================
// Test 8: Secret Overwrite Conflict Notice (Local + External Watchers) & `secretExists` Hint
// =========================================================================

#[tokio::test]
async fn test_drop_secret_exists_hint_and_conflict_notice_local_and_external_watchers() {
    let dir = TempDir::new().unwrap();
    let mut node_cfg = NodeConfig::router(NodeId::new("drop-conflict@box").unwrap(), dir.path());
    node_cfg.secret_backend = Some(SecretBackend::File);
    node_cfg.drop_relay = DropRelayConfig {
        enabled: true,
        ..DropRelayConfig::default()
    };
    let node = UnifiedNode::open(node_cfg).expect("open UnifiedNode");
    let (http_addr, _server_handle) = Arc::clone(&node)
        .serve("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .await
        .expect("bind local drop relay HTTP server");

    // Enroll an active human admin authority + issue NodeCertV1 (`hcert1_`).
    let human_admin = Ed25519KeyPair::generate().unwrap();
    let attacker_kp = Ed25519KeyPair::generate().unwrap();
    let human_id = "bogdan@phone";
    {
        let db = node.db();
        db.human()
            .upsert_authority(
                &HumanAuthorityInput {
                    human_id: human_id.to_string(),
                    kid: human_admin.kid(),
                    label: "iPhone Passkey".to_string(),
                    role: HumanAuthorityRole::Admin,
                    jwk_json: serde_json::to_string(&human_admin.to_jwk()).unwrap(),
                    enc_jwk_json: None,
                    prf_salt: Some("salt-conflict-01".to_string()),
                    auth_epoch: 1,
                },
                now_ms(),
            )
            .unwrap();
    }
    let _ = node
        .issue_node_cert(&human_admin, &human_admin.kid(), 30)
        .expect("issue NodeCertV1");

    let daemon = LocalDaemon::start(
        Arc::clone(&node),
        None,
        LocalDaemonConfig {
            drop_watcher_backoff_ms: vec![40, 80, 160],
            ..Default::default()
        },
    )
    .await
    .expect("start LocalDaemon");
    let sock = daemon.socket_path().to_path_buf();

    let mut client_opts = McpOptions::new(sock.clone());
    client_opts.backend = Some(HarnessKind::Claude);
    let mut client = TestMcpClient::spawn(client_opts);
    client.initialize().await;

    let (_, join_err) = client
        .call_verified_claude(
            &sock,
            "conflict-s1",
            "hyp_mesh",
            json!({ "action": "join", "handle": "ops" }),
        )
        .await;
    assert!(!join_err);
    let sid = "claude:conflict-s1";

    let decode_frag = |url: &str| -> Value {
        let b64 = url
            .strip_prefix("https://hyphae.to/drop#drop=")
            .expect("URL must start with https://hyphae.to/drop#drop=");
        let bytes = URL_SAFE_NO_PAD.decode(b64).expect("valid base64url");
        serde_json::from_slice(&bytes).expect("valid fragment JSON")
    };

    // 1. Before secret exists: `secretExists` is false in JSON output and omitted from URL fragment.
    let (absent_txt, absent_err) = client
        .call_verified_claude(
            &sock,
            "conflict-s1",
            "hyp_mesh",
            json!({
                "action": "drop_link",
                "kind": "secret",
                "secretName": "my-api-key"
            }),
        )
        .await;
    assert!(!absent_err, "drop_link failed: {absent_txt}");
    let absent_val: Value = serde_json::from_str(&absent_txt).unwrap();
    assert_eq!(absent_val["secretExists"], json!(false));
    let absent_frag = decode_frag(absent_val["url"].as_str().unwrap());
    assert!(
        absent_frag.get("secretExists").is_none(),
        "absent secret must omit secretExists from fragment: {absent_frag}"
    );

    // 2. Pre-seed `my-api-key` -> `secretExists: true` in both JSON output and URL fragment (zero secret leak!).
    let orig_secret = "sk-orig-secret-canary-v1";
    node.secret_store().set("my-api-key", orig_secret).unwrap();

    let (present_txt, present_err) = client
        .call_verified_claude(
            &sock,
            "conflict-s1",
            "hyp_mesh",
            json!({
                "action": "drop_link",
                "kind": "secret",
                "secretName": "my-api-key"
            }),
        )
        .await;
    assert!(!present_err, "drop_link failed: {present_txt}");
    assert!(
        !present_txt.contains(orig_secret),
        "ZERO-LEAK VIOLATION: existing secret bytes leaked into drop_link output!"
    );
    let present_val: Value = serde_json::from_str(&present_txt).unwrap();
    assert_eq!(present_val["secretExists"], json!(true));
    let present_frag = decode_frag(present_val["url"].as_str().unwrap());
    assert_eq!(present_frag["secretName"], json!("my-api-key"));
    assert_eq!(present_frag["secretExists"], json!(true));
    assert_eq!(present_frag["relay"], format!("http://{http_addr}"));

    let local_relay_url = present_frag["relay"].as_str().unwrap().to_string();
    let local_drop_id = present_frag["dropId"].as_str().unwrap().to_string();
    let local_post_cap = present_frag["postCap"].as_str().unwrap().to_string();

    let build_secret_env =
        |signer: &Ed25519KeyPair, drop_id: &str, name: &str, overwrite: bool, body: &str| {
            let now = now_ms();
            let claim = HumanClaimV1 {
                v: 1,
                kind: HumanDropKind::Secret,
                claim_id: format!("clm-{}", uuid_v4()),
                human_id: human_id.to_string(),
                human_kid: signer.kid(),
                auth_epoch: 1,
                issued_at: format_rfc3339_millis(now),
                expires_at: format_rfc3339_millis(now + 300_000),
                drop_id: drop_id.to_string(),
                audience: HumanAudience {
                    node_id: "drop-conflict@box".to_string(),
                    node_enc_kid: node.identity().encryption.kid(),
                    handle: Some("ops".to_string()),
                },
                secret_spec: Some(SecretDropSpec {
                    name: name.to_string(),
                    overwrite,
                }),
                body: body.to_string(),
            };
            seal_human_drop(&claim, signer, &node.identity().encryption.public_key())
                .expect("seal secret drop")
        };

    let http_client = HttpClient::new().unwrap();
    let post_drop_env = |relay: &str, drop_id: &str, post_cap: &str, env_json: String| {
        let client_ref = &http_client;
        let uri = format!("{relay}/v1/drops/{drop_id}");
        let cap = post_cap.to_string();
        async move {
            let req = Request::builder()
                .method(Method::POST)
                .uri(uri)
                .header(CONTENT_TYPE, "application/json")
                .header(DROP_CAP_HEADER, cap)
                .body(full_body(env_json.into_bytes()))
                .unwrap();
            let (status, _, _) =
                HttpClient::collect(client_ref.request(req).await.expect("POST drop"), 64 * 1024)
                    .await
                    .unwrap();
            assert!(
                status == StatusCode::OK
                    || status == StatusCode::CREATED
                    || status == StatusCode::ACCEPTED,
                "unexpected POST /v1/drops status: {status}"
            );
        }
    };

    // 3a. Local watcher: unauthenticated forged envelope MUST NOT spam a conflict notice!
    let forged_env = build_secret_env(
        &attacker_kp,
        &local_drop_id,
        "my-api-key",
        false,
        "forged-junk-secret",
    );
    post_drop_env(
        &local_relay_url,
        &local_drop_id,
        &local_post_cap,
        to_canonical_json(&forged_env).unwrap(),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(120)).await;
    assert!(
        node.db().local().peek_inbox(sid, 10).unwrap().is_empty(),
        "forged/unauthenticated envelope MUST NOT enqueue any notice"
    );

    // 3b. Local watcher: valid human-signed drop with overwrite=false triggers metadata-only conflict notice!
    let blocked_secret = "sk-blocked-overwrite-false-canary-v2";
    let conflict_env = build_secret_env(
        &human_admin,
        &local_drop_id,
        "my-api-key",
        false,
        blocked_secret,
    );
    post_drop_env(
        &local_relay_url,
        &local_drop_id,
        &local_post_cap,
        to_canonical_json(&conflict_env).unwrap(),
    )
    .await;

    let conflict_deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    let conflict_box = loop {
        let items = node.db().local().peek_inbox(sid, 10).unwrap();
        if !items.is_empty() {
            break items;
        }
        assert!(
            tokio::time::Instant::now() < conflict_deadline,
            "timed out waiting for local watcher secret conflict notice"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    };
    assert_eq!(conflict_box.len(), 1);
    assert!(conflict_box[0].text.contains("[hyphae notice]"));
    assert!(conflict_box[0].text.contains(&local_drop_id));
    assert!(conflict_box[0].text.contains("my-api-key"));
    assert!(conflict_box[0].text.contains("Overwrite"));
    assert!(!conflict_box[0].text.contains(orig_secret));
    assert!(!conflict_box[0].text.contains(blocked_secret));
    assert_eq!(
        node.secret_store().get("my-api-key").unwrap().as_str(),
        orig_secret,
        "overwrite=false MUST NOT overwrite existing secret"
    );
    assert_zero_bytes_in_sqlite_files(dir.path(), blocked_secret);

    // 3c. Local watcher MUST remain alive so resubmitting with overwrite=true succeeds on the same drop!
    let updated_secret = "sk-updated-overwrite-true-canary-v3";
    let overwrite_env = build_secret_env(
        &human_admin,
        &local_drop_id,
        "my-api-key",
        true,
        updated_secret,
    );
    post_drop_env(
        &local_relay_url,
        &local_drop_id,
        &local_post_cap,
        to_canonical_json(&overwrite_env).unwrap(),
    )
    .await;

    let overwrite_deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        let val_ok = node
            .secret_store()
            .get("my-api-key")
            .ok()
            .is_some_and(|v| v.as_str() == updated_secret);
        let burned = node.drop_relay().health(now_ms()).buffered_bytes == 0;
        let items = node.db().local().peek_inbox(sid, 10).unwrap();
        if val_ok && burned && items.len() >= 2 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < overwrite_deadline,
            "timed out waiting for local watcher overwrite resubmission (val_ok={val_ok}, burned={burned}, inbox_len={})",
            items.len()
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_zero_bytes_in_sqlite_files(dir.path(), updated_secret);
    let local_items = node.db().local().peek_inbox(sid, 10).unwrap();
    assert!(
        local_items
            .iter()
            .any(|m| m.text.contains("stored in SecretStore") && m.text.contains("my-api-key")),
        "expected stored confirmation in inbox, got: {local_items:?}"
    );
    assert!(
        local_items
            .iter()
            .all(|m| !m.text.contains(updated_secret) && !m.text.contains(blocked_secret)),
        "ZERO-LEAK VIOLATION in session inbox!"
    );

    // 4. External drop watcher: junk ignored, conflict notified once (deduped by seq),
    //    watcher stays alive, overwrite=true resubmission succeeds and acks seq=3!
    let ext_orig_secret = "sk-ext-orig-canary-v1";
    let ext_blocked_secret = "sk-ext-blocked-canary-v2";
    let ext_updated_secret = "sk-ext-updated-canary-v3";
    node.secret_store()
        .set("ext-api-key", ext_orig_secret)
        .unwrap();

    let (_, join2_err) = client
        .call_verified_claude(
            &sock,
            "conflict-ext",
            "hyp_mesh",
            json!({ "action": "join", "handle": "ops-ext" }),
        )
        .await;
    assert!(!join2_err);
    let ext_sid = "claude:conflict-ext";

    let ext_drop_id = "drop_ext_conflict_01";
    let ext_forged = to_canonical_json(&build_secret_env(
        &attacker_kp,
        ext_drop_id,
        "ext-api-key",
        false,
        "ext-forged-junk",
    ))
    .unwrap();
    let ext_conflict = to_canonical_json(&build_secret_env(
        &human_admin,
        ext_drop_id,
        "ext-api-key",
        false,
        ext_blocked_secret,
    ))
    .unwrap();
    let ext_overwrite = to_canonical_json(&build_secret_env(
        &human_admin,
        ext_drop_id,
        "ext-api-key",
        true,
        ext_updated_secret,
    ))
    .unwrap();

    let send_overwrite_gate = Arc::new(Notify::new());
    let acked_seqs: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ext_relay_url = format!("http://{}", listener.local_addr().unwrap());

    let gate_srv = Arc::clone(&send_overwrite_gate);
    let acks_srv = Arc::clone(&acked_seqs);
    let srv_forged = ext_forged.clone();
    let srv_conflict = ext_conflict.clone();
    let srv_overwrite = ext_overwrite.clone();
    let ext_srv_task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let gate = Arc::clone(&gate_srv);
            let acks = Arc::clone(&acks_srv);
            let forged_s = srv_forged.clone();
            let conflict_s = srv_conflict.clone();
            let overwrite_s = srv_overwrite.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let n = stream.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);
                let first_line = req.lines().next().unwrap_or_default();
                if first_line.starts_with("POST /v1/drops ") {
                    let body = serde_json::to_string(&json!({
                        "dropId": ext_drop_id,
                        "expiresAtMs": now_ms() + 300_000,
                        "postCap": "hdcap1_ext_post",
                        "subCap": "hdcap1_ext_sub",
                        "maxPayloadBytes": 65536,
                        "maxItems": 4,
                    }))
                    .unwrap();
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                } else if first_line.starts_with(&format!("GET /v1/drops/{ext_drop_id}/stream ")) {
                    let head = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n";
                    let _ = stream.write_all(head.as_bytes()).await;
                    // 1. Forged junk (id=1), 2. Valid conflict (id=2), 3. Duplicate conflict replay (id=2).
                    let first_batch = format!(
                        "id: 1\nevent: drop\ndata: {forged_s}\n\n\
                         id: 2\nevent: drop\ndata: {conflict_s}\n\n\
                         id: 2\nevent: drop\ndata: {conflict_s}\n\n"
                    );
                    let _ = stream.write_all(first_batch.as_bytes()).await;
                    let _ = stream.flush().await;
                    // Wait for test to verify intermediate conflict state, then send overwrite=true (id=3).
                    gate.notified().await;
                    let second_batch = format!("id: 3\nevent: drop\ndata: {overwrite_s}\n\n");
                    let _ = stream.write_all(second_batch.as_bytes()).await;
                    let _ = stream.flush().await;
                    tokio::time::sleep(Duration::from_millis(500)).await;
                } else if first_line.starts_with(&format!("POST /v1/drops/{ext_drop_id}/ack ")) {
                    if let Some((_, body_part)) = req.split_once("\r\n\r\n") {
                        if let Ok(v) = serde_json::from_str::<Value>(body_part.trim()) {
                            if let Some(seq) = v.get("seq").and_then(Value::as_u64) {
                                acks.lock().unwrap().push(seq);
                            }
                        }
                    }
                    let body = serde_json::to_string(&json!({
                        "ackedSeq": 3,
                        "burnedItems": 3,
                        "burnedBytes": 0,
                        "remainingItems": 0,
                        "slotClosed": true,
                    }))
                    .unwrap();
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

    let (ext_link_txt, ext_link_err) = client
        .call_verified_claude(
            &sock,
            "conflict-ext",
            "hyp_mesh",
            json!({
                "action": "drop_link",
                "kind": "secret",
                "secretName": "ext-api-key",
                "relay": ext_relay_url,
            }),
        )
        .await;
    assert!(!ext_link_err, "external drop_link failed: {ext_link_txt}");
    let ext_link_val: Value = serde_json::from_str(&ext_link_txt).unwrap();
    assert_eq!(ext_link_val["secretExists"], json!(true));
    let ext_frag = decode_frag(ext_link_val["url"].as_str().unwrap());
    assert_eq!(ext_frag["secretExists"], json!(true));

    // Wait for the external watcher to deliver the conflict notice for `id: 2`.
    let ext_conflict_deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        let items = node.db().local().peek_inbox(ext_sid, 10).unwrap();
        if !items.is_empty() {
            break;
        }
        assert!(
            tokio::time::Instant::now() < ext_conflict_deadline,
            "timed out waiting for external watcher secret conflict notice"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    // Give duplicate `id: 2` replay a brief moment to prove it was deduplicated.
    tokio::time::sleep(Duration::from_millis(120)).await;

    let ext_conflict_items = node.db().local().peek_inbox(ext_sid, 10).unwrap();
    assert_eq!(
        ext_conflict_items.len(),
        1,
        "expected strictly 1 deduplicated conflict notice (junk ignored & duplicate seq deduped), got: {ext_conflict_items:?}"
    );
    assert!(ext_conflict_items[0].text.contains("[hyphae notice]"));
    assert!(ext_conflict_items[0].text.contains(ext_drop_id));
    assert!(ext_conflict_items[0].text.contains("ext-api-key"));
    assert!(ext_conflict_items[0].text.contains("Overwrite"));
    assert!(!ext_conflict_items[0].text.contains(ext_orig_secret));
    assert!(!ext_conflict_items[0].text.contains(ext_blocked_secret));
    assert_eq!(
        node.secret_store().get("ext-api-key").unwrap().as_str(),
        ext_orig_secret,
        "external watcher conflict MUST NOT overwrite secret"
    );
    assert_zero_bytes_in_sqlite_files(dir.path(), ext_blocked_secret);

    // Release `id: 3` (overwrite=true) on the SAME open SSE stream!
    send_overwrite_gate.notify_one();

    let ext_overwrite_deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        let val_ok = node
            .secret_store()
            .get("ext-api-key")
            .ok()
            .is_some_and(|v| v.as_str() == ext_updated_secret);
        let ack_ok = acked_seqs.lock().unwrap().contains(&3);
        if val_ok && ack_ok {
            break;
        }
        assert!(
            tokio::time::Instant::now() < ext_overwrite_deadline,
            "timed out waiting for external watcher overwrite resubmission (val_ok={val_ok}, ack_ok={ack_ok})"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_zero_bytes_in_sqlite_files(dir.path(), ext_updated_secret);

    ext_srv_task.abort();
    client.close().await;
    daemon.stop().await;
    node.shutdown();
}
