//! Deterministic E2E tests for GitHub Issue #29 (`LocalDaemon` laptop sleep/wake recovery):
//! 1. Interrupted `Active` Session A clears stale lease & flushes queued DM + concise `[hyphae notice]`;
//!    quiet `Idle` Session B (0 pending mail) receives ZERO unsolicited wakeups (`notify_all_enrolled: false`);
//!    transient-held `Idle` Session C clears `hold_retries` & flushes pending DM strictly at-most-once
//!    (zero duplicates across follow-up pass);
//!    Focus Mode Session D & muted Session E respect Focus Mode / mute & deduplicate wake notices.
//! 2. Tier 4 Herdr cold spawn is NEVER triggered solely by a wake notice (even with an allowlisted
//!    `herdrTemplate` and zero live transport), while a real unread DM still triggers it.
//! 3. Authenticated local IPC RPC `"system.wake"` triggers recovery + registered `WakeHook`s
//!    and fails closed on malformed parameters.
//! 4. External Blind Drop Relay SSE watcher recycles a stalled/half-open stream immediately on
//!    `handle_system_wake()` and ingests the human directive in <500ms.
//! 5. Opt-in `notify_all_enrolled: true` notifies quiet enrolled sessions while skipping unenrolled ones.

mod common;

use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::TestMcpClient;
use hyp_crypto::human::{HumanAudience, HumanClaimV1, HumanDropKind, seal_human_drop};
use hyp_crypto::rfc3339::format_rfc3339_millis;
use hyp_crypto::{Ed25519KeyPair, SecretBackend, X25519KeyPair};
use hyp_harness::daemon::{
    DeliveryRetryConfig, InboundItem, LocalDaemon, LocalDaemonConfig, WakeRecoveryConfig,
};
use hyp_harness::mcp::McpOptions;
use hyp_harness::protocol::HarnessKind;
use hyp_harness::sock::daemon_rpc_async;
use hyp_harness::transport::{PushMode, PushOutcome, PushTransport, TransportFuture};
use hyp_node::engine::http_util::SseEvent;
use hyp_node::engine::{NodeConfig, UnifiedNode};
use hyp_node::gates::TrustTier as GateTrustTier;
use hyp_proto::address::NodeId;
use hyp_store::{HumanAuthorityInput, HumanAuthorityRole, MailboxKind, now_ms};
use serde_json::json;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Notify;

fn open_local_node(node_id: &str, dir: &Path) -> Arc<UnifiedNode> {
    let mut cfg = NodeConfig::local(NodeId::new(node_id).unwrap(), dir);
    cfg.secret_backend = Some(SecretBackend::File);
    UnifiedNode::open(cfg).expect("open UnifiedNode")
}

/// RFC 0004: pushes carry only the `<hyphae-inbox>` digest; bodies stay unread in the mailbox
/// until the agent reads them via `hyp_inbox`.
fn unread_texts(node: &UnifiedNode, sid: &str) -> String {
    let texts: Vec<String> = node
        .db()
        .local()
        .peek_inbox(sid, 50)
        .unwrap()
        .into_iter()
        .map(|e| e.text)
        .collect();
    texts.join("\n")
}

struct RecordingTransport {
    delivered: Mutex<Vec<(String, PushMode)>>,
    notify: Notify,
}

impl RecordingTransport {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            delivered: Mutex::new(Vec::new()),
            notify: Notify::new(),
        })
    }

    fn snapshot(&self) -> Vec<(String, PushMode)> {
        self.delivered.lock().unwrap().clone()
    }

    async fn wait_for_count(&self, expected: usize, timeout: Duration) -> Vec<(String, PushMode)> {
        let deadline = Instant::now() + timeout;
        loop {
            let cur = self.snapshot();
            if cur.len() >= expected {
                return cur;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                panic!(
                    "RecordingTransport timed out waiting for {expected} deliveries (got {}): {cur:?}",
                    cur.len()
                );
            }
            let _ = tokio::time::timeout(
                remaining.min(Duration::from_millis(25)),
                self.notify.notified(),
            )
            .await;
        }
    }
}

impl PushTransport for RecordingTransport {
    fn kind(&self) -> &'static str {
        "test_inline"
    }

    fn supports_interrupt(&self) -> bool {
        true
    }

    fn deliver<'a>(&'a self, text: &'a str, mode: PushMode) -> TransportFuture<'a, PushOutcome> {
        let text = text.to_string();
        Box::pin(async move {
            self.delivered.lock().unwrap().push((text, mode));
            self.notify.notify_waiters();
            PushOutcome::delivered()
        })
    }
}

/// Transport that returns `PushOutcome::hold("herdr_working")` while `should_hold` is true,
/// then delivers normally once flipped to `false` (simulating transient retry hold across sleep).
struct FlakyHoldTransport {
    should_hold: AtomicBool,
    hold_attempts: AtomicUsize,
    delivered: Mutex<Vec<(String, PushMode)>>,
    notify: Notify,
}

impl FlakyHoldTransport {
    fn new(start_holding: bool) -> Arc<Self> {
        Arc::new(Self {
            should_hold: AtomicBool::new(start_holding),
            hold_attempts: AtomicUsize::new(0),
            delivered: Mutex::new(Vec::new()),
            notify: Notify::new(),
        })
    }

    fn set_holding(&self, hold: bool) {
        self.should_hold.store(hold, Ordering::SeqCst);
    }

    fn snapshot(&self) -> Vec<(String, PushMode)> {
        self.delivered.lock().unwrap().clone()
    }
}

impl PushTransport for FlakyHoldTransport {
    fn kind(&self) -> &'static str {
        "test_flaky_herdr"
    }

    fn supports_interrupt(&self) -> bool {
        true
    }

    fn deliver<'a>(&'a self, text: &'a str, mode: PushMode) -> TransportFuture<'a, PushOutcome> {
        let text = text.to_string();
        Box::pin(async move {
            if self.should_hold.load(Ordering::SeqCst) {
                self.hold_attempts.fetch_add(1, Ordering::SeqCst);
                self.notify.notify_waiters();
                return PushOutcome::hold("herdr_working");
            }
            self.delivered.lock().unwrap().push((text, mode));
            self.notify.notify_waiters();
            PushOutcome::delivered()
        })
    }
}

fn enroll_session(node: &UnifiedNode, session_id: &str, handle: &str) {
    let now = now_ms();
    let db = node.db();
    db.local().register_session(session_id, "{}", now).unwrap();
    db.local()
        .set_session_handle(session_id, Some(handle), now)
        .unwrap();
}

async fn mark_active_via_call_start(sock: &Path, session_id: &str) {
    let resp = daemon_rpc_async(
        sock,
        &json!({
            "type": "call.start",
            "harness": "claude",
            "sessionId": session_id,
            "tool": "hyp_inbox",
            "callId": format!("call-{session_id}"),
        }),
        Duration::from_secs(2),
    )
    .await;
    assert!(resp.ok, "call.start failed for {session_id}: {resp:?}");
}

#[tokio::test]
async fn wake_recovery_flushes_interrupted_active_and_held_idle_without_spamming_quiet_idle() {
    let dir = TempDir::new().unwrap();
    let node = open_local_node("wake29@local", dir.path());
    let daemon = LocalDaemon::start(
        Arc::clone(&node),
        None,
        LocalDaemonConfig {
            auto_detect_transports: false,
            queue_activity_lease: Duration::from_secs(60),
            delivery_retry: DeliveryRetryConfig {
                // Very long backoff so retry C will NOT self-fire during the test.
                hold_retry_backoff_ms: vec![60_000],
                hold_retry_max_attempts: 4,
                ..Default::default()
            },
            wake_recovery: WakeRecoveryConfig {
                enabled: true,
                min_sleep_seconds: 15,
                notify_interrupted_active: true,
                notify_all_enrolled: false,
            },
            // Fast follow-up pass so we explicitly verify zero duplicate deliveries!
            wake_followup_flush_delay: Duration::from_millis(80),
            ..Default::default()
        },
    )
    .await
    .expect("start LocalDaemon");
    let sock = daemon.socket_path().to_path_buf();

    let sid_a = "claude:wake-a";
    let sid_b = "claude:wake-b";
    let sid_c = "claude:wake-c";
    let sid_d = "claude:wake-d-focus";
    let sid_e = "claude:wake-e-muted";

    enroll_session(&node, sid_a, "alice");
    enroll_session(&node, sid_b, "bob");
    enroll_session(&node, sid_c, "carol");
    enroll_session(&node, sid_d, "dave");
    enroll_session(&node, sid_e, "eve");

    let transport_a = RecordingTransport::new();
    let transport_b = RecordingTransport::new();
    let transport_c = FlakyHoldTransport::new(true);
    let transport_d = RecordingTransport::new();
    let transport_e = RecordingTransport::new();

    daemon.register_session_transport(sid_a, Arc::clone(&transport_a) as Arc<dyn PushTransport>);
    daemon.register_session_transport(sid_b, Arc::clone(&transport_b) as Arc<dyn PushTransport>);
    daemon.register_session_transport(sid_c, Arc::clone(&transport_c) as Arc<dyn PushTransport>);
    daemon.register_session_transport(sid_d, Arc::clone(&transport_d) as Arc<dyn PushTransport>);
    daemon.register_session_transport(sid_e, Arc::clone(&transport_e) as Arc<dyn PushTransport>);

    // Configure Focus Mode on Session D and mute `hyphae:system` on Session E.
    let focus_res = daemon_rpc_async(
        &sock,
        &json!({ "type": "session.focus", "sessionId": sid_d, "enabled": true }),
        Duration::from_secs(2),
    )
    .await;
    assert!(focus_res.ok, "focus on D: {focus_res:?}");

    let mute_res = daemon_rpc_async(
        &sock,
        &json!({ "type": "session.mute", "sessionId": sid_e, "target": "hyphae:system" }),
        Duration::from_secs(2),
    )
    .await;
    assert!(mute_res.ok, "mute on E: {mute_res:?}");

    // Mark Sessions A, D, and E as `Active` mid-turn (simulating turn interrupted by laptop sleep).
    mark_active_via_call_start(&sock, sid_a).await;
    mark_active_via_call_start(&sock, sid_d).await;
    mark_active_via_call_start(&sock, sid_e).await;

    // Session A receives a `queue` DM while `Active`: MUST stay held by the 60s activity lease!
    daemon
        .ingest_inbound(InboundItem {
            session_id: sid_a.into(),
            origin_node: "wake29@local".into(),
            item_id: "dm-for-active-a".into(),
            source: "wake29@local/ops".into(),
            text: "queued-dm-for-session-a".into(),
            kind: MailboxKind::Message,
            trust_tier: GateTrustTier::SelfHost,
        })
        .await
        .unwrap();

    // Session C (`Idle`) receives a DM while transport holds with `herdr_working` -> enters `hold_retries`.
    daemon
        .ingest_inbound(InboundItem {
            session_id: sid_c.into(),
            origin_node: "wake29@local".into(),
            item_id: "dm-held-for-c".into(),
            source: "wake29@local/ops".into(),
            text: "held-dm-for-session-c".into(),
            kind: MailboxKind::Message,
            trust_tier: GateTrustTier::SelfHost,
        })
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(60)).await;
    assert!(
        transport_a.snapshot().is_empty(),
        "Session A's queued DM must remain deferred while Active before sleep"
    );
    assert!(transport_b.snapshot().is_empty());
    assert!(transport_c.snapshot().is_empty());
    assert_eq!(
        transport_c.hold_attempts.load(Ordering::SeqCst),
        1,
        "Session C must have attempted once and entered hold_retries"
    );

    // Host wakes after 10 minutes (600s); Session C's transport is now ready.
    transport_c.set_holding(false);
    let report = daemon.handle_system_wake(Duration::from_secs(600)).await;

    assert_eq!(report.wake_epoch, 1);
    assert_eq!(report.slept_ms, 600_000);
    assert_eq!(report.cleared_hold_retries, 1);
    assert!(report.cleared_active_sessions.contains(&sid_a.to_string()));
    assert!(report.cleared_active_sessions.contains(&sid_d.to_string()));
    assert!(report.cleared_active_sessions.contains(&sid_e.to_string()));
    assert!(!report.cleared_active_sessions.contains(&sid_b.to_string()));
    assert!(!report.cleared_active_sessions.contains(&sid_c.to_string()));
    assert!(report.notified_sessions.contains(&sid_a.to_string()));
    assert!(report.notified_sessions.contains(&sid_d.to_string()));
    assert!(
        !report.notified_sessions.contains(&sid_e.to_string()),
        "muted session E must not be notified"
    );
    assert!(
        !report.notified_sessions.contains(&sid_b.to_string()),
        "quiet idle session B must not be notified when notify_all_enrolled is false"
    );

    // 1. Session A: stale `Active` lease cleared -> queued DM + concise `[hyphae notice]` flushed!
    let got_a = transport_a.wait_for_count(1, Duration::from_secs(2)).await;
    let combined_a: String = got_a
        .iter()
        .map(|(txt, _)| txt.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        combined_a.contains("<system from=\"hyphae:system\" count=\"1\"/>")
            && combined_a.contains("<dm from=")
            && !combined_a.contains("queued-dm-for-session-a")
            && !combined_a.contains("Host woke"),
        "Session A must receive a metadata-only digest counting its DM + wake notice: {combined_a:?}"
    );
    let unread_a = unread_texts(&node, sid_a);
    assert!(
        unread_a.contains("queued-dm-for-session-a")
            && unread_a.contains(
                "[hyphae notice] Host woke from sleep after 10m; your previous turn may have been interrupted. Peer links reconnected."
            ),
        "Session A must hold its queued DM + concise wake notice unread: {unread_a:?}"
    );

    // 2. Session C: transient `hold_retries` cleared -> pending DM flushed immediately!
    let got_c = transport_c.snapshot();
    assert_eq!(
        got_c.len(),
        1,
        "Session C must flush immediately on wake: {got_c:?}"
    );
    assert!(got_c[0].0.starts_with("<hyphae-inbox ") && got_c[0].0.contains("<dm from="));
    assert!(unread_texts(&node, sid_c).contains("held-dm-for-session-c"));

    // Wait past the 80ms follow-up flush timer + invoke an extra manual flush to prove at-most-once!
    tokio::time::sleep(Duration::from_millis(180)).await;
    daemon.flush_pending_sessions().await;

    assert_eq!(
        transport_a.snapshot().len(),
        got_a.len(),
        "Session A must receive zero duplicate deliveries across follow-up flush"
    );
    assert_eq!(
        transport_c.snapshot().len(),
        1,
        "Session C must receive strictly at-most-once delivery (zero duplicates)"
    );

    // 3. Session B (`Idle`, 0 mail): ZERO unsolicited wakeups!
    assert!(
        transport_b.snapshot().is_empty(),
        "Quiet idle Session B must receive ZERO wakeups when notify_all_enrolled == false"
    );

    // 4. Session D (Focus Mode ON): ZERO unsolicited L2 push wakeups; notice stays cleanly pending as Notify!
    assert!(
        transport_d.snapshot().is_empty(),
        "Focus Mode Session D must NOT receive an unsolicited L2 push wakeup"
    );
    assert_eq!(node.db().local().pending_count(sid_d).unwrap(), 1);

    // Triggering a second wake while Session D still has a pending wake notice MUST NOT stack a duplicate!
    mark_active_via_call_start(&sock, sid_d).await;
    let report2 = daemon.handle_system_wake(Duration::from_secs(300)).await;
    assert!(
        !report2.notified_sessions.contains(&sid_d.to_string()),
        "second wake must NOT enqueue a duplicate pending wake notice for Session D"
    );
    assert_eq!(node.db().local().pending_count(sid_d).unwrap(), 1);

    // 5. Session E (muted `hyphae:system`): ZERO wakeups & ZERO pending wake notices!
    assert!(transport_e.snapshot().is_empty());
    assert_eq!(node.db().local().pending_count(sid_e).unwrap(), 0);

    daemon.stop().await;
    node.shutdown();
}

#[cfg(unix)]
#[tokio::test]
async fn wake_notice_never_triggers_tier4_herdr_cold_spawn() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    let dir = TempDir::new().unwrap();
    let marker = dir.path().join("herdr-cold-spawn.log");
    let fake_hc = dir.path().join("fake-hc.sh");
    fs::write(
        &fake_hc,
        format!(
            "#!/bin/sh\necho \"$@\" >> \"{}\"\nexit 0\n",
            marker.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&fake_hc, fs::Permissions::from_mode(0o755)).unwrap();

    let node = open_local_node("coldwake@local", dir.path());
    let daemon = LocalDaemon::start(
        Arc::clone(&node),
        None,
        LocalDaemonConfig {
            auto_detect_transports: false,
            herdr_bin: Some(fake_hc.display().to_string()),
            queue_activity_lease: Duration::from_secs(60),
            delivery_retry: DeliveryRetryConfig {
                herdr_spawn_allowlist: vec!["wake-worker".to_string()],
                ..Default::default()
            },
            wake_recovery: WakeRecoveryConfig {
                enabled: true,
                min_sleep_seconds: 15,
                notify_interrupted_active: true,
                notify_all_enrolled: false,
            },
            wake_followup_flush_delay: Duration::from_millis(50),
            ..Default::default()
        },
    )
    .await
    .expect("start LocalDaemon");
    let sock = daemon.socket_path().to_path_buf();

    let sid = "claude:cold-wake-only";
    let now = now_ms();
    {
        let db = node.db();
        db.local()
            .register_session(
                sid,
                r#"{"kind":"claude","herdrTemplate":"wake-worker"}"#,
                now,
            )
            .unwrap();
        db.local()
            .set_session_handle(sid, Some("worker"), now)
            .unwrap();
    }

    // Mark session `Active` with NO live transport and ZERO real DMs.
    mark_active_via_call_start(&sock, sid).await;

    let report = daemon.handle_system_wake(Duration::from_secs(300)).await;
    assert!(report.notified_sessions.contains(&sid.to_string()));

    // Wait past the follow-up flush pass as well.
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(
        !marker.exists(),
        "Tier 4 cold spawn MUST NEVER fire solely for a wake notice!"
    );
    assert_eq!(
        node.db().local().pending_count(sid).unwrap(),
        1,
        "wake notice stays safely queued in SQLite for next hook/resume"
    );

    // Sanity check: a REAL unread DM on the exact same session DOES trigger allowlisted Tier 4 cold spawn!
    daemon
        .ingest_inbound(InboundItem {
            session_id: sid.into(),
            origin_node: "coldwake@local".into(),
            item_id: "real-dm-1".into(),
            source: "coldwake@local/human".into(),
            text: "real-work-needs-cold-spawn".into(),
            kind: MailboxKind::Message,
            trust_tier: GateTrustTier::SelfHost,
        })
        .await
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(3);
    while !marker.exists() && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(
        marker.exists(),
        "sanity check: real unread DM must still trigger allowlisted Tier 4 cold spawn"
    );

    daemon.stop().await;
    node.shutdown();
}

#[tokio::test]
async fn system_wake_ipc_rpc_triggers_recovery_hooks_and_fails_closed_on_bad_args() {
    let dir = TempDir::new().unwrap();
    let node = open_local_node("ipc-wake@local", dir.path());
    let daemon = LocalDaemon::start(
        Arc::clone(&node),
        None,
        LocalDaemonConfig {
            auto_detect_transports: false,
            queue_activity_lease: Duration::from_secs(60),
            wake_followup_flush_delay: Duration::ZERO,
            ..Default::default()
        },
    )
    .await
    .expect("start LocalDaemon");
    let sock = daemon.socket_path().to_path_buf();

    let hook_slept = Arc::new(Mutex::new(Vec::<u64>::new()));
    let hook_slept_bg = Arc::clone(&hook_slept);
    daemon.on_system_wake(move |dur| {
        let log = Arc::clone(&hook_slept_bg);
        async move {
            log.lock().unwrap().push(dur.as_millis() as u64);
        }
    });

    let sid = "claude:ipc-wake-a";
    enroll_session(&node, sid, "alice");
    let transport = RecordingTransport::new();
    daemon.register_session_transport(sid, Arc::clone(&transport) as Arc<dyn PushTransport>);
    mark_active_via_call_start(&sock, sid).await;

    // Invalid params fail closed without bumping wake_epoch.
    for bad_pkt in [
        json!({ "type": "system.wake", "sleptMs": -10 }),
        json!({ "type": "system.wake", "sleptMs": "120000" }),
        json!({ "type": "system.wake", "sleptSeconds": -1 }),
    ] {
        let resp = daemon_rpc_async(&sock, &bad_pkt, Duration::from_secs(2)).await;
        assert!(
            !resp.ok,
            "bad system.wake payload must fail closed: {bad_pkt}"
        );
    }
    assert_eq!(node.current_wake_epoch(), 0);
    assert!(hook_slept.lock().unwrap().is_empty());

    // Valid authenticated local IPC RPC triggers full recovery + wake hooks!
    let resp = daemon_rpc_async(
        &sock,
        &json!({ "type": "system.wake", "sleptSeconds": 120 }),
        Duration::from_secs(2),
    )
    .await;
    assert!(resp.ok, "system.wake RPC failed: {resp:?}");
    let res = resp.result.expect("result payload");
    assert_eq!(res["wakeEpoch"], json!(1));
    assert_eq!(res["sleptMs"], json!(120_000));
    assert_eq!(res["notifiedSessions"], json!([sid]));
    assert_eq!(*hook_slept.lock().unwrap(), vec![120_000]);

    let got = transport.wait_for_count(1, Duration::from_secs(2)).await;
    assert!(
        got[0]
            .0
            .contains("<system from=\"hyphae:system\" count=\"1\"/>")
    );
    assert!(unread_texts(&node, sid).contains("Host woke from sleep after 2m"));

    daemon.stop().await;
    node.shutdown();
}

#[tokio::test]
async fn external_drop_watcher_recycles_stalled_sse_immediately_on_wake() {
    let dir = TempDir::new().unwrap();
    let human_sign = Ed25519KeyPair::generate().unwrap();
    let human_enc = X25519KeyPair::generate().unwrap();

    // Start a mock external Blind Drop Relay that:
    // - handles POST /v1/drops -> returns drop_id + postCap + subCap
    // - handles GET /v1/drops/{id}/stream:
    //   - conn #1: sends 200 SSE headers + `: connected` and STALLS forever!
    //   - conn #2: immediately streams a signed verified HumanDropEnvelopeV1 directive!
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = listener.local_addr().unwrap();
    let relay_url = format!("http://{relay_addr}");

    let mut cfg = NodeConfig::local(NodeId::new("dropwake@local").unwrap(), dir.path());
    cfg.secret_backend = Some(SecretBackend::File);
    cfg.drop_relay_url = Some(relay_url.clone());
    let node = UnifiedNode::open(cfg).expect("open node");

    let now = now_ms();
    node.db()
        .human()
        .upsert_authority(
            &HumanAuthorityInput {
                human_id: "alice".to_string(),
                kid: human_sign.kid(),
                label: "Alice".to_string(),
                role: HumanAuthorityRole::Admin,
                jwk_json: serde_json::to_string(&human_sign.public_key().to_jwk()).unwrap(),
                enc_jwk_json: Some(
                    serde_json::to_string(&human_enc.public_key().to_jwk()).unwrap(),
                ),
                prf_salt: None,
                auth_epoch: 1,
            },
            now,
        )
        .unwrap();

    let drop_id = "wakeDropSlot0123456789";
    let claim = HumanClaimV1 {
        v: 1,
        kind: HumanDropKind::Directive,
        claim_id: "claim-wake-drop-1".to_string(),
        human_id: "alice".to_string(),
        human_kid: human_sign.kid(),
        auth_epoch: 1,
        issued_at: format_rfc3339_millis(now),
        expires_at: format_rfc3339_millis(now + 300_000),
        drop_id: drop_id.to_string(),
        audience: HumanAudience {
            node_id: "dropwake@local".to_string(),
            node_enc_kid: node.identity().encryption.public_key().kid(),
            handle: Some("agent1".to_string()),
        },
        secret_spec: None,
        body: "directive-delivered-after-wake-reconnect".to_string(),
    };
    let env = seal_human_drop(
        &claim,
        &human_sign,
        &node.identity().encryption.public_key(),
    )
    .expect("seal signed human drop");
    let env_json = serde_json::to_string(&env).unwrap();

    let stream_conns = Arc::new(AtomicUsize::new(0));
    let first_stream_notify = Arc::new(Notify::new());
    let conns_bg = Arc::clone(&stream_conns);
    let notify_bg = Arc::clone(&first_stream_notify);

    let relay_task = tokio::spawn(async move {
        let exp_ms = now_ms() + 300_000;
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            let conns = Arc::clone(&conns_bg);
            let first = Arc::clone(&notify_bg);
            let env_payload = env_json.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let n = match sock.read(&mut buf).await {
                    Ok(n) if n > 0 => n,
                    _ => return,
                };
                let req = String::from_utf8_lossy(&buf[..n]);
                let first_line = req.lines().next().unwrap_or("");
                let mut parts = first_line.split_whitespace();
                let method = parts.next().unwrap_or("");
                let path = parts.next().unwrap_or("");

                if method == "POST" && path == "/v1/drops" {
                    let body = serde_json::to_string(&json!({
                        "dropId": drop_id,
                        "expiresAtMs": exp_ms,
                        "postCap": "hdcap1_post_test_cap",
                        "subCap": "hdcap1_sub_test_cap",
                        "maxPayloadBytes": 65536,
                        "maxItems": 4,
                    }))
                    .unwrap();
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                } else if method == "GET" && path == format!("/v1/drops/{drop_id}/stream") {
                    let num = conns.fetch_add(1, Ordering::SeqCst) + 1;
                    if num == 1 {
                        let hdr = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream; charset=utf-8\r\nConnection: keep-alive\r\n\r\n: connected\n\n";
                        let _ = sock.write_all(hdr.as_bytes()).await;
                        let _ = sock.flush().await;
                        first.notify_waiters();
                        let mut drain = [0u8; 64];
                        loop {
                            match sock.read(&mut drain).await {
                                Ok(0) | Err(_) => break,
                                Ok(_) => {}
                            }
                        }
                    } else {
                        let sse = SseEvent::new("drop", env_payload).with_id("1").encode();
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream; charset=utf-8\r\nConnection: keep-alive\r\n\r\n{sse}"
                        );
                        let _ = sock.write_all(resp.as_bytes()).await;
                        let _ = sock.flush().await;
                    }
                } else if method == "POST" && path == format!("/v1/drops/{drop_id}/ack") {
                    let body = r#"{"ackedSeq":1,"burnedItems":1,"burnedBytes":100,"remainingItems":0,"slotClosed":true}"#;
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                }
            });
        }
    });

    let daemon = LocalDaemon::start(
        Arc::clone(&node),
        None,
        LocalDaemonConfig {
            auto_detect_transports: false,
            wake_followup_flush_delay: Duration::ZERO,
            ..Default::default()
        },
    )
    .await
    .expect("start LocalDaemon");
    let sock = daemon.socket_path().to_path_buf();

    let sid = "claude:drop-wake-sess";
    let transport = RecordingTransport::new();
    let mut mcp = TestMcpClient::spawn(McpOptions {
        backend: Some(HarnessKind::Claude),
        ephemeral: false,
        ..McpOptions::new(sock.clone())
    });
    mcp.initialize().await;

    let join_pre = daemon_rpc_async(
        &sock,
        &json!({
            "type": "call.start",
            "harness": "claude",
            "sessionId": sid,
            "tool": "hyp_session",
            "callId": "tu-join",
        }),
        Duration::from_secs(2),
    )
    .await;
    assert!(join_pre.ok, "join call.start failed: {join_pre:?}");
    let join_tok = join_pre.result.unwrap()["callToken"]
        .as_str()
        .unwrap()
        .to_string();
    let (join_txt, join_err) = mcp
        .call_tool(
            "hyp_mesh",
            json!({ "action": "join", "handle": "agent1", "_meshCall": join_tok }),
            Some(json!({ "claudecode/toolUseId": "tu-join" })),
        )
        .await;
    assert!(!join_err, "join failed: {join_txt}");
    daemon.register_session_transport(sid, Arc::clone(&transport) as Arc<dyn PushTransport>);

    // Create external drop link (spawns `spawn_external_drop_watcher` against mock relay).
    let dl_pre = daemon_rpc_async(
        &sock,
        &json!({
            "type": "call.start",
            "harness": "claude",
            "sessionId": sid,
            "tool": "hyp_mesh",
            "callId": "tu-dl",
        }),
        Duration::from_secs(2),
    )
    .await;
    assert!(dl_pre.ok, "dl call.start failed: {dl_pre:?}");
    let dl_tok = dl_pre.result.unwrap()["callToken"]
        .as_str()
        .unwrap()
        .to_string();
    let (dl_txt, dl_err) = mcp
        .call_tool(
            "hyp_mesh",
            json!({ "action": "drop_link", "kind": "directive", "_meshCall": dl_tok }),
            Some(json!({ "claudecode/toolUseId": "tu-dl" })),
        )
        .await;
    assert!(!dl_err, "drop_link failed: {dl_txt}");

    // Transition session idle so the delivered directive flushes immediately to `transport`.
    let _ = daemon_rpc_async(
        &sock,
        &json!({ "type": "session.idle", "sessionId": sid }),
        Duration::from_secs(2),
    )
    .await;

    // Wait for external drop watcher SSE conn #1 to establish & stall.
    tokio::time::timeout(Duration::from_secs(2), async {
        while stream_conns.load(Ordering::SeqCst) < 1 {
            first_stream_notify.notified().await;
        }
    })
    .await
    .expect("drop watcher conn #1 must connect");
    tokio::time::sleep(Duration::from_millis(60)).await;
    assert_eq!(stream_conns.load(Ordering::SeqCst), 1);
    assert!(transport.snapshot().is_empty());

    // Fire system wake -> external drop watcher immediately recycles stalled SSE and delivers!
    let t0 = Instant::now();
    daemon.handle_system_wake(Duration::from_secs(60)).await;

    let got = transport
        .wait_for_count(1, Duration::from_millis(500))
        .await;
    let elapsed = t0.elapsed();
    assert!(
        elapsed < Duration::from_millis(500),
        "external drop watcher wake recycle took {elapsed:?}"
    );
    assert!(
        got[0].0.contains("verified=\"true\"")
            && unread_texts(&node, sid).contains("directive-delivered-after-wake-reconnect"),
        "expected verified human directive after wake reconnect: {got:?}"
    );
    assert!(stream_conns.load(Ordering::SeqCst) >= 2);

    mcp.close().await;
    relay_task.abort();
    daemon.stop().await;
    node.shutdown();
}

#[tokio::test]
async fn notify_all_enrolled_opt_in_notifies_quiet_idle_enrolled_sessions_only() {
    let dir = TempDir::new().unwrap();
    let node = open_local_node("optin-wake@local", dir.path());
    let daemon = LocalDaemon::start(
        Arc::clone(&node),
        None,
        LocalDaemonConfig {
            auto_detect_transports: false,
            wake_recovery: WakeRecoveryConfig {
                enabled: true,
                min_sleep_seconds: 15,
                notify_interrupted_active: true,
                notify_all_enrolled: true,
            },
            wake_followup_flush_delay: Duration::ZERO,
            ..Default::default()
        },
    )
    .await
    .expect("start LocalDaemon");

    let sid_enrolled = "claude:optin-enrolled";
    let sid_unenrolled = "claude:optin-unenrolled";
    enroll_session(&node, sid_enrolled, "alice");
    node.db()
        .local()
        .register_session(sid_unenrolled, "{}", now_ms())
        .unwrap();

    let t_enrolled = RecordingTransport::new();
    let t_unenrolled = RecordingTransport::new();
    daemon.register_session_transport(
        sid_enrolled,
        Arc::clone(&t_enrolled) as Arc<dyn PushTransport>,
    );
    daemon.register_session_transport(
        sid_unenrolled,
        Arc::clone(&t_unenrolled) as Arc<dyn PushTransport>,
    );

    let report = daemon.handle_system_wake(Duration::from_secs(300)).await;
    assert_eq!(report.notified_sessions, vec![sid_enrolled.to_string()]);

    let got = t_enrolled.wait_for_count(1, Duration::from_secs(2)).await;
    assert!(
        got[0]
            .0
            .contains("<system from=\"hyphae:system\" count=\"1\"/>")
    );
    assert!(
        unread_texts(&node, sid_enrolled)
            .contains("[hyphae notice] Host woke from sleep after 5m. Peer links reconnected.")
    );
    assert!(
        t_unenrolled.snapshot().is_empty(),
        "unenrolled session without handle must not be notified by notify_all_enrolled"
    );

    daemon.stop().await;
    node.shutdown();
}
