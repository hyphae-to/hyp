//! Differential & E2E tests for Live Daemon Hot-Reload of Security Gate (`gate.reload`)
//! and Quarantine Approvals / Rejections (`inbox.wake`) on `LocalDaemon`.
//!
//! Covers:
//! 1. Live `gate.reload` happy path: swaps active `SecurityGatePipeline` without restart,
//!    immediately enforcing newly configured Stage 1 rules & filter plugins on BOTH `LocalDaemon`
//!    and shared `LocalIngestServer`!
//! 2. Fail-closed mutated inputs (McKeeman nearby altered cases):
//!    - 1-bit flipped `policy_signature` HMAC
//!    - Tampered rule without re-signing
//!    - Signature-stripping downgrade attack (`require_signed_policy: true -> false` / `None`)
//!    - Invalid regex / corrupted JSON config
//!    - Unconfigured reloader
//!
//!    All reject reload fail-closed AND preserve the previously active valid pipeline intact!
//! 3. Live `inbox.wake` after SQLite `approve_quarantined` & `reject_quarantined`:
//!    - Immediately wakes an idle session with an attached mock `PushTransport` (zero restart!)
//!    - Resolves target session from `receipt` alone when `sessionId` is omitted
//!    - Immediately clears `counts.quarantined` and `daemon.quarantinedGlobal` in both
//!      `session.summary` RPC and debounced atomic `<state_dir>/ui/state.json`!
//! 4. Cross-OS loopback TCP (`LocalDaemon::start_tcp` -> `connector.addr`) differential parity.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hyp_crypto::{SecretBackend, SecretStore};
use hyp_harness::daemon::{GateReloader, InboundItem, LocalDaemon, LocalDaemonConfig};
use hyp_harness::sock::{DaemonRpcResult, daemon_rpc_async};
use hyp_harness::transport::{PushMode, PushOutcome, PushTransport, TransportFuture};
use hyp_node::engine::{LocalIngestServer, NodeConfig, UnifiedNode, send_local_ingest_event};
use hyp_node::gates::SecurityGatePipeline;
use hyp_node::gates::policy::{
    FilterAdapterConfig, FilterPluginConfig, SecurityGateConfig, Stage1DenyAction, Stage2Matchers,
    TrustTier as GateTrustTier, sign_gate_policy,
};
use hyp_proto::address::NodeId;
use hyp_store::{GateAuditQuery, GateDecision as StoreGateDecision, MailboxKind, NodeDb, now_ms};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::sync::Notify;

fn open_local_node(node_id: &str, dir: &Path) -> Arc<UnifiedNode> {
    let mut cfg = NodeConfig::local(NodeId::new(node_id).unwrap(), dir);
    cfg.secret_backend = Some(SecretBackend::File);
    UnifiedNode::open(cfg).expect("open UnifiedNode")
}

async fn rpc(sock: &Path, pkt: &Value) -> DaemonRpcResult {
    daemon_rpc_async(sock, pkt, Duration::from_secs(5)).await
}

/// Deterministic mock `PushTransport` recording all delivered payloads and waking waiters.
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
                remaining.min(Duration::from_millis(50)),
                self.notify.notified(),
            )
            .await;
        }
    }
}

impl PushTransport for RecordingTransport {
    fn kind(&self) -> &'static str {
        "herdr"
    }

    fn supports_interrupt(&self) -> bool {
        true
    }

    fn deliver<'a>(&'a self, prompt: &'a str, mode: PushMode) -> TransportFuture<'a, PushOutcome> {
        Box::pin(async move {
            self.delivered
                .lock()
                .unwrap()
                .push((prompt.to_string(), mode));
            self.notify.notify_waiters();
            PushOutcome::Delivered
        })
    }
}

fn sign_and_write_gate_config(
    config_path: &Path,
    secrets: &SecretStore,
    mut gate_cfg: SecurityGateConfig,
) -> SecurityGateConfig {
    gate_cfg.require_signed_policy = true;
    gate_cfg.policy_signature = None;
    let sig = sign_gate_policy(&gate_cfg, secrets).expect("sign gate policy");
    gate_cfg.policy_signature = Some(sig);
    let doc = json!({ "gate": gate_cfg });
    fs::write(config_path, serde_json::to_string_pretty(&doc).unwrap()).unwrap();
    gate_cfg
}

fn make_disk_reloader(
    config_path: PathBuf,
    state_dir: PathBuf,
    gate_db: Arc<Mutex<NodeDb>>,
) -> GateReloader {
    Arc::new(move || {
        let raw = fs::read_to_string(&config_path)
            .map_err(|e| format!("failed to read {}: {e}", config_path.display()))?;
        let doc: Value = serde_json::from_str(&raw)
            .map_err(|e| format!("invalid JSON in {}: {e}", config_path.display()))?;
        let gate_cfg: SecurityGateConfig = match doc.get("gate") {
            Some(v) => serde_json::from_value(v.clone())
                .map_err(|e| format!("invalid gate config: {e}"))?,
            None => SecurityGateConfig::default(),
        };
        let secrets = Arc::new(SecretStore::new(&state_dir, SecretBackend::File));
        let pipeline = SecurityGatePipeline::new(gate_cfg, Arc::clone(&gate_db), Some(secrets))
            .map_err(|e| format!("failed to build pipeline: {e}"))?;
        pipeline
            .verify_policy_integrity()
            .map_err(|e| format!("gate_policy_tampered: {e}"))?;
        Ok(Some(Arc::new(pipeline)))
    })
}

async fn wait_for_ui_state_rev(path: &Path, min_rev: u64) -> Value {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if let Ok(raw) = fs::read_to_string(path) {
            if let Ok(val) = serde_json::from_str::<Value>(&raw) {
                if val.get("rev").and_then(Value::as_u64).unwrap_or(0) >= min_rev {
                    return val;
                }
            }
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {} to reach rev >= {min_rev}",
            path.display()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn gate_reload_swaps_live_pipeline_without_restart_and_blocks_new_rule() {
    let tmp = TempDir::new().unwrap();
    let state_dir = tmp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap();
    let config_path = state_dir.join("node.json");

    let node = open_local_node("reload-happy@box", &state_dir);
    let secrets = Arc::new(SecretStore::new(&state_dir, SecretBackend::File));
    let gate_db = Arc::new(Mutex::new(
        NodeDb::open(state_dir.join("node.sqlite")).unwrap(),
    ));

    // Initial signed policy: no regex denylist, 0 filters.
    let initial_cfg =
        sign_and_write_gate_config(&config_path, &secrets, SecurityGateConfig::default());
    let initial_pipeline = Arc::new(
        SecurityGatePipeline::new(
            initial_cfg,
            Arc::clone(&gate_db),
            Some(Arc::clone(&secrets)),
        )
        .unwrap(),
    );

    let daemon = LocalDaemon::start(
        Arc::clone(&node),
        Some(initial_pipeline),
        LocalDaemonConfig::default(),
    )
    .await
    .expect("start LocalDaemon");
    daemon.set_gate_reloader(make_disk_reloader(
        config_path.clone(),
        state_dir.clone(),
        Arc::clone(&gate_db),
    ));

    // Also start LocalIngestServer sharing the exact same hot-reloadable gate slot!
    let ingest_srv = LocalIngestServer::start_with_shared_gate(
        Arc::clone(&node),
        daemon.gate_slot(),
        node.config().local_ingest.clone(),
    )
    .await
    .expect("start LocalIngestServer");

    // Register session + live push transport.
    node.db()
        .local()
        .register_session("claude:live-gate", "{}", now_ms())
        .unwrap();
    let transport = RecordingTransport::new();
    daemon.register_session_transport("claude:live-gate", transport.clone());

    // 1. Before reload: payload containing `FORBIDDEN_SECRET_RULE` is allowed & delivered!
    let res1 = daemon
        .ingest_inbound(InboundItem {
            session_id: "claude:live-gate".into(),
            origin_node: "bob@laptop".into(),
            item_id: "msg-before-reload".into(),
            source: "bob@laptop/dev".into(),
            text: "status FORBIDDEN_SECRET_RULE ok".into(),
            kind: MailboxKind::Message,
            trust_tier: GateTrustTier::Peer,
        })
        .await
        .unwrap();
    assert!(
        res1.is_some(),
        "expected message to be allowed before reload"
    );
    let deliveries = transport.wait_for_count(1, Duration::from_secs(2)).await;
    assert!(deliveries[0].0.contains("FORBIDDEN_SECRET_RULE"));

    // 2. Write a NEW signed policy adding a Stage 1 block rule + 1 enabled filter plugin.
    let mut updated_cfg = SecurityGateConfig::default();
    updated_cfg
        .stage1
        .inbound_regex_denylist
        .push("FORBIDDEN_SECRET_RULE".to_string());
    updated_cfg.stage1.regex_deny_action = Stage1DenyAction::Block;
    updated_cfg.filters.push(FilterPluginConfig {
        id: "local-guard".to_string(),
        enabled: true,
        matchers: Stage2Matchers {
            trust_tiers: vec![GateTrustTier::Guest],
            ..Default::default()
        },
        on_error: Default::default(),
        max_concurrent: 2,
        busy_retry_after_ms: 1_000,
        adapter: FilterAdapterConfig::OpenAiCompat {
            base_url: "http://127.0.0.1:11434/v1".to_string(),
            model: "qwen2.5:3b".to_string(),
            temperature: 0.0,
            max_output_tokens: 128,
            timeout_ms: 2_000,
            max_input_chars: 4096,
            min_allow_confidence: 0.75,
            api_key_secret: None,
            policy_notes: String::new(),
        },
    });
    sign_and_write_gate_config(&config_path, &secrets, updated_cfg);

    let rev_before = daemon.ui_rev();
    let reload_resp = rpc(daemon.socket_path(), &json!({ "type": "gate.reload" })).await;
    assert!(reload_resp.ok, "gate.reload failed: {reload_resp:?}");
    let r = reload_resp.result.unwrap();
    assert_eq!(r["reloaded"], true);
    assert_eq!(r["enabled"], true);
    assert_eq!(r["filterCount"], 1);
    assert_eq!(r["requireSignedPolicy"], true);
    assert!(daemon.ui_rev() > rev_before, "gate.reload must bump ui_rev");

    // 3. Immediately after reload (NO restart): `FORBIDDEN_SECRET_RULE` is BLOCKED!
    let res2 = daemon
        .ingest_inbound(InboundItem {
            session_id: "claude:live-gate".into(),
            origin_node: "bob@laptop".into(),
            item_id: "msg-after-reload-blocked".into(),
            source: "bob@laptop/dev".into(),
            text: "please run FORBIDDEN_SECRET_RULE now".into(),
            kind: MailboxKind::Message,
            trust_tier: GateTrustTier::Peer,
        })
        .await
        .unwrap();
    assert!(
        res2.is_none(),
        "newly reloaded gate rule must immediately block matching inbound item"
    );
    assert_eq!(
        transport.snapshot().len(),
        1,
        "blocked item must never wake live transport"
    );

    // Verify immutable gate_audit recorded the Block decision.
    let blocked_rows = node
        .db()
        .local()
        .query_gate_audit(&GateAuditQuery {
            decision: Some(StoreGateDecision::Block),
            direction: None,
            session_id: Some("claude:live-gate".into()),
            since_ms: None,
            until_ms: None,
            limit: Some(10),
        })
        .unwrap();
    assert_eq!(blocked_rows.len(), 1);

    // 4. Shared LocalIngestServer also immediately enforces the newly reloaded gate rule!
    let ingest_receipt = send_local_ingest_event(
        ingest_srv.endpoint_path(),
        &json!({
            "type": hyp_proto::cloudevent::TYPE_SCHEDULED_MESSAGE_V1,
            "topic": "local.schedule",
            "data": { "text": "trigger FORBIDDEN_SECRET_RULE via ingest" }
        }),
    )
    .await
    .expect("send local ingest event");
    assert_eq!(
        ingest_receipt["ok"], false,
        "shared LocalIngestServer must enforce newly reloaded block rule: {ingest_receipt}"
    );
    assert_eq!(ingest_receipt["error"], "gate_blocked");

    // 5. Benign messages still pass cleanly and wake transport immediately!
    let res3 = daemon
        .ingest_inbound(InboundItem {
            session_id: "claude:live-gate".into(),
            origin_node: "bob@laptop".into(),
            item_id: "msg-after-reload-benign".into(),
            source: "bob@laptop/dev".into(),
            text: "benign engineering update".into(),
            kind: MailboxKind::Message,
            trust_tier: GateTrustTier::Peer,
        })
        .await
        .unwrap();
    assert!(res3.is_some());
    let deliveries = transport.wait_for_count(2, Duration::from_secs(2)).await;
    assert!(deliveries[1].0.contains("benign engineering update"));

    ingest_srv.stop().await;
    daemon.stop().await;
}

#[tokio::test]
async fn gate_reload_fail_closed_preserves_active_pipeline_on_tamper_downgrade_or_bad_config() {
    let tmp = TempDir::new().unwrap();
    let state_dir = tmp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap();
    let config_path = state_dir.join("node.json");

    let node = open_local_node("reload-tamper@box", &state_dir);
    let secrets = Arc::new(SecretStore::new(&state_dir, SecretBackend::File));
    let gate_db = Arc::new(Mutex::new(
        NodeDb::open(state_dir.join("node.sqlite")).unwrap(),
    ));

    // Initial locked, signed policy blocking `BLOCK_ME_ALWAYS`.
    let mut initial_cfg = SecurityGateConfig::default();
    initial_cfg
        .stage1
        .inbound_regex_denylist
        .push("BLOCK_ME_ALWAYS".to_string());
    initial_cfg.stage1.regex_deny_action = Stage1DenyAction::Block;
    let initial_signed = sign_and_write_gate_config(&config_path, &secrets, initial_cfg);
    let initial_pipeline = Arc::new(
        SecurityGatePipeline::new(
            initial_signed.clone(),
            Arc::clone(&gate_db),
            Some(Arc::clone(&secrets)),
        )
        .unwrap(),
    );

    let daemon = LocalDaemon::start(
        Arc::clone(&node),
        Some(initial_pipeline),
        LocalDaemonConfig::default(),
    )
    .await
    .expect("start LocalDaemon");

    // Case 0: Unconfigured reloader fails closed cleanly.
    let no_reloader_resp = rpc(daemon.socket_path(), &json!({ "type": "gate.reload" })).await;
    assert!(!no_reloader_resp.ok);
    assert!(
        no_reloader_resp
            .error
            .as_deref()
            .unwrap_or("")
            .contains("gate_reload_not_configured")
    );

    daemon.set_gate_reloader(make_disk_reloader(
        config_path.clone(),
        state_dir.clone(),
        Arc::clone(&gate_db),
    ));

    // Helper verifying `BLOCK_ME_ALWAYS` is still blocked by the preserved active pipeline.
    let assert_still_blocking = |idx: usize| {
        let daemon_ref = &daemon;
        async move {
            let res = daemon_ref
                .ingest_inbound(InboundItem {
                    session_id: "claude:sec".into(),
                    origin_node: "bob@laptop".into(),
                    item_id: format!("check-still-blocked-{idx}"),
                    source: "bob@laptop/dev".into(),
                    text: "attack BLOCK_ME_ALWAYS payload".into(),
                    kind: MailboxKind::Message,
                    trust_tier: GateTrustTier::Peer,
                })
                .await
                .unwrap();
            assert!(
                res.is_none(),
                "active pipeline MUST remain intact and block after failed reload #{idx}"
            );
        }
    };

    assert_still_blocking(0).await;

    // Mutation A: Flip 1 hex char in `policy_signature` on disk.
    let mut bad_sig_cfg = initial_signed.clone();
    let orig_sig = bad_sig_cfg.policy_signature.clone().unwrap();
    let flipped_last = if orig_sig.ends_with('a') { 'b' } else { 'a' };
    let mut mutated_sig = orig_sig[..orig_sig.len() - 1].to_string();
    mutated_sig.push(flipped_last);
    bad_sig_cfg.policy_signature = Some(mutated_sig);
    fs::write(
        &config_path,
        serde_json::to_string_pretty(&json!({ "gate": bad_sig_cfg })).unwrap(),
    )
    .unwrap();
    let resp_a = rpc(daemon.socket_path(), &json!({ "type": "gate.reload" })).await;
    assert!(!resp_a.ok, "1-bit flipped HMAC must fail closed");
    assert!(
        resp_a
            .error
            .as_deref()
            .unwrap_or("")
            .contains("gate_policy_tampered")
    );
    assert_still_blocking(1).await;

    // Mutation B: Remove denylist rule without re-signing.
    let mut tampered_rule_cfg = initial_signed.clone();
    tampered_rule_cfg.stage1.inbound_regex_denylist.clear();
    fs::write(
        &config_path,
        serde_json::to_string_pretty(&json!({ "gate": tampered_rule_cfg })).unwrap(),
    )
    .unwrap();
    let resp_b = rpc(daemon.socket_path(), &json!({ "type": "gate.reload" })).await;
    assert!(
        !resp_b.ok,
        "tampered rule without re-signing must fail closed"
    );
    assert!(
        resp_b
            .error
            .as_deref()
            .unwrap_or("")
            .contains("gate_policy_tampered")
    );
    assert_still_blocking(2).await;

    // Mutation C: Signature-stripping downgrade attack (`require_signed_policy: false, policy_signature: None`).
    let stripped_cfg = SecurityGateConfig {
        require_signed_policy: false,
        policy_signature: None,
        ..Default::default()
    };
    fs::write(
        &config_path,
        serde_json::to_string_pretty(&json!({ "gate": stripped_cfg })).unwrap(),
    )
    .unwrap();
    let resp_c = rpc(daemon.socket_path(), &json!({ "type": "gate.reload" })).await;
    assert!(
        !resp_c.ok,
        "downgrading a locked policy to unsigned via gate.reload MUST fail closed"
    );
    assert!(
        resp_c
            .error
            .as_deref()
            .unwrap_or("")
            .contains("gate_policy_tampered")
    );
    assert_still_blocking(3).await;

    // Mutation D: Invalid regex in `stage1.inbound_regex_denylist` and corrupted JSON.
    let mut bad_regex_cfg = SecurityGateConfig::default();
    bad_regex_cfg
        .stage1
        .inbound_regex_denylist
        .push("[unclosed-regex".to_string());
    sign_and_write_gate_config(&config_path, &secrets, bad_regex_cfg);
    let resp_d1 = rpc(daemon.socket_path(), &json!({ "type": "gate.reload" })).await;
    assert!(!resp_d1.ok, "invalid regex must fail closed");
    assert_still_blocking(4).await;

    fs::write(&config_path, "{ not valid json").unwrap();
    let resp_d2 = rpc(daemon.socket_path(), &json!({ "type": "gate.reload" })).await;
    assert!(!resp_d2.ok, "corrupted JSON must fail closed");
    assert_still_blocking(5).await;

    daemon.stop().await;
}

#[tokio::test]
async fn inbox_wake_immediately_delivers_approved_item_and_clears_quarantine_badges() {
    let tmp = TempDir::new().unwrap();
    let state_dir = tmp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap();

    let node = open_local_node("wake-quarantine@box", &state_dir);
    let secrets = Arc::new(SecretStore::new(&state_dir, SecretBackend::File));
    let gate_db = Arc::new(Mutex::new(
        NodeDb::open(state_dir.join("node.sqlite")).unwrap(),
    ));

    let mut gate_cfg = SecurityGateConfig::default();
    gate_cfg
        .stage1
        .inbound_regex_denylist
        .push("SUSPICIOUS_HOLD".to_string());
    gate_cfg.stage1.regex_deny_action = Stage1DenyAction::Quarantine;
    let pipeline = Arc::new(
        SecurityGatePipeline::new(gate_cfg, Arc::clone(&gate_db), Some(Arc::clone(&secrets)))
            .unwrap(),
    );

    let daemon = LocalDaemon::start(
        Arc::clone(&node),
        Some(pipeline),
        LocalDaemonConfig::default(),
    )
    .await
    .expect("start LocalDaemon");

    node.db()
        .local()
        .register_session("claude:idle-1", "{}", now_ms())
        .unwrap();
    let transport = RecordingTransport::new();
    daemon.register_session_transport("claude:idle-1", transport.clone());

    // 1. Ingest two quarantined items for `claude:idle-1`.
    for (id, body) in [
        ("q-approve-1", "SUSPICIOUS_HOLD please review PR #42"),
        ("q-reject-2", "SUSPICIOUS_HOLD spam payload"),
    ] {
        let out = daemon
            .ingest_inbound(InboundItem {
                session_id: "claude:idle-1".into(),
                origin_node: "ext@peer".into(),
                item_id: id.into(),
                source: "ext@peer/sender".into(),
                text: body.into(),
                kind: MailboxKind::Message,
                trust_tier: GateTrustTier::Peer,
            })
            .await
            .unwrap();
        assert!(out.is_none(), "item {id} must be quarantined");
    }
    assert!(
        transport.snapshot().is_empty(),
        "quarantined items must NEVER wake transport"
    );

    // Verify `session.summary` AND `ui/state.json` both show 2 quarantined items.
    let summary_before = rpc(
        daemon.socket_path(),
        &json!({ "type": "session.summary", "sessionId": "claude:idle-1", "detail": "compact" }),
    )
    .await;
    assert!(summary_before.ok);
    let sb = summary_before.result.unwrap();
    assert_eq!(sb["session"]["counts"]["quarantined"], 2);
    assert_eq!(sb["daemon"]["quarantinedGlobal"], 2);

    let ui_before = wait_for_ui_state_rev(&daemon.ui_state_path(), daemon.ui_rev()).await;
    assert_eq!(ui_before["daemon"]["quarantinedGlobal"], 2);

    let quarantined = node
        .db()
        .local()
        .list_quarantined(Some("claude:idle-1"), 10)
        .unwrap();
    assert_eq!(quarantined.len(), 2);
    let approve_receipt = quarantined
        .iter()
        .find(|e| e.text.contains("PR #42"))
        .unwrap()
        .receipt
        .clone();
    let reject_receipt = quarantined
        .iter()
        .find(|e| e.text.contains("spam payload"))
        .unwrap()
        .receipt
        .clone();

    // 2. Simulate `hyp inbox approve <approve_receipt>` updating SQLite out-of-band,
    //    then calling `inbox.wake` with ONLY `receipt` (verifying receipt -> sessionId lookup!).
    let external_db = NodeDb::open(state_dir.join("node.sqlite")).unwrap();
    external_db
        .local()
        .approve_quarantined(&approve_receipt, "human-cli", now_ms())
        .unwrap();
    drop(external_db);

    let wake_resp = rpc(
        daemon.socket_path(),
        &json!({ "type": "inbox.wake", "receipt": approve_receipt }),
    )
    .await;
    assert!(wake_resp.ok, "inbox.wake failed: {wake_resp:?}");
    let wr = wake_resp.result.unwrap();
    assert_eq!(wr["woken"], true);
    assert_eq!(wr["sessionId"], "claude:idle-1");
    assert_eq!(wr["quarantinedRemaining"], 1);
    assert_eq!(wr["quarantinedGlobal"], 1);
    let wake_rev = wr["rev"].as_u64().unwrap();

    // Attached PushTransport MUST have received the approved message immediately (NO restart!).
    let deliveries = transport.wait_for_count(1, Duration::from_secs(2)).await;
    assert!(
        deliveries[0]
            .0
            .contains("SUSPICIOUS_HOLD please review PR #42"),
        "expected approved body in delivery, got: {}",
        deliveries[0].0
    );

    // `session.summary` AND `ui/state.json` must immediately reflect quarantined=1.
    let summary_mid = rpc(
        daemon.socket_path(),
        &json!({ "type": "session.summary", "sessionId": "claude:idle-1", "detail": "compact" }),
    )
    .await;
    let sm = summary_mid.result.unwrap();
    assert_eq!(sm["session"]["counts"]["quarantined"], 1);
    assert_eq!(sm["daemon"]["quarantinedGlobal"], 1);

    let ui_mid = wait_for_ui_state_rev(&daemon.ui_state_path(), wake_rev).await;
    assert_eq!(ui_mid["daemon"]["quarantinedGlobal"], 1);

    // 3. Simulate `hyp inbox reject <reject_receipt>` updating SQLite out-of-band, then `inbox.wake`.
    let external_db = NodeDb::open(state_dir.join("node.sqlite")).unwrap();
    external_db
        .local()
        .reject_quarantined(&reject_receipt, "human-cli", "spam", None, now_ms())
        .unwrap();
    drop(external_db);

    let rej_wake = rpc(
        daemon.socket_path(),
        &json!({
            "type": "inbox.wake",
            "sessionId": "claude:idle-1",
            "receipt": reject_receipt
        }),
    )
    .await;
    assert!(rej_wake.ok);
    let rw = rej_wake.result.unwrap();
    assert_eq!(rw["woken"], false, "rejected item must not wake transport");
    assert_eq!(rw["sessionId"], "claude:idle-1");
    assert_eq!(rw["quarantinedRemaining"], 0);
    assert_eq!(rw["quarantinedGlobal"], 0);
    let rej_rev = rw["rev"].as_u64().unwrap();

    assert_eq!(
        transport.snapshot().len(),
        1,
        "rejected item must never be delivered"
    );

    let summary_after = rpc(
        daemon.socket_path(),
        &json!({ "type": "session.summary", "sessionId": "claude:idle-1", "detail": "compact" }),
    )
    .await;
    let sa = summary_after.result.unwrap();
    assert_eq!(sa["session"]["counts"]["quarantined"], 0);
    assert_eq!(sa["daemon"]["quarantinedGlobal"], 0);

    let ui_after = wait_for_ui_state_rev(&daemon.ui_state_path(), rej_rev).await;
    assert_eq!(ui_after["daemon"]["quarantinedGlobal"], 0);
    let ui_sess = ui_after["sessions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["sessionId"] == "claude:idle-1")
        .unwrap();
    assert_eq!(ui_sess["counts"]["quarantined"], 0);

    daemon.stop().await;
}

#[tokio::test]
async fn cross_os_tcp_loopback_parity_for_gate_reload_and_inbox_wake() {
    let tmp = TempDir::new().unwrap();
    let state_dir = tmp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap();
    let config_path = state_dir.join("node.json");
    let addr_file = state_dir.join("connector.addr");

    let node = open_local_node("tcp-parity@box", &state_dir);
    let secrets = Arc::new(SecretStore::new(&state_dir, SecretBackend::File));
    let gate_db = Arc::new(Mutex::new(
        NodeDb::open(state_dir.join("node.sqlite")).unwrap(),
    ));

    let init_cfg =
        sign_and_write_gate_config(&config_path, &secrets, SecurityGateConfig::default());
    let init_pipe = Arc::new(
        SecurityGatePipeline::new(init_cfg, Arc::clone(&gate_db), Some(Arc::clone(&secrets)))
            .unwrap(),
    );

    let daemon = LocalDaemon::start_tcp(
        Arc::clone(&node),
        Some(init_pipe),
        LocalDaemonConfig::default(),
        addr_file.clone(),
    )
    .await
    .expect("start_tcp LocalDaemon");
    daemon.set_gate_reloader(make_disk_reloader(
        config_path.clone(),
        state_dir.clone(),
        Arc::clone(&gate_db),
    ));

    node.db()
        .local()
        .register_session("claude:tcp-1", "{}", now_ms())
        .unwrap();
    let transport = RecordingTransport::new();
    daemon.register_session_transport("claude:tcp-1", transport.clone());

    // Hot-reload over loopback TCP (`connector.addr`) to quarantine `TCP_HOLD_TOKEN`.
    let mut new_cfg = SecurityGateConfig::default();
    new_cfg
        .stage1
        .inbound_regex_denylist
        .push("TCP_HOLD_TOKEN".to_string());
    new_cfg.stage1.regex_deny_action = Stage1DenyAction::Quarantine;
    sign_and_write_gate_config(&config_path, &secrets, new_cfg);

    let rel = rpc(&addr_file, &json!({ "type": "gate.reload" })).await;
    assert!(rel.ok, "TCP gate.reload failed: {rel:?}");
    assert_eq!(rel.result.unwrap()["reloaded"], true);

    let ing = daemon
        .ingest_inbound(InboundItem {
            session_id: "claude:tcp-1".into(),
            origin_node: "ext@peer".into(),
            item_id: "tcp-q1".into(),
            source: "ext@peer/bot".into(),
            text: "hello TCP_HOLD_TOKEN from remote".into(),
            kind: MailboxKind::Message,
            trust_tier: GateTrustTier::Peer,
        })
        .await
        .unwrap();
    assert!(ing.is_none());

    let receipt = node
        .db()
        .local()
        .list_quarantined(Some("claude:tcp-1"), 5)
        .unwrap()[0]
        .receipt
        .clone();
    node.db()
        .local()
        .approve_quarantined(&receipt, "human-cli", now_ms())
        .unwrap();

    let wake = rpc(
        &addr_file,
        &json!({ "type": "inbox.wake", "receipt": receipt }),
    )
    .await;
    assert!(wake.ok, "TCP inbox.wake failed: {wake:?}");
    let wr = wake.result.unwrap();
    assert_eq!(wr["woken"], true);
    assert_eq!(wr["sessionId"], "claude:tcp-1");
    assert_eq!(wr["quarantinedRemaining"], 0);

    let deliveries = transport.wait_for_count(1, Duration::from_secs(2)).await;
    assert!(deliveries[0].0.contains("TCP_HOLD_TOKEN"));

    daemon.stop().await;
}
