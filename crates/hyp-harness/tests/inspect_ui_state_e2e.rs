//! Comprehensive differential, security, streaming, and regression E2E tests for v0.6.0
//! Stream A backend & IPC foundations:
//! 1. McKeeman Reference-Model Differential Test comparing:
//!    - Pure in-memory reference model,
//!    - `session.summary` RPC (`full` and `compact`),
//!    - `sessions.summary` batch RPC, and
//!    - Debounced atomic `<state_dir>/ui/state.json` on disk (`0700` dir / `0600` file on Unix),
//!      while proving ZERO untrusted body / quarantined payload leakage!
//! 2. Backend merge regression (`session.hint` -> bare `register_session` / `call.start`) +
//!    daemon restart hydration of `herdr_terminal_index` from SQLite.
//! 3. Herdr anti-recycle guard (`herdrCreatedMs` mismatch fails closed) + sequential session ranking.
//! 4. Ownership & validation fail-closed security tests (`session.unsubscribe` cross-session
//!    rejection, invalid urgency/patterns/sessionId/herdrTerminalId, non-blocking read-only summary).
//! 5. Live streaming `inspect.watch` push notifications & clean EOF disconnect.
//! 6. `wait.subscribe` resolution via `herdrTerminalId`.
//! 7. Cross-platform loopback TCP (`LocalDaemon::start_tcp`) parity.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hyp_crypto::SecretBackend;
use hyp_harness::daemon::{InboundItem, LocalDaemon, LocalDaemonConfig, UI_STATE_SCHEMA_VERSION};
use hyp_harness::sock::{
    MAX_SOCKET_LINE_BYTES, connect_daemon_async, daemon_rpc_async, read_bounded_line_async,
    write_ndjson_line_async,
};
use hyp_harness::transport::PushTransport;
use hyp_harness::transport::herdr::{HerdrTarget, HerdrTransport};
use hyp_node::engine::{NodeConfig, SubscribeRequest, TopicConfig, UnifiedNode};
use hyp_node::gates::TrustTier as GateTrustTier;
use hyp_proto::address::NodeId;
use hyp_proto::filter::Filter as ProtoFilter;
use hyp_store::{DeliveryMode, GateState, MailboxInsert, MailboxKind, now_ms};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::io::BufReader;

fn make_local_node(node_id: &str, dir: &TempDir) -> Arc<UnifiedNode> {
    hyp_harness::enable_test_env_isolation();
    let mut cfg = NodeConfig::local(NodeId::new(node_id).unwrap(), dir.path());
    cfg.secret_backend = Some(SecretBackend::File);
    cfg.topics.push(TopicConfig {
        topic: "github".into(),
        kind: Some("github-webhook".into()),
        description: Some("Local GitHub webhook stream".into()),
        metadata: None,
        has_provisioned_publisher: true,
    });
    cfg.topics.push(TopicConfig {
        topic: "alerts".into(),
        kind: Some("prometheus".into()),
        description: Some("Local alerts".into()),
        metadata: None,
        has_provisioned_publisher: true,
    });
    UnifiedNode::open(cfg).expect("open local UnifiedNode")
}

async fn rpc(sock: &Path, pkt: Value) -> hyp_harness::sock::DaemonRpcResult {
    daemon_rpc_async(sock, &pkt, Duration::from_secs(3)).await
}

/// Polls `<state_dir>/ui/state.json` until `rev >= min_rev` (bounded at 2s) to verify the
/// 100 ms debounced atomic projector converges cleanly.
async fn wait_for_ui_state_rev(path: &Path, min_rev: u64) -> Value {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if let Ok(raw) = std::fs::read_to_string(path) {
            let normalized = raw.replace("\r\n", "\n");
            if let Ok(val) = serde_json::from_str::<Value>(&normalized) {
                if val.get("rev").and_then(Value::as_u64).unwrap_or(0) >= min_rev {
                    return val;
                }
            }
        }
        if Instant::now() >= deadline {
            let current = std::fs::read_to_string(path).unwrap_or_else(|_| "<missing>".into());
            panic!(
                "timed out waiting for {} to reach rev >= {min_rev}; current={current}",
                path.display()
            );
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Pure in-memory McKeeman reference model tracking expected observable summary fields for each session.
#[derive(Debug, Clone, Default)]
struct RefSessionModel {
    harness: String,
    handle: Option<String>,
    herdr_terminal_id: Option<String>,
    herdr_created_ms: Option<i64>,
    focus_mode: bool,
    focus_allow_vips: bool,
    delivery_mode: String,
    subscriptions: BTreeMap<String, (String, String, String, i64)>, // id -> (topic, origin, mode, coalesce)
    pending_items: Vec<(String, String)>,                           // (kind, source)
    quarantined: usize,
    muted_archived: usize,
    session_mutes: BTreeSet<String>,
    rules: BTreeMap<String, String>, // target -> delivery
    channels: BTreeSet<String>,
}

#[derive(Debug, Default)]
struct RefWorldModel {
    node_id: String,
    global_mutes: BTreeSet<String>,
    sessions: BTreeMap<String, RefSessionModel>,
}

impl RefWorldModel {
    fn new(node_id: &str) -> Self {
        Self {
            node_id: node_id.to_string(),
            global_mutes: BTreeSet::new(),
            sessions: BTreeMap::new(),
        }
    }

    fn quarantined_global(&self) -> usize {
        self.sessions.values().map(|s| s.quarantined).sum()
    }

    fn assert_session_matches(&self, session_id: &str, actual: &Value, expect_details: bool) {
        let m = self
            .sessions
            .get(session_id)
            .unwrap_or_else(|| panic!("missing ref model for {session_id}"));
        assert_eq!(actual["sessionId"], session_id);
        assert_eq!(actual["harness"], m.harness);
        assert_eq!(actual["enrolled"], m.handle.is_some());
        assert_eq!(actual["handle"].as_str(), m.handle.as_deref());
        let expected_addr = m.handle.as_deref().map(|h| format!("{}/{h}", self.node_id));
        assert_eq!(actual["address"].as_str(), expected_addr.as_deref());
        assert_eq!(
            actual["herdrTerminalId"].as_str(),
            m.herdr_terminal_id.as_deref()
        );
        assert_eq!(actual["herdrCreatedMs"].as_i64(), m.herdr_created_ms);
        assert_eq!(actual["focusMode"], m.focus_mode);
        assert_eq!(actual["focusAllowInterruptVips"], m.focus_allow_vips);
        assert_eq!(actual["deliveryMode"], m.delivery_mode);

        let expected_muted_rules = m.session_mutes.len() + self.global_mutes.len();
        let expected_muted_all = m.session_mutes.contains("*")
            || self.global_mutes.contains("*")
            || m.rules.get("*").map(String::as_str) == Some("mute");
        assert_eq!(actual["mutedAll"], expected_muted_all);

        let counts = &actual["counts"];
        assert_eq!(counts["subscriptions"], m.subscriptions.len());
        assert_eq!(counts["queued"], m.pending_items.len());
        assert_eq!(counts["quarantined"], m.quarantined);
        assert_eq!(counts["mutedRules"], expected_muted_rules);
        assert_eq!(counts["mutedArchived"], m.muted_archived);
        assert_eq!(counts["channels"], m.channels.len());
        assert!(counts.get("wakeups").is_none());
        assert!(actual["details"].get("wakeups").is_none());

        let ub = &actual["unreadBreakdown"];
        let count_kind = |k: &str| m.pending_items.iter().filter(|(kind, _)| kind == k).count();
        assert_eq!(ub["messages"], count_kind("message"));
        assert_eq!(ub["events"], count_kind("event"));
        assert_eq!(ub["plugins"], count_kind("plugin"));
        assert_eq!(ub["transfers"], count_kind("transfer"));
        assert_eq!(ub["kv"], count_kind("kv"));

        if !expect_details {
            assert!(
                actual.get("details").is_none(),
                "compact summary must omit details"
            );
            return;
        }

        let details = actual
            .get("details")
            .expect("full summary must include details");
        assert_eq!(
            details["subscriptions"].as_array().unwrap().len(),
            m.subscriptions.len()
        );
        assert_eq!(
            details["queuedItems"].as_array().unwrap().len(),
            m.pending_items.len()
        );
        for qi in details["queuedItems"].as_array().unwrap() {
            let obj = qi.as_object().unwrap();
            assert!(
                !obj.contains_key("text"),
                "queuedItem MUST NOT contain text"
            );
            assert!(
                !obj.contains_key("body"),
                "queuedItem MUST NOT contain body"
            );
            assert!(
                !obj.contains_key("data"),
                "queuedItem MUST NOT contain data"
            );
            assert!(obj.contains_key("receipt"));
            assert!(obj.contains_key("kind"));
            assert!(obj.contains_key("source"));
            assert!(obj.contains_key("originNode"));
            assert!(obj.contains_key("receivedAt"));
            assert!(obj.contains_key("notified"));
            assert!(obj.contains_key("urgency"));
        }

        let actual_channels: BTreeSet<String> = details["channels"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .map(ToString::to_string)
            .collect();
        assert_eq!(actual_channels, m.channels);

        let actual_rules: BTreeMap<String, String> = details["rules"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| {
                (
                    r["target"].as_str().unwrap().to_string(),
                    r["delivery"].as_str().unwrap().to_string(),
                )
            })
            .collect();
        assert_eq!(actual_rules, m.rules);

        let actual_mutes: BTreeSet<(String, String)> = details["mutes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| {
                (
                    r["scope"].as_str().unwrap().to_string(),
                    r["pattern"].as_str().unwrap().to_string(),
                )
            })
            .collect();
        let mut expected_mutes: BTreeSet<(String, String)> = BTreeSet::new();
        for p in &m.session_mutes {
            expected_mutes.insert(("session".to_string(), p.clone()));
        }
        for p in &self.global_mutes {
            expected_mutes.insert(("connector".to_string(), p.clone()));
        }
        assert_eq!(actual_mutes, expected_mutes);
    }
}

fn assert_no_sentinels(label: &str, val: &Value, sentinels: &[&str]) {
    let serialized = serde_json::to_string(val).unwrap();
    for s in sentinels {
        assert!(
            !serialized.contains(s),
            "SECURITY VIOLATION: {label} leaked untrusted sentinel {s:?} in payload: {serialized}"
        );
    }
}

async fn assert_all_four_oracles_agree(
    model: &RefWorldModel,
    daemon: &LocalDaemon,
    session_ids: &[&str],
    sentinels: &[&str],
) {
    let sock = daemon.socket_path();
    let expected_rev = daemon.ui_rev();

    // Oracle 2 & 3: `sessions.summary` batch RPC
    let batch_res = rpc(sock, json!({ "type": "sessions.summary" })).await;
    assert!(
        batch_res.ok,
        "sessions.summary failed: {:?}",
        batch_res.error
    );
    let batch = Value::Object(batch_res.result.unwrap());
    assert_eq!(batch["schemaVersion"], UI_STATE_SCHEMA_VERSION);
    assert_eq!(batch["daemon"]["online"], true);
    assert_eq!(batch["daemon"]["nodeId"], model.node_id);
    assert_eq!(
        batch["daemon"]["quarantinedGlobal"],
        model.quarantined_global()
    );
    assert_no_sentinels("sessions.summary", &batch, sentinels);

    // Oracle 4: Atomic `<state_dir>/ui/state.json` on disk
    let ui_state = wait_for_ui_state_rev(&daemon.ui_state_path(), expected_rev).await;
    assert_eq!(ui_state["schemaVersion"], UI_STATE_SCHEMA_VERSION);
    assert_eq!(ui_state["daemon"]["nodeId"], model.node_id);
    assert_eq!(
        ui_state["daemon"]["quarantinedGlobal"],
        model.quarantined_global()
    );
    assert_eq!(ui_state["byHerdrTerminal"], batch["byHerdrTerminal"]);
    assert_no_sentinels("ui/state.json", &ui_state, sentinels);

    for &sid in session_ids {
        // Oracle 2a: `session.summary` (full)
        let single_res = rpc(
            sock,
            json!({ "type": "session.summary", "sessionId": sid, "detail": "full" }),
        )
        .await;
        assert!(single_res.ok);
        let single = Value::Object(single_res.result.unwrap());
        assert_no_sentinels("session.summary(full)", &single, sentinels);
        model.assert_session_matches(sid, &single["session"], true);

        // Oracle 2b: `session.summary` (compact)
        let compact_res = rpc(
            sock,
            json!({ "type": "session.summary", "sessionId": sid, "detail": "compact" }),
        )
        .await;
        assert!(compact_res.ok);
        let compact = Value::Object(compact_res.result.unwrap());
        assert_no_sentinels("session.summary(compact)", &compact, sentinels);
        model.assert_session_matches(sid, &compact["session"], false);

        // Exact cross-oracle parity: single == batch == ui/state.json!
        let from_batch = batch["sessions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["sessionId"] == sid)
            .expect("session present in sessions.summary");
        let from_disk = ui_state["sessions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["sessionId"] == sid)
            .expect("session present in ui/state.json");
        assert_eq!(
            &single["session"], from_batch,
            "session.summary and sessions.summary diverged for {sid}"
        );
        assert_eq!(
            from_batch, from_disk,
            "sessions.summary and ui/state.json diverged for {sid}"
        );
    }
}

#[tokio::test]
async fn mckeeman_reference_model_differential_parity_and_zero_body_leakage() {
    let dir = TempDir::new().unwrap();
    let node = make_local_node("alice@macbook", &dir);
    let daemon = LocalDaemon::start(Arc::clone(&node), None, LocalDaemonConfig::default())
        .await
        .expect("start LocalDaemon");
    let sock = daemon.socket_path();

    // Verify immediate initial `ui/state.json` exists on startup with strict Unix permissions!
    assert!(
        daemon.ui_state_path().is_file(),
        "initial ui/state.json must be written on daemon startup"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let ui_dir = daemon.ui_state_path().parent().unwrap().to_path_buf();
        let dir_mode = std::fs::metadata(&ui_dir).unwrap().permissions().mode() & 0o777;
        let file_mode = std::fs::metadata(daemon.ui_state_path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700, "<state_dir>/ui must be 0700");
        assert_eq!(file_mode, 0o600, "<state_dir>/ui/state.json must be 0600");
    }

    let sentinels = [
        "SENTINEL_DM_SECRET_BODY_9911",
        "SENTINEL_EVENT_PAYLOAD_8822",
        "SENTINEL_BRIDGE_BODY_7733",
        "SENTINEL_QUARANTINED_TEXT_6644",
        "SENTINEL_QUARANTINED_SOURCE_5555",
    ];

    let mut model = RefWorldModel::new("alice@macbook");

    // Step 1: Register two sessions via `session.hint` with Herdr terminal pins.
    let s1 = "claude:diff-s1";
    let s2 = "codex:diff-s2";
    assert!(
        rpc(
            sock,
            json!({
                "type": "session.hint",
                "harness": "claude",
                "sessionId": s1,
                "herdrTerminalId": "t4g",
                "herdrCreatedMs": 1_750_000_000_000i64,
                "cwd": "/work/hyphae"
            })
        )
        .await
        .ok
    );
    assert!(
        rpc(
            sock,
            json!({
                "type": "session.hint",
                "harness": "codex",
                "sessionId": s2,
                "herdrTerminalId": "t9k",
                "herdrCreatedMs": 1_750_000_009_000i64
            })
        )
        .await
        .ok
    );
    model.sessions.insert(
        s1.into(),
        RefSessionModel {
            harness: "claude".into(),
            herdr_terminal_id: Some("t4g".into()),
            herdr_created_ms: Some(1_750_000_000_000),
            delivery_mode: "queue".into(),
            focus_allow_vips: true,
            ..Default::default()
        },
    );
    model.sessions.insert(
        s2.into(),
        RefSessionModel {
            harness: "codex".into(),
            herdr_terminal_id: Some("t9k".into()),
            herdr_created_ms: Some(1_750_000_009_000),
            delivery_mode: "queue".into(),
            focus_allow_vips: true,
            ..Default::default()
        },
    );
    assert_all_four_oracles_agree(&model, &daemon, &[s1, s2], &sentinels).await;

    // Step 2: Join handles & channels.
    node.register_handle(s1, "alice").await.unwrap();
    node.register_handle(s2, "reviewer").await.unwrap();
    node.join_channel("#ops", "alice").await.unwrap();
    node.join_channel("#release", "alice").await.unwrap();
    model.sessions.get_mut(s1).unwrap().handle = Some("alice".into());
    model.sessions.get_mut(s2).unwrap().handle = Some("reviewer".into());
    model
        .sessions
        .get_mut(s1)
        .unwrap()
        .channels
        .extend(["#ops".to_string(), "#release".to_string()]);

    // Step 3: Subscribe s1 to `local.github` with a CloudEvents filter.
    let sub = node
        .subscribe_local_or_remote(SubscribeRequest {
            id: Some("sub-gh-1".into()),
            subscriber_session: s1.into(),
            qualified_topic: "local.github".into(),
            filters: vec![ProtoFilter::Exact(BTreeMap::from([(
                "type".to_string(),
                "pr.review_requested".to_string(),
            )]))],
            coalesce_seconds: 15,
            mode: DeliveryMode::Full,
        })
        .await
        .unwrap();
    model.sessions.get_mut(s1).unwrap().subscriptions.insert(
        sub.subscription.id.clone(),
        ("github".into(), "alice@macbook".into(), "queue".into(), 15),
    );

    // Step 5: Ingest unread items of multiple kinds + one quarantined item with secret sentinels!
    daemon
        .ingest_inbound(InboundItem {
            session_id: s1.into(),
            origin_node: "bob@laptop".into(),
            item_id: "dm-1".into(),
            source: "bob@laptop/dev".into(),
            text: "SENTINEL_DM_SECRET_BODY_9911".into(),
            kind: MailboxKind::Message,
            trust_tier: GateTrustTier::Peer,
        })
        .await
        .unwrap();
    daemon
        .ingest_inbound(InboundItem {
            session_id: s1.into(),
            origin_node: "alice@macbook".into(),
            item_id: "ev-1".into(),
            source: "alice@macbook.github".into(),
            text: "SENTINEL_EVENT_PAYLOAD_8822".into(),
            kind: MailboxKind::Event,
            trust_tier: GateTrustTier::SelfHost,
        })
        .await
        .unwrap();
    daemon
        .ingest_inbound(InboundItem {
            session_id: s1.into(),
            origin_node: "bridge:slack".into(),
            item_id: "br-1".into(),
            source: "slack:ops".into(),
            text: "SENTINEL_BRIDGE_BODY_7733".into(),
            kind: MailboxKind::Plugin,
            trust_tier: GateTrustTier::Bridge,
        })
        .await
        .unwrap();
    node.db()
        .local()
        .put_in_mailbox(
            &MailboxInsert {
                session_id: s1.into(),
                origin_node: "untrusted@net".into(),
                item_id: "q-1".into(),
                text: "SENTINEL_QUARANTINED_TEXT_6644".into(),
                kind: MailboxKind::Message,
                source: "SENTINEL_QUARANTINED_SOURCE_5555".into(),
                gate_state: GateState::Quarantined,
                gate_reason: Some("prompt_injection".into()),
                traceparent: None,
            },
            now_ms(),
        )
        .unwrap();
    {
        let m1 = model.sessions.get_mut(s1).unwrap();
        m1.pending_items
            .push(("message".into(), "bob@laptop/dev".into()));
        m1.pending_items
            .push(("event".into(), "alice@macbook.github".into()));
        m1.pending_items.push(("plugin".into(), "slack:ops".into()));
        m1.quarantined = 1;
    }

    // Step 6: Toggle Focus Mode, add session mute, global mute, and delivery rules via quick-control RPCs!
    let focus_res = rpc(
        sock,
        json!({ "type": "session.focus", "herdrTerminalId": "t4g", "enabled": true, "allowVips": true }),
    )
    .await;
    assert!(focus_res.ok, "session.focus failed: {:?}", focus_res.error);
    {
        let m1 = model.sessions.get_mut(s1).unwrap();
        m1.focus_mode = true;
        m1.focus_allow_vips = true;
        m1.delivery_mode = "notify".into();
    }

    let mute_res = rpc(
        sock,
        json!({ "type": "session.mute", "sessionId": s1, "source": "#noisy-ci" }),
    )
    .await;
    assert!(mute_res.ok);
    model
        .sessions
        .get_mut(s1)
        .unwrap()
        .session_mutes
        .insert("#noisy-ci".into());
    model
        .sessions
        .get_mut(s1)
        .unwrap()
        .rules
        .insert("#noisy-ci".into(), "mute".into());

    let global_mute = rpc(sock, json!({ "type": "mute.add", "target": "spam/*" })).await;
    assert!(global_mute.ok);
    model.global_mutes.insert("spam/*".into());

    let rule_res = rpc(
        sock,
        json!({ "type": "session.rule", "sessionId": s1, "source": "bob@laptop/dev", "urgency": "interrupt" }),
    )
    .await;
    assert!(rule_res.ok);
    model
        .sessions
        .get_mut(s1)
        .unwrap()
        .rules
        .insert("bob@laptop/dev".into(), "interrupt".into());

    // Ingest a muted message -> must archive silently (`mutedArchived == 1`, NOT increase `queued`).
    daemon
        .ingest_inbound(InboundItem {
            session_id: s1.into(),
            origin_node: "alice@macbook".into(),
            item_id: "muted-1".into(),
            source: "alice@macbook/#noisy-ci:ci@host/bot".into(),
            text: "noisy ci log".into(),
            kind: MailboxKind::Message,
            trust_tier: GateTrustTier::Peer,
        })
        .await
        .unwrap();
    model.sessions.get_mut(s1).unwrap().muted_archived = 1;

    assert_all_four_oracles_agree(&model, &daemon, &[s1, s2], &sentinels).await;

    // Verify filterSummary rendered cleanly on s1's subscription.
    let s1_sum = rpc(sock, json!({ "type": "session.summary", "sessionId": s1 })).await;
    let s1_subs = s1_sum.result.unwrap()["session"]["details"]["subscriptions"]
        .as_array()
        .unwrap()
        .clone();
    assert_eq!(s1_subs[0]["filterSummary"], "type=pr.review_requested");

    // Step 7: Mutate via unmute, rule removal, leave_channel, unsubscribe, and mailbox drain!
    assert!(
        rpc(
            sock,
            json!({ "type": "session.unmute", "sessionId": s1, "source": "#noisy-ci" })
        )
        .await
        .ok
    );
    model
        .sessions
        .get_mut(s1)
        .unwrap()
        .session_mutes
        .remove("#noisy-ci");
    model
        .sessions
        .get_mut(s1)
        .unwrap()
        .rules
        .remove("#noisy-ci");

    assert!(
        rpc(
            sock,
            json!({ "type": "session.rule", "sessionId": s1, "source": "bob@laptop/dev", "remove": true })
        )
        .await
        .ok
    );
    model
        .sessions
        .get_mut(s1)
        .unwrap()
        .rules
        .remove("bob@laptop/dev");

    assert!(
        rpc(
            sock,
            json!({ "type": "session.leave_channel", "herdrTerminalId": "t4g", "channel": "#release" })
        )
        .await
        .ok
    );
    model
        .sessions
        .get_mut(s1)
        .unwrap()
        .channels
        .remove("#release");

    assert!(
        rpc(
            sock,
            json!({ "type": "session.unsubscribe", "sessionId": s1, "subscriptionId": "sub-gh-1" })
        )
        .await
        .ok
    );
    model
        .sessions
        .get_mut(s1)
        .unwrap()
        .subscriptions
        .remove("sub-gh-1");

    // Exit Focus Mode, then drain pending items.
    assert!(
        rpc(
            sock,
            json!({ "type": "session.focus", "sessionId": s1, "enabled": false })
        )
        .await
        .ok
    );
    {
        let m1 = model.sessions.get_mut(s1).unwrap();
        m1.focus_mode = false;
        m1.delivery_mode = "queue".into();
    }
    let drain_res = rpc(sock, json!({ "type": "mailbox.drain", "sessionId": s1 })).await;
    assert!(drain_res.ok);
    // RFC 0004: `mailbox.drain` emits a metadata-only `<hyphae-inbox>` XML digest and marks rows
    // `notified = 1` WITHOUT acknowledging them as delivered — all 3 items stay unread (`queued`)
    // until explicitly read/acked via `hyp_inbox`!
    assert_all_four_oracles_agree(&model, &daemon, &[s1, s2], &sentinels).await;

    // Now acknowledge the 3 unread items (matching `hyp_inbox` default `ack: true`) and confirm
    // all four oracles drop to 0 queued!
    {
        let db = node.db();
        let ids: Vec<String> = db
            .local()
            .peek_inbox(s1, 20)
            .unwrap()
            .into_iter()
            .map(|e| e.receipt)
            .collect();
        let refs: Vec<&str> = ids.iter().map(String::as_str).collect();
        db.local().acknowledge_inbox(s1, &refs, now_ms()).unwrap();
    }
    let _ = rpc(sock, json!({ "type": "inbox.wake", "sessionId": s1 })).await;
    model.sessions.get_mut(s1).unwrap().pending_items.clear();

    assert_all_four_oracles_agree(&model, &daemon, &[s1, s2], &sentinels).await;

    daemon.stop().await;
}

#[tokio::test]
async fn backend_merge_preserves_herdr_terminal_and_hydrates_on_restart() {
    let dir = TempDir::new().unwrap();
    let node = make_local_node("alice@mac", &dir);
    let daemon1 = LocalDaemon::start(Arc::clone(&node), None, LocalDaemonConfig::default())
        .await
        .unwrap();
    let sock1 = daemon1.socket_path();

    // 1. session.hint sets herdrTerminalId + herdrCreatedMs.
    let hint_res = rpc(
        sock1,
        json!({
            "type": "session.hint",
            "harness": "claude",
            "sessionId": "claude:merge-1",
            "herdrTerminalId": "t4g",
            "herdrCreatedMs": 1_710_000_000_000i64
        }),
    )
    .await;
    assert!(hint_res.ok);

    // 2. Subsequent bare register_session AND call.start WITHOUT herdrTerminalId MUST preserve t4g!
    node.register_session("claude:merge-1", r#"{"kind":"claude"}"#)
        .unwrap();
    let call_res = rpc(
        sock1,
        json!({
            "type": "call.start",
            "harness": "claude",
            "sessionId": "claude:merge-1",
            "tool": "hyp_mesh",
            "callId": "tc-merge-1"
        }),
    )
    .await;
    assert!(call_res.ok);

    let sum1 = rpc(
        sock1,
        json!({ "type": "session.summary", "herdrTerminalId": "t4g" }),
    )
    .await;
    assert!(sum1.ok);
    let sess1 = &sum1.result.unwrap()["session"];
    assert_eq!(sess1["sessionId"], "claude:merge-1");
    assert_eq!(sess1["herdrTerminalId"], "t4g");
    assert_eq!(sess1["herdrCreatedMs"], 1_710_000_000_000i64);

    // 3. Restart LocalDaemon against the same SQLite DB -> herdr_terminal_index MUST hydrate!
    daemon1.stop().await;
    let daemon2 = LocalDaemon::start(Arc::clone(&node), None, LocalDaemonConfig::default())
        .await
        .unwrap();
    let sum2 = rpc(
        daemon2.socket_path(),
        json!({ "type": "session.summary", "herdrTerminalId": "t4g" }),
    )
    .await;
    assert!(sum2.ok);
    assert_eq!(
        sum2.result.unwrap()["session"]["sessionId"],
        "claude:merge-1"
    );

    // 4. Registering an explicit HerdrTransport also populates live transport & pinned created_ms.
    let mut target = HerdrTarget::new("t8z");
    target.created_ms = Some(1_720_000_000_000);
    node.register_session("claude:merge-2", r#"{"kind":"claude"}"#)
        .unwrap();
    daemon2.register_session_transport(
        "claude:merge-2",
        Arc::new(HerdrTransport::new(target)) as Arc<dyn PushTransport>,
    );
    let sum_t8z = rpc(
        daemon2.socket_path(),
        json!({
            "type": "session.summary",
            "herdrTerminalId": "t8z",
            "herdrCreatedMs": 1_720_000_000_000i64
        }),
    )
    .await;
    assert!(sum_t8z.ok);
    let sess_t8z = &sum_t8z.result.unwrap()["session"];
    assert_eq!(sess_t8z["sessionId"], "claude:merge-2");
    assert_eq!(sess_t8z["transportKind"], "herdr");
    assert_eq!(sess_t8z["hasLiveTransport"], true);
    assert_eq!(sess_t8z["herdrCreatedMs"], 1_720_000_000_000i64);

    daemon2.stop().await;
}

#[tokio::test]
async fn herdr_anti_recycle_guard_and_sequential_session_ranking() {
    let dir = TempDir::new().unwrap();
    let node = make_local_node("alice@mac", &dir);
    let daemon = LocalDaemon::start(Arc::clone(&node), None, LocalDaemonConfig::default())
        .await
        .unwrap();
    let sock = daemon.socket_path();

    // Session A ran in terminal t4g with created_ms = 1_000_000.
    node.db()
        .local()
        .merge_session_backend(
            "claude:old",
            &json!({
                "kind": "claude",
                "herdrTerminalId": "t4g",
                "herdrCreatedMs": 1_000_000i64
            }),
            1_000_100,
        )
        .unwrap();
    node.db()
        .local()
        .set_session_handle("claude:old", Some("oldbot"), 1_000_100)
        .unwrap();

    // Recycled terminal t4g now has created_ms = 2_000_000 -> MUST NOT return stale Session A!
    let stale_query = rpc(
        sock,
        json!({
            "type": "session.summary",
            "herdrTerminalId": "t4g",
            "herdrCreatedMs": 2_000_000i64
        }),
    )
    .await;
    assert!(stale_query.ok);
    assert!(
        stale_query.result.unwrap()["session"].is_null(),
        "mismatched herdrCreatedMs must fail closed and return session: null"
    );

    // Matching created_ms = 1_000_000 still resolves Session A.
    let old_query = rpc(
        sock,
        json!({
            "type": "session.summary",
            "herdrTerminalId": "t4g",
            "herdrCreatedMs": 1_000_000i64
        }),
    )
    .await;
    assert_eq!(
        old_query.result.unwrap()["session"]["sessionId"],
        "claude:old"
    );

    // Two sequential sessions in the SAME live recycled terminal (created_ms = 2_000_000):
    // newer last_seen (codex:seq2) beats older last_seen (claude:seq1).
    node.db()
        .local()
        .merge_session_backend(
            "claude:seq1",
            &json!({
                "kind": "claude",
                "herdrTerminalId": "t4g",
                "herdrCreatedMs": 2_000_000i64
            }),
            2_000_100,
        )
        .unwrap();
    node.db()
        .local()
        .merge_session_backend(
            "codex:seq2",
            &json!({
                "kind": "codex",
                "herdrTerminalId": "t4g",
                "herdrCreatedMs": 2_000_000i64
            }),
            2_000_500,
        )
        .unwrap();

    let new_query = rpc(
        sock,
        json!({
            "type": "session.summary",
            "herdrTerminalId": "t4g",
            "herdrCreatedMs": 2_000_000i64
        }),
    )
    .await;
    assert_eq!(
        new_query.result.unwrap()["session"]["sessionId"],
        "codex:seq2"
    );

    daemon.stop().await;
}

#[tokio::test]
async fn ownership_validation_and_malformed_inputs_fail_closed() {
    let dir = TempDir::new().unwrap();
    let node = make_local_node("alice@mac", &dir);
    let daemon = LocalDaemon::start(Arc::clone(&node), None, LocalDaemonConfig::default())
        .await
        .unwrap();
    let sock = daemon.socket_path();

    node.register_session("claude:owner-a", r#"{"kind":"claude"}"#)
        .unwrap();
    node.register_session("claude:other-b", r#"{"kind":"claude"}"#)
        .unwrap();

    let sub = node
        .subscribe_local_or_remote(SubscribeRequest {
            id: Some("sub-secret-a".into()),
            subscriber_session: "claude:owner-a".into(),
            qualified_topic: "local.github".into(),
            filters: vec![],
            coalesce_seconds: 0,
            mode: DeliveryMode::Full,
        })
        .await
        .unwrap();
    assert_eq!(sub.subscription.id, "sub-secret-a");

    // Cross-session unsubscribe MUST fail closed and leave sub intact!
    let steal = rpc(
        sock,
        json!({
            "type": "session.unsubscribe",
            "sessionId": "claude:other-b",
            "subscriptionId": "sub-secret-a"
        }),
    )
    .await;
    assert!(!steal.ok, "cross-session unsubscribe must fail closed");
    assert!(
        node.db()
            .events()
            .get_subscription("sub-secret-a")
            .unwrap()
            .is_some(),
        "subscription must remain intact after rejected cross-session unsubscribe"
    );

    // Owner unsubscribe succeeds cleanly.
    let legit = rpc(
        sock,
        json!({
            "type": "session.unsubscribe",
            "sessionId": "claude:owner-a",
            "subscriptionId": "sub-secret-a"
        }),
    )
    .await;
    assert!(legit.ok);
    assert!(
        node.db()
            .events()
            .get_subscription("sub-secret-a")
            .unwrap()
            .is_none()
    );

    // Invalid urgencies, patterns, IDs, scopes, and TTLs MUST fail closed!
    let invalid_packets = vec![
        json!({ "type": "session.rule", "sessionId": "claude:owner-a", "source": "bob/a", "urgency": "nuclear" }),
        json!({ "type": "session.rule", "sessionId": "claude:owner-a", "source": "", "urgency": "notify" }),
        json!({ "type": "session.rule", "sessionId": "claude:owner-a", "source": "a".repeat(300), "urgency": "notify" }),
        json!({ "type": "session.rule", "sessionId": "claude:owner-a", "source": "bad\nline", "urgency": "notify" }),
        json!({ "type": "session.mute", "sessionId": "claude:owner-a", "source": "   " }),
        json!({ "type": "session.mute", "sessionId": "claude:owner-a", "source": "#ci", "scope": "universe" }),
        json!({ "type": "session.mute", "sessionId": "claude:owner-a", "source": "#ci", "ttlSeconds": 0 }),
        json!({ "type": "session.focus", "sessionId": "claude:owner-a" }),
        json!({ "type": "session.summary", "sessionId": "claude:$(whoami)" }),
        json!({ "type": "session.summary", "herdrTerminalId": "--json" }),
        json!({ "type": "session.summary", "herdrTerminalId": "t4g\nnewline" }),
        json!({ "type": "session.summary", "detail": "verbose" }),
        json!({ "type": "session.leave_channel", "sessionId": "claude:owner-a", "channel": "#ops" }), // unenrolled!
    ];
    for pkt in invalid_packets {
        let res = rpc(sock, pkt.clone()).await;
        assert!(!res.ok, "expected invalid RPC to fail closed: {pkt}");
    }

    daemon.stop().await;
}

#[tokio::test]
async fn inspect_watch_streams_live_mutations_and_disconnects_cleanly() {
    let dir = TempDir::new().unwrap();
    let node = make_local_node("alice@mac", &dir);
    let daemon = LocalDaemon::start(Arc::clone(&node), None, LocalDaemonConfig::default())
        .await
        .unwrap();
    let sock = daemon.socket_path();

    node.register_session("claude:w1", r#"{"kind":"claude"}"#)
        .unwrap();

    // Connect two watchers: scoped to claude:w1, and unscoped (all sessions).
    let (r1, mut w1) = connect_daemon_async(sock).await.unwrap();
    let mut reader1 = BufReader::new(r1);
    write_ndjson_line_async(
        &mut w1,
        &json!({ "type": "inspect.watch", "sessionId": "claude:w1" }),
    )
    .await
    .unwrap();

    let (r2, mut w2) = connect_daemon_async(sock).await.unwrap();
    let mut reader2 = BufReader::new(r2);
    write_ndjson_line_async(&mut w2, &json!({ "type": "inspect.watch" }))
        .await
        .unwrap();

    // 1. Both immediately receive initial `inspect.snapshot`.
    let line1_a = tokio::time::timeout(
        Duration::from_secs(2),
        read_bounded_line_async(&mut reader1, MAX_SOCKET_LINE_BYTES),
    )
    .await
    .unwrap()
    .unwrap()
    .unwrap();
    let snap1_a: Value = serde_json::from_str(&line1_a).unwrap();
    assert_eq!(snap1_a["type"], "inspect.snapshot");
    assert_eq!(snap1_a["session"]["sessionId"], "claude:w1");
    assert_eq!(snap1_a["session"]["focusMode"], false);
    let rev_a = snap1_a["rev"].as_u64().unwrap();

    let line2_a = tokio::time::timeout(
        Duration::from_secs(2),
        read_bounded_line_async(&mut reader2, MAX_SOCKET_LINE_BYTES),
    )
    .await
    .unwrap()
    .unwrap()
    .unwrap();
    let snap2_a: Value = serde_json::from_str(&line2_a).unwrap();
    assert_eq!(snap2_a["type"], "inspect.snapshot");
    assert_eq!(snap2_a["sessions"].as_array().unwrap().len(), 1);

    // 2. Mutate Focus Mode -> both watchers receive live pushed snapshot!
    let focus = rpc(
        sock,
        json!({ "type": "session.focus", "sessionId": "claude:w1", "enabled": true }),
    )
    .await;
    assert!(focus.ok);

    let line1_b = tokio::time::timeout(
        Duration::from_secs(2),
        read_bounded_line_async(&mut reader1, MAX_SOCKET_LINE_BYTES),
    )
    .await
    .unwrap()
    .unwrap()
    .unwrap();
    let snap1_b: Value = serde_json::from_str(&line1_b).unwrap();
    assert_eq!(snap1_b["type"], "inspect.snapshot");
    assert!(snap1_b["rev"].as_u64().unwrap() > rev_a);
    assert_eq!(snap1_b["session"]["focusMode"], true);

    let line2_b = tokio::time::timeout(
        Duration::from_secs(2),
        read_bounded_line_async(&mut reader2, MAX_SOCKET_LINE_BYTES),
    )
    .await
    .unwrap()
    .unwrap()
    .unwrap();
    let snap2_b: Value = serde_json::from_str(&line2_b).unwrap();
    assert_eq!(snap2_b["type"], "inspect.snapshot");
    assert_eq!(snap2_b["sessions"][0]["focusMode"], true);

    // 3. Invalid target on inspect.watch fails closed with `inspect.error` and closes stream.
    let (r_bad, mut w_bad) = connect_daemon_async(sock).await.unwrap();
    let mut reader_bad = BufReader::new(r_bad);
    write_ndjson_line_async(
        &mut w_bad,
        &json!({ "type": "inspect.watch", "sessionId": "claude:$(evil)" }),
    )
    .await
    .unwrap();
    let err_line = tokio::time::timeout(
        Duration::from_secs(2),
        read_bounded_line_async(&mut reader_bad, MAX_SOCKET_LINE_BYTES),
    )
    .await
    .unwrap()
    .unwrap()
    .unwrap();
    let err_pkt: Value = serde_json::from_str(&err_line).unwrap();
    assert_eq!(err_pkt["type"], "inspect.error");
    assert_eq!(err_pkt["code"], "invalid_session");

    // 4. Clean disconnect of watchers -> daemon stays responsive with zero leaked tasks.
    drop(w1);
    drop(reader1);
    drop(w2);
    drop(reader2);
    tokio::time::sleep(Duration::from_millis(40)).await;

    let still_ok = rpc(
        sock,
        json!({ "type": "session.summary", "sessionId": "claude:w1" }),
    )
    .await;
    assert!(still_ok.ok);
    assert_eq!(still_ok.result.unwrap()["session"]["focusMode"], true);

    daemon.stop().await;
}

#[tokio::test]
async fn wait_subscribe_resolves_herdr_terminal_id_and_tcp_loopback_parity() {
    let dir = TempDir::new().unwrap();
    let node = make_local_node("alice@win", &dir);
    let addr_file = dir.path().join("connector.addr");
    let daemon = LocalDaemon::start_tcp(
        Arc::clone(&node),
        None,
        LocalDaemonConfig::default(),
        addr_file.clone(),
    )
    .await
    .unwrap();

    // Initial ui/state.json exists for TCP mode too.
    assert!(daemon.ui_state_path().is_file());

    // Register session bound to Herdr terminal `t7w`.
    let hint = rpc(
        &addr_file,
        json!({
            "type": "session.hint",
            "harness": "claude",
            "sessionId": "claude:tcp-1",
            "herdrTerminalId": "t7w"
        }),
    )
    .await;
    assert!(hint.ok);

    // Subscribe `wait.subscribe` using ONLY `herdrTerminalId` over loopback TCP!
    let (r, mut w) = connect_daemon_async(&addr_file).await.unwrap();
    let mut reader = BufReader::new(r);
    write_ndjson_line_async(
        &mut w,
        &json!({ "type": "wait.subscribe", "mode": "once", "herdrTerminalId": "t7w" }),
    )
    .await
    .unwrap();
    let ready_line = tokio::time::timeout(
        Duration::from_secs(2),
        read_bounded_line_async(&mut reader, MAX_SOCKET_LINE_BYTES),
    )
    .await
    .unwrap()
    .unwrap()
    .unwrap();
    let ready: Value = serde_json::from_str(&ready_line).unwrap();
    assert_eq!(ready["type"], "wait.ready");
    assert_eq!(ready["sessionId"], "claude:tcp-1");

    // Ingest inbound DM -> waiter wakes immediately!
    daemon
        .ingest_inbound(InboundItem {
            session_id: "claude:tcp-1".into(),
            origin_node: "bob@lap".into(),
            item_id: "m-tcp-1".into(),
            source: "bob@lap/dev".into(),
            text: "hello over tcp".into(),
            kind: MailboxKind::Message,
            trust_tier: GateTrustTier::Peer,
        })
        .await
        .unwrap();

    let items_line = tokio::time::timeout(
        Duration::from_secs(2),
        read_bounded_line_async(&mut reader, MAX_SOCKET_LINE_BYTES),
    )
    .await
    .unwrap()
    .unwrap()
    .unwrap();
    let items: Value = serde_json::from_str(&items_line).unwrap();
    assert_eq!(items["type"], "wait.items");
    let wait_txt = items["items"][0]["text"].as_str().unwrap();
    assert!(wait_txt.starts_with("<hyphae-inbox "));
    assert!(wait_txt.contains("<dm from=\"bob@lap/dev\" count=\"1\"/>"));
    assert!(!wait_txt.contains("hello over tcp"));

    // Verify `session.summary` & debounced `ui/state.json` over loopback TCP match.
    let sum = rpc(
        &addr_file,
        json!({ "type": "session.summary", "herdrTerminalId": "t7w" }),
    )
    .await;
    assert!(sum.ok);
    assert_eq!(sum.result.unwrap()["session"]["sessionId"], "claude:tcp-1");
    let ui_disk = wait_for_ui_state_rev(&daemon.ui_state_path(), daemon.ui_rev()).await;
    assert_eq!(ui_disk["byHerdrTerminal"]["t7w"], "claude:tcp-1");

    daemon.stop().await;
}
