//! Pure-Rust end-to-end integration tests for:
//! - Issue #44: Stream subscriptions persist `key` and delivery urgency across full `UnifiedNode`
//!   and `LocalDaemon` restarts so re-subscribing with the same `key` updates in place with zero
//!   duplicates, and `unsubscribe` by `key` works cleanly across restarts.
//! - Issue #45: `hyp_stream subscribe` reports accurate stored event counts from SQLite for both
//!   bare `<topic>` and `local.<topic>` instead of falsely emitting `"0 events so far"`.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use hyp_crypto::SecretBackend;
use hyp_harness::daemon::{LocalDaemon, LocalDaemonConfig};
use hyp_harness::hooks::{HandleHookOptions, HookEvent, HookTransportHints, handle_hook_payload};
use hyp_harness::mcp::{McpOptions, run_mcp_io};
use hyp_harness::protocol::HarnessKind;
use hyp_node::engine::{NodeConfig, TopicConfig, UnifiedNode};
use hyp_proto::address::NodeId;
use hyp_proto::cloudevent::CloudEvent;
use hyp_proto::filter::DiagnosticCode;
use hyp_store::{CloudEvent as StoreCloudEvent, now_ms};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream};

fn hook_opts(event: HookEvent, sock: &Path) -> HandleHookOptions {
    hyp_harness::enable_test_env_isolation();
    HandleHookOptions {
        harness: HarnessKind::Claude,
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
    fn spawn(sock: &Path) -> Self {
        let options = McpOptions::new(sock.to_path_buf());
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
                    "clientInfo": {"name": "stream-restart-e2e", "version": "1"}
                }),
            )
            .await;
        self.send_json(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
            .await;
        res
    }

    async fn call_verified_claude(
        &mut self,
        sock: &Path,
        session_raw: &str,
        tool_name: &str,
        arguments: Value,
    ) -> (Value, bool) {
        self.next_id += 1;
        let call_id = format!("toolu_{}_{}", session_raw, self.next_id);
        let sock_owned = sock.to_path_buf();
        let sess_owned = session_raw.to_string();
        let tool_owned = tool_name.to_string();
        let call_owned = call_id.clone();
        let args_owned = arguments.clone();
        tokio::task::spawn_blocking(move || {
            let payload = json!({
                "session_id": sess_owned,
                "tool_use_id": call_owned,
                "tool_name": tool_owned,
                "tool_input": args_owned,
            });
            let _ = handle_hook_payload(
                payload.as_object().expect("hook payload object"),
                &hook_opts(HookEvent::PreToolUse, &sock_owned),
            );
        })
        .await
        .expect("PreToolUse hook task panicked");

        let res = self
            .request(
                "tools/call",
                json!({
                    "name": tool_name,
                    "arguments": arguments,
                    "_meta": { "claudecode/toolUseId": call_id }
                }),
            )
            .await;
        let result = &res["result"];
        let text = result["content"][0]["text"].as_str().unwrap_or_default();
        let is_error = result["isError"].as_bool() == Some(true);
        let parsed = serde_json::from_str::<Value>(text).unwrap_or_else(|_| json!({ "raw": text }));
        (parsed, is_error)
    }

    async fn close(self) {
        drop(self.writer);
        let _ = tokio::time::timeout(Duration::from_secs(5), self.task).await;
    }
}

fn make_local_node_config(state_dir: &Path, extra_topics: &[&str]) -> NodeConfig {
    let mut cfg = NodeConfig::local(NodeId::new("alice@macbook").unwrap(), state_dir);
    cfg.secret_backend = Some(SecretBackend::File);
    for topic in extra_topics {
        cfg.topics.push(TopicConfig {
            topic: (*topic).to_string(),
            kind: Some("source".to_string()),
            description: Some(format!("Test topic {topic}")),
            metadata: None,
            has_provisioned_publisher: true,
        });
    }
    cfg
}

#[tokio::test]
async fn stream_subscription_key_and_urgency_survive_daemon_restart_without_duplicates() {
    hyp_harness::enable_test_env_isolation();
    let dir = TempDir::new().unwrap();
    let state_dir = dir.path().join("state");

    // ---- Boot #1: join & subscribe with `key: "gmail:riley"` and `mode: "interrupt"` ----
    let sub_id_1 = {
        let node = UnifiedNode::open(make_local_node_config(&state_dir, &["agentmail"])).unwrap();
        let daemon = LocalDaemon::start(Arc::clone(&node), None, LocalDaemonConfig::default())
            .await
            .unwrap();
        let sock_path = daemon.socket_path().to_path_buf();

        let mut mcp = TestMcpClient::spawn(&sock_path);
        mcp.initialize().await;

        let (_, join_err) = mcp
            .call_verified_claude(
                &sock_path,
                "sess-restart-1",
                "hyp_mesh",
                json!({ "action": "join", "handle": "alice" }),
            )
            .await;
        assert!(!join_err);

        let (sub_res, sub_err) = mcp
            .call_verified_claude(
                &sock_path,
                "sess-restart-1",
                "hyp_stream",
                json!({
                    "action": "subscribe",
                    "topic": "local.agentmail",
                    "key": "gmail:riley",
                    "filters": [{ "exact": { "type": "email.received" } }],
                    "mode": "interrupt",
                }),
            )
            .await;
        assert!(!sub_err, "initial subscribe failed: {sub_res}");
        assert_eq!(sub_res["outcome"], "created");
        let sub_id = sub_res["id"].as_str().unwrap().to_string();

        let (list_res, list_err) = mcp
            .call_verified_claude(
                &sock_path,
                "sess-restart-1",
                "hyp_stream",
                json!({ "action": "list" }),
            )
            .await;
        assert!(!list_err);
        let subs = list_res["subscriptions"].as_array().unwrap();
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0]["id"], sub_id);
        assert_eq!(subs[0]["key"], "gmail:riley");
        assert_eq!(subs[0]["mode"], "interrupt");

        mcp.close().await;
        daemon.shutdown();
        node.shutdown();
        sub_id
    };

    // ---- Boot #2: completely fresh UnifiedNode + LocalDaemon on same state_dir ----
    {
        let node = UnifiedNode::open(make_local_node_config(&state_dir, &["agentmail"])).unwrap();
        let daemon = LocalDaemon::start(Arc::clone(&node), None, LocalDaemonConfig::default())
            .await
            .unwrap();
        let sock_path = daemon.socket_path().to_path_buf();

        let mut mcp = TestMcpClient::spawn(&sock_path);
        mcp.initialize().await;

        // `list` after restart MUST still return `key == "gmail:riley"` and `mode == "interrupt"`!
        let (list_after_restart, list_err) = mcp
            .call_verified_claude(
                &sock_path,
                "sess-restart-1",
                "hyp_stream",
                json!({ "action": "list" }),
            )
            .await;
        assert!(!list_err, "list after restart failed: {list_after_restart}");
        let subs = list_after_restart["subscriptions"].as_array().unwrap();
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0]["id"], sub_id_1);
        assert_eq!(
            subs[0]["key"], "gmail:riley",
            "subscription key must survive restart: {list_after_restart}"
        );
        assert_eq!(
            subs[0]["mode"], "interrupt",
            "subscription urgency mode must survive restart: {list_after_restart}"
        );

        // Re-subscribing with the same `key: "gmail:riley"` MUST update in place with ZERO duplicates!
        let (resub_res, resub_err) = mcp
            .call_verified_claude(
                &sock_path,
                "sess-restart-1",
                "hyp_stream",
                json!({
                    "action": "subscribe",
                    "topic": "local.agentmail",
                    "key": "gmail:riley",
                    "filters": [{ "exact": { "type": "email.urgent" } }],
                    "mode": "notify",
                }),
            )
            .await;
        assert!(!resub_err, "re-subscribe failed: {resub_res}");
        assert_eq!(
            resub_res["outcome"], "updated",
            "re-subscribing with persisted key must update in place: {resub_res}"
        );
        assert_eq!(
            resub_res["id"], sub_id_1,
            "re-subscribing with persisted key must reuse the existing subscription ID"
        );

        let (list_after_update, list_err2) = mcp
            .call_verified_claude(
                &sock_path,
                "sess-restart-1",
                "hyp_stream",
                json!({ "action": "list" }),
            )
            .await;
        assert!(!list_err2);
        let subs2 = list_after_update["subscriptions"].as_array().unwrap();
        assert_eq!(
            subs2.len(),
            1,
            "re-subscribing after restart MUST NOT create duplicate subscriptions: {list_after_update}"
        );
        assert_eq!(subs2[0]["id"], sub_id_1);
        assert_eq!(subs2[0]["key"], "gmail:riley");
        assert_eq!(subs2[0]["mode"], "notify");
        assert_eq!(
            subs2[0]["filters"],
            json!([{ "exact": { "type": "email.urgent" } }])
        );

        mcp.close().await;
        daemon.shutdown();
        node.shutdown();
    }

    // ---- Boot #3: verify unsubscribe by `key` also survives restart & cleans up metadata ----
    {
        let node = UnifiedNode::open(make_local_node_config(&state_dir, &["agentmail"])).unwrap();
        let daemon = LocalDaemon::start(Arc::clone(&node), None, LocalDaemonConfig::default())
            .await
            .unwrap();
        let sock_path = daemon.socket_path().to_path_buf();

        let mut mcp = TestMcpClient::spawn(&sock_path);
        mcp.initialize().await;

        let (unsub_res, unsub_err) = mcp
            .call_verified_claude(
                &sock_path,
                "sess-restart-1",
                "hyp_stream",
                json!({ "action": "unsubscribe", "key": "gmail:riley" }),
            )
            .await;
        assert!(!unsub_err, "unsubscribe by key failed: {unsub_res}");
        assert_eq!(unsub_res["removed"], true);

        let (list_empty, _) = mcp
            .call_verified_claude(
                &sock_path,
                "sess-restart-1",
                "hyp_stream",
                json!({ "action": "list" }),
            )
            .await;
        assert!(list_empty["subscriptions"].as_array().unwrap().is_empty());
        assert!(
            node.db()
                .events()
                .get_subscription_meta(&sub_id_1)
                .unwrap()
                .is_none(),
            "persisted sub_meta must be deleted atomically on unsubscribe"
        );

        mcp.close().await;
        daemon.shutdown();
        node.shutdown();
    }
}

#[tokio::test]
async fn stream_subscribe_reports_accurate_stored_event_count_for_bare_and_local_topics() {
    hyp_harness::enable_test_env_isolation();
    let dir = TempDir::new().unwrap();
    let state_dir = dir.path().join("state");

    let node = UnifiedNode::open(make_local_node_config(
        &state_dir,
        &["agentmail", "empty-topic"],
    ))
    .unwrap();
    let daemon = LocalDaemon::start(Arc::clone(&node), None, LocalDaemonConfig::default())
        .await
        .unwrap();
    let sock_path = daemon.socket_path().to_path_buf();

    // 1. Publish 2 events onto `local.agentmail` BEFORE any subscriber exists (so bodies are
    //    cleared on ingest, matching real-world pre-subscription ingestion).
    for i in 1..=2 {
        let ev = CloudEvent::new(
            format!("mail-{i}"),
            "agentmail://inbox/riley",
            "com.agentmail.message.received",
            json!({ "subject": format!("hello {i}") }),
        );
        node.publish_event("local.agentmail", ev).await.unwrap();
    }

    // 2. Also ingest a legacy/direct row stored under `origin_node = "local"` with
    //    `topic = "local.alerts"` AND a bare topic row under `alice@macbook` / `"alerts"`
    //    to prove topic normalization folds both forms together consistently.
    {
        let db = node.db();
        let store_ev1 = StoreCloudEvent {
            specversion: "1.0".to_string(),
            id: "alert-1".to_string(),
            source: "local://monitor".to_string(),
            event_type: "to.hyphae.alert.v1".to_string(),
            subject: None,
            time: None,
            datacontenttype: "application/json".to_string(),
            dataschema: None,
            data: json!({ "level": "warn" }),
            extensions: Default::default(),
        };
        let store_ev2 = StoreCloudEvent {
            id: "alert-2".to_string(),
            ..store_ev1.clone()
        };
        db.events()
            .ingest("local", "local.alerts", "local-pub", &store_ev1, now_ms())
            .unwrap();
        db.events()
            .ingest(
                "alice@macbook",
                "alerts",
                "local-pub",
                &store_ev2,
                now_ms() + 1,
            )
            .unwrap();
    }

    // 3. Verify `local_topic_catalog()` reports exact stored event counts from SQLite.
    let catalog = node.local_topic_catalog();
    let agentmail_entry = catalog
        .iter()
        .find(|e| e.topic == "agentmail")
        .expect("agentmail in catalog");
    assert_eq!(agentmail_entry.observed.event_count, 2);
    assert!(agentmail_entry.observed.last_event_at.is_some());
    assert!(
        agentmail_entry
            .observed
            .sources
            .iter()
            .any(|s| s == "agentmail://inbox/riley")
    );

    let alerts_entry = catalog
        .iter()
        .find(|e| e.topic == "alerts")
        .expect("dynamic alerts topic with stored events in catalog");
    assert_eq!(alerts_entry.observed.event_count, 2);

    let empty_entry = catalog
        .iter()
        .find(|e| e.topic == "empty-topic")
        .expect("empty-topic in catalog");
    assert_eq!(empty_entry.observed.event_count, 0);

    // 4. Subscribe via MCP `hyp_stream` (both `local.agentmail` and bare `alerts`) and assert
    //    diagnostics NEVER falsely claim `"0 events so far"`!
    let mut mcp = TestMcpClient::spawn(&sock_path);
    mcp.initialize().await;

    let (_, join_err) = mcp
        .call_verified_claude(
            &sock_path,
            "sess-diag-1",
            "hyp_mesh",
            json!({ "action": "join", "handle": "alice" }),
        )
        .await;
    assert!(!join_err);

    for (key, topic) in [
        ("sub-local-agentmail", "local.agentmail"),
        ("sub-bare-agentmail", "agentmail"),
        ("sub-local-alerts", "local.alerts"),
        ("sub-bare-alerts", "alerts"),
    ] {
        let (sub_res, sub_err) = mcp
            .call_verified_claude(
                &sock_path,
                "sess-diag-1",
                "hyp_stream",
                json!({
                    "action": "subscribe",
                    "topic": topic,
                    "key": key,
                }),
            )
            .await;
        assert!(!sub_err, "subscribe({topic}) failed: {sub_res}");
        let diags = sub_res["diagnostics"].as_array().unwrap();
        assert!(
            !diags.iter().any(|d| {
                d["code"] == json!(DiagnosticCode::TopicNoEventsYet)
                    || d["message"]
                        .as_str()
                        .is_some_and(|m| m.contains("0 events so far"))
            }),
            "subscribe({topic}) must NOT falsely report '0 events so far': {sub_res}"
        );
    }

    // 5. Contrast check: a topic with genuinely 0 stored events STILL reports `topic_no_events_yet`.
    let (empty_res, empty_err) = mcp
        .call_verified_claude(
            &sock_path,
            "sess-diag-1",
            "hyp_stream",
            json!({
                "action": "subscribe",
                "topic": "local.empty-topic",
                "key": "sub-empty",
            }),
        )
        .await;
    assert!(!empty_err, "subscribe(empty-topic) failed: {empty_res}");
    let empty_diags = empty_res["diagnostics"].as_array().unwrap();
    assert!(
        empty_diags
            .iter()
            .any(|d| d["code"] == json!(DiagnosticCode::TopicNoEventsYet)),
        "topic with 0 stored events must still emit topic_no_events_yet: {empty_res}"
    );

    mcp.close().await;
    daemon.shutdown();
    node.shutdown();
}
