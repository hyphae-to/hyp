//! Deterministic tests for GitHub Issue #29 (`hyp-node` layer):
//! - `PeerLink` holding a stalled/half-open SSE stream aborts immediately when
//!   `UnifiedNode::notify_system_wake()` fires, reconnects, and delivers queued messages in <500ms.
//! - `PeerLink` parked inside a multi-second backoff sleep interrupts immediately on
//!   `notify_system_wake()` and reconnects without waiting for backoff expiry.
//! - `SubprocessSupervisor::send_system_wake()` broadcasts `{ "jsonrpc": "2.0", "method":
//!   "system.wake", "params": { "sleptMs": ... } }` to external plugins and cleanly tolerates
//!   older plugins that omit `onWake`.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hyp_crypto::SecretBackend;
use hyp_node::adapters::{
    AdapterError, AdapterHealth, AdapterKind, BoxFuture, HelloMode, NodeAdapter, NodeAdapterHost,
    PublishOutcome, PublishStatus, SubprocessConfig, SubprocessSupervisor,
};
use hyp_node::engine::http_util::SseEvent;
use hyp_node::engine::{NodeConfig, UnifiedNode};
use hyp_proto::address::NodeId;
use hyp_proto::cloudevent::CloudEvent as ProtoCloudEvent;
use hyp_proto::manifest::E2eePolicy;
use hyp_proto::rpc::EventKeyRef;
use hyp_proto::scopes::ScopePreset;
use hyp_store::{
    MessageRecord, MessageState, PeerInput, PeerProfile, PeerStatus, TrustTier, now_ms, sha256_hex,
};
use serde_json::json;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Notify;

fn open_local_node(node_id: &str, dir: &std::path::Path) -> Arc<UnifiedNode> {
    let mut cfg = NodeConfig::local(NodeId::new(node_id).unwrap(), dir);
    cfg.secret_backend = Some(SecretBackend::File);
    cfg.e2ee_policy = E2eePolicy::Prefer;
    UnifiedNode::open(cfg).expect("open UnifiedNode")
}

/// Minimal raw HTTP/1.1 mock peer server that simulates:
/// - `GET /v1/manifest` -> 404 (legacy v1 peer fallback, zero crypto handshake overhead)
/// - `GET /v1/keys` -> 404
/// - `PUT /v1/handles` / `GET /v1/handles` -> 200 `{ "handles": [] }`
/// - `POST /v1/inbox/ack` -> 200 `{ "acked": true }` + records acked IDs
/// - `GET /v1/inbox`:
///   - mode `StallFirst`: connection #1 sends `200 OK` SSE headers + `: connected` and STALLS
///     indefinitely (simulating a half-open dead TCP socket across laptop sleep); connection #2+
///     immediately streams the queued `MessageRecord`!
///   - mode `BackoffFirst`: connection #1 returns `503 Service Unavailable` with `Retry-After: 30`
///     (putting `spawn_sse_worker` into 5s backoff sleep); connection #2+ immediately streams the
///     queued `MessageRecord`!
enum MockInboxBehavior {
    StallFirst,
    BackoffFirst,
}

struct MockSsePeer {
    addr: std::net::SocketAddr,
    inbox_connections: Arc<AtomicUsize>,
    first_conn_notify: Arc<Notify>,
    acked_ids: Arc<Mutex<Vec<String>>>,
    ack_notify: Arc<Notify>,
    shutdown: Arc<AtomicBool>,
    task: tokio::task::JoinHandle<()>,
}

impl MockSsePeer {
    async fn start(behavior: MockInboxBehavior, queued_msg: MessageRecord) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock peer");
        let addr = listener.local_addr().unwrap();
        let inbox_connections = Arc::new(AtomicUsize::new(0));
        let first_conn_notify = Arc::new(Notify::new());
        let acked_ids = Arc::new(Mutex::new(Vec::new()));
        let ack_notify = Arc::new(Notify::new());
        let shutdown = Arc::new(AtomicBool::new(false));
        let behavior = Arc::new(behavior);
        let queued_msg = Arc::new(queued_msg);

        let conns_bg = Arc::clone(&inbox_connections);
        let first_bg = Arc::clone(&first_conn_notify);
        let acks_bg = Arc::clone(&acked_ids);
        let ack_notify_bg = Arc::clone(&ack_notify);
        let shut_bg = Arc::clone(&shutdown);

        let task = tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                if shut_bg.load(Ordering::Acquire) {
                    break;
                }
                let conns = Arc::clone(&conns_bg);
                let first = Arc::clone(&first_bg);
                let acks = Arc::clone(&acks_bg);
                let ack_n = Arc::clone(&ack_notify_bg);
                let beh = Arc::clone(&behavior);
                let msg = Arc::clone(&queued_msg);

                tokio::spawn(async move {
                    let mut buf = vec![0u8; 8192];
                    let n = match sock.read(&mut buf).await {
                        Ok(n) if n > 0 => n,
                        _ => return,
                    };
                    let req_str = String::from_utf8_lossy(&buf[..n]);
                    let first_line = req_str.lines().next().unwrap_or("");
                    let mut parts = first_line.split_whitespace();
                    let method = parts.next().unwrap_or("");
                    let path = parts.next().unwrap_or("");

                    match (method, path) {
                        ("GET", "/v1/manifest") | ("GET", "/v1/keys") => {
                            let resp = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                            let _ = sock.write_all(resp.as_bytes()).await;
                        }
                        ("PUT", "/v1/handles") | ("GET", "/v1/handles") => {
                            let body = r#"{"handles":[]}"#;
                            let resp = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                                body.len()
                            );
                            let _ = sock.write_all(resp.as_bytes()).await;
                        }
                        ("POST", "/v1/inbox/ack") => {
                            if let Some((_, body_part)) = req_str.split_once("\r\n\r\n") {
                                if let Ok(v) = serde_json::from_str::<serde_json::Value>(body_part)
                                {
                                    if let Some(id) = v.get("id").and_then(|s| s.as_str()) {
                                        acks.lock().unwrap().push(id.to_string());
                                        ack_n.notify_waiters();
                                    }
                                }
                            }
                            let body = r#"{"acked":true}"#;
                            let resp = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                                body.len()
                            );
                            let _ = sock.write_all(resp.as_bytes()).await;
                        }
                        ("GET", "/v1/inbox") => {
                            let conn_num = conns.fetch_add(1, Ordering::SeqCst) + 1;
                            if conn_num == 1 {
                                match *beh {
                                    MockInboxBehavior::StallFirst => {
                                        let headers = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream; charset=utf-8\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\n\r\n: connected\n\n";
                                        let _ = sock.write_all(headers.as_bytes()).await;
                                        let _ = sock.flush().await;
                                        first.notify_waiters();
                                        // Hold TCP socket silently open forever to simulate a half-open
                                        // socket across laptop sleep until the client drops it!
                                        let mut drain = [0u8; 64];
                                        loop {
                                            match sock.read(&mut drain).await {
                                                Ok(0) | Err(_) => break,
                                                Ok(_) => {}
                                            }
                                        }
                                    }
                                    MockInboxBehavior::BackoffFirst => {
                                        let resp = "HTTP/1.1 503 Service Unavailable\r\nRetry-After: 30\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                                        let _ = sock.write_all(resp.as_bytes()).await;
                                        let _ = sock.flush().await;
                                        first.notify_waiters();
                                    }
                                }
                            } else {
                                // Reconnected after wake: stream the queued message immediately!
                                let data = serde_json::to_string(&*msg).unwrap();
                                let sse = SseEvent::new("message", data)
                                    .with_id(format!("message:{}", msg.id))
                                    .encode();
                                let resp = format!(
                                    "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream; charset=utf-8\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\n\r\n{sse}"
                                );
                                let _ = sock.write_all(resp.as_bytes()).await;
                                let _ = sock.flush().await;
                                // Keep open briefly until client closes.
                                let mut drain = [0u8; 64];
                                let _ = tokio::time::timeout(
                                    Duration::from_secs(5),
                                    sock.read(&mut drain),
                                )
                                .await;
                            }
                        }
                        _ => {
                            let resp = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                            let _ = sock.write_all(resp.as_bytes()).await;
                        }
                    }
                });
            }
        });

        Self {
            addr,
            inbox_connections,
            first_conn_notify,
            acked_ids,
            ack_notify,
            shutdown,
            task,
        }
    }

    fn endpoint(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn stop(self) {
        self.shutdown.store(true, Ordering::Release);
        self.task.abort();
    }
}

fn seed_paired_peer_and_session(node: &UnifiedNode, peer_id: &str, endpoint: &str) {
    let now = now_ms();
    let db = node.db();
    db.local()
        .register_session("claude:wake-peer-sess", "{}", now)
        .unwrap();
    db.local()
        .set_session_handle("claude:wake-peer-sess", Some("alice"), now)
        .unwrap();
    db.peers()
        .upsert_peer(
            &PeerInput {
                peer_id: peer_id.to_string(),
                endpoint: Some(endpoint.to_string()),
                profile: PeerProfile::Router,
                trust_tier: TrustTier::Peer,
                status: PeerStatus::Active,
                scopes: ScopePreset::Member.expand(),
                auth_credential_ref: None,
            },
            now,
        )
        .unwrap();
}

#[tokio::test]
async fn peer_link_recycles_stalled_half_open_sse_immediately_on_system_wake() {
    let dir = TempDir::new().unwrap();
    let node = open_local_node("laptop@local", dir.path());
    let now = now_ms();

    let text = "queued-during-laptop-sleep".to_string();
    let queued = MessageRecord {
        id: "msg-after-wake-1".to_string(),
        from_addr: "hub@remote/ops".to_string(),
        to_addr: "laptop@local/alice".to_string(),
        channel: None,
        digest: sha256_hex(text.as_bytes()),
        text,
        sent_at: now,
        state: MessageState::Pending,
        reason: None,
        hold_until: 0,
        settled_at: None,
        origin_environment_id: None,
        origin_thread_id: None,
        e2ee_epoch: None,
    };

    let mock = MockSsePeer::start(MockInboxBehavior::StallFirst, queued).await;
    seed_paired_peer_and_session(&node, "hub@remote", &mock.endpoint());

    let report = node.reconcile_peers(Duration::from_secs(2)).await;
    assert_eq!(report.active_peers, 1);

    // Wait for SSE connection #1 to establish and stall on the half-open stream.
    tokio::time::timeout(Duration::from_secs(2), async {
        while mock.inbox_connections.load(Ordering::SeqCst) < 1 {
            mock.first_conn_notify.notified().await;
        }
    })
    .await
    .expect("SSE connection #1 must establish");

    // Confirm connection #1 stays stalled and delivers nothing before wake.
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert_eq!(mock.inbox_connections.load(Ordering::SeqCst), 1);
    assert_eq!(
        node.db()
            .local()
            .pending_count("claude:wake-peer-sess")
            .unwrap(),
        0
    );

    // Fire system wake -> stalled SSE stream MUST abort & reconnect immediately (<500ms)!
    let mut local_rx = node.subscribe_local_inbox();
    let t0 = Instant::now();
    let epoch = node.notify_system_wake(Duration::from_secs(120));
    assert_eq!(epoch, 1);
    assert_eq!(node.current_wake_epoch(), 1);
    assert_eq!(
        node.last_system_wake().expect("last_wake").slept_for,
        Duration::from_secs(120)
    );

    // Wait for message commit in local mailbox (strictly <500ms!).
    tokio::time::timeout(Duration::from_millis(500), async {
        loop {
            if node
                .db()
                .local()
                .pending_count("claude:wake-peer-sess")
                .unwrap()
                >= 1
            {
                break;
            }
            let _ = tokio::time::timeout(Duration::from_millis(20), local_rx.recv()).await;
        }
    })
    .await
    .expect("queued DM must arrive in <500ms after notify_system_wake");

    let elapsed = t0.elapsed();
    assert!(
        elapsed < Duration::from_millis(500),
        "wake reconnect + delivery took {elapsed:?}, expected <500ms"
    );
    assert!(
        mock.inbox_connections.load(Ordering::SeqCst) >= 2,
        "PeerLink must have opened a fresh SSE connection after wake"
    );

    let items = node
        .db()
        .local()
        .peek_inbox("claude:wake-peer-sess", 10)
        .unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].item_id, "msg-after-wake-1");
    assert_eq!(items[0].text, "queued-during-laptop-sleep");

    // Verify commit-before-ack sent POST /v1/inbox/ack for the delivered message.
    tokio::time::timeout(Duration::from_millis(500), async {
        while !mock
            .acked_ids
            .lock()
            .unwrap()
            .iter()
            .any(|id| id == "msg-after-wake-1")
        {
            mock.ack_notify.notified().await;
        }
    })
    .await
    .expect("PeerLink must ack delivered message");

    node.shutdown();
    mock.stop();
}

#[tokio::test]
async fn peer_link_interrupts_backoff_sleep_and_reconnects_immediately_on_system_wake() {
    let dir = TempDir::new().unwrap();
    let node = open_local_node("laptop-backoff@local", dir.path());
    let now = now_ms();

    let text = "delivered-after-backoff-reset".to_string();
    let queued = MessageRecord {
        id: "msg-after-backoff-wake".to_string(),
        from_addr: "hub-backoff@remote/ops".to_string(),
        to_addr: "laptop-backoff@local/alice".to_string(),
        channel: None,
        digest: sha256_hex(text.as_bytes()),
        text,
        sent_at: now,
        state: MessageState::Pending,
        reason: None,
        hold_until: 0,
        settled_at: None,
        origin_environment_id: None,
        origin_thread_id: None,
        e2ee_epoch: None,
    };

    let mock = MockSsePeer::start(MockInboxBehavior::BackoffFirst, queued).await;
    seed_paired_peer_and_session(&node, "hub-backoff@remote", &mock.endpoint());

    let report = node.reconcile_peers(Duration::from_secs(2)).await;
    assert_eq!(report.active_peers, 1);

    // Wait for connection #1 to receive 503 Retry-After: 30 (enters 5s capped backoff sleep).
    tokio::time::timeout(Duration::from_secs(2), async {
        while mock.inbox_connections.load(Ordering::SeqCst) < 1 {
            mock.first_conn_notify.notified().await;
        }
    })
    .await
    .expect("SSE connection #1 must hit 503");

    tokio::time::sleep(Duration::from_millis(80)).await;
    assert_eq!(
        mock.inbox_connections.load(Ordering::SeqCst),
        1,
        "worker must be parked in 5s backoff before wake"
    );

    let mut local_rx = node.subscribe_local_inbox();
    let t0 = Instant::now();
    node.notify_system_wake(Duration::from_secs(60));

    tokio::time::timeout(Duration::from_millis(500), async {
        loop {
            if node
                .db()
                .local()
                .pending_count("claude:wake-peer-sess")
                .unwrap()
                >= 1
            {
                break;
            }
            let _ = tokio::time::timeout(Duration::from_millis(20), local_rx.recv()).await;
        }
    })
    .await
    .expect("wake must interrupt 5s backoff and deliver in <500ms");

    let elapsed = t0.elapsed();
    assert!(
        elapsed < Duration::from_millis(500),
        "wake backoff interrupt took {elapsed:?}, expected <500ms"
    );

    node.shutdown();
    mock.stop();
}

struct RecordingHost {
    events: Mutex<Vec<(String, ProtoCloudEvent)>>,
    notify: Notify,
}

impl RecordingHost {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            events: Mutex::new(Vec::new()),
            notify: Notify::new(),
        })
    }
}

impl NodeAdapterHost for RecordingHost {
    fn publish_event<'a>(
        &'a self,
        to: &'a str,
        event: ProtoCloudEvent,
    ) -> BoxFuture<'a, Result<PublishOutcome, AdapterError>> {
        let to = to.to_string();
        Box::pin(async move {
            self.events.lock().unwrap().push((to, event));
            self.notify.notify_waiters();
            Ok(PublishOutcome {
                status: PublishStatus::Stored,
                matched: 1,
            })
        })
    }

    fn update_status<'a>(&'a self, _id: &'a str, _health: AdapterHealth) -> BoxFuture<'a, ()> {
        Box::pin(async {})
    }

    fn report_delivery_failed<'a>(
        &'a self,
        _id: &'a str,
        _target: &'a str,
        _events: Vec<EventKeyRef>,
        _reason: &'a str,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async {})
    }
}

#[tokio::test]
async fn subprocess_supervisor_sends_system_wake_notification_to_plugins() {
    let sdk_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../plugins/sdk/client.mjs");
    assert!(sdk_path.is_file(), "missing SDK at {}", sdk_path.display());
    let sdk_path = sdk_path
        .into_os_string()
        .into_string()
        .expect("UTF-8 SDK path");

    // 1. Plugin WITH `onWake` handler receives `{ sleptMs: 90000 }` and emits confirmation event.
    let wake_script = r#"
        import { pathToFileURL } from "node:url";
        const { MeshPluginClient } = await import(pathToFileURL(process.env.SDK_MJS_PATH).href);
        const mesh = new MeshPluginClient({
          onWake: async ({ sleptMs }) => {
            await mesh.send("ops", {
              specversion: "1.0",
              id: "wake-ack-" + sleptMs,
              source: "test/wake-plugin",
              type: "to.hyphae.test.wake",
              datacontenttype: "application/json",
              data: { sleptMs },
            });
          },
        });
        await mesh.ready;
    "#;

    let mut cfg = SubprocessConfig::new(
        "wake-plugin",
        AdapterKind::Source,
        "node",
        vec![
            "--input-type=module".to_string(),
            "-e".to_string(),
            wake_script.to_string(),
        ],
        vec!["ops".to_string()],
    );
    cfg.hello_mode = HelloMode::LegacyV1;
    cfg.env = BTreeMap::from([("SDK_MJS_PATH".to_string(), sdk_path.clone())]);

    let host = RecordingHost::new();
    let sup = SubprocessSupervisor::new(cfg);
    sup.start(Arc::clone(&host) as Arc<dyn NodeAdapterHost>)
        .await
        .expect("start wake-plugin");

    // Allow child a moment to finish `await mesh.ready`.
    tokio::time::sleep(Duration::from_millis(120)).await;
    sup.send_system_wake(Duration::from_secs(90))
        .await
        .expect("send_system_wake");

    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if !host.events.lock().unwrap().is_empty() {
                break;
            }
            host.notify.notified().await;
        }
    })
    .await
    .expect("wake-plugin must receive system.wake and publish confirmation");

    let recorded = host.events.lock().unwrap().clone();
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].1.id, "wake-ack-90000");
    assert_eq!(recorded[0].1.data, Some(json!({ "sleptMs": 90_000 })));
    sup.stop().await.expect("stop wake-plugin");

    // 2. Older plugin WITHOUT `onWake` safely ignores `system.wake` and keeps running!
    let legacy_script = r#"
        import { pathToFileURL } from "node:url";
        const { MeshPluginClient } = await import(pathToFileURL(process.env.SDK_MJS_PATH).href);
        const mesh = new MeshPluginClient();
        await mesh.ready;
        setTimeout(async () => {
          await mesh.send("ops", {
            specversion: "1.0",
            id: "still-alive-after-wake",
            source: "test/legacy-plugin",
            type: "to.hyphae.test.alive",
            datacontenttype: "application/json",
            data: { alive: true },
          });
        }, 200);
    "#;
    let mut legacy_cfg = SubprocessConfig::new(
        "legacy-plugin",
        AdapterKind::Source,
        "node",
        vec![
            "--input-type=module".to_string(),
            "-e".to_string(),
            legacy_script.to_string(),
        ],
        vec!["ops".to_string()],
    );
    legacy_cfg.hello_mode = HelloMode::LegacyV1;
    legacy_cfg.env = BTreeMap::from([("SDK_MJS_PATH".to_string(), sdk_path)]);

    let legacy_host = RecordingHost::new();
    let legacy_sup = SubprocessSupervisor::new(legacy_cfg);
    legacy_sup
        .start(Arc::clone(&legacy_host) as Arc<dyn NodeAdapterHost>)
        .await
        .expect("start legacy-plugin");

    tokio::time::sleep(Duration::from_millis(80)).await;
    legacy_sup
        .send_system_wake(Duration::from_secs(45))
        .await
        .expect("send_system_wake to legacy plugin");

    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if !legacy_host.events.lock().unwrap().is_empty() {
                break;
            }
            legacy_host.notify.notified().await;
        }
    })
    .await
    .expect("legacy plugin without onWake must survive system.wake");

    assert_eq!(legacy_sup.restart_count(), 0);
    assert_eq!(
        legacy_host.events.lock().unwrap()[0].1.id,
        "still-alive-after-wake"
    );
    legacy_sup.stop().await.expect("stop legacy-plugin");
}
