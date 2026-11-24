//! Real External Plugins & SDK Subprocess E2E Tests (`plugins/*` + `SubprocessSupervisor` + `UnifiedNode`).
//!
//! Spawns the **real repository plugin scripts** under `plugins/` over Unix fd-3 IPC via
//! `SubprocessSupervisor` wired into a live `UnifiedNode`, with loopback-only mock external APIs
//! (`MockHttpServer`) and ephemeral `TempDir` state.
//!
//! Guarded cleanly with `#[cfg(unix)]` so Windows builds emit ZERO unused-import or dead-code
//! warnings. Individual Node/Python tests skip gracefully ONLY if `node` or `python3` is missing
//! from `PATH`.

#[cfg(unix)]
mod common;

#[cfg(unix)]
mod unix_tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use bytes::Bytes;
    use http::header::{AUTHORIZATION, CONTENT_TYPE};
    use http::{HeaderMap, HeaderValue, Method, Request, StatusCode};
    use serde_json::{Value, json};
    use tempfile::TempDir;
    use tokio::net::TcpListener;
    use tokio::sync::Mutex as AsyncMutex;
    use zeroize::Zeroizing;

    use crate::common::{MockHttpServer, MockRequest, MockResponse, UnifiedNodeAdapterHost};
    use hyp_crypto::SecretBackend;
    use hyp_node::adapters::{
        AdapterError, AdapterKind, HelloMode, NodeAdapter, PrometheusWebhookAdapter,
        PrometheusWebhookConfig, SubprocessConfig, SubprocessSupervisor,
        compute_hmac_sha256_header, verify_hmac_sha256_header,
    };
    use hyp_node::engine::http_util::{HttpClient, empty_body, full_body};
    use hyp_node::engine::{NodeConfig, SubscribeRequest, UnifiedNode};
    use hyp_proto::address::NodeId;
    use hyp_proto::rpc::StatusParams;
    use hyp_store::{DeliveryMode, now_ms};

    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .expect("resolve repository root")
    }

    fn find_binary(name: &str) -> Option<String> {
        let output = std::process::Command::new(name)
            .arg("--version")
            .output()
            .ok()?;
        if output.status.success() {
            Some(name.to_string())
        } else {
            None
        }
    }

    async fn pick_free_loopback_port() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral port");
        let port = listener.local_addr().expect("local addr").port();
        drop(listener);
        port
    }

    async fn wait_for_http_ready(url: &str, timeout_dur: Duration) {
        let client = HttpClient::new().unwrap();
        let deadline = tokio::time::Instant::now() + timeout_dur;
        loop {
            let req = Request::builder()
                .method(Method::GET)
                .uri(url)
                .body(empty_body())
                .unwrap();
            if client.request(req).await.is_ok() {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for plugin HTTP server at {url}"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    fn open_test_node(name: &str, dir: &Path) -> Arc<UnifiedNode> {
        let mut cfg = NodeConfig::local(NodeId::new(name).unwrap(), dir);
        cfg.secret_backend = Some(SecretBackend::File);
        UnifiedNode::open(cfg).unwrap()
    }

    // ========================================================================
    // 1. `plugins/webhook/index.mjs`: HMAC-SHA256, 401, 413, & outbound signed post
    // ========================================================================

    #[tokio::test]
    async fn real_webhook_plugin_hmac_body_cap_and_outbound_post_e2e() {
        let Some(node_bin) = find_binary("node") else {
            eprintln!("SKIP real_webhook_plugin_hmac_body_cap_and_outbound_post_e2e: `node` not on PATH");
            return;
        };

        let tmp = TempDir::new().unwrap();
        let secret = "super-secret-webhook-hmac-key-2026";
        let secret_file = tmp.path().join("webhook.secret");
        fs::write(&secret_file, secret).unwrap();

        let captured_outbound: Arc<AsyncMutex<Vec<(HeaderMap, Bytes)>>> =
            Arc::new(AsyncMutex::new(Vec::new()));
        let captured_srv = Arc::clone(&captured_outbound);
        let mock_callback = MockHttpServer::start(move |req: MockRequest| {
            let captured = Arc::clone(&captured_srv);
            async move {
                captured.lock().await.push((req.headers, req.body));
                MockResponse::json(StatusCode::OK, &json!({ "received": true }))
            }
        })
        .await;

        let node = open_test_node("webhook-node", tmp.path());
        node.register_handle("sess-wh", "agent").await.unwrap();
        node.subscribe_local_or_remote(SubscribeRequest {
            id: Some("sub-wh".to_string()),
            subscriber_session: "sess-wh".to_string(),
            qualified_topic: "local.webhook".to_string(),
            filters: Vec::new(),
            coalesce_seconds: 0,
            mode: DeliveryMode::Full,
        })
        .await
        .unwrap();

        let host = UnifiedNodeAdapterHost::new(Arc::clone(&node));
        let port = pick_free_loopback_port().await;
        let plugin_script = repo_root().join("plugins/webhook/index.mjs");
        assert!(plugin_script.exists(), "missing {}", plugin_script.display());

        let mut cfg = SubprocessConfig::new(
            "webhook-real",
            AdapterKind::Bridge,
            node_bin,
            vec![plugin_script.to_string_lossy().into_owned()],
            vec!["webhook".to_string()],
        );
        cfg.hello_mode = HelloMode::Auto;
        cfg.env.insert("WEBHOOK_HOST".into(), "127.0.0.1".into());
        cfg.env.insert("WEBHOOK_PORT".into(), port.to_string());
        cfg.env.insert("WEBHOOK_PATH".into(), "/webhook".into());
        cfg.env.insert("WEBHOOK_TARGET".into(), "webhook".into());
        cfg.env.insert(
            "WEBHOOK_SECRET_FILE".into(),
            secret_file.to_string_lossy().into_owned(),
        );
        cfg.env
            .insert("WEBHOOK_POST_URL".into(), mock_callback.url("/reply"));

        let supervisor = SubprocessSupervisor::new(cfg);
        supervisor.start(Arc::clone(&host) as _).await.unwrap();

        let webhook_url = format!("http://127.0.0.1:{port}/webhook");
        wait_for_http_ready(&format!("http://127.0.0.1:{port}/ready-probe"), Duration::from_secs(10)).await;

        let client = HttpClient::new().unwrap();

        // (a) Valid HMAC-SHA256 POST -> 202 + CloudEvent ingested into UnifiedNode!
        let valid_body = serde_json::to_vec(&json!({
            "id": "wh-evt-001",
            "type": "com.acme.deploy",
            "source": "ci/jenkins",
            "subject": "service/api",
            "data": { "sha": "deadbeef", "env": "staging" }
        }))
        .unwrap();
        let valid_sig = compute_hmac_sha256_header(secret.as_bytes(), &valid_body);
        let req_ok = Request::builder()
            .method(Method::POST)
            .uri(&webhook_url)
            .header(CONTENT_TYPE, "application/json")
            .header("x-webhook-signature-256", &valid_sig)
            .body(full_body(valid_body.clone()))
            .unwrap();
        let resp_ok = client.request(req_ok).await.unwrap();
        let (st_ok, _, body_ok) = HttpClient::collect(resp_ok, 64 * 1024).await.unwrap();
        assert_eq!(
            st_ok,
            StatusCode::ACCEPTED,
            "expected 202, got {st_ok}: {}",
            String::from_utf8_lossy(&body_ok)
        );
        let ack_json: Value = serde_json::from_slice(&body_ok).unwrap();
        assert_eq!(ack_json["status"], "stored");
        assert_eq!(ack_json["id"], "wh-evt-001");

        let events = host.wait_for_event_count(1, Duration::from_secs(5)).await;
        assert_eq!(events[0].0, "webhook");
        assert_eq!(events[0].1.id, "wh-evt-001");
        assert_eq!(events[0].1.event_type, "com.acme.deploy");
        assert_eq!(events[0].1.source, "ci/jenkins");
        assert_eq!(events[0].1.subject.as_deref(), Some("service/api"));

        // Verify the CloudEvent was genuinely persisted & matched to `sess-wh` in `UnifiedNode` SQLite!
        let batches = {
            let db = node.db();
            let now = now_ms();
            let _ = db.events().tick(now);
            db.events().claim_due_batches("sess-wh", now).unwrap()
        };
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].topic, "webhook");
        assert_eq!(batches[0].events.len(), 1);
        assert_eq!(batches[0].events[0].id, "wh-evt-001");
        assert_eq!(batches[0].events[0].data["sha"], json!("deadbeef"));

        // (b) 1-bit flipped HMAC signature -> 401!
        let mut bad_sig_bytes = valid_sig.clone().into_bytes();
        let last = bad_sig_bytes.len() - 1;
        bad_sig_bytes[last] = if bad_sig_bytes[last] == b'0' { b'1' } else { b'0' };
        let bad_sig = String::from_utf8(bad_sig_bytes).unwrap();
        let req_bad_sig = Request::builder()
            .method(Method::POST)
            .uri(&webhook_url)
            .header(CONTENT_TYPE, "application/json")
            .header("x-webhook-signature-256", bad_sig)
            .body(full_body(valid_body))
            .unwrap();
        let resp_bad_sig = client.request(req_bad_sig).await.unwrap();
        assert_eq!(resp_bad_sig.status(), StatusCode::UNAUTHORIZED);

        // (c) >64 KiB body -> 413 Payload Too Large!
        let oversized = vec![b'x'; 70_000];
        let oversized_sig = compute_hmac_sha256_header(secret.as_bytes(), &oversized);
        let req_big = Request::builder()
            .method(Method::POST)
            .uri(&webhook_url)
            .header(CONTENT_TYPE, "application/json")
            .header("x-webhook-signature-256", oversized_sig)
            .body(full_body(oversized))
            .unwrap();
        let resp_big = client.request(req_big).await.unwrap();
        assert_eq!(resp_big.status(), StatusCode::PAYLOAD_TOO_LARGE);

        // Neither rejected request may have ingested an event.
        assert_eq!(host.published_events().await.len(), 1);

        // (d) Outbound `supervisor.post(...)` -> loopback mock receives signed `X-Webhook-Signature-256`!
        let post_res = supervisor
            .post(
                "webhook",
                BTreeMap::from([
                    ("text".to_string(), json!("Deployment verified OK")),
                    ("channel".to_string(), json!("#ops")),
                ]),
                Duration::from_secs(5),
            )
            .await
            .expect("outbound webhook post must succeed");
        assert_eq!(post_res["ok"], json!(true));
        assert_eq!(post_res["status"], json!(200));

        let out_calls = captured_outbound.lock().await;
        assert_eq!(out_calls.len(), 1);
        let (out_headers, out_body) = &out_calls[0];
        let out_sig = out_headers
            .get("x-webhook-signature-256")
            .and_then(|v| v.to_str().ok());
        assert!(
            verify_hmac_sha256_header(secret.as_bytes(), out_body, out_sig, true),
            "outbound webhook POST must carry valid X-Webhook-Signature-256; got {out_sig:?}"
        );
        let out_json: Value = serde_json::from_slice(out_body).unwrap();
        assert_eq!(out_json["text"], "Deployment verified OK");
        assert_eq!(out_json["channel"], "#ops");

        let _ = supervisor.stop().await;
        node.shutdown();
    }

    // ========================================================================
    // 2. `plugins/prometheus/index.mjs` vs native Rust `PrometheusWebhookAdapter`
    //    (Differential Assertion + Invalid Auth 401)
    // ========================================================================

    #[tokio::test]
    async fn real_prometheus_plugin_differential_parity_with_native_rust_adapter() {
        let Some(node_bin) = find_binary("node") else {
            eprintln!("SKIP real_prometheus_plugin_differential_parity_with_native_rust_adapter: `node` not on PATH");
            return;
        };

        let tmp = TempDir::new().unwrap();
        let node_plugin_dir = tmp.path().join("node-plugin");
        let node_rust_dir = tmp.path().join("node-rust");

        let bearer_token = "prom-bearer-secret-998877";
        let hmac_secret = "prom-hmac-secret-112233";
        let bearer_file = tmp.path().join("prom.bearer");
        let hmac_file = tmp.path().join("prom.hmac");
        fs::write(&bearer_file, bearer_token).unwrap();
        fs::write(&hmac_file, hmac_secret).unwrap();

        let plugin_node = open_test_node("prom-plugin-node", &node_plugin_dir);
        let plugin_host = UnifiedNodeAdapterHost::new(Arc::clone(&plugin_node));

        let rust_node = open_test_node("prom-rust-node", &node_rust_dir);
        let rust_host = UnifiedNodeAdapterHost::new(Arc::clone(&rust_node));

        // Start native Rust `PrometheusWebhookAdapter`.
        let mut rust_cfg = PrometheusWebhookConfig::new("prom-native", "alerts");
        rust_cfg.bearer_token = Some(Zeroizing::new(bearer_token.to_string()));
        rust_cfg.webhook_secret = Some(Zeroizing::new(hmac_secret.to_string()));
        let rust_adapter = PrometheusWebhookAdapter::new(rust_cfg);
        rust_adapter.start(Arc::clone(&rust_host) as _).await.unwrap();

        // Start real `plugins/prometheus/index.mjs` subprocess.
        let port = pick_free_loopback_port().await;
        let plugin_script = repo_root().join("plugins/prometheus/index.mjs");
        assert!(plugin_script.exists(), "missing {}", plugin_script.display());

        let mut sub_cfg = SubprocessConfig::new(
            "prom-real",
            AdapterKind::Source,
            node_bin,
            vec![plugin_script.to_string_lossy().into_owned()],
            vec!["alerts".to_string()],
        );
        sub_cfg.hello_mode = HelloMode::Auto;
        sub_cfg.env.insert("PROMETHEUS_HOST".into(), "127.0.0.1".into());
        sub_cfg.env.insert("PROMETHEUS_PORT".into(), port.to_string());
        sub_cfg.env.insert("PROMETHEUS_PATH".into(), "/alerts".into());
        sub_cfg.env.insert("PROMETHEUS_TOPIC".into(), "alerts".into());
        sub_cfg.env.insert(
            "PROMETHEUS_BEARER_TOKEN_FILE".into(),
            bearer_file.to_string_lossy().into_owned(),
        );
        sub_cfg.env.insert(
            "PROMETHEUS_WEBHOOK_SECRET_FILE".into(),
            hmac_file.to_string_lossy().into_owned(),
        );

        let supervisor = SubprocessSupervisor::new(sub_cfg);
        supervisor.start(Arc::clone(&plugin_host) as _).await.unwrap();

        wait_for_http_ready(
            &format!("http://127.0.0.1:{port}/health"),
            Duration::from_secs(10),
        )
        .await;

        let alerts_url = format!("http://127.0.0.1:{port}/alerts");
        let alertmanager_v4_payload = serde_json::to_vec(&json!({
            "version": "4",
            "groupKey": "{}:{alertname=\"HighErrorRate\"}",
            "status": "firing",
            "receiver": "hyphae-oncall",
            "externalURL": "https://alertmanager.internal",
            "commonLabels": {
                "cluster": "prod-us-east",
                "service": "checkout-api"
            },
            "commonAnnotations": {
                "runbook": "https://runbooks.internal/errors"
            },
            "alerts": [
                {
                    "status": "firing",
                    "fingerprint": "fp-firing-001",
                    "labels": {
                        "alertname": "HighErrorRate",
                        "severity": "critical",
                        "instance": "checkout-01:9090"
                    },
                    "annotations": {
                        "summary": "5xx rate above 5%",
                        "description": "Checkout API returning elevated 500s"
                    },
                    "startsAt": "2026-11-24T12:00:00Z",
                    "endsAt": "0001-01-01T00:00:00Z",
                    "generatorURL": "https://prometheus.internal/graph?g0=1"
                },
                {
                    "status": "resolved",
                    "fingerprint": "fp-resolved-002",
                    "labels": {
                        "alertname": "HighLatency",
                        "severity": "warning",
                        "instance": "checkout-02:9090"
                    },
                    "annotations": {
                        "summary": "p99 latency recovered",
                        "description": "Latency returned below 200ms"
                    },
                    "startsAt": "2026-11-24T11:30:00Z",
                    "endsAt": "2026-11-24T12:05:00Z",
                    "generatorURL": "https://prometheus.internal/graph?g0=2"
                }
            ]
        }))
        .unwrap();

        let valid_sig = compute_hmac_sha256_header(hmac_secret.as_bytes(), &alertmanager_v4_payload);
        let client = HttpClient::new().unwrap();

        // 1. Send valid Alertmanager v4 payload to real Node plugin.
        let req_valid = Request::builder()
            .method(Method::POST)
            .uri(&alerts_url)
            .header(CONTENT_TYPE, "application/json")
            .header(AUTHORIZATION, format!("Bearer {bearer_token}"))
            .header("x-webhook-signature-256", &valid_sig)
            .body(full_body(alertmanager_v4_payload.clone()))
            .unwrap();
        let resp_valid = client.request(req_valid).await.unwrap();
        let (st_valid, _, body_valid) = HttpClient::collect(resp_valid, 64 * 1024).await.unwrap();
        assert_eq!(
            st_valid,
            StatusCode::OK,
            "prometheus plugin failed: {}",
            String::from_utf8_lossy(&body_valid)
        );
        let body_json: Value = serde_json::from_slice(&body_valid).unwrap();
        assert_eq!(body_json["ok"], json!(true));
        assert_eq!(body_json["alerts"], json!(2));

        // 2. Feed EXACT same headers & body to native Rust `PrometheusWebhookAdapter`!
        let mut rust_headers = HeaderMap::new();
        rust_headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {bearer_token}")).unwrap(),
        );
        rust_headers.insert(
            "x-webhook-signature-256",
            HeaderValue::from_str(&valid_sig).unwrap(),
        );
        rust_adapter
            .ingest_webhook(&rust_headers, &alertmanager_v4_payload)
            .await
            .expect("native Rust PrometheusWebhookAdapter must succeed");

        // 3. Differential oracle comparison: Node plugin CloudEvents == Rust adapter CloudEvents!
        let plugin_events = plugin_host
            .wait_for_event_count(2, Duration::from_secs(5))
            .await;
        let rust_events = rust_host.published_events().await;
        assert_eq!(plugin_events.len(), 2);
        assert_eq!(rust_events.len(), 2);

        for (idx, ((ptopic, pev), (rtopic, rev))) in
            plugin_events.iter().zip(rust_events.iter()).enumerate()
        {
            assert_eq!(ptopic, rtopic, "alert[{idx}] topic mismatch");
            assert_eq!(pev.id, rev.id, "alert[{idx}] id mismatch");
            assert_eq!(pev.event_type, rev.event_type, "alert[{idx}] type mismatch");
            assert_eq!(pev.source, rev.source, "alert[{idx}] source mismatch");
            assert_eq!(pev.subject, rev.subject, "alert[{idx}] subject mismatch");
            assert_eq!(pev.time, rev.time, "alert[{idx}] time mismatch");

            let pdata = pev.data.as_ref().expect("plugin alert data");
            let rdata = rev.data.as_ref().expect("rust alert data");
            for field in [
                "status",
                "alertname",
                "severity",
                "service",
                "instance",
                "summary",
                "description",
                "labels",
                "annotations",
                "startsAt",
                "endsAt",
                "generatorURL",
                "receiver",
                "externalURL",
            ] {
                assert_eq!(
                    pdata.get(field),
                    rdata.get(field),
                    "alert[{idx}] data.{field} mismatch: plugin={:?} vs rust={:?}",
                    pdata.get(field),
                    rdata.get(field)
                );
            }
        }
        assert_eq!(plugin_events[0].1.event_type, "io.prometheus.alert.firing");
        assert_eq!(plugin_events[1].1.event_type, "io.prometheus.alert.resolved");

        // 4. Invalid auth (wrong Bearer AND bad HMAC) -> 401 on BOTH plugin and Rust adapter!
        let req_bad_bearer = Request::builder()
            .method(Method::POST)
            .uri(&alerts_url)
            .header(CONTENT_TYPE, "application/json")
            .header(AUTHORIZATION, "Bearer wrong-token")
            .header("x-webhook-signature-256", &valid_sig)
            .body(full_body(alertmanager_v4_payload.clone()))
            .unwrap();
        assert_eq!(
            client.request(req_bad_bearer).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );

        let mut bad_rust_headers = HeaderMap::new();
        bad_rust_headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer wrong-token"));
        bad_rust_headers.insert(
            "x-webhook-signature-256",
            HeaderValue::from_str(&valid_sig).unwrap(),
        );
        assert!(matches!(
            rust_adapter
                .ingest_webhook(&bad_rust_headers, &alertmanager_v4_payload)
                .await,
            Err(AdapterError::Unauthorized(_))
        ));

        let req_bad_hmac = Request::builder()
            .method(Method::POST)
            .uri(&alerts_url)
            .header(CONTENT_TYPE, "application/json")
            .header(AUTHORIZATION, format!("Bearer {bearer_token}"))
            .header(
                "x-webhook-signature-256",
                "sha256=0000000000000000000000000000000000000000000000000000000000000000",
            )
            .body(full_body(alertmanager_v4_payload))
            .unwrap();
        assert_eq!(
            client.request(req_bad_hmac).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );

        let _ = rust_adapter.stop().await;
        let _ = supervisor.stop().await;
        plugin_node.shutdown();
        rust_node.shutdown();
    }

    // ========================================================================
    // 3. `plugins/telegram/index.mjs`: allowlist filter, offset persistence, & outbound sendMessage
    // ========================================================================

    #[tokio::test]
    async fn real_telegram_plugin_polling_allowlist_offset_and_outbound_post_e2e() {
        let Some(node_bin) = find_binary("node") else {
            eprintln!("SKIP real_telegram_plugin_polling_allowlist_offset_and_outbound_post_e2e: `node` not on PATH");
            return;
        };

        let tmp = TempDir::new().unwrap();
        let bot_token = "123456:FAKE_TEST_BOT_TOKEN";
        let token_file = tmp.path().join("tg.token");
        let state_file = tmp.path().join("tg.state.json");
        fs::write(&token_file, bot_token).unwrap();

        let sent_messages: Arc<AsyncMutex<Vec<Value>>> = Arc::new(AsyncMutex::new(Vec::new()));
        let sent_srv = Arc::clone(&sent_messages);
        let delivered_batch = Arc::new(AtomicBool::new(false));
        let delivered_srv = Arc::clone(&delivered_batch);

        let mock_tg = MockHttpServer::start(move |req: MockRequest| {
            let sent = Arc::clone(&sent_srv);
            let delivered = Arc::clone(&delivered_srv);
            async move {
                let body_val: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
                if req.path.ends_with("/getUpdates") {
                    let offset = body_val.get("offset").and_then(Value::as_i64).unwrap_or(0);
                    if offset == 0 && !delivered.swap(true, Ordering::SeqCst) {
                        return MockResponse::json(
                            StatusCode::OK,
                            &json!({
                                "ok": true,
                                "result": [
                                    {
                                        "update_id": 100,
                                        "message": {
                                            "message_id": 1,
                                            "date": 1764000000,
                                            "chat": { "id": 999999, "type": "private" },
                                            "from": { "id": 888, "username": "intruder", "first_name": "Evil" },
                                            "text": "DROP_ME_DISALLOWED_CHAT"
                                        }
                                    },
                                    {
                                        "update_id": 101,
                                        "message": {
                                            "message_id": 2,
                                            "date": 1764000001,
                                            "chat": { "id": 12345, "type": "private" },
                                            "from": { "id": 42, "username": "alice", "first_name": "Alice" },
                                            "text": "Hello from allowlisted Telegram chat!"
                                        }
                                    }
                                ]
                            }),
                        );
                    }
                    // Yield gently on subsequent long-polls so mock does not spin.
                    tokio::time::sleep(Duration::from_millis(150)).await;
                    return MockResponse::json(StatusCode::OK, &json!({ "ok": true, "result": [] }));
                }
                if req.path.ends_with("/sendMessage") {
                    sent.lock().await.push(body_val);
                    return MockResponse::json(
                        StatusCode::OK,
                        &json!({ "ok": true, "result": { "message_id": 777 } }),
                    );
                }
                MockResponse::json(
                    StatusCode::NOT_FOUND,
                    &json!({ "ok": false, "description": "unknown method" }),
                )
            }
        })
        .await;

        let node = open_test_node("tg-node", tmp.path());
        let host = UnifiedNodeAdapterHost::new(Arc::clone(&node));
        let plugin_script = repo_root().join("plugins/telegram/index.mjs");
        assert!(plugin_script.exists(), "missing {}", plugin_script.display());

        let mut cfg = SubprocessConfig::new(
            "telegram-real",
            AdapterKind::Bridge,
            node_bin,
            vec![plugin_script.to_string_lossy().into_owned()],
            vec!["telegram".to_string()],
        );
        cfg.hello_mode = HelloMode::Auto;
        cfg.env.insert(
            "TELEGRAM_BOT_TOKEN_FILE".into(),
            token_file.to_string_lossy().into_owned(),
        );
        cfg.env.insert("TELEGRAM_TARGET".into(), "telegram".into());
        cfg.env.insert("TELEGRAM_ALLOWED_CHATS".into(), "12345".into());
        cfg.env.insert("TELEGRAM_API_BASE".into(), mock_tg.base_url());
        cfg.env.insert(
            "TELEGRAM_STATE_FILE".into(),
            state_file.to_string_lossy().into_owned(),
        );

        let supervisor = SubprocessSupervisor::new(cfg);
        supervisor.start(Arc::clone(&host) as _).await.unwrap();

        // Allowlisted chat 12345 MUST arrive as a CloudEvent; disallowed chat 999999 MUST be dropped!
        let _ = host.wait_for_event_count(1, Duration::from_secs(10)).await;
        // Give the polling loop a brief moment to persist offset 102 after ack.
        let offset_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            if let Ok(raw) = fs::read_to_string(&state_file) {
                if let Ok(v) = serde_json::from_str::<Value>(&raw) {
                    if v.get("offset").and_then(Value::as_i64) == Some(102) {
                        break;
                    }
                }
            }
            assert!(
                tokio::time::Instant::now() < offset_deadline,
                "timed out waiting for TELEGRAM_STATE_FILE offset=102"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }

        let all_events = host.published_events().await;
        assert_eq!(all_events.len(), 1, "non-allowlisted chat must be dropped silently");
        assert_eq!(all_events[0].0, "telegram");
        assert_eq!(all_events[0].1.id, "101");
        assert_eq!(all_events[0].1.event_type, "com.telegram.message");
        let tg_data = all_events[0].1.data.as_ref().expect("telegram event data");
        assert_eq!(tg_data["chat_id"], json!(12345));
        assert_eq!(
            tg_data["text"],
            json!("Hello from allowlisted Telegram chat!")
        );

        // Outbound post to allowlisted chat -> mock `sendMessage` receives it!
        let post_ok = supervisor
            .post(
                "telegram",
                BTreeMap::from([
                    ("chatId".to_string(), json!("12345")),
                    ("text".to_string(), json!("Reply from Hyphae agent")),
                    ("replyTo".to_string(), json!("2")),
                ]),
                Duration::from_secs(5),
            )
            .await
            .expect("allowed Telegram post must succeed");
        assert_eq!(post_ok["ok"], json!(true));
        assert_eq!(post_ok["chatId"], json!("12345"));
        assert_eq!(post_ok["messageId"], json!(777));

        // Outbound post to disallowed chat -> fails closed & never hits mock API!
        let post_denied = supervisor
            .post(
                "telegram",
                BTreeMap::from([
                    ("chatId".to_string(), json!("999999")),
                    ("text".to_string(), json!("Should never be sent")),
                ]),
                Duration::from_secs(5),
            )
            .await
            .expect_err("disallowed Telegram chat must fail closed");
        assert!(
            matches!(&post_denied, AdapterError::RequestFailed(msg) if msg.contains("TELEGRAM_ALLOWED_CHATS")),
            "expected TELEGRAM_ALLOWED_CHATS error, got {post_denied:?}"
        );

        let outbound = sent_messages.lock().await;
        assert_eq!(outbound.len(), 1, "only allowlisted sendMessage may be called");
        assert_eq!(outbound[0]["chat_id"], json!("12345"));
        assert_eq!(outbound[0]["text"], json!("Reply from Hyphae agent"));
        assert_eq!(outbound[0]["reply_to_message_id"], json!(2));

        let _ = supervisor.stop().await;
        node.shutdown();
    }

    // ========================================================================
    // 4. `plugins/slack/index.mjs`: fail-closed startup guards + loopback mock `auth.test` / `chat.postMessage`
    // ========================================================================

    #[tokio::test]
    async fn real_slack_plugin_fail_closed_guards_and_outbound_post_e2e() {
        let Some(node_bin) = find_binary("node") else {
            eprintln!("SKIP real_slack_plugin_fail_closed_guards_and_outbound_post_e2e: `node` not on PATH");
            return;
        };

        let tmp = TempDir::new().unwrap();
        let plugin_script = repo_root().join("plugins/slack/index.mjs");
        assert!(plugin_script.exists(), "missing {}", plugin_script.display());

        let app_token = "xapp-test-1-000";
        let bot_token = "xoxb-test-2-000";
        let app_token_file = tmp.path().join("slack.app");
        let bot_token_file = tmp.path().join("slack.bot");
        fs::write(&app_token_file, app_token).unwrap();
        fs::write(&bot_token_file, bot_token).unwrap();

        // (a) Fails closed when NO allowlist is configured!
        let no_allowlist = tokio::process::Command::new(&node_bin)
            .arg(&plugin_script)
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("SLACK_APP_TOKEN_FILE", &app_token_file)
            .env("SLACK_BOT_TOKEN_FILE", &bot_token_file)
            .output()
            .await
            .expect("run slack plugin without allowlist");
        assert!(
            !no_allowlist.status.success(),
            "Slack plugin MUST exit non-zero without allowlist"
        );
        let stderr_no_allow = String::from_utf8_lossy(&no_allowlist.stderr);
        assert!(
            stderr_no_allow.contains("SLACK_ALLOWED_USERS")
                && stderr_no_allow.contains("SLACK_ALLOWED_CHANNELS"),
            "unexpected stderr for missing allowlist: {stderr_no_allow}"
        );

        // (b) Rejects non-HTTPS non-loopback `SLACK_API_BASE`!
        let bad_base = tokio::process::Command::new(&node_bin)
            .arg(&plugin_script)
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("SLACK_APP_TOKEN_FILE", &app_token_file)
            .env("SLACK_BOT_TOKEN_FILE", &bot_token_file)
            .env("SLACK_ALLOWED_CHANNELS", "C_ALLOW")
            .env("SLACK_API_BASE", "http://evil.example.com/api")
            .output()
            .await
            .expect("run slack plugin with non-https non-loopback api base");
        assert!(
            !bad_base.status.success(),
            "Slack plugin MUST reject non-HTTPS non-loopback SLACK_API_BASE"
        );
        let stderr_bad_base = String::from_utf8_lossy(&bad_base.stderr);
        assert!(
            stderr_bad_base.contains("SLACK_API_BASE must use https:// or loopback http://"),
            "unexpected stderr for bad SLACK_API_BASE: {stderr_bad_base}"
        );

        // (c) Connects to loopback mock `SLACK_API_BASE` (`auth.test` / `chat.postMessage`)
        //     and verifies outbound `supervisor.post(...)` + channel allowlist enforcement!
        type SlackPostCapture = Vec<(Option<String>, Value)>;
        let auth_tested = Arc::new(AtomicBool::new(false));
        let auth_tested_srv = Arc::clone(&auth_tested);
        let posted_messages: Arc<AsyncMutex<SlackPostCapture>> =
            Arc::new(AsyncMutex::new(Vec::new()));
        let posted_srv = Arc::clone(&posted_messages);

        let mock_slack = MockHttpServer::start(move |req: MockRequest| {
            let auth_flag = Arc::clone(&auth_tested_srv);
            let posted = Arc::clone(&posted_srv);
            async move {
                let auth_hdr = req.header_str("authorization").map(ToOwned::to_owned);
                let body_val: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
                if req.path.ends_with("/auth.test") {
                    if auth_hdr.as_deref() == Some("Bearer xoxb-test-2-000") {
                        auth_flag.store(true, Ordering::SeqCst);
                        return MockResponse::json(
                            StatusCode::OK,
                            &json!({ "ok": true, "user_id": "U_HYPHAE_BOT", "team_id": "T_ACME" }),
                        );
                    }
                    return MockResponse::json(
                        StatusCode::UNAUTHORIZED,
                        &json!({ "ok": false, "error": "invalid_auth" }),
                    );
                }
                if req.path.ends_with("/apps.connections.open") {
                    // Return cleanly so the socket reconnect loop backs off while `onPost` stays live!
                    return MockResponse::json(
                        StatusCode::OK,
                        &json!({ "ok": false, "error": "test_socket_paused" }),
                    );
                }
                if req.path.ends_with("/chat.postMessage") {
                    posted.lock().await.push((auth_hdr, body_val.clone()));
                    return MockResponse::json(
                        StatusCode::OK,
                        &json!({
                            "ok": true,
                            "channel": body_val["channel"],
                            "ts": "1764000123.000400"
                        }),
                    );
                }
                MockResponse::json(
                    StatusCode::NOT_FOUND,
                    &json!({ "ok": false, "error": "unknown_method" }),
                )
            }
        })
        .await;

        let node = open_test_node("slack-node", tmp.path());
        let host = UnifiedNodeAdapterHost::new(Arc::clone(&node));

        let mut cfg = SubprocessConfig::new(
            "slack-real",
            AdapterKind::Bridge,
            node_bin,
            vec![plugin_script.to_string_lossy().into_owned()],
            vec!["slack".to_string()],
        );
        cfg.hello_mode = HelloMode::Auto;
        cfg.env.insert(
            "SLACK_APP_TOKEN_FILE".into(),
            app_token_file.to_string_lossy().into_owned(),
        );
        cfg.env.insert(
            "SLACK_BOT_TOKEN_FILE".into(),
            bot_token_file.to_string_lossy().into_owned(),
        );
        cfg.env.insert("SLACK_TARGET".into(), "slack".into());
        cfg.env.insert("SLACK_ALLOWED_CHANNELS".into(), "C_ALLOW".into());
        cfg.env.insert("SLACK_DEFAULT_CHANNEL".into(), "C_ALLOW".into());
        cfg.env.insert("SLACK_API_BASE".into(), mock_slack.base_url());

        let supervisor = SubprocessSupervisor::new(cfg);
        supervisor.start(Arc::clone(&host) as _).await.unwrap();

        // Wait for `auth.test` to succeed (proves `mesh.ready` completed AND bot token verified).
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while !auth_tested.load(Ordering::SeqCst) {
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for Slack plugin auth.test call"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }

        // Outbound post to allowlisted channel -> calls mock `chat.postMessage`!
        let ok_res = supervisor
            .post(
                "slack",
                BTreeMap::from([
                    ("channel".to_string(), json!("C_ALLOW")),
                    ("text".to_string(), json!("Release v2.2.0 complete")),
                    ("threadTs".to_string(), json!("1764000000.000100")),
                ]),
                Duration::from_secs(5),
            )
            .await
            .expect("allowed Slack post must succeed");
        assert_eq!(ok_res["ok"], json!(true));
        assert_eq!(ok_res["channel"], json!("C_ALLOW"));
        assert_eq!(ok_res["ts"], json!("1764000123.000400"));

        // Outbound post to non-allowlisted channel -> fails closed!
        let denied_res = supervisor
            .post(
                "slack",
                BTreeMap::from([
                    ("channel".to_string(), json!("C_FORBIDDEN")),
                    ("text".to_string(), json!("Should be rejected")),
                ]),
                Duration::from_secs(5),
            )
            .await
            .expect_err("disallowed Slack channel must fail closed");
        assert!(
            matches!(&denied_res, AdapterError::RequestFailed(msg) if msg.contains("SLACK_ALLOWED_CHANNELS")),
            "expected SLACK_ALLOWED_CHANNELS error, got {denied_res:?}"
        );

        let sent = posted_messages.lock().await;
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0.as_deref(), Some("Bearer xoxb-test-2-000"));
        assert_eq!(sent[0].1["channel"], json!("C_ALLOW"));
        assert_eq!(sent[0].1["text"], json!("Release v2.2.0 complete"));
        assert_eq!(sent[0].1["thread_ts"], json!("1764000000.000100"));

        let _ = supervisor.stop().await;
        node.shutdown();
    }

    // ========================================================================
    // 5a. Node SDK Direct Verification (`plugins/sdk/client.mjs`)
    // ========================================================================

    #[tokio::test]
    async fn real_node_sdk_client_mjs_hello_ack_nack_and_post_rpc_e2e() {
        let Some(node_bin) = find_binary("node") else {
            eprintln!("SKIP real_node_sdk_client_mjs_hello_ack_nack_and_post_rpc_e2e: `node` not on PATH");
            return;
        };

        let tmp = TempDir::new().unwrap();
        let sdk_path = repo_root().join("plugins/sdk/client.mjs");
        assert!(sdk_path.exists(), "missing {}", sdk_path.display());
        let report_file = tmp.path().join("sdk_mjs_report.json");
        let helper_script = tmp.path().join("sdk_mjs_harness.mjs");

        fs::write(
            &helper_script,
            r#"
import { writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

const { MeshPluginClient } = await import(pathToFileURL(process.env.SDK_MJS_PATH).href);

const mesh = new MeshPluginClient({
  onPost: async (params) => {
    if (params.fail) throw new Error("intentional_post_failure");
    return { echoed: params.text, target: params.target };
  },
});

const hello = await mesh.ready;

const validEvent = {
  specversion: "1.0",
  id: "sdk-mjs-evt-1",
  source: "sdk/node-test",
  type: "com.hyphae.sdk.ping",
  time: "2026-11-24T12:00:00Z",
  datacontenttype: "application/json",
  data: { ok: true, lang: "mjs" },
};
const ackStored = await mesh.send("sdk-node", validEvent);
const ackDup = await mesh.send("sdk-node", validEvent);
const nackInvalid = await mesh.send("sdk-node", {
  specversion: "9.9",
  id: "",
  source: "bad",
  type: "bad",
});
const nackTarget = await mesh.send("unconfigured-target", validEvent);

writeFileSync(
  process.env.SDK_REPORT_FILE,
  JSON.stringify({ hello, ackStored, ackDup, nackInvalid, nackTarget }),
  "utf8",
);

// Keep alive for outbound `post` RPCs until fd 3 closes cleanly on stop().
setInterval(() => {}, 10_000);
"#,
        )
        .unwrap();

        let node = open_test_node("sdk-mjs-node", tmp.path());
        let host = UnifiedNodeAdapterHost::new(Arc::clone(&node));

        let mut cfg = SubprocessConfig::new(
            "sdk-mjs-test",
            AdapterKind::Bridge,
            node_bin,
            vec![helper_script.to_string_lossy().into_owned()],
            vec!["sdk-node".to_string()],
        );
        cfg.hello_mode = HelloMode::Auto;
        cfg.env.insert(
            "SDK_MJS_PATH".into(),
            sdk_path.to_string_lossy().into_owned(),
        );
        cfg.env.insert(
            "SDK_REPORT_FILE".into(),
            report_file.to_string_lossy().into_owned(),
        );

        let supervisor = SubprocessSupervisor::new(cfg);
        supervisor.start(Arc::clone(&host) as _).await.unwrap();

        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let report: Value = loop {
            if let Ok(raw) = fs::read_to_string(&report_file) {
                if let Ok(v) = serde_json::from_str::<Value>(&raw) {
                    break v;
                }
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for sdk_mjs_report.json"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        };

        assert_eq!(report["hello"]["type"], "hello");
        assert_eq!(report["hello"]["protocol"], 1);
        assert_eq!(report["hello"]["targets"], json!(["sdk-node"]));
        assert_eq!(report["ackStored"]["type"], "ack");
        assert_eq!(report["ackStored"]["status"], "stored");
        assert_eq!(report["ackDup"]["type"], "ack");
        assert_eq!(report["ackDup"]["status"], "duplicate");
        assert_eq!(report["nackInvalid"]["type"], "nack");
        assert_eq!(report["nackInvalid"]["error"], "invalid_event");
        assert_eq!(report["nackTarget"]["type"], "nack");
        assert_eq!(report["nackTarget"]["error"], "unknown_target");

        let ingested = host.published_events().await;
        assert_eq!(ingested.len(), 1);
        assert_eq!(ingested[0].1.id, "sdk-mjs-evt-1");

        // Outbound `post` RPC round-trip (success + error propagation)!
        let rpc_ok = supervisor
            .post(
                "sdk-node",
                BTreeMap::from([("text".to_string(), json!("hello-mjs-sdk"))]),
                Duration::from_secs(5),
            )
            .await
            .expect("sdk.mjs post RPC must succeed");
        assert_eq!(rpc_ok["echoed"], json!("hello-mjs-sdk"));
        assert_eq!(rpc_ok["target"], json!("sdk-node"));

        let rpc_err = supervisor
            .post(
                "sdk-node",
                BTreeMap::from([("fail".to_string(), json!(true))]),
                Duration::from_secs(5),
            )
            .await
            .expect_err("sdk.mjs post handler error must propagate");
        assert!(
            matches!(&rpc_err, AdapterError::RequestFailed(msg) if msg.contains("intentional_post_failure")),
            "unexpected post RPC error: {rpc_err:?}"
        );

        let _ = supervisor.stop().await;
        node.shutdown();
    }

    // ========================================================================
    // 5b. Python SDK Direct Verification (`plugins/sdk/client.py`)
    // ========================================================================

    #[tokio::test]
    async fn real_python_sdk_client_py_hello_ack_nack_and_status_e2e() {
        let Some(python_bin) = find_binary("python3") else {
            eprintln!("SKIP real_python_sdk_client_py_hello_ack_nack_and_status_e2e: `python3` not on PATH");
            return;
        };

        let tmp = TempDir::new().unwrap();
        let sdk_dir = repo_root().join("plugins/sdk");
        assert!(sdk_dir.join("client.py").exists(), "missing client.py");
        let report_file = tmp.path().join("sdk_py_report.json");
        let status_file = tmp.path().join("sdk_py_status.json");
        let helper_script = tmp.path().join("sdk_py_harness.py");

        fs::write(
            &helper_script,
            r#"
import json
import os
import sys

sys.path.insert(0, os.environ["SDK_PY_DIR"])
from client import MeshPluginClient

def on_status(msg):
    with open(os.environ["SDK_STATUS_FILE"], "w", encoding="utf-8") as f:
        json.dump(msg, f)

client = MeshPluginClient(on_status=on_status)

valid_event = {
    "specversion": "1.0",
    "id": "sdk-py-evt-1",
    "source": "sdk/python-test",
    "type": "com.hyphae.sdk.py.ping",
    "time": "2026-11-24T12:00:00Z",
    "datacontenttype": "application/json",
    "data": {"ok": True, "lang": "python"},
}

ack_stored = client.send("sdk-py", valid_event, retry_unavailable=False)
ack_dup = client.send("sdk-py", valid_event, retry_unavailable=False)

nack_invalid_err = None
try:
    client.send("sdk-py", {"specversion": "9.9", "id": "", "source": "x", "type": "y"}, retry_unavailable=False)
except RuntimeError as exc:
    nack_invalid_err = str(exc)

nack_target_err = None
try:
    client.send("wrong-target", valid_event, retry_unavailable=False)
except RuntimeError as exc:
    nack_target_err = str(exc)

with open(os.environ["SDK_REPORT_FILE"], "w", encoding="utf-8") as f:
    json.dump({
        "plugin": client.plugin,
        "targets": client.targets,
        "ack_stored": ack_stored,
        "ack_dup": ack_dup,
        "nack_invalid_err": nack_invalid_err,
        "nack_target_err": nack_target_err,
    }, f)

# Wait cleanly until fd 3 closes on supervisor.stop() so supervisor does not restart us.
client._dead.wait(timeout=15)
"#,
        )
        .unwrap();

        let node = open_test_node("sdk-py-node", tmp.path());
        let host = UnifiedNodeAdapterHost::new(Arc::clone(&node));

        let mut cfg = SubprocessConfig::new(
            "sdk-py-test",
            AdapterKind::Source,
            python_bin,
            vec![helper_script.to_string_lossy().into_owned()],
            vec!["sdk-py".to_string()],
        );
        cfg.hello_mode = HelloMode::Auto;
        cfg.env.insert(
            "SDK_PY_DIR".into(),
            sdk_dir.to_string_lossy().into_owned(),
        );
        cfg.env.insert(
            "SDK_REPORT_FILE".into(),
            report_file.to_string_lossy().into_owned(),
        );
        cfg.env.insert(
            "SDK_STATUS_FILE".into(),
            status_file.to_string_lossy().into_owned(),
        );

        let supervisor = SubprocessSupervisor::new(cfg);
        supervisor.start(Arc::clone(&host) as _).await.unwrap();

        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let report: Value = loop {
            if let Ok(raw) = fs::read_to_string(&report_file) {
                if let Ok(v) = serde_json::from_str::<Value>(&raw) {
                    break v;
                }
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for sdk_py_report.json"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        };

        assert_eq!(report["plugin"], "sdk-py-test");
        assert_eq!(report["targets"], json!(["sdk-py"]));
        assert_eq!(report["ack_stored"]["type"], "ack");
        assert_eq!(report["ack_stored"]["status"], "stored");
        assert_eq!(report["ack_dup"]["type"], "ack");
        assert_eq!(report["ack_dup"]["status"], "duplicate");
        let inv_err = report["nack_invalid_err"]
            .as_str()
            .expect("invalid event must raise RuntimeError on nack");
        assert!(
            inv_err.contains("invalid_event"),
            "expected invalid_event in python nack error, got {inv_err}"
        );
        let tgt_err = report["nack_target_err"]
            .as_str()
            .expect("unknown target must raise RuntimeError on nack");
        assert!(
            tgt_err.contains("unknown_target"),
            "expected unknown_target in python nack error, got {tgt_err}"
        );

        // Verify host -> Python `status` notification delivery as well!
        supervisor
            .send_status(StatusParams {
                target: "sdk-py".to_string(),
                pending: 3,
                oldest_age_seconds: 12,
                t3_connected: true,
            })
            .await
            .expect("send_status to python sdk must succeed");

        let st_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let st_msg: Value = loop {
            if let Ok(raw) = fs::read_to_string(&status_file) {
                if let Ok(v) = serde_json::from_str::<Value>(&raw) {
                    break v;
                }
            }
            assert!(
                tokio::time::Instant::now() < st_deadline,
                "timed out waiting for Python on_status callback"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        };
        assert_eq!(st_msg["type"], "status");
        assert_eq!(st_msg["target"], "sdk-py");
        assert_eq!(st_msg["pending"], 3);

        let ingested = host.published_events().await;
        assert_eq!(ingested.len(), 1);
        assert_eq!(ingested[0].1.id, "sdk-py-evt-1");

        let _ = supervisor.stop().await;
        node.shutdown();
    }
}
