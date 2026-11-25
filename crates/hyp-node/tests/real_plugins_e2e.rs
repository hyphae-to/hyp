//! Real External Plugins & SDK Subprocess E2E Tests (`plugins/*` + `SubprocessSupervisor` + `UnifiedNode`).
//!
//! Spawns the **real repository plugin scripts** under `plugins/` over BOTH Unix fd-3 IPC (Unix)
//! and authenticated loopback-TCP IPC (`PluginTransportMode::LoopbackTcp`, Unix + Windows) via
//! `SubprocessSupervisor` wired into a live `UnifiedNode`, with loopback-only mock external APIs
//! (`MockHttpServer`) and ephemeral `TempDir` state.
//!
//! Individual Node/Python tests skip gracefully ONLY if `node` or Python 3 is missing from `PATH`.

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
    use sha2::{Digest, Sha256};
    use tempfile::TempDir;
    use tokio::net::TcpListener;
    use tokio::sync::Mutex as AsyncMutex;
    use zeroize::Zeroizing;

    use crate::common::{MockHttpServer, MockRequest, MockResponse, UnifiedNodeAdapterHost};
    use hyp_crypto::SecretBackend;
    use hyp_node::adapters::{
        AdapterError, AdapterHealth, AdapterKind, HelloMode, NodeAdapter, PrometheusWebhookAdapter,
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

        // (a) Valid HMAC-SHA256 POST -> 202 + deterministic SHA-256 event ID ingested into UnifiedNode!
        let valid_body = serde_json::to_vec(&json!({
            "id": "wh-evt-001",
            "type": "com.acme.deploy",
            "source": "ci/jenkins",
            "subject": "service/api",
            "data": { "sha": "deadbeef", "env": "staging" }
        }))
        .unwrap();
        let expected_id = format!("sha256:{}", hex::encode(Sha256::digest(&valid_body)));
        let valid_sig = compute_hmac_sha256_header(secret.as_bytes(), &valid_body);
        let req_ok = Request::builder()
            .method(Method::POST)
            .uri(&webhook_url)
            .header(CONTENT_TYPE, "application/json")
            .header("x-webhook-signature-256", &valid_sig)
            .header("x-delivery-id", "unsigned-header-id-ignored-1")
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
        assert_eq!(ack_json["id"], expected_id);

        // Replaying the same signed body with a different unsigned `x-delivery-id` MUST yield
        // the exact same SHA-256 event ID and deduplicate (`status: "duplicate"`)!
        let req_replay_hdr = Request::builder()
            .method(Method::POST)
            .uri(&webhook_url)
            .header(CONTENT_TYPE, "application/json")
            .header("x-webhook-signature-256", &valid_sig)
            .header("x-delivery-id", "unsigned-header-id-ignored-2")
            .body(full_body(valid_body.clone()))
            .unwrap();
        let resp_replay_hdr = client.request(req_replay_hdr).await.unwrap();
        let (st_rep, _, body_rep) = HttpClient::collect(resp_replay_hdr, 64 * 1024).await.unwrap();
        assert_eq!(st_rep, StatusCode::ACCEPTED);
        let rep_json: Value = serde_json::from_slice(&body_rep).unwrap();
        assert_eq!(rep_json["status"], "duplicate");
        assert_eq!(rep_json["id"], expected_id);

        let events = host.wait_for_event_count(1, Duration::from_secs(5)).await;
        assert_eq!(events[0].0, "webhook");
        assert_eq!(events[0].1.id, expected_id);
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
        assert_eq!(batches[0].events[0].id, expected_id);
        assert_eq!(batches[0].events[0].data["sha"], json!("deadbeef"));

        // (a2) Timestamp-bound HMAC (`x-webhook-timestamp`) within 5m passes; stale >5m fails 401!
        let fresh_ts = (now_ms() / 1000).to_string();
        let ts_body = serde_json::to_vec(&json!({
            "type": "com.acme.deploy",
            "source": "ci/jenkins",
            "data": { "sha": "cafebabe" }
        }))
        .unwrap();
        let mut ts_signed_input = format!("{fresh_ts}.").into_bytes();
        ts_signed_input.extend_from_slice(&ts_body);
        let fresh_ts_sig = compute_hmac_sha256_header(secret.as_bytes(), &ts_signed_input);
        let req_ts_ok = Request::builder()
            .method(Method::POST)
            .uri(&webhook_url)
            .header(CONTENT_TYPE, "application/json")
            .header("x-webhook-timestamp", &fresh_ts)
            .header("x-webhook-signature-256", &fresh_ts_sig)
            .body(full_body(ts_body.clone()))
            .unwrap();
        let resp_ts_ok = client.request(req_ts_ok).await.unwrap();
        assert_eq!(resp_ts_ok.status(), StatusCode::ACCEPTED);
        let _ = host.wait_for_event_count(2, Duration::from_secs(5)).await;

        let stale_ts = ((now_ms() / 1000) - 600).to_string();
        let mut stale_input = format!("{stale_ts}.").into_bytes();
        stale_input.extend_from_slice(&ts_body);
        let stale_sig = compute_hmac_sha256_header(secret.as_bytes(), &stale_input);
        let req_ts_stale = Request::builder()
            .method(Method::POST)
            .uri(&webhook_url)
            .header(CONTENT_TYPE, "application/json")
            .header("x-webhook-timestamp", &stale_ts)
            .header("x-webhook-signature-256", &stale_sig)
            .body(full_body(ts_body))
            .unwrap();
        assert_eq!(
            client.request(req_ts_stale).await.unwrap().status(),
            StatusCode::UNAUTHORIZED,
            "expired x-webhook-timestamp (>5m) MUST fail 401"
        );

        // Stale signed payload timestamp MUST also fail 401!
        let stale_payload_body = serde_json::to_vec(&json!({
            "type": "com.acme.deploy",
            "source": "ci/jenkins",
            "timestamp": "2020-01-01T00:00:00Z",
            "data": { "sha": "old" }
        }))
        .unwrap();
        let stale_payload_sig = compute_hmac_sha256_header(secret.as_bytes(), &stale_payload_body);
        let req_stale_payload = Request::builder()
            .method(Method::POST)
            .uri(&webhook_url)
            .header(CONTENT_TYPE, "application/json")
            .header("x-webhook-signature-256", &stale_payload_sig)
            .body(full_body(stale_payload_body))
            .unwrap();
        assert_eq!(
            client.request(req_stale_payload).await.unwrap().status(),
            StatusCode::UNAUTHORIZED,
            "stale signed payload timestamp MUST fail 401"
        );

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

        // None of the rejected requests (nor the duplicate replay) may have added a 3rd event.
        assert_eq!(host.published_events().await.len(), 2);

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
        let sent_reactions: Arc<AsyncMutex<Vec<Value>>> = Arc::new(AsyncMutex::new(Vec::new()));
        let reactions_srv = Arc::clone(&sent_reactions);
        let delivered_batch = Arc::new(AtomicBool::new(false));
        let delivered_srv = Arc::clone(&delivered_batch);

        let mock_tg = MockHttpServer::start(move |req: MockRequest| {
            let sent = Arc::clone(&sent_srv);
            let reactions = Arc::clone(&reactions_srv);
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
                if req.path.ends_with("/setMessageReaction") {
                    reactions.lock().await.push(body_val);
                    return MockResponse::json(
                        StatusCode::OK,
                        &json!({ "ok": true, "result": true }),
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
        drop(outbound);

        // Reactions:
        // (1) Explicit `replyTo` reaction-only (no text!) -> calls `setMessageReaction` ONLY.
        let rxn_explicit = supervisor
            .post(
                "telegram",
                BTreeMap::from([
                    ("chatId".to_string(), json!("12345")),
                    ("reaction".to_string(), json!("👍")),
                    ("replyTo".to_string(), json!("42")),
                    ("text".to_string(), json!("")),
                ]),
                Duration::from_secs(5),
            )
            .await
            .expect("explicit Telegram reaction must succeed");
        assert_eq!(rxn_explicit["ok"], json!(true));
        assert_eq!(rxn_explicit["chatId"], json!("12345"));
        assert_eq!(rxn_explicit["reacted"], json!(true));
        assert_eq!(rxn_explicit["reaction"], json!("👍"));
        assert_eq!(rxn_explicit["reactedMessageId"], json!(42));
        assert!(rxn_explicit.get("messageId").is_none());

        // (2) Omitted `replyTo` & `chatId` -> falls back cleanly to last inbound chat (12345) & message_id (2)!
        let rxn_fallback = supervisor
            .post(
                "telegram",
                BTreeMap::from([
                    ("reaction".to_string(), json!("🔥")),
                    ("text".to_string(), json!("")),
                ]),
                Duration::from_secs(5),
            )
            .await
            .expect("fallback Telegram reaction must succeed");
        assert_eq!(rxn_fallback["ok"], json!(true));
        assert_eq!(rxn_fallback["chatId"], json!("12345"));
        assert_eq!(rxn_fallback["reacted"], json!(true));
        assert_eq!(rxn_fallback["reaction"], json!("🔥"));
        assert_eq!(rxn_fallback["reactedMessageId"], json!(2));

        // (3) Empty `reaction: ""` -> removes reaction (`reaction: []`)!
        let rxn_clear = supervisor
            .post(
                "telegram",
                BTreeMap::from([
                    ("chatId".to_string(), json!("12345")),
                    ("reaction".to_string(), json!("")),
                    ("replyTo".to_string(), json!("42")),
                    ("text".to_string(), json!("")),
                ]),
                Duration::from_secs(5),
            )
            .await
            .expect("empty Telegram reaction removal must succeed");
        assert_eq!(rxn_clear["ok"], json!(true));
        assert_eq!(rxn_clear["reacted"], json!(true));
        assert_eq!(rxn_clear["reaction"], json!(""));
        assert_eq!(rxn_clear["reactedMessageId"], json!(42));

        // (4) Combo `reaction` + `text` -> calls BOTH `setMessageReaction` AND `sendMessage`!
        let rxn_combo = supervisor
            .post(
                "telegram",
                BTreeMap::from([
                    ("chatId".to_string(), json!("12345")),
                    ("reaction".to_string(), json!("🎉")),
                    ("replyTo".to_string(), json!("2")),
                    ("text".to_string(), json!("On it!")),
                ]),
                Duration::from_secs(5),
            )
            .await
            .expect("combo Telegram reaction+text must succeed");
        assert_eq!(rxn_combo["ok"], json!(true));
        assert_eq!(rxn_combo["reacted"], json!(true));
        assert_eq!(rxn_combo["reaction"], json!("🎉"));
        assert_eq!(rxn_combo["reactedMessageId"], json!(2));
        assert_eq!(rxn_combo["messageId"], json!(777));

        // (5) Disallowed chat reaction -> fails closed & never hits `setMessageReaction`!
        let rxn_denied = supervisor
            .post(
                "telegram",
                BTreeMap::from([
                    ("chatId".to_string(), json!("999999")),
                    ("reaction".to_string(), json!("👍")),
                    ("replyTo".to_string(), json!("1")),
                ]),
                Duration::from_secs(5),
            )
            .await
            .expect_err("disallowed Telegram chat reaction must fail closed");
        assert!(
            matches!(&rxn_denied, AdapterError::RequestFailed(msg) if msg.contains("TELEGRAM_ALLOWED_CHATS")),
            "expected TELEGRAM_ALLOWED_CHATS error on reaction, got {rxn_denied:?}"
        );

        let rxn_calls = sent_reactions.lock().await;
        assert_eq!(rxn_calls.len(), 4, "expected exactly 4 setMessageReaction calls");
        assert_eq!(
            rxn_calls[0],
            json!({
                "chat_id": "12345",
                "message_id": 42,
                "reaction": [{ "type": "emoji", "emoji": "👍" }]
            })
        );
        assert_eq!(
            rxn_calls[1],
            json!({
                "chat_id": "12345",
                "message_id": 2,
                "reaction": [{ "type": "emoji", "emoji": "🔥" }]
            })
        );
        assert_eq!(
            rxn_calls[2],
            json!({
                "chat_id": "12345",
                "message_id": 42,
                "reaction": []
            })
        );
        assert_eq!(
            rxn_calls[3],
            json!({
                "chat_id": "12345",
                "message_id": 2,
                "reaction": [{ "type": "emoji", "emoji": "🎉" }]
            })
        );

        let outbound_after = sent_messages.lock().await;
        assert_eq!(outbound_after.len(), 2, "only text posts may call sendMessage");
        assert_eq!(outbound_after[1]["text"], json!("On it!"));
        assert_eq!(outbound_after[1]["reply_to_message_id"], json!(2));

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
        type SlackReactionCapture = Vec<(String, Option<String>, Value)>;
        let auth_tested = Arc::new(AtomicBool::new(false));
        let auth_tested_srv = Arc::clone(&auth_tested);
        let posted_messages: Arc<AsyncMutex<SlackPostCapture>> =
            Arc::new(AsyncMutex::new(Vec::new()));
        let posted_srv = Arc::clone(&posted_messages);
        let slack_reactions: Arc<AsyncMutex<SlackReactionCapture>> =
            Arc::new(AsyncMutex::new(Vec::new()));
        let slack_reactions_srv = Arc::clone(&slack_reactions);

        let mock_slack = MockHttpServer::start(move |req: MockRequest| {
            let auth_flag = Arc::clone(&auth_tested_srv);
            let posted = Arc::clone(&posted_srv);
            let reactions = Arc::clone(&slack_reactions_srv);
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
                if req.path.ends_with("/reactions.add") {
                    reactions
                        .lock()
                        .await
                        .push(("reactions.add".to_string(), auth_hdr, body_val));
                    return MockResponse::json(StatusCode::OK, &json!({ "ok": true }));
                }
                if req.path.ends_with("/reactions.remove") {
                    reactions
                        .lock()
                        .await
                        .push(("reactions.remove".to_string(), auth_hdr, body_val));
                    return MockResponse::json(StatusCode::OK, &json!({ "ok": true }));
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
        drop(sent);

        // Slack reactions: Unicode mapping (`👍` -> `thumbsup`), shortcode (`:rocket:`) + text combo,
        // `reactions.remove` via `remove: true`, and fail-closed on empty reaction without name.
        let slack_rxn_add = supervisor
            .post(
                "slack",
                BTreeMap::from([
                    ("channel".to_string(), json!("C_ALLOW")),
                    ("reaction".to_string(), json!("👍")),
                    ("replyTo".to_string(), json!("1764000000.000100")),
                    ("text".to_string(), json!("")),
                ]),
                Duration::from_secs(5),
            )
            .await
            .expect("Slack Unicode reaction add must succeed");
        assert_eq!(slack_rxn_add["ok"], json!(true));
        assert_eq!(slack_rxn_add["reacted"], json!(true));
        assert_eq!(slack_rxn_add["reaction"], json!("thumbsup"));

        let slack_rxn_combo = supervisor
            .post(
                "slack",
                BTreeMap::from([
                    ("channel".to_string(), json!("C_ALLOW")),
                    ("reaction".to_string(), json!(":rocket:")),
                    ("replyTo".to_string(), json!("1764000000.000200")),
                    ("text".to_string(), json!("Shipped!")),
                ]),
                Duration::from_secs(5),
            )
            .await
            .expect("Slack combo reaction+text must succeed");
        assert_eq!(slack_rxn_combo["ok"], json!(true));
        assert_eq!(slack_rxn_combo["reaction"], json!("rocket"));
        assert_eq!(slack_rxn_combo["ts"], json!("1764000123.000400"));

        let slack_rxn_rm = supervisor
            .post(
                "slack",
                BTreeMap::from([
                    ("channel".to_string(), json!("C_ALLOW")),
                    ("reaction".to_string(), json!("👍")),
                    ("remove".to_string(), json!(true)),
                    ("replyTo".to_string(), json!("1764000000.000100")),
                ]),
                Duration::from_secs(5),
            )
            .await
            .expect("Slack reactions.remove must succeed");
        assert_eq!(slack_rxn_rm["ok"], json!(true));
        assert_eq!(slack_rxn_rm["removed"], json!(true));
        assert_eq!(slack_rxn_rm["reaction"], json!("thumbsup"));

        let slack_empty_err = supervisor
            .post(
                "slack",
                BTreeMap::from([
                    ("channel".to_string(), json!("C_ALLOW")),
                    ("reaction".to_string(), json!("")),
                    ("replyTo".to_string(), json!("1764000000.000100")),
                ]),
                Duration::from_secs(5),
            )
            .await
            .expect_err("Slack empty reaction without emoji name must fail clearly");
        assert!(
            matches!(&slack_empty_err, AdapterError::RequestFailed(msg) if msg.contains("reactions.remove")),
            "expected reactions.remove guidance, got {slack_empty_err:?}"
        );

        let rxns = slack_reactions.lock().await;
        assert_eq!(rxns.len(), 3);
        assert_eq!(rxns[0].0, "reactions.add");
        assert_eq!(
            rxns[0].2,
            json!({ "channel": "C_ALLOW", "timestamp": "1764000000.000100", "name": "thumbsup" })
        );
        assert_eq!(rxns[1].0, "reactions.add");
        assert_eq!(
            rxns[1].2,
            json!({ "channel": "C_ALLOW", "timestamp": "1764000000.000200", "name": "rocket" })
        );
        assert_eq!(rxns[2].0, "reactions.remove");
        assert_eq!(
            rxns[2].2,
            json!({ "channel": "C_ALLOW", "timestamp": "1764000000.000100", "name": "thumbsup" })
        );

        let _ = supervisor.stop().await;
        node.shutdown();
    }

    // ========================================================================
    // 4b. `plugins/whatsapp/index.mjs`: signed inbound webhook + outbound text & reaction Cloud API
    // ========================================================================

    #[tokio::test]
    async fn real_whatsapp_plugin_webhook_and_reactions_e2e() {
        let Some(node_bin) = find_binary("node") else {
            eprintln!("SKIP real_whatsapp_plugin_webhook_and_reactions_e2e: `node` not on PATH");
            return;
        };

        let tmp = TempDir::new().unwrap();
        let plugin_script = repo_root().join("plugins/whatsapp/index.mjs");
        assert!(plugin_script.exists(), "missing {}", plugin_script.display());

        let app_secret = "wa-test-app-secret-2026";
        let access_token = "wa-test-bearer-token-2026";
        let app_secret_file = tmp.path().join("wa.secret");
        let access_token_file = tmp.path().join("wa.token");
        fs::write(&app_secret_file, app_secret).unwrap();
        fs::write(&access_token_file, access_token).unwrap();

        let captured_wa: Arc<AsyncMutex<Vec<Value>>> = Arc::new(AsyncMutex::new(Vec::new()));
        let captured_wa_srv = Arc::clone(&captured_wa);
        let mock_wa = MockHttpServer::start(move |req: MockRequest| {
            let captured = Arc::clone(&captured_wa_srv);
            async move {
                let body_val: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
                if req.path.ends_with("/987654321/messages") {
                    captured.lock().await.push(body_val);
                    return MockResponse::json(
                        StatusCode::OK,
                        &json!({ "messaging_product": "whatsapp", "messages": [{ "id": "wamid.OUT_1" }] }),
                    );
                }
                MockResponse::json(
                    StatusCode::NOT_FOUND,
                    &json!({ "error": { "message": "unknown path" } }),
                )
            }
        })
        .await;

        let node = open_test_node("wa-node", tmp.path());
        let host = UnifiedNodeAdapterHost::new(Arc::clone(&node));
        let port = pick_free_loopback_port().await;

        let mut cfg = SubprocessConfig::new(
            "whatsapp-real",
            AdapterKind::Bridge,
            node_bin,
            vec![plugin_script.to_string_lossy().into_owned()],
            vec!["whatsapp".to_string()],
        );
        cfg.hello_mode = HelloMode::Auto;
        cfg.env.insert("WHATSAPP_HOST".into(), "127.0.0.1".into());
        cfg.env.insert("WHATSAPP_PORT".into(), port.to_string());
        cfg.env.insert("WHATSAPP_PATH".into(), "/whatsapp".into());
        cfg.env.insert("WHATSAPP_TARGET".into(), "whatsapp".into());
        cfg.env.insert("WHATSAPP_PHONE_NUMBER_ID".into(), "987654321".into());
        cfg.env.insert("WHATSAPP_ALLOWED_NUMBERS".into(), "+15551234567".into());
        cfg.env.insert(
            "WHATSAPP_APP_SECRET_FILE".into(),
            app_secret_file.to_string_lossy().into_owned(),
        );
        cfg.env.insert(
            "WHATSAPP_ACCESS_TOKEN_FILE".into(),
            access_token_file.to_string_lossy().into_owned(),
        );
        cfg.env.insert("WHATSAPP_API_BASE".into(), mock_wa.base_url());

        let supervisor = SubprocessSupervisor::new(cfg);
        supervisor.start(Arc::clone(&host) as _).await.unwrap();

        wait_for_http_ready(
            &format!("http://127.0.0.1:{port}/health"),
            Duration::from_secs(10),
        )
        .await;

        // 1. Deliver signed inbound WhatsApp webhook message (`wamid.IN_42`).
        let inbound_body = serde_json::to_vec(&json!({
            "entry": [{
                "changes": [{
                    "value": {
                        "metadata": { "phone_number_id": "987654321" },
                        "contacts": [{ "wa_id": "15551234567", "profile": { "name": "Alex" } }],
                        "messages": [{
                            "from": "15551234567",
                            "id": "wamid.IN_42",
                            "timestamp": "1764000001",
                            "type": "text",
                            "text": { "body": "Ship it?" }
                        }]
                    }
                }]
            }]
        }))
        .unwrap();
        let sig = compute_hmac_sha256_header(app_secret.as_bytes(), &inbound_body);
        let client = HttpClient::new().unwrap();
        let req = Request::builder()
            .method(Method::POST)
            .uri(format!("http://127.0.0.1:{port}/whatsapp"))
            .header(CONTENT_TYPE, "application/json")
            .header("x-hub-signature-256", sig)
            .body(full_body(inbound_body))
            .unwrap();
        let resp = client.request(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let _ = host.wait_for_event_count(1, Duration::from_secs(5)).await;

        // 2. Reaction-only omitting `replyTo` -> falls back to `wamid.IN_42`!
        let rxn_res = supervisor
            .post(
                "whatsapp",
                BTreeMap::from([
                    ("reaction".to_string(), json!("👍")),
                    ("text".to_string(), json!("")),
                ]),
                Duration::from_secs(5),
            )
            .await
            .expect("WhatsApp reaction-only must succeed");
        assert_eq!(rxn_res["ok"], json!(true));
        assert_eq!(rxn_res["reacted"], json!(true));
        assert_eq!(rxn_res["reaction"], json!("👍"));
        assert_eq!(rxn_res["reactedMessageId"], json!("wamid.IN_42"));
        assert!(rxn_res.get("messageId").is_none());

        // 3. Empty reaction (`""`) removes reaction natively with explicit `replyTo`.
        let clear_res = supervisor
            .post(
                "whatsapp",
                BTreeMap::from([
                    ("reaction".to_string(), json!("")),
                    ("replyTo".to_string(), json!("wamid.EXPLICIT_9")),
                ]),
                Duration::from_secs(5),
            )
            .await
            .expect("WhatsApp reaction removal must succeed");
        assert_eq!(clear_res["reacted"], json!(true));
        assert_eq!(clear_res["reaction"], json!(""));
        assert_eq!(clear_res["reactedMessageId"], json!("wamid.EXPLICIT_9"));

        // 4. Combo reaction + text sends both reaction and text payloads.
        let combo_res = supervisor
            .post(
                "whatsapp",
                BTreeMap::from([
                    ("reaction".to_string(), json!("🚀")),
                    ("replyTo".to_string(), json!("wamid.IN_42")),
                    ("text".to_string(), json!("Deployed!")),
                ]),
                Duration::from_secs(5),
            )
            .await
            .expect("WhatsApp combo reaction+text must succeed");
        assert_eq!(combo_res["reacted"], json!(true));
        assert_eq!(combo_res["messageId"], json!("wamid.OUT_1"));

        // 5. Disallowed recipient fails closed!
        let denied = supervisor
            .post(
                "whatsapp",
                BTreeMap::from([
                    ("to".to_string(), json!("15559999999")),
                    ("reaction".to_string(), json!("👍")),
                ]),
                Duration::from_secs(5),
            )
            .await
            .expect_err("disallowed WhatsApp recipient must fail closed");
        assert!(
            matches!(&denied, AdapterError::RequestFailed(msg) if msg.contains("WHATSAPP_ALLOWED_NUMBERS")),
            "expected WHATSAPP_ALLOWED_NUMBERS error, got {denied:?}"
        );

        let calls = captured_wa.lock().await;
        assert_eq!(calls.len(), 4);
        assert_eq!(
            calls[0],
            json!({
                "messaging_product": "whatsapp",
                "recipient_type": "individual",
                "to": "15551234567",
                "type": "reaction",
                "reaction": { "message_id": "wamid.IN_42", "emoji": "👍" }
            })
        );
        assert_eq!(
            calls[1],
            json!({
                "messaging_product": "whatsapp",
                "recipient_type": "individual",
                "to": "15551234567",
                "type": "reaction",
                "reaction": { "message_id": "wamid.EXPLICIT_9", "emoji": "" }
            })
        );
        assert_eq!(
            calls[2],
            json!({
                "messaging_product": "whatsapp",
                "recipient_type": "individual",
                "to": "15551234567",
                "type": "reaction",
                "reaction": { "message_id": "wamid.IN_42", "emoji": "🚀" }
            })
        );
        assert_eq!(calls[3]["type"], json!("text"));
        assert_eq!(calls[3]["text"]["body"], json!("Deployed!"));
        assert_eq!(calls[3]["context"]["message_id"], json!("wamid.IN_42"));

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

    // ========================================================================
    // 6. Fail-closed Auth on Webhook & Prometheus Plugins (B7)
    // ========================================================================

    #[tokio::test]
    async fn real_webhook_and_prometheus_plugins_fail_closed_without_auth_and_reject_non_loopback_unsigned() {
        let Some(node_bin) = find_binary("node") else {
            eprintln!("SKIP real_webhook_and_prometheus_plugins_fail_closed_without_auth_and_reject_non_loopback_unsigned: `node` not on PATH");
            return;
        };

        let webhook_script = repo_root().join("plugins/webhook/index.mjs");
        let prom_script = repo_root().join("plugins/prometheus/index.mjs");
        let path_env = std::env::var("PATH").unwrap_or_default();

        // 1. Webhook refuses to boot without WEBHOOK_SECRET (unless WEBHOOK_ALLOW_UNSIGNED=1).
        let wh_no_auth = tokio::process::Command::new(&node_bin)
            .arg(&webhook_script)
            .env_clear()
            .env("PATH", &path_env)
            .output()
            .await
            .expect("run webhook without auth");
        assert!(
            !wh_no_auth.status.success(),
            "webhook plugin MUST fail closed without WEBHOOK_SECRET"
        );
        let wh_err = String::from_utf8_lossy(&wh_no_auth.stderr);
        assert!(
            wh_err.contains("WEBHOOK_SECRET") && wh_err.contains("WEBHOOK_ALLOW_UNSIGNED"),
            "unexpected webhook no-auth stderr: {wh_err}"
        );

        // 2. Webhook NEVER allows unsigned on non-loopback bind (0.0.0.0) even with WEBHOOK_ALLOW_UNSIGNED=1!
        let wh_non_loopback = tokio::process::Command::new(&node_bin)
            .arg(&webhook_script)
            .env_clear()
            .env("PATH", &path_env)
            .env("WEBHOOK_HOST", "0.0.0.0")
            .env("WEBHOOK_ALLOW_UNSIGNED", "1")
            .output()
            .await
            .expect("run webhook non-loopback unsigned");
        assert!(
            !wh_non_loopback.status.success(),
            "webhook plugin MUST reject unsigned mode on 0.0.0.0"
        );
        let wh_nl_err = String::from_utf8_lossy(&wh_non_loopback.stderr);
        assert!(
            wh_nl_err.contains("non-loopback"),
            "unexpected webhook non-loopback stderr: {wh_nl_err}"
        );

        // 3. Prometheus refuses to boot without Bearer/Basic/HMAC auth.
        let prom_no_auth = tokio::process::Command::new(&node_bin)
            .arg(&prom_script)
            .env_clear()
            .env("PATH", &path_env)
            .output()
            .await
            .expect("run prometheus without auth");
        assert!(
            !prom_no_auth.status.success(),
            "prometheus plugin MUST fail closed without auth"
        );
        let prom_err = String::from_utf8_lossy(&prom_no_auth.stderr);
        assert!(
            prom_err.contains("PROMETHEUS_BEARER_TOKEN")
                && prom_err.contains("PROMETHEUS_BASIC_AUTH")
                && prom_err.contains("PROMETHEUS_ALLOW_UNSIGNED"),
            "unexpected prometheus no-auth stderr: {prom_err}"
        );

        // 4. Prometheus NEVER allows unsigned on non-loopback bind (0.0.0.0) even with PROMETHEUS_ALLOW_UNSIGNED=1!
        let prom_non_loopback = tokio::process::Command::new(&node_bin)
            .arg(&prom_script)
            .env_clear()
            .env("PATH", &path_env)
            .env("PROMETHEUS_HOST", "0.0.0.0")
            .env("PROMETHEUS_ALLOW_UNSIGNED", "1")
            .output()
            .await
            .expect("run prometheus non-loopback unsigned");
        assert!(
            !prom_non_loopback.status.success(),
            "prometheus plugin MUST reject unsigned mode on 0.0.0.0"
        );
        let prom_nl_err = String::from_utf8_lossy(&prom_non_loopback.stderr);
        assert!(
            prom_nl_err.contains("non-loopback"),
            "unexpected prometheus non-loopback stderr: {prom_nl_err}"
        );

        // 5. Prometheus accepts PROMETHEUS_BASIC_AUTH (and rejects invalid Basic credentials 401).
        let tmp = TempDir::new().unwrap();
        let node = open_test_node("prom-basic-node", tmp.path());
        let host = UnifiedNodeAdapterHost::new(Arc::clone(&node));
        let port = pick_free_loopback_port().await;

        let mut cfg = SubprocessConfig::new(
            "prom-basic",
            AdapterKind::Source,
            node_bin,
            vec![prom_script.to_string_lossy().into_owned()],
            vec!["alerts".to_string()],
        );
        cfg.env.insert("PROMETHEUS_HOST".into(), "127.0.0.1".into());
        cfg.env.insert("PROMETHEUS_PORT".into(), port.to_string());
        cfg.env.insert("PROMETHEUS_PATH".into(), "/alerts".into());
        cfg.env.insert("PROMETHEUS_TOPIC".into(), "alerts".into());
        cfg.env
            .insert("PROMETHEUS_BASIC_AUTH".into(), "prom:s3cr3t!".into());

        let supervisor = SubprocessSupervisor::new(cfg);
        supervisor.start(Arc::clone(&host) as _).await.unwrap();
        wait_for_http_ready(
            &format!("http://127.0.0.1:{port}/health"),
            Duration::from_secs(10),
        )
        .await;

        let client = HttpClient::new().unwrap();
        let alerts_url = format!("http://127.0.0.1:{port}/alerts");
        let payload = serde_json::to_vec(&json!({
            "alerts": [{
                "status": "firing",
                "fingerprint": "fp-basic-1",
                "labels": { "alertname": "DiskFull", "severity": "critical" },
                "startsAt": "2026-11-24T12:00:00Z"
            }]
        }))
        .unwrap();

        let bad_req = Request::builder()
            .method(Method::POST)
            .uri(&alerts_url)
            .header(CONTENT_TYPE, "application/json")
            .header(AUTHORIZATION, "Basic d3Jvbmc6Y3JlZHM=")
            .body(full_body(payload.clone()))
            .unwrap();
        assert_eq!(
            client.request(bad_req).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );

        // base64("prom:s3cr3t!") == "cHJvbTpzM2NyM3Qh"
        let ok_req = Request::builder()
            .method(Method::POST)
            .uri(&alerts_url)
            .header(CONTENT_TYPE, "application/json")
            .header(AUTHORIZATION, "Basic cHJvbTpzM2NyM3Qh")
            .body(full_body(payload))
            .unwrap();
        assert_eq!(
            client.request(ok_req).await.unwrap().status(),
            StatusCode::OK
        );
        let _ = host.wait_for_event_count(1, Duration::from_secs(5)).await;

        let _ = supervisor.stop().await;
        node.shutdown();
    }

    #[tokio::test]
    async fn real_slack_bridge_fail_closed_unseen_channel_and_no_cross_channel_reaction() {
        let Some(node_bin) = find_binary("node") else {
            eprintln!("SKIP real_slack_bridge_fail_closed_unseen_channel_and_no_cross_channel_reaction: `node` not on PATH");
            return;
        };

        let tmp = TempDir::new().unwrap();
        let plugin_script = repo_root().join("plugins/slack/index.mjs");
        let app_file = tmp.path().join("slack.app");
        let bot_file = tmp.path().join("slack.bot");
        fs::write(&app_file, "xapp-iso-1").unwrap();
        fs::write(&bot_file, "xoxb-iso-2").unwrap();

        let auth_ok = Arc::new(AtomicBool::new(false));
        let auth_srv = Arc::clone(&auth_ok);
        let mock_slack = MockHttpServer::start(move |req: MockRequest| {
            let auth_flag = Arc::clone(&auth_srv);
            async move {
                if req.path.ends_with("/auth.test") {
                    auth_flag.store(true, Ordering::SeqCst);
                    return MockResponse::json(
                        StatusCode::OK,
                        &json!({ "ok": true, "user_id": "U_BOT", "team_id": "T_ISO" }),
                    );
                }
                MockResponse::json(
                    StatusCode::OK,
                    &json!({ "ok": false, "error": "paused_for_test" }),
                )
            }
        })
        .await;

        let node = open_test_node("slack-iso-node", tmp.path());
        let host = UnifiedNodeAdapterHost::new(Arc::clone(&node));

        // Configure ONLY SLACK_ALLOWED_USERS (no SLACK_ALLOWED_CHANNELS, no SLACK_DEFAULT_CHANNEL):
        // posting to an unseen channel MUST fail closed!
        let mut cfg = SubprocessConfig::new(
            "slack-iso",
            AdapterKind::Bridge,
            node_bin,
            vec![plugin_script.to_string_lossy().into_owned()],
            vec!["pm".to_string()],
        );
        cfg.env.insert(
            "SLACK_APP_TOKEN_FILE".into(),
            app_file.to_string_lossy().into_owned(),
        );
        cfg.env.insert(
            "SLACK_BOT_TOKEN_FILE".into(),
            bot_file.to_string_lossy().into_owned(),
        );
        cfg.env.insert("SLACK_TARGET".into(), "pm".into());
        cfg.env.insert("SLACK_ALLOWED_USERS".into(), "U_ALICE".into());
        cfg.env.insert("SLACK_API_BASE".into(), mock_slack.base_url());

        let supervisor = SubprocessSupervisor::new(cfg);
        supervisor.start(Arc::clone(&host) as _).await.unwrap();

        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while !auth_ok.load(Ordering::SeqCst) {
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for Slack auth.test"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }

        let unseen_err = supervisor
            .post(
                "pm",
                BTreeMap::from([
                    ("channel".to_string(), json!("C_RANDOM_UNSEEN")),
                    ("text".to_string(), json!("Exfil attempt")),
                ]),
                Duration::from_secs(5),
            )
            .await
            .expect_err("unseen Slack channel MUST fail closed");
        assert!(
            matches!(&unseen_err, AdapterError::RequestFailed(msg) if msg.contains("not an allowed or previously seen")),
            "expected fail-closed unseen channel error, got {unseen_err:?}"
        );

        let _ = supervisor.stop().await;
        node.shutdown();
    }

    // ========================================================================
    // 7. Bridge Fail-Closed Outbound Recipients & Per-Chat Isolation (B3 & B4)
    // ========================================================================

    #[tokio::test]
    async fn real_telegram_bridge_fail_closed_unseen_chat_and_no_cross_chat_reaction_fallback() {
        let Some(node_bin) = find_binary("node") else {
            eprintln!("SKIP real_telegram_bridge_fail_closed_unseen_chat_and_no_cross_chat_reaction_fallback: `node` not on PATH");
            return;
        };

        let tmp = TempDir::new().unwrap();
        let token_file = tmp.path().join("tg.token");
        fs::write(&token_file, "123456:TG_ISO_TEST_TOKEN").unwrap();

        let delivered = Arc::new(AtomicBool::new(false));
        let delivered_srv = Arc::clone(&delivered);
        let mock_tg = MockHttpServer::start(move |req: MockRequest| {
            let del = Arc::clone(&delivered_srv);
            async move {
                if req.path.ends_with("/getUpdates") {
                    if !del.swap(true, Ordering::SeqCst) {
                        return MockResponse::json(
                            StatusCode::OK,
                            &json!({
                                "ok": true,
                                "result": [
                                    {
                                        "update_id": 201,
                                        "message": {
                                            "message_id": 10,
                                            "date": 1764000010,
                                            "chat": { "id": 11111, "type": "private" },
                                            "from": { "id": 42, "username": "alice" },
                                            "text": "Chat A msg"
                                        }
                                    },
                                    {
                                        "update_id": 202,
                                        "message": {
                                            "message_id": 20,
                                            "date": 1764000011,
                                            "chat": { "id": 22222, "type": "group" },
                                            "from": { "id": 42, "username": "alice" },
                                            "text": "Chat B msg"
                                        }
                                    }
                                ]
                            }),
                        );
                    }
                    tokio::time::sleep(Duration::from_millis(150)).await;
                    return MockResponse::json(StatusCode::OK, &json!({ "ok": true, "result": [] }));
                }
                if req.path.ends_with("/sendMessage") {
                    return MockResponse::json(
                        StatusCode::OK,
                        &json!({ "ok": true, "result": { "message_id": 500 } }),
                    );
                }
                if req.path.ends_with("/setMessageReaction") {
                    return MockResponse::json(StatusCode::OK, &json!({ "ok": true, "result": true }));
                }
                MockResponse::json(StatusCode::NOT_FOUND, &json!({ "ok": false }))
            }
        })
        .await;

        let node = open_test_node("tg-iso-node", tmp.path());
        let host = UnifiedNodeAdapterHost::new(Arc::clone(&node));
        let plugin_script = repo_root().join("plugins/telegram/index.mjs");

        // Configure ONLY TELEGRAM_ALLOWED_USERS (no TELEGRAM_ALLOWED_CHATS, no TELEGRAM_DEFAULT_CHAT),
        // matching the documented config in docs/plugins.md!
        let mut cfg = SubprocessConfig::new(
            "tg-iso",
            AdapterKind::Bridge,
            node_bin,
            vec![plugin_script.to_string_lossy().into_owned()],
            vec!["personal".to_string()],
        );
        cfg.env.insert(
            "TELEGRAM_BOT_TOKEN_FILE".into(),
            token_file.to_string_lossy().into_owned(),
        );
        cfg.env.insert("TELEGRAM_TARGET".into(), "personal".into());
        cfg.env.insert("TELEGRAM_ALLOWED_USERS".into(), "42".into());
        cfg.env.insert("TELEGRAM_API_BASE".into(), mock_tg.base_url());

        let supervisor = SubprocessSupervisor::new(cfg);
        supervisor.start(Arc::clone(&host) as _).await.unwrap();
        let _ = host.wait_for_event_count(2, Duration::from_secs(10)).await;

        // 1. Outbound to UNSEEN chat `999999` MUST fail closed even without TELEGRAM_ALLOWED_CHATS!
        let unseen_err = supervisor
            .post(
                "personal",
                BTreeMap::from([
                    ("chatId".to_string(), json!("999999")),
                    ("text".to_string(), json!("Exfil attempt")),
                ]),
                Duration::from_secs(5),
            )
            .await
            .expect_err("unseen Telegram chat MUST fail closed");
        assert!(
            matches!(&unseen_err, AdapterError::RequestFailed(msg) if msg.contains("not an allowed or previously seen")),
            "expected unseen chat fail-closed error, got {unseen_err:?}"
        );

        // 2. Omitting `chatId` when >1 chat has been seen (and no default) MUST fail clearly!
        let ambiguous_err = supervisor
            .post(
                "personal",
                BTreeMap::from([("text".to_string(), json!("Which chat?"))]),
                Duration::from_secs(5),
            )
            .await
            .expect_err("ambiguous omitted chatId MUST fail");
        assert!(
            matches!(&ambiguous_err, AdapterError::RequestFailed(msg) if msg.contains("explicit chatId")),
            "expected explicit chatId error, got {ambiguous_err:?}"
        );

        // 3. Explicit chatId for seen chat `11111` reacts strictly to chat `11111`'s message 10 (NOT chat 22222's message 20)!
        let rxn_a = supervisor
            .post(
                "personal",
                BTreeMap::from([
                    ("chatId".to_string(), json!("11111")),
                    ("reaction".to_string(), json!("👍")),
                ]),
                Duration::from_secs(5),
            )
            .await
            .expect("reaction in chat A must succeed");
        assert_eq!(rxn_a["reactedMessageId"], json!(10));

        let _ = supervisor.stop().await;
        node.shutdown();
    }

    #[tokio::test]
    async fn real_whatsapp_bridge_isolates_per_recipient_reactions_and_requires_explicit_to_when_ambiguous() {
        let Some(node_bin) = find_binary("node") else {
            eprintln!("SKIP real_whatsapp_bridge_isolates_per_recipient_reactions_and_requires_explicit_to_when_ambiguous: `node` not on PATH");
            return;
        };

        let tmp = TempDir::new().unwrap();
        let plugin_script = repo_root().join("plugins/whatsapp/index.mjs");
        let app_secret = "wa-iso-secret-2026";
        let app_secret_file = tmp.path().join("wa.secret");
        let access_token_file = tmp.path().join("wa.token");
        fs::write(&app_secret_file, app_secret).unwrap();
        fs::write(&access_token_file, "wa-token-iso").unwrap();

        let mock_wa = MockHttpServer::start(|_req: MockRequest| async move {
            MockResponse::json(
                StatusCode::OK,
                &json!({ "messaging_product": "whatsapp", "messages": [{ "id": "wamid.OUT" }] }),
            )
        })
        .await;

        let node = open_test_node("wa-iso-node", tmp.path());
        let host = UnifiedNodeAdapterHost::new(Arc::clone(&node));
        let port = pick_free_loopback_port().await;

        let mut cfg = SubprocessConfig::new(
            "wa-iso",
            AdapterKind::Bridge,
            node_bin,
            vec![plugin_script.to_string_lossy().into_owned()],
            vec!["whatsapp".to_string()],
        );
        cfg.env.insert("WHATSAPP_HOST".into(), "127.0.0.1".into());
        cfg.env.insert("WHATSAPP_PORT".into(), port.to_string());
        cfg.env.insert("WHATSAPP_PATH".into(), "/whatsapp".into());
        cfg.env.insert("WHATSAPP_TARGET".into(), "whatsapp".into());
        cfg.env.insert("WHATSAPP_PHONE_NUMBER_ID".into(), "987654321".into());
        cfg.env.insert(
            "WHATSAPP_ALLOWED_NUMBERS".into(),
            "+15551111111,+15552222222,+15553333333".into(),
        );
        cfg.env.insert(
            "WHATSAPP_APP_SECRET_FILE".into(),
            app_secret_file.to_string_lossy().into_owned(),
        );
        cfg.env.insert(
            "WHATSAPP_ACCESS_TOKEN_FILE".into(),
            access_token_file.to_string_lossy().into_owned(),
        );
        cfg.env.insert("WHATSAPP_API_BASE".into(), mock_wa.base_url());

        let supervisor = SubprocessSupervisor::new(cfg);
        supervisor.start(Arc::clone(&host) as _).await.unwrap();
        wait_for_http_ready(
            &format!("http://127.0.0.1:{port}/health"),
            Duration::from_secs(10),
        )
        .await;

        let client = HttpClient::new().unwrap();
        let body = serde_json::to_vec(&json!({
            "entry": [{
                "changes": [{
                    "value": {
                        "metadata": { "phone_number_id": "987654321" },
                        "messages": [
                            { "from": "15551111111", "id": "wamid.A1", "timestamp": "1764000001", "type": "text", "text": { "body": "Hi from A" } },
                            { "from": "15552222222", "id": "wamid.B2", "timestamp": "1764000002", "type": "text", "text": { "body": "Hi from B" } }
                        ]
                    }
                }]
            }]
        }))
        .unwrap();
        let sig = compute_hmac_sha256_header(app_secret.as_bytes(), &body);
        let req = Request::builder()
            .method(Method::POST)
            .uri(format!("http://127.0.0.1:{port}/whatsapp"))
            .header(CONTENT_TYPE, "application/json")
            .header("x-hub-signature-256", sig)
            .body(full_body(body))
            .unwrap();
        assert_eq!(client.request(req).await.unwrap().status(), StatusCode::OK);
        let _ = host.wait_for_event_count(2, Duration::from_secs(5)).await;

        // 1. Omitting `to` when 2 recipients were seen without default MUST fail!
        let ambig = supervisor
            .post(
                "whatsapp",
                BTreeMap::from([("text".to_string(), json!("Ambiguous reply"))]),
                Duration::from_secs(5),
            )
            .await
            .expect_err("omitted recipient must fail when multiple recipients seen");
        assert!(
            matches!(&ambig, AdapterError::RequestFailed(msg) if msg.contains("explicit recipient")),
            "unexpected error: {ambig:?}"
        );

        // 2. Reacting to allowlisted recipient C (who never sent a message) without replyTo MUST fail
        //    instead of falling back to global lastMessageId from A/B!
        let no_cross = supervisor
            .post(
                "whatsapp",
                BTreeMap::from([
                    ("to".to_string(), json!("15553333333")),
                    ("reaction".to_string(), json!("👍")),
                ]),
                Duration::from_secs(5),
            )
            .await
            .expect_err("must NOT fall back to another recipient's message_id");
        assert!(
            matches!(&no_cross, AdapterError::RequestFailed(msg) if msg.contains("15553333333")),
            "unexpected error: {no_cross:?}"
        );

        let _ = supervisor.stop().await;
        node.shutdown();
    }

    // ========================================================================
    // 8. SubprocessSupervisor Stderr Capture, Secret Redaction & CrashLoopBackOff (B5)
    // ========================================================================

    #[tokio::test]
    async fn supervisor_captures_redacted_stderr_log_and_trips_crash_loop_circuit_breaker() {
        let Some(python_bin) = find_binary("python3") else {
            eprintln!("SKIP supervisor_captures_redacted_stderr_log_and_trips_crash_loop_circuit_breaker: `python3` not on PATH");
            return;
        };

        let tmp = TempDir::new().unwrap();
        let log_path = tmp.path().join("logs").join("plugin-crashloop.log");
        let secret_val = "sk_live_SUPER_SENSITIVE_TOKEN_987654321";

        let script = r#"
import os, sys
tok = os.environ.get("MY_BOT_TOKEN", "")
sys.stderr.write(f"fatal auth failure using token={tok} on startup\n")
sys.stderr.flush()
sys.exit(1)
"#;

        let node = open_test_node("crash-node", tmp.path());
        let host = UnifiedNodeAdapterHost::new(Arc::clone(&node));

        let mut cfg = SubprocessConfig::new(
            "crashloop",
            AdapterKind::Bridge,
            python_bin,
            vec!["-u".to_string(), "-c".to_string(), script.to_string()],
            vec!["ops".to_string()],
        );
        cfg.env.insert("MY_BOT_TOKEN".to_string(), secret_val.to_string());
        cfg.redacted_values.push(secret_val.to_string());
        cfg.stderr_log_path = Some(log_path.clone());
        cfg.initial_backoff = Duration::from_millis(15);
        cfg.max_backoff = Duration::from_millis(30);
        cfg.rapid_crash_window = Duration::from_secs(5);
        cfg.max_rapid_crashes = 3;

        let supervisor = SubprocessSupervisor::new(cfg);
        supervisor.start(Arc::clone(&host) as _).await.unwrap();

        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while !supervisor.is_crash_loop_backoff() {
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for CrashLoopBackOff; health={:?} restarts={}",
                supervisor.health(),
                supervisor.restart_count()
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }

        // Circuit breaker stopped hot-looping after 3 rapid crashes (2 restarts after initial attempt).
        let restarts_at_trip = supervisor.restart_count();
        assert_eq!(restarts_at_trip, 2, "expected 2 restarts before 3rd crash trips breaker");
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(
            supervisor.restart_count(),
            restarts_at_trip,
            "supervisor MUST stop respawning once in CrashLoopBackOff"
        );

        // Health & last_error carry CrashLoopBackOff + redacted stderr error, NEVER the raw secret!
        let health = supervisor.health();
        match &health {
            AdapterHealth::Degraded(msg) => {
                assert!(msg.contains("CrashLoopBackOff"), "expected CrashLoopBackOff in {msg}");
                assert!(msg.contains("fatal auth failure"), "expected stderr detail in {msg}");
                assert!(msg.contains("[REDACTED]"), "expected [REDACTED] in {msg}");
                assert!(!msg.contains(secret_val), "raw secret leaked into health: {msg}");
            }
            other => panic!("expected Degraded(CrashLoopBackOff), got {other:?}"),
        }

        let recent = supervisor.recent_stderr();
        assert!(!recent.is_empty(), "expected captured stderr lines");
        assert!(recent.iter().any(|l| l.contains("[REDACTED]")));
        for line in &recent {
            assert!(!line.contains(secret_val), "raw secret leaked in recent_stderr: {line}");
        }

        // Bounded per-plugin log file exists with 0600 permissions and redacted content!
        let log_content = fs::read_to_string(&log_path).expect("read plugin stderr log");
        assert!(log_content.contains("fatal auth failure"));
        assert!(log_content.contains("[REDACTED]"));
        assert!(log_content.contains("CrashLoopBackOff"));
        assert!(
            !log_content.contains(secret_val),
            "raw secret leaked into plugin stderr log: {log_content}"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&log_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "plugin stderr log must be 0600, got {mode:o}");
        }

        let _ = supervisor.stop().await;
        node.shutdown();
    }
}

// ============================================================================
// Cross-Platform (Windows + Unix) Authenticated Loopback-TCP Transport & SDK Parity
// ============================================================================

mod loopback_tcp_parity_tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::time::Duration;

    use bytes::Bytes;
    use http::header::CONTENT_TYPE;
    use http::{HeaderMap, Method, Request, StatusCode};
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};
    use tempfile::TempDir;
    use tokio::net::TcpListener;
    use tokio::sync::Mutex as AsyncMutex;

    use crate::common::{MockHttpServer, MockRequest, MockResponse, UnifiedNodeAdapterHost};
    use hyp_crypto::SecretBackend;
    use hyp_node::adapters::supervisor::PluginTransportMode;
    use hyp_node::adapters::{
        AdapterError, AdapterHealth, AdapterKind, HelloMode, NodeAdapter, SubprocessConfig,
        SubprocessSupervisor, WireProtocol, compute_hmac_sha256_header, verify_hmac_sha256_header,
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

    fn find_python3_binary() -> Option<String> {
        for candidate in ["python3", "python"] {
            let Ok(out) = std::process::Command::new(candidate)
                .args(["-c", "import sys; print(sys.version_info[0])"])
                .output()
            else {
                continue;
            };
            if out.status.success() && String::from_utf8_lossy(&out.stdout).trim() == "3" {
                return Some(candidate.to_string());
            }
        }
        None
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

    #[tokio::test]
    async fn loopback_tcp_node_sdk_client_mjs_jsonrpc_v2_and_real_webhook_bridge_parity_e2e() {
        let Some(node_bin) = find_binary("node") else {
            eprintln!(
                "SKIP loopback_tcp_node_sdk_client_mjs_jsonrpc_v2_and_real_webhook_bridge_parity_e2e: `node` not on PATH"
            );
            return;
        };

        let tmp = TempDir::new().unwrap();
        let sdk_path = repo_root().join("plugins/sdk/client.mjs");
        assert!(sdk_path.exists(), "missing {}", sdk_path.display());

        // --------------------------------------------------------------------
        // (1) Fail-closed non-loopback address guard in `plugins/sdk/client.mjs`
        // --------------------------------------------------------------------
        let guard_script = tmp.path().join("sdk_mjs_loopback_guard.mjs");
        fs::write(
            &guard_script,
            r#"
import { pathToFileURL } from "node:url";
const { MeshPluginClient } = await import(pathToFileURL(process.env.SDK_MJS_PATH).href);
for (const badAddr of ["192.168.1.10:8080", "0.0.0.0:8080", "evil.example.com:8080", "127.0.0.1:0", "not-a-host-port"]) {
  process.env.HYPHAE_PLUGIN_ADDR = badAddr;
  process.env.HYPHAE_PLUGIN_TOKEN = "a".repeat(64);
  let threw = false;
  try {
    new MeshPluginClient();
  } catch (err) {
    threw = true;
  }
  if (!threw) {
    throw new Error(`Expected MeshPluginClient to reject invalid/non-loopback addr: ${badAddr}`);
  }
}
"#,
        )
        .unwrap();
        let guard_out = tokio::process::Command::new(&node_bin)
            .arg(&guard_script)
            .env("SDK_MJS_PATH", &sdk_path)
            .output()
            .await
            .expect("run client.mjs loopback guard check");
        assert!(
            guard_out.status.success(),
            "client.mjs loopback guard failed: stderr={}",
            String::from_utf8_lossy(&guard_out.stderr)
        );

        // --------------------------------------------------------------------
        // (2) Real `plugins/sdk/client.mjs` over authenticated `LoopbackTcp`
        // --------------------------------------------------------------------
        let sdk_report_file = tmp.path().join("tcp_sdk_mjs_report.json");
        let sdk_harness = tmp.path().join("tcp_sdk_mjs_harness.mjs");
        fs::write(
            &sdk_harness,
            r#"
import { writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

const { MeshPluginClient } = await import(pathToFileURL(process.env.SDK_MJS_PATH).href);

const transportBefore = process.env.HYPHAE_PLUGIN_TRANSPORT ?? null;
const hadAddrBefore = Boolean(process.env.HYPHAE_PLUGIN_ADDR);
const hadTokenBefore = Boolean(process.env.HYPHAE_PLUGIN_TOKEN);

const mesh = new MeshPluginClient({
  onPost: async (params) => {
    if (params.fail) throw new Error("tcp_intentional_post_failure");
    return { echoed: params.text, target: params.target, transport: transportBefore };
  },
});

const tokenPoppedAfterCtor = process.env.HYPHAE_PLUGIN_TOKEN === undefined;
const hello = await mesh.ready;

const validEvent = {
  specversion: "1.0",
  id: "tcp-sdk-mjs-evt-1",
  source: "sdk/node-tcp-test",
  type: "com.hyphae.sdk.tcp.ping",
  time: "2026-11-25T12:00:00Z",
  datacontenttype: "application/json",
  data: { ok: true, transport: "tcp", lang: "mjs" },
};
const ackStored = await mesh.send("sdk-tcp", validEvent);
const ackDup = await mesh.send("sdk-tcp", validEvent);
const nackInvalid = await mesh.send("sdk-tcp", {
  specversion: "9.9",
  id: "",
  source: "bad",
  type: "bad",
});
const nackTarget = await mesh.send("wrong-target", validEvent);

writeFileSync(
  process.env.SDK_REPORT_FILE,
  JSON.stringify({
    transportBefore,
    hadAddrBefore,
    hadTokenBefore,
    tokenPoppedAfterCtor,
    hello,
    ackStored,
    ackDup,
    nackInvalid,
    nackTarget,
  }),
  "utf8",
);

setInterval(() => {}, 10_000);
"#,
        )
        .unwrap();

        let sdk_node = open_test_node("tcp-sdk-mjs-node", &tmp.path().join("sdk-node"));
        let sdk_host = UnifiedNodeAdapterHost::new(Arc::clone(&sdk_node));
        let mut sdk_cfg = SubprocessConfig::new(
            "sdk-mjs-tcp",
            AdapterKind::Bridge,
            node_bin.clone(),
            vec![sdk_harness.to_string_lossy().into_owned()],
            vec!["sdk-tcp".to_string()],
        );
        sdk_cfg.transport_mode = PluginTransportMode::LoopbackTcp;
        sdk_cfg.hello_mode = HelloMode::Auto;
        sdk_cfg
            .env
            .insert("SDK_MJS_PATH".into(), sdk_path.to_string_lossy().into_owned());
        sdk_cfg.env.insert(
            "SDK_REPORT_FILE".into(),
            sdk_report_file.to_string_lossy().into_owned(),
        );

        let sdk_sup = SubprocessSupervisor::new(sdk_cfg);
        sdk_sup.start(Arc::clone(&sdk_host) as _).await.unwrap();

        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let report: Value = loop {
            if let Ok(raw) = fs::read_to_string(&sdk_report_file) {
                if let Ok(v) = serde_json::from_str::<Value>(&raw) {
                    break v;
                }
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for tcp_sdk_mjs_report.json; health={:?} stderr={:?}",
                sdk_sup.health(),
                sdk_sup.recent_stderr()
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        };

        assert_eq!(report["transportBefore"], "tcp");
        assert_eq!(report["hadAddrBefore"], true);
        assert_eq!(report["hadTokenBefore"], true);
        assert_eq!(
            report["tokenPoppedAfterCtor"], true,
            "client.mjs MUST delete HYPHAE_PLUGIN_TOKEN from process.env immediately"
        );
        assert_eq!(report["hello"]["type"], "hello");
        assert_eq!(report["hello"]["protocol"], 1);
        assert_eq!(report["hello"]["targets"], json!(["sdk-tcp"]));
        assert_eq!(report["ackStored"]["type"], "ack");
        assert_eq!(report["ackStored"]["status"], "stored");
        assert_eq!(report["ackDup"]["type"], "ack");
        assert_eq!(report["ackDup"]["status"], "duplicate");
        assert_eq!(report["nackInvalid"]["type"], "nack");
        assert_eq!(report["nackInvalid"]["error"], "invalid_event");
        assert_eq!(report["nackTarget"]["type"], "nack");
        assert_eq!(report["nackTarget"]["error"], "unknown_target");

        let post_ok = sdk_sup
            .post(
                "sdk-tcp",
                BTreeMap::from([("text".to_string(), json!("hello over loopback tcp"))]),
                Duration::from_secs(5),
            )
            .await
            .expect("outbound post over LoopbackTcp must succeed");
        assert_eq!(
            post_ok,
            json!({ "echoed": "hello over loopback tcp", "target": "sdk-tcp", "transport": "tcp" })
        );

        let post_err = sdk_sup
            .post(
                "sdk-tcp",
                BTreeMap::from([("fail".to_string(), json!(true))]),
                Duration::from_secs(5),
            )
            .await
            .expect_err("intentional post error must propagate over LoopbackTcp");
        assert!(
            matches!(&post_err, AdapterError::RequestFailed(m) if m.contains("tcp_intentional_post_failure")),
            "unexpected post_err: {post_err:?}"
        );

        let sdk_ingested = sdk_host.published_events().await;
        assert_eq!(sdk_ingested.len(), 1);
        assert_eq!(sdk_ingested[0].1.id, "tcp-sdk-mjs-evt-1");

        let _ = sdk_sup.stop().await;
        assert_eq!(sdk_sup.health(), AdapterHealth::Stopped);
        sdk_node.shutdown();

        // --------------------------------------------------------------------
        // (3) JSON-RPC 2.0 v2 pipelined auth + `hyphae/hello` + `hyphae/publish` + `hyphae/post`
        // --------------------------------------------------------------------
        let v2_script = tmp.path().join("tcp_jsonrpc_v2.mjs");
        fs::write(
            &v2_script,
            r#"
import net from "node:net";
import { createInterface } from "node:readline";

const [host, portStr] = process.env.HYPHAE_PLUGIN_ADDR.split(":");
const token = process.env.HYPHAE_PLUGIN_TOKEN;
delete process.env.HYPHAE_PLUGIN_TOKEN;

const sock = net.createConnection({ host, port: Number(portStr) });
sock.setNoDelay(true);

// Pipeline auth + hyphae/hello in ONE single TCP write to prove auth reader never eats leftover bytes!
sock.write(
  JSON.stringify({ type: "auth", token }) + "\n" +
  JSON.stringify({ jsonrpc: "2.0", id: "h1", method: "hyphae/hello", params: { protocol: 2, plugin: "v2-tcp", targets: ["ops"] } }) + "\n",
);

const rl = createInterface({ input: sock });
rl.on("line", (line) => {
  if (!line.trim()) return;
  const msg = JSON.parse(line);
  if (msg.id === "h1" && msg.result) {
    sock.write(
      JSON.stringify({
        jsonrpc: "2.0",
        id: "p1",
        method: "hyphae/publish",
        params: {
          to: "ops",
          event: {
            specversion: "1.0",
            id: "v2-tcp-evt-1",
            source: "tcp/jsonrpc-v2",
            type: "to.hyphae.tcp.v2",
            datacontenttype: "application/json",
            data: { pipelined: true },
          },
        },
      }) + "\n",
    );
  } else if (msg.method === "hyphae/post" && msg.id !== undefined) {
    sock.write(
      JSON.stringify({
        jsonrpc: "2.0",
        id: msg.id,
        result: { v2: true, target: msg.params.target, text: msg.params.params.text },
      }) + "\n",
    );
  }
});
rl.on("close", () => process.exit(0));
"#,
        )
        .unwrap();

        let v2_node = open_test_node("tcp-v2-node", &tmp.path().join("v2-node"));
        let v2_host = UnifiedNodeAdapterHost::new(Arc::clone(&v2_node));
        let mut v2_cfg = SubprocessConfig::new(
            "v2-tcp",
            AdapterKind::Bridge,
            node_bin.clone(),
            vec![v2_script.to_string_lossy().into_owned()],
            vec!["ops".to_string()],
        );
        v2_cfg.transport_mode = PluginTransportMode::LoopbackTcp;
        v2_cfg.hello_mode = HelloMode::Auto;

        let v2_sup = SubprocessSupervisor::new(v2_cfg);
        v2_sup.start(Arc::clone(&v2_host) as _).await.unwrap();

        let v2_events = v2_host.wait_for_event_count(1, Duration::from_secs(10)).await;
        assert_eq!(v2_events[0].0, "ops");
        assert_eq!(v2_events[0].1.id, "v2-tcp-evt-1");
        assert_eq!(v2_sup.detected_protocol(), WireProtocol::JsonRpcV2);

        let v2_post = v2_sup
            .post(
                "ops",
                BTreeMap::from([("text".to_string(), json!("rpc-v2-tcp-ok"))]),
                Duration::from_secs(5),
            )
            .await
            .expect("JSON-RPC 2.0 post over LoopbackTcp must succeed");
        assert_eq!(
            v2_post,
            json!({ "v2": true, "target": "ops", "text": "rpc-v2-tcp-ok" })
        );

        let _ = v2_sup.stop().await;
        v2_node.shutdown();

        // --------------------------------------------------------------------
        // (4) Real unmodified `plugins/webhook/index.mjs` over `LoopbackTcp`
        //     (+ differential comparison against `UnixFd3` on Unix!)
        // --------------------------------------------------------------------
        let secret = "tcp-webhook-parity-secret-2026";
        let secret_file = tmp.path().join("wh_tcp.secret");
        fs::write(&secret_file, secret).unwrap();

        let captured_outbound: Arc<AsyncMutex<Vec<(HeaderMap, Bytes)>>> =
            Arc::new(AsyncMutex::new(Vec::new()));
        let captured_srv = Arc::clone(&captured_outbound);
        let mock_cb = MockHttpServer::start(move |req: MockRequest| {
            let captured = Arc::clone(&captured_srv);
            async move {
                captured.lock().await.push((req.headers, req.body));
                MockResponse::json(StatusCode::OK, &json!({ "received": true }))
            }
        })
        .await;

        let wh_node = open_test_node("wh-tcp-node", &tmp.path().join("wh-tcp-node"));
        wh_node.register_handle("sess-tcp-wh", "agent").await.unwrap();
        wh_node
            .subscribe_local_or_remote(SubscribeRequest {
                id: Some("sub-tcp-wh".to_string()),
                subscriber_session: "sess-tcp-wh".to_string(),
                qualified_topic: "local.webhook".to_string(),
                filters: Vec::new(),
                coalesce_seconds: 0,
                mode: DeliveryMode::Full,
            })
            .await
            .unwrap();
        let wh_host = UnifiedNodeAdapterHost::new(Arc::clone(&wh_node));
        let wh_port = pick_free_loopback_port().await;
        let plugin_script = repo_root().join("plugins/webhook/index.mjs");

        let mut wh_cfg = SubprocessConfig::new(
            "webhook-tcp",
            AdapterKind::Bridge,
            node_bin.clone(),
            vec![plugin_script.to_string_lossy().into_owned()],
            vec!["webhook".to_string()],
        );
        wh_cfg.transport_mode = PluginTransportMode::LoopbackTcp;
        wh_cfg.hello_mode = HelloMode::Auto;
        wh_cfg.env.insert("WEBHOOK_HOST".into(), "127.0.0.1".into());
        wh_cfg.env.insert("WEBHOOK_PORT".into(), wh_port.to_string());
        wh_cfg.env.insert("WEBHOOK_PATH".into(), "/webhook".into());
        wh_cfg.env.insert("WEBHOOK_TARGET".into(), "webhook".into());
        wh_cfg.env.insert(
            "WEBHOOK_SECRET_FILE".into(),
            secret_file.to_string_lossy().into_owned(),
        );
        wh_cfg
            .env
            .insert("WEBHOOK_POST_URL".into(), mock_cb.url("/cb"));

        let wh_sup = SubprocessSupervisor::new(wh_cfg);
        wh_sup.start(Arc::clone(&wh_host) as _).await.unwrap();
        wait_for_http_ready(
            &format!("http://127.0.0.1:{wh_port}/ready-probe"),
            Duration::from_secs(10),
        )
        .await;

        let client = HttpClient::new().unwrap();
        let wh_url = format!("http://127.0.0.1:{wh_port}/webhook");
        let valid_body = serde_json::to_vec(&json!({
            "type": "com.acme.tcp.deploy",
            "source": "ci/win-runner",
            "subject": "service/payments",
            "data": { "sha": "faceb00c", "platform": "cross" }
        }))
        .unwrap();
        let expected_id = format!("sha256:{}", hex::encode(Sha256::digest(&valid_body)));
        let valid_sig = compute_hmac_sha256_header(secret.as_bytes(), &valid_body);

        let req_ok = Request::builder()
            .method(Method::POST)
            .uri(&wh_url)
            .header(CONTENT_TYPE, "application/json")
            .header("x-webhook-signature-256", &valid_sig)
            .body(full_body(valid_body.clone()))
            .unwrap();
        let resp_ok = client.request(req_ok).await.unwrap();
        let (st_ok, _, body_ok) = HttpClient::collect(resp_ok, 64 * 1024).await.unwrap();
        assert_eq!(st_ok, StatusCode::ACCEPTED);
        let ack_json: Value = serde_json::from_slice(&body_ok).unwrap();
        assert_eq!(ack_json["status"], "stored");
        assert_eq!(ack_json["id"], expected_id);

        let tcp_events = wh_host.wait_for_event_count(1, Duration::from_secs(5)).await;
        assert_eq!(tcp_events[0].0, "webhook");
        assert_eq!(tcp_events[0].1.id, expected_id);
        assert_eq!(tcp_events[0].1.event_type, "com.acme.tcp.deploy");

        // Verify persisted into UnifiedNode SQLite batch for local subscriber!
        let batches = {
            let db = wh_node.db();
            let now = now_ms();
            let _ = db.events().tick(now);
            db.events().claim_due_batches("sess-tcp-wh", now).unwrap()
        };
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].events[0].id, expected_id);

        // Outbound signed post over LoopbackTcp!
        let wh_post = wh_sup
            .post(
                "webhook",
                BTreeMap::from([("text".to_string(), json!("Signed TCP webhook reply"))]),
                Duration::from_secs(5),
            )
            .await
            .expect("webhook outbound post over LoopbackTcp must succeed");
        assert_eq!(wh_post["ok"], json!(true));
        let out_calls = captured_outbound.lock().await;
        assert_eq!(out_calls.len(), 1);
        let out_sig = out_calls[0]
            .0
            .get("x-webhook-signature-256")
            .and_then(|v| v.to_str().ok());
        assert!(verify_hmac_sha256_header(
            secret.as_bytes(),
            &out_calls[0].1,
            out_sig,
            true
        ));
        drop(out_calls);

        // Differential Unix fd-3 vs LoopbackTcp parity check on Unix!
        #[cfg(unix)]
        {
            let fd3_node = open_test_node("wh-fd3-node", &tmp.path().join("wh-fd3-node"));
            let fd3_host = UnifiedNodeAdapterHost::new(Arc::clone(&fd3_node));
            let fd3_port = pick_free_loopback_port().await;

            let mut fd3_cfg = SubprocessConfig::new(
                "webhook-fd3",
                AdapterKind::Bridge,
                node_bin,
                vec![plugin_script.to_string_lossy().into_owned()],
                vec!["webhook".to_string()],
            );
            fd3_cfg.transport_mode = PluginTransportMode::UnixFd3;
            fd3_cfg.hello_mode = HelloMode::Auto;
            fd3_cfg.env.insert("WEBHOOK_HOST".into(), "127.0.0.1".into());
            fd3_cfg.env.insert("WEBHOOK_PORT".into(), fd3_port.to_string());
            fd3_cfg.env.insert("WEBHOOK_PATH".into(), "/webhook".into());
            fd3_cfg.env.insert("WEBHOOK_TARGET".into(), "webhook".into());
            fd3_cfg.env.insert(
                "WEBHOOK_SECRET_FILE".into(),
                secret_file.to_string_lossy().into_owned(),
            );

            let fd3_sup = SubprocessSupervisor::new(fd3_cfg);
            fd3_sup.start(Arc::clone(&fd3_host) as _).await.unwrap();
            wait_for_http_ready(
                &format!("http://127.0.0.1:{fd3_port}/ready-probe"),
                Duration::from_secs(10),
            )
            .await;

            let req_fd3 = Request::builder()
                .method(Method::POST)
                .uri(format!("http://127.0.0.1:{fd3_port}/webhook"))
                .header(CONTENT_TYPE, "application/json")
                .header("x-webhook-signature-256", &valid_sig)
                .body(full_body(valid_body))
                .unwrap();
            assert_eq!(client.request(req_fd3).await.unwrap().status(), StatusCode::ACCEPTED);

            let fd3_events = fd3_host.wait_for_event_count(1, Duration::from_secs(5)).await;
            assert_eq!(tcp_events[0].0, fd3_events[0].0);
            assert_eq!(tcp_events[0].1.id, fd3_events[0].1.id);
            assert_eq!(tcp_events[0].1.event_type, fd3_events[0].1.event_type);
            assert_eq!(tcp_events[0].1.source, fd3_events[0].1.source);
            assert_eq!(tcp_events[0].1.subject, fd3_events[0].1.subject);
            assert_eq!(tcp_events[0].1.data, fd3_events[0].1.data);

            let _ = fd3_sup.stop().await;
            fd3_node.shutdown();
        }

        let _ = wh_sup.stop().await;
        wh_node.shutdown();
    }

    #[tokio::test]
    async fn loopback_tcp_python_sdk_client_py_hello_publish_status_and_post_e2e() {
        let Some(python_bin) = find_python3_binary() else {
            eprintln!(
                "SKIP loopback_tcp_python_sdk_client_py_hello_publish_status_and_post_e2e: Python 3 not on PATH"
            );
            return;
        };

        let tmp = TempDir::new().unwrap();
        let sdk_dir = repo_root().join("plugins/sdk");
        assert!(sdk_dir.join("client.py").exists(), "missing client.py");

        // (1) Fail-closed non-loopback address guard in `plugins/sdk/client.py`
        let guard_script = tmp.path().join("sdk_py_loopback_guard.py");
        fs::write(
            &guard_script,
            r#"
import os, sys
sys.path.insert(0, os.environ["SDK_PY_DIR"])
from client import MeshPluginClient

for bad_addr in ["192.168.1.5:9000", "0.0.0.0:9000", "evil.example:9000", "127.0.0.1:0", "broken"]:
    os.environ["HYPHAE_PLUGIN_ADDR"] = bad_addr
    os.environ["HYPHAE_PLUGIN_TOKEN"] = "b" * 64
    threw = False
    try:
        MeshPluginClient()
    except (ValueError, RuntimeError):
        threw = True
    assert threw, f"expected MeshPluginClient to reject {bad_addr!r}"
"#,
        )
        .unwrap();
        let guard_out = tokio::process::Command::new(&python_bin)
            .arg(&guard_script)
            .env("SDK_PY_DIR", &sdk_dir)
            .output()
            .await
            .expect("run client.py loopback guard check");
        assert!(
            guard_out.status.success(),
            "client.py loopback guard failed: stderr={}",
            String::from_utf8_lossy(&guard_out.stderr)
        );

        // (2) Full round-trip over `PluginTransportMode::LoopbackTcp`:
        //     auth token popped + hello + publish + duplicate + nack + status + inbound on_post RPC!
        let report_file = tmp.path().join("tcp_sdk_py_report.json");
        let status_file = tmp.path().join("tcp_sdk_py_status.json");
        let helper_script = tmp.path().join("tcp_sdk_py_harness.py");
        fs::write(
            &helper_script,
            r#"
import json
import os
import sys

sys.path.insert(0, os.environ["SDK_PY_DIR"])
from client import MeshPluginClient

transport_before = os.environ.get("HYPHAE_PLUGIN_TRANSPORT")
had_token_before = bool(os.environ.get("HYPHAE_PLUGIN_TOKEN"))

def on_status(msg):
    with open(os.environ["SDK_STATUS_FILE"], "w", encoding="utf-8") as f:
        json.dump(msg, f)

def on_post(params):
    if params.get("fail"):
        raise RuntimeError("py_tcp_post_error")
    return {
        "echoed": params.get("text"),
        "target": params.get("target"),
        "transport": transport_before,
    }

client = MeshPluginClient(on_status=on_status, on_post=on_post)
token_popped = os.environ.get("HYPHAE_PLUGIN_TOKEN") is None

valid_event = {
    "specversion": "1.0",
    "id": "tcp-sdk-py-evt-1",
    "source": "sdk/python-tcp-test",
    "type": "com.hyphae.sdk.py.tcp.ping",
    "time": "2026-11-25T12:00:00Z",
    "datacontenttype": "application/json",
    "data": {"ok": True, "lang": "python", "transport": "tcp"},
}

ack_stored = client.send("sdk-py-tcp", valid_event, retry_unavailable=False)
ack_dup = client.send("sdk-py-tcp", valid_event, retry_unavailable=False)

nack_invalid_err = None
try:
    client.send("sdk-py-tcp", {"specversion": "9.9", "id": "", "source": "x", "type": "y"}, retry_unavailable=False)
except RuntimeError as exc:
    nack_invalid_err = str(exc)

nack_target_err = None
try:
    client.send("wrong-target", valid_event, retry_unavailable=False)
except RuntimeError as exc:
    nack_target_err = str(exc)

with open(os.environ["SDK_REPORT_FILE"], "w", encoding="utf-8") as f:
    json.dump({
        "transport_before": transport_before,
        "had_token_before": had_token_before,
        "token_popped": token_popped,
        "plugin": client.plugin,
        "targets": client.targets,
        "ack_stored": ack_stored,
        "ack_dup": ack_dup,
        "nack_invalid_err": nack_invalid_err,
        "nack_target_err": nack_target_err,
    }, f)

client._dead.wait(timeout=15)
"#,
        )
        .unwrap();

        let node = open_test_node("tcp-sdk-py-node", tmp.path());
        let host = UnifiedNodeAdapterHost::new(Arc::clone(&node));

        let mut cfg = SubprocessConfig::new(
            "sdk-py-tcp-test",
            AdapterKind::Bridge,
            python_bin,
            vec!["-u".to_string(), helper_script.to_string_lossy().into_owned()],
            vec!["sdk-py-tcp".to_string()],
        );
        cfg.transport_mode = PluginTransportMode::LoopbackTcp;
        cfg.hello_mode = HelloMode::Auto;
        cfg.env
            .insert("SDK_PY_DIR".into(), sdk_dir.to_string_lossy().into_owned());
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
                "timed out waiting for tcp_sdk_py_report.json; health={:?} stderr={:?}",
                supervisor.health(),
                supervisor.recent_stderr()
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        };

        assert_eq!(report["transport_before"], "tcp");
        assert_eq!(report["had_token_before"], true);
        assert_eq!(
            report["token_popped"], true,
            "client.py MUST pop HYPHAE_PLUGIN_TOKEN from os.environ immediately"
        );
        assert_eq!(report["plugin"], "sdk-py-tcp-test");
        assert_eq!(report["targets"], json!(["sdk-py-tcp"]));
        assert_eq!(report["ack_stored"]["type"], "ack");
        assert_eq!(report["ack_stored"]["status"], "stored");
        assert_eq!(report["ack_dup"]["type"], "ack");
        assert_eq!(report["ack_dup"]["status"], "duplicate");
        assert!(
            report["nack_invalid_err"]
                .as_str()
                .is_some_and(|s| s.contains("invalid_event"))
        );
        assert!(
            report["nack_target_err"]
                .as_str()
                .is_some_and(|s| s.contains("unknown_target"))
        );

        // Verify host -> Python `status` notification over LoopbackTcp.
        supervisor
            .send_status(StatusParams {
                target: "sdk-py-tcp".to_string(),
                pending: 4,
                oldest_age_seconds: 19,
                t3_connected: true,
            })
            .await
            .expect("send_status over LoopbackTcp must succeed");

        let st_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let st_msg: Value = loop {
            if let Ok(raw) = fs::read_to_string(&status_file) {
                if let Ok(v) = serde_json::from_str::<Value>(&raw) {
                    break v;
                }
            }
            assert!(
                tokio::time::Instant::now() < st_deadline,
                "timed out waiting for Python TCP on_status callback"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        };
        assert_eq!(st_msg["type"], "status");
        assert_eq!(st_msg["target"], "sdk-py-tcp");
        assert_eq!(st_msg["pending"], 4);

        // Verify host -> Python outbound `post` -> `on_post` handler over LoopbackTcp!
        let py_post_ok = supervisor
            .post(
                "sdk-py-tcp",
                BTreeMap::from([("text".to_string(), json!("ping python tcp post"))]),
                Duration::from_secs(5),
            )
            .await
            .expect("Python on_post over LoopbackTcp must succeed");
        assert_eq!(
            py_post_ok,
            json!({
                "echoed": "ping python tcp post",
                "target": "sdk-py-tcp",
                "transport": "tcp"
            })
        );

        let py_post_err = supervisor
            .post(
                "sdk-py-tcp",
                BTreeMap::from([("fail".to_string(), json!(true))]),
                Duration::from_secs(5),
            )
            .await
            .expect_err("Python on_post failure must propagate over LoopbackTcp");
        assert!(
            matches!(&py_post_err, AdapterError::RequestFailed(m) if m.contains("py_tcp_post_error")),
            "unexpected py_post_err: {py_post_err:?}"
        );

        let ingested = host.published_events().await;
        assert_eq!(ingested.len(), 1);
        assert_eq!(ingested[0].1.id, "tcp-sdk-py-evt-1");

        let _ = supervisor.stop().await;
        assert_eq!(supervisor.health(), AdapterHealth::Stopped);
        node.shutdown();
    }

    #[tokio::test]
    async fn loopback_tcp_fail_closed_auth_wrong_token_missing_auth_oversized_timeout_and_redaction() {
        let Some(node_bin) = find_binary("node") else {
            eprintln!(
                "SKIP loopback_tcp_fail_closed_auth_wrong_token_missing_auth_oversized_timeout_and_redaction: `node` not on PATH"
            );
            return;
        };

        let tmp = TempDir::new().unwrap();

        // --------------------------------------------------------------------
        // (a) Wrong 1-bit-flipped token + leaked HYPHAE_PLUGIN_TOKEN in stderr
        // --------------------------------------------------------------------
        let wrong_tok_script = tmp.path().join("bad_auth_token.mjs");
        fs::write(
            &wrong_tok_script,
            r#"
import net from "node:net";
const [host, portStr] = process.env.HYPHAE_PLUGIN_ADDR.split(":");
const realToken = process.env.HYPHAE_PLUGIN_TOKEN ?? "";
// Simulate a buggy plugin accidentally logging process.env / handshake token to stderr!
process.stderr.write(`BUGGY_ENV_DUMP_START=${realToken}=BUGGY_ENV_DUMP_END\n`);
const badToken = (realToken[0] === "0" ? "1" : "0") + realToken.slice(1);
const sock = net.createConnection({ host, port: Number(portStr) });
sock.on("error", () => {});
sock.write(
  JSON.stringify({ type: "auth", token: badToken }) + "\n" +
  JSON.stringify({
    type: "event",
    to: "ops",
    event: {
      specversion: "1.0",
      id: "unauth-evt-wrong-tok",
      source: "attacker",
      type: "com.evil.spoof",
      data: { pwned: true }
    }
  }) + "\n",
);
setInterval(() => {}, 10_000);
"#,
        )
        .unwrap();

        let log_path = tmp.path().join("logs").join("plugin-bad-auth.log");
        let node_a = open_test_node("tcp-auth-a", &tmp.path().join("node-a"));
        let host_a = UnifiedNodeAdapterHost::new(Arc::clone(&node_a));
        let mut cfg_a = SubprocessConfig::new(
            "bad-auth-tok",
            AdapterKind::Bridge,
            node_bin.clone(),
            vec![wrong_tok_script.to_string_lossy().into_owned()],
            vec!["ops".to_string()],
        );
        cfg_a.transport_mode = PluginTransportMode::LoopbackTcp;
        cfg_a.stderr_log_path = Some(log_path.clone());
        cfg_a.initial_backoff = Duration::from_millis(20);
        cfg_a.max_backoff = Duration::from_millis(40);
        cfg_a.max_rapid_crashes = 2;
        cfg_a.startup_timeout = Duration::from_secs(3);

        let sup_a = SubprocessSupervisor::new(cfg_a);
        sup_a.start(Arc::clone(&host_a) as _).await.unwrap();

        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while !sup_a.is_crash_loop_backoff() {
            assert!(
                tokio::time::Instant::now() < deadline,
                "expected wrong-token plugin to fail closed into CrashLoopBackOff; health={:?}",
                sup_a.health()
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }

        assert!(!sup_a.is_connected().await, "unauthenticated child must never be connected");
        assert!(
            host_a.published_events().await.is_empty(),
            "spoofed event after wrong auth token MUST NEVER reach UnifiedNode"
        );
        match sup_a.health() {
            AdapterHealth::Degraded(msg) => {
                assert!(
                    msg.contains("invalid handshake token"),
                    "expected invalid handshake token error, got: {msg}"
                );
                assert!(
                    msg.contains("BUGGY_ENV_DUMP_START=[REDACTED]=BUGGY_ENV_DUMP_END"),
                    "expected redacted HYPHAE_PLUGIN_TOKEN in health, got: {msg}"
                );
            }
            other => panic!("expected Degraded on wrong auth token, got {other:?}"),
        }
        let recent = sup_a.recent_stderr();
        assert!(
            recent
                .iter()
                .any(|l| l.contains("BUGGY_ENV_DUMP_START=[REDACTED]=BUGGY_ENV_DUMP_END")),
            "HYPHAE_PLUGIN_TOKEN MUST be redacted in recent_stderr: {recent:?}"
        );
        let log_raw = fs::read_to_string(&log_path).expect("read bad-auth stderr log");
        assert!(
            log_raw.contains("BUGGY_ENV_DUMP_START=[REDACTED]=BUGGY_ENV_DUMP_END"),
            "HYPHAE_PLUGIN_TOKEN MUST be redacted in stderr log file: {log_raw}"
        );

        let _ = sup_a.stop().await;
        node_a.shutdown();

        // --------------------------------------------------------------------
        // (b) Missing auth line: sends `event` directly without authenticating
        // --------------------------------------------------------------------
        let no_auth_script = tmp.path().join("missing_auth.mjs");
        fs::write(
            &no_auth_script,
            r#"
import net from "node:net";
const [host, portStr] = process.env.HYPHAE_PLUGIN_ADDR.split(":");
const sock = net.createConnection({ host, port: Number(portStr) });
sock.on("error", () => {});
sock.write(JSON.stringify({
  type: "event",
  to: "ops",
  event: {
    specversion: "1.0",
    id: "unauth-evt-missing",
    source: "attacker",
    type: "com.evil.noauth",
    data: { pwned: true }
  }
}) + "\n");
setInterval(() => {}, 10_000);
"#,
        )
        .unwrap();

        let node_b = open_test_node("tcp-auth-b", &tmp.path().join("node-b"));
        let host_b = UnifiedNodeAdapterHost::new(Arc::clone(&node_b));
        let mut cfg_b = SubprocessConfig::new(
            "missing-auth",
            AdapterKind::Bridge,
            node_bin.clone(),
            vec![no_auth_script.to_string_lossy().into_owned()],
            vec!["ops".to_string()],
        );
        cfg_b.transport_mode = PluginTransportMode::LoopbackTcp;
        cfg_b.initial_backoff = Duration::from_millis(20);
        cfg_b.max_backoff = Duration::from_millis(40);
        cfg_b.max_rapid_crashes = 1;
        cfg_b.startup_timeout = Duration::from_secs(3);

        let sup_b = SubprocessSupervisor::new(cfg_b);
        sup_b.start(Arc::clone(&host_b) as _).await.unwrap();

        let deadline_b = tokio::time::Instant::now() + Duration::from_secs(10);
        while !sup_b.is_crash_loop_backoff() {
            assert!(
                tokio::time::Instant::now() < deadline_b,
                "expected missing-auth plugin to fail closed; health={:?}",
                sup_b.health()
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(host_b.published_events().await.is_empty());
        assert!(
            sup_b
                .last_error()
                .is_some_and(|e| e.contains("TCP plugin auth failed")),
            "expected TCP auth failure error, got: {:?}",
            sup_b.last_error()
        );
        let _ = sup_b.stop().await;
        node_b.shutdown();

        // --------------------------------------------------------------------
        // (c) Oversized (>4 KiB) auth line rejected immediately without hanging
        // --------------------------------------------------------------------
        let big_auth_script = tmp.path().join("oversized_auth.mjs");
        fs::write(
            &big_auth_script,
            r#"
import net from "node:net";
const [host, portStr] = process.env.HYPHAE_PLUGIN_ADDR.split(":");
const sock = net.createConnection({ host, port: Number(portStr) });
sock.on("error", () => {});
sock.write("A".repeat(5000));
setInterval(() => {}, 10_000);
"#,
        )
        .unwrap();

        let node_c = open_test_node("tcp-auth-c", &tmp.path().join("node-c"));
        let host_c = UnifiedNodeAdapterHost::new(Arc::clone(&node_c));
        let mut cfg_c = SubprocessConfig::new(
            "oversized-auth",
            AdapterKind::Bridge,
            node_bin.clone(),
            vec![big_auth_script.to_string_lossy().into_owned()],
            vec!["ops".to_string()],
        );
        cfg_c.transport_mode = PluginTransportMode::LoopbackTcp;
        cfg_c.initial_backoff = Duration::from_millis(20);
        cfg_c.max_rapid_crashes = 1;
        cfg_c.startup_timeout = Duration::from_secs(5);

        let sup_c = SubprocessSupervisor::new(cfg_c);
        sup_c.start(Arc::clone(&host_c) as _).await.unwrap();
        let deadline_c = tokio::time::Instant::now() + Duration::from_secs(5);
        while !sup_c.is_crash_loop_backoff() {
            assert!(
                tokio::time::Instant::now() < deadline_c,
                "expected oversized auth frame to be rejected quickly; health={:?}",
                sup_c.health()
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(
            sup_c
                .last_error()
                .is_some_and(|e| e.contains("4096 byte limit")),
            "expected 4096 byte limit error, got: {:?}",
            sup_c.last_error()
        );
        let _ = sup_c.stop().await;
        node_c.shutdown();

        // --------------------------------------------------------------------
        // (d) Silent TCP connection times out cleanly at `startup_timeout`
        // --------------------------------------------------------------------
        let silent_script = tmp.path().join("silent_auth.mjs");
        fs::write(
            &silent_script,
            r#"
import net from "node:net";
const [host, portStr] = process.env.HYPHAE_PLUGIN_ADDR.split(":");
const sock = net.createConnection({ host, port: Number(portStr) });
sock.on("error", () => {});
setInterval(() => {}, 10_000);
"#,
        )
        .unwrap();

        let node_d = open_test_node("tcp-auth-d", &tmp.path().join("node-d"));
        let host_d = UnifiedNodeAdapterHost::new(Arc::clone(&node_d));
        let mut cfg_d = SubprocessConfig::new(
            "silent-auth",
            AdapterKind::Bridge,
            node_bin,
            vec![silent_script.to_string_lossy().into_owned()],
            vec!["ops".to_string()],
        );
        cfg_d.transport_mode = PluginTransportMode::LoopbackTcp;
        cfg_d.initial_backoff = Duration::from_millis(20);
        cfg_d.max_rapid_crashes = 1;
        cfg_d.startup_timeout = Duration::from_millis(450);

        let sup_d = SubprocessSupervisor::new(cfg_d);
        sup_d.start(Arc::clone(&host_d) as _).await.unwrap();
        let deadline_d = tokio::time::Instant::now() + Duration::from_secs(5);
        while !sup_d.is_crash_loop_backoff() {
            assert!(
                tokio::time::Instant::now() < deadline_d,
                "expected silent TCP plugin to time out cleanly; health={:?}",
                sup_d.health()
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(
            sup_d.last_error().is_some_and(|e| e.contains("timed out")),
            "expected timeout error, got: {:?}",
            sup_d.last_error()
        );
        let _ = sup_d.stop().await;
        assert_eq!(sup_d.health(), AdapterHealth::Stopped);
        node_d.shutdown();
    }
}
