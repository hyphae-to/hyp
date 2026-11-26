//! Wave 3D End-to-End Tests (`5b`/`B6`, `5c`/`P1-7`/`B20`, `H7`, `5a`/`D6`, `6a`/`G9`).
//!
//! Strictly isolated (`TempDir`, `127.0.0.1:0`, `SecretBackend::File`, zero live user config
//! or Keychain mutations).

use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use bytes::Bytes;
use http::{Method, Request, StatusCode};
use hyp_crypto::rfc3339::now_unix_ms;
use hyp_crypto::transfer::TarInputEntry;
use hyp_crypto::{Ed25519KeyPair, SecretBackend};
use hyp_node::adapters::{GitHubWebhookAdapter, GitHubWebhookConfig, compute_hmac_sha256_header};
use hyp_node::engine::config::{ForwardingMode, ForwardingPolicy, ForwardingRule};
use hyp_node::engine::http_util::{HttpClient, full_body};
use hyp_node::engine::node::SubscribeRequest;
use hyp_node::engine::peer_link::{
    PostMessageRequest, PublishEventRequest, http_auth_signing_input,
};
use hyp_node::engine::{NodeConfig, NodeProfile, UnifiedNode};
use hyp_node::gates::{SecurityGateConfig, SecurityGatePipeline, Stage1DenyAction};
use hyp_proto::address::NodeId;
use hyp_proto::cloudevent::CloudEvent;
use hyp_proto::filter::Filter;
use hyp_proto::scopes::ScopePreset;
use hyp_store::{
    DeliveryMode, GateAuditQuery, GateDecision as StoreGateDecision, GateState, NodeDb, TrustTier,
    now_ms,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use zeroize::Zeroizing;

fn admin_proto_jwk(key: &Ed25519KeyPair) -> hyp_proto::manifest::OkpJwk {
    serde_json::from_value(serde_json::to_value(key.to_jwk()).expect("jwk value"))
        .expect("proto okp jwk")
}

async fn register_session_with_handle(node: &UnifiedNode, session_id: &str, handle: &str) {
    node.register_session(session_id, "{}").unwrap();
    node.register_handle(session_id, handle).await.unwrap();
}

fn stage_tar_entry(
    stage_dir: &std::path::Path,
    local_name: &str,
    archive_path: &str,
    bytes: &[u8],
) -> TarInputEntry {
    let source_path = stage_dir.join(local_name);
    fs::write(&source_path, bytes).expect("write tar source file");
    TarInputEntry {
        archive_path: archive_path.to_string(),
        source_path,
    }
}

fn make_node_cfg(id: &str, profile: NodeProfile, dir: &TempDir) -> NodeConfig {
    let mut cfg = NodeConfig::new(NodeId::new(id).unwrap(), profile, dir.path());
    cfg.secret_backend = Some(SecretBackend::File);
    cfg
}

async fn send_raw_http(
    client: &HttpClient,
    method: Method,
    url: &str,
    headers: &[(&str, String)],
    body: Bytes,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(url);
    for (k, v) in headers {
        builder = builder.header(*k, v.as_str());
    }
    let req = builder.body(full_body(body)).expect("valid request");
    let resp = client.request(req).await.expect("http send");
    let (status, _hdrs, bytes) = HttpClient::collect(resp, 1024 * 1024)
        .await
        .expect("collect response");
    let val = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| json!({ "raw": String::from_utf8_lossy(&bytes).to_string() }));
    (status, val)
}

async fn pair_admin_peer(
    hub: &Arc<UnifiedNode>,
    admin_key: &Ed25519KeyPair,
    peer_node: &Arc<UnifiedNode>,
    scopes: &[&str],
) {
    let (am2, _grant) = hub
        .create_admin_invite(
            admin_key,
            peer_node.node_id().as_str(),
            scopes,
            TrustTier::Org,
            3_600_000,
        )
        .expect("create admin invite");
    peer_node
        .accept_am2_invite(&am2)
        .await
        .expect("accept am2 invite");
}

async fn wait_for_mailbox_count(
    node: &UnifiedNode,
    session_id: &str,
    min_count: usize,
) -> Vec<hyp_store::MailboxEntry> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let items = {
            let db = node.db();
            db.local().peek_inbox(session_id, 50).unwrap_or_default()
        };
        if items.len() >= min_count {
            return items;
        }
        if tokio::time::Instant::now() >= deadline {
            return items;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

// ============================================================================
// 5b (B6): Compiled-in pure-Rust webhook HTTP routes (fail-closed + publish)
// ============================================================================

#[tokio::test]
async fn wave3d_5b_compiled_in_webhooks_fail_closed_and_publish_cloudevents() {
    let hub_dir = TempDir::new().unwrap();
    let reader_dir = TempDir::new().unwrap();
    let admin_key = Ed25519KeyPair::generate().unwrap();

    let mut hub_cfg = make_node_cfg("webhook-hub", NodeProfile::Router, &hub_dir);
    hub_cfg.admin_jwk = Some(admin_proto_jwk(&admin_key));
    let hub = UnifiedNode::open(hub_cfg).unwrap();

    let gh_secret = "gh-webhook-secret-top";
    let mut gh_cfg = GitHubWebhookConfig::new("github", "github", gh_secret);
    gh_cfg.allowed_repos = vec!["acme/app".to_string()];
    hub.attach_github_webhook(Arc::new(GitHubWebhookAdapter::new(gh_cfg)))
        .await
        .unwrap();

    let gh_sec_secret = "gh-sec-secret-2";
    let gh_sec_cfg = GitHubWebhookConfig::new("gh-sec", "sec-github", gh_sec_secret);
    hub.attach_github_webhook(Arc::new(GitHubWebhookAdapter::new(gh_sec_cfg)))
        .await
        .unwrap();

    let (addr, server_task) = Arc::clone(&hub)
        .serve("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .await
        .unwrap();
    let base = format!("http://{addr}");

    // Subscribe a local session to the native GitHub source.
    register_session_with_handle(&hub, "local-watcher", "ops").await;
    hub.subscribe_local_or_remote(SubscribeRequest {
        id: Some("sub-gh".to_string()),
        subscriber_session: "local-watcher".to_string(),
        qualified_topic: "local.github".to_string(),
        filters: vec![Filter::Exact(
            [("repo".to_string(), "acme/app".to_string())]
                .into_iter()
                .collect(),
        )],
        coalesce_seconds: 0,
        mode: DeliveryMode::Full,
    })
    .await
    .unwrap();
    // Also pair a remote reader subscribed to `webhook-hub.github` over SSE.
    let reader = UnifiedNode::open(make_node_cfg(
        "reader@laptop",
        NodeProfile::Local,
        &reader_dir,
    ))
    .unwrap();
    register_session_with_handle(&reader, "reader-sess", "dev").await;
    let member_scopes_owned = ScopePreset::Member.expand();
    let member_scopes: Vec<&str> = member_scopes_owned.iter().map(String::as_str).collect();
    pair_admin_peer(&hub, &admin_key, &reader, &member_scopes).await;
    reader
        .subscribe_local_or_remote(SubscribeRequest {
            id: Some("remote-gh".to_string()),
            subscriber_session: "reader-sess".to_string(),
            qualified_topic: "webhook-hub.github".to_string(),
            filters: vec![Filter::Exact(
                [("repo".to_string(), "acme/app".to_string())]
                    .into_iter()
                    .collect(),
            )],
            coalesce_seconds: 0,
            mode: DeliveryMode::Full,
        })
        .await
        .unwrap();

    let client = HttpClient::new().unwrap();

    // 1. GitHub webhook: missing & 1-bit-flipped HMAC fail closed with 401.
    let gh_body = serde_json::to_vec(&json!({
        "action": "opened",
        "repository": { "full_name": "acme/app" },
        "sender": { "login": "alice", "type": "User" },
        "pull_request": {
            "number": 42,
            "title": "Wire webhooks",
            "html_url": "https://github.com/acme/app/pull/42",
            "state": "open",
            "body": "ready for review",
            "labels": [],
            "assignees": []
        }
    }))
    .unwrap();
    let (st, _) = send_raw_http(
        &client,
        Method::POST,
        &format!("{base}/v1/webhooks/github"),
        &[
            ("x-github-event", "pull_request".to_string()),
            ("x-github-delivery", "deliv-1".to_string()),
        ],
        Bytes::from(gh_body.clone()),
    )
    .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);

    let good_gh_sig = compute_hmac_sha256_header(gh_secret.as_bytes(), &gh_body);
    let mut bad_gh_sig = good_gh_sig.clone();
    let last = bad_gh_sig.pop().unwrap();
    bad_gh_sig.push(if last == 'a' { 'b' } else { 'a' });
    let (st, _) = send_raw_http(
        &client,
        Method::POST,
        &format!("{base}/v1/webhooks/github"),
        &[
            ("x-hub-signature-256", bad_gh_sig),
            ("x-github-event", "pull_request".to_string()),
            ("x-github-delivery", "deliv-1".to_string()),
        ],
        Bytes::from(gh_body.clone()),
    )
    .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);

    // Valid GitHub webhook publishes & delivers to BOTH local session and remote SSE peer!
    let expected_gh_id = format!("gh-{}", hex::encode(Sha256::digest(&gh_body)));
    let (st, val) = send_raw_http(
        &client,
        Method::POST,
        &format!("{base}/v1/webhooks/github"),
        &[
            ("x-hub-signature-256", good_gh_sig.clone()),
            ("x-github-event", "pull_request".to_string()),
            ("x-github-delivery", "deliv-1".to_string()),
        ],
        Bytes::from(gh_body.clone()),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "github webhook failed: {val}");
    assert_eq!(val["status"], "published");
    assert_eq!(val["eventId"], expected_gh_id);

    // B8: Replaying the exact same signed GitHub body with a spoofed `X-GitHub-Delivery` MUST
    // derive the exact same SHA-256 event ID and deduplicate (`duplicate`)!
    let (st, val_dup) = send_raw_http(
        &client,
        Method::POST,
        &format!("{base}/v1/webhooks/github"),
        &[
            ("x-hub-signature-256", good_gh_sig),
            ("x-github-event", "pull_request".to_string()),
            (
                "x-github-delivery",
                "spoofed-unsigned-delivery-id".to_string(),
            ),
        ],
        Bytes::from(gh_body),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(val_dup["eventId"], expected_gh_id);
    assert_eq!(val_dup["publishStatus"], "duplicate");

    // Named second GitHub webhook route `/v1/webhooks/github/:id`.
    let gh_sec_body = serde_json::to_vec(&json!({
        "action": "opened",
        "repository": { "full_name": "acme/sec" },
        "sender": { "login": "secbot", "type": "User" },
        "issues": null,
        "issue": {
            "number": 7,
            "title": "Advisory",
            "html_url": "https://github.com/acme/sec/issues/7",
            "state": "open",
            "body": "check",
            "labels": [],
            "assignees": []
        }
    }))
    .unwrap();
    let sec_sig = compute_hmac_sha256_header(gh_sec_secret.as_bytes(), &gh_sec_body);
    let (st, val) = send_raw_http(
        &client,
        Method::POST,
        &format!("{base}/v1/webhooks/github/gh-sec"),
        &[
            ("x-hub-signature-256", sec_sig),
            ("x-github-event", "issues".to_string()),
            ("x-github-delivery", "deliv-sec-1".to_string()),
        ],
        Bytes::from(gh_sec_body),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "named github webhook failed: {val}");
    assert_eq!(val["status"], "published");

    // Adapter-owned topic protection: remote peer holding `stream:publish=*` MUST be rejected
    // with 403 `not_granted` when attempting `POST /v1/events` onto an adapter-owned webhook topic!
    let pub_peer_dir = TempDir::new().unwrap();
    let pub_peer = UnifiedNode::open(make_node_cfg(
        "spoofer@laptop",
        NodeProfile::Local,
        &pub_peer_dir,
    ))
    .unwrap();
    pair_admin_peer(&hub, &admin_key, &pub_peer, &["stream:publish=*"]).await;
    let pub_link = pub_peer.peer_link("webhook-hub").await.unwrap();
    for owned_topic in ["github", "sec-github"] {
        let spoof_ev = CloudEvent::new(
            format!("spoof-{owned_topic}"),
            "spoofer@laptop/src",
            "com.example.spoof",
            json!({ "forged": true }),
        );
        let err = pub_link
            .publish_event(&PublishEventRequest {
                topic: owned_topic.to_string(),
                event: spoof_ev,
            })
            .await
            .expect_err("remote POST /v1/events onto adapter-owned webhook topic must fail closed");
        assert!(
            err.to_string().contains("403") || err.to_string().contains("not_granted"),
            "expected 403 not_granted on adapter-owned topic '{owned_topic}', got: {err}"
        );
    }
    pub_peer.shutdown();

    // Unconfigured webhook id returns 404.
    let (st, _) = send_raw_http(
        &client,
        Method::POST,
        &format!("{base}/v1/webhooks/stream/does-not-exist"),
        &[],
        Bytes::from_static(b"{}"),
    )
    .await;
    assert_eq!(st, StatusCode::NOT_FOUND);

    // Every native GitHub event carries the externally sourced marker.
    let local_items = wait_for_mailbox_count(&hub, "local-watcher", 1).await;
    assert_eq!(local_items.len(), 1, "expected one matching GitHub batch");
    for item in &local_items {
        let parsed: Value = serde_json::from_str(&item.text).unwrap();
        let events = parsed["events"].as_array().expect("events array");
        assert!(!events.is_empty());
        for ev in events {
            assert_eq!(
                ev["hyphaesourcekind"].as_str(),
                Some("external-webhook"),
                "webhook CloudEvent missing hyphaesourcekind=external-webhook: {ev}"
            );
        }
    }

    // Remote SSE peer receives the filtered GitHub webhook event!
    let remote_items = wait_for_mailbox_count(&reader, "reader-sess", 1).await;
    assert!(
        remote_items
            .iter()
            .any(|m| m.text.contains("Wire webhooks")),
        "remote peer should receive GitHub webhook over SSE"
    );

    reader.shutdown();
    hub.shutdown_adapters().await;
    hub.shutdown();
    server_task.abort();
}

// ============================================================================
// 5c (P1-7): Router DMs work without forward:via; non-router & transit enforce both
// ============================================================================

#[tokio::test]
async fn wave3d_5c_router_dm_works_and_relay_enforces_forwarding_plus_forward_via() {
    let hub_dir = TempDir::new().unwrap();
    let laptop_dir = TempDir::new().unwrap();
    let server_dir = TempDir::new().unwrap();
    let no_recv_dir = TempDir::new().unwrap();
    let admin_key = Ed25519KeyPair::generate().unwrap();
    let admin_proto = admin_proto_jwk(&admin_key);

    // --- Part A: Laptop <-> Team Hub (Router, ForwardingMode::Deny) <-> Server ---
    let mut hub_cfg = make_node_cfg("acme-team", NodeProfile::Router, &hub_dir);
    hub_cfg.admin_jwk = Some(admin_proto.clone());
    assert_eq!(hub_cfg.forwarding.mode, ForwardingMode::Deny);
    let hub = UnifiedNode::open(hub_cfg).unwrap();
    let (_hub_addr, hub_task) = Arc::clone(&hub)
        .serve("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();

    let laptop = UnifiedNode::open(make_node_cfg(
        "alice@laptop",
        NodeProfile::Local,
        &laptop_dir,
    ))
    .unwrap();
    let server =
        UnifiedNode::open(make_node_cfg("bob@server", NodeProfile::Local, &server_dir)).unwrap();
    let no_recv = UnifiedNode::open(make_node_cfg(
        "sendonly@bot",
        NodeProfile::Local,
        &no_recv_dir,
    ))
    .unwrap();

    register_session_with_handle(&laptop, "s-alice", "dev").await;
    register_session_with_handle(&server, "s-bob", "ops").await;
    register_session_with_handle(&no_recv, "s-bot", "bot").await;

    // Standard `member` preset (dm:send=*, dm:receive, ZERO forward:via!).
    let member_scopes_owned = ScopePreset::Member.expand();
    let member_scopes: Vec<&str> = member_scopes_owned.iter().map(String::as_str).collect();
    pair_admin_peer(&hub, &admin_key, &laptop, &member_scopes).await;
    pair_admin_peer(&hub, &admin_key, &server, &member_scopes).await;
    // Peer with dm:send=* ONLY (NO dm:receive!).
    pair_admin_peer(&hub, &admin_key, &no_recv, &["dm:send=*"]).await;

    // Laptop -> Team Hub -> Server E2EE DM succeeds with zero forward:via AND attributes
    // mailbox `origin_node` to the verified sender (`alice@laptop`), NEVER the relaying hub!
    laptop
        .send_dm("dev", "bob@server/ops", "hello via team hub")
        .await
        .expect("Laptop <-> Team Hub <-> Server DM must succeed");
    let bob_items = wait_for_mailbox_count(&server, "s-bob", 1).await;
    let dm_item = bob_items
        .iter()
        .find(|m| m.text.contains("hello via team hub"))
        .expect("bob@server should receive decrypted DM");
    assert_eq!(
        dm_item.origin_node, "alice@laptop",
        "hub-relayed DM must attribute mailbox origin_node to verified sender, NOT relaying hub"
    );

    // Sending to a peer lacking `dm:receive` fails closed with 403 not_granted!
    let err = laptop
        .send_dm("dev", "sendonly@bot/bot", "should fail dm:receive")
        .await
        .expect_err("DM to peer without dm:receive must fail closed");
    let err_str = err.to_string();
    assert!(
        err_str.contains("403")
            || err_str.contains("dm:receive")
            || err_str.contains("not_granted"),
        "expected 403 dm:receive denial, got: {err_str}"
    );

    laptop.shutdown();
    server.shutdown();
    no_recv.shutdown();
    hub.shutdown();
    hub_task.abort();

    // --- Part B: Non-router P2P relay enforces BOTH forwarding allowlist AND forward:via ---
    let p2p_deny_dir = TempDir::new().unwrap();
    let p2p_allow_dir = TempDir::new().unwrap();
    let caller_star_dir = TempDir::new().unwrap();
    let caller_fwd_dir = TempDir::new().unwrap();

    // P2P node with default Deny forwarding: rejects relay even with `*`.
    let mut deny_cfg = make_node_cfg("relay-deny@p2p", NodeProfile::P2p, &p2p_deny_dir);
    deny_cfg.admin_jwk = Some(admin_proto.clone());
    let relay_deny = UnifiedNode::open(deny_cfg).unwrap();
    relay_deny
        .db()
        .messages()
        .register_handle("charlie@third", "ops", None, now_ms())
        .unwrap();
    let (_d_addr, deny_task) = Arc::clone(&relay_deny)
        .serve("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();

    let caller_star = UnifiedNode::open(make_node_cfg(
        "alice-star@laptop",
        NodeProfile::Local,
        &caller_star_dir,
    ))
    .unwrap();
    pair_admin_peer(&relay_deny, &admin_key, &caller_star, &["*"]).await;
    let deny_link = caller_star.peer_link("relay-deny@p2p").await.unwrap();
    let deny_err = deny_link
        .post_message(&PostMessageRequest {
            id: "relay-dm-1".to_string(),
            from_handle: "dev".to_string(),
            to: "charlie@third/ops".to_string(),
            text: "relayed".to_string(),
            content_type: None,
            e2ee_epoch: None,
        })
        .await
        .expect_err("P2P node with ForwardingMode::Deny must reject third-party DM relay");
    assert!(
        deny_err.to_string().contains("403") && deny_err.to_string().contains("forward:via"),
        "expected 403 forward:via denial, got: {deny_err}"
    );

    // P2P node with Allowlist forwarding: still rejects `*` caller without `forward:via`,
    // and allows caller that holds explicit `forward:via=charlie@third`!
    let mut allow_cfg = make_node_cfg("relay-allow@p2p", NodeProfile::P2p, &p2p_allow_dir);
    allow_cfg.admin_jwk = Some(admin_proto);
    allow_cfg.forwarding = ForwardingPolicy {
        mode: ForwardingMode::Allowlist,
        rules: vec![
            ForwardingRule {
                from_peer: "*".to_string(),
                to_peer: "charlie@third".to_string(),
                topic: Some("dm".to_string()),
                max_hops: None,
            },
            ForwardingRule {
                from_peer: "*".to_string(),
                to_peer: "*".to_string(),
                topic: Some("ops".to_string()),
                max_hops: None,
            },
        ],
        max_hops: 2,
    };
    let relay_allow = UnifiedNode::open(allow_cfg).unwrap();
    relay_allow
        .db()
        .messages()
        .register_handle("charlie@third", "ops", None, now_ms())
        .unwrap();
    let (_a_addr, allow_task) = Arc::clone(&relay_allow)
        .serve("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();

    let caller_fwd = UnifiedNode::open(make_node_cfg(
        "alice-fwd@laptop",
        NodeProfile::Local,
        &caller_fwd_dir,
    ))
    .unwrap();
    pair_admin_peer(&relay_allow, &admin_key, &caller_star, &["*"]).await;
    pair_admin_peer(
        &relay_allow,
        &admin_key,
        &caller_fwd,
        &[
            "dm:send=*",
            "stream:publish=ops",
            "forward:via=charlie@third",
            "forward:via=origin@ext",
        ],
    )
    .await;

    let star_allow_link = caller_star.peer_link("relay-allow@p2p").await.unwrap();
    let fwd_allow_link = caller_fwd.peer_link("relay-allow@p2p").await.unwrap();

    // `*` caller lacks `forward:via=charlie@third` -> STILL 403 even with Allowlist!
    let err = star_allow_link
        .post_message(&PostMessageRequest {
            id: "relay-dm-2".to_string(),
            from_handle: "dev".to_string(),
            to: "charlie@third/ops".to_string(),
            text: "relayed".to_string(),
            content_type: None,
            e2ee_epoch: None,
        })
        .await
        .expect_err("wildcard `*` must never grant forward:via");
    assert!(err.to_string().contains("403"), "got: {err}");

    // Caller with BOTH Allowlist AND `forward:via=charlie@third` succeeds!
    let resp = fwd_allow_link
        .post_message(&PostMessageRequest {
            id: "relay-dm-3".to_string(),
            from_handle: "dev".to_string(),
            to: "charlie@third/ops".to_string(),
            text: "relayed".to_string(),
            content_type: None,
            e2ee_epoch: None,
        })
        .await
        .expect("explicit forward:via + forwarding allowlist must permit relay");
    assert_eq!(resp.id, "relay-dm-3");

    // --- Part C: Foreign-origin transit event forwarding enforces forward:via ---
    let mut transit_ev = CloudEvent::new(
        "transit-ev-1",
        "origin@ext/src",
        "com.example.ping",
        json!({ "ok": true }),
    );
    transit_ev.set_extension("hyphaeorigin", "origin@ext");
    transit_ev.set_extension("hyphaehops", "1");

    let err = star_allow_link
        .publish_event(&PublishEventRequest {
            topic: "ops".to_string(),
            event: transit_ev.clone(),
        })
        .await
        .expect_err("foreign transit event must fail closed without forward:via");
    assert!(err.to_string().contains("403"), "got: {err}");

    let ingest = fwd_allow_link
        .publish_event(&PublishEventRequest {
            topic: "ops".to_string(),
            event: transit_ev,
        })
        .await
        .expect("foreign transit event succeeds with allowlist + forward:via=origin@ext");
    assert!(!ingest.deduplicated);

    // Missing `hyphaeorigin` WITH `hyphaevia` indicating transit MUST NOT bypass foreign-origin checks!
    let mut via_only_ev = CloudEvent::new(
        "transit-via-only-1",
        "origin@ext/src",
        "com.example.ping",
        json!({ "ok": true }),
    );
    via_only_ev.set_extension("hyphaevia", "origin@ext");
    let err = star_allow_link
        .publish_event(&PublishEventRequest {
            topic: "ops".to_string(),
            event: via_only_ev,
        })
        .await
        .expect_err(
            "omitted hyphaeorigin with foreign hyphaevia must fail closed without forward:via",
        );
    assert!(err.to_string().contains("403"), "got: {err}");

    // `ForwardingPolicy { max_hops: 0, .. }` clamps effective_max_hops() to 1 so ingest never breaks.
    let zero_hops_policy = ForwardingPolicy {
        max_hops: 0,
        ..ForwardingPolicy::default()
    };
    assert_eq!(zero_hops_policy.effective_max_hops(), 1);

    caller_star.shutdown();
    caller_fwd.shutdown();
    relay_deny.shutdown();
    relay_allow.shutdown();
    deny_task.abort();
    allow_task.abort();
}

// ============================================================================
// Wave 4A Cut: `POST /v1/node/update` & `POST /v1/bridges/post` Return 404
// ============================================================================

#[tokio::test]
async fn wave4a_cut_remote_node_update_and_bridges_post_return_404_and_no_capability() {
    let hub_dir = TempDir::new().unwrap();
    let peer_dir = TempDir::new().unwrap();
    let admin_key = Ed25519KeyPair::generate().unwrap();

    let mut hub_cfg = make_node_cfg("cut-hub", NodeProfile::Router, &hub_dir);
    hub_cfg.admin_jwk = Some(admin_proto_jwk(&admin_key));
    let hub = UnifiedNode::open(hub_cfg).unwrap();

    // Manifest MUST NOT advertise `node.self-update.v1`!
    let (_signed, manifest, _etag) = hub.build_signed_manifest(None).unwrap();
    assert!(
        !manifest
            .capabilities
            .iter()
            .any(|c| c.as_str() == "node.self-update.v1"),
        "v0.7.0 manifest must never advertise node.self-update.v1"
    );

    let (addr, task) = Arc::clone(&hub)
        .serve("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let base = format!("http://{addr}");

    let peer =
        UnifiedNode::open(make_node_cfg("admin@laptop", NodeProfile::Local, &peer_dir)).unwrap();
    pair_admin_peer(
        &hub,
        &admin_key,
        &peer,
        &["*", "bridge:post=telegram:personal"],
    )
    .await;

    let client = HttpClient::new().unwrap();
    for (path, body) in [
        (
            "/v1/node/update",
            br#"{"channel":"stable","targetVersion":"2.3.0"}"#.as_slice(),
        ),
        (
            "/v1/bridges/post",
            br#"{"plugin":"telegram","target":"personal","text":"hi"}"#.as_slice(),
        ),
    ] {
        let body_sha = hex::encode(Sha256::digest(body));
        let ts = now_ms();
        let nonce = format!("cut-nonce-{}", path.trim_start_matches('/'));
        let sign_input = http_auth_signing_input("POST", path, ts, &nonce, &body_sha);
        let sig = peer
            .identity()
            .signing
            .sign_domain_b64("http-auth", &sign_input);
        let (st, _) = send_raw_http(
            &client,
            Method::POST,
            &format!("{base}{path}"),
            &[
                ("content-type", "application/json".to_string()),
                ("x-hyphae-node", "admin@laptop".to_string()),
                ("x-hyphae-timestamp", ts.to_string()),
                ("x-hyphae-nonce", nonce),
                ("x-hyphae-sig", sig),
            ],
            Bytes::copy_from_slice(body),
        )
        .await;
        assert_eq!(
            st,
            StatusCode::NOT_FOUND,
            "cut endpoint POST {path} must return 404 Not Found"
        );
    }

    peer.shutdown();
    hub.shutdown();
    task.abort();
}

// ============================================================================
// 6a (G9): Stage-Before-Unpack Transfer Attachment Gate
// ============================================================================

#[tokio::test]
async fn wave3d_6a_transfer_stage_before_unpack_blocks_quarantines_and_allows() {
    let sender_dir = TempDir::new().unwrap();
    let recv_dir = TempDir::new().unwrap();
    let src_files_dir = TempDir::new().unwrap();

    let sender = UnifiedNode::open(make_node_cfg(
        "sender@laptop",
        NodeProfile::P2p,
        &sender_dir,
    ))
    .unwrap();
    let receiver =
        UnifiedNode::open(make_node_cfg("recv@server", NodeProfile::P2p, &recv_dir)).unwrap();
    register_session_with_handle(&sender, "s-send", "dev").await;
    register_session_with_handle(&receiver, "s-recv", "ops").await;

    // Attach a SecurityGatePipeline to receiver:
    // - Default Stage 1 attachment guard (blocks `.sh` unless allowlisted)
    // - Quarantine regex matching "QUARANTINE_MARKER"
    let mut gate_cfg = SecurityGateConfig::default();
    gate_cfg
        .stage1
        .inbound_regex_denylist
        .push("QUARANTINE_MARKER".to_string());
    gate_cfg.stage1.regex_deny_action = Stage1DenyAction::Quarantine;
    let gate_db = Arc::new(Mutex::new(
        NodeDb::open(recv_dir.path().join("node.sqlite")).unwrap(),
    ));
    let gate = Arc::new(SecurityGatePipeline::new(gate_cfg, Arc::clone(&gate_db), None).unwrap());
    receiver.set_security_gate(Some(gate));

    let (_r_addr, r_task) = Arc::clone(&receiver)
        .serve("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();

    let (hp2p1, _offer) = receiver
        .create_p2p_invite(vec!["*".to_string()], vec!["*".to_string()], 3_600_000)
        .unwrap();
    sender
        .accept_p2p_invite(&hp2p1, vec!["*".to_string()])
        .await
        .unwrap();

    let received_root = recv_dir.path().join("received_transfers");
    let staging_root = received_root.join(".staging");
    let quarantine_root = received_root.join(".quarantine");

    // 1. Disallowed `.sh` attachment MUST fail closed and NEVER appear in `received_transfers/<id>` or `.staging/<id>`.
    let bad_entry = stage_tar_entry(
        src_files_dir.path(),
        "exploit.sh",
        "exploit.sh",
        b"#!/bin/sh\necho pwn\n",
    );
    let bad_err = sender
        .send_files("recv@server", Some("ops"), &[bad_entry], None)
        .await
        .expect_err("disallowed .sh attachment must be blocked");
    assert!(
        bad_err.to_string().to_ascii_lowercase().contains("blocked")
            || bad_err.to_string().contains("attachment"),
        "expected attachment block error, got: {bad_err}"
    );
    let final_entries_after_block: Vec<PathBuf> = fs::read_dir(&received_root)
        .unwrap()
        .filter_map(|e| e.ok().map(|de| de.path()))
        .filter(|p| {
            let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
            name != ".staging" && name != ".quarantine"
        })
        .collect();
    assert!(
        final_entries_after_block.is_empty(),
        "blocked transfer must never land in received_transfers/: {final_entries_after_block:?}"
    );
    let staging_leftovers: Vec<PathBuf> = fs::read_dir(&staging_root)
        .unwrap()
        .filter_map(|e| e.ok().map(|de| de.path()))
        .collect();
    assert!(
        staging_leftovers.is_empty(),
        "staging dir must be cleaned up on block: {staging_leftovers:?}"
    );
    let audit_rows = receiver
        .db()
        .local()
        .query_gate_audit(&GateAuditQuery {
            decision: Some(StoreGateDecision::Block),
            limit: Some(10),
            ..GateAuditQuery::default()
        })
        .unwrap();
    assert!(
        audit_rows.iter().any(|r| r.stage == "stage1.attachment"),
        "expected stage1.attachment block audit row"
    );

    // 2. Quarantined transfer MUST land strictly in `.quarantine/<id>` (0700), NEVER in `received_transfers/<id>`,
    //    and mailbox item MUST be Quarantined (invisible to `peek_inbox`).
    let q_entry = stage_tar_entry(
        src_files_dir.path(),
        "QUARANTINE_MARKER.txt",
        "QUARANTINE_MARKER.txt",
        b"suspicious payload",
    );
    let q_res = sender
        .send_files("recv@server", Some("ops"), &[q_entry], None)
        .await
        .expect("quarantined transfer should park cleanly");
    assert!(
        !received_root.join(&q_res.id).exists(),
        "quarantined transfer must NEVER exist in received_transfers/<id>"
    );
    assert!(
        !staging_root.join(&q_res.id).exists(),
        "staging dir must be moved away on quarantine"
    );
    let q_file = quarantine_root
        .join(&q_res.id)
        .join("QUARANTINE_MARKER.txt");
    assert!(
        q_file.exists(),
        "quarantined payload must be isolated in .quarantine/<id>"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(quarantine_root.join(&q_res.id))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700, "quarantine dir must be 0700");
    }
    let visible_inbox = receiver.db().local().peek_inbox("s-recv", 20).unwrap();
    assert!(
        visible_inbox.is_empty(),
        "quarantined transfer must be invisible to agent peek_inbox"
    );
    let quarantined_rows = receiver
        .db()
        .local()
        .list_quarantined(Some("s-recv"), 20)
        .unwrap();
    assert_eq!(quarantined_rows.len(), 1);
    assert_eq!(quarantined_rows[0].gate_state, GateState::Quarantined);

    // 3. Allowed benign transfer unpacks cleanly into `received_transfers/<id>` with accurate `diskPath`.
    let ok_entry = stage_tar_entry(
        src_files_dir.path(),
        "report.txt",
        "report.txt",
        b"hello verified world",
    );
    let ok_res = sender
        .send_files("recv@server", Some("ops"), &[ok_entry], None)
        .await
        .expect("benign transfer must succeed");
    let final_file = received_root.join(&ok_res.id).join("report.txt");
    assert_eq!(fs::read(&final_file).unwrap(), b"hello verified world");
    assert!(!staging_root.join(&ok_res.id).exists());
    let inbox = wait_for_mailbox_count(&receiver, "s-recv", 1).await;
    assert_eq!(inbox.len(), 1);
    let notice: Value = serde_json::from_str(&inbox[0].text).unwrap();
    assert_eq!(
        notice["files"][0]["diskPath"].as_str(),
        Some(final_file.to_string_lossy().as_ref()),
        "mailbox diskPath must point to final unpacked dir, never .staging"
    );

    // 4. Per-peer `transfer_attachment_allowlist` allowing `.sh` from `sender@laptop` succeeds!
    let mut allow_sh_cfg = SecurityGateConfig::default();
    allow_sh_cfg
        .stage1
        .transfer_attachment_allowlist
        .insert("sender@laptop".to_string(), vec![".sh".to_string()]);
    let allow_gate =
        Arc::new(SecurityGatePipeline::new(allow_sh_cfg, Arc::clone(&gate_db), None).unwrap());
    receiver.set_security_gate(Some(allow_gate));

    let sh_entry = stage_tar_entry(
        src_files_dir.path(),
        "deploy.sh",
        "deploy.sh",
        b"#!/bin/sh\necho ok\n",
    );
    let sh_res = sender
        .send_files("recv@server", Some("ops"), &[sh_entry], None)
        .await
        .expect("allowlisted .sh attachment must unpack cleanly");
    assert!(received_root.join(&sh_res.id).join("deploy.sh").exists());

    sender.shutdown();
    receiver.shutdown();
    r_task.abort();

    // 5. G9 startup sweep: stale `.staging/<id>` leftovers from a prior crash are cleaned up on open!
    let stale_dir = staging_root.join("stale-crash-leftover");
    fs::create_dir_all(&stale_dir).unwrap();
    fs::write(stale_dir.join("halfway.tmp"), b"stale").unwrap();
    let reopened =
        UnifiedNode::open(make_node_cfg("recv@server", NodeProfile::P2p, &recv_dir)).unwrap();
    assert!(
        !stale_dir.exists(),
        "G9: UnifiedNode::open must sweep stale .staging/ leftovers on startup"
    );
    reopened.shutdown();
}
