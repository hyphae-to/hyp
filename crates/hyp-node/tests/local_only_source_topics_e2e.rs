//! Multi-node E2E & McKeeman differential security tests for local-only topics
//! (Issue #25 / Blind Spot B6) and immediate local topic batch delivery (Issue #39 / B1).
//!
//! Strictly isolated (`TempDir`, `127.0.0.1:0`, `SecretBackend::File`, zero live host config
//! or Keychain mutations).

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, Method, Request, StatusCode};
use hyp_crypto::{Ed25519KeyPair, SecretBackend};
use hyp_node::adapters::webhooks::{
    EXT_SOURCE_KIND, GitHubWebhookAdapter, GitHubWebhookConfig, SOURCE_KIND_EXTERNAL_WEBHOOK,
    compute_hmac_sha256_header,
};
use hyp_node::adapters::{GitHubPublicAdapter, GitHubPublicConfig};
use hyp_node::engine::http_util::{HttpClient, full_body};
use hyp_node::engine::node::SubscribeRequest;
use hyp_node::engine::peer_link::{
    PublishEventRequest, PutSubscriptionsRequest, SubscriptionInputWire,
};
use hyp_node::engine::{NodeConfig, NodeError, NodeProfile, TopicConfig, UnifiedNode};
use hyp_node::node_file::NodeFile;
use hyp_proto::address::NodeId;
use hyp_proto::cloudevent::CloudEvent;
use hyp_proto::filter::DiagnosticCode;
use hyp_proto::scopes::ScopePreset;
use hyp_store::{DeliveryMode, TrustTier};
use serde_json::{Value, json};
use tempfile::TempDir;

fn admin_proto_jwk(key: &Ed25519KeyPair) -> hyp_proto::manifest::OkpJwk {
    serde_json::from_value(serde_json::to_value(key.to_jwk()).expect("jwk value"))
        .expect("proto okp jwk")
}

fn make_node_cfg(id: &str, profile: NodeProfile, dir: &TempDir) -> NodeConfig {
    let mut cfg = NodeConfig::new(NodeId::new(id).unwrap(), profile, dir.path());
    cfg.secret_backend = Some(SecretBackend::File);
    cfg
}

fn store_trust_tier(preset: ScopePreset) -> TrustTier {
    match preset {
        ScopePreset::GuestRo | ScopePreset::Guest => TrustTier::Guest,
        ScopePreset::Observer => TrustTier::Peer,
        ScopePreset::Member | ScopePreset::Full => TrustTier::Org,
    }
}

async fn pair_peer_with_preset(
    host: &Arc<UnifiedNode>,
    admin_key: &Ed25519KeyPair,
    peer_node: &Arc<UnifiedNode>,
    preset: ScopePreset,
) {
    let expanded = preset.expand();
    let scope_refs: Vec<&str> = expanded.iter().map(String::as_str).collect();
    let (am2, _grant) = host
        .create_admin_invite(
            admin_key,
            peer_node.node_id().as_str(),
            &scope_refs,
            store_trust_tier(preset),
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
    timeout: Duration,
) -> Vec<hyp_store::MailboxEntry> {
    let deadline = tokio::time::Instant::now() + timeout;
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
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Issue #25 (B6) + Issue #39 (B1) Multi-Node Differential Test:
///
/// Compares local-only (`exposeTopic: false`) vs explicitly exposed (`exposeTopic: true`) source
/// topics across ALL wildcard-stream presets (`member`, `observer`, `full`), an unprivileged
/// `guest` peer (oracle-resistance check), and a same-node local session:
/// - Local-only topics MUST NOT appear in `/v1/manifest` for any remote peer.
/// - Remote `PUT /v1/subscriptions` onto a local-only topic MUST fail closed with `403 Forbidden`
///   (`error == "topic_local_only"`) for `member`, `observer`, AND `full` presets (even though
///   all three hold `stream:subscribe=*`!).
/// - Unprivileged `guest` peer receives `403 not_granted` (cannot enumerate local-only topics).
/// - Remote subscription diagnostics on unknown topics NEVER leak local-only topic names.
/// - Remote `POST /v1/events` onto a local-only topic MUST fail closed with `403 topic_local_only`.
/// - Same-node local sessions subscribe cleanly (zero `unprovisioned_topic` errors) and receive
///   `coalesceSeconds: 0` events immediately via `deliver_local_topic_batches`.
/// - Explicitly exposed topics (`exposeTopic: true`) advertise in `/v1/manifest`, accept `200 OK`
///   remote subscriptions, and fan out events over live SSE carrying `hyphaesourcekind`.
/// - Restarting with `exposeTopic` toggled from `true` -> `false` prunes stale remote
///   subscriptions while preserving local session subscriptions.
#[tokio::test]
async fn local_only_topics_fail_closed_across_member_observer_full_presets_and_preserve_local() {
    let host_dir = TempDir::new().unwrap();
    let member_dir = TempDir::new().unwrap();
    let observer_dir = TempDir::new().unwrap();
    let full_dir = TempDir::new().unwrap();
    let guest_dir = TempDir::new().unwrap();
    let admin_key = Ed25519KeyPair::generate().unwrap();

    // 1. Boot host node with one local-only source topic (`private-alerts`, default `exposeTopic: false`)
    //    and one explicitly exposed source topic (`public-builds`, `exposeTopic: true`).
    let mut host_cfg = make_node_cfg("alice@laptop", NodeProfile::P2p, &host_dir);
    host_cfg.admin_jwk = Some(admin_proto_jwk(&admin_key));
    let native: NodeFile = serde_json::from_value(json!({
        "sources": [
            {"kind": "github-webhook", "topic": "local.private-alerts", "exposeTopic": false},
            {"kind": "github-webhook", "topic": "private-adapter", "exposeTopic": false},
            {"kind": "github-public", "topic": "private-poll", "exposeTopic": false},
            {"kind": "github-webhook", "topic": "public-builds"}
        ]
    }))
    .unwrap();
    host_cfg.local_only_topics.extend(
        native
            .native_local_only_topics()
            .unwrap()
            .map(str::to_owned),
    );
    host_cfg.topics.push(TopicConfig {
        topic: "private-alerts".into(),
        kind: Some("github-webhook".into()),
        description: None,
        metadata: None,
        has_provisioned_publisher: true,
    });
    host_cfg.topics.push(TopicConfig {
        topic: "public-builds".to_string(),
        kind: Some("source".to_string()),
        description: Some("Exposed CI builds source plugin".to_string()),
        metadata: None,
        has_provisioned_publisher: true,
    });

    let host = UnifiedNode::open(host_cfg).unwrap();
    let webhook_secret = "fixture-webhook-key";
    let webhook = Arc::new(GitHubWebhookAdapter::new(GitHubWebhookConfig::new(
        "private-alerts",
        "private-alerts",
        webhook_secret,
    )));
    host.attach_github_webhook(Arc::clone(&webhook))
        .await
        .unwrap();
    host.attach_github_webhook(Arc::new(GitHubWebhookAdapter::new(
        GitHubWebhookConfig::new("private-adapter", "private-adapter", webhook_secret),
    )))
    .await
    .unwrap();
    host.attach_github_public(Arc::new(
        GitHubPublicAdapter::new(GitHubPublicConfig {
            topic: "private-poll".into(),
            api_base_url: "http://127.0.0.1:9".into(),
            ..Default::default()
        })
        .unwrap(),
    ))
    .await
    .unwrap();
    let (host_addr, host_task) = Arc::clone(&host)
        .serve("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let base_url = format!("http://{host_addr}");

    // 2. Pair four real remote peer nodes with `member`, `observer`, `full`, and `guest` presets!
    let member = UnifiedNode::open(make_node_cfg(
        "peer-member@box",
        NodeProfile::Router,
        &member_dir,
    ))
    .unwrap();
    let observer = UnifiedNode::open(make_node_cfg(
        "peer-observer@box",
        NodeProfile::Local,
        &observer_dir,
    ))
    .unwrap();
    let full = UnifiedNode::open(make_node_cfg(
        "peer-full@box",
        NodeProfile::Local,
        &full_dir,
    ))
    .unwrap();
    let guest = UnifiedNode::open(make_node_cfg(
        "peer-guest@box",
        NodeProfile::Local,
        &guest_dir,
    ))
    .unwrap();

    pair_peer_with_preset(&host, &admin_key, &member, ScopePreset::Member).await;
    pair_peer_with_preset(&host, &admin_key, &observer, ScopePreset::Observer).await;
    pair_peer_with_preset(&host, &admin_key, &full, ScopePreset::Full).await;
    pair_peer_with_preset(&host, &admin_key, &guest, ScopePreset::Guest).await;

    // 3. Differential check across ALL three wildcard `stream:subscribe=*` presets!
    for (label, peer) in [
        ("member", &member),
        ("observer", &observer),
        ("full", &full),
    ] {
        let link = peer.peer_link("alice@laptop").await.expect("peer link");

        // 3a. `/v1/manifest` MUST NOT advertise local-only `private-alerts`, MUST advertise `public-builds`.
        let manifest_outcome = link.fetch_manifest(None).await.unwrap();
        let payload = match manifest_outcome {
            hyp_node::engine::ManifestFetchOutcome::Signed { manifest, .. } => {
                manifest.decode_payload().unwrap()
            }
            other => panic!("{label}: expected Signed manifest, got {other:?}"),
        };
        assert!(
            !payload.advertised.topics.iter().any(|t| matches!(
                t.topic.as_str(),
                "private-alerts" | "private-adapter" | "private-poll"
            )),
            "{label}: local-only topic 'private-alerts' MUST NOT appear in remote /v1/manifest: {:?}",
            payload.advertised.topics
        );
        assert!(
            payload
                .advertised
                .topics
                .iter()
                .any(|t| t.topic == "public-builds"),
            "{label}: exposed topic 'public-builds' MUST appear in remote /v1/manifest: {:?}",
            payload.advertised.topics
        );

        // 3b. `PUT /v1/subscriptions` on local-only `private-alerts` MUST fail closed with 403 `topic_local_only`!
        let err = link
            .put_subscriptions(&PutSubscriptionsRequest {
                subscriptions: vec![SubscriptionInputWire {
                    id: format!("snoop-{label}"),
                    topic: "private-alerts".to_string(),
                    filters: vec![],
                    coalesce_seconds: 0,
                    max_batch_age_ms: None,
                    max_wakes_per_hour: None,
                    mode: DeliveryMode::Full,
                }],
                replace_topic: None,
            })
            .await
            .expect_err(&format!(
                "{label} preset holding stream:subscribe=* MUST be blocked from local-only topic 'private-alerts'"
            ));
        match err {
            NodeError::RemoteProblem(prob) => {
                assert_eq!(prob.status, 403, "{label}: expected HTTP 403, got {prob:?}");
                assert_eq!(
                    prob.error, "topic_local_only",
                    "{label}: expected error=topic_local_only, got {prob:?}"
                );
                assert!(
                    prob.detail
                        .as_deref()
                        .unwrap_or("")
                        .contains("exposeTopic: false"),
                    "{label}: expected clear exposeTopic: false reason in detail: {prob:?}"
                );
            }
            other => panic!("{label}: expected RemoteProblem(403 topic_local_only), got {other:?}"),
        }

        // 3c. Mixed batch containing BOTH an exposed topic AND a local-only topic MUST fail
        //     closed atomically (neither subscription saved!).
        let mixed_err = link
            .put_subscriptions(&PutSubscriptionsRequest {
                subscriptions: vec![
                    SubscriptionInputWire {
                        id: format!("ok-mixed-{label}"),
                        topic: "public-builds".to_string(),
                        filters: vec![],
                        coalesce_seconds: 0,
                        max_batch_age_ms: None,
                        max_wakes_per_hour: None,
                        mode: DeliveryMode::Full,
                    },
                    SubscriptionInputWire {
                        id: format!("bad-mixed-{label}"),
                        topic: "private-alerts".to_string(),
                        filters: vec![],
                        coalesce_seconds: 0,
                        max_batch_age_ms: None,
                        max_wakes_per_hour: None,
                        mode: DeliveryMode::Full,
                    },
                ],
                replace_topic: None,
            })
            .await
            .expect_err("mixed batch with local-only topic must fail closed atomically");
        assert!(
            matches!(&mixed_err, NodeError::RemoteProblem(p) if p.status == 403 && p.error == "topic_local_only"),
            "{label}: expected 403 topic_local_only on mixed batch, got {mixed_err:?}"
        );
        let subs_after = link.list_subscriptions().await.unwrap();
        assert!(
            subs_after.subscriptions.is_empty(),
            "{label}: atomic fail-closed must persist 0 subscriptions: {:?}",
            subs_after.subscriptions
        );
    }

    // A paired router uses the same authenticated upstream subscription endpoint.
    let relay_error = member
        .subscribe_local_or_remote(SubscribeRequest {
            id: None,
            qualified_topic: "alice@laptop.private-alerts".into(),
            subscriber_session: "relay-session".into(),
            filters: vec![],
            coalesce_seconds: 0,
            mode: DeliveryMode::Full,
        })
        .await
        .expect_err("upstream pushdown from a paired router must respect local-only policy");
    assert!(
        matches!(&relay_error, NodeError::RemoteProblem(p) if p.status == 403 && p.error == "topic_local_only")
    );

    // 4. Unprivileged `guest` peer (no `stream:subscribe`) MUST receive `403 not_granted` (NOT
    //    `topic_local_only`) so unprivileged callers cannot enumerate local-only topic names.
    {
        let guest_link = guest.peer_link("alice@laptop").await.expect("peer link");
        let guest_err = guest_link
            .put_subscriptions(&PutSubscriptionsRequest {
                subscriptions: vec![SubscriptionInputWire {
                    id: "probe-guest".to_string(),
                    topic: "private-alerts".to_string(),
                    filters: vec![],
                    coalesce_seconds: 0,
                    max_batch_age_ms: None,
                    max_wakes_per_hour: None,
                    mode: DeliveryMode::Full,
                }],
                replace_topic: None,
            })
            .await
            .expect_err("guest without stream:subscribe must be denied");
        match guest_err {
            NodeError::RemoteProblem(prob) => {
                assert_eq!(prob.status, 403);
                assert_eq!(
                    prob.error, "not_granted",
                    "unprivileged peer must see not_granted rather than topic_local_only oracle: {prob:?}"
                );
            }
            other => panic!("expected RemoteProblem(403 not_granted), got {other:?}"),
        }
    }

    // 5. Subscription diagnostics for an unknown topic MUST NOT leak `"private-alerts"` in `(available: ...)`.
    {
        let obs_link = observer.peer_link("alice@laptop").await.expect("peer link");
        let resp = obs_link
            .put_subscriptions(&PutSubscriptionsRequest {
                subscriptions: vec![SubscriptionInputWire {
                    id: "probe-unknown".to_string(),
                    topic: "nonexistent-topic".to_string(),
                    filters: vec![],
                    coalesce_seconds: 0,
                    max_batch_age_ms: None,
                    max_wakes_per_hour: None,
                    mode: DeliveryMode::Full,
                }],
                replace_topic: None,
            })
            .await
            .unwrap();
        for diag in &resp.diagnostics {
            assert!(
                !diag.message.contains("private-alerts"),
                "remote subscription diagnostic leaked local-only topic 'private-alerts': {diag:?}"
            );
        }
        let _ = obs_link.delete_subscription("probe-unknown").await;
    }

    // 6. Remote `POST /v1/events` onto local-only `private-alerts` by `full` peer MUST fail closed with 403!
    {
        let full_link = full.peer_link("alice@laptop").await.expect("peer link");
        let spoof_ev = CloudEvent::new(
            "spoof-1",
            "spoof://remote",
            "com.evil.spoof",
            json!({ "text": "forged private-alerts event" }),
        );
        let pub_err = full_link
            .publish_event(&PublishEventRequest {
                topic: "private-alerts".to_string(),
                event: spoof_ev,
            })
            .await
            .expect_err("remote peer MUST NOT publish onto local-only topic 'private-alerts'");
        assert!(
            matches!(&pub_err, NodeError::RemoteProblem(p) if p.status == 403 && p.error == "topic_local_only"),
            "expected 403 topic_local_only on remote POST /v1/events, got {pub_err:?}"
        );
    }

    // 7. Exposed topic (`public-builds`): `observer` subscribes via `subscribe_local_or_remote`
    //    (which issues `PUT /v1/subscriptions` -> 200 OK!) and receives events over live SSE!
    observer.register_session("obs-sess", "{}").unwrap();
    let exposed_sub = observer
        .subscribe_local_or_remote(SubscribeRequest {
            id: Some("sub-public-builds".to_string()),
            qualified_topic: "alice@laptop.public-builds".to_string(),
            subscriber_session: "obs-sess".to_string(),
            filters: vec![],
            coalesce_seconds: 0,
            mode: DeliveryMode::Full,
        })
        .await
        .expect("observer should subscribe to exposed topic 'public-builds'");
    assert_eq!(exposed_sub.topic, "public-builds");

    observer.register_session("coalesced", "{}").unwrap();
    observer
        .subscribe_local_or_remote(SubscribeRequest {
            id: Some("sub-coalesced".into()),
            qualified_topic: "alice@laptop.public-builds".into(),
            subscriber_session: "coalesced".into(),
            filters: vec![],
            coalesce_seconds: 1,
            mode: DeliveryMode::Full,
        })
        .await
        .unwrap();

    // 8. Same-node local session subscribes to `local.private-alerts` with `coalesceSeconds: 0`!
    //    Must succeed cleanly with zero `UnprovisionedTopic` diagnostics!
    host.register_session("local-owner", "{}").unwrap();
    let local_sub = host
        .subscribe_local_or_remote(SubscribeRequest {
            id: Some("sub-local-private-alerts".to_string()),
            qualified_topic: "local.private-alerts".to_string(),
            subscriber_session: "local-owner".to_string(),
            filters: vec![],
            coalesce_seconds: 0,
            mode: DeliveryMode::Full,
        })
        .await
        .expect("same-node local session must subscribe cleanly to local-only topic");
    assert!(
        !local_sub
            .diagnostics
            .iter()
            .any(|d| d.code == DiagnosticCode::UnprovisionedTopic),
        "local session should see provisioned publisher for local-only topic: {:?}",
        local_sub.diagnostics
    );

    // 9. Publish events onto BOTH `local.private-alerts` (local-only) and `local.public-builds` (exposed),
    //    and flush immediately via public `deliver_local_topic_batches` (testing both bare and
    //    `local.`-prefixed topic forms!).
    let payload = br#"{"action":"opened","repository":{"full_name":"demo/project"},"issue":{"number":1,"title":"Private local notice"},"sender":{"login":"demo"}}"#;
    let mut headers = HeaderMap::new();
    headers.insert("x-github-event", "issues".parse().unwrap());
    headers.insert(
        "x-hub-signature-256",
        compute_hmac_sha256_header(webhook_secret.as_bytes(), payload)
            .parse()
            .unwrap(),
    );
    webhook.ingest_webhook(&headers, payload).await.unwrap();

    let mut build_ev = CloudEvent::new(
        "build-pub-1",
        "source:ci-exposed",
        "to.hyphae.build.passed",
        json!({ "commit": "abc1234", "status": "green" }),
    );
    build_ev.set_extension(EXT_SOURCE_KIND, SOURCE_KIND_EXTERNAL_WEBHOOK);
    let build_ingest = host
        .publish_event("local.public-builds", build_ev)
        .await
        .unwrap();
    assert_eq!(
        build_ingest.matched, 1,
        "remote observer should match public-builds"
    );

    // Local session immediately received `Private local notice` with `hyphaesourcekind=external-webhook`!
    let local_items = wait_for_mailbox_count(&host, "local-owner", 1, Duration::from_secs(2)).await;
    assert_eq!(local_items.len(), 1);
    let local_payload: Value = serde_json::from_str(&local_items[0].text).unwrap();
    assert_eq!(
        local_payload["events"][0]["data"]["title"],
        "Private local notice"
    );
    assert_eq!(
        local_payload["events"][0]["hyphaesourcekind"],
        "external-webhook"
    );

    // Remote `observer` receives ONLY `public-builds` (and ZERO `private-alerts` events)!
    let obs_items = wait_for_mailbox_count(&observer, "obs-sess", 1, Duration::from_secs(5)).await;
    assert_eq!(obs_items.len(), 1);
    assert_eq!(obs_items[0].origin_node, "alice@laptop");
    assert_eq!(obs_items[0].source, "alice@laptop.public-builds");
    let obs_payload: Value = serde_json::from_str(&obs_items[0].text).unwrap();
    assert_eq!(obs_payload["topic"], "public-builds");
    assert_eq!(
        obs_payload["events"][0]["hyphaesourcekind"],
        "external-webhook"
    );
    assert!(
        !obs_items[0].text.contains("Private local notice"),
        "remote peer must NEVER receive private local-only topic content"
    );

    // The same remote event also reaches the coalesced session on its own deadline.
    // No second upstream event or manual flush should be necessary.
    let coalesced = wait_for_mailbox_count(&observer, "coalesced", 1, Duration::from_secs(5)).await;
    assert_eq!(
        coalesced.len(),
        1,
        "coalesced remote batch missed its deadline"
    );
    let payload: Value = serde_json::from_str(&coalesced[0].text).unwrap();
    assert_eq!(coalesced[0].origin_node, obs_items[0].origin_node);
    assert_eq!(coalesced[0].source, obs_items[0].source);
    assert_eq!(payload["events"], obs_payload["events"]);

    // Confirm raw HTTP `POST /v1/subscriptions` also never bypasses anything (returns 400).
    let client = HttpClient::new().unwrap();
    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("{base_url}/v1/subscriptions"))
        .body(full_body(Bytes::from_static(b"{}")))
        .unwrap();
    let resp = client.request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // 10. Restart regression test (`exposeTopic: true` -> `false`):
    //     `observer` currently has an active subscription to `public-builds` in `host`'s SQLite.
    //     Now shut down `host` and reopen with `public-builds` added to `local_only_topics`!
    //     Stale remote subscriptions on `public-builds` MUST be pruned on startup while same-node
    //     local subscriptions remain intact!
    let observer_link = observer.peer_link("alice@laptop").await.unwrap();
    observer_link
        .put_subscriptions(&PutSubscriptionsRequest {
            subscriptions: vec![SubscriptionInputWire {
                id: "legacy-prefixed".into(),
                topic: "local.public-builds".into(),
                filters: vec![],
                coalesce_seconds: 0,
                max_batch_age_ms: None,
                max_wakes_per_hour: None,
                mode: DeliveryMode::Full,
            }],
            replace_topic: None,
        })
        .await
        .unwrap();

    host.shutdown();
    host_task.abort();
    let _ = host_task.await;
    // Keep an undelivered batch in SQLite to exercise removal of queued data at restart.
    let prior_remote_id = host
        .db()
        .events()
        .list_subscriptions(Some("peer-observer@box"))
        .unwrap()
        .into_iter()
        .find(|s| s.topic == "public-builds")
        .unwrap()
        .id;
    host.publish_event(
        "local.public-builds",
        CloudEvent::new(
            "pending-before-restart",
            "source:ci",
            "com.demo.build",
            json!({"status":"queued"}),
        ),
    )
    .await
    .unwrap();
    assert!(
        host.db()
            .events()
            .list_batches(&prior_remote_id)
            .unwrap()
            .iter()
            .any(|batch| batch.state == hyp_store::BatchState::Pending)
    );

    let mut host_cfg_locked = make_node_cfg("alice@laptop", NodeProfile::P2p, &host_dir);
    host_cfg_locked.admin_jwk = Some(admin_proto_jwk(&admin_key));
    host_cfg_locked.topics.push(TopicConfig {
        topic: "private-alerts".to_string(),
        kind: Some("source".to_string()),
        description: None,
        metadata: None,
        has_provisioned_publisher: true,
    });
    host_cfg_locked.topics.push(TopicConfig {
        topic: "public-builds".to_string(),
        kind: Some("source".to_string()),
        description: None,
        metadata: None,
        has_provisioned_publisher: true,
    });
    let locked: NodeFile = serde_json::from_value(json!({
        "sources": [
            {"kind": "github-webhook", "topic": "private-alerts", "exposeTopic": false},
            {"kind": "github-webhook", "topic": "local.public-builds", "exposeTopic": false}
        ]
    }))
    .unwrap();
    host_cfg_locked.local_only_topics.extend(
        locked
            .native_local_only_topics()
            .unwrap()
            .map(str::to_owned),
    );

    let host_reopened = UnifiedNode::open(host_cfg_locked).unwrap();
    {
        let db = host_reopened.db();
        let all_subs = db.events().list_subscriptions(None).unwrap();
        assert!(
            db.events()
                .list_batches(&prior_remote_id)
                .unwrap()
                .is_empty()
        );
        assert!(
            all_subs
                .iter()
                .any(|s| s.subscriber == "local-owner" && s.topic == "private-alerts"),
            "same-node local session subscription must survive restart: {all_subs:?}"
        );
        assert!(
            !all_subs.iter().any(|s| s.subscriber == "peer-observer@box"
                && matches!(s.topic.as_str(), "public-builds" | "local.public-builds")),
            "stale remote peer subscription on newly local-only topic MUST be pruned on open: {all_subs:?}"
        );
    }

    let (reopened_addr, reopened_task) = Arc::clone(&host_reopened)
        .serve("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let observer_link = observer
        .connect_peer("alice@laptop", &format!("http://{reopened_addr}"))
        .await
        .unwrap();
    let manifest = observer_link.fetch_manifest(None).await.unwrap();
    let hyp_node::engine::ManifestFetchOutcome::Signed { manifest, .. } = manifest else {
        panic!("expected signed manifest after restart");
    };
    assert!(
        !manifest
            .decode_payload()
            .unwrap()
            .advertised
            .topics
            .iter()
            .any(|t| t.topic == "public-builds")
    );
    assert!(
        observer_link
            .list_subscriptions()
            .await
            .unwrap()
            .subscriptions
            .is_empty()
    );

    // Publishing to `public-builds` now matches 0 remote subscribers!
    let build_ev2 = CloudEvent::new(
        "build-priv-2",
        "source:ci-exposed",
        "to.hyphae.build.secret",
        json!({ "secret": "AFTER_LOCKDOWN_NEVER_LEAK" }),
    );
    let after_res = host_reopened
        .publish_event("local.public-builds", build_ev2)
        .await
        .unwrap();
    assert_eq!(
        after_res.matched, 0,
        "locked-down topic must match 0 remote peers after restart"
    );

    member.shutdown();
    observer.shutdown();
    full.shutdown();
    guest.shutdown();
    host_reopened.shutdown();
    reopened_task.abort();
}

#[tokio::test]
async fn scheduler_resumes_remote_backlog_after_hold_without_exceeding_wake_cap() {
    use hyp_store::{AckOutcome, SubscriptionSpec, now_ms};

    let dir = TempDir::new().unwrap();
    let node = UnifiedNode::open(make_node_cfg("receiver@box", NodeProfile::P2p, &dir)).unwrap();
    let mut wakes = node.subscribe_local_inbox();
    let origin = "source@box";
    {
        // Seed the state of a receiver restarting with remote events already committed.
        let db = node.db();
        let events = db.events();
        let now = now_ms();
        for (subscriber, cap) in [("held", 100), ("capped", 1)] {
            db.local().register_session(subscriber, "{}", now).unwrap();
            events
                .upsert_subscription(
                    &SubscriptionSpec {
                        id: subscriber.into(),
                        subscriber: subscriber.into(),
                        topic: "builds".into(),
                        origin_node: origin.into(),
                        filters: vec![],
                        coalesce_seconds: 0,
                        max_batch_age_ms: None,
                        max_wakes_per_hour: Some(cap),
                        mode: DeliveryMode::Full,
                    },
                    now,
                )
                .unwrap();
        }
        for index in 0..65 {
            let event = hyp_store::CloudEvent::new(
                index.to_string(),
                "builds",
                "com.example.build",
                json!({}),
            );
            events
                .ingest(origin, "builds", origin, &event, now)
                .unwrap();
        }
        let oldest = events.claim_due_batches("held", now).unwrap().remove(0);
        events
            .ack_batch(
                "held",
                &oldest.id,
                &AckOutcome::Hold {
                    reason: "local_inbox_full".into(),
                    retry_after_ms: Some(200),
                },
                now_ms(),
            )
            .unwrap();
    }

    tokio::time::timeout(Duration::from_secs(5), async {
        while node.db().local().pending_count("held").unwrap() < 65 {
            wakes.recv().await.unwrap();
        }
    })
    .await
    .expect("hold expiry must drain past the 64-round pass without a new event");
    assert_eq!(node.db().local().pending_count("capped").unwrap(), 1);
    node.shutdown();
}
