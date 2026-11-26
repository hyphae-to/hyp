//! Multi-node E2E & McKeeman differential security tests for local-only topics
//! (Issue #25 / Blind Spot B6) and immediate local topic batch delivery (Issue #39 / B1).
//!
//! Strictly isolated (`TempDir`, `127.0.0.1:0`, `SecretBackend::File`, zero live host config
//! or Keychain mutations).

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{Method, Request, StatusCode};
use hyp_crypto::{Ed25519KeyPair, SecretBackend};
use hyp_node::adapters::webhooks::{EXT_SOURCE_KIND, SOURCE_KIND_EXTERNAL_WEBHOOK};
use hyp_node::engine::http_util::{HttpClient, full_body};
use hyp_node::engine::node::SubscribeRequest;
use hyp_node::engine::peer_link::{
    PublishEventRequest, PutSubscriptionsRequest, SubscriptionInputWire,
};
use hyp_node::engine::{NodeConfig, NodeError, NodeProfile, TopicConfig, UnifiedNode};
use hyp_proto::address::NodeId;
use hyp_proto::cloudevent::CloudEvent;
use hyp_proto::filter::DiagnosticCode;
use hyp_proto::scopes::ScopePreset;
use hyp_store::{DeliveryMode, MailboxPutOptions, TrustTier, now_ms};
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

    // 1. Boot host node with one local-only source topic (`gmail`, default `exposeTopic: false`)
    //    and one explicitly exposed source topic (`public-builds`, `exposeTopic: true`).
    let mut host_cfg = make_node_cfg("alice@laptop", NodeProfile::P2p, &host_dir);
    host_cfg.admin_jwk = Some(admin_proto_jwk(&admin_key));
    host_cfg.topics.push(TopicConfig {
        topic: "gmail".to_string(),
        kind: Some("source".to_string()),
        description: Some("Personal Gmail source plugin".to_string()),
        metadata: None,
        has_provisioned_publisher: true,
    });
    host_cfg.local_only_topics.insert("gmail".to_string());
    host_cfg.topics.push(TopicConfig {
        topic: "public-builds".to_string(),
        kind: Some("source".to_string()),
        description: Some("Exposed CI builds source plugin".to_string()),
        metadata: None,
        has_provisioned_publisher: true,
    });

    let host = UnifiedNode::open(host_cfg).unwrap();
    let (host_addr, host_task) = Arc::clone(&host)
        .serve("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let base_url = format!("http://{host_addr}");

    // 2. Pair four real remote peer nodes with `member`, `observer`, `full`, and `guest` presets!
    let member = UnifiedNode::open(make_node_cfg(
        "peer-member@box",
        NodeProfile::Local,
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

        // 3a. `/v1/manifest` MUST NOT advertise local-only `gmail`, MUST advertise `public-builds`.
        let manifest_outcome = link.fetch_manifest(None).await.unwrap();
        let payload = match manifest_outcome {
            hyp_node::engine::ManifestFetchOutcome::Signed { manifest, .. } => {
                manifest.decode_payload().unwrap()
            }
            other => panic!("{label}: expected Signed manifest, got {other:?}"),
        };
        assert!(
            !payload.advertised.topics.iter().any(|t| t.topic == "gmail"),
            "{label}: local-only topic 'gmail' MUST NOT appear in remote /v1/manifest: {:?}",
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

        // 3b. `PUT /v1/subscriptions` on local-only `gmail` MUST fail closed with 403 `topic_local_only`!
        let err = link
            .put_subscriptions(&PutSubscriptionsRequest {
                subscriptions: vec![SubscriptionInputWire {
                    id: format!("snoop-{label}"),
                    topic: "gmail".to_string(),
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
                "{label} preset holding stream:subscribe=* MUST be blocked from local-only topic 'gmail'"
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
                        topic: "gmail".to_string(),
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

    // 4. Unprivileged `guest` peer (no `stream:subscribe`) MUST receive `403 not_granted` (NOT
    //    `topic_local_only`) so unprivileged callers cannot enumerate local-only topic names.
    {
        let guest_link = guest.peer_link("alice@laptop").await.expect("peer link");
        let guest_err = guest_link
            .put_subscriptions(&PutSubscriptionsRequest {
                subscriptions: vec![SubscriptionInputWire {
                    id: "probe-guest".to_string(),
                    topic: "gmail".to_string(),
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

    // 5. Subscription diagnostics for an unknown topic MUST NOT leak `"gmail"` in `(available: ...)`.
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
                !diag.message.contains("gmail"),
                "remote subscription diagnostic leaked local-only topic 'gmail': {diag:?}"
            );
        }
        let _ = obs_link.delete_subscription("probe-unknown").await;
    }

    // 6. Remote `POST /v1/events` onto local-only `gmail` by `full` peer MUST fail closed with 403!
    {
        let full_link = full.peer_link("alice@laptop").await.expect("peer link");
        let spoof_ev = CloudEvent::new(
            "spoof-1",
            "spoof://remote",
            "com.evil.spoof",
            json!({ "text": "forged gmail event" }),
        );
        let pub_err = full_link
            .publish_event(&PublishEventRequest {
                topic: "gmail".to_string(),
                event: spoof_ev,
            })
            .await
            .expect_err("remote peer MUST NOT publish onto local-only topic 'gmail'");
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

    // 8. Same-node local session subscribes to `local.gmail` with `coalesceSeconds: 0`!
    //    Must succeed cleanly with zero `UnprovisionedTopic` diagnostics!
    host.register_session("local-owner", "{}").unwrap();
    let local_sub = host
        .subscribe_local_or_remote(SubscribeRequest {
            id: Some("sub-local-gmail".to_string()),
            qualified_topic: "local.gmail".to_string(),
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

    // 9. Publish events onto BOTH `local.gmail` (local-only) and `local.public-builds` (exposed),
    //    and flush immediately via public `deliver_local_topic_batches` (testing both bare and
    //    `local.`-prefixed topic forms!).
    let mut gmail_ev = CloudEvent::new(
        "gmail-priv-1",
        "source:mailfeed",
        "to.hyphae.mail.received",
        json!({ "subject": "PRIVATE_OTP_991122" }),
    );
    gmail_ev.set_extension(EXT_SOURCE_KIND, SOURCE_KIND_EXTERNAL_WEBHOOK);
    let gmail_ingest = host.publish_event("local.gmail", gmail_ev).await.unwrap();
    assert_eq!(
        gmail_ingest.matched, 1,
        "only local session should match gmail"
    );
    let woken = host
        .deliver_local_topic_batches(
            "local.gmail",
            &MailboxPutOptions::default(),
            None,
            false,
            now_ms(),
        )
        .unwrap();
    assert_eq!(woken, 1, "local session should be woken immediately");

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

    // Local session immediately received `PRIVATE_OTP_991122` with `hyphaesourcekind=external-webhook`!
    let local_items = wait_for_mailbox_count(&host, "local-owner", 1, Duration::from_secs(2)).await;
    assert_eq!(local_items.len(), 1);
    let local_payload: Value = serde_json::from_str(&local_items[0].text).unwrap();
    assert_eq!(
        local_payload["events"][0]["data"]["subject"],
        "PRIVATE_OTP_991122"
    );
    assert_eq!(
        local_payload["events"][0]["hyphaesourcekind"],
        "external-webhook"
    );

    // Remote `observer` receives ONLY `public-builds` (and ZERO `gmail` events)!
    let obs_items = wait_for_mailbox_count(&observer, "obs-sess", 1, Duration::from_secs(5)).await;
    assert_eq!(obs_items.len(), 1);
    let obs_payload: Value = serde_json::from_str(&obs_items[0].text).unwrap();
    assert_eq!(obs_payload["topic"], "public-builds");
    assert_eq!(
        obs_payload["events"][0]["hyphaesourcekind"],
        "external-webhook"
    );
    assert!(
        !obs_items[0].text.contains("PRIVATE_OTP_991122"),
        "remote peer must NEVER receive private local-only topic content"
    );

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
    host.shutdown();
    host_task.abort();

    let mut host_cfg_locked = make_node_cfg("alice@laptop", NodeProfile::P2p, &host_dir);
    host_cfg_locked.admin_jwk = Some(admin_proto_jwk(&admin_key));
    host_cfg_locked.topics.push(TopicConfig {
        topic: "gmail".to_string(),
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
    host_cfg_locked
        .local_only_topics
        .insert("gmail".to_string());
    host_cfg_locked
        .local_only_topics
        .insert("public-builds".to_string());

    let host_reopened = UnifiedNode::open(host_cfg_locked).unwrap();
    {
        let db = host_reopened.db();
        let all_subs = db.events().list_subscriptions(None).unwrap();
        assert!(
            all_subs
                .iter()
                .any(|s| s.subscriber == "local-owner" && s.topic == "gmail"),
            "same-node local session subscription must survive restart: {all_subs:?}"
        );
        assert!(
            !all_subs
                .iter()
                .any(|s| s.subscriber == "peer-observer@box" && s.topic == "public-builds"),
            "stale remote peer subscription on newly local-only topic MUST be pruned on open: {all_subs:?}"
        );
    }

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
}
