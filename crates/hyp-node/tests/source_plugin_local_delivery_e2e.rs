//! Regression: events published by an external subprocess `source` plugin must reach sessions on
//! the SAME node, not only paired remote subscribers.
//!
//! `UnifiedNode::publish_event` stores the event and opens a batch for every matching
//! subscription, but it does not move those batches into local session mailboxes. Compiled-in
//! adapters get that flush from the node's own adapter host. The host that publishes for
//! subprocess plugins did not, so a local thread subscribed to `local.<plugin>` saw its batch stay
//! `pending` forever (found live with the AgentMail plugin).
//! `hyp_node::adapters::deliver_source_topic_to_local_sessions` is the flush that host now calls.

use std::collections::BTreeMap;
use std::sync::Arc;

use hyp_crypto::SecretBackend;
use hyp_node::adapters::deliver_source_topic_to_local_sessions;
use hyp_node::engine::{NodeConfig, SubscribeRequest, TopicConfig, UnifiedNode};
use hyp_proto::address::NodeId;
use hyp_proto::cloudevent::CloudEvent;
use hyp_proto::filter::Filter;
use hyp_store::{DeliveryMode, now_ms};
use serde_json::json;
use tempfile::TempDir;

fn open_node_with_source_topic(dir: &TempDir, topic: &str) -> Arc<UnifiedNode> {
    let mut cfg = NodeConfig::local(NodeId::new("src@box").unwrap(), dir.path());
    cfg.secret_backend = Some(SecretBackend::File);
    cfg.topics.push(TopicConfig {
        topic: topic.to_string(),
        kind: Some("source".to_string()),
        description: Some("External source plugin 'agentmail'".to_string()),
        metadata: None,
        has_provisioned_publisher: true,
    });
    UnifiedNode::open(cfg).unwrap()
}

fn mail_event(id: &str, subject: &str) -> CloudEvent {
    serde_json::from_value(json!({
        "specversion": "1.0",
        "id": id,
        "source": "agentmail/billing@agentmail.to",
        "type": "to.agentmail.message.received",
        "datacontenttype": "application/json",
        "data": { "subject": subject, "from": "grace@example.com" }
    }))
    .unwrap()
}

async fn subscribe(node: &UnifiedNode, session: &str, id: &str, subject_prefix: &str) {
    {
        let db = node.db();
        db.local()
            .register_session(session, "{}", now_ms())
            .unwrap();
    }
    node.subscribe_local_or_remote(SubscribeRequest {
        id: Some(id.to_string()),
        subscriber_session: session.to_string(),
        qualified_topic: "local.agentmail".to_string(),
        filters: vec![Filter::Prefix(BTreeMap::from([(
            "data.subject".to_string(),
            subject_prefix.to_string(),
        )]))],
        coalesce_seconds: 0,
        mode: DeliveryMode::Full,
    })
    .await
    .unwrap();
}

fn mailbox_len(node: &UnifiedNode, session: &str) -> usize {
    let db = node.db();
    db.local().peek_inbox_ex(session, 20).unwrap().len()
}

#[tokio::test]
async fn source_plugin_event_reaches_matching_local_sessions_only_after_the_flush() {
    let tmp = TempDir::new().unwrap();
    let node = open_node_with_source_topic(&tmp, "agentmail");
    subscribe(&node, "claude:invoices", "sub-invoices", "Invoice").await;
    subscribe(&node, "claude:alerts", "sub-alerts", "ALERT").await;

    let res = node
        .publish_event(
            "local.agentmail",
            mail_event("evt-1", "Invoice #1042 overdue"),
        )
        .await
        .unwrap();
    assert_eq!(res.matched, 1, "exactly one subscription's filter matches");
    assert!(!res.deduplicated);

    // Publishing alone stores and batches: nothing is in any local mailbox yet. This is the state
    // a subprocess source plugin used to leave its local subscribers in.
    assert_eq!(mailbox_len(&node, "claude:invoices"), 0);

    let reached = deliver_source_topic_to_local_sessions(&node, "agentmail").unwrap();
    assert_eq!(
        reached, 1,
        "the flush must reach the one matching local session"
    );
    assert_eq!(mailbox_len(&node, "claude:invoices"), 1);
    assert_eq!(
        mailbox_len(&node, "claude:alerts"),
        0,
        "a session whose filter did not match must receive nothing"
    );

    // Flushing again is a no-op, and a redelivered event (same source + id) is deduplicated by the
    // node, so it never produces a second mailbox item.
    assert_eq!(
        deliver_source_topic_to_local_sessions(&node, "agentmail").unwrap(),
        0
    );
    let again = node
        .publish_event(
            "local.agentmail",
            mail_event("evt-1", "Invoice #1042 overdue"),
        )
        .await
        .unwrap();
    assert!(again.deduplicated);
    assert_eq!(
        deliver_source_topic_to_local_sessions(&node, "agentmail").unwrap(),
        0
    );
    assert_eq!(mailbox_len(&node, "claude:invoices"), 1);

    // Backlog: three more matching events are stored before any flush runs (the state a node is in
    // after a failed flush or a restart). One call must drain all of them, not one per call, or the
    // newest mail would always lag one event behind.
    for n in 2..=4 {
        let res = node
            .publish_event(
                "local.agentmail",
                mail_event(&format!("evt-{n}"), &format!("Invoice #{n} overdue")),
            )
            .await
            .unwrap();
        assert_eq!(res.matched, 1);
    }
    assert_eq!(mailbox_len(&node, "claude:invoices"), 1);
    // The return value counts sessions reached per pass, so it is at least 1 here; the property that
    // matters is that every backlogged event is in the mailbox after a single call.
    assert!(deliver_source_topic_to_local_sessions(&node, "agentmail").unwrap() >= 1);
    assert_eq!(mailbox_len(&node, "claude:invoices"), 4);
    assert_eq!(mailbox_len(&node, "claude:alerts"), 0);

    // A topic nobody on this node subscribed to flushes nothing and does not error.
    assert_eq!(
        deliver_source_topic_to_local_sessions(&node, "sentry").unwrap(),
        0
    );
}

#[tokio::test]
async fn compiled_in_source_drains_backlog_without_skipping_holds_or_caps() {
    use http::HeaderMap;
    use hyp_node::adapters::{
        GitHubWebhookAdapter, GitHubWebhookConfig, WebhookIngestOutcome, compute_hmac_sha256_header,
    };
    use hyp_store::{AckOutcome, BatchState, SubscriptionSpec};

    let tmp = TempDir::new().unwrap();
    let topic = "ci";
    let node = open_node_with_source_topic(&tmp, topic);
    let secret = "test-secret";
    let config = GitHubWebhookConfig::new(topic, topic, secret);
    let adapter = Arc::new(GitHubWebhookAdapter::new(config));
    node.attach_github_webhook(Arc::clone(&adapter))
        .await
        .unwrap();

    for (session, cap) in [("free", 90), ("held", 90), ("capped", 2)] {
        let db = node.db();
        db.local()
            .register_session(session, "{}", now_ms())
            .unwrap();
        db.events()
            .upsert_subscription(
                &SubscriptionSpec {
                    id: session.to_string(),
                    origin_node: node.node_id().to_string(),
                    topic: topic.to_string(),
                    subscriber: session.to_string(),
                    filters: vec![],
                    coalesce_seconds: 0,
                    max_batch_age_ms: None,
                    max_wakes_per_hour: Some(cap),
                    mode: DeliveryMode::Full,
                },
                now_ms(),
            )
            .unwrap();
    }

    // Let the startup scheduler sweep an empty inbox, then seed a backlog without
    // invoking the native adapter. 70 batches exceed the node's 64-round pass.
    tokio::task::yield_now().await;
    for n in 0..70 {
        let result = node
            .publish_event("local.ci", mail_event(&format!("stored-{n}"), "Backlog"))
            .await
            .unwrap();
        assert_eq!(result.matched, 3);
    }
    {
        let db = node.db();
        let held = &db.events().list_batches("held").unwrap()[0];
        assert!(
            db.events()
                .ack_batch(
                    "held",
                    &held.id,
                    &AckOutcome::Hold {
                        reason: "test_hold".into(),
                        retry_after_ms: Some(60_000),
                    },
                    now_ms(),
                )
                .unwrap()
        );
    }

    let body = br#"{"action":"opened","repository":{"full_name":"acme/ci"},"issue":{"number":71,"title":"final-publish"},"sender":{"login":"ci"}}"#;
    let mut headers = HeaderMap::new();
    headers.insert("x-github-event", "issues".parse().unwrap());
    headers.insert(
        "x-hub-signature-256",
        compute_hmac_sha256_header(secret.as_bytes(), body)
            .parse()
            .unwrap(),
    );
    let result = adapter.ingest_webhook(&headers, body).await.unwrap();
    let WebhookIngestOutcome::Published { outcome, .. } = result else {
        panic!("webhook did not publish: {result:?}");
    };
    assert_eq!(outcome.matched, 3);
    let db = node.db();
    let received = db.local().peek_inbox_ex("free", 100).unwrap();
    assert_eq!(received.len(), 71);
    assert!(
        received
            .iter()
            .any(|entry| entry.entry.text.contains("final-publish"))
    );
    for (session, delivered_count) in [("held", 0), ("capped", 2)] {
        assert_eq!(
            db.local().peek_inbox_ex(session, 100).unwrap().len(),
            delivered_count
        );
        let batches = db.events().list_batches(session).unwrap();
        assert_eq!(
            batches
                .iter()
                .filter(|batch| batch.state == BatchState::Pending)
                .count(),
            71 - delivered_count
        );
    }
}
