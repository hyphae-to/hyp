//! Comprehensive unit and edge-case tests for every `hyp-store` subsystem.

use std::collections::{BTreeMap, HashSet};
use std::fs;

use hyp_store::{
    AckOutcome, BridgeLink, CURRENT_SCHEMA_VERSION, ChannelEpochInput, CloudEvent, DeliveryMode,
    DirectoryCheckpointInput, EnqueueMessage, EventLimits, Filter, GateAuditInput, GateAuditQuery,
    GateDecision, GateDirection, GateState, GrantDirection, GrantInput, KeyStatus, KeyUse,
    KvDeleteInput, KvEpochInput, KvSetInput, MailboxInsert, MailboxKind, MailboxPutResult,
    ManifestCacheUpdate, MessageLimits, MessageState, MuteRuleInput, NodeDb, PeerInput,
    PeerKeyInput, PeerProfile, PeerStatus, PluginTargetHandoff, PostChannelInput, RevocationInput,
    StoreConfig, StoreError, SubscriptionSpec, TransferLimits, TransferState, TransferSubmit,
    TrustTier, UpstreamPushdownInput, WriteModel, check_filters, epoch_ms_to_rfc3339,
    matches_filters, sha256_hex,
};
use serde_json::json;
use tempfile::TempDir;

const HOUR_MS: i64 = 60 * 60 * 1000;
const DAY_MS: i64 = 24 * HOUR_MS;

fn sample_event(id: &str, source: &str, event_type: &str, repo: &str) -> CloudEvent {
    CloudEvent::new(
        id,
        source,
        event_type,
        json!({ "action": "opened", "number": 42 }),
    )
    .with_subject("pull/42")
    .with_extension("repo", repo)
    .with_time(epoch_ms_to_rfc3339(1_700_000_000_000))
}

#[test]
fn db_open_pragmas_permissions_and_all_tables() {
    let dir = TempDir::new().unwrap();
    let nested = dir.path().join("hyphae-state");
    let db_path = nested.join("node.sqlite");

    let db = NodeDb::open(&db_path).unwrap();
    assert_eq!(db.schema_version().unwrap(), CURRENT_SCHEMA_VERSION);
    assert_eq!(db.journal_mode().unwrap().to_lowercase(), "wal");

    let fk: i64 = db
        .connection()
        .query_row("PRAGMA foreign_keys", [], |r| r.get(0))
        .unwrap();
    assert_eq!(fk, 1);

    let sync_mode: i64 = db
        .connection()
        .query_row("PRAGMA synchronous", [], |r| r.get(0))
        .unwrap();
    assert_eq!(sync_mode, 1); // NORMAL

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let dir_mode = fs::metadata(&nested).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700, "parent state dir must be 0700");
        let transfers_mode = fs::metadata(db.transfers_dir())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(transfers_mode, 0o700, "transfers dir must be 0700");
        let file_mode = fs::metadata(&db_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(file_mode, 0o600, "node.sqlite must be 0600");
    }

    // Verify every single unified v2 table exists.
    let tables: HashSet<String> = {
        let mut stmt = db
            .connection()
            .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
            .unwrap();
        let res = stmt
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .collect::<Result<HashSet<String>, _>>()
            .unwrap();
        drop(stmt);
        res
    };
    for expected in [
        "schema_version",
        "handles",
        "messages",
        "channel_members",
        "channel_epochs",
        "publishers",
        "publisher_grants",
        "events",
        "subscriptions",
        "batches",
        "batch_events",
        "upstream_pushdowns",
        "transfers",
        "kv_entries",
        "kv_epochs",
        "peers",
        "peer_routes",
        "grants",
        "revocations",
        "peer_keys",
        "directory_checkpoints",
        "metadata",
        "sessions",
        "mailbox",
        "muted_sources",
        "plugin_targets",
        "bridge_links",
        "gate_audit",
    ] {
        assert!(tables.contains(expected), "missing table '{expected}'");
    }

    assert!(!tables.contains("deliveries"));

    // Idle DB must report None for next_deadline_ms.
    assert_eq!(db.next_deadline_ms(1_700_000_000_000).unwrap(), None);

    // Re-opening is idempotent.
    drop(db);
    let db2 = NodeDb::open(&db_path).unwrap();
    assert_eq!(db2.schema_version().unwrap(), CURRENT_SCHEMA_VERSION);
}

#[test]
fn events_idempotency_coalescing_wake_cap_and_retention() {
    let config = StoreConfig {
        event_limits: EventLimits {
            max_batch_events: 3,
            max_wakes_per_hour_per_subscription: 2,
            max_pending_batches_per_subscription: 5,
            retention_ms: DAY_MS,
            idempotency_ms: 7 * DAY_MS,
            hold_retry_ms: 15_000,
            prune_interval_ms: 60_000,
            ..EventLimits::default()
        },
        ..StoreConfig::default()
    };
    let db = NodeDb::open_in_memory_with_config(config).unwrap();
    let t0 = 1_700_000_000_000i64;

    // Publisher CRUD
    let pub_rec = db
        .events()
        .add_publisher("gh-hook", "secret-token-123", &["github", "alerts"], t0)
        .unwrap();
    assert_eq!(pub_rec.topics, vec!["alerts", "github"]);
    assert!(
        db.events()
            .authenticate_publisher("secret-token-123")
            .unwrap()
            .is_some()
    );
    assert!(
        db.events()
            .authenticate_publisher("wrong-token")
            .unwrap()
            .is_none()
    );
    assert!(db.events().revoke_publisher("gh-hook", t0 + 1).unwrap());
    assert!(
        db.events()
            .authenticate_publisher("secret-token-123")
            .unwrap()
            .is_none()
    );

    // Subscribe to acme-team.github with exact repo filter & 10s coalesce window & 2 wakes/hr cap.
    db.events()
        .upsert_subscription(
            &SubscriptionSpec {
                id: "sub-1".to_string(),
                origin_node: "acme-team".to_string(),
                topic: "github".to_string(),
                subscriber: "sess-claude".to_string(),
                filters: vec![Filter::exact("repo", "acme/checkout")],
                coalesce_seconds: 10,
                max_batch_age_ms: Some(60_000),
                max_wakes_per_hour: Some(2),
                mode: DeliveryMode::Full,
            },
            t0,
        )
        .unwrap();

    // Non-matching event produces 0 matches and clears body while keeping idempotency key.
    let unrelated = sample_event(
        "ev-unrel",
        "github.com/acme/other",
        "com.github.push",
        "acme/other",
    );
    let r0 = db
        .events()
        .ingest("acme-team", "github", "gh-hook", &unrelated, t0)
        .unwrap();
    assert_eq!(r0.matched, 0);
    assert!(!r0.deduplicated);

    // Matching event 1 opens coalescing batch with flush_at = t0 + 10_000.
    let ev1 = sample_event(
        "ev-1",
        "github.com/acme/checkout",
        "com.github.pr",
        "acme/checkout",
    );
    let r1 = db
        .events()
        .ingest("acme-team", "github", "gh-hook", &ev1, t0)
        .unwrap();
    assert_eq!(r1.matched, 1);
    assert_eq!(r1.batches_created, 1);
    assert_eq!(r1.batches_merged, 0);
    assert_eq!(db.events().next_deadline_ms(t0).unwrap(), Some(t0 + 10_000));

    // Exact replay (even with updated `time`) is idempotent and does NOT duplicate batch events.
    let mut ev1_replay = ev1.clone();
    ev1_replay.time = Some(epoch_ms_to_rfc3339(t0 + 2_000));
    let dup = db
        .events()
        .ingest("acme-team", "github", "gh-hook", &ev1_replay, t0 + 2_000)
        .unwrap();
    assert!(dup.deduplicated);
    assert_eq!(dup.batches_created, 0);
    assert_eq!(dup.batches_merged, 0);

    // Mutated replay with same key fails closed with IdConflict.
    let mut ev1_conflict = ev1.clone();
    ev1_conflict.data = json!({ "action": "closed" });
    let err = db
        .events()
        .ingest("acme-team", "github", "gh-hook", &ev1_conflict, t0 + 3_000)
        .unwrap_err();
    assert!(matches!(err, StoreError::IdConflict(_)));

    // Second matching event merges into the open batch and pushes flush_at forward to t0 + 14_000.
    let ev2 = sample_event(
        "ev-2",
        "github.com/acme/checkout",
        "com.github.pr",
        "acme/checkout",
    );
    let r2 = db
        .events()
        .ingest("acme-team", "github", "gh-hook", &ev2, t0 + 4_000)
        .unwrap();
    assert_eq!(r2.batches_created, 0);
    assert_eq!(r2.batches_merged, 1);
    assert_eq!(
        db.events().next_deadline_ms(t0 + 4_000).unwrap(),
        Some(t0 + 14_000)
    );

    // Still open -> nothing due yet.
    assert!(
        db.events()
            .claim_due_batches("sess-claude", t0 + 13_999)
            .unwrap()
            .is_empty()
    );

    // Advance to flush_at -> tick closes the batch into pending.
    let tick = db.events().tick(t0 + 14_000).unwrap();
    assert_eq!(tick.batches_closed, 1);

    let due = db
        .events()
        .claim_due_batches("sess-claude", t0 + 14_000)
        .unwrap();
    assert_eq!(due.len(), 1);
    assert_eq!(due[0].events.len(), 2);
    assert_eq!(due[0].events[0].id, "ev-1");
    assert_eq!(due[0].events[1].id, "ev-2");

    // Hold batch 1 -> delayed until t0 + 14_000 + 15_000.
    assert!(
        db.events()
            .ack_batch(
                "sess-claude",
                &due[0].id,
                &AckOutcome::Hold {
                    reason: "gate_busy".to_string(),
                    retry_after_ms: None,
                },
                t0 + 14_000,
            )
            .unwrap()
    );
    assert!(
        db.events()
            .claim_due_batches("sess-claude", t0 + 20_000)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        db.events().next_deadline_ms(t0 + 20_000).unwrap(),
        Some(t0 + 29_000)
    );

    // Come off hold and deliver batch 1 (wake 1 of 2/hr).
    let due_again = db
        .events()
        .claim_due_batches("sess-claude", t0 + 29_000)
        .unwrap();
    assert_eq!(due_again.len(), 1);
    assert!(
        db.events()
            .ack_batch(
                "sess-claude",
                &due_again[0].id,
                &AckOutcome::Delivered,
                t0 + 30_000
            )
            .unwrap()
    );

    // Fill max_batch_events=3 to force-close batch 2 immediately, then deliver it (wake 2 of 2/hr).
    for i in 3..=5 {
        let ev = sample_event(
            &format!("ev-{i}"),
            "github.com/acme/checkout",
            "com.github.pr",
            "acme/checkout",
        );
        db.events()
            .ingest("acme-team", "github", "gh-hook", &ev, t0 + 31_000)
            .unwrap();
    }
    let due2 = db
        .events()
        .claim_due_batches("sess-claude", t0 + 31_000)
        .unwrap();
    assert_eq!(due2.len(), 1);
    assert_eq!(due2[0].events.len(), 3);
    db.events()
        .ack_batch(
            "sess-claude",
            &due2[0].id,
            &AckOutcome::Delivered,
            t0 + 32_000,
        )
        .unwrap();

    // Create batch 3 (3 events -> force-closed) -> MUST be delayed by hourly wake cap (2/hr)!
    for i in 6..=8 {
        let ev = sample_event(
            &format!("ev-{i}"),
            "github.com/acme/checkout",
            "com.github.pr",
            "acme/checkout",
        );
        db.events()
            .ingest("acme-team", "github", "gh-hook", &ev, t0 + 33_000)
            .unwrap();
    }
    assert!(
        db.events()
            .claim_due_batches("sess-claude", t0 + 33_000)
            .unwrap()
            .is_empty(),
        "3rd batch in 1h must be delayed by wake cap"
    );
    // Exact wake-cap unblock time is wake_1_settled_at + 1h = t0 + 30_000 + HOUR_MS.
    let unblock = t0 + 30_000 + HOUR_MS;
    assert_eq!(
        db.events()
            .wake_cap_unblock_at("sub-1", t0 + 33_000)
            .unwrap(),
        Some(unblock)
    );
    assert_eq!(
        db.events().next_deadline_ms(t0 + 33_000).unwrap(),
        Some(unblock)
    );

    // At exactly `unblock`, batch 3 becomes due!
    let due3 = db
        .events()
        .claim_due_batches("sess-claude", unblock)
        .unwrap();
    assert_eq!(due3.len(), 1);
    assert_eq!(due3[0].events.len(), 3);
    db.events()
        .ack_batch(
            "sess-claude",
            &due3[0].id,
            &AckOutcome::Delivered,
            unblock + 100,
        )
        .unwrap();

    // Advance past 24h retention -> settled batches pruned, event bodies cleared, idempotency preserved.
    let t_24h = unblock + DAY_MS + 10_000;
    let prune24 = db.events().tick(t_24h).unwrap();
    assert_eq!(prune24.batches_pruned, 3);
    assert!(prune24.event_bodies_cleared > 0);
    assert!(
        db.events()
            .is_known_event(
                "acme-team",
                "github",
                "gh-hook",
                "github.com/acme/checkout",
                "ev-1"
            )
            .unwrap()
    );

    // Advance past 7d idempotency -> all events pruned and scheduler returns None (idle!).
    let t_7d = t0 + 8 * DAY_MS;
    let prune7d = db.events().tick(t_7d).unwrap();
    assert!(prune7d.events_pruned > 0);
    assert_eq!(db.events().next_deadline_ms(t_7d).unwrap(), None);
}

#[test]
fn events_upstream_pushdown_and_filter_validation() {
    let db = NodeDb::open_in_memory().unwrap();
    let t0 = 1_700_000_000_000i64;

    // Filter nesting > 8 fails closed.
    let mut deep = Filter::exact("repo", "a/b");
    for _ in 0..8 {
        deep = Filter::Not(Box::new(deep));
    }
    assert!(matches!(
        check_filters(&[deep]),
        Err(StoreError::InvalidFilter { .. })
    ));

    // Data field + array matching semantics.
    let ev = CloudEvent::new(
        "e1",
        "github.com/acme/web",
        "com.github.issues.opened",
        json!({ "labels": ["urgent", "p0"], "count": 5, "draft": false }),
    )
    .with_extension("repo", "acme/web");
    let mut m = BTreeMap::new();
    m.insert("data.labels".to_string(), "p0".to_string());
    m.insert("data.count".to_string(), "5".to_string());
    m.insert("data.draft".to_string(), "false".to_string());
    assert!(matches_filters(&[Filter::Exact(m)], &ev));

    // Upstream pushdowns CRUD + dirty reset on filter change.
    let pd = db
        .events()
        .upsert_upstream_pushdown(
            &UpstreamPushdownInput {
                id: "pd:github:0".to_string(),
                peer_id: "acme-team".to_string(),
                topic: "github".to_string(),
                shard_index: 0,
                filters_json: r#"[{"exact":{"repo":"acme/web"}}]"#.to_string(),
                coalesce_seconds: 15,
                local_sub_count: 2,
            },
            t0,
        )
        .unwrap();
    assert!(pd.synced_at.is_none());
    assert!(db.events().mark_pushdown_synced(&pd.id, t0 + 100).unwrap());
    let list = db
        .events()
        .list_upstream_pushdowns(Some("acme-team"))
        .unwrap();
    assert_eq!(list[0].synced_at, Some(t0 + 100));

    // Updating filters clears synced_at so sync loop re-pushes upstream.
    let pd2 = db
        .events()
        .upsert_upstream_pushdown(
            &UpstreamPushdownInput {
                id: "pd:github:0".to_string(),
                peer_id: "acme-team".to_string(),
                topic: "github".to_string(),
                shard_index: 0,
                filters_json: r#"[{"exact":{"repo":"acme/api"}}]"#.to_string(),
                coalesce_seconds: 15,
                local_sub_count: 3,
            },
            t0 + 200,
        )
        .unwrap();
    assert!(pd2.synced_at.is_none());
}

#[test]
fn messages_channels_preserve_e2ee_ciphertext_without_prefix_mutation() {
    let config = StoreConfig {
        message_limits: MessageLimits {
            ttl_ms: DAY_MS,
            settled_retention_ms: 7 * DAY_MS,
            hold_retry_ms: 10_000,
            prune_interval_ms: 60_000,
            ..MessageLimits::default()
        },
        ..StoreConfig::default()
    };
    let db = NodeDb::open_in_memory_with_config(config).unwrap();
    let t0 = 1_700_000_000_000i64;

    db.messages()
        .register_handle("alice@mac", "claude", Some("s1"), t0)
        .unwrap();
    db.messages()
        .register_handle("bob@lap", "codex", Some("s2"), t0)
        .unwrap();
    db.messages()
        .register_handle("carol@dev", "gemini", Some("s3"), t0)
        .unwrap();

    // Join #incidents
    db.channels()
        .join("acme-team", "#incidents", "alice@mac", "claude", t0)
        .unwrap();
    db.channels()
        .join("acme-team", "#incidents", "bob@lap", "codex", t0)
        .unwrap();
    db.channels()
        .join("acme-team", "#incidents", "carol@dev", "gemini", t0)
        .unwrap();

    // Store E2EE channel epoch 1, reject rollback/equivocation.
    let ep1 = db
        .channels()
        .put_epoch(
            &ChannelEpochInput {
                host_node: "acme-team".to_string(),
                channel: "#incidents".to_string(),
                epoch: 1,
                creator_node_id: "alice@mac".to_string(),
                key_envelope_json: r#"{"hpke":"wrapped-v1"}"#.to_string(),
                members: vec!["alice@mac/claude".into(), "bob@lap/codex".into()],
                signature: "sig-ep1".to_string(),
            },
            t0,
        )
        .unwrap();
    assert_eq!(ep1.epoch, 1);
    db.channels()
        .put_epoch(
            &ChannelEpochInput {
                host_node: "acme-team".to_string(),
                channel: "#incidents".to_string(),
                epoch: 2,
                creator_node_id: "alice@mac".to_string(),
                key_envelope_json: r#"{"hpke":"wrapped-v2"}"#.to_string(),
                members: vec![
                    "alice@mac/claude".into(),
                    "bob@lap/codex".into(),
                    "carol@dev/gemini".into(),
                ],
                signature: "sig-ep2".to_string(),
            },
            t0 + 100,
        )
        .unwrap();
    // Equivocating epoch 2 must fail closed.
    let eq_err = db
        .channels()
        .put_epoch(
            &ChannelEpochInput {
                host_node: "acme-team".to_string(),
                channel: "#incidents".to_string(),
                epoch: 2,
                creator_node_id: "alice@mac".to_string(),
                key_envelope_json: r#"{"hpke":"tampered"}"#.to_string(),
                members: vec!["alice@mac/claude".into()],
                signature: "sig-bad".to_string(),
            },
            t0 + 200,
        )
        .unwrap_err();
    assert!(matches!(eq_err, StoreError::EpochConflict { .. }));

    // Post E2EE ciphertext envelope to #incidents.
    let ciphertext = r#"{"v":2,"alg":"aes-256-gcm","epoch":2,"ct":"aGVsbG8td29ybGQ="}"#;
    let res = db
        .channels()
        .post(
            &PostChannelInput {
                id: "post-1".to_string(),
                host_node: "acme-team".to_string(),
                channel: "#incidents".to_string(),
                from_node: "alice@mac".to_string(),
                from_handle: "claude".to_string(),
                text: ciphertext.to_string(),
                e2ee_epoch: Some(2),
            },
            t0 + 500,
        )
        .unwrap();
    assert_eq!(res.delivered_to, vec!["bob@lap/codex", "carol@dev/gemini"]);
    assert!(res.failed.is_empty());

    // CRITICAL INVARIANT: Payload text MUST NOT be prefixed with `[#incidents] `!
    let bob_due = db
        .messages()
        .due_messages("bob@lap", |_| false, t0 + 500)
        .unwrap();
    assert_eq!(bob_due.len(), 1);
    assert_eq!(bob_due[0].text, ciphertext);
    assert_eq!(bob_due[0].channel.as_deref(), Some("#incidents"));
    assert_eq!(bob_due[0].e2ee_epoch, Some(2));

    // Hold, then deliver Bob's message; reject Carol's via stale handle pruning.
    assert!(
        db.messages()
            .ack(
                "bob@lap",
                &bob_due[0].id,
                &AckOutcome::Hold {
                    reason: "busy".into(),
                    retry_after_ms: Some(5_000),
                },
                t0 + 600,
            )
            .unwrap()
    );
    assert_eq!(
        db.messages().next_deadline_ms(t0 + 600).unwrap(),
        Some(t0 + 5_600)
    );
    assert!(
        db.messages()
            .ack(
                "bob@lap",
                &bob_due[0].id,
                &AckOutcome::Delivered,
                t0 + 6_000
            )
            .unwrap()
    );

    // Heartbeat Alice & Bob, let Carol go stale and prune.
    db.messages()
        .heartbeat_handle("alice@mac", "claude", t0 + 10_000)
        .unwrap();
    db.messages()
        .heartbeat_handle("bob@lap", "codex", t0 + 10_000)
        .unwrap();
    let pruned = db
        .messages()
        .prune_stale_handles(t0 + 5_000, t0 + 10_000)
        .unwrap();
    assert_eq!(pruned, vec!["carol@dev/gemini"]);
    let carol_msg = db
        .messages()
        .get_message("post-1:carol@dev/gemini")
        .unwrap()
        .unwrap();
    assert_eq!(carol_msg.state, MessageState::Rejected);
    assert_eq!(carol_msg.reason.as_deref(), Some("not_enrolled"));

    // After 7-day settled retention, tick prunes settled messages and scheduler goes idle (None).
    let t_8d = t0 + 8 * DAY_MS;
    let tick = db.messages().tick(t_8d).unwrap();
    assert_eq!(tick.settled_pruned, 2);
    assert_eq!(db.messages().next_deadline_ms(t_8d).unwrap(), None);
}

#[test]
fn transfers_atomic_blobs_quotas_expiry_and_orphan_sweep() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("node.sqlite");
    let config = StoreConfig {
        transfer_limits: TransferLimits {
            max_bytes: 100,
            max_pending_per_recipient: 2,
            max_pending_bytes_per_recipient: 120,
            max_pending_global: 3,
            max_pending_bytes_global: 180,
            hold_retry_ms: 5_000,
        },
        ..StoreConfig::default()
    };
    let db = NodeDb::open_with_config(&db_path, config).unwrap();
    let t0 = 1_700_000_000_000i64;

    // Reject path traversal IDs fail-closed.
    let bad = db.transfers().submit(
        &TransferSubmit {
            id: "../escape".to_string(),
            from_node: "alice@mac".to_string(),
            to_node: "bob@lap".to_string(),
            transfer_type: "files".to_string(),
            header_json: "{}".to_string(),
            expected_sha256: None,
            expires_at: t0 + 60_000,
        },
        b"hello",
        t0,
    );
    assert!(matches!(bad, Err(StoreError::InvalidInput(_))));

    // Reject mismatched SHA-256 fail-closed without leaving files on disk.
    let mismatch = db.transfers().submit(
        &TransferSubmit {
            id: "tx-bad-sha".to_string(),
            from_node: "alice@mac".to_string(),
            to_node: "bob@lap".to_string(),
            transfer_type: "files".to_string(),
            header_json: "{}".to_string(),
            expected_sha256: Some("0000".to_string()),
            expires_at: t0 + 60_000,
        },
        b"ciphertext",
        t0,
    );
    assert!(matches!(mismatch, Err(StoreError::InvalidInput(_))));
    assert!(!db.transfers_dir().join("tx-bad-sha").exists());

    // Submit transfer 1 (70 bytes) -> ok, 0600 permissions.
    let blob1 = vec![0xABu8; 70];
    let res1 = db
        .transfers()
        .submit(
            &TransferSubmit {
                id: "tx-1".to_string(),
                from_node: "alice@mac".to_string(),
                to_node: "bob@lap".to_string(),
                transfer_type: "files".to_string(),
                header_json: r#"{"id":"tx-1"}"#.to_string(),
                expected_sha256: Some(sha256_hex(&blob1)),
                expires_at: t0 + 60_000,
            },
            &blob1,
            t0,
        )
        .unwrap();
    assert!(!res1.deduplicated);
    assert_eq!(
        db.transfers().read_blob("bob@lap", "tx-1").unwrap(),
        Some(blob1.clone())
    );
    assert_eq!(db.transfers().read_blob("mallory", "tx-1").unwrap(), None);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(db.transfers_dir().join("tx-1"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    // Duplicate replay is idempotent.
    let dup = db
        .transfers()
        .submit(
            &TransferSubmit {
                id: "tx-1".to_string(),
                from_node: "alice@mac".to_string(),
                to_node: "bob@lap".to_string(),
                transfer_type: "files".to_string(),
                header_json: r#"{"id":"tx-1"}"#.to_string(),
                expected_sha256: None,
                expires_at: t0 + 60_000,
            },
            &blob1,
            t0 + 100,
        )
        .unwrap();
    assert!(dup.deduplicated);

    // Per-recipient byte quota (70 + 60 > 120) fails closed and leaves no file.
    let over_recip = db.transfers().submit(
        &TransferSubmit {
            id: "tx-over-recip".to_string(),
            from_node: "alice@mac".to_string(),
            to_node: "bob@lap".to_string(),
            transfer_type: "files".to_string(),
            header_json: "{}".to_string(),
            expected_sha256: None,
            expires_at: t0 + 60_000,
        },
        &[1u8; 60],
        t0,
    );
    assert!(matches!(over_recip, Err(StoreError::QuotaExceeded(_))));
    assert!(!db.transfers_dir().join("tx-over-recip").exists());

    // Submit 90 bytes to carol (global = 160 <= 180) -> ok.
    db.transfers()
        .submit(
            &TransferSubmit {
                id: "tx-2".to_string(),
                from_node: "alice@mac".to_string(),
                to_node: "carol@dev".to_string(),
                transfer_type: "files".to_string(),
                header_json: "{}".to_string(),
                expected_sha256: None,
                expires_at: t0 + 30_000,
            },
            &[2u8; 90],
            t0,
        )
        .unwrap();

    // Global byte quota (160 + 30 > 180) fails closed!
    let over_global = db.transfers().submit(
        &TransferSubmit {
            id: "tx-over-global".to_string(),
            from_node: "alice@mac".to_string(),
            to_node: "dave@box".to_string(),
            transfer_type: "files".to_string(),
            header_json: "{}".to_string(),
            expected_sha256: None,
            expires_at: t0 + 60_000,
        },
        &[3u8; 30],
        t0,
    );
    assert!(matches!(over_global, Err(StoreError::QuotaExceeded(_))));

    // Create a stray `.part-*` file and orphan blob, verify sweep_orphans removes ONLY them.
    fs::write(
        db.transfers_dir().join("tx-crash.part-deadbeef"),
        b"partial",
    )
    .unwrap();
    fs::write(db.transfers_dir().join("tx-orphan-blob"), b"orphan").unwrap();
    let sweep = db.transfers().sweep_orphans().unwrap();
    assert_eq!(sweep.part_files_removed, 1);
    assert_eq!(sweep.orphan_blobs_removed, 1);
    assert!(db.transfers_dir().join("tx-1").exists());
    assert!(db.transfers_dir().join("tx-2").exists());

    // Next deadline must be tx-2 expiry (t0 + 30_000).
    assert_eq!(
        db.transfers().next_deadline_ms(t0).unwrap(),
        Some(t0 + 30_000)
    );

    // Expire tx-2 via tick -> row marked expired AND blob deleted from disk!
    let tick = db.transfers().tick(t0 + 30_000).unwrap();
    assert_eq!(tick.expired, 1);
    assert_eq!(tick.blobs_removed, 1);
    assert!(!db.transfers_dir().join("tx-2").exists());
    assert_eq!(
        db.transfers().get("tx-2").unwrap().unwrap().state,
        TransferState::Expired
    );

    // Ack tx-1 delivered -> blob deleted from disk, scheduler returns None!
    assert!(
        db.transfers()
            .ack("bob@lap", "tx-1", &AckOutcome::Delivered, t0 + 31_000)
            .unwrap()
    );
    assert!(!db.transfers_dir().join("tx-1").exists());
    assert_eq!(db.transfers().next_deadline_ms(t0 + 31_000).unwrap(), None);
}

#[test]
fn kv_write_models_cas_ttl_epochs_and_atomic_cloudevent_emission() {
    let db = NodeDb::open_in_memory().unwrap();
    let t0 = 1_700_000_000_000i64;

    // Subscribe to local.kv filtered to ns="pair" and key prefix "plan/".
    db.events()
        .upsert_subscription(
            &SubscriptionSpec {
                id: "kv-watch".to_string(),
                origin_node: "local".to_string(),
                topic: "kv".to_string(),
                subscriber: "sess-watcher".to_string(),
                filters: vec![Filter::exact("ns", "pair"), Filter::prefix("key", "plan/")],
                coalesce_seconds: 0,
                max_batch_age_ms: None,
                max_wakes_per_hour: None,
                mode: DeliveryMode::Full,
            },
            t0,
        )
        .unwrap();

    // 1. Owner write model: only owner can update/delete.
    let set1 = db
        .kv()
        .set(
            &KvSetInput {
                host_node: "local".to_string(),
                namespace: "pair".to_string(),
                key: "plan/v1".to_string(),
                value: json!({ "status": "draft" }),
                content_type: None,
                write_model: WriteModel::Owner,
                owner_id: None,
                allowlist: None,
                writer_id: "alice".to_string(),
                expected_version: None,
                e2ee_epoch: None,
                signature: None,
                ttl_ms: Some(10_000),
            },
            t0,
        )
        .unwrap();
    assert_eq!(set1.entry.version, 1);
    assert_eq!(set1.event.matched, 1);

    // Non-owner fails closed AND emits zero CloudEvents!
    let unauth = db
        .kv()
        .set(
            &KvSetInput {
                host_node: "local".to_string(),
                namespace: "pair".to_string(),
                key: "plan/v1".to_string(),
                value: json!({ "status": "hijack" }),
                content_type: None,
                write_model: WriteModel::Owner,
                owner_id: None,
                allowlist: None,
                writer_id: "mallory".to_string(),
                expected_version: None,
                e2ee_epoch: None,
                signature: None,
                ttl_ms: None,
            },
            t0 + 100,
        )
        .unwrap_err();
    assert!(matches!(unauth, StoreError::Unauthorized(_)));

    // 2. Shared write model: strict CAS optimistic concurrency.
    db.kv()
        .set(
            &KvSetInput {
                host_node: "local".to_string(),
                namespace: "pair".to_string(),
                key: "plan/lock".to_string(),
                value: json!({ "holder": "alice" }),
                content_type: None,
                write_model: WriteModel::Shared,
                owner_id: None,
                allowlist: None,
                writer_id: "alice".to_string(),
                expected_version: Some(0),
                e2ee_epoch: Some(1),
                signature: None,
                ttl_ms: None,
            },
            t0 + 200,
        )
        .unwrap();

    // Missing or stale expected_version fails closed with VersionConflict { current_version: 1 }.
    let conflict = db
        .kv()
        .set(
            &KvSetInput {
                host_node: "local".to_string(),
                namespace: "pair".to_string(),
                key: "plan/lock".to_string(),
                value: json!({ "holder": "bob" }),
                content_type: None,
                write_model: WriteModel::Shared,
                owner_id: None,
                allowlist: None,
                writer_id: "bob".to_string(),
                expected_version: Some(0),
                e2ee_epoch: Some(1),
                signature: None,
                ttl_ms: None,
            },
            t0 + 300,
        )
        .unwrap_err();
    assert!(matches!(
        conflict,
        StoreError::VersionConflict { current_version: 1 }
    ));

    // Matching CAS succeeds -> version 2.
    let cas_ok = db
        .kv()
        .set(
            &KvSetInput {
                host_node: "local".to_string(),
                namespace: "pair".to_string(),
                key: "plan/lock".to_string(),
                value: json!({ "holder": "bob" }),
                content_type: None,
                write_model: WriteModel::Shared,
                owner_id: None,
                allowlist: None,
                writer_id: "bob".to_string(),
                expected_version: Some(1),
                e2ee_epoch: Some(1),
                signature: None,
                ttl_ms: None,
            },
            t0 + 400,
        )
        .unwrap();
    assert_eq!(cas_ok.entry.version, 2);

    // 3. Allowlist write model.
    db.kv()
        .set(
            &KvSetInput {
                host_node: "local".to_string(),
                namespace: "pair".to_string(),
                key: "notes/a".to_string(),
                value: json!("hello"),
                content_type: None,
                write_model: WriteModel::Allowlist,
                owner_id: None,
                allowlist: Some(vec!["alice".into(), "bob".into()]),
                writer_id: "alice".to_string(),
                expected_version: None,
                e2ee_epoch: None,
                signature: None,
                ttl_ms: None,
            },
            t0 + 500,
        )
        .unwrap();
    // Bob is in allowlist -> allowed.
    db.kv()
        .set(
            &KvSetInput {
                host_node: "local".to_string(),
                namespace: "pair".to_string(),
                key: "notes/a".to_string(),
                value: json!("updated-by-bob"),
                content_type: None,
                write_model: WriteModel::Allowlist,
                owner_id: None,
                allowlist: None,
                writer_id: "bob".to_string(),
                expected_version: None,
                e2ee_epoch: None,
                signature: None,
                ttl_ms: None,
            },
            t0 + 600,
        )
        .unwrap();
    // Carol is NOT in allowlist -> Unauthorized.
    assert!(matches!(
        db.kv().set(
            &KvSetInput {
                host_node: "local".to_string(),
                namespace: "pair".to_string(),
                key: "notes/a".to_string(),
                value: json!("nope"),
                content_type: None,
                write_model: WriteModel::Allowlist,
                owner_id: None,
                allowlist: None,
                writer_id: "carol".to_string(),
                expected_version: None,
                e2ee_epoch: None,
                signature: None,
                ttl_ms: None,
            },
            t0 + 700,
        ),
        Err(StoreError::Unauthorized(_))
    ));

    // Delete `plan/lock` with correct CAS -> emits `to.hyphae.kv.deleted`!
    let del = db
        .kv()
        .delete(
            &KvDeleteInput {
                host_node: "local".to_string(),
                namespace: "pair".to_string(),
                key: "plan/lock".to_string(),
                writer_id: "bob".to_string(),
                expected_version: Some(2),
            },
            t0 + 800,
        )
        .unwrap();
    assert!(del.deleted);
    assert_eq!(del.previous_version, Some(2));

    // Oversized KV value (> 6 KiB) succeeds and emits metadata+sha256 CloudEvent without exceeding CE limit!
    let big_str = "x".repeat(12_000);
    let big_res = db
        .kv()
        .set(
            &KvSetInput {
                host_node: "local".to_string(),
                namespace: "pair".to_string(),
                key: "plan/large".to_string(),
                value: json!({ "blob": big_str }),
                content_type: None,
                write_model: WriteModel::Owner,
                owner_id: None,
                allowlist: None,
                writer_id: "alice".to_string(),
                expected_version: None,
                e2ee_epoch: None,
                signature: None,
                ttl_ms: None,
            },
            t0 + 900,
        )
        .unwrap();
    assert_eq!(big_res.event.matched, 1);

    // Drain all watched KV events for `plan/` (notes/a did NOT match the prefix filter).
    let mut watched_types = Vec::new();
    while let Some(batch) = db
        .events()
        .claim_due_batches("sess-watcher", t0 + 900)
        .unwrap()
        .into_iter()
        .next()
    {
        for ev in &batch.events {
            watched_types.push((ev.event_type.clone(), ev.extensions.get("key").cloned()));
        }
        db.events()
            .ack_batch("sess-watcher", &batch.id, &AckOutcome::Delivered, t0 + 900)
            .unwrap();
    }
    assert_eq!(
        watched_types,
        vec![
            ("to.hyphae.kv.set".to_string(), Some("plan/v1".to_string())),
            (
                "to.hyphae.kv.set".to_string(),
                Some("plan/lock".to_string())
            ),
            (
                "to.hyphae.kv.set".to_string(),
                Some("plan/lock".to_string())
            ),
            (
                "to.hyphae.kv.deleted".to_string(),
                Some("plan/lock".to_string())
            ),
            (
                "to.hyphae.kv.set".to_string(),
                Some("plan/large".to_string())
            ),
        ]
    );

    // TTL expiry check & next_deadline_ms
    assert_eq!(db.kv().next_deadline_ms().unwrap(), Some(t0 + 10_000));
    assert!(
        db.kv()
            .get("local", "pair", "plan/v1", t0 + 10_000)
            .unwrap()
            .is_none()
    );
    assert_eq!(db.kv().tick(t0 + 10_000).unwrap(), 1);
    assert_eq!(db.kv().next_deadline_ms().unwrap(), None);

    // KV epoch monotonic storage
    let ep = db
        .kv()
        .put_epoch(
            &KvEpochInput {
                host_node: "local".to_string(),
                namespace: "pair".to_string(),
                epoch: 1,
                creator_node_id: "alice@mac".to_string(),
                key_envelope_json: r#"{"hpke":"k1"}"#.to_string(),
                members: vec!["alice@mac".into(), "bob@lap".into()],
                signature: "sig-1".to_string(),
            },
            t0,
        )
        .unwrap();
    assert_eq!(ep.epoch, 1);
    assert_eq!(
        db.kv()
            .latest_epoch("local", "pair")
            .unwrap()
            .unwrap()
            .epoch,
        1
    );
}

#[test]
fn local_state_quarantine_human_review_mutes_and_immutable_gate_audit() {
    let db = NodeDb::open_in_memory().unwrap();
    let t0 = 1_700_000_000_000i64;

    // Metadata identity lock fails closed on mismatch.
    db.local().ensure_metadata("node_id", "alice@mac").unwrap();
    db.local().ensure_metadata("node_id", "alice@mac").unwrap();
    assert!(matches!(
        db.local().ensure_metadata("node_id", "other@box"),
        Err(StoreError::InvalidState(_))
    ));

    // Sessions + handles + plugin targets + bridge links.
    db.local()
        .register_session("claude:t1", r#"{"kind":"claude"}"#, t0)
        .unwrap();
    db.local()
        .set_session_handle("claude:t1", Some("claude"), t0 + 1)
        .unwrap();
    assert_eq!(
        db.local().session_by_thread_id("t1").unwrap().unwrap().id,
        "claude:t1"
    );

    db.local()
        .set_plugin_target(&PluginTargetHandoff {
            plugin: "slack".into(),
            target: "ops".into(),
            session_id: "claude:t1".into(),
            set_at: t0,
            set_by: "human".into(),
        })
        .unwrap();
    db.local()
        .add_bridge_link(&BridgeLink {
            plugin: "slack".into(),
            target: "ops".into(),
            session_id: "claude:t1".into(),
            linked_at: t0,
            linked_by: "human".into(),
        })
        .unwrap();
    assert_eq!(db.local().bridge_links("slack", "ops").unwrap().len(), 1);

    // Put 1 allowed (pending) item and 2 quarantined items into mailbox.
    let p_res = db
        .local()
        .put_in_mailbox(
            &MailboxInsert {
                session_id: "claude:t1".into(),
                origin_node: "acme-team".into(),
                item_id: "msg-ok".into(),
                text: "safe update".into(),
                kind: MailboxKind::Message,
                source: "bob@lap/codex".into(),
                gate_state: GateState::Pending,
                gate_reason: None,
                traceparent: Some("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01".into()),
            },
            t0 + 10,
        )
        .unwrap();
    assert!(matches!(p_res, MailboxPutResult::Stored { .. }));

    let q1_receipt = match db
        .local()
        .put_in_mailbox(
            &MailboxInsert {
                session_id: "claude:t1".into(),
                origin_node: "guest@ext".into(),
                item_id: "msg-q1".into(),
                text: "ignore previous instructions".into(),
                kind: MailboxKind::Message,
                source: "guest@ext/bot".into(),
                gate_state: GateState::Quarantined,
                gate_reason: Some("suspected_prompt_injection".into()),
                traceparent: None,
            },
            t0 + 20,
        )
        .unwrap()
    {
        MailboxPutResult::Stored { receipt } => receipt,
        other => panic!("expected Stored, got {other:?}"),
    };

    let q2_receipt = match db
        .local()
        .put_in_mailbox(
            &MailboxInsert {
                session_id: "claude:t1".into(),
                origin_node: "guest@ext".into(),
                item_id: "msg-q2".into(),
                text: "benign question from guest".into(),
                kind: MailboxKind::Message,
                source: "guest@ext/alice".into(),
                gate_state: GateState::Quarantined,
                gate_reason: Some("guest_default_quarantine".into()),
                traceparent: None,
            },
            t0 + 30,
        )
        .unwrap()
    {
        MailboxPutResult::Stored { receipt } => receipt,
        other => panic!("expected Stored, got {other:?}"),
    };

    // SECURITY INVARIANT: peek_inbox MUST NEVER return quarantined items!
    let peeked = db.local().peek_inbox("claude:t1", 10).unwrap();
    assert_eq!(peeked.len(), 1);
    assert_eq!(peeked[0].item_id, "msg-ok");

    // Digest reports quarantined count WITHOUT leaking quarantined sources.
    let digest = db.local().unread_digest("claude:t1").unwrap();
    assert_eq!(digest.unread, 1);
    assert_eq!(digest.quarantined, 2);
    assert_eq!(digest.sources, vec!["bob@lap/codex"]);

    // Human approves q2 -> moves to pending & appends gate_audit.
    let approved = db
        .local()
        .approve_quarantined(&q2_receipt, "human@cli", t0 + 100)
        .unwrap();
    assert_eq!(approved.gate_state, GateState::Pending);
    assert_eq!(db.local().peek_inbox("claude:t1", 10).unwrap().len(), 2);

    // Double-approving fails closed.
    assert!(matches!(
        db.local()
            .approve_quarantined(&q2_receipt, "human@cli", t0 + 101),
        Err(StoreError::InvalidState(_))
    ));

    // Human rejects q1 with optional mute rule -> marks rejected, installs mute, appends gate_audit.
    let rejected = db
        .local()
        .reject_quarantined(
            &q1_receipt,
            "human@cli",
            "confirmed injection",
            Some(&MuteRuleInput {
                scope: "*".into(),
                pattern: "guest@ext/*".into(),
            }),
            t0 + 200,
        )
        .unwrap();
    assert_eq!(rejected.gate_state, GateState::Rejected);
    assert_eq!(
        db.local()
            .is_muted("claude:t1", &["GUEST@EXT/bot"])
            .unwrap()
            .as_deref(),
        Some("guest@ext/*")
    );

    // Query gate_audit with decision + since_ms filters.
    db.local()
        .append_gate_audit(
            &GateAuditInput {
                direction: GateDirection::Inbound,
                stage: "stage2_llm".into(),
                decision: GateDecision::Quarantine,
                origin_node: Some("guest@ext".into()),
                source: Some("guest@ext/bot".into()),
                session_id: Some("claude:t1".into()),
                receipt_id: Some(q1_receipt.clone()),
                event_type: Some("to.hyphae.dm.v1".into()),
                trust_tier: Some("guest".into()),
                confidence: Some(0.92),
                categories: vec!["prompt_injection".into()],
                reason: Some("suspected_prompt_injection".into()),
                traceparent: None,
                payload_sha256: sha256_hex(b"ignore previous instructions"),
                reviewer: None,
            },
            t0 + 25,
        )
        .unwrap();

    let blocked = db
        .local()
        .query_gate_audit(&GateAuditQuery {
            decision: Some(GateDecision::Block),
            since_ms: Some(t0 + 150),
            limit: Some(10),
            ..GateAuditQuery::default()
        })
        .unwrap();
    assert_eq!(blocked.len(), 1);
    assert_eq!(blocked[0].reviewer.as_deref(), Some("human@cli"));

    // IMMUTABILITY INVARIANT: SQLite triggers forbid UPDATE and DELETE on gate_audit!
    let upd_err = db
        .connection()
        .execute("UPDATE gate_audit SET decision = 'allow'", []);
    assert!(
        upd_err.is_err(),
        "gate_audit UPDATE must be blocked by trigger"
    );
    let del_err = db.connection().execute("DELETE FROM gate_audit", []);
    assert!(
        del_err.is_err(),
        "gate_audit DELETE must be blocked by trigger"
    );
}

#[test]
fn peers_manifest_anti_rollback_and_e2ee_anti_downgrade() {
    let db = NodeDb::open_in_memory().unwrap();
    let t0 = 1_700_000_000_000i64;

    db.peers()
        .upsert_peer(
            &PeerInput {
                peer_id: "acme-team".into(),
                endpoint: Some("https://mesh.acme.internal".into()),
                profile: PeerProfile::Router,
                trust_tier: TrustTier::Org,
                status: PeerStatus::Active,
                scopes: vec!["dm:send".into(), "dm:receive".into()],
                auth_credential_ref: Some("peer-acme-token".into()),
            },
            t0,
        )
        .unwrap();

    // Cache v1 manifest (legacy plaintext only).
    let p1 = db
        .peers()
        .cache_manifest(
            "acme-team",
            &ManifestCacheUpdate {
                manifest_version: 1,
                manifest_json: r#"{"manifestVersion":1}"#.into(),
                etag: Some("\"v1\"".into()),
                capabilities: vec!["dm.v1".into(), "events.v1".into()],
                accept_downgrade: false,
            },
            t0 + 10,
        )
        .unwrap();
    assert_eq!(p1.manifest_version, 1);
    assert!(p1.observed_e2ee_caps.is_empty());

    // Upgrade to v2 with E2EE capabilities -> ratchets permanently!
    let p2 = db
        .peers()
        .cache_manifest(
            "acme-team",
            &ManifestCacheUpdate {
                manifest_version: 2,
                manifest_json: r#"{"manifestVersion":2,"e2ee":true}"#.into(),
                etag: Some("\"v2\"".into()),
                capabilities: vec![
                    "dm.v1".into(),
                    "dm.e2ee.v1".into(),
                    "channel.e2ee.v1".into(),
                ],
                accept_downgrade: false,
            },
            t0 + 20,
        )
        .unwrap();
    assert_eq!(p2.manifest_version, 2);
    assert_eq!(p2.observed_e2ee_caps, vec!["channel.e2ee.v1", "dm.e2ee.v1"]);

    // Anti-rollback: version 1 rejected!
    let rb = db
        .peers()
        .cache_manifest(
            "acme-team",
            &ManifestCacheUpdate {
                manifest_version: 1,
                manifest_json: r#"{"manifestVersion":1}"#.into(),
                etag: None,
                capabilities: vec!["dm.e2ee.v1".into(), "channel.e2ee.v1".into()],
                accept_downgrade: false,
            },
            t0 + 30,
        )
        .unwrap_err();
    assert!(matches!(
        rb,
        StoreError::ManifestRollback {
            expected_min: 2,
            received: 1,
            ..
        }
    ));

    // Same-version equivocation rejected!
    let eq = db
        .peers()
        .cache_manifest(
            "acme-team",
            &ManifestCacheUpdate {
                manifest_version: 2,
                manifest_json: r#"{"manifestVersion":2,"tampered":true}"#.into(),
                etag: None,
                capabilities: vec!["dm.e2ee.v1".into(), "channel.e2ee.v1".into()],
                accept_downgrade: false,
            },
            t0 + 35,
        )
        .unwrap_err();
    assert!(matches!(eq, StoreError::ManifestRollback { .. }));

    // Anti-downgrade: v3 dropping `channel.e2ee.v1` MUST FAIL CLOSED!
    let dg = db
        .peers()
        .cache_manifest(
            "acme-team",
            &ManifestCacheUpdate {
                manifest_version: 3,
                manifest_json: r#"{"manifestVersion":3,"downgraded":true}"#.into(),
                etag: None,
                capabilities: vec!["dm.v1".into(), "dm.e2ee.v1".into()],
                accept_downgrade: false,
            },
            t0 + 40,
        )
        .unwrap_err();
    assert!(matches!(
        dg,
        StoreError::CapabilityDowngrade { ref missing_capabilities, .. }
            if missing_capabilities == &vec!["channel.e2ee.v1".to_string()]
    ));

    // Explicit `accept_downgrade: true` override succeeds and updates observed set.
    let p3 = db
        .peers()
        .cache_manifest(
            "acme-team",
            &ManifestCacheUpdate {
                manifest_version: 3,
                manifest_json: r#"{"manifestVersion":3,"downgraded":true}"#.into(),
                etag: Some("\"v3\"".into()),
                capabilities: vec!["dm.v1".into(), "dm.e2ee.v1".into()],
                accept_downgrade: true,
            },
            t0 + 50,
        )
        .unwrap();
    assert_eq!(p3.manifest_version, 3);
    assert_eq!(p3.observed_e2ee_caps, vec!["dm.e2ee.v1"]);

    // Grants, revocations, peer keys & directory checkpoints anti-rollback.
    db.peers()
        .add_grant(
            &GrantInput {
                id: "g-1".into(),
                peer_id: "acme-team".into(),
                direction: GrantDirection::Inbound,
                signed_json: r#"{"payload":"p","sig":"s"}"#.into(),
                scopes: vec!["dm:send".into()],
                trust_tier: TrustTier::Org,
                issued_at: t0,
                pair_by: Some(t0 + 60_000),
                expires_at: None,
            },
            t0,
        )
        .unwrap();
    db.peers()
        .claim_grant("g-1", r#"{"binding":"b"}"#, t0 + 1_000)
        .unwrap();
    assert!(matches!(
        db.peers()
            .claim_grant("g-1", r#"{"binding":"b2"}"#, t0 + 1_001),
        Err(StoreError::AlreadyPaired(_))
    ));
    db.peers()
        .add_revocation(
            &RevocationInput {
                grant_id: "g-1".into(),
                peer_id: "acme-team".into(),
                signed_json: r#"{"rev":"1"}"#.into(),
            },
            t0 + 2_000,
        )
        .unwrap();
    assert!(db.peers().is_grant_revoked("g-1").unwrap());

    db.peers()
        .upsert_peer_key(
            &PeerKeyInput {
                peer_id: "acme-team".into(),
                kid: "thumbprint-1".into(),
                key_use: KeyUse::Signing,
                jwk_json: r#"{"kty":"OKP","crv":"Ed25519","x":"abc"}"#.into(),
                status: KeyStatus::Active,
                expires_at: None,
            },
            t0,
        )
        .unwrap();
    assert_eq!(
        db.peers()
            .list_peer_keys("acme-team", Some(KeyUse::Signing), true)
            .unwrap()
            .len(),
        1
    );

    db.peers()
        .record_checkpoint(
            &DirectoryCheckpointInput {
                authority_id: "org-ca".into(),
                version: 5,
                root_hash: "aaaa".into(),
                signed_json: "{}".into(),
                issued_at: t0,
            },
            t0,
        )
        .unwrap();
    assert!(matches!(
        db.peers().record_checkpoint(
            &DirectoryCheckpointInput {
                authority_id: "org-ca".into(),
                version: 4,
                root_hash: "bbbb".into(),
                signed_json: "{}".into(),
                issued_at: t0,
            },
            t0 + 10,
        ),
        Err(StoreError::CheckpointRollback {
            expected_min: 5,
            received: 4,
            ..
        })
    ));
}

#[test]
fn scheduler_unifies_exact_earliest_deadline_across_all_subsystems() {
    let db = NodeDb::open_in_memory().unwrap();
    let t0 = 1_700_000_000_000i64;

    // 1. Completely idle -> None!
    assert_eq!(db.next_deadline_ms(t0).unwrap(), None);

    // 2. Add expiring KV entry at t0 + 5_000.
    db.kv()
        .set(
            &KvSetInput {
                host_node: "local".into(),
                namespace: "cache".into(),
                key: "k1".into(),
                value: json!(1),
                content_type: None,
                write_model: WriteModel::Owner,
                owner_id: None,
                allowlist: None,
                writer_id: "alice".into(),
                expected_version: None,
                e2ee_epoch: None,
                signature: None,
                ttl_ms: Some(5_000),
            },
            t0,
        )
        .unwrap();
    assert_eq!(db.next_deadline_ms(t0).unwrap(), Some(t0 + 5_000));

    // 3. Add transfer expiring at t0 + 3_000 -> earliest moves to t0 + 3_000.
    db.transfers()
        .submit(
            &TransferSubmit {
                id: "tx-s1".into(),
                from_node: "alice@mac".into(),
                to_node: "bob@lap".into(),
                transfer_type: "files".into(),
                header_json: "{}".into(),
                expected_sha256: None,
                expires_at: t0 + 3_000,
            },
            b"abc",
            t0,
        )
        .unwrap();
    assert_eq!(db.next_deadline_ms(t0).unwrap(), Some(t0 + 3_000));

    // 4. Add message with hold_until at t0 + 2_000 -> earliest moves to t0 + 2_000.
    db.messages()
        .register_handle("alice@mac", "a", None, t0)
        .unwrap();
    db.messages()
        .register_handle("bob@lap", "b", None, t0)
        .unwrap();
    db.messages()
        .enqueue(
            &EnqueueMessage {
                id: "m-1".into(),
                from_node: "alice@mac".into(),
                from_handle: "a".into(),
                to_addr: "bob@lap/b".into(),
                channel: None,
                text: "hi".into(),
                origin_environment_id: None,
                origin_thread_id: None,
                e2ee_epoch: None,
            },
            t0,
        )
        .unwrap();
    db.messages()
        .ack(
            "bob@lap",
            "m-1",
            &AckOutcome::Hold {
                reason: "wait".into(),
                retry_after_ms: Some(2_000),
            },
            t0,
        )
        .unwrap();
    assert_eq!(db.next_deadline_ms(t0).unwrap(), Some(t0 + 2_000));

    // 5. Add event coalescing batch flushing at t0 + 1_000 -> earliest moves to t0 + 1_000!
    db.events()
        .upsert_subscription(
            &SubscriptionSpec {
                id: "s-1".into(),
                origin_node: "local".into(),
                topic: "ci".into(),
                subscriber: "sess-1".into(),
                filters: vec![],
                coalesce_seconds: 1,
                max_batch_age_ms: None,
                max_wakes_per_hour: None,
                mode: DeliveryMode::Full,
            },
            t0,
        )
        .unwrap();
    db.events()
        .ingest(
            "local",
            "ci",
            "pub",
            &sample_event("e1", "ci/1", "ci.run", "a/b"),
            t0,
        )
        .unwrap();

    let bd = db.next_deadline_breakdown(t0).unwrap();
    assert_eq!(bd.events, Some(t0 + 1_000));
    assert_eq!(bd.messages, Some(t0 + 2_000));
    assert_eq!(bd.transfers, Some(t0 + 3_000));
    assert_eq!(bd.kv, Some(t0 + 5_000));
    assert_eq!(bd.earliest, Some(t0 + 1_000));

    // Tick at t0 + 5_000 expires transfer + KV + closes event batch.
    let rep = db.tick(t0 + 5_000).unwrap();
    assert_eq!(rep.events.batches_closed, 1);
    assert_eq!(rep.transfers.expired, 1);
    assert_eq!(rep.kv_expired, 1);

    // Deliver remaining message & event batch, then advance past 7d retention -> completely idle (None)!
    db.messages()
        .ack("bob@lap", "m-1", &AckOutcome::Delivered, t0 + 5_000)
        .unwrap();
    let due_ev = db.events().claim_due_batches("sess-1", t0 + 5_000).unwrap();
    assert_eq!(due_ev.len(), 1);
    db.events()
        .ack_batch("sess-1", &due_ev[0].id, &AckOutcome::Delivered, t0 + 5_000)
        .unwrap();
    db.tick(t0 + 8 * DAY_MS).unwrap();
    assert_eq!(db.next_deadline_ms(t0 + 8 * DAY_MS).unwrap(), None);
}

#[test]
fn edge_cases_session_pruning_set_subscriptions_and_staged_transfer_rollback() {
    let db = NodeDb::open_in_memory().unwrap();
    let t0 = 1_700_000_000_000i64;

    // 1. Session pruning cascades cleanly across mailbox, per-session mutes, bridge_links, plugin_targets.
    db.local().register_session("s-stale", "{}", t0).unwrap();
    db.local().register_session("s-active", "{}", t0).unwrap();
    db.local()
        .add_mute("s-stale", "noisy", "human", t0)
        .unwrap();
    db.local()
        .add_mute("*", "global-muted", "human", t0)
        .unwrap();
    db.local()
        .add_bridge_link(&BridgeLink {
            plugin: "slack".into(),
            target: "ops".into(),
            session_id: "s-stale".into(),
            linked_at: t0,
            linked_by: "human".into(),
        })
        .unwrap();
    db.local()
        .set_plugin_target(&PluginTargetHandoff {
            plugin: "slack".into(),
            target: "ops".into(),
            session_id: "s-stale".into(),
            set_at: t0,
            set_by: "human".into(),
        })
        .unwrap();
    db.local()
        .put_in_mailbox(
            &MailboxInsert {
                session_id: "s-stale".into(),
                origin_node: "local".into(),
                item_id: "m1".into(),
                text: "bye".into(),
                kind: MailboxKind::Message,
                source: "a".into(),
                gate_state: GateState::Pending,
                gate_reason: None,
                traceparent: None,
            },
            t0,
        )
        .unwrap();

    let mut active = HashSet::new();
    active.insert("s-active".to_string());

    // UR1: While `s-stale` holds unread `pending` mail, `prune_sessions` MUST NOT prune it or
    // delete its unread mailbox rows!
    let report_blocked = db.local().prune_sessions(t0 + 1_000, &active).unwrap();
    assert!(
        report_blocked.pruned_sessions.is_empty(),
        "UR1: session with unread pending mail must not be pruned: {report_blocked:?}"
    );
    assert!(db.local().get_session("s-stale").unwrap().is_some());
    assert_eq!(db.local().pending_count("s-stale").unwrap(), 1);
    assert_eq!(db.local().bridge_links("slack", "ops").unwrap().len(), 1);
    assert!(
        db.local()
            .get_plugin_target("slack", "ops")
            .unwrap()
            .is_some()
    );

    // Once unread mail is drained (`pending` -> `delivered`), `prune_sessions` cascades cleanly!
    let drained = db.local().drain_inbox("s-stale", 10, t0 + 500).unwrap();
    assert_eq!(drained.len(), 1);
    let report = db.local().prune_sessions(t0 + 1_000, &active).unwrap();
    assert_eq!(report.pruned_sessions, vec!["s-stale"]);
    assert!(db.local().get_session("s-stale").unwrap().is_none());
    assert!(db.local().get_session("s-active").unwrap().is_some());
    assert!(db.local().bridge_links("slack", "ops").unwrap().is_empty());
    assert!(
        db.local()
            .get_plugin_target("slack", "ops")
            .unwrap()
            .is_none()
    );
    assert_eq!(db.local().pending_count("s-stale").unwrap(), 0);
    // Global mute must remain untouched!
    assert_eq!(db.local().list_mutes(None).unwrap().len(), 1);

    // 2. set_subscriptions drops batches when topic changes and rejects cross-subscriber ID theft.
    db.events()
        .set_subscriptions(
            "sess-a",
            &[SubscriptionSpec {
                id: "sub-x".into(),
                origin_node: "local".into(),
                topic: "t1".into(),
                subscriber: "sess-a".into(),
                filters: vec![],
                coalesce_seconds: 10,
                max_batch_age_ms: None,
                max_wakes_per_hour: None,
                mode: DeliveryMode::Full,
            }],
            t0,
        )
        .unwrap();
    db.events()
        .ingest("local", "t1", "p", &sample_event("e1", "s", "t", "r/1"), t0)
        .unwrap();
    assert_eq!(db.events().list_batches("sub-x").unwrap().len(), 1);

    // Cross-subscriber ID theft fails closed.
    let theft = db.events().set_subscriptions(
        "sess-b",
        &[SubscriptionSpec {
            id: "sub-x".into(),
            origin_node: "local".into(),
            topic: "t1".into(),
            subscriber: "sess-b".into(),
            filters: vec![],
            coalesce_seconds: 0,
            max_batch_age_ms: None,
            max_wakes_per_hour: None,
            mode: DeliveryMode::Full,
        }],
        t0 + 1,
    );
    assert!(matches!(theft, Err(StoreError::IdConflict(_))));

    // Topic change deletes old topic's batches.
    db.events()
        .set_subscriptions(
            "sess-a",
            &[SubscriptionSpec {
                id: "sub-x".into(),
                origin_node: "local".into(),
                topic: "t2".into(),
                subscriber: "sess-a".into(),
                filters: vec![],
                coalesce_seconds: 10,
                max_batch_age_ms: None,
                max_wakes_per_hour: None,
                mode: DeliveryMode::Full,
            }],
            t0 + 2,
        )
        .unwrap();
    assert!(db.events().list_batches("sub-x").unwrap().is_empty());

    // 3. Staged transfer file deleted on SHA-256 mismatch, and remove_node cleans blobs.
    let part = db.transfers().staging_path("tx-staged").unwrap();
    fs::write(&part, b"payload").unwrap();
    let bad = db.transfers().commit_staged_file(
        &TransferSubmit {
            id: "tx-staged".into(),
            from_node: "alice@mac".into(),
            to_node: "bob@lap".into(),
            transfer_type: "files".into(),
            header_json: "{}".into(),
            expected_sha256: Some("deadbeef".into()),
            expires_at: t0 + 10_000,
        },
        &part,
        t0,
    );
    assert!(bad.is_err());
    assert!(
        !part.exists(),
        "failed staged upload must delete .part file"
    );

    db.transfers()
        .submit(
            &TransferSubmit {
                id: "tx-rev".into(),
                from_node: "alice@mac".into(),
                to_node: "bob@lap".into(),
                transfer_type: "files".into(),
                header_json: "{}".into(),
                expected_sha256: None,
                expires_at: t0 + 10_000,
            },
            b"secret",
            t0,
        )
        .unwrap();
    assert_eq!(db.transfers().remove_node("bob@lap", t0 + 100).unwrap(), 1);
    assert!(!db.transfers_dir().join("tx-rev").exists());
}

#[test]
fn v060_backend_merge_and_metadata_read_helpers() {
    let db = NodeDb::open_in_memory().unwrap();
    let t0 = 1_700_000_000_000i64;

    // 1. merge_session_backend + register_session preserve persisted Herdr & thread metadata.
    let s1 = db
        .local()
        .merge_session_backend(
            "claude:s1",
            &serde_json::json!({
                "kind": "claude",
                "herdrTerminalId": "t4g",
                "herdrCreatedMs": 1_700_000_111_000i64,
                "cwd": "/work/repo"
            }),
            t0,
        )
        .unwrap();
    let parsed1: serde_json::Value = serde_json::from_str(&s1.backend_json).unwrap();
    assert_eq!(parsed1["herdrTerminalId"], "t4g");
    assert_eq!(parsed1["herdrCreatedMs"], 1_700_000_111_000i64);

    // Subsequent bare register_session must NOT clobber persisted herdrTerminalId / herdrCreatedMs / cwd.
    let s1_after = db
        .local()
        .register_session("claude:s1", r#"{"kind":"claude"}"#, t0 + 500)
        .unwrap();
    let parsed_after: serde_json::Value = serde_json::from_str(&s1_after.backend_json).unwrap();
    assert_eq!(parsed_after["kind"], "claude");
    assert_eq!(parsed_after["herdrTerminalId"], "t4g");
    assert_eq!(parsed_after["herdrCreatedMs"], 1_700_000_111_000i64);
    assert_eq!(parsed_after["cwd"], "/work/repo");

    // Null fields in merge_session_backend never wipe existing keys; non-objects fail closed.
    let s1_merged = db
        .local()
        .merge_session_backend(
            "claude:s1",
            &serde_json::json!({ "herdrTerminalId": null, "codexThreadId": "thr-9" }),
            t0 + 600,
        )
        .unwrap();
    let parsed_merged: serde_json::Value = serde_json::from_str(&s1_merged.backend_json).unwrap();
    assert_eq!(parsed_merged["herdrTerminalId"], "t4g");
    assert_eq!(parsed_merged["codexThreadId"], "thr-9");

    assert!(matches!(
        db.local()
            .merge_session_backend("claude:s1", &serde_json::json!("not-an-object"), t0),
        Err(StoreError::InvalidInput(_))
    ));
    assert!(matches!(
        db.local()
            .merge_session_backend("", &serde_json::json!({}), t0),
        Err(StoreError::InvalidInput(_))
    ));

    // 2. list_sessions_by_herdr_terminal filters cleanly and orders by last_seen DESC.
    db.local()
        .merge_session_backend(
            "codex:s2",
            &serde_json::json!({ "kind": "codex", "herdrTerminalId": "t4g" }),
            t0 + 900,
        )
        .unwrap();
    db.local()
        .merge_session_backend(
            "claude:other",
            &serde_json::json!({ "kind": "claude", "herdrTerminalId": "t9z" }),
            t0 + 950,
        )
        .unwrap();
    let on_t4g = db.local().list_sessions_by_herdr_terminal("t4g").unwrap();
    let ids: Vec<&str> = on_t4g.iter().map(|s| s.id.as_str()).collect();
    assert_eq!(ids, vec!["codex:s2", "claude:s1"]);
    assert!(
        db.local()
            .list_sessions_by_herdr_terminal("")
            .unwrap()
            .is_empty()
    );

    // 3. list_pending_metadata & quarantined_count never include quarantined or delivered items.
    db.local()
        .put_in_mailbox(
            &MailboxInsert {
                session_id: "claude:s1".into(),
                origin_node: "bob@lap".into(),
                item_id: "dm-1".into(),
                text: "SECRET_PENDING_BODY".into(),
                kind: MailboxKind::Message,
                source: "bob@lap/reviewer".into(),
                gate_state: GateState::Pending,
                gate_reason: None,
                traceparent: None,
            },
            t0 + 1_000,
        )
        .unwrap();
    db.local()
        .put_in_mailbox(
            &MailboxInsert {
                session_id: "claude:s1".into(),
                origin_node: "local".into(),
                item_id: "ev-2".into(),
                text: "SECRET_EVENT_BODY".into(),
                kind: MailboxKind::Event,
                source: "local.github".into(),
                gate_state: GateState::Pending,
                gate_reason: None,
                traceparent: None,
            },
            t0 + 2_000,
        )
        .unwrap();
    db.local()
        .put_in_mailbox(
            &MailboxInsert {
                session_id: "claude:s1".into(),
                origin_node: "evil@host".into(),
                item_id: "q-1".into(),
                text: "SECRET_QUARANTINED_BODY".into(),
                kind: MailboxKind::Message,
                source: "evil@host/attacker".into(),
                gate_state: GateState::Quarantined,
                gate_reason: Some("prompt_injection".into()),
                traceparent: None,
            },
            t0 + 3_000,
        )
        .unwrap();

    let meta = db.local().list_pending_metadata("claude:s1", 10).unwrap();
    assert_eq!(meta.len(), 2);
    assert_eq!(meta[0].item_id, "ev-2");
    assert_eq!(meta[1].item_id, "dm-1");
    assert_eq!(db.local().quarantined_count(Some("claude:s1")).unwrap(), 1);
    assert_eq!(db.local().quarantined_count(Some("codex:s2")).unwrap(), 0);
    assert_eq!(db.local().quarantined_count(None).unwrap(), 1);

    // 4. list_channels_for_address returns sorted channel memberships for an address.
    db.messages()
        .register_handle("alice@mac", "alice", Some("claude:s1"), t0)
        .unwrap();
    db.channels()
        .join("alice@mac", "#release", "alice@mac", "alice", t0)
        .unwrap();
    db.channels()
        .join("alice@mac", "#ops", "alice@mac", "alice", t0)
        .unwrap();
    let joined = db
        .channels()
        .list_channels_for_address("alice@mac/alice")
        .unwrap();
    assert_eq!(
        joined,
        vec![
            ("alice@mac".to_string(), "#ops".to_string()),
            ("alice@mac".to_string(), "#release".to_string()),
        ]
    );

    // 5. delete_subscription_for_subscriber fails closed on wrong subscriber!
    db.events()
        .upsert_subscription(
            &SubscriptionSpec {
                id: "sub-owned-by-s1".into(),
                origin_node: "local".into(),
                topic: "github".into(),
                subscriber: "claude:s1".into(),
                filters: vec![Filter::exact("type", "pr.opened")],
                coalesce_seconds: 15,
                max_batch_age_ms: None,
                max_wakes_per_hour: None,
                mode: DeliveryMode::Full,
            },
            t0,
        )
        .unwrap();
    assert!(
        !db.events()
            .delete_subscription_for_subscriber("sub-owned-by-s1", "codex:s2")
            .unwrap()
    );
    assert!(
        db.events()
            .get_subscription("sub-owned-by-s1")
            .unwrap()
            .is_some()
    );
    assert!(
        db.events()
            .delete_subscription_for_subscriber("sub-owned-by-s1", "claude:s1")
            .unwrap()
    );
    assert!(
        db.events()
            .get_subscription("sub-owned-by-s1")
            .unwrap()
            .is_none()
    );
}

#[test]
fn ur1_prune_sessions_preserves_unread_pending_and_quarantined_mail() {
    let db = NodeDb::open_in_memory().unwrap();
    let t0 = 1_700_000_000_000i64;

    db.local().register_session("s-pending", "{}", t0).unwrap();
    db.local()
        .register_session("s-quarantined", "{}", t0)
        .unwrap();
    db.local()
        .register_session("s-delivered", "{}", t0)
        .unwrap();
    db.local().register_session("s-empty", "{}", t0).unwrap();

    db.local()
        .put_in_mailbox(
            &MailboxInsert {
                session_id: "s-pending".into(),
                origin_node: "bob@lap".into(),
                item_id: "p1".into(),
                text: "unread important DM".into(),
                kind: MailboxKind::Message,
                source: "bob@lap/dev".into(),
                gate_state: GateState::Pending,
                gate_reason: None,
                traceparent: None,
            },
            t0,
        )
        .unwrap();
    db.local()
        .put_in_mailbox(
            &MailboxInsert {
                session_id: "s-quarantined".into(),
                origin_node: "ext@host".into(),
                item_id: "q1".into(),
                text: "quarantined payload".into(),
                kind: MailboxKind::Message,
                source: "ext@host/bot".into(),
                gate_state: GateState::Quarantined,
                gate_reason: Some("prompt_injection".into()),
                traceparent: None,
            },
            t0,
        )
        .unwrap();
    db.local()
        .put_in_mailbox(
            &MailboxInsert {
                session_id: "s-delivered".into(),
                origin_node: "bob@lap".into(),
                item_id: "d1".into(),
                text: "already read".into(),
                kind: MailboxKind::Message,
                source: "bob@lap/dev".into(),
                gate_state: GateState::Pending,
                gate_reason: None,
                traceparent: None,
            },
            t0,
        )
        .unwrap();
    db.local().drain_inbox("s-delivered", 10, t0 + 100).unwrap();

    let report = db
        .local()
        .prune_sessions(t0 + 10_000, &HashSet::new())
        .unwrap();
    let pruned: HashSet<String> = report.pruned_sessions.into_iter().collect();
    assert!(pruned.contains("s-empty"));
    assert!(pruned.contains("s-delivered"));
    assert!(!pruned.contains("s-pending"));
    assert!(!pruned.contains("s-quarantined"));

    assert_eq!(db.local().pending_count("s-pending").unwrap(), 1);
    assert_eq!(
        db.local().quarantined_count(Some("s-quarantined")).unwrap(),
        1
    );
}

#[test]
fn g3_coalesce_update_resets_reviewed_at_human_auth_and_gate_reason() {
    let db = NodeDb::open_in_memory().unwrap();
    let t0 = 1_700_000_000_000i64;
    db.local().register_session("claude:s1", "{}", t0).unwrap();

    let opts = hyp_store::MailboxPutOptions {
        coalesce_key: Some("feed:alerts".into()),
        expires_at: Some(t0 + 60_000),
    };
    let receipt = match db
        .local()
        .put_in_mailbox_ex(
            &MailboxInsert {
                session_id: "claude:s1".into(),
                origin_node: "local".into(),
                item_id: "ev-1".into(),
                text: "Verified initial alert".into(),
                kind: MailboxKind::Event,
                source: "local.alerts".into(),
                gate_state: GateState::Pending,
                gate_reason: Some("downgraded_to_notify".into()),
                traceparent: None,
            },
            &opts,
            t0,
        )
        .unwrap()
    {
        MailboxPutResult::Stored { receipt } => receipt,
        other => panic!("expected Stored, got {other:?}"),
    };

    // Simulate prior gate approval + HumanVerified cryptographic badge + notified = 1.
    assert!(
        db.local()
            .mark_mailbox_gate_approved(
                "claude:s1",
                &receipt,
                Some("downgraded_to_notify"),
                t0 + 10
            )
            .unwrap()
    );
    assert!(
        db.human()
            .set_mailbox_human_auth(&receipt, r#"{"humanId":"alice","kid":"k1"}"#)
            .unwrap()
    );
    db.local().mark_mailbox_notified("claude:s1").unwrap();

    let before = db.local().get_mailbox_entry(&receipt).unwrap().unwrap();
    assert!(before.reviewed_at.is_some());
    assert_eq!(before.gate_reason.as_deref(), Some("downgraded_to_notify"));
    assert!(before.notified);
    assert!(
        db.human()
            .get_mailbox_human_auth(&receipt)
            .unwrap()
            .is_some()
    );

    // Coalesce a new untrusted payload onto the same receipt!
    let receipt2 = match db
        .local()
        .put_in_mailbox_ex(
            &MailboxInsert {
                session_id: "claude:s1".into(),
                origin_node: "local".into(),
                item_id: "ev-2".into(),
                text: "UNTRUSTED OVERWRITTEN PAYLOAD".into(),
                kind: MailboxKind::Event,
                source: "local.alerts".into(),
                gate_state: GateState::Pending,
                gate_reason: Some("stale_hint".into()),
                traceparent: None,
            },
            &opts,
            t0 + 20,
        )
        .unwrap()
    {
        MailboxPutResult::Stored { receipt } => receipt,
        other => panic!("expected Stored on coalesce, got {other:?}"),
    };
    assert_eq!(receipt2, receipt);

    let after = db.local().get_mailbox_entry_ex(&receipt).unwrap().unwrap();
    assert_eq!(after.entry.item_id, "ev-2");
    assert_eq!(after.entry.text, "UNTRUSTED OVERWRITTEN PAYLOAD");
    assert_eq!(after.missed_count, 1);
    assert!(!after.entry.notified);
    assert!(
        after.entry.reviewed_at.is_none(),
        "G3: coalesce MUST reset reviewed_at to NULL"
    );
    assert!(
        after.entry.gate_reason.is_none(),
        "G3: coalesce MUST reset gate_reason to NULL"
    );
    assert!(
        db.human()
            .get_mailbox_human_auth(&receipt)
            .unwrap()
            .is_none(),
        "G3: coalesce MUST reset human_auth_json to NULL"
    );
    assert!(
        db.local()
            .peek_inbox_with_visibility("claude:s1", 10, hyp_store::MailboxVisibility::GateCleared)
            .unwrap()
            .is_empty(),
        "G3: coalesced row must NOT appear in gate-cleared inbox until re-screened"
    );
    let local = db.local();
    let gated = hyp_store::MailboxVisibility::GateCleared;
    assert_eq!(local.pending_count("claude:s1").unwrap(), 1);
    assert_eq!(
        local
            .pending_count_with_visibility("claude:s1", gated)
            .unwrap(),
        0
    );
    assert_eq!(local.unread_digest("claude:s1").unwrap().unread, 1);
    let digest = local
        .unread_digest_with_visibility("claude:s1", gated)
        .unwrap();
    assert_eq!(digest.unread, 0);
    assert!(digest.sources.is_empty());
    assert_eq!(
        local.list_pending_metadata("claude:s1", 10).unwrap().len(),
        1
    );
    assert!(
        local
            .list_pending_metadata_with_visibility("claude:s1", 10, gated)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn subscription_meta_persists_across_reopen_and_cleans_up_atomically() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("node.sqlite");
    let t0 = 1_700_000_000_000i64;

    {
        let db = NodeDb::open(&db_path).unwrap();
        db.events()
            .upsert_subscription(
                &SubscriptionSpec {
                    id: "sub-1".into(),
                    origin_node: "alice@macbook".into(),
                    topic: "agentmail".into(),
                    subscriber: "claude:s1".into(),
                    filters: vec![],
                    coalesce_seconds: 0,
                    max_batch_age_ms: None,
                    max_wakes_per_hour: None,
                    mode: DeliveryMode::Full,
                },
                t0,
            )
            .unwrap();
        db.events()
            .set_subscription_meta(
                "sub-1",
                &hyp_store::SubscriptionMeta {
                    key: Some("gmail:bowd".into()),
                    urgency: Some("interrupt".into()),
                },
            )
            .unwrap();

        db.events()
            .upsert_subscription(
                &SubscriptionSpec {
                    id: "sub-2".into(),
                    origin_node: "alice@macbook".into(),
                    topic: "github".into(),
                    subscriber: "claude:s2".into(),
                    filters: vec![],
                    coalesce_seconds: 0,
                    max_batch_age_ms: None,
                    max_wakes_per_hour: None,
                    mode: DeliveryMode::Notify,
                },
                t0 + 1,
            )
            .unwrap();
        db.events()
            .set_subscription_meta(
                "sub-2",
                &hyp_store::SubscriptionMeta {
                    key: Some("gh:org".into()),
                    urgency: Some("notify".into()),
                },
            )
            .unwrap();
    }

    // Reopen fresh NodeDb from disk and verify metadata & lookup by key survive intact.
    let db = NodeDb::open(&db_path).unwrap();
    let meta1 = db
        .events()
        .get_subscription_meta("sub-1")
        .unwrap()
        .expect("persisted meta for sub-1");
    assert_eq!(meta1.key.as_deref(), Some("gmail:bowd"));
    assert_eq!(meta1.urgency.as_deref(), Some("interrupt"));

    let found = db
        .events()
        .find_subscription_by_key("claude:s1", "gmail:bowd")
        .unwrap()
        .expect("find_subscription_by_key must locate persisted key");
    assert_eq!(found.id, "sub-1");
    assert!(
        db.events()
            .find_subscription_by_key("claude:s2", "gmail:bowd")
            .unwrap()
            .is_none(),
        "key lookup must be scoped per subscriber"
    );

    // Wrong subscriber delete fails closed and preserves metadata!
    assert!(
        !db.events()
            .delete_subscription_for_subscriber("sub-1", "claude:s2")
            .unwrap()
    );
    assert!(
        db.events()
            .get_subscription_meta("sub-1")
            .unwrap()
            .is_some()
    );

    // Owner delete removes both subscription and persisted metadata atomically.
    assert!(
        db.events()
            .delete_subscription_for_subscriber("sub-1", "claude:s1")
            .unwrap()
    );
    assert!(
        db.events()
            .get_subscription_meta("sub-1")
            .unwrap()
            .is_none()
    );

    // `remove_subscriber` cleans up metadata atomically too.
    assert_eq!(db.events().remove_subscriber("claude:s2").unwrap(), 1);
    assert!(
        db.events()
            .get_subscription_meta("sub-2")
            .unwrap()
            .is_none()
    );
    assert!(db.events().list_subscription_meta().unwrap().is_empty());
}

#[test]
fn topic_event_stats_normalizes_bare_and_local_prefixed_topics_and_extracts_repos() {
    let db = NodeDb::open_in_memory().unwrap();
    let t0 = 1_700_000_000_000i64;

    let make_ev = |id: &str, source: &str| CloudEvent {
        specversion: "1.0".into(),
        id: id.into(),
        source: source.into(),
        event_type: "com.example.test".into(),
        subject: None,
        time: None,
        datacontenttype: "application/json".into(),
        dataschema: None,
        data: json!({ "ok": true }),
        extensions: Default::default(),
    };

    // Bare topic under node_id + local-prefixed topic under "local" fold into one "agentmail" bucket.
    db.events()
        .ingest(
            "alice@macbook",
            "agentmail",
            "pub-1",
            &make_ev("ev-1", "agentmail://inbox/a"),
            t0,
        )
        .unwrap();
    db.events()
        .ingest(
            "local",
            "local.agentmail",
            "pub-1",
            &make_ev("ev-2", "agentmail://inbox/b"),
            t0 + 50,
        )
        .unwrap();

    // GitHub event ingested with 0 subscribers (so `body` is cleared to NULL on ingest)
    // still extracts `owner/repo` from `source = "github.com/acme/checkout"`.
    db.events()
        .ingest(
            "alice@macbook",
            "github",
            "gh-adapter",
            &make_ev("gh-1", "github.com/acme/checkout"),
            t0 + 100,
        )
        .unwrap();

    // Remote peer event on a different origin_node MUST NOT be counted in local stats.
    db.events()
        .ingest(
            "remote-hub",
            "agentmail",
            "remote-pub",
            &make_ev("remote-1", "agentmail://remote"),
            t0 + 200,
        )
        .unwrap();

    let stats = db
        .events()
        .topic_event_stats(&["alice@macbook", "local"])
        .unwrap();

    let am = stats.get("agentmail").expect("agentmail stats");
    assert_eq!(am.event_count, 2);
    assert_eq!(am.last_received_at, Some(t0 + 50));
    assert_eq!(
        am.sources,
        vec![
            "agentmail://inbox/a".to_string(),
            "agentmail://inbox/b".to_string()
        ]
    );

    let gh = stats.get("github").expect("github stats");
    assert_eq!(gh.event_count, 1);
    assert_eq!(gh.repos, vec!["acme/checkout".to_string()]);
}
