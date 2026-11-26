//! Multi-connection WAL concurrency & `PRAGMA data_version` cache invalidation tests.

use std::sync::{Arc, Barrier};
use std::thread;

use hyp_store::{
    AckOutcome, CloudEvent, DeliveryMode, Filter, GrantDirection, GrantInput, KvSetInput, NodeDb,
    StoreError, SubscriptionSpec, TrustTier, WriteModel,
};
use serde_json::json;
use tempfile::TempDir;

#[test]
fn multi_connection_wal_pragma_data_version_invalidates_filter_cache() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("node.sqlite");
    let t0 = 1_700_000_000_000i64;

    let conn_a = NodeDb::open(&db_path).unwrap();
    let conn_b = NodeDb::open(&db_path).unwrap();

    // Conn A registers subscription 1 on (acme-team, github) for repo "acme/checkout".
    conn_a
        .events()
        .upsert_subscription(
            &SubscriptionSpec {
                id: "sub-a".into(),
                origin_node: "acme-team".into(),
                topic: "github".into(),
                subscriber: "sess-a".into(),
                filters: vec![Filter::exact("repo", "acme/checkout")],
                coalesce_seconds: 0,
                max_batch_age_ms: None,
                max_wakes_per_hour: None,
                mode: DeliveryMode::Full,
            },
            t0,
        )
        .unwrap();

    // Ingest 2 events via Conn A: 1st warms cache (miss), 2nd hits cache (hit).
    let ev1 = CloudEvent::new(
        "ev-1",
        "github.com/acme/checkout",
        "com.github.pr",
        json!({}),
    )
    .with_extension("repo", "acme/checkout");
    let ev2 = CloudEvent::new(
        "ev-2",
        "github.com/acme/checkout",
        "com.github.pr",
        json!({}),
    )
    .with_extension("repo", "acme/checkout");
    assert_eq!(
        conn_a
            .events()
            .ingest("acme-team", "github", "gh", &ev1, t0 + 1)
            .unwrap()
            .matched,
        1
    );
    assert_eq!(
        conn_a
            .events()
            .ingest("acme-team", "github", "gh", &ev2, t0 + 2)
            .unwrap()
            .matched,
        1
    );
    let stats_before = conn_a.events().cache_stats();
    assert_eq!(stats_before.misses, 1);
    assert_eq!(stats_before.hits, 1);

    // Now Conn B (a completely separate SQLite connection!) adds subscription 2 for "acme/payments".
    conn_b
        .events()
        .upsert_subscription(
            &SubscriptionSpec {
                id: "sub-b".into(),
                origin_node: "acme-team".into(),
                topic: "github".into(),
                subscriber: "sess-b".into(),
                filters: vec![Filter::exact("repo", "acme/payments")],
                coalesce_seconds: 0,
                max_batch_age_ms: None,
                max_wakes_per_hour: None,
                mode: DeliveryMode::Full,
            },
            t0 + 10,
        )
        .unwrap();

    // Conn A ingests a payments event WITHOUT any out-of-band cache invalidation call.
    // `PRAGMA data_version` detects Conn B's commit, invalidates Conn A's compiled filter cache,
    // and routes the event to `sub-b` immediately!
    let ev_pay = CloudEvent::new(
        "ev-pay",
        "github.com/acme/payments",
        "com.github.pr",
        json!({}),
    )
    .with_extension("repo", "acme/payments");
    let res = conn_a
        .events()
        .ingest("acme-team", "github", "gh", &ev_pay, t0 + 20)
        .unwrap();
    assert_eq!(
        res.matched, 1,
        "Conn A must see Conn B's newly added subscription"
    );

    let stats_after = conn_a.events().cache_stats();
    assert!(
        stats_after.invalidations > stats_before.invalidations,
        "PRAGMA data_version change must trigger cache invalidation"
    );
    assert_eq!(stats_after.misses, 2);

    let due_b = conn_b
        .events()
        .claim_due_batches("sess-b", t0 + 20)
        .unwrap();
    assert_eq!(due_b.len(), 1);
    assert_eq!(due_b[0].events[0].id, "ev-pay");

    // Now Conn B deletes `sub-b`; Conn A must immediately stop matching `acme/payments`.
    assert!(conn_b.events().delete_subscription("sub-b").unwrap());
    let ev_pay2 = CloudEvent::new(
        "ev-pay-2",
        "github.com/acme/payments",
        "com.github.pr",
        json!({}),
    )
    .with_extension("repo", "acme/payments");
    let res2 = conn_a
        .events()
        .ingest("acme-team", "github", "gh", &ev_pay2, t0 + 30)
        .unwrap();
    assert_eq!(
        res2.matched, 0,
        "Conn A must drop deleted subscription via PRAGMA data_version"
    );
}

#[test]
fn multi_thread_wal_concurrent_kv_cas_and_atomic_event_emission() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("node.sqlite");
    let t0 = 1_700_000_000_000i64;

    // Seed watcher subscription on `local.kv` before threads race.
    {
        let db = NodeDb::open(&db_path).unwrap();
        db.events()
            .upsert_subscription(
                &SubscriptionSpec {
                    id: "kv-counter-sub".into(),
                    origin_node: "local".into(),
                    topic: "kv".into(),
                    subscriber: "counter-watcher".into(),
                    filters: vec![
                        Filter::exact("ns", "bench"),
                        Filter::exact("key", "counter"),
                    ],
                    coalesce_seconds: 0,
                    max_batch_age_ms: None,
                    max_wakes_per_hour: None,
                    mode: DeliveryMode::Full,
                },
                t0,
            )
            .unwrap();
    }

    let threads = 4usize;
    let increments_per_thread = 20usize;
    let barrier = Arc::new(Barrier::new(threads));
    let mut handles = Vec::new();

    for tid in 0..threads {
        let path = db_path.clone();
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let db = NodeDb::open(&path).unwrap();
            barrier.wait();
            let mut conflicts = 0usize;
            for step in 0..increments_per_thread {
                loop {
                    let current = db.kv().get("local", "bench", "counter", t0 + 1000).unwrap();
                    let (ver, val) = match current {
                        Some(entry) => (entry.version, entry.value.as_u64().unwrap()),
                        None => (0u64, 0u64),
                    };
                    match db.kv().set(
                        &KvSetInput {
                            host_node: "local".into(),
                            namespace: "bench".into(),
                            key: "counter".into(),
                            value: json!(val + 1),
                            content_type: None,
                            write_model: WriteModel::Shared,
                            owner_id: None,
                            allowlist: None,
                            writer_id: format!("worker-{tid}"),
                            expected_version: Some(ver),
                            e2ee_epoch: None,
                            signature: None,
                            ttl_ms: None,
                        },
                        t0 + 1000 + (step as i64),
                    ) {
                        Ok(_) => break,
                        Err(StoreError::VersionConflict { .. }) => {
                            conflicts += 1;
                            continue;
                        }
                        Err(other) => panic!("unexpected error in WAL CAS race: {other}"),
                    }
                }
            }
            conflicts
        }));
    }

    let total_conflicts: usize = handles.into_iter().map(|h| h.join().unwrap()).sum();
    let expected_total = (threads * increments_per_thread) as u64;

    let db = NodeDb::open(&db_path).unwrap();
    let final_entry = db
        .kv()
        .get("local", "bench", "counter", t0 + 5_000)
        .unwrap()
        .unwrap();
    assert_eq!(final_entry.version, expected_total);
    assert_eq!(final_entry.value.as_u64(), Some(expected_total));
    let _ = total_conflicts; // conflicts occur naturally under thread scheduling

    // Verify EVERY single atomic KV write emitted exactly 1 CloudEvent batch (no lost updates!).
    let mut delivered_versions = Vec::new();
    let mut now = t0 + 5_000;
    while let Some(batch) = db
        .events()
        .claim_due_batches("counter-watcher", now)
        .unwrap()
        .into_iter()
        .next()
    {
        for ev in &batch.events {
            let v: u64 = ev.extensions.get("version").unwrap().parse().unwrap();
            delivered_versions.push(v);
        }
        db.events()
            .ack_batch("counter-watcher", &batch.id, &AckOutcome::Delivered, now)
            .unwrap();
        // Advance clock by 1h every 25 acks to stay under default 30/hr wake cap during drain.
        if delivered_versions.len() % 25 == 0 {
            now += 60 * 60 * 1000 + 1;
        }
    }
    delivered_versions.sort_unstable();
    let expected_versions: Vec<u64> = (1..=expected_total).collect();
    assert_eq!(delivered_versions, expected_versions);
}

#[test]
fn multi_thread_wal_single_use_grant_claim_and_event_idempotency_race() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("node.sqlite");
    let t0 = 1_700_000_000_000i64;

    {
        let db = NodeDb::open(&db_path).unwrap();
        db.peers()
            .add_grant(
                &GrantInput {
                    id: "one-shot-grant".into(),
                    peer_id: "bob@lap".into(),
                    direction: GrantDirection::Inbound,
                    signed_json: r#"{"payload":"p","sig":"s"}"#.into(),
                    scopes: vec!["dm:send".into()],
                    trust_tier: TrustTier::Peer,
                    issued_at: t0,
                    pair_by: Some(t0 + 60_000),
                    expires_at: None,
                },
                t0,
            )
            .unwrap();
        db.events()
            .upsert_subscription(
                &SubscriptionSpec {
                    id: "dedup-sub".into(),
                    origin_node: "local".into(),
                    topic: "hooks".into(),
                    subscriber: "sess-1".into(),
                    filters: vec![],
                    coalesce_seconds: 0,
                    max_batch_age_ms: None,
                    max_wakes_per_hour: None,
                    mode: DeliveryMode::Full,
                },
                t0,
            )
            .unwrap();
    }

    let n = 6usize;
    let barrier = Arc::new(Barrier::new(n));
    let mut handles = Vec::new();
    for tid in 0..n {
        let path = db_path.clone();
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let db = NodeDb::open(&path).unwrap();
            barrier.wait();
            let claim_won = match db.peers().claim_grant(
                "one-shot-grant",
                &format!("{{\"claimer\":{tid}}}"),
                t0 + 100,
            ) {
                Ok(_) => true,
                Err(StoreError::AlreadyPaired(_)) => false,
                Err(other) => panic!("unexpected claim error: {other}"),
            };

            let ev = CloudEvent::new("same-event-id", "hook/src", "hook.fired", json!({ "k": 1 }));
            let ingest = db
                .events()
                .ingest("local", "hooks", "pub-1", &ev, t0 + 200)
                .unwrap();
            (claim_won, !ingest.deduplicated)
        }));
    }

    let results: Vec<(bool, bool)> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let claim_winners = results.iter().filter(|(won, _)| *won).count();
    let fresh_ingests = results.iter().filter(|(_, fresh)| *fresh).count();
    assert_eq!(
        claim_winners, 1,
        "exactly one thread must win single-use grant claim"
    );
    assert_eq!(
        fresh_ingests, 1,
        "exactly one thread must record fresh event"
    );

    let db = NodeDb::open(&db_path).unwrap();
    let batches = db.events().list_batches("dedup-sub").unwrap();
    assert_eq!(
        batches.len(),
        1,
        "idempotent race must create exactly 1 batch"
    );
    assert_eq!(batches[0].event_count, 1);
}
