//! End-to-end concurrency, anti-rollback, digest tamper-sensitivity, deadline-scheduler
//! pruning, and v1->v2->v3->v4 schema migration tests for `HumanAuthorityStore`.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::sync::{Arc, Barrier};
use std::thread;

use hyp_store::{
    CURRENT_SCHEMA_VERSION, GateState, HumanAuthorityInput, HumanAuthorityRole,
    HumanAuthorityStatus, HumanClaimKind, HumanDelegationPolicyInput, HumanNodeCertInput,
    MailboxInsert, MailboxKind, MailboxPutResult, NodeDb, PeerInput, PeerProfile, PeerStatus,
    StoreError, TrustTier,
};
use rusqlite::{Connection, OpenFlags, params};
use tempfile::TempDir;

const SCHEMA_V1_SQL: &str = include_str!("../migrations/0001_initial_v2.sql");
const SCHEMA_V2_SQL: &str = include_str!("../migrations/0002_discovery_and_routes.sql");
const SCHEMA_V3_SQL: &str = include_str!("../migrations/0003_wakeups.sql");
const SCHEMA_V4_SQL: &str = include_str!("../migrations/0004_human_authority.sql");
const SCHEMA_V5_SQL: &str = include_str!("../migrations/0005_human_enc_jwk.sql");
const SCHEMA_V6_SQL: &str = include_str!("../migrations/0006_muted_sources_expires_at.sql");
const SCHEMA_V7_SQL: &str = include_str!("../migrations/0007_delegated_human_admission.sql");

const T0: i64 = 1_795_554_000_000;

fn sample_jwk(x: &str) -> String {
    format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{x}"}}"#)
}

fn sample_enc_jwk(x: &str) -> String {
    format!(r#"{{"crv":"X25519","kty":"OKP","x":"{x}"}}"#)
}

fn sample_authority(
    human_id: &str,
    kid: &str,
    role: HumanAuthorityRole,
    epoch: u64,
) -> HumanAuthorityInput {
    HumanAuthorityInput {
        human_id: human_id.to_string(),
        kid: kid.to_string(),
        label: format!("{human_id}-{kid}"),
        role,
        jwk_json: sample_jwk(&format!("key_{kid}")),
        enc_jwk_json: None,
        prf_salt: if role == HumanAuthorityRole::Signer {
            Some(format!("salt_{kid}"))
        } else {
            None
        },
        auth_epoch: epoch,
    }
}

fn snapshot_tables_and_columns(conn: &Connection) -> BTreeMap<String, Vec<String>> {
    let mut tables = BTreeMap::new();
    let mut stmt = conn
        .prepare(
            "SELECT name FROM sqlite_master
             WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
             ORDER BY name ASC",
        )
        .unwrap();
    let names: Vec<String> = stmt
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    for name in names {
        let mut cstmt = conn
            .prepare(&format!("PRAGMA table_info(\"{name}\")"))
            .unwrap();
        let cols: Vec<String> = cstmt
            .query_map([], |r| {
                let col_name: String = r.get(1)?;
                let col_type: String = r.get(2)?;
                let notnull: i64 = r.get(3)?;
                let dflt: Option<String> = r.get(4)?;
                let pk: i64 = r.get(5)?;
                Ok(format!("{col_name}:{col_type}:{notnull}:{dflt:?}:{pk}"))
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        tables.insert(name, cols);
    }
    tables
}

fn snapshot_indexes(conn: &Connection) -> BTreeMap<String, (String, Option<String>)> {
    let mut stmt = conn
        .prepare(
            "SELECT name, tbl_name, sql FROM sqlite_master
             WHERE type = 'index' AND name NOT LIKE 'sqlite_%'
             ORDER BY name ASC",
        )
        .unwrap();
    stmt.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            (r.get::<_, String>(1)?, r.get::<_, Option<String>>(2)?),
        ))
    })
    .unwrap()
    .collect::<Result<BTreeMap<_, _>, _>>()
    .unwrap()
}

fn seed_db_at_version(path: &Path, version: i64) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let conn = Connection::open(path).unwrap();
    conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
    let _: String = conn
        .query_row("PRAGMA journal_mode = WAL", [], |r| r.get(0))
        .unwrap();
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER PRIMARY KEY,
            applied_at INTEGER NOT NULL
        );",
    )
    .unwrap();

    conn.execute_batch(SCHEMA_V1_SQL).unwrap();
    conn.execute(
        "INSERT INTO schema_version (version, applied_at) VALUES (1, ?1)",
        params![T0],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO sessions (id, backend_json, handle, last_seen, delivery_mode, created_at)
         VALUES ('sess-1', '{\"harness\":\"claude\"}', 'ops', ?1, 'full', ?1)",
        params![T0],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO mailbox (receipt, session_id, origin_node, item_id, text, received_at, kind, source, gate_state)
         VALUES ('rcpt-legacy', 'sess-1', 'local', 'item-1', 'pre-v4 message', ?1, 'message', 'local/bot', 'pending')",
        params![T0],
    )
    .unwrap();

    if version >= 2 {
        conn.execute_batch(SCHEMA_V2_SQL).unwrap();
        conn.execute(
            "INSERT INTO schema_version (version, applied_at) VALUES (2, ?1)",
            params![T0 + 1],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO peer_routes (target_node, via_peer, updated_at) VALUES ('bob@lap', 'acme-hub', ?1)",
            params![T0 + 1],
        )
        .unwrap();
    }

    if version >= 3 {
        conn.execute_batch(SCHEMA_V3_SQL).unwrap();
        conn.execute(
            "INSERT INTO schema_version (version, applied_at) VALUES (3, ?1)",
            params![T0 + 2],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO wakeups (id, target_session_id, label, note, trigger_kind, next_fire_at, created_at, updated_at)
             VALUES ('wk-v3', 'sess-1', 'check', 'run check', 'timer', ?1, ?2, ?2)",
            params![T0 + 60_000, T0 + 2],
        )
        .unwrap();
    }

    if version >= 4 {
        conn.execute_batch(SCHEMA_V4_SQL).unwrap();
        conn.execute(
            "INSERT INTO schema_version (version, applied_at) VALUES (4, ?1)",
            params![T0 + 3],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO human_authorities
                (human_id, kid, label, role, jwk_json, prf_salt, auth_epoch, status, created_at)
             VALUES ('bogdan', 'kid_v4_legacy', 'v4-passkey', 'signer', ?1, 'salt_v4', 1, 'active', ?2)",
            params![sample_jwk("v4_legacy_key"), T0 + 3],
        )
        .unwrap();
    }
}

#[test]
fn sixteen_thread_concurrent_consume_claim_nonce_race_allows_exactly_one() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("node.sqlite");
    let setup = NodeDb::open(&db_path).unwrap();
    drop(setup);

    let threads = 16usize;
    let rounds = 8usize;

    for round in 0..rounds {
        let claim_id = format!("claim_race_{round}_9f2aB7xQ_kL3mNp");
        let barrier = Arc::new(Barrier::new(threads));
        let mut joins = Vec::with_capacity(threads);

        for tid in 0..threads {
            let path = db_path.clone();
            let cid = claim_id.clone();
            let barrier = Arc::clone(&barrier);
            joins.push(thread::spawn(move || {
                let db =
                    NodeDb::open(&path).unwrap_or_else(|e| panic!("thread {tid} failed open: {e}"));
                barrier.wait();
                db.human()
                    .consume_claim_nonce(
                        &cid,
                        "human_kid_phone_1",
                        HumanClaimKind::Secret,
                        T0 + 600_000,
                        T0 + (tid as i64),
                    )
                    .unwrap_or_else(|e| panic!("thread {tid} round {round} failed consume: {e}"))
            }));
        }

        let mut winners = 0usize;
        let mut replays = 0usize;
        for j in joins {
            if j.join().unwrap() {
                winners += 1;
            } else {
                replays += 1;
            }
        }
        assert_eq!(
            winners, 1,
            "round {round}: EXACTLY 1 thread must win single-use nonce consumption"
        );
        assert_eq!(
            replays,
            threads - 1,
            "round {round}: all remaining {} threads must see replay (false)",
            threads - 1
        );
    }
}

#[test]
fn monotonic_min_auth_epoch_anti_rollback_and_revoked_key_non_resurrection() {
    let db = NodeDb::open_in_memory().unwrap();
    let human = db.human();

    assert_eq!(human.min_auth_epoch().unwrap(), 1);
    assert!(human.list_authorities(true).unwrap().is_empty());

    // Enroll laptop admin + two phone signer keys
    let admin = human
        .upsert_authority(
            &sample_authority("bogdan", "kid_admin_1", HumanAuthorityRole::Admin, 1),
            T0,
        )
        .unwrap();
    assert_eq!(admin.status, HumanAuthorityStatus::Active);
    assert_eq!(admin.role, HumanAuthorityRole::Admin);

    human
        .upsert_authority(
            &sample_authority("bogdan", "kid_phone_1", HumanAuthorityRole::Signer, 1),
            T0 + 1,
        )
        .unwrap();
    human
        .upsert_authority(
            &sample_authority("bogdan", "kid_phone_2", HumanAuthorityRole::Signer, 2),
            T0 + 2,
        )
        .unwrap();

    // Cross-human kid conflict fails closed
    assert!(matches!(
        human.upsert_authority(
            &sample_authority("alice", "kid_phone_1", HumanAuthorityRole::Signer, 1),
            T0 + 3,
        ),
        Err(StoreError::IdConflict(_))
    ));

    // Active lookups & listing
    assert!(
        human
            .get_active_authority_by_kid("kid_phone_1")
            .unwrap()
            .is_some()
    );
    assert_eq!(human.list_authorities(false).unwrap().len(), 3);

    // Revoke phone_1 and advance min_auth_epoch -> 4
    let rev1_json = r#"{"payload":"{}","sig":"sig1"}"#;
    let new_min = human
        .revoke_authority_monotonic("bogdan", "kid_phone_1", 4, rev1_json, T0 + 100)
        .unwrap();
    assert_eq!(new_min, 4);
    assert_eq!(human.min_auth_epoch().unwrap(), 4);
    assert_eq!(
        human.get_active_authority_by_kid("kid_phone_1").unwrap(),
        None
    );
    assert_eq!(human.list_authorities(false).unwrap().len(), 2);
    assert_eq!(human.list_authorities(true).unwrap().len(), 3);

    let revoked_rec = human
        .get_authority("bogdan", "kid_phone_1")
        .unwrap()
        .unwrap();
    assert_eq!(revoked_rec.status, HumanAuthorityStatus::Revoked);
    assert_eq!(revoked_rec.revoked_at, Some(T0 + 100));
    assert_eq!(revoked_rec.revocation_json.as_deref(), Some(rev1_json));

    // Attempting to resurrect a revoked key via upsert MUST fail closed!
    assert!(matches!(
        human.upsert_authority(
            &sample_authority("bogdan", "kid_phone_1", HumanAuthorityRole::Signer, 5),
            T0 + 200,
        ),
        Err(StoreError::InvalidState(_))
    ));

    // Revoking phone_2 with stale lower epoch (2 < 4) STILL revokes phone_2 AND NEVER rolls back min_auth_epoch!
    let rev2_json = r#"{"payload":"{}","sig":"sig2"}"#;
    let stayed_min = human
        .revoke_authority_monotonic("bogdan", "kid_phone_2", 2, rev2_json, T0 + 300)
        .unwrap();
    assert_eq!(stayed_min, 4, "min_auth_epoch must NEVER roll back below 4");
    assert_eq!(human.min_auth_epoch().unwrap(), 4);
    assert_eq!(
        human.get_active_authority_by_kid("kid_phone_2").unwrap(),
        None
    );

    // Unknown key revocation fails with NotFound
    assert!(matches!(
        human.revoke_authority_monotonic("bogdan", "kid_nonexistent", 10, rev2_json, T0 + 400),
        Err(StoreError::NotFound(_))
    ));
    assert_eq!(human.min_auth_epoch().unwrap(), 4);
}

#[test]
fn authorities_digest_is_order_independent_and_detects_every_mutation() {
    // Insertion order independence across two fresh DBs
    let db_a = NodeDb::open_in_memory().unwrap();
    let db_b = NodeDb::open_in_memory().unwrap();

    let k1 = sample_authority("alice", "kid_z", HumanAuthorityRole::Admin, 1);
    let k2 = sample_authority("bogdan", "kid_a", HumanAuthorityRole::Signer, 2);

    let d_empty = db_a.human().authorities_digest().unwrap();
    assert_eq!(d_empty.len(), 64);
    assert_eq!(d_empty, db_b.human().authorities_digest().unwrap());

    db_a.human().upsert_authority(&k1, T0).unwrap();
    db_a.human().upsert_authority(&k2, T0 + 1).unwrap();

    db_b.human().upsert_authority(&k2, T0 + 999).unwrap();
    db_b.human().upsert_authority(&k1, T0 + 500).unwrap();

    let d_both_a = db_a.human().authorities_digest().unwrap();
    let d_both_b = db_b.human().authorities_digest().unwrap();
    assert_eq!(
        d_both_a, d_both_b,
        "digest must be deterministic regardless of insertion order"
    );
    assert_ne!(d_both_a, d_empty);

    // Every security-relevant field mutation MUST alter authorities_digest()!
    let mut prev = d_both_a;

    // 1. Mutate role via raw SQLite tampering
    db_a.connection()
        .execute(
            "UPDATE human_authorities SET role = 'admin' WHERE human_id = 'bogdan' AND kid = 'kid_a'",
            [],
        )
        .unwrap();
    let d_role = db_a.human().authorities_digest().unwrap();
    assert_ne!(d_role, prev, "role tamper must change digest");
    prev = d_role;

    // 2. Mutate jwk_json via raw SQLite tampering
    db_a.connection()
        .execute(
            "UPDATE human_authorities SET jwk_json = '{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"EVIL\"}' WHERE kid = 'kid_a'",
            [],
        )
        .unwrap();
    let d_jwk = db_a.human().authorities_digest().unwrap();
    assert_ne!(d_jwk, prev, "jwk_json tamper must change digest");
    prev = d_jwk;

    // 2b. Set & mutate enc_jwk_json (both legitimate upgrade and raw SQLite tampering)
    assert!(
        db_a.human()
            .update_authority_enc_jwk("kid_a", &sample_enc_jwk("enc_legit_1"), T0 + 5)
            .unwrap()
    );
    let d_enc_set = db_a.human().authorities_digest().unwrap();
    assert_ne!(d_enc_set, prev, "setting enc_jwk_json must change digest");
    prev = d_enc_set;

    db_a.connection()
        .execute(
            "UPDATE human_authorities SET enc_jwk_json = '{\"crv\":\"X25519\",\"kty\":\"OKP\",\"x\":\"EVIL_ENC\"}' WHERE kid = 'kid_a'",
            [],
        )
        .unwrap();
    let d_enc_tamper = db_a.human().authorities_digest().unwrap();
    assert_ne!(d_enc_tamper, prev, "enc_jwk_json tamper must change digest");
    prev = d_enc_tamper;

    // 3. Mutate auth_epoch via raw SQLite tampering
    db_a.connection()
        .execute(
            "UPDATE human_authorities SET auth_epoch = 99 WHERE kid = 'kid_a'",
            [],
        )
        .unwrap();
    let d_epoch = db_a.human().authorities_digest().unwrap();
    assert_ne!(d_epoch, prev, "auth_epoch tamper must change digest");
    prev = d_epoch;

    // 4. N3: Revoking an existing key (and advancing min_auth_epoch) MUST preserve the
    //    enrolled-identity digest so a cryptographically verified mesh revocation does NOT
    //    brick a locked Security Gate — while immediately marking the key revoked & inactive
    //    and refusing resurrection!
    let new_min = db_a
        .human()
        .revoke_authority_monotonic("bogdan", "kid_a", 3, r#"{"r":1}"#, T0 + 10)
        .unwrap();
    assert_eq!(new_min, 3);
    assert_eq!(db_a.human().min_auth_epoch().unwrap(), 3);
    assert_eq!(
        db_a.human().get_active_authority_by_kid("kid_a").unwrap(),
        None,
        "revoked key must immediately be excluded from active lookups"
    );
    let d_revoked = db_a.human().authorities_digest().unwrap();
    assert_eq!(
        d_revoked, prev,
        "N3: monotonic revocation must preserve enrolled-identity digest"
    );
    // Attempting to resurrect the revoked key fails closed!
    assert!(matches!(
        db_a.human().upsert_authority(
            &sample_authority("bogdan", "kid_a", HumanAuthorityRole::Admin, 100),
            T0 + 15,
        ),
        Err(StoreError::InvalidState(_))
    ));

    // 5. Enrolling any unauthorized new authority key MUST change digest!
    let k_rogue = sample_authority("rogue", "kid_rogue", HumanAuthorityRole::Admin, 1);
    db_a.human().upsert_authority(&k_rogue, T0 + 20).unwrap();
    let d_injected = db_a.human().authorities_digest().unwrap();
    assert_ne!(
        d_injected, prev,
        "unauthorized key insertion must change digest"
    );
    prev = d_injected;

    // 6. Delete a row via raw SQLite tampering MUST change digest!
    db_a.connection()
        .execute("DELETE FROM human_authorities WHERE kid = 'kid_a'", [])
        .unwrap();
    let d_deleted = db_a.human().authorities_digest().unwrap();
    assert_ne!(d_deleted, prev, "row deletion must change digest");
}

#[test]
fn nonce_ttl_pruning_wired_into_scheduler_deadline_and_tick() {
    let db = NodeDb::open_in_memory().unwrap();

    // Completely idle DB -> zero polling (`None`)
    let bd0 = db.next_deadline_breakdown(T0).unwrap();
    assert_eq!(bd0.human_nonces, None);
    assert_eq!(bd0.earliest, None);
    assert_eq!(db.next_deadline_ms(T0).unwrap(), None);

    // Consume two nonces with staggered TTLs
    assert!(
        db.human()
            .consume_claim_nonce(
                "nonce-1",
                "kid_1",
                HumanClaimKind::Directive,
                T0 + 60_000,
                T0
            )
            .unwrap()
    );
    assert!(
        db.human()
            .consume_claim_nonce(
                "nonce-2",
                "kid_1",
                HumanClaimKind::Secret,
                T0 + 120_000,
                T0 + 1
            )
            .unwrap()
    );

    let bd1 = db.next_deadline_breakdown(T0 + 5_000).unwrap();
    assert_eq!(bd1.human_nonces, Some(T0 + 60_000));
    assert_eq!(bd1.earliest, Some(T0 + 60_000));

    // Tick 1 ms before first expiry -> 0 pruned, replay still blocked!
    let rep_before = db.tick(T0 + 59_999).unwrap();
    assert_eq!(rep_before.human_nonces_pruned, 0);
    assert!(
        !db.human()
            .consume_claim_nonce(
                "nonce-1",
                "kid_1",
                HumanClaimKind::Directive,
                T0 + 60_000,
                T0 + 59_999
            )
            .unwrap()
    );

    // Tick at exact first expiry -> 1 pruned, next deadline advances to T0 + 120_000
    let rep_first = db.tick(T0 + 60_000).unwrap();
    assert_eq!(rep_first.human_nonces_pruned, 1);
    let bd2 = db.next_deadline_breakdown(T0 + 60_000).unwrap();
    assert_eq!(bd2.human_nonces, Some(T0 + 120_000));
    assert_eq!(bd2.earliest, Some(T0 + 120_000));

    // Tick at second expiry -> 1 pruned, scheduler returns cleanly to None (idle)
    let rep_second = db.tick(T0 + 120_000).unwrap();
    assert_eq!(rep_second.human_nonces_pruned, 1);
    let bd3 = db.next_deadline_breakdown(T0 + 120_000).unwrap();
    assert_eq!(bd3.human_nonces, None);
    assert_eq!(bd3.earliest, None);
    assert_eq!(db.next_deadline_ms(T0 + 120_000).unwrap(), None);
}

#[test]
fn node_certs_anti_rollback_and_mailbox_human_auth_json_attachment() {
    let db = NodeDb::open_in_memory().unwrap();

    // 1. NodeCert storage, latest ordering, and epoch anti-rollback
    assert_eq!(db.human().get_latest_node_cert("prod@eu-1").unwrap(), None);

    let c1 = db
        .human()
        .put_node_cert(&HumanNodeCertInput {
            node_id: "prod@eu-1".to_string(),
            human_kid: "kid_admin_1".to_string(),
            auth_epoch: 1,
            signed_json: r#"{"payload":"v1","sig":"s1"}"#.to_string(),
            issued_at: T0,
            expires_at: T0 + 86_400_000,
        })
        .unwrap();
    assert_eq!(
        db.human().get_latest_node_cert("prod@eu-1").unwrap(),
        Some(c1)
    );

    let c2 = db
        .human()
        .put_node_cert(&HumanNodeCertInput {
            node_id: "prod@eu-1".to_string(),
            human_kid: "kid_admin_1".to_string(),
            auth_epoch: 2,
            signed_json: r#"{"payload":"v2","sig":"s2"}"#.to_string(),
            issued_at: T0 + 10_000,
            expires_at: T0 + 172_800_000,
        })
        .unwrap();
    assert_eq!(
        db.human().get_latest_node_cert("prod@eu-1").unwrap(),
        Some(c2)
    );

    // Epoch rollback on same (node_id, human_kid) fails closed!
    assert!(matches!(
        db.human().put_node_cert(&HumanNodeCertInput {
            node_id: "prod@eu-1".to_string(),
            human_kid: "kid_admin_1".to_string(),
            auth_epoch: 1,
            signed_json: r#"{"payload":"stale","sig":"s0"}"#.to_string(),
            issued_at: T0 + 20_000,
            expires_at: T0 + 200_000_000,
        }),
        Err(StoreError::InvalidState(_))
    ));

    // 2. Mailbox `human_auth_json` attachment without disturbing existing MailboxEntry APIs
    let res = db
        .local()
        .put_in_mailbox(
            &MailboxInsert {
                session_id: "sess-ops".to_string(),
                origin_node: "prod@eu-1".to_string(),
                item_id: "drop-item-1".to_string(),
                text: "Verified directive body".to_string(),
                kind: MailboxKind::Message,
                source: "human:bogdan".to_string(),
                gate_state: GateState::Pending,
                gate_reason: None,
                traceparent: None,
            },
            T0,
        )
        .unwrap();
    let receipt = match res {
        MailboxPutResult::Stored { receipt } => receipt,
        other => panic!("expected Stored, got {other:?}"),
    };

    assert_eq!(db.human().get_mailbox_human_auth(&receipt).unwrap(), None);
    let auth_meta =
        r#"{"claimId":"c1","humanId":"bogdan","humanKid":"kid_phone_1","verified":true}"#;
    assert!(
        db.human()
            .set_mailbox_human_auth(&receipt, auth_meta)
            .unwrap()
    );
    assert_eq!(
        db.human()
            .get_mailbox_human_auth(&receipt)
            .unwrap()
            .as_deref(),
        Some(auth_meta)
    );
    // Missing receipt returns false
    assert!(
        !db.human()
            .set_mailbox_human_auth("rcpt-does-not-exist", auth_meta)
            .unwrap()
    );
    // Existing mailbox peek still returns intact record
    let inbox = db.local().peek_inbox("sess-ops", 10).unwrap();
    assert_eq!(inbox.len(), 1);
    assert_eq!(inbox[0].receipt, receipt);
    assert_eq!(inbox[0].text, "Verified directive body");
}

#[test]
fn enc_jwk_lifecycle_preferred_lookup_and_revocation_guard() {
    let db = NodeDb::open_in_memory().unwrap();
    let human = db.human();

    // Empty store -> None
    assert_eq!(human.get_preferred_human_enc_jwk(None).unwrap(), None);
    assert_eq!(
        human.get_preferred_human_enc_jwk(Some("bogdan")).unwrap(),
        None
    );

    // Enroll authority without enc_jwk_json -> preferred lookup still None
    let a1 = sample_authority("bogdan", "kid_no_enc", HumanAuthorityRole::Admin, 1);
    let r1 = human.upsert_authority(&a1, T0).unwrap();
    assert_eq!(r1.enc_jwk_json, None);
    assert_eq!(human.get_preferred_human_enc_jwk(None).unwrap(), None);
    assert_eq!(human.list_active_authorities().unwrap().len(), 1);

    // Enroll authority WITH enc_jwk_json for alice at T0 + 10
    let mut a2 = sample_authority("alice", "kid_alice_enc", HumanAuthorityRole::Signer, 1);
    a2.enc_jwk_json = Some(sample_enc_jwk("alice_x25519_1"));
    let r2 = human.upsert_authority(&a2, T0 + 10).unwrap();
    assert_eq!(
        r2.enc_jwk_json.as_deref(),
        Some(sample_enc_jwk("alice_x25519_1").as_str())
    );
    assert_eq!(
        human
            .get_preferred_human_enc_jwk(None)
            .unwrap()
            .unwrap()
            .kid,
        "kid_alice_enc"
    );
    assert_eq!(
        human
            .get_preferred_human_enc_jwk(Some("alice"))
            .unwrap()
            .unwrap()
            .kid,
        "kid_alice_enc"
    );
    assert_eq!(
        human.get_preferred_human_enc_jwk(Some("bogdan")).unwrap(),
        None
    );

    // Upgrade bogdan's existing active authority (created_at = T0) with enc_jwk_json
    assert!(
        human
            .update_authority_enc_jwk("kid_no_enc", &sample_enc_jwk("bogdan_x25519_old"), T0 + 20)
            .unwrap()
    );
    // For bogdan specifically, returns kid_no_enc; globally alice (created_at = T0 + 10 > T0) is newer!
    assert_eq!(
        human
            .get_preferred_human_enc_jwk(Some("bogdan"))
            .unwrap()
            .unwrap()
            .kid,
        "kid_no_enc"
    );
    assert_eq!(
        human
            .get_preferred_human_enc_jwk(None)
            .unwrap()
            .unwrap()
            .kid,
        "kid_alice_enc"
    );

    // Enroll newer bogdan authority WITH enc_jwk_json at T0 + 50 -> becomes newest globally & for bogdan
    let mut a3 = sample_authority("bogdan", "kid_bogdan_new", HumanAuthorityRole::Signer, 2);
    a3.enc_jwk_json = Some(sample_enc_jwk("bogdan_x25519_new"));
    human.upsert_authority(&a3, T0 + 50).unwrap();
    assert_eq!(
        human
            .get_preferred_human_enc_jwk(None)
            .unwrap()
            .unwrap()
            .kid,
        "kid_bogdan_new"
    );
    assert_eq!(
        human
            .get_preferred_human_enc_jwk(Some("bogdan"))
            .unwrap()
            .unwrap()
            .kid,
        "kid_bogdan_new"
    );

    // Even newer bogdan authority WITHOUT enc_jwk_json is ignored by preferred_enc_jwk lookup
    let a4 = sample_authority(
        "bogdan",
        "kid_bogdan_no_enc2",
        HumanAuthorityRole::Signer,
        3,
    );
    human.upsert_authority(&a4, T0 + 100).unwrap();
    assert_eq!(
        human
            .get_preferred_human_enc_jwk(Some("bogdan"))
            .unwrap()
            .unwrap()
            .kid,
        "kid_bogdan_new"
    );

    // Revoking kid_bogdan_new falls back cleanly to kid_no_enc (for bogdan) and kid_alice_enc (globally),
    // AND refuses to update enc_jwk_json on the revoked key!
    human
        .revoke_authority_monotonic("bogdan", "kid_bogdan_new", 2, r#"{"r":1}"#, T0 + 150)
        .unwrap();
    assert!(
        !human
            .update_authority_enc_jwk(
                "kid_bogdan_new",
                &sample_enc_jwk("revoked_attempt"),
                T0 + 160
            )
            .unwrap()
    );
    assert!(
        !human
            .update_authority_enc_jwk("kid_missing", &sample_enc_jwk("missing"), T0 + 160)
            .unwrap()
    );
    assert!(
        human
            .update_authority_enc_jwk("kid_no_enc", "not-a-json-object", T0 + 160)
            .is_err()
    );
    assert_eq!(
        human
            .get_preferred_human_enc_jwk(Some("bogdan"))
            .unwrap()
            .unwrap()
            .kid,
        "kid_no_enc"
    );
    assert_eq!(
        human
            .get_preferred_human_enc_jwk(None)
            .unwrap()
            .unwrap()
            .kid,
        "kid_alice_enc"
    );
}

#[test]
fn full_v1_v2_v3_v4_to_v5_migration_parity_backups_and_zero_data_loss() {
    assert_eq!(CURRENT_SCHEMA_VERSION, 10);
    let dir = TempDir::new().unwrap();

    let v1_path = dir.path().join("from-v1").join("node.sqlite");
    let v2_path = dir.path().join("from-v2").join("node.sqlite");
    let v3_path = dir.path().join("from-v3").join("node.sqlite");
    let v4_path = dir.path().join("from-v4").join("node.sqlite");
    let fresh_path = dir.path().join("fresh-v5").join("node.sqlite");

    seed_db_at_version(&v1_path, 1);
    seed_db_at_version(&v2_path, 2);
    seed_db_at_version(&v3_path, 3);
    seed_db_at_version(&v4_path, 4);

    let db_v1 = NodeDb::open(&v1_path).unwrap();
    let db_v2 = NodeDb::open(&v2_path).unwrap();
    let db_v3 = NodeDb::open(&v3_path).unwrap();
    let db_v4 = NodeDb::open(&v4_path).unwrap();
    let db_fresh = NodeDb::open(&fresh_path).unwrap();

    let fresh_cols = snapshot_tables_and_columns(db_fresh.connection());
    let fresh_idx = snapshot_indexes(db_fresh.connection());

    for (from_ver, db) in [(1i64, &db_v1), (2, &db_v2), (3, &db_v3), (4, &db_v4)] {
        assert_eq!(db.schema_version().unwrap(), CURRENT_SCHEMA_VERSION);
        let applied: Vec<i64> = db
            .applied_migrations()
            .unwrap()
            .into_iter()
            .map(|(v, _)| v)
            .collect();
        assert_eq!(applied, vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);

        // Bit-for-bit structural schema parity with fresh latest
        assert_eq!(
            snapshot_tables_and_columns(db.connection()),
            fresh_cols,
            "v{from_ver}->v{CURRENT_SCHEMA_VERSION} tables/columns must match fresh"
        );
        assert_eq!(
            snapshot_indexes(db.connection()),
            fresh_idx,
            "v{from_ver}->v{CURRENT_SCHEMA_VERSION} indexes must match fresh"
        );

        // Backup exists, 0600 perms, genuine snapshot at `from_ver`
        let backups = db.list_migration_backups().unwrap();
        assert_eq!(backups.len(), 1);
        let bak_name = backups[0].file_name().unwrap().to_str().unwrap();
        assert!(
            bak_name.starts_with(&format!(
                "node.sqlite.v{from_ver}-to-v{CURRENT_SCHEMA_VERSION}-"
            )) && bak_name.ends_with(".bak"),
            "unexpected backup name: {bak_name}"
        );
        let bak_conn =
            Connection::open_with_flags(&backups[0], OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        let bak_ver: i64 = bak_conn
            .query_row("SELECT MAX(version) FROM schema_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(bak_ver, from_ver);

        // Pre-existing rows survive untouched
        let mb = db.local().peek_inbox("sess-1", 10).unwrap();
        assert_eq!(mb.len(), 1);
        assert_eq!(mb[0].receipt, "rcpt-legacy");
        assert_eq!(
            db.human().get_mailbox_human_auth("rcpt-legacy").unwrap(),
            None
        );

        // Post-migration v5 operations work immediately (including enc_jwk_json!)
        let mut post_auth =
            sample_authority("bogdan", "kid_post_mig", HumanAuthorityRole::Admin, 1);
        post_auth.enc_jwk_json = Some(sample_enc_jwk("post_mig_x25519"));
        let stored = db.human().upsert_authority(&post_auth, T0 + 100).unwrap();
        assert_eq!(
            stored.enc_jwk_json.as_deref(),
            Some(sample_enc_jwk("post_mig_x25519").as_str())
        );
        assert!(
            db.human()
                .consume_claim_nonce(
                    "claim_post_mig",
                    "kid_post_mig",
                    HumanClaimKind::Directive,
                    T0 + 60_000,
                    T0 + 100,
                )
                .unwrap()
        );
    }

    // Verify v4 authority survived v4->v5 untouched with enc_jwk_json = None and can be upgraded in-place!
    let legacy_v4 = db_v4
        .human()
        .get_active_authority_by_kid("kid_v4_legacy")
        .unwrap()
        .expect("v4 human authority must survive v4->v5 migration");
    assert_eq!(legacy_v4.human_id, "bogdan");
    assert_eq!(legacy_v4.enc_jwk_json, None);
    assert!(
        db_v4
            .human()
            .update_authority_enc_jwk(
                "kid_v4_legacy",
                &sample_enc_jwk("upgraded_v4_x25519"),
                T0 + 200
            )
            .unwrap()
    );
    let upgraded_v4 = db_v4
        .human()
        .get_active_authority_by_kid("kid_v4_legacy")
        .unwrap()
        .unwrap();
    assert_eq!(
        upgraded_v4.enc_jwk_json.as_deref(),
        Some(sample_enc_jwk("upgraded_v4_x25519").as_str())
    );

    // Verify v3 wakeup survived v3->v7 untouched
    assert!(db_v3.wakeups().get_wakeup("wk-v3").unwrap().is_some());
    // Verify v2 peer_route survived v2->v7 untouched
    assert_eq!(
        db_v2
            .peers()
            .get_peer_route("bob@lap")
            .unwrap()
            .unwrap()
            .via_peer,
        "acme-hub"
    );
}

#[test]
fn v6_to_v7_migration_delegation_policy_invite_nonces_and_cascade_peer_revocation() {
    let dir = TempDir::new().unwrap();
    let v6_path = dir.path().join("from-v6").join("node.sqlite");
    let fresh_path = dir.path().join("fresh-v7").join("node.sqlite");

    // 1. Seed a genuine v6 SQLite database with pre-existing peer, authority, and directive nonce.
    seed_db_at_version(&v6_path, 4);
    {
        let conn = Connection::open(&v6_path).unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        conn.execute_batch(SCHEMA_V5_SQL).unwrap();
        conn.execute(
            "INSERT INTO schema_version (version, applied_at) VALUES (5, ?1)",
            params![T0 + 4],
        )
        .unwrap();
        conn.execute_batch(SCHEMA_V6_SQL).unwrap();
        conn.execute(
            "INSERT INTO schema_version (version, applied_at) VALUES (6, ?1)",
            params![T0 + 5],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO peers (peer_id, endpoint, profile, trust_tier, status, scopes_json, created_at, updated_at)
             VALUES ('alice@macbook', 'https://alice.example', 'local', 'org', 'active', '[\"dm:*\"]', ?1, ?1)",
            params![T0 + 5],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO human_claim_nonces (claim_id, human_kid, kind, expires_at, consumed_at)
             VALUES ('legacy-dir-1', 'kid_v4_legacy', 'directive', ?1, ?2)",
            params![T0 + 600_000, T0 + 5],
        )
        .unwrap();
    }

    // 2. Open with NodeDb -> migrates v6 to the current schema with a backup and schema parity.
    let db = NodeDb::open(&v6_path).unwrap();
    let fresh = NodeDb::open(&fresh_path).unwrap();
    assert_eq!(db.schema_version().unwrap(), CURRENT_SCHEMA_VERSION);
    let applied: Vec<i64> = db
        .applied_migrations()
        .unwrap()
        .into_iter()
        .map(|(v, _)| v)
        .collect();
    assert_eq!(applied, vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    assert_eq!(
        snapshot_tables_and_columns(db.connection()),
        snapshot_tables_and_columns(fresh.connection())
    );
    let norm_idx = |conn: &Connection| -> BTreeMap<String, (String, Option<String>)> {
        snapshot_indexes(conn)
            .into_iter()
            .map(|(k, (tbl, sql))| {
                (
                    k,
                    (
                        tbl,
                        sql.map(|s| s.split_whitespace().collect::<Vec<_>>().join(" ")),
                    ),
                )
            })
            .collect()
    };
    assert_eq!(norm_idx(db.connection()), norm_idx(fresh.connection()));
    let backups = db.list_migration_backups().unwrap();
    assert_eq!(backups.len(), 1);
    assert!(
        backups[0]
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with(&format!("node.sqlite.v6-to-v{CURRENT_SCHEMA_VERSION}-"))
    );

    // Existing v6 peer & directive nonce survive untouched!
    let alice = db.peers().get_peer("alice@macbook").unwrap().unwrap();
    assert_eq!(alice.admitted_by_human_id, None);
    assert_eq!(alice.admitted_auth_epoch, None);
    assert!(
        !db.human()
            .consume_claim_nonce(
                "legacy-dir-1",
                "kid_v4_legacy",
                HumanClaimKind::Directive,
                T0 + 600_000,
                T0 + 10,
            )
            .unwrap(),
        "pre-existing v6 directive nonce must survive rebuild of human_claim_nonces"
    );

    // 3. New `HumanClaimKind::HumanInvite` single-use consumption works and blocks replay.
    assert!(
        db.human()
            .consume_claim_nonce(
                "invite-uuid-1",
                "admin_kid_1",
                HumanClaimKind::HumanInvite,
                T0 + 86_400_000,
                T0 + 20,
            )
            .unwrap()
    );
    assert!(
        !db.human()
            .consume_claim_nonce(
                "invite-uuid-1",
                "admin_kid_1",
                HumanClaimKind::HumanInvite,
                T0 + 86_400_000,
                T0 + 21,
            )
            .unwrap()
    );

    // 4. Delegation policy validation fails closed on forbidden scopes, bare `*`, or invalid max_devices.
    for bad_policy in [
        HumanDelegationPolicyInput {
            human_id: "philip".to_string(),
            node_prefix: "*".to_string(),
            scopes: vec!["dm:send".to_string()],
            max_devices: 5,
            delegation_enabled: true,
        },
        HumanDelegationPolicyInput {
            human_id: "philip".to_string(),
            node_prefix: "philip@*".to_string(),
            scopes: vec!["*".to_string()],
            max_devices: 5,
            delegation_enabled: true,
        },
        HumanDelegationPolicyInput {
            human_id: "philip".to_string(),
            node_prefix: "philip@*".to_string(),
            scopes: vec!["dm:send".to_string(), "bridge:post=slack:ops".to_string()],
            max_devices: 5,
            delegation_enabled: true,
        },
        HumanDelegationPolicyInput {
            human_id: "philip".to_string(),
            node_prefix: "philip@*".to_string(),
            scopes: vec!["dm:send".to_string(), "forward:via=hub".to_string()],
            max_devices: 5,
            delegation_enabled: true,
        },
        HumanDelegationPolicyInput {
            human_id: "philip".to_string(),
            node_prefix: "philip@*".to_string(),
            scopes: vec!["dm:send".to_string()],
            max_devices: 0,
            delegation_enabled: true,
        },
    ] {
        assert!(
            db.human()
                .upsert_delegation_policy(&bad_policy, T0 + 30)
                .is_err(),
            "forbidden delegation policy {bad_policy:?} MUST fail closed"
        );
    }

    let policy = db
        .human()
        .upsert_delegation_policy(
            &HumanDelegationPolicyInput {
                human_id: "philip".to_string(),
                node_prefix: "philip@*".to_string(),
                scopes: vec![
                    "dm:send".to_string(),
                    "dm:receive".to_string(),
                    "kv:read=*".to_string(),
                ],
                max_devices: 2,
                delegation_enabled: true,
            },
            T0 + 30,
        )
        .unwrap();
    assert_eq!(policy.node_prefix, "philip@*");
    assert_eq!(policy.max_devices, 2);
    assert!(policy.delegation_enabled);
    assert_eq!(
        db.human().get_delegation_policy("philip").unwrap(),
        Some(policy.clone())
    );

    // 5. Admitted peers provenance, counting, bearer token binding, and atomic cascade revocation!
    let p1 = db
        .peers()
        .upsert_peer_with_admission(
            &PeerInput {
                peer_id: "philip@macbook".to_string(),
                endpoint: None,
                profile: PeerProfile::Local,
                trust_tier: TrustTier::Org,
                status: PeerStatus::Active,
                scopes: vec!["dm:*".to_string()],
                auth_credential_ref: None,
            },
            Some("philip"),
            Some(1),
            T0 + 40,
        )
        .unwrap();
    assert_eq!(p1.admitted_by_human_id.as_deref(), Some("philip"));
    assert_eq!(p1.admitted_auth_epoch, Some(1));

    let p2 = db
        .peers()
        .upsert_peer_with_admission(
            &PeerInput {
                peer_id: "philip@devbox".to_string(),
                endpoint: None,
                profile: PeerProfile::Local,
                trust_tier: TrustTier::Org,
                status: PeerStatus::Active,
                scopes: vec!["dm:*".to_string()],
                auth_credential_ref: None,
            },
            Some("philip"),
            Some(1),
            T0 + 41,
        )
        .unwrap();
    assert_eq!(p2.admitted_by_human_id.as_deref(), Some("philip"));

    assert_eq!(
        db.peers()
            .count_active_peers_admitted_by_human("philip", None)
            .unwrap(),
        2
    );
    assert_eq!(
        db.peers()
            .count_active_peers_admitted_by_human("philip", Some("philip@macbook"))
            .unwrap(),
        1
    );

    // Attach bearer tokens + routes to Philip's devices and Alice's unrelated device.
    db.local()
        .set_metadata(
            "auth_token:hash_philip_1",
            r#"{"peerId":"philip@macbook","grantId":"g1","signingKid":"k1"}"#,
        )
        .unwrap();
    db.local()
        .set_metadata(
            "auth_token:hash_philip_2",
            r#"{"peerId":"philip@devbox","grantId":"g2","signingKid":"k2"}"#,
        )
        .unwrap();
    db.local()
        .set_metadata(
            "auth_token:hash_alice",
            r#"{"peerId":"alice@macbook","grantId":"ga","signingKid":"ka"}"#,
        )
        .unwrap();
    db.peers()
        .upsert_peer_route("downstream@box", "philip@macbook", T0 + 42)
        .unwrap();

    // Cascade revoke all peers admitted by `philip`.
    let revoked = db
        .peers()
        .revoke_peers_admitted_by_human("philip", T0 + 100)
        .unwrap();
    assert_eq!(
        revoked,
        vec!["philip@devbox".to_string(), "philip@macbook".to_string()]
    );
    assert_eq!(
        db.peers()
            .count_active_peers_admitted_by_human("philip", None)
            .unwrap(),
        0
    );
    assert_eq!(
        db.peers()
            .get_peer("philip@macbook")
            .unwrap()
            .unwrap()
            .status,
        PeerStatus::Revoked
    );
    assert_eq!(
        db.peers()
            .get_peer("philip@devbox")
            .unwrap()
            .unwrap()
            .status,
        PeerStatus::Revoked
    );
    assert_eq!(
        db.local().get_metadata("auth_token:hash_philip_1").unwrap(),
        None
    );
    assert_eq!(
        db.local().get_metadata("auth_token:hash_philip_2").unwrap(),
        None
    );
    assert_eq!(db.peers().get_peer_route("downstream@box").unwrap(), None);

    // Unrelated peer `alice@macbook` & her bearer token MUST remain untouched!
    assert_eq!(
        db.peers()
            .get_peer("alice@macbook")
            .unwrap()
            .unwrap()
            .status,
        PeerStatus::Active
    );
    assert!(
        db.local()
            .get_metadata("auth_token:hash_alice")
            .unwrap()
            .is_some()
    );

    // Disabling delegation policy updates cleanly.
    assert!(
        db.human()
            .set_delegation_enabled("philip", false, T0 + 101)
            .unwrap()
    );
    assert!(
        !db.human()
            .get_delegation_policy("philip")
            .unwrap()
            .unwrap()
            .delegation_enabled
    );
}

#[test]
fn v7_to_v8_migration_gate_lock_seal_anti_rollback_and_approval_nonces() {
    let dir = TempDir::new().unwrap();
    let v7_path = dir.path().join("from-v7").join("node.sqlite");
    let fresh_path = dir.path().join("fresh-current").join("node.sqlite");

    // 1. Seed a genuine v7 SQLite database with pre-existing human_invite + directive nonces.
    seed_db_at_version(&v7_path, 4);
    {
        let conn = Connection::open(&v7_path).unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        conn.execute_batch(SCHEMA_V5_SQL).unwrap();
        conn.execute(
            "INSERT INTO schema_version (version, applied_at) VALUES (5, ?1)",
            params![T0 + 4],
        )
        .unwrap();
        conn.execute_batch(SCHEMA_V6_SQL).unwrap();
        conn.execute(
            "INSERT INTO schema_version (version, applied_at) VALUES (6, ?1)",
            params![T0 + 5],
        )
        .unwrap();
        conn.execute_batch(SCHEMA_V7_SQL).unwrap();
        conn.execute(
            "INSERT INTO schema_version (version, applied_at) VALUES (7, ?1)",
            params![T0 + 6],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO human_claim_nonces (claim_id, human_kid, kind, expires_at, consumed_at)
             VALUES ('v7-invite-nonce', 'kid_v4_legacy', 'human_invite', ?1, ?2)",
            params![T0 + 600_000, T0 + 6],
        )
        .unwrap();
    }

    // 2. Open with NodeDb -> migrates v7 to the current schema with a backup and schema parity.
    let db = NodeDb::open(&v7_path).unwrap();
    let fresh = NodeDb::open(&fresh_path).unwrap();
    assert_eq!(db.schema_version().unwrap(), CURRENT_SCHEMA_VERSION);
    let applied: Vec<i64> = db
        .applied_migrations()
        .unwrap()
        .into_iter()
        .map(|(v, _)| v)
        .collect();
    assert_eq!(applied, vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    assert_eq!(
        snapshot_tables_and_columns(db.connection()),
        snapshot_tables_and_columns(fresh.connection())
    );
    let norm_idx = |conn: &Connection| -> BTreeMap<String, (String, Option<String>)> {
        snapshot_indexes(conn)
            .into_iter()
            .map(|(k, (tbl, sql))| {
                (
                    k,
                    (
                        tbl,
                        sql.map(|s| s.split_whitespace().collect::<Vec<_>>().join(" ")),
                    ),
                )
            })
            .collect()
    };
    assert_eq!(norm_idx(db.connection()), norm_idx(fresh.connection()));
    let backups = db.list_migration_backups().unwrap();
    assert_eq!(backups.len(), 1);
    assert!(
        backups[0]
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with(&format!("node.sqlite.v7-to-v{CURRENT_SCHEMA_VERSION}-"))
    );

    // Pre-existing v7 human_invite nonce survives rebuild of `human_claim_nonces`.
    assert!(
        !db.human()
            .consume_claim_nonce(
                "v7-invite-nonce",
                "kid_v4_legacy",
                HumanClaimKind::HumanInvite,
                T0 + 600_000,
                T0 + 20,
            )
            .unwrap()
    );

    // 3. New `HumanClaimKind::Approval` single-use nonce consumption works and blocks replay.
    assert!(
        db.human()
            .consume_claim_nonce(
                "an_approval_nonce_1",
                "kid_admin_pk",
                HumanClaimKind::Approval,
                T0 + 600_000,
                T0 + 30,
            )
            .unwrap()
    );
    assert!(
        !db.human()
            .consume_claim_nonce(
                "an_approval_nonce_1",
                "kid_admin_pk",
                HumanClaimKind::Approval,
                T0 + 600_000,
                T0 + 31,
            )
            .unwrap()
    );

    // 4. `gate_lock_seal` CRUD and strict monotonic `seal_seq` anti-rollback enforcement!
    assert_eq!(db.human().get_gate_lock_seal().unwrap(), None);

    // Reject seal_seq == 0 and a non-object signed claim.
    let claim = |sig: &str| format!(r#"{{"payload":"{{\"v\":1}}","sig":"{sig}"}}"#);
    assert!(matches!(
        db.human().put_gate_lock_seal(0, &claim("s0"), T0 + 40),
        Err(StoreError::InvalidInput(_))
    ));
    assert!(matches!(
        db.human()
            .put_gate_lock_seal(1, "\"not-an-object\"", T0 + 40),
        Err(StoreError::InvalidInput(_))
    ));

    let s1 = db
        .human()
        .put_gate_lock_seal(1, &claim("sig1"), T0 + 50)
        .unwrap();
    assert_eq!(s1.seal_seq, 1);
    assert_eq!(s1.signed_claim_json, claim("sig1"));
    assert_eq!(db.human().get_gate_lock_seal().unwrap(), Some(s1.clone()));

    // Equal seal_seq = 1 MUST fail closed with InvalidState and leave the row untouched!
    assert!(matches!(
        db.human().put_gate_lock_seal(1, &claim("stale"), T0 + 60),
        Err(StoreError::InvalidState(_))
    ));
    assert_eq!(db.human().get_gate_lock_seal().unwrap(), Some(s1));

    // Strictly higher seal_seq = 2 replaces the single row.
    let s2 = db
        .human()
        .put_gate_lock_seal(2, &claim("sig2"), T0 + 70)
        .unwrap();
    assert_eq!(s2.seal_seq, 2);
    assert_eq!(db.human().get_gate_lock_seal().unwrap(), Some(s2));

    // 5. `projected_authorities_digest_after_upsert` matches exact post-upsert `authorities_digest()`!
    let mut new_auth = sample_authority("alice", "kid_proj_1", HumanAuthorityRole::Admin, 1);
    new_auth.enc_jwk_json = Some(sample_enc_jwk("proj_enc_1"));
    let projected_new = db
        .human()
        .projected_authorities_digest_after_upsert(&new_auth)
        .unwrap();
    db.human().upsert_authority(&new_auth, T0 + 80).unwrap();
    let actual_new = db.human().authorities_digest().unwrap();
    assert_eq!(
        projected_new, actual_new,
        "projected digest before new insert must equal actual post-upsert digest"
    );

    let mut updated_auth = new_auth.clone();
    updated_auth.enc_jwk_json = Some(sample_enc_jwk("proj_enc_2"));
    let projected_upd = db
        .human()
        .projected_authorities_digest_after_upsert(&updated_auth)
        .unwrap();
    db.human().upsert_authority(&updated_auth, T0 + 90).unwrap();
    let actual_upd = db.human().authorities_digest().unwrap();
    assert_eq!(
        projected_upd, actual_upd,
        "projected digest before update must equal actual post-upsert digest"
    );
}

#[test]
fn pending_bootstrap_cannot_inject_after_first_passkey_enrollment_or_revocation() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("node.sqlite");
    let first = NodeDb::open(&path).unwrap();
    let pending = NodeDb::open(&path).unwrap();
    assert!(!first.human().requires_live_approval().unwrap());
    assert!(!pending.human().requires_live_approval().unwrap());
    let mut admin = sample_authority("admin", "passkey_key", HumanAuthorityRole::Admin, 1);
    admin.prf_salt = Some("passkey_salt".into());
    first.human().bootstrap_authority(&admin, T0).unwrap();
    let rogue = sample_authority("rogue", "pending_key", HumanAuthorityRole::Admin, 1);
    assert!(matches!(
        pending.human().bootstrap_authority(&rogue, T0 + 1),
        Err(StoreError::InvalidState(_))
    ));
    first
        .human()
        .revoke_authority_monotonic("admin", "passkey_key", 1, "{}", T0 + 2)
        .unwrap();
    assert!(matches!(
        pending.human().bootstrap_authority(&rogue, T0 + 3),
        Err(StoreError::InvalidState(_))
    ));
    let records = first.human().list_authorities(true).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].kid, "passkey_key");
    assert_eq!(records[0].status, HumanAuthorityStatus::Revoked);
}

#[test]
fn nested_store_savepoints_exist_only_inside_explicit_write_scope() {
    let db = NodeDb::open_in_memory().unwrap();
    let first = sample_authority("first", "first_key", HumanAuthorityRole::Signer, 1);
    db.connection().execute_batch("BEGIN IMMEDIATE").unwrap();
    assert!(
        db.human().upsert_authority(&first, T0).is_err(),
        "ordinary store calls must not silently join arbitrary transactions"
    );
    db.connection().execute_batch("ROLLBACK").unwrap();
    db.with_write_transaction(|| {
        db.human().upsert_authority(&first, T0)?;
        db.with_write_transaction(|| {
            db.human().upsert_authority(
                &sample_authority("second", "second_key", HumanAuthorityRole::Signer, 1),
                T0,
            )?;
            Ok::<(), StoreError>(())
        })?;
        Ok::<(), StoreError>(())
    })
    .unwrap();
    assert_eq!(db.human().list_authorities(true).unwrap().len(), 2);
}
