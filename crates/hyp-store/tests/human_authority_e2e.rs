//! End-to-end concurrency, anti-rollback, digest tamper-sensitivity, deadline-scheduler
//! pruning, and v1->v2->v3->v4 schema migration tests for `HumanAuthorityStore`.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::sync::{Arc, Barrier};
use std::thread;

use hyp_store::{
    CURRENT_SCHEMA_VERSION, GateState, HumanAuthorityInput, HumanAuthorityRole,
    HumanAuthorityStatus, HumanClaimKind, HumanNodeCertInput, MailboxInsert, MailboxKind,
    MailboxPutResult, NodeDb, StoreError,
};
use rusqlite::{Connection, OpenFlags, params};
use tempfile::TempDir;

const SCHEMA_V1_SQL: &str = include_str!("../migrations/0001_initial_v2.sql");
const SCHEMA_V2_SQL: &str = include_str!("../migrations/0002_discovery_and_routes.sql");
const SCHEMA_V3_SQL: &str = include_str!("../migrations/0003_wakeups.sql");
const SCHEMA_V4_SQL: &str = include_str!("../migrations/0004_human_authority.sql");

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
                let db = NodeDb::open(&path)
                    .unwrap_or_else(|e| panic!("thread {tid} failed open: {e}"));
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
    assert!(human.get_active_authority_by_kid("kid_phone_1").unwrap().is_some());
    assert_eq!(human.list_authorities(false).unwrap().len(), 3);

    // Revoke phone_1 and advance min_auth_epoch -> 4
    let rev1_json = r#"{"payload":"{}","sig":"sig1"}"#;
    let new_min = human
        .revoke_authority_monotonic("bogdan", "kid_phone_1", 4, rev1_json, T0 + 100)
        .unwrap();
    assert_eq!(new_min, 4);
    assert_eq!(human.min_auth_epoch().unwrap(), 4);
    assert_eq!(human.get_active_authority_by_kid("kid_phone_1").unwrap(), None);
    assert_eq!(human.list_authorities(false).unwrap().len(), 2);
    assert_eq!(human.list_authorities(true).unwrap().len(), 3);

    let revoked_rec = human.get_authority("bogdan", "kid_phone_1").unwrap().unwrap();
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
    assert_eq!(human.get_active_authority_by_kid("kid_phone_2").unwrap(), None);

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
    assert_eq!(d_both_a, d_both_b, "digest must be deterministic regardless of insertion order");
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

    // 4. Mutate status via revocation (also advances min_auth_epoch)
    db_a.human()
        .revoke_authority_monotonic("bogdan", "kid_a", 3, r#"{"r":1}"#, T0 + 10)
        .unwrap();
    let d_revoked = db_a.human().authorities_digest().unwrap();
    assert_ne!(d_revoked, prev, "status/min_auth_epoch change must change digest");
    prev = d_revoked;

    // 5. Mutate min_auth_epoch directly in metadata
    db_a.connection()
        .execute(
            "UPDATE metadata SET value = '1' WHERE key = 'human.min_auth_epoch'",
            [],
        )
        .unwrap();
    let d_min_tamper = db_a.human().authorities_digest().unwrap();
    assert_ne!(
        d_min_tamper, prev,
        "min_auth_epoch rollback tamper in metadata must change digest"
    );
    prev = d_min_tamper;

    // 6. Delete a row via raw SQLite tampering
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
            .consume_claim_nonce("nonce-1", "kid_1", HumanClaimKind::Directive, T0 + 60_000, T0)
            .unwrap()
    );
    assert!(
        db.human()
            .consume_claim_nonce("nonce-2", "kid_1", HumanClaimKind::Secret, T0 + 120_000, T0 + 1)
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
            .consume_claim_nonce("nonce-1", "kid_1", HumanClaimKind::Directive, T0 + 60_000, T0 + 59_999)
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
    assert_eq!(db.human().get_latest_node_cert("prod@eu-1").unwrap(), Some(c1));

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
    assert_eq!(db.human().get_latest_node_cert("prod@eu-1").unwrap(), Some(c2));

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
    let auth_meta = r#"{"claimId":"c1","humanId":"bogdan","humanKid":"kid_phone_1","verified":true}"#;
    assert!(db.human().set_mailbox_human_auth(&receipt, auth_meta).unwrap());
    assert_eq!(
        db.human().get_mailbox_human_auth(&receipt).unwrap().as_deref(),
        Some(auth_meta)
    );
    // Missing receipt returns false
    assert!(!db.human().set_mailbox_human_auth("rcpt-does-not-exist", auth_meta).unwrap());
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
    assert_eq!(human.get_preferred_human_enc_jwk(Some("bogdan")).unwrap(), None);

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
        human.get_preferred_human_enc_jwk(None).unwrap().unwrap().kid,
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
        human.get_preferred_human_enc_jwk(None).unwrap().unwrap().kid,
        "kid_alice_enc"
    );

    // Enroll newer bogdan authority WITH enc_jwk_json at T0 + 50 -> becomes newest globally & for bogdan
    let mut a3 = sample_authority("bogdan", "kid_bogdan_new", HumanAuthorityRole::Signer, 2);
    a3.enc_jwk_json = Some(sample_enc_jwk("bogdan_x25519_new"));
    human.upsert_authority(&a3, T0 + 50).unwrap();
    assert_eq!(
        human.get_preferred_human_enc_jwk(None).unwrap().unwrap().kid,
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
    let a4 = sample_authority("bogdan", "kid_bogdan_no_enc2", HumanAuthorityRole::Signer, 3);
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
            .update_authority_enc_jwk("kid_bogdan_new", &sample_enc_jwk("revoked_attempt"), T0 + 160)
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
        human.get_preferred_human_enc_jwk(None).unwrap().unwrap().kid,
        "kid_alice_enc"
    );
}

#[test]
fn full_v1_v2_v3_v4_to_v5_migration_parity_backups_and_zero_data_loss() {
    assert_eq!(CURRENT_SCHEMA_VERSION, 5);
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
        assert_eq!(db.schema_version().unwrap(), 5);
        let applied: Vec<i64> = db
            .applied_migrations()
            .unwrap()
            .into_iter()
            .map(|(v, _)| v)
            .collect();
        assert_eq!(applied, vec![1, 2, 3, 4, 5]);

        // Bit-for-bit structural schema parity with fresh v5
        assert_eq!(
            snapshot_tables_and_columns(db.connection()),
            fresh_cols,
            "v{from_ver}->v5 tables/columns must match fresh v5"
        );
        assert_eq!(
            snapshot_indexes(db.connection()),
            fresh_idx,
            "v{from_ver}->v5 indexes must match fresh v5"
        );

        // Backup exists, 0600 perms, genuine snapshot at `from_ver`
        let backups = db.list_migration_backups().unwrap();
        assert_eq!(backups.len(), 1);
        let bak_name = backups[0].file_name().unwrap().to_str().unwrap();
        assert!(
            bak_name.starts_with(&format!("node.sqlite.v{from_ver}-to-v5-"))
                && bak_name.ends_with(".bak"),
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
        assert_eq!(db.human().get_mailbox_human_auth("rcpt-legacy").unwrap(), None);

        // Post-migration v5 operations work immediately (including enc_jwk_json!)
        let mut post_auth = sample_authority("bogdan", "kid_post_mig", HumanAuthorityRole::Admin, 1);
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
            .update_authority_enc_jwk("kid_v4_legacy", &sample_enc_jwk("upgraded_v4_x25519"), T0 + 200)
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

    // Verify v3 wakeup survived v3->v5 untouched
    assert!(db_v3.wakeups().get_wakeup("wk-v3").unwrap().is_some());
    // Verify v2 peer_route survived v2->v5 untouched
    assert_eq!(
        db_v2.peers().get_peer_route("bob@lap").unwrap().unwrap().via_peer,
        "acme-hub"
    );
}
