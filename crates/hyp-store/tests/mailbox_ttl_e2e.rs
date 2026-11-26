//! Mailbox coalescing, TTL scheduling, and historical mailbox schema compatibility.

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::Path;

use hyp_store::{
    CURRENT_SCHEMA_VERSION, GateState, MailboxInsert, MailboxKind, MailboxPutOptions,
    MailboxPutResult, NodeDb, StoreConfig,
};
use rusqlite::{Connection, OpenFlags, params};
use tempfile::TempDir;

const SCHEMA_V1_SQL: &str = include_str!("../migrations/0001_initial_v2.sql");
const SCHEMA_V2_SQL: &str = include_str!("../migrations/0002_discovery_and_routes.sql");

const MIN_MS: i64 = 60_000;
// 2026-06-15T00:00:00.000Z (Monday)
const BASE_T0: i64 = 1_781_481_600_000;

fn event_mailbox_insert(
    session_id: &str,
    source_id: &str,
    item_id: &str,
    text: &str,
) -> MailboxInsert {
    MailboxInsert {
        session_id: session_id.to_string(),
        origin_node: "local".to_string(),
        item_id: item_id.to_string(),
        text: text.to_string(),
        kind: MailboxKind::Event,
        source: format!("event:{source_id}"),
        gate_state: GateState::Pending,
        gate_reason: None,
        traceparent: None,
    }
}

#[test]
fn mailbox_coalescing_missed_count_ttl_and_zero_polling_deadlines() {
    let config = StoreConfig {
        mailbox_max_pending_per_session: 2,
        ..StoreConfig::default()
    };
    let db = NodeDb::open_in_memory_with_config(config).unwrap();

    // Idle DB reports None for all deadlines (zero polling!).
    let bd0 = db.next_deadline_breakdown(BASE_T0).unwrap();
    assert_eq!(bd0.mailbox_ttl, None);
    assert_eq!(bd0.earliest(), None);
    assert_eq!(bd0.earliest, None);

    // Put #1 with coalesce_key + TTL.
    let opts1 = MailboxPutOptions {
        coalesce_key: Some("event:wk-1".to_string()),
        expires_at: Some(BASE_T0 + 60_000),
    };
    let r1 = match db
        .local()
        .put_in_mailbox_ex(
            &event_mailbox_insert("sess-1", "wk-1", "tick-1", "first tick"),
            &opts1,
            BASE_T0,
        )
        .unwrap()
    {
        MailboxPutResult::Stored { receipt } => receipt,
        other => panic!("expected Stored, got {other:?}"),
    };
    db.local().mark_mailbox_notified("sess-1").unwrap();
    let ex1 = db.local().get_mailbox_entry_ex(&r1).unwrap().unwrap();
    assert_eq!(ex1.coalesce_key.as_deref(), Some("event:wk-1"));
    assert_eq!(ex1.expires_at, Some(BASE_T0 + 60_000));
    assert_eq!(ex1.missed_count, 0);
    assert!(ex1.entry.notified);

    // Fill the 2nd (and final!) queue slot with a regular non-TTL message.
    db.local()
        .put_in_mailbox(
            &MailboxInsert {
                session_id: "sess-1".to_string(),
                origin_node: "local".to_string(),
                item_id: "dm-1".to_string(),
                text: "regular dm".to_string(),
                kind: MailboxKind::Message,
                source: "alice/claude".to_string(),
                gate_state: GateState::Pending,
                gate_reason: None,
                traceparent: None,
            },
            BASE_T0 + 1_000,
        )
        .unwrap();

    // A non-matching new item hits QueueFull.
    assert_eq!(
        db.local()
            .put_in_mailbox_ex(
                &event_mailbox_insert("sess-1", "wk-other", "other-1", "overflow"),
                &MailboxPutOptions {
                    coalesce_key: Some("event:wk-other".to_string()),
                    expires_at: Some(BASE_T0 + 30_000),
                },
                BASE_T0 + 2_000,
            )
            .unwrap(),
        MailboxPutResult::QueueFull
    );

    // Coalescing into the existing pending `event:wk-1` slot SUCCEEDS even while queue is full!
    let opts2 = MailboxPutOptions {
        coalesce_key: Some("event:wk-1".to_string()),
        expires_at: Some(BASE_T0 + 120_000),
    };
    let r2 = match db
        .local()
        .put_in_mailbox_ex(
            &event_mailbox_insert("sess-1", "wk-1", "tick-2", "second tick"),
            &opts2,
            BASE_T0 + 10_000,
        )
        .unwrap()
    {
        MailboxPutResult::Stored { receipt } => receipt,
        other => panic!("expected coalesced Stored, got {other:?}"),
    };
    assert_eq!(r2, r1, "coalescing must reuse existing receipt");
    let ex2 = db.local().get_mailbox_entry_ex(&r1).unwrap().unwrap();
    assert_eq!(ex2.entry.item_id, "tick-2");
    assert_eq!(ex2.entry.text, "second tick");
    assert_eq!(ex2.entry.received_at, BASE_T0 + 10_000);
    assert_eq!(ex2.expires_at, Some(BASE_T0 + 120_000));
    assert!(
        !ex2.entry.notified,
        "coalesced update must reset notified = false"
    );
    assert_eq!(ex2.missed_count, 1);

    // Exact duplicate retry of `tick-2` returns Duplicate without bumping missed_count!
    assert_eq!(
        db.local()
            .put_in_mailbox_ex(
                &event_mailbox_insert("sess-1", "wk-1", "tick-2", "second tick"),
                &opts2,
                BASE_T0 + 11_000,
            )
            .unwrap(),
        MailboxPutResult::Duplicate
    );
    assert_eq!(
        db.local()
            .get_mailbox_entry_ex(&r1)
            .unwrap()
            .unwrap()
            .missed_count,
        1
    );

    // Quarantined row with same coalesce_key must NOT merge into pending row.
    let mut quarantined_insert = event_mailbox_insert("sess-1", "wk-1", "q-1", "suspicious");
    quarantined_insert.gate_state = GateState::Quarantined;
    let rq = match db
        .local()
        .put_in_mailbox_ex(&quarantined_insert, &opts2, BASE_T0 + 12_000)
        .unwrap()
    {
        MailboxPutResult::Stored { receipt } => receipt,
        other => panic!("expected quarantined Stored, got {other:?}"),
    };
    assert_ne!(rq, r1);
    assert_eq!(
        db.local()
            .get_mailbox_entry_ex(&r1)
            .unwrap()
            .unwrap()
            .missed_count,
        1
    );

    // Scheduler deadline breakdown accurately tracks updated TTL (BASE_T0 + 120_000).
    let bd1 = db.next_deadline_breakdown(BASE_T0 + 15_000).unwrap();
    assert_eq!(bd1.mailbox_ttl, Some(BASE_T0 + 120_000));
    assert_eq!(bd1.earliest(), Some(BASE_T0 + 120_000));
    assert_eq!(bd1.earliest, Some(BASE_T0 + 120_000));

    // Before TTL: tick expires 0.
    assert_eq!(db.tick(BASE_T0 + 119_999).unwrap().mailbox_expired, 0);
    assert_eq!(db.local().pending_count("sess-1").unwrap(), 2);

    // At TTL: tick expires ONLY the pending TTL item (regular DM & quarantined item untouched!).
    let rep = db.tick(BASE_T0 + 120_000).unwrap();
    assert_eq!(rep.mailbox_expired, 1);
    assert!(db.local().get_mailbox_entry(&r1).unwrap().is_none());
    assert_eq!(db.local().pending_count("sess-1").unwrap(), 1);
    assert!(db.local().get_mailbox_entry(&rq).unwrap().is_some());
    assert_eq!(db.next_deadline_ms(BASE_T0 + 120_000).unwrap(), None);

    // After draining or expiring, a subsequent insert with the same coalesce_key creates a fresh row.
    let r_fresh = match db
        .local()
        .put_in_mailbox_ex(
            &event_mailbox_insert("sess-1", "wk-1", "tick-3", "fresh after ttl"),
            &MailboxPutOptions {
                coalesce_key: Some("event:wk-1".to_string()),
                expires_at: Some(BASE_T0 + 300_000),
            },
            BASE_T0 + 130_000,
        )
        .unwrap()
    {
        MailboxPutResult::Stored { receipt } => receipt,
        other => panic!("expected Stored, got {other:?}"),
    };
    assert_ne!(r_fresh, r1);
    let ex_fresh = db.local().get_mailbox_entry_ex(&r_fresh).unwrap().unwrap();
    assert_eq!(ex_fresh.missed_count, 0);

    // Drain delivers it; next put creates another fresh row with missed_count = 0.
    let drained = db
        .local()
        .drain_inbox_ex("sess-1", 10, BASE_T0 + 135_000)
        .unwrap();
    assert_eq!(drained.len(), 2);
    assert_eq!(db.next_deadline_ms(BASE_T0 + 135_000).unwrap(), None);

    // Idle mailbox TTL sweeps and deadline computation take no write lock
    // (verified on file-backed WAL DB while another connection holds `BEGIN IMMEDIATE`).
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("idle.sqlite");
    let file_db = NodeDb::open(&path).unwrap();
    let writer = Connection::open(&path).unwrap();
    writer.execute_batch("BEGIN IMMEDIATE;").unwrap();
    assert_eq!(file_db.next_deadline_ms(BASE_T0).unwrap(), None);
    assert_eq!(
        file_db
            .local()
            .expire_pending_mailbox(BASE_T0 + 1_000)
            .unwrap(),
        0
    );
    writer.execute_batch("ROLLBACK;").unwrap();
    let idle_rep = file_db.tick(BASE_T0 + 1_000).unwrap();
    assert_eq!(idle_rep.mailbox_expired, 0);
}

struct XorShift64(u64);

impl XorShift64 {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn range(&mut self, upper: usize) -> usize {
        (self.next() as usize) % upper
    }
}

#[derive(Debug, Clone)]
struct OracleMailboxRow {
    receipt: String,
    session_id: String,
    item_id: String,
    text: String,
    received_at: i64,
    notified: bool,
    coalesce_key: Option<String>,
    expires_at: Option<i64>,
    missed_count: u64,
}

#[derive(Default)]
struct ReferenceOracle {
    pending_mailbox: Vec<OracleMailboxRow>,
    seen_mailbox_keys: HashSet<(String, String)>, // (session_id, item_id)
    max_pending_per_session: usize,
}

impl ReferenceOracle {
    fn new(max_pending_per_session: usize) -> Self {
        Self {
            pending_mailbox: Vec::new(),
            seen_mailbox_keys: HashSet::new(),
            max_pending_per_session,
        }
    }

    fn expire_mailbox(&mut self, now_ms: i64) -> usize {
        let before = self.pending_mailbox.len();
        self.pending_mailbox
            .retain(|row| row.expires_at.is_none_or(|exp| exp > now_ms));
        before - self.pending_mailbox.len()
    }

    fn put_mailbox(
        &mut self,
        session_id: &str,
        item_id: &str,
        text: &str,
        opts: &MailboxPutOptions,
        actual_receipt: Option<&str>,
        now_ms: i64,
    ) -> &'static str {
        if let Some(key) = opts.coalesce_key.as_deref() {
            if self
                .seen_mailbox_keys
                .contains(&(session_id.to_string(), item_id.to_string()))
            {
                return "duplicate";
            }
            if let Some(existing) = self
                .pending_mailbox
                .iter_mut()
                .rev()
                .find(|r| r.session_id == session_id && r.coalesce_key.as_deref() == Some(key))
            {
                existing.item_id = item_id.to_string();
                existing.text = text.to_string();
                existing.received_at = now_ms;
                existing.expires_at = opts.expires_at;
                existing.notified = false;
                existing.missed_count += 1;
                self.seen_mailbox_keys
                    .insert((session_id.to_string(), item_id.to_string()));
                return "stored";
            }
        }
        let pending_for_sess = self
            .pending_mailbox
            .iter()
            .filter(|r| r.session_id == session_id)
            .count();
        if pending_for_sess >= self.max_pending_per_session {
            return "queue_full";
        }
        if !self
            .seen_mailbox_keys
            .insert((session_id.to_string(), item_id.to_string()))
        {
            return "duplicate";
        }
        self.pending_mailbox.push(OracleMailboxRow {
            receipt: actual_receipt.unwrap_or_default().to_string(),
            session_id: session_id.to_string(),
            item_id: item_id.to_string(),
            text: text.to_string(),
            received_at: now_ms,
            notified: false,
            coalesce_key: opts.coalesce_key.clone(),
            expires_at: opts.expires_at,
            missed_count: 0,
        });
        "stored"
    }

    fn drain_mailbox(&mut self, session_id: &str) -> Vec<OracleMailboxRow> {
        let mut drained = Vec::new();
        let mut keep = Vec::new();
        for row in self.pending_mailbox.drain(..) {
            if row.session_id == session_id {
                drained.push(row);
            } else {
                keep.push(row);
            }
        }
        self.pending_mailbox = keep;
        drained.sort_by(|a, b| {
            a.received_at
                .cmp(&b.received_at)
                .then(a.receipt.cmp(&b.receipt))
        });
        drained
    }

    fn next_mailbox_ttl_deadline(&self) -> Option<i64> {
        self.pending_mailbox
            .iter()
            .filter_map(|r| r.expires_at)
            .min()
    }
}

#[test]
fn differential_mailbox_state_machine_with_wal_reopen() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("oracle-node.sqlite");

    let store_cfg = StoreConfig {
        mailbox_max_pending_per_session: 5,
        ..StoreConfig::default()
    };

    let mut db = NodeDb::open_with_config(&db_path, store_cfg.clone()).unwrap();
    let mut oracle = ReferenceOracle::new(5);
    let mut rng = XorShift64(0xDEAD_BEEF_CAFE_BABEu64);

    let sessions = ["sess-a", "sess-b", "sess-c"];

    let mut now = BASE_T0;
    let mut next_item_seq = 0usize;

    for step in 0..320usize {
        // Periodically close and reopen WAL SQLite to verify crash/restart persistence parity!
        if step > 0 && step % 64 == 0 {
            drop(db);
            db = NodeDb::open_with_config(&db_path, store_cfg.clone()).unwrap();
        }

        let op = rng.range(100);
        if op < 25 {
            now += (1 + rng.range(60)) as i64 * MIN_MS;
            let expired = oracle.expire_mailbox(now);
            assert_eq!(
                db.tick(now).unwrap().mailbox_expired,
                expired,
                "step {step}"
            );
        } else if op < 78 {
            // Standalone mailbox put with coalescing + optional TTL.
            next_item_seq += 1;
            let sess = sessions[rng.range(sessions.len())];
            let wk_key = format!("wk-mb-{}", rng.range(3));
            let item_id = format!("mb-{next_item_seq}");
            let text = format!("payload-{next_item_seq}");
            let opts = MailboxPutOptions {
                coalesce_key: if rng.range(3) != 0 {
                    Some(format!("event:{wk_key}"))
                } else {
                    None
                },
                expires_at: if rng.range(2) == 0 {
                    Some(now + ((rng.range(5) as i64) + 1) * 10 * MIN_MS)
                } else {
                    None
                },
            };
            let s_put = db
                .local()
                .put_in_mailbox_ex(
                    &event_mailbox_insert(sess, &wk_key, &item_id, &text),
                    &opts,
                    now,
                )
                .unwrap();
            let (s_tag, receipt_opt) = match &s_put {
                MailboxPutResult::Stored { receipt } => ("stored", Some(receipt.as_str())),
                MailboxPutResult::Duplicate => ("duplicate", None),
                MailboxPutResult::QueueFull => ("queue_full", None),
            };
            let o_tag = oracle.put_mailbox(sess, &item_id, &text, &opts, receipt_opt, now);
            assert_eq!(s_tag, o_tag, "step {step}: standalone mailbox put mismatch");
        } else {
            // Drain a random session's inbox.
            let sess = sessions[rng.range(sessions.len())];
            let o_drained = oracle.drain_mailbox(sess);
            let s_drained = db.local().drain_inbox_ex(sess, 100, now).unwrap();
            assert_eq!(
                s_drained.len(),
                o_drained.len(),
                "step {step}: drain count mismatch"
            );
            for (sd, od) in s_drained.iter().zip(o_drained.iter()) {
                assert_eq!(sd.entry.receipt, od.receipt);
                assert_eq!(sd.entry.item_id, od.item_id);
                assert_eq!(sd.entry.text, od.text);
                assert_eq!(sd.coalesce_key, od.coalesce_key);
                assert_eq!(sd.expires_at, od.expires_at);
                assert_eq!(sd.missed_count, od.missed_count);
            }
        }

        let bd = db.next_deadline_breakdown(now).unwrap();
        assert_eq!(
            bd.mailbox_ttl,
            oracle.next_mailbox_ttl_deadline(),
            "step {step}: mailbox_ttl deadline mismatch"
        );
        assert_eq!(bd.earliest, bd.earliest());

        for sess in sessions {
            let s_inbox = db.local().peek_inbox_ex(sess, 100).unwrap();
            let mut o_inbox: Vec<&OracleMailboxRow> = oracle
                .pending_mailbox
                .iter()
                .filter(|r| r.session_id == sess)
                .collect();
            o_inbox.sort_by(|a, b| {
                a.received_at
                    .cmp(&b.received_at)
                    .then(a.receipt.cmp(&b.receipt))
            });
            assert_eq!(
                s_inbox.len(),
                o_inbox.len(),
                "step {step} {sess}: pending len mismatch"
            );
            for (si, oi) in s_inbox.iter().zip(o_inbox.iter()) {
                assert_eq!(si.entry.receipt, oi.receipt);
                assert_eq!(si.entry.item_id, oi.item_id);
                assert_eq!(si.entry.text, oi.text);
                assert_eq!(si.entry.notified, oi.notified);
                assert_eq!(si.coalesce_key, oi.coalesce_key);
                assert_eq!(si.expires_at, oi.expires_at);
                assert_eq!(si.missed_count, oi.missed_count);
            }
        }
    }
}

type TableColumns = Vec<(String, String, i64, Option<String>)>;

fn snapshot_schema_tables_and_columns(conn: &Connection) -> BTreeMap<String, TableColumns> {
    let mut tables = Vec::new();
    {
        let mut stmt = conn
            .prepare(
                "SELECT name FROM sqlite_master
                 WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
                 ORDER BY name ASC",
            )
            .unwrap();
        let rows = stmt
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        tables.extend(rows);
    }

    let mut out = BTreeMap::new();
    for table in tables {
        let mut stmt = conn
            .prepare(&format!("PRAGMA table_info(\"{table}\")"))
            .unwrap();
        let cols = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, Option<String>>(4)?,
                ))
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        out.insert(table, cols);
    }
    out
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

fn seed_v2_db(path: &Path) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
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
    conn.execute_batch(SCHEMA_V2_SQL).unwrap();
    conn.execute(
        "INSERT INTO schema_version (version, applied_at) VALUES (1, ?1), (2, ?2)",
        params![BASE_T0, BASE_T0 + 100],
    )
    .unwrap();

    // Seed v2 data across handles (with description), peer_routes, sessions, and mailbox.
    conn.execute(
        "INSERT INTO handles (node_id, handle, session_id, registered_at, last_heartbeat_at, description)
         VALUES ('local', 'claude', 'sess-v2', ?1, ?1, 'v2 reviewer')",
        params![BASE_T0],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO peer_routes (target_node, via_peer, updated_at)
         VALUES ('bob@lap', 'acme-hub', ?1)",
        params![BASE_T0],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO sessions (id, backend_json, handle, last_seen, delivery_mode, created_at)
         VALUES ('sess-v2', '{\"harness\":\"claude\"}', 'claude', ?1, 'full', ?1)",
        params![BASE_T0],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO mailbox (receipt, session_id, origin_node, item_id, text, received_at, kind, source, gate_state)
         VALUES ('rcpt-v2', 'sess-v2', 'acme-hub', 'msg-v2', 'preserved across v2->v3', ?1, 'message', 'bob@lap/codex', 'pending')",
        params![BASE_T0 + 50],
    )
    .unwrap();
}

#[test]
fn historical_mailbox_upgrade_backup_and_data_preservation() {
    let dir = TempDir::new().unwrap();
    let v2_path = dir.path().join("v2-upgrade").join("node.sqlite");
    let v1_path = dir.path().join("v1-upgrade").join("node.sqlite");
    let fresh_path = dir.path().join("fresh").join("node.sqlite");

    // 1. Seed v2 DB & open to upgrade v2 -> v3.
    seed_v2_db(&v2_path);
    let migrated_v2 = NodeDb::open(&v2_path).unwrap();

    // 2. Seed v1 DB & open to upgrade v1 -> v2 -> v3.
    {
        fs::create_dir_all(v1_path.parent().unwrap()).unwrap();
        let conn = Connection::open(&v1_path).unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL);",
        )
        .unwrap();
        conn.execute_batch(SCHEMA_V1_SQL).unwrap();
        conn.execute(
            "INSERT INTO schema_version (version, applied_at) VALUES (1, ?1)",
            params![BASE_T0],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO mailbox (receipt, session_id, origin_node, item_id, text, received_at, kind, source, gate_state)
             VALUES ('rcpt-v1', 'sess-v1', 'local', 'msg-v1', 'preserved across v1->v3', ?1, 'message', 'local/bot', 'pending')",
            params![BASE_T0],
        )
        .unwrap();
    }
    let migrated_v1 = NodeDb::open(&v1_path).unwrap();
    let fresh = NodeDb::open(&fresh_path).unwrap();

    assert_eq!(
        migrated_v2.schema_version().unwrap(),
        CURRENT_SCHEMA_VERSION
    );
    assert_eq!(
        migrated_v1.schema_version().unwrap(),
        CURRENT_SCHEMA_VERSION
    );
    assert_eq!(fresh.schema_version().unwrap(), CURRENT_SCHEMA_VERSION);
    assert!(migrated_v2.schema_version().unwrap() >= 3);

    // Exact schema parity: v2->v3 and v1->v2->v3 both match fresh v3 bit-for-bit!
    let fresh_cols = snapshot_schema_tables_and_columns(fresh.connection());
    let fresh_idx = snapshot_indexes(fresh.connection());
    assert_eq!(
        snapshot_schema_tables_and_columns(migrated_v2.connection()),
        fresh_cols
    );
    assert_eq!(
        snapshot_schema_tables_and_columns(migrated_v1.connection()),
        fresh_cols
    );
    assert_eq!(snapshot_indexes(migrated_v2.connection()), fresh_idx);
    assert_eq!(snapshot_indexes(migrated_v1.connection()), fresh_idx);

    // Verify v2->v3 backup exists, is 0600, and is a genuine pre-migration v2 snapshot!
    let v2_backups = migrated_v2.list_migration_backups().unwrap();
    assert_eq!(v2_backups.len(), 1);
    let bak_name = v2_backups[0].file_name().unwrap().to_str().unwrap();
    assert!(
        bak_name.starts_with(&format!("node.sqlite.v2-to-v{CURRENT_SCHEMA_VERSION}-"))
            && bak_name.ends_with(".bak"),
        "unexpected v2->v{CURRENT_SCHEMA_VERSION} backup name: {bak_name}"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&v2_backups[0]).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
    let bak_conn =
        Connection::open_with_flags(&v2_backups[0], OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    let bak_ver: i64 = bak_conn
        .query_row("SELECT MAX(version) FROM schema_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(bak_ver, 2);
    let bak_cols = snapshot_schema_tables_and_columns(&bak_conn);
    assert!(!bak_cols.contains_key("wakeups"));

    // Verify v1->latest backup exists and is a genuine v1 snapshot!
    let v1_backups = migrated_v1.list_migration_backups().unwrap();
    assert_eq!(v1_backups.len(), 1);
    assert!(
        v1_backups[0]
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with(&format!("node.sqlite.v1-to-v{CURRENT_SCHEMA_VERSION}-"))
    );

    // Verify all pre-existing v2 data survived untouched and mailbox defaults are clean.
    let h = migrated_v2
        .messages()
        .get_handle("local", "claude")
        .unwrap()
        .unwrap();
    assert_eq!(h.description.as_deref(), Some("v2 reviewer"));
    assert_eq!(
        migrated_v2
            .peers()
            .get_peer_route("bob@lap")
            .unwrap()
            .unwrap()
            .via_peer,
        "acme-hub"
    );
    let mb_v2 = migrated_v2
        .local()
        .get_mailbox_entry_ex("rcpt-v2")
        .unwrap()
        .unwrap();
    assert_eq!(mb_v2.entry.text, "preserved across v2->v3");
    assert_eq!(mb_v2.coalesce_key, None);
    assert_eq!(mb_v2.expires_at, None);
    assert_eq!(mb_v2.missed_count, 0);

    let mb_v1 = migrated_v1
        .local()
        .get_mailbox_entry_ex("rcpt-v1")
        .unwrap()
        .unwrap();
    assert_eq!(mb_v1.entry.text, "preserved across v1->v3");
    assert_eq!(mb_v1.missed_count, 0);
}
