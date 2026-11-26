//! Differential SQLite schema migration, backup, concurrency, rollback, handle-description,
//! and multi-hub `peer_routes` end-to-end tests for `hyp-store` v0.3.0 (schema v2).

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::Path;
use std::sync::{Arc, Barrier};
use std::thread;

use hyp_store::{
    CURRENT_SCHEMA_VERSION, GateAuditQuery, HandleRecord, MAX_HANDLE_DESCRIPTION_CHARS,
    MAX_MIGRATION_BACKUPS, MIGRATIONS, Migration, MigrationKind, NodeDb, PeerInput, PeerProfile,
    PeerRoute, PeerStatus, StoreError, TrustTier, run_migrations_with, sanitize_handle_description,
};
use rusqlite::{Connection, OpenFlags, params};
use tempfile::TempDir;

const SCHEMA_V1_SQL: &str = include_str!("../migrations/0001_initial_v2.sql");
const T0: i64 = 1_700_000_000_000;

#[derive(Debug, Clone, PartialEq, Eq)]
struct ColumnInfo {
    cid: i64,
    name: String,
    col_type: String,
    notnull: i64,
    dflt_value: Option<String>,
    pk: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ForeignKeyInfo {
    id: i64,
    seq: i64,
    table: String,
    from: String,
    to: String,
    on_update: String,
    on_delete: String,
    match_clause: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CanonicalSchema {
    table_sql: BTreeMap<String, String>,
    table_columns: BTreeMap<String, Vec<ColumnInfo>>,
    table_fks: BTreeMap<String, Vec<ForeignKeyInfo>>,
    indexes: BTreeMap<String, (String, Option<String>)>,
    triggers: BTreeMap<String, (String, Option<String>)>,
}

fn snapshot_canonical_schema(conn: &Connection) -> CanonicalSchema {
    let mut table_sql = BTreeMap::new();
    {
        let mut stmt = conn
            .prepare(
                "SELECT name, sql FROM sqlite_master
                 WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
                 ORDER BY name ASC",
            )
            .unwrap();
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .unwrap();
        for row in rows {
            let (name, sql) = row.unwrap();
            table_sql.insert(name, sql);
        }
    }

    let mut table_columns = BTreeMap::new();
    let mut table_fks = BTreeMap::new();
    for table in table_sql.keys() {
        let mut col_stmt = conn
            .prepare(&format!("PRAGMA table_info(\"{table}\")"))
            .unwrap();
        let cols: Vec<ColumnInfo> = col_stmt
            .query_map([], |row| {
                Ok(ColumnInfo {
                    cid: row.get(0)?,
                    name: row.get(1)?,
                    col_type: row.get(2)?,
                    notnull: row.get(3)?,
                    dflt_value: row.get(4)?,
                    pk: row.get(5)?,
                })
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        table_columns.insert(table.clone(), cols);

        let mut fk_stmt = conn
            .prepare(&format!("PRAGMA foreign_key_list(\"{table}\")"))
            .unwrap();
        let fks: Vec<ForeignKeyInfo> = fk_stmt
            .query_map([], |row| {
                Ok(ForeignKeyInfo {
                    id: row.get(0)?,
                    seq: row.get(1)?,
                    table: row.get(2)?,
                    from: row.get(3)?,
                    to: row.get(4)?,
                    on_update: row.get(5)?,
                    on_delete: row.get(6)?,
                    match_clause: row.get(7)?,
                })
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        table_fks.insert(table.clone(), fks);
    }

    let mut indexes = BTreeMap::new();
    {
        let mut stmt = conn
            .prepare(
                "SELECT name, tbl_name, sql FROM sqlite_master
                 WHERE type = 'index' AND name NOT LIKE 'sqlite_%'
                 ORDER BY name ASC",
            )
            .unwrap();
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            })
            .unwrap();
        for row in rows {
            let (name, tbl, sql) = row.unwrap();
            indexes.insert(name, (tbl, sql));
        }
    }

    let mut triggers = BTreeMap::new();
    {
        let mut stmt = conn
            .prepare(
                "SELECT name, tbl_name, sql FROM sqlite_master
                 WHERE type = 'trigger'
                 ORDER BY name ASC",
            )
            .unwrap();
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            })
            .unwrap();
        for row in rows {
            let (name, tbl, sql) = row.unwrap();
            triggers.insert(name, (tbl, sql));
        }
    }

    CanonicalSchema {
        table_sql,
        table_columns,
        table_fks,
        indexes,
        triggers,
    }
}

/// Builds a realistic v0.2.0 (`schema_version = 1`) SQLite database seeded across all major tables.
fn create_seeded_v1_db(path: &Path, enable_wal: bool) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    let conn = Connection::open(path).unwrap();
    conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
    if enable_wal {
        let _: String = conn
            .query_row("PRAGMA journal_mode = WAL", [], |r| r.get(0))
            .unwrap();
    }
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

    // Seed peers
    conn.execute(
        "INSERT INTO peers (peer_id, endpoint, profile, trust_tier, status, scopes_json, created_at, updated_at)
         VALUES (?1, ?2, 'router', 'org', 'active', '[\"dm:send\",\"channel:post\"]', ?3, ?3)",
        params!["acme-team", "https://hub.acme.example", T0],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO peers (peer_id, endpoint, profile, trust_tier, status, scopes_json, created_at, updated_at)
         VALUES (?1, ?2, 'p2p', 'peer', 'active', '[\"dm:send\"]', ?3, ?3)",
        params!["bob@laptop", "https://bob.local:8443", T0 + 1],
    )
    .unwrap();

    // Seed handles (v1 has no `description` column)
    conn.execute(
        "INSERT INTO handles (node_id, handle, session_id, registered_at, last_heartbeat_at)
         VALUES ('local', 'claude', 'sess-1', ?1, ?1),
                ('acme-team', 'codex', NULL, ?1, ?1)",
        params![T0],
    )
    .unwrap();

    // Seed messages
    conn.execute(
        "INSERT INTO messages (id, from_addr, to_addr, channel, text, digest, sent_at, state)
         VALUES ('msg-1', 'acme-team/codex', 'local/claude', NULL, 'hello from v1', 'deadbeef', ?1, 'pending'),
                ('msg-2', 'acme-team/codex', 'local/claude', '#incidents', 'alert text', 'cafebabe', ?2, 'pending')",
        params![T0 + 10, T0 + 20],
    )
    .unwrap();

    // Seed channel_members & channel_epochs
    conn.execute(
        "INSERT INTO channel_members (host_node, channel, address, joined_at)
         VALUES ('acme-team', '#incidents', 'local/claude', ?1),
                ('acme-team', '#incidents', 'acme-team/codex', ?1)",
        params![T0 + 5],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO channel_epochs (host_node, channel, epoch, creator_node_id, key_envelope_json, members_json, signature, created_at)
         VALUES ('acme-team', '#incidents', 1, 'acme-team', '{\"k\":\"v1\"}', '[\"acme-team/codex\",\"local/claude\"]', 'sig1', ?1)",
        params![T0 + 6],
    )
    .unwrap();

    // Seed publishers & publisher_grants (foreign key relationship)
    conn.execute(
        "INSERT INTO publishers (id, token_hash, created_at) VALUES ('gh-pub', 'hash-123', ?1)",
        params![T0],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO publisher_grants (publisher_id, topic) VALUES ('gh-pub', 'github')",
        [],
    )
    .unwrap();

    // Seed events, subscriptions, batches, batch_events
    conn.execute(
        "INSERT INTO events (origin_node, topic, publisher, source, event_id, digest, body, bytes, matched, received_at)
         VALUES ('acme-team', 'github', 'gh-pub', 'github.com/acme/app', 'ev-1', 'd1', '{}', 2, 1, ?1)",
        params![T0 + 30],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO subscriptions (id, origin_node, topic, subscriber, filters_json, coalesce_seconds, mode, created_at, updated_at)
         VALUES ('sub-1', 'acme-team', 'github', 'sess-1', '[]', 0, 'full', ?1, ?1)",
        params![T0 + 25],
    )
    .unwrap();

    // Seed kv_entries
    conn.execute(
        "INSERT INTO kv_entries (host_node, namespace, key, value_json, version, write_model, writer_id, created_at, updated_at)
         VALUES ('local', 'deploy', 'active', '{\"sha\":\"abc123\"}', 1, 'shared', 'local/claude', ?1, ?1)",
        params![T0 + 40],
    )
    .unwrap();

    // Seed sessions, mailbox, bridge_links, plugin_targets, gate_audit
    conn.execute(
        "INSERT INTO sessions (id, backend_json, handle, last_seen, delivery_mode, created_at)
         VALUES ('sess-1', '{\"harness\":\"claude\"}', 'claude', ?1, 'full', ?1)",
        params![T0],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO mailbox (receipt, session_id, origin_node, item_id, text, received_at, kind, source, gate_state)
         VALUES ('rcpt-1', 'sess-1', 'acme-team', 'msg-1', 'hello from v1', ?1, 'message', 'acme-team/codex', 'pending')",
        params![T0 + 15],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO bridge_links (plugin, target, session_id, linked_at, linked_by)
         VALUES ('slack', 'C01234', 'sess-1', ?1, 'claude')",
        params![T0 + 50],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO plugin_targets (plugin, target, session_id, set_at, set_by)
         VALUES ('slack', 'C01234', 'sess-1', ?1, 'claude')",
        params![T0 + 50],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO gate_audit (created_at, direction, stage, decision, origin_node, source, session_id, payload_sha256)
         VALUES (?1, 'inbound', 'prefilter', 'allow', 'acme-team', 'acme-team/codex', 'sess-1', 'abc')",
        params![T0 + 60],
    )
    .unwrap();
}

#[test]
fn registry_invariants_and_invalid_registry_rejection() {
    assert_eq!(CURRENT_SCHEMA_VERSION, 7);
    assert_eq!(MIGRATIONS.len() as i64, CURRENT_SCHEMA_VERSION);
    let mut names = HashSet::new();
    for (idx, m) in MIGRATIONS.iter().enumerate() {
        assert_eq!(m.version, (idx as i64) + 1);
        assert!(!m.name.is_empty());
        assert!(names.insert(m.name), "duplicate migration name {}", m.name);
    }

    let conn = Connection::open_in_memory().unwrap();
    let bad_order = [
        Migration {
            version: 2,
            name: "second",
            disable_foreign_keys: false,
            kind: MigrationKind::Sql("SELECT 1;"),
        },
        Migration {
            version: 1,
            name: "first",
            disable_foreign_keys: false,
            kind: MigrationKind::Sql("SELECT 1;"),
        },
    ];
    assert!(matches!(
        run_migrations_with(&conn, None, &bad_order),
        Err(StoreError::InvalidInput(_))
    ));

    let dup_name = [
        Migration {
            version: 1,
            name: "same",
            disable_foreign_keys: false,
            kind: MigrationKind::Sql("SELECT 1;"),
        },
        Migration {
            version: 2,
            name: "same",
            disable_foreign_keys: false,
            kind: MigrationKind::Sql("SELECT 1;"),
        },
    ];
    assert!(matches!(
        run_migrations_with(&conn, None, &dup_name),
        Err(StoreError::InvalidInput(_))
    ));
}

#[test]
fn differential_schema_and_data_parity_v1_migrated_equals_fresh_v2() {
    let dir = TempDir::new().unwrap();
    // Deliberately include a single quote in a directory segment to exercise SQL literal escaping
    // in `VACUUM INTO '<path>'`.
    let migrated_path = dir.path().join("o'connor-state").join("node.sqlite");
    let fresh_path = dir.path().join("fresh-state").join("node.sqlite");

    create_seeded_v1_db(&migrated_path, true);

    let migrated = NodeDb::open(&migrated_path).unwrap();
    let fresh = NodeDb::open(&fresh_path).unwrap();

    // 1. Exact structural equality across sqlite_master, PRAGMA table_info, FKs, indexes, triggers.
    let migrated_schema = snapshot_canonical_schema(migrated.connection());
    let fresh_schema = snapshot_canonical_schema(fresh.connection());
    assert_eq!(
        migrated_schema, fresh_schema,
        "migrated v1->v2 schema must match fresh v2 schema bit-for-bit"
    );

    // 2. Version & applied_migrations metadata.
    assert_eq!(migrated.schema_version().unwrap(), CURRENT_SCHEMA_VERSION);
    assert_eq!(fresh.schema_version().unwrap(), CURRENT_SCHEMA_VERSION);
    let applied_migrated = migrated.applied_migrations().unwrap();
    assert_eq!(
        applied_migrated.iter().map(|(v, _)| *v).collect::<Vec<_>>(),
        vec![1, 2, 3, 4, 5, 6, 7]
    );
    assert_eq!(applied_migrated[0].1, T0);
    assert!(applied_migrated[1].1 >= T0);
    assert!(applied_migrated[2].1 >= T0);
    assert!(applied_migrated[3].1 >= T0);
    assert!(applied_migrated[4].1 >= T0);
    assert!(applied_migrated[5].1 >= T0);
    assert!(applied_migrated[6].1 >= T0);

    // 3. All seeded v1 rows survive untouched; handles default to `description: None`.
    let peer = migrated.peers().get_peer("acme-team").unwrap().unwrap();
    assert_eq!(peer.endpoint.as_deref(), Some("https://hub.acme.example"));
    assert_eq!(migrated.peers().list_peers(None).unwrap().len(), 2);

    let handles = migrated.messages().list_handles(None).unwrap();
    assert_eq!(handles.len(), 2);
    for h in &handles {
        assert_eq!(h.description, None);
    }
    let claude = migrated
        .messages()
        .get_handle("local", "claude")
        .unwrap()
        .unwrap();
    assert_eq!(claude.session_id.as_deref(), Some("sess-1"));
    assert_eq!(claude.description, None);

    let msg1 = migrated.messages().get_message("msg-1").unwrap().unwrap();
    assert_eq!(msg1.text, "hello from v1");
    let msg2 = migrated.messages().get_message("msg-2").unwrap().unwrap();
    assert_eq!(msg2.channel.as_deref(), Some("#incidents"));

    assert_eq!(
        migrated
            .channels()
            .members("acme-team", "#incidents")
            .unwrap(),
        vec!["acme-team/codex", "local/claude"]
    );
    let ep1 = migrated
        .channels()
        .latest_epoch("acme-team", "#incidents")
        .unwrap()
        .unwrap();
    assert_eq!(ep1.epoch, 1);

    let kv = migrated
        .kv()
        .get("local", "deploy", "active", T0 + 100)
        .unwrap()
        .unwrap();
    assert_eq!(kv.value["sha"], "abc123");

    let sess = migrated.local().get_session("sess-1").unwrap().unwrap();
    assert_eq!(sess.handle.as_deref(), Some("claude"));
    let mailbox = migrated.local().peek_inbox("sess-1", 10).unwrap();
    assert_eq!(mailbox.len(), 1);
    assert_eq!(mailbox[0].receipt, "rcpt-1");
    assert_eq!(
        migrated
            .local()
            .bridge_links_for_session("sess-1")
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        migrated
            .local()
            .get_plugin_target("slack", "C01234")
            .unwrap()
            .unwrap()
            .session_id,
        "sess-1"
    );
    assert_eq!(
        migrated
            .local()
            .query_gate_audit(&GateAuditQuery::default())
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        migrated
            .events()
            .list_subscriptions(Some("sess-1"))
            .unwrap()
            .len(),
        1
    );

    // 4. Pre-migration backup verification (exists, 0600 perms, valid readable v1 SQLite DB).
    let backups = migrated.list_migration_backups().unwrap();
    assert_eq!(backups.len(), 1, "exactly one v1->v2 backup must exist");
    let backup_path = &backups[0];
    assert!(backup_path.exists());
    let backup_name = backup_path.file_name().unwrap().to_str().unwrap();
    assert!(
        backup_name.starts_with(&format!("node.sqlite.v1-to-v{CURRENT_SCHEMA_VERSION}-"))
            && backup_name.ends_with(".bak"),
        "unexpected backup filename: {backup_name}"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let dir_mode = fs::metadata(backup_path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700, "backups dir must be 0700");
        let file_mode = fs::metadata(backup_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(file_mode, 0o600, "backup file must be 0600");
    }

    // Open backup read-only and verify it is a genuine pre-migration v1 snapshot.
    let bak_conn =
        Connection::open_with_flags(backup_path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    let bak_ver: i64 = bak_conn
        .query_row("SELECT MAX(version) FROM schema_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(bak_ver, 1);
    let bak_schema = snapshot_canonical_schema(&bak_conn);
    assert!(!bak_schema.table_sql.contains_key("peer_routes"));
    assert!(!bak_schema.table_sql.contains_key("wakeups"));
    assert!(!bak_schema.table_sql.contains_key("human_authorities"));
    assert!(!bak_schema.table_sql.contains_key("human_claim_nonces"));
    assert!(!bak_schema.table_sql.contains_key("human_node_certs"));
    assert!(
        !bak_schema.table_columns["handles"]
            .iter()
            .any(|c| c.name == "description")
    );
    let bak_msg: String = bak_conn
        .query_row("SELECT text FROM messages WHERE id = 'msg-1'", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(bak_msg, "hello from v1");

    // Fresh DB had no pre-existing v1 data, so zero backups should have been created for it.
    assert!(fresh.list_migration_backups().unwrap().is_empty());
}

#[test]
fn idempotent_reopen_zero_write_lock_fast_path_and_backup_retention() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("node.sqlite");
    create_seeded_v1_db(&db_path, true);

    // Seed 5 older mock backups before upgrading v1 -> v2.
    let backups_dir = dir.path().join("backups");
    fs::create_dir_all(&backups_dir).unwrap();
    for i in 1..=5 {
        let mock = backups_dir.join(format!("node.sqlite.v1-to-v2-{}000-1.bak", i));
        fs::write(&mock, format!("mock-backup-{i}")).unwrap();
    }

    let db = NodeDb::open(&db_path).unwrap();
    assert_eq!(db.schema_version().unwrap(), CURRENT_SCHEMA_VERSION);

    let backups = db.list_migration_backups().unwrap();
    assert_eq!(
        backups.len(),
        MAX_MIGRATION_BACKUPS,
        "retention must trim backups to MAX_MIGRATION_BACKUPS ({MAX_MIGRATION_BACKUPS})"
    );
    // Newest backup (index 0) must be the real SQLite v1 backup created during migration.
    let bak_conn =
        Connection::open_with_flags(&backups[0], OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    let bak_ver: i64 = bak_conn
        .query_row("SELECT MAX(version) FROM schema_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(bak_ver, 1);

    // Re-opening an already-v2 DB creates ZERO additional backups.
    drop(db);
    let db2 = NodeDb::open(&db_path).unwrap();
    let backups_after = db2.list_migration_backups().unwrap();
    assert_eq!(backups_after, backups);

    // Verify fast-path takes ZERO write lock: hold an active `BEGIN IMMEDIATE` write lock on
    // another connection while `NodeDb::open` opens the already-v2 DB.
    let writer = Connection::open(&db_path).unwrap();
    writer.execute_batch("BEGIN IMMEDIATE;").unwrap();
    let db3 = NodeDb::open(&db_path).unwrap();
    assert_eq!(db3.schema_version().unwrap(), CURRENT_SCHEMA_VERSION);
    writer.execute_batch("ROLLBACK;").unwrap();

    // In-memory DB reports no backups.
    let mem = NodeDb::open_in_memory().unwrap();
    assert!(mem.list_migration_backups().unwrap().is_empty());
}

#[test]
fn eight_thread_concurrent_open_upgrade_storm_on_wal_and_delete_v1_dbs() {
    for enable_wal in [true, false] {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("node.sqlite");
        create_seeded_v1_db(&db_path, enable_wal);

        let threads = 8usize;
        let barrier = Arc::new(Barrier::new(threads));
        let mut joins = Vec::with_capacity(threads);

        for tid in 0..threads {
            let path = db_path.clone();
            let barrier = Arc::clone(&barrier);
            joins.push(thread::spawn(move || {
                barrier.wait();
                let db = NodeDb::open(&path)
                    .unwrap_or_else(|e| panic!("thread {tid} failed NodeDb::open: {e}"));
                assert_eq!(db.schema_version().unwrap(), CURRENT_SCHEMA_VERSION);
                assert_eq!(db.journal_mode().unwrap().to_lowercase(), "wal");
                let handles = db.messages().list_handles(None).unwrap();
                assert_eq!(handles.len(), 2);
                db.peers()
                    .upsert_peer_route(&format!("node-{tid}"), "acme-team", T0 + (tid as i64))
                    .unwrap();
            }));
        }

        for j in joins {
            j.join().unwrap();
        }

        let final_db = NodeDb::open(&db_path).unwrap();
        assert_eq!(final_db.schema_version().unwrap(), CURRENT_SCHEMA_VERSION);
        let integrity: String = final_db
            .connection()
            .query_row("PRAGMA integrity_check", [], |r| r.get(0))
            .unwrap();
        assert_eq!(integrity, "ok");
        assert_eq!(final_db.peers().list_peer_routes().unwrap().len(), threads);

        let backups = final_db.list_migration_backups().unwrap();
        assert!(
            !backups.is_empty() && backups.len() <= MAX_MIGRATION_BACKUPS,
            "expected 1..={MAX_MIGRATION_BACKUPS} backups, found {}",
            backups.len()
        );
    }
}

#[test]
fn mid_migration_failure_rolls_back_atomically_and_fk_rebuild_safety() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("node.sqlite");
    let db = NodeDb::open(&db_path).unwrap();
    assert_eq!(db.schema_version().unwrap(), CURRENT_SCHEMA_VERSION);
    let next_ver = CURRENT_SCHEMA_VERSION + 1;

    // Seed a publisher + publisher_grants row (FK child -> parent).
    db.events()
        .add_publisher("pub-1", "tok-secret-1", &["github"], T0)
        .unwrap();

    // 1. Failing SQL next-version migration must roll back partial DDL atomically.
    let mut failing_sql_migrations = MIGRATIONS.to_vec();
    failing_sql_migrations.push(Migration {
        version: next_ver,
        name: "0006_broken_sql",
        disable_foreign_keys: false,
        kind: MigrationKind::Sql(
            "CREATE TABLE partial_should_rollback (id INTEGER PRIMARY KEY);
             INSERT INTO partial_should_rollback (id) VALUES (1);
             THIS IS INVALID SQL;",
        ),
    });
    let err =
        run_migrations_with(db.connection(), Some(&db_path), &failing_sql_migrations).unwrap_err();
    assert!(matches!(err, StoreError::Sqlite(_)));
    assert_eq!(db.schema_version().unwrap(), CURRENT_SCHEMA_VERSION);
    let partial_exists: Option<i64> = db
        .connection()
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'partial_should_rollback'",
            [],
            |r| r.get(0),
        )
        .ok();
    assert_eq!(partial_exists, None, "partial DDL must be rolled back");
    // Pre-migration backup should have been captured before the next migration ran.
    assert_eq!(db.list_migration_backups().unwrap().len(), 1);

    // 2. Failing Fn next-version migration must also roll back atomically.
    fn failing_fn(conn: &Connection) -> hyp_store::StoreResult<()> {
        conn.execute_batch("CREATE TABLE fn_partial (id INTEGER PRIMARY KEY);")?;
        Err(StoreError::InvalidState("simulated fn error".to_string()))
    }
    let mut failing_fn_migrations = MIGRATIONS.to_vec();
    failing_fn_migrations.push(Migration {
        version: next_ver,
        name: "0006_broken_fn",
        disable_foreign_keys: false,
        kind: MigrationKind::Fn(failing_fn),
    });
    let err =
        run_migrations_with(db.connection(), Some(&db_path), &failing_fn_migrations).unwrap_err();
    assert!(matches!(err, StoreError::InvalidState(_)));
    assert_eq!(db.schema_version().unwrap(), CURRENT_SCHEMA_VERSION);
    let fn_partial_exists: Option<i64> = db
        .connection()
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'fn_partial'",
            [],
            |r| r.get(0),
        )
        .ok();
    assert_eq!(fn_partial_exists, None);

    // 3. `disable_foreign_keys: true` migration that leaves an FK violation must fail
    //    `PRAGMA foreign_key_check`, roll back, AND unconditionally restore `PRAGMA foreign_keys = ON`.
    let mut fk_violation_migrations = MIGRATIONS.to_vec();
    fk_violation_migrations.push(Migration {
        version: next_ver,
        name: "0006_fk_orphan",
        disable_foreign_keys: true,
        kind: MigrationKind::Sql(
            "INSERT INTO publisher_grants (publisher_id, topic) VALUES ('ghost-pub', 'alerts');",
        ),
    });
    let err =
        run_migrations_with(db.connection(), Some(&db_path), &fk_violation_migrations).unwrap_err();
    assert!(
        matches!(err, StoreError::InvalidState(ref msg) if msg.contains("foreign_key_check")),
        "expected foreign_key_check InvalidState, got: {err:?}"
    );
    assert_eq!(db.schema_version().unwrap(), CURRENT_SCHEMA_VERSION);
    let orphan_count: i64 = db
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM publisher_grants WHERE publisher_id = 'ghost-pub'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(orphan_count, 0, "orphan FK row must be rolled back");
    let fk_enabled: i64 = db
        .connection()
        .query_row("PRAGMA foreign_keys", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        fk_enabled, 1,
        "PRAGMA foreign_keys must be restored to ON after rollback"
    );

    // 4. Valid `disable_foreign_keys: true` table rebuild succeeds and restores `PRAGMA foreign_keys = ON`.
    let mut fk_rebuild_ok = MIGRATIONS.to_vec();
    fk_rebuild_ok.push(Migration {
        version: next_ver,
        name: "0006_rebuild_publishers_ok",
        disable_foreign_keys: true,
        kind: MigrationKind::Sql(
            "CREATE TABLE publishers_new (
                id TEXT PRIMARY KEY,
                token_hash TEXT NOT NULL UNIQUE,
                created_at INTEGER NOT NULL,
                revoked_at INTEGER,
                note TEXT
             );
             INSERT INTO publishers_new (id, token_hash, created_at, revoked_at, note)
             SELECT id, token_hash, created_at, revoked_at, 'migrated' FROM publishers;
             DROP TABLE publishers;
             ALTER TABLE publishers_new RENAME TO publishers;",
        ),
    });
    run_migrations_with(db.connection(), Some(&db_path), &fk_rebuild_ok).unwrap();
    assert_eq!(db.schema_version().unwrap(), next_ver);
    let fk_enabled_after: i64 = db
        .connection()
        .query_row("PRAGMA foreign_keys", [], |r| r.get(0))
        .unwrap();
    assert_eq!(fk_enabled_after, 1);
    let note: String = db
        .connection()
        .query_row("SELECT note FROM publishers WHERE id = 'pub-1'", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(note, "migrated");
}

#[test]
fn fail_closed_downgrade_protection_for_future_schema_version() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("node.sqlite");

    {
        let db = NodeDb::open(&db_path).unwrap();
        db.connection()
            .execute(
                "INSERT INTO schema_version (version, applied_at) VALUES (999, ?1)",
                params![T0],
            )
            .unwrap();
    }

    let err = match NodeDb::open(&db_path) {
        Ok(_) => panic!("opening a v999 DB must fail closed"),
        Err(e) => e,
    };
    match err {
        StoreError::InvalidState(msg) => {
            assert!(msg.contains("999"), "error must cite DB version 999: {msg}");
            assert!(
                msg.contains(&CURRENT_SCHEMA_VERSION.to_string()),
                "error must cite supported version {CURRENT_SCHEMA_VERSION}: {msg}"
            );
            assert!(
                msg.contains("backups"),
                "error must mention backups directory for file-backed DB: {msg}"
            );
        }
        other => panic!("expected StoreError::InvalidState, got {other:?}"),
    }

    // In-memory future version also fails closed cleanly.
    let mem = NodeDb::open_in_memory().unwrap();
    mem.connection()
        .execute(
            "INSERT INTO schema_version (version, applied_at) VALUES (999, ?1)",
            params![T0],
        )
        .unwrap();
    assert!(matches!(
        run_migrations_with(mem.connection(), None, MIGRATIONS),
        Err(StoreError::InvalidState(_))
    ));
}

#[test]
fn handle_description_sanitization_and_lifecycle() {
    // Pure sanitization edge cases.
    assert_eq!(sanitize_handle_description(None), None);
    assert_eq!(sanitize_handle_description(Some("")), None);
    assert_eq!(
        sanitize_handle_description(Some("   \t\r\n\x00\x1b\x7f\u{0085}  ")),
        None
    );
    assert_eq!(
        sanitize_handle_description(Some("  Code\treview\r\nagent\x00with   spaces \u{00a0} ")),
        Some("Code review agent with spaces".to_string())
    );

    // Boundary lengths (200 chars exact, >200 chars truncated, no dangling trailing space).
    let exact_200 = "a".repeat(MAX_HANDLE_DESCRIPTION_CHARS);
    assert_eq!(
        sanitize_handle_description(Some(&exact_200)),
        Some(exact_200.clone())
    );
    let over_250 = "b".repeat(250);
    let trunc_200 = sanitize_handle_description(Some(&over_250)).unwrap();
    assert_eq!(trunc_200.chars().count(), MAX_HANDLE_DESCRIPTION_CHARS);

    let boundary_space = format!("{} tail", "c".repeat(MAX_HANDLE_DESCRIPTION_CHARS - 1));
    let sanitized_boundary = sanitize_handle_description(Some(&boundary_space)).unwrap();
    assert_eq!(
        sanitized_boundary,
        "c".repeat(MAX_HANDLE_DESCRIPTION_CHARS - 1),
        "truncation must not leave a dangling trailing space"
    );

    let boundary_fits = format!("{} x", "d".repeat(MAX_HANDLE_DESCRIPTION_CHARS - 2));
    let sanitized_fits = sanitize_handle_description(Some(&boundary_fits)).unwrap();
    assert_eq!(sanitized_fits.chars().count(), MAX_HANDLE_DESCRIPTION_CHARS);
    assert!(sanitized_fits.ends_with(" x"));

    // Multibyte UTF-8: emojis & CJK (must truncate by Unicode chars without panicking).
    let emojis = "🦀".repeat(220);
    let sanitized_emojis = sanitize_handle_description(Some(&emojis)).unwrap();
    assert_eq!(
        sanitized_emojis.chars().count(),
        MAX_HANDLE_DESCRIPTION_CHARS
    );
    assert_eq!(sanitized_emojis.len(), MAX_HANDLE_DESCRIPTION_CHARS * 4);

    let cjk = "日本語テスト".repeat(50);
    let sanitized_cjk = sanitize_handle_description(Some(&cjk)).unwrap();
    assert_eq!(sanitized_cjk.chars().count(), MAX_HANDLE_DESCRIPTION_CHARS);

    // Store persistence, heartbeat preservation, overwrite/clear, set_handles_with_descriptions, and serde compatibility.
    let db = NodeDb::open_in_memory().unwrap();
    let rec = db
        .messages()
        .register_handle_with_description(
            "alice@mac",
            "reviewer",
            Some("sess-r"),
            Some("  Reviews\nRust\tPRs  "),
            T0,
        )
        .unwrap();
    assert_eq!(rec.description.as_deref(), Some("Reviews Rust PRs"));
    let json_with = serde_json::to_string(&rec).unwrap();
    assert!(json_with.contains("\"description\":\"Reviews Rust PRs\""));

    // Heartbeat preserves description.
    assert!(
        db.messages()
            .heartbeat_handle("alice@mac", "reviewer", T0 + 5_000)
            .unwrap()
    );
    let fetched = db
        .messages()
        .get_handle("alice@mac", "reviewer")
        .unwrap()
        .unwrap();
    assert_eq!(fetched.description.as_deref(), Some("Reviews Rust PRs"));
    assert_eq!(fetched.last_heartbeat_at, T0 + 5_000);

    // Explicit `register_handle` (description = None) clears description & omits field in JSON.
    let cleared = db
        .messages()
        .register_handle("alice@mac", "reviewer", None, T0 + 10_000)
        .unwrap();
    assert_eq!(cleared.description, None);
    assert_eq!(cleared.session_id.as_deref(), Some("sess-r"));
    let json_without = serde_json::to_string(&cleared).unwrap();
    assert!(!json_without.contains("description"));
    let roundtrip: HandleRecord = serde_json::from_str(&json_without).unwrap();
    assert_eq!(roundtrip, cleared);

    // `set_handles_with_descriptions` replaces set atomically with sanitized descriptions.
    let synced = db
        .messages()
        .set_handles_with_descriptions(
            "alice@mac",
            &[
                ("reviewer", Some("Updated\tdesc")),
                ("builder", Some("  ")),
                ("ops", Some("On-call\r\ntriage")),
            ],
            T0 + 20_000,
        )
        .unwrap();
    assert_eq!(synced.len(), 3);
    assert_eq!(synced[0].handle, "builder");
    assert_eq!(synced[0].description, None);
    assert_eq!(synced[1].handle, "ops");
    assert_eq!(synced[1].description.as_deref(), Some("On-call triage"));
    assert_eq!(synced[2].handle, "reviewer");
    assert_eq!(synced[2].description.as_deref(), Some("Updated desc"));

    // Backward-compatible `set_handles` still works cleanly.
    let legacy = db
        .messages()
        .set_handles("alice@mac", &["ops"], T0 + 30_000)
        .unwrap();
    assert_eq!(legacy.len(), 1);
    assert_eq!(legacy[0].handle, "ops");
    assert_eq!(legacy[0].description, None);
}

#[test]
fn multi_hub_peer_routes_crud_validation_and_revocation_cleanup() {
    let db = NodeDb::open_in_memory().unwrap();

    // Register hubs.
    for hub in ["hub-a", "hub-b", "hub-c"] {
        db.peers()
            .upsert_peer(
                &PeerInput {
                    peer_id: hub.to_string(),
                    endpoint: Some(format!("https://{hub}.example")),
                    profile: PeerProfile::Router,
                    trust_tier: TrustTier::Org,
                    status: PeerStatus::Active,
                    scopes: vec!["dm:send".to_string()],
                    auth_credential_ref: None,
                },
                T0,
            )
            .unwrap();
    }

    // Validation: reject empty, invalid node IDs, and self-loops.
    assert!(matches!(
        db.peers().upsert_peer_route("", "hub-a", T0),
        Err(StoreError::InvalidInput(_))
    ));
    assert!(matches!(
        db.peers().upsert_peer_route("bob@lap", "", T0),
        Err(StoreError::InvalidInput(_))
    ));
    assert!(matches!(
        db.peers().upsert_peer_route("Bad/Node", "hub-a", T0),
        Err(StoreError::InvalidInput(_))
    ));
    assert!(matches!(
        db.peers().upsert_peer_route("bob@lap", "UPPER", T0),
        Err(StoreError::InvalidInput(_))
    ));
    assert!(matches!(
        db.peers().upsert_peer_route("hub-a", "hub-a", T0),
        Err(StoreError::InvalidInput(_))
    ));

    // Upsert & update routes.
    let r1 = db
        .peers()
        .upsert_peer_route("carol@dev", "hub-a", T0)
        .unwrap();
    assert_eq!(
        r1,
        PeerRoute {
            target_node: "carol@dev".to_string(),
            via_peer: "hub-a".to_string(),
            updated_at: T0,
        }
    );
    db.peers()
        .upsert_peer_route("alice@mac", "hub-a", T0 + 1)
        .unwrap();
    db.peers()
        .upsert_peer_route("bob@lap", "hub-b", T0 + 2)
        .unwrap();
    db.peers()
        .upsert_peer_route("dave@box", "hub-c", T0 + 3)
        .unwrap();

    // Update existing target_node to point through a different hub.
    let r1_updated = db
        .peers()
        .upsert_peer_route("carol@dev", "hub-b", T0 + 10)
        .unwrap();
    assert_eq!(r1_updated.via_peer, "hub-b");
    assert_eq!(r1_updated.updated_at, T0 + 10);
    assert_eq!(
        db.peers().get_peer_route("carol@dev").unwrap(),
        Some(r1_updated)
    );

    // Ordered by target_node ASC.
    let ordered: Vec<String> = db
        .peers()
        .list_peer_routes()
        .unwrap()
        .into_iter()
        .map(|r| r.target_node)
        .collect();
    assert_eq!(
        ordered,
        vec!["alice@mac", "bob@lap", "carol@dev", "dave@box"]
    );

    // Explicit delete_peer_route & delete_peer_routes_via.
    assert!(db.peers().delete_peer_route("dave@box").unwrap());
    assert!(!db.peers().delete_peer_route("dave@box").unwrap());

    // Re-add route via hub-c and another via hub-a.
    db.peers()
        .upsert_peer_route("dave@box", "hub-c", T0 + 20)
        .unwrap();
    db.peers()
        .upsert_peer_route("eve@vm", "hub-a", T0 + 21)
        .unwrap();

    // Revoking `hub-a` clears all routes via `hub-a` atomically while preserving others.
    assert!(
        db.peers()
            .set_peer_status("hub-a", PeerStatus::Revoked, T0 + 30)
            .unwrap()
    );
    assert_eq!(db.peers().get_peer_route("alice@mac").unwrap(), None);
    assert_eq!(db.peers().get_peer_route("eve@vm").unwrap(), None);
    assert!(db.peers().get_peer_route("bob@lap").unwrap().is_some());
    assert!(db.peers().get_peer_route("carol@dev").unwrap().is_some());
    assert!(db.peers().get_peer_route("dave@box").unwrap().is_some());

    // Deleting `hub-b` clears all routes via `hub-b` atomically while preserving `hub-c`.
    assert!(db.peers().delete_peer("hub-b").unwrap());
    assert_eq!(db.peers().get_peer_route("bob@lap").unwrap(), None);
    assert_eq!(db.peers().get_peer_route("carol@dev").unwrap(), None);
    assert_eq!(
        db.peers()
            .get_peer_route("dave@box")
            .unwrap()
            .unwrap()
            .via_peer,
        "hub-c"
    );

    // Explicit `delete_peer_routes_via` returns exact deleted count.
    db.peers()
        .upsert_peer_route("frank@vm", "hub-c", T0 + 40)
        .unwrap();
    assert_eq!(db.peers().delete_peer_routes_via("hub-c").unwrap(), 2);
    assert!(db.peers().list_peer_routes().unwrap().is_empty());

    // Upserting a peer with `PeerStatus::Revoked` also clears any routes via it.
    db.peers()
        .upsert_peer_route("grace@vm", "hub-c", T0 + 50)
        .unwrap();
    db.peers()
        .upsert_peer(
            &PeerInput {
                peer_id: "hub-c".to_string(),
                endpoint: Some("https://hub-c.example".to_string()),
                profile: PeerProfile::Router,
                trust_tier: TrustTier::Org,
                status: PeerStatus::Revoked,
                scopes: vec![],
                auth_credential_ref: None,
            },
            T0 + 60,
        )
        .unwrap();
    assert!(db.peers().list_peer_routes().unwrap().is_empty());
}
