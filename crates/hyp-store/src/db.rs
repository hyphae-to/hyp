//! Unified `node.sqlite` WAL connection, Unix permission enforcement, declarative atomic
//! `BEGIN IMMEDIATE` schema migrations with automatic pre-migration `VACUUM INTO` backups,
//! and RAII transaction helper.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::thread;
use std::time::{Duration, Instant, UNIX_EPOCH};

use rusqlite::{Connection, ErrorCode, OpenFlags, OptionalExtension};

use crate::error::{StoreError, StoreResult};
use crate::events::{CompiledSubscription, EventLimits, EventStore};
use crate::human::HumanAuthorityStore;
use crate::kv::KvStore;
use crate::local::LocalStateStore;
use crate::messages::{ChannelStore, MessageLimits, MessageStore};
use crate::peers::PeerStore;
use crate::transfers::{TransferLimits, TransferStore};
use crate::types::now_ms;
use crate::wakeups::{WakeupLimits, WakeupStore};

/// Current unified schema version stored in `schema_version`.
pub const CURRENT_SCHEMA_VERSION: i64 = 8;
/// Maximum number of pre-migration `node.sqlite.v*.bak` backups retained per database directory.
pub const MAX_MIGRATION_BACKUPS: usize = 3;
const BUSY_TIMEOUT_MS: u64 = 5_000;
const BACKUP_FILE_PREFIX: &str = "node.sqlite.v";
const BACKUP_FILE_SUFFIX: &str = ".bak";
const SCHEMA_VERSION_TABLE_SQL: &str = "CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER PRIMARY KEY,
            applied_at INTEGER NOT NULL
        );";

/// Executable body of a schema migration step.
#[derive(Debug, Clone, Copy)]
pub enum MigrationKind {
    Sql(&'static str),
    Fn(fn(&Connection) -> StoreResult<()>),
}

/// Declarative, immutable forward-only schema migration entry.
#[derive(Debug, Clone, Copy)]
pub struct Migration {
    pub version: i64,
    pub name: &'static str,
    pub disable_foreign_keys: bool,
    pub kind: MigrationKind,
}

/// Immutable registry of all Hyphae `node.sqlite` schema migrations.
///
/// Existing entries must never be mutated once shipped; append new migrations with
/// monotonically increasing versions.
pub const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: "0001_initial_v2",
        disable_foreign_keys: false,
        kind: MigrationKind::Sql(include_str!("../migrations/0001_initial_v2.sql")),
    },
    Migration {
        version: 2,
        name: "0002_discovery_and_routes",
        disable_foreign_keys: false,
        kind: MigrationKind::Sql(include_str!("../migrations/0002_discovery_and_routes.sql")),
    },
    Migration {
        version: 3,
        name: "wakeups_and_mailbox_ttl",
        disable_foreign_keys: false,
        kind: MigrationKind::Sql(include_str!("../migrations/0003_wakeups.sql")),
    },
    Migration {
        version: 4,
        name: "human_authority_drops",
        disable_foreign_keys: false,
        kind: MigrationKind::Sql(include_str!("../migrations/0004_human_authority.sql")),
    },
    Migration {
        version: 5,
        name: "0005_human_enc_jwk",
        disable_foreign_keys: false,
        kind: MigrationKind::Sql(include_str!("../migrations/0005_human_enc_jwk.sql")),
    },
    Migration {
        version: 6,
        name: "0006_muted_sources_expires_at",
        disable_foreign_keys: false,
        kind: MigrationKind::Fn(migrate_0006_muted_sources_expires_at),
    },
    Migration {
        version: 7,
        name: "0007_delegated_human_admission",
        disable_foreign_keys: false,
        kind: MigrationKind::Fn(migrate_0007_delegated_human_admission),
    },
    Migration {
        version: 8,
        name: "0008_gate_lock_seal",
        disable_foreign_keys: false,
        kind: MigrationKind::Sql(include_str!("../migrations/0008_gate_lock_seal.sql")),
    },
];

fn migrate_0006_muted_sources_expires_at(conn: &Connection) -> StoreResult<()> {
    let mut stmt = conn.prepare("PRAGMA table_info(muted_sources)")?;
    let has_expires_at = stmt
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<Result<Vec<_>, _>>()?
        .iter()
        .any(|col| col == "expires_at");
    if !has_expires_at {
        conn.execute_batch(include_str!(
            "../migrations/0006_muted_sources_expires_at.sql"
        ))?;
    }
    Ok(())
}

fn migrate_0007_delegated_human_admission(conn: &Connection) -> StoreResult<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS human_delegation_policies (
            human_id TEXT PRIMARY KEY,
            node_prefix TEXT NOT NULL,
            scopes_json TEXT NOT NULL DEFAULT '[]',
            max_devices INTEGER NOT NULL DEFAULT 10,
            delegation_enabled INTEGER NOT NULL DEFAULT 0,
            updated_at INTEGER NOT NULL
        );",
    )?;

    let peer_cols: Vec<String> = {
        let mut stmt = conn.prepare("PRAGMA table_info(peers)")?;
        let mut cols = Vec::new();
        for row in stmt.query_map([], |row| row.get::<_, String>(1))? {
            cols.push(row?);
        }
        cols
    };
    if !peer_cols.iter().any(|c| c == "admitted_by_human_id") {
        conn.execute_batch("ALTER TABLE peers ADD COLUMN admitted_by_human_id TEXT;")?;
    }
    if !peer_cols.iter().any(|c| c == "admitted_auth_epoch") {
        conn.execute_batch("ALTER TABLE peers ADD COLUMN admitted_auth_epoch INTEGER;")?;
    }

    conn.execute_batch(
        "CREATE INDEX IF NOT EXISTS peers_admitted_by_human
            ON peers (admitted_by_human_id, status);

        CREATE TABLE human_claim_nonces_v7 (
            claim_id TEXT PRIMARY KEY,
            human_kid TEXT NOT NULL,
            kind TEXT NOT NULL CHECK (kind IN ('directive', 'secret', 'human_invite')),
            expires_at INTEGER NOT NULL,
            consumed_at INTEGER NOT NULL
        );

        INSERT INTO human_claim_nonces_v7 (claim_id, human_kid, kind, expires_at, consumed_at)
            SELECT claim_id, human_kid, kind, expires_at, consumed_at FROM human_claim_nonces;

        DROP TABLE human_claim_nonces;

        ALTER TABLE human_claim_nonces_v7 RENAME TO human_claim_nonces;

        CREATE INDEX IF NOT EXISTS human_claim_nonces_expires
            ON human_claim_nonces (expires_at);",
    )?;
    Ok(())
}

const _: () = {
    assert!(!MIGRATIONS.is_empty(), "MIGRATIONS must not be empty");
    assert!(
        MIGRATIONS.len() as i64 == CURRENT_SCHEMA_VERSION,
        "CURRENT_SCHEMA_VERSION must match MIGRATIONS.len()"
    );
    let mut i = 0;
    while i < MIGRATIONS.len() {
        let m = &MIGRATIONS[i];
        assert!(
            m.version == (i as i64) + 1,
            "MIGRATIONS versions must be contiguous 1..=CURRENT_SCHEMA_VERSION"
        );
        assert!(!m.name.is_empty(), "migration name must not be empty");
        let a = m.name.as_bytes();
        let mut j = 0;
        while j < i {
            let b = MIGRATIONS[j].name.as_bytes();
            let mut same = a.len() == b.len();
            if same {
                let mut k = 0;
                while k < a.len() {
                    if a[k] != b[k] {
                        same = false;
                        break;
                    }
                    k += 1;
                }
            }
            assert!(!same, "migration names must be unique");
            j += 1;
        }
        i += 1;
    }
};

/// Configuration knobs for all subsystems backed by `NodeDb`.
#[derive(Debug, Clone)]
pub struct StoreConfig {
    pub event_limits: EventLimits,
    pub message_limits: MessageLimits,
    pub transfer_limits: TransferLimits,
    pub wakeup_limits: WakeupLimits,
    pub mailbox_max_pending_per_session: usize,
    /// Optional explicit directory for encrypted transfer blobs.
    /// Defaults to `<db_parent>/transfers` for file-backed DBs and an isolated temporary directory
    /// for in-memory DBs.
    pub transfers_dir: Option<PathBuf>,
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            event_limits: EventLimits::default(),
            message_limits: MessageLimits::default(),
            transfer_limits: TransferLimits::default(),
            wakeup_limits: WakeupLimits::default(),
            mailbox_max_pending_per_session: 100,
            transfers_dir: None,
        }
    }
}

/// Internal compiled subscription cache protected by `PRAGMA data_version`.
#[derive(Debug, Default)]
pub(crate) struct EventCacheState {
    pub data_version: Option<i64>,
    pub by_topic: HashMap<(String, String), Vec<CompiledSubscription>>,
    pub last_prune_ms: Option<i64>,
    pub hits: u64,
    pub misses: u64,
    pub invalidations: u64,
}

/// RAII guard for a SQLite `BEGIN IMMEDIATE` write transaction.
///
/// Automatically rolls back on drop unless [`ImmediateTx::commit`] succeeds.
pub(crate) struct ImmediateTx<'a> {
    conn: &'a Connection,
    committed: bool,
}

impl<'a> ImmediateTx<'a> {
    pub(crate) fn begin(conn: &'a Connection) -> StoreResult<Self> {
        conn.execute_batch("BEGIN IMMEDIATE")?;
        Ok(Self {
            conn,
            committed: false,
        })
    }

    pub(crate) fn conn(&self) -> &'a Connection {
        self.conn
    }

    pub(crate) fn commit(mut self) -> StoreResult<()> {
        self.conn.execute_batch("COMMIT")?;
        self.committed = true;
        Ok(())
    }
}

impl Drop for ImmediateTx<'_> {
    fn drop(&mut self) {
        if !self.committed {
            let _ = self.conn.execute_batch("ROLLBACK");
        }
    }
}

/// RAII guard that temporarily disables `PRAGMA foreign_keys` outside a transaction
/// (as required by SQLite for table rebuilds) and unconditionally restores it to `ON` on drop.
struct ForeignKeysGuard<'a> {
    conn: &'a Connection,
    active: bool,
}

impl<'a> ForeignKeysGuard<'a> {
    fn disable_if(conn: &'a Connection, disable: bool) -> StoreResult<Self> {
        if disable {
            conn.execute_batch("PRAGMA foreign_keys = OFF;")?;
        }
        Ok(Self {
            conn,
            active: disable,
        })
    }

    fn restore(mut self) -> StoreResult<()> {
        if self.active {
            self.active = false;
            self.conn.execute_batch("PRAGMA foreign_keys = ON;")?;
        }
        Ok(())
    }
}

impl Drop for ForeignKeysGuard<'_> {
    fn drop(&mut self) {
        if self.active {
            let _ = self.conn.execute_batch("PRAGMA foreign_keys = ON;");
        }
    }
}

/// Unified Hyphae v2 SQLite WAL database handle (`node.sqlite`).
///
/// Owns one `rusqlite::Connection` configured for WAL concurrency and exposes scoped store views
/// (`events()`, `messages()`, `channels()`, `transfers()`, `kv()`, `local()`, `peers()`) plus
/// the unified exact deadline scheduler (`next_deadline_ms()` / `tick()`).
pub struct NodeDb {
    conn: Connection,
    db_path: Option<PathBuf>,
    transfers_dir: PathBuf,
    /// Temporary directory created automatically for `open_in_memory()` transfer blobs;
    /// removed cleanly on `Drop`.
    ephemeral_transfers_dir: Option<PathBuf>,
    config: StoreConfig,
    pub(crate) event_cache: Mutex<EventCacheState>,
    pub(crate) message_last_prune_ms: Mutex<Option<i64>>,
}

impl Drop for NodeDb {
    fn drop(&mut self) {
        if let Some(dir) = &self.ephemeral_transfers_dir {
            let _ = fs::remove_dir_all(dir);
        }
    }
}

impl NodeDb {
    /// Opens (or creates) a WAL-mode `node.sqlite` at `path` with default limits.
    ///
    /// Enforces `0700` on the parent directory and transfers directory, and `0600` on the
    /// database file (plus `-wal` / `-shm` sidecars if present) on Unix.
    pub fn open(path: impl AsRef<Path>) -> StoreResult<Self> {
        Self::open_with_config(path, StoreConfig::default())
    }

    /// Opens (or creates) a WAL-mode `node.sqlite` at `path` with custom [`StoreConfig`].
    pub fn open_with_config(path: impl AsRef<Path>, config: StoreConfig) -> StoreResult<Self> {
        let path = path.as_ref().to_path_buf();
        let parent = db_parent(&path);
        ensure_dir_0700(parent)?;

        let transfers_dir = config
            .transfers_dir
            .clone()
            .unwrap_or_else(|| parent.join("transfers"));
        ensure_dir_0700(&transfers_dir)?;

        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let conn = Connection::open_with_flags(&path, flags)?;
        configure_connection(&conn, true)?;
        migrate(&conn, Some(&path))?;

        // Enforce user-only 0600 permissions on DB file and WAL sidecars.
        ensure_file_0600(&path)?;
        ensure_sidecar_0600(&path, "-wal")?;
        ensure_sidecar_0600(&path, "-shm")?;

        Ok(Self {
            conn,
            db_path: Some(path),
            transfers_dir,
            ephemeral_transfers_dir: None,
            config,
            event_cache: Mutex::new(EventCacheState::default()),
            message_last_prune_ms: Mutex::new(None),
        })
    }

    /// Opens an isolated in-memory `NodeDb` (with an ephemeral `0700` transfer directory).
    pub fn open_in_memory() -> StoreResult<Self> {
        Self::open_in_memory_with_config(StoreConfig::default())
    }

    /// Opens an isolated in-memory `NodeDb` with custom [`StoreConfig`].
    pub fn open_in_memory_with_config(config: StoreConfig) -> StoreResult<Self> {
        let conn = Connection::open_in_memory()?;
        configure_connection(&conn, false)?;
        migrate(&conn, None)?;

        let (transfers_dir, ephemeral_transfers_dir) = if let Some(dir) = &config.transfers_dir {
            ensure_dir_0700(dir)?;
            (dir.clone(), None)
        } else {
            let dir =
                std::env::temp_dir().join(format!("hyp-store-mem-{}", crate::types::uuid_v4()));
            ensure_dir_0700(&dir)?;
            (dir.clone(), Some(dir))
        };

        Ok(Self {
            conn,
            db_path: None,
            transfers_dir,
            ephemeral_transfers_dir,
            config,
            event_cache: Mutex::new(EventCacheState::default()),
            message_last_prune_ms: Mutex::new(None),
        })
    }

    /// Returns the currently applied schema version.
    pub fn schema_version(&self) -> StoreResult<i64> {
        let version: Option<i64> =
            self.conn
                .query_row("SELECT MAX(version) FROM schema_version", [], |row| {
                    row.get(0)
                })?;
        Ok(version.unwrap_or(0))
    }

    /// Returns all applied migrations as `(version, applied_at)` pairs ordered ascending.
    pub fn applied_migrations(&self) -> StoreResult<Vec<(i64, i64)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT version, applied_at FROM schema_version ORDER BY version ASC")?;
        let rows = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Lists pre-migration backup files (`<db_parent>/backups/node.sqlite.v*.bak`) sorted newest-first.
    ///
    /// Returns an empty vector for in-memory databases or when no backups exist.
    pub fn list_migration_backups(&self) -> StoreResult<Vec<PathBuf>> {
        let Some(db_path) = &self.db_path else {
            return Ok(Vec::new());
        };
        list_migration_backups_for_db(db_path)
    }

    /// Returns SQLite's `PRAGMA data_version` for this connection.
    pub fn data_version(&self) -> StoreResult<i64> {
        let v: i64 = self
            .conn
            .query_row("PRAGMA data_version", [], |row| row.get(0))?;
        Ok(v)
    }

    /// Returns SQLite's active `PRAGMA journal_mode`.
    pub fn journal_mode(&self) -> StoreResult<String> {
        let mode: String = self
            .conn
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
        Ok(mode)
    }

    /// Returns the store configuration.
    pub fn config(&self) -> &StoreConfig {
        &self.config
    }

    /// Returns the database path, or `None` for in-memory instances.
    pub fn db_path(&self) -> Option<&Path> {
        self.db_path.as_deref()
    }

    /// Returns the directory where transfer blobs are stored.
    pub fn transfers_dir(&self) -> &Path {
        &self.transfers_dir
    }

    /// Direct read-only access to the underlying `rusqlite::Connection` for diagnostics/tests.
    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    pub(crate) fn conn(&self) -> &Connection {
        &self.conn
    }

    pub(crate) fn immediate_tx(&self) -> StoreResult<ImmediateTx<'_>> {
        ImmediateTx::begin(&self.conn)
    }

    // ---- Scoped subsystem store accessors ----

    pub fn events(&self) -> EventStore<'_> {
        EventStore::new(self)
    }

    pub fn messages(&self) -> MessageStore<'_> {
        MessageStore::new(self)
    }

    pub fn channels(&self) -> ChannelStore<'_> {
        ChannelStore::new(self)
    }

    pub fn transfers(&self) -> TransferStore<'_> {
        TransferStore::new(self)
    }

    pub fn kv(&self) -> KvStore<'_> {
        KvStore::new(self)
    }

    pub fn local(&self) -> LocalStateStore<'_> {
        LocalStateStore::new(self)
    }

    pub fn peers(&self) -> PeerStore<'_> {
        PeerStore::new(self)
    }

    pub fn wakeups(&self) -> WakeupStore<'_> {
        WakeupStore::new(self)
    }

    pub fn human(&self) -> HumanAuthorityStore<'_> {
        HumanAuthorityStore::new(self)
    }
}

/// Applies required SQLite PRAGMAs (WAL with busy-retry on file DBs, synchronous=NORMAL,
/// busy_timeout=5000, foreign_keys=ON).
fn configure_connection(conn: &Connection, file_backed: bool) -> StoreResult<()> {
    conn.busy_timeout(Duration::from_millis(BUSY_TIMEOUT_MS))?;
    conn.execute_batch("PRAGMA foreign_keys = ON;")?;
    if file_backed {
        enable_wal_with_retry(conn)?;
    }
    conn.execute_batch("PRAGMA synchronous = NORMAL;")?;
    Ok(())
}

/// Switching a freshly created SQLite file to WAL takes an exclusive lock and SQLite does not
/// always apply `busy_timeout` during the mode transition. Retry cleanly until `BUSY_TIMEOUT_MS`.
fn enable_wal_with_retry(conn: &Connection) -> StoreResult<()> {
    let deadline = Instant::now() + Duration::from_millis(BUSY_TIMEOUT_MS);
    loop {
        match conn.query_row("PRAGMA journal_mode", [], |row| row.get::<_, String>(0)) {
            Ok(mode) if mode.eq_ignore_ascii_case("wal") => return Ok(()),
            Ok(_) => {}
            Err(err) if is_locked_error(&err) && Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(20));
                continue;
            }
            Err(err) => return Err(err.into()),
        }
        match conn.query_row("PRAGMA journal_mode = WAL", [], |row| {
            row.get::<_, String>(0)
        }) {
            Ok(_) => return Ok(()),
            Err(err) if is_locked_error(&err) && Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(err) => return Err(err.into()),
        }
    }
}

fn is_locked_error(err: &rusqlite::Error) -> bool {
    matches!(
        err,
        rusqlite::Error::SqliteFailure(e, _)
            if matches!(e.code, ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked)
    )
}

fn retry_on_locked<T, F>(mut op: F) -> StoreResult<T>
where
    F: FnMut() -> StoreResult<T>,
{
    let deadline = Instant::now() + Duration::from_millis(BUSY_TIMEOUT_MS);
    loop {
        match op() {
            Ok(val) => return Ok(val),
            Err(StoreError::Sqlite(ref err))
                if is_locked_error(err) && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(20));
            }
            Err(err) => return Err(err),
        }
    }
}

fn db_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn backup_dir_for_db(db_path: &Path) -> PathBuf {
    db_parent(db_path).join("backups")
}

/// Runs the production [`MIGRATIONS`] registry against `conn`.
fn migrate(conn: &Connection, db_path: Option<&Path>) -> StoreResult<()> {
    run_migrations_with(conn, db_path, MIGRATIONS)
}

/// Runs an explicit slice of declarative [`Migration`] steps against `conn`.
///
/// Guarantees:
/// - **Zero write lock fast-path** when `schema_version` already equals the target version.
/// - **Fail-closed downgrade protection** when the database schema version is newer than supported.
/// - **Automatic atomic pre-migration `VACUUM INTO` backup** (`0600` perms, retaining newest
///   [`MAX_MIGRATION_BACKUPS`]) whenever upgrading an existing file-backed database.
/// - **Per-step atomic `BEGIN IMMEDIATE` execution** with double-checked version guards,
///   safe `PRAGMA foreign_keys = OFF` table-rebuild restoration, and `PRAGMA foreign_key_check`
///   verification before commit.
pub fn run_migrations_with(
    conn: &Connection,
    db_path: Option<&Path>,
    migrations: &[Migration],
) -> StoreResult<()> {
    let target_version = validate_migration_registry(migrations)?;

    // 1. Fast-path read-only check (no write lock when already up to date).
    let initial_current = retry_on_locked(|| read_current_schema_version(conn))?;
    if initial_current == target_version {
        return Ok(());
    }
    if initial_current > target_version {
        return Err(newer_schema_error(initial_current, target_version, db_path));
    }

    // Serialize intra-process upgrade storms on the same DB path so concurrent threads do not
    // create duplicate redundant pre-migration backups or contend on `VACUUM INTO`.
    let _process_guard = db_path.map(migration_lock_for);
    let _locked = _process_guard
        .as_ref()
        .map(|m| m.lock().unwrap_or_else(|e| e.into_inner()));

    let mut current = retry_on_locked(|| read_current_schema_version(conn))?;
    if current == target_version {
        return Ok(());
    }
    if current > target_version {
        return Err(newer_schema_error(current, target_version, db_path));
    }

    // 2. Automatic atomic pre-migration backup for existing file-backed databases.
    if let Some(path) = db_path {
        if current > 0 && current < target_version {
            create_pre_migration_backup(conn, path, current, target_version)?;
        }
    }

    // 3. Per-step atomic migration execution.
    for m in migrations {
        if m.version <= current {
            continue;
        }

        // `PRAGMA foreign_keys` changes must happen outside an active transaction in SQLite.
        // Declaring `fk_guard` before the inner `tx` scope guarantees `tx` rolls back or commits
        // BEFORE `fk_guard` restores `PRAGMA foreign_keys = ON`.
        let fk_guard = ForeignKeysGuard::disable_if(conn, m.disable_foreign_keys)?;
        {
            let tx = retry_on_locked(|| ImmediateTx::begin(conn))?;
            tx.conn().execute_batch(SCHEMA_VERSION_TABLE_SQL)?;
            let locked_current: i64 = tx
                .conn()
                .query_row("SELECT MAX(version) FROM schema_version", [], |row| {
                    row.get::<_, Option<i64>>(0)
                })?
                .unwrap_or(0);

            if locked_current > target_version {
                return Err(newer_schema_error(locked_current, target_version, db_path));
            }
            if m.version <= locked_current {
                tx.commit()?;
                current = locked_current;
            } else {
                match m.kind {
                    MigrationKind::Sql(sql) => tx.conn().execute_batch(sql)?,
                    MigrationKind::Fn(func) => func(tx.conn())?,
                }

                if m.disable_foreign_keys {
                    let violations = collect_foreign_key_violations(tx.conn())?;
                    if !violations.is_empty() {
                        return Err(StoreError::InvalidState(format!(
                            "migration {} ('{}') failed foreign_key_check: {}",
                            m.version,
                            m.name,
                            violations.join("; ")
                        )));
                    }
                }

                tx.conn().execute(
                    "INSERT INTO schema_version (version, applied_at) VALUES (?1, ?2)",
                    rusqlite::params![m.version, now_ms()],
                )?;
                tx.commit()?;
                current = m.version;
            }
        }
        fk_guard.restore()?;
    }

    Ok(())
}

fn validate_migration_registry(migrations: &[Migration]) -> StoreResult<i64> {
    let mut prev_version = 0i64;
    let mut seen_names = HashSet::with_capacity(migrations.len());
    for m in migrations {
        if m.version <= prev_version {
            return Err(StoreError::InvalidInput(format!(
                "migration versions must be strictly ascending positive integers (saw {} after {})",
                m.version, prev_version
            )));
        }
        if m.name.is_empty() {
            return Err(StoreError::InvalidInput(format!(
                "migration {} has an empty name",
                m.version
            )));
        }
        if !seen_names.insert(m.name) {
            return Err(StoreError::InvalidInput(format!(
                "duplicate migration name '{}'",
                m.name
            )));
        }
        prev_version = m.version;
    }
    Ok(prev_version)
}

fn read_current_schema_version(conn: &Connection) -> StoreResult<i64> {
    let exists: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_version'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    if exists.is_none() {
        return Ok(0);
    }
    let version: Option<i64> =
        conn.query_row("SELECT MAX(version) FROM schema_version", [], |row| {
            row.get(0)
        })?;
    Ok(version.unwrap_or(0))
}

fn newer_schema_error(current: i64, supported: i64, db_path: Option<&Path>) -> StoreError {
    let hint = db_path
        .map(|p| {
            format!(
                "; upgrade `hyp` or restore a pre-migration backup from '{}'",
                backup_dir_for_db(p).display()
            )
        })
        .unwrap_or_else(|| "; upgrade `hyp` to open this database".to_string());
    StoreError::InvalidState(format!(
        "database schema version {current} is newer than supported version {supported}{hint}"
    ))
}

fn collect_foreign_key_violations(conn: &Connection) -> StoreResult<Vec<String>> {
    let mut stmt = conn.prepare("PRAGMA foreign_key_check;")?;
    let rows = stmt
        .query_map([], |row| {
            let table: String = row.get(0)?;
            let rowid: Option<i64> = row.get(1)?;
            let parent: String = row.get(2)?;
            let fkid: i64 = row.get(3)?;
            Ok(format!(
                "table={table} rowid={rowid:?} parent={parent} fkid={fkid}"
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

fn migration_lock_for(db_path: &Path) -> Arc<Mutex<()>> {
    static LOCKS: OnceLock<Mutex<HashMap<PathBuf, Weak<Mutex<()>>>>> = OnceLock::new();
    let canonical_key = db_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .and_then(|p| fs::canonicalize(p).ok())
        .map(|p| match db_path.file_name() {
            Some(name) => p.join(name),
            None => p,
        })
        .unwrap_or_else(|| db_path.to_path_buf());

    let map_mutex = LOCKS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut map = map_mutex.lock().unwrap_or_else(|e| e.into_inner());
    map.retain(|_, weak| weak.strong_count() > 0);
    if let Some(existing) = map.get(&canonical_key).and_then(Weak::upgrade) {
        return existing;
    }
    let lock = Arc::new(Mutex::new(()));
    map.insert(canonical_key, Arc::downgrade(&lock));
    lock
}

fn create_pre_migration_backup(
    conn: &Connection,
    db_path: &Path,
    from_version: i64,
    target_version: i64,
) -> StoreResult<()> {
    let backups_dir = backup_dir_for_db(db_path);
    ensure_dir_0700(&backups_dir)?;

    let ts = now_ms();
    let pid = std::process::id();
    let mut seq = 0u32;
    let backup_path = loop {
        let name = if seq == 0 {
            format!(
                "{BACKUP_FILE_PREFIX}{from_version}-to-v{target_version}-{ts}-{pid}{BACKUP_FILE_SUFFIX}"
            )
        } else {
            format!(
                "{BACKUP_FILE_PREFIX}{from_version}-to-v{target_version}-{ts}-{pid}-{seq}{BACKUP_FILE_SUFFIX}"
            )
        };
        let candidate = backups_dir.join(name);
        if !candidate.exists() {
            break candidate;
        }
        seq = seq.saturating_add(1);
    };

    let tmp_name = format!(
        ".{}.tmp",
        backup_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("backup")
    );
    let tmp_path = backups_dir.join(tmp_name);
    let tmp_str = tmp_path.to_str().ok_or_else(|| {
        StoreError::InvalidInput("migration backup path is not valid UTF-8".to_string())
    })?;
    let escaped = tmp_str.replace('\'', "''");
    let vacuum_sql = format!("VACUUM INTO '{escaped}';");

    let deadline = Instant::now() + Duration::from_millis(BUSY_TIMEOUT_MS);
    loop {
        let _ = fs::remove_file(&tmp_path);
        match conn.execute_batch(&vacuum_sql) {
            Ok(()) => break,
            Err(err) if is_locked_error(&err) && Instant::now() < deadline => {
                // If another process already finished migrating while we waited, skip backup cleanly.
                if let Ok(latest) = read_current_schema_version(conn) {
                    if latest >= target_version {
                        let _ = fs::remove_file(&tmp_path);
                        return Ok(());
                    }
                }
                thread::sleep(Duration::from_millis(20));
            }
            Err(err) => {
                let _ = fs::remove_file(&tmp_path);
                if is_locked_error(&err) {
                    if let Ok(latest) = read_current_schema_version(conn) {
                        if latest >= target_version {
                            return Ok(());
                        }
                    }
                }
                return Err(err.into());
            }
        }
    }

    ensure_file_0600(&tmp_path)?;
    fs::rename(&tmp_path, &backup_path)?;
    ensure_file_0600(&backup_path)?;
    prune_migration_backups(&backups_dir, MAX_MIGRATION_BACKUPS)?;
    Ok(())
}

fn parse_backup_timestamp_ms(file_name: &str) -> Option<i64> {
    let stem = file_name
        .strip_prefix(BACKUP_FILE_PREFIX)?
        .strip_suffix(BACKUP_FILE_SUFFIX)?;
    let (_, after_to) = stem.split_once("-to-v")?;
    let (_, after_target) = after_to.split_once('-')?;
    let ts_part = after_target.split('-').next()?;
    ts_part.parse::<i64>().ok()
}

fn list_migration_backups_in_dir(backups_dir: &Path) -> StoreResult<Vec<PathBuf>> {
    if !backups_dir.exists() {
        return Ok(Vec::new());
    }
    let mut entries: Vec<(i64, u128, bool, String, PathBuf)> = Vec::new();
    for entry in fs::read_dir(backups_dir)? {
        let entry = match entry {
            Ok(e) => e,
            Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
            Err(err) => return Err(err.into()),
        };
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !name.starts_with(BACKUP_FILE_PREFIX) || !name.ends_with(BACKUP_FILE_SUFFIX) {
            continue;
        }
        let metadata = match entry.metadata() {
            Ok(m) => m,
            Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
            Err(err) => return Err(err.into()),
        };
        if !metadata.is_file() {
            continue;
        }
        let mtime_dur = metadata
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .unwrap_or_default();
        let parsed_ts = parse_backup_timestamp_ms(name);
        let sort_ts =
            parsed_ts.unwrap_or_else(|| i64::try_from(mtime_dur.as_millis()).unwrap_or(i64::MAX));
        entries.push((
            sort_ts,
            mtime_dur.as_nanos(),
            parsed_ts.is_some(),
            name.to_string(),
            path,
        ));
    }
    // Sort newest-first.
    entries.sort_by(|a, b| {
        b.0.cmp(&a.0)
            .then_with(|| b.1.cmp(&a.1))
            .then_with(|| b.2.cmp(&a.2))
            .then_with(|| b.3.cmp(&a.3))
    });
    Ok(entries.into_iter().map(|e| e.4).collect())
}

fn list_migration_backups_for_db(db_path: &Path) -> StoreResult<Vec<PathBuf>> {
    list_migration_backups_in_dir(&backup_dir_for_db(db_path))
}

fn prune_migration_backups(backups_dir: &Path, keep: usize) -> StoreResult<()> {
    let backups = list_migration_backups_in_dir(backups_dir)?;
    for stale in backups.into_iter().skip(keep) {
        if let Err(err) = fs::remove_file(&stale) {
            if err.kind() != io::ErrorKind::NotFound {
                return Err(err.into());
            }
        }
    }
    Ok(())
}

/// Creates directory if needed and enforces `0700` permissions on Unix.
pub(crate) fn ensure_dir_0700(dir: &Path) -> StoreResult<()> {
    fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Enforces `0600` permissions on an existing file on Unix.
pub(crate) fn ensure_file_0600(file: &Path) -> StoreResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if file.exists() {
            if let Err(err) = fs::set_permissions(file, fs::Permissions::from_mode(0o600)) {
                if err.kind() != io::ErrorKind::NotFound {
                    return Err(err.into());
                }
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = file;
    }
    Ok(())
}

fn ensure_sidecar_0600(db_path: &Path, suffix: &str) -> StoreResult<()> {
    let mut os = db_path.as_os_str().to_os_string();
    os.push(suffix);
    let sidecar = PathBuf::from(os);
    if sidecar.exists() {
        ensure_file_0600(&sidecar)?;
    }
    Ok(())
}
