//! Unified `node.sqlite` WAL connection, Unix permission enforcement, atomic `BEGIN IMMEDIATE`
//! schema migrations, and RAII transaction helper.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use rusqlite::{Connection, ErrorCode, OpenFlags};

use crate::error::{StoreError, StoreResult};
use crate::events::{CompiledSubscription, EventLimits, EventStore};
use crate::kv::KvStore;
use crate::local::LocalStateStore;
use crate::messages::{ChannelStore, MessageLimits, MessageStore};
use crate::peers::PeerStore;
use crate::transfers::{TransferLimits, TransferStore};
use crate::types::now_ms;

/// Current unified v2 schema version stored in `schema_version`.
pub const CURRENT_SCHEMA_VERSION: i64 = 1;
const BUSY_TIMEOUT_MS: u64 = 5_000;

/// Configuration knobs for all subsystems backed by `NodeDb`.
#[derive(Debug, Clone)]
pub struct StoreConfig {
    pub event_limits: EventLimits,
    pub message_limits: MessageLimits,
    pub transfer_limits: TransferLimits,
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
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
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
        migrate(&conn)?;

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
        migrate(&conn)?;

        let (transfers_dir, ephemeral_transfers_dir) = if let Some(dir) = &config.transfers_dir {
            ensure_dir_0700(dir)?;
            (dir.clone(), None)
        } else {
            let dir = std::env::temp_dir().join(format!("hyp-store-mem-{}", crate::types::uuid_v4()));
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
        let version: Option<i64> = self
            .conn
            .query_row("SELECT MAX(version) FROM schema_version", [], |row| {
                row.get(0)
            })?;
        Ok(version.unwrap_or(0))
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

/// Runs atomic `BEGIN IMMEDIATE` schema migrations guarded by `schema_version`.
fn migrate(conn: &Connection) -> StoreResult<()> {
    let tx = ImmediateTx::begin(conn)?;
    tx.conn().execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER PRIMARY KEY,
            applied_at INTEGER NOT NULL
        );",
    )?;
    let current: Option<i64> =
        tx.conn()
            .query_row("SELECT MAX(version) FROM schema_version", [], |row| {
                row.get(0)
            })?;
    let current = current.unwrap_or(0);
    if current > CURRENT_SCHEMA_VERSION {
        return Err(StoreError::InvalidState(format!(
            "database schema version {current} is newer than supported version {CURRENT_SCHEMA_VERSION}"
        )));
    }
    if current < 1 {
        tx.conn().execute_batch(SCHEMA_V1)?;
        tx.conn().execute(
            "INSERT INTO schema_version (version, applied_at) VALUES (?1, ?2)",
            rusqlite::params![1i64, now_ms()],
        )?;
    }
    tx.commit()?;
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
            fs::set_permissions(file, fs::Permissions::from_mode(0o600))?;
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

/// Complete unified v2 `node.sqlite` schema (v1).
const SCHEMA_V1: &str = r#"
-- =========================================================================
-- 1. Messaging & Channels
-- =========================================================================

CREATE TABLE IF NOT EXISTS handles (
    node_id TEXT NOT NULL,
    handle TEXT NOT NULL,
    session_id TEXT,
    registered_at INTEGER NOT NULL,
    last_heartbeat_at INTEGER NOT NULL,
    PRIMARY KEY (node_id, handle)
);
CREATE INDEX IF NOT EXISTS handles_heartbeat ON handles (last_heartbeat_at);

CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,
    from_addr TEXT NOT NULL,
    to_addr TEXT NOT NULL,
    channel TEXT,
    text TEXT NOT NULL,
    digest TEXT NOT NULL,
    sent_at INTEGER NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending', 'delivered', 'rejected', 'expired')),
    reason TEXT,
    hold_until INTEGER NOT NULL DEFAULT 0,
    settled_at INTEGER,
    origin_environment_id TEXT,
    origin_thread_id TEXT,
    e2ee_epoch INTEGER
);
CREATE INDEX IF NOT EXISTS messages_pending ON messages (to_addr, sent_at) WHERE state = 'pending';
CREATE INDEX IF NOT EXISTS messages_recent ON messages (to_addr, sent_at);
CREATE INDEX IF NOT EXISTS messages_settled ON messages (settled_at) WHERE state != 'pending' AND settled_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS messages_hold ON messages (hold_until) WHERE state = 'pending' AND hold_until > 0;

CREATE TABLE IF NOT EXISTS channel_members (
    host_node TEXT NOT NULL DEFAULT 'local',
    channel TEXT NOT NULL,
    address TEXT NOT NULL,
    joined_at INTEGER NOT NULL,
    PRIMARY KEY (host_node, channel, address)
);
CREATE INDEX IF NOT EXISTS channel_members_address ON channel_members (address);

CREATE TABLE IF NOT EXISTS channel_epochs (
    host_node TEXT NOT NULL DEFAULT 'local',
    channel TEXT NOT NULL,
    epoch INTEGER NOT NULL,
    creator_node_id TEXT NOT NULL,
    key_envelope_json TEXT NOT NULL,
    members_json TEXT NOT NULL,
    signature TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (host_node, channel, epoch)
);
CREATE INDEX IF NOT EXISTS channel_epochs_latest ON channel_epochs (host_node, channel, epoch DESC);

-- =========================================================================
-- 2. Universal CloudEvents Bus & Pushdown Subscriptions
-- =========================================================================

CREATE TABLE IF NOT EXISTS publishers (
    id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL,
    revoked_at INTEGER
);

CREATE TABLE IF NOT EXISTS publisher_grants (
    publisher_id TEXT NOT NULL REFERENCES publishers(id) ON DELETE CASCADE,
    topic TEXT NOT NULL,
    PRIMARY KEY (publisher_id, topic)
);

CREATE TABLE IF NOT EXISTS events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    origin_node TEXT NOT NULL DEFAULT 'local',
    topic TEXT NOT NULL,
    publisher TEXT NOT NULL,
    source TEXT NOT NULL,
    event_id TEXT NOT NULL,
    digest TEXT NOT NULL,
    body TEXT,
    bytes INTEGER NOT NULL,
    matched INTEGER NOT NULL DEFAULT 0,
    received_at INTEGER NOT NULL,
    UNIQUE (origin_node, topic, publisher, source, event_id)
);
CREATE INDEX IF NOT EXISTS events_received ON events (received_at);
CREATE INDEX IF NOT EXISTS events_with_body ON events (received_at) WHERE body IS NOT NULL;
CREATE INDEX IF NOT EXISTS events_origin_topic ON events (origin_node, topic, received_at);

CREATE TABLE IF NOT EXISTS subscriptions (
    id TEXT PRIMARY KEY,
    origin_node TEXT NOT NULL DEFAULT 'local',
    topic TEXT NOT NULL,
    subscriber TEXT NOT NULL,
    filters_json TEXT NOT NULL,
    coalesce_seconds INTEGER NOT NULL DEFAULT 0,
    max_batch_age_ms INTEGER,
    max_wakes_per_hour INTEGER,
    mode TEXT NOT NULL DEFAULT 'full' CHECK (mode IN ('full', 'notify')),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS subscriptions_origin_topic ON subscriptions (origin_node, topic);
CREATE INDEX IF NOT EXISTS subscriptions_subscriber ON subscriptions (subscriber);

CREATE TABLE IF NOT EXISTS batches (
    id TEXT PRIMARY KEY,
    subscription_id TEXT NOT NULL,
    origin_node TEXT NOT NULL DEFAULT 'local',
    subscriber TEXT NOT NULL,
    topic TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('open', 'pending', 'delivered', 'rejected', 'dropped')),
    event_count INTEGER NOT NULL DEFAULT 0,
    opened_at INTEGER NOT NULL,
    last_event_at INTEGER NOT NULL,
    flush_at INTEGER NOT NULL,
    closed_at INTEGER,
    hold_until INTEGER NOT NULL DEFAULT 0,
    reason TEXT,
    settled_at INTEGER
);
CREATE INDEX IF NOT EXISTS batches_subscription ON batches (subscription_id, state, closed_at);
CREATE INDEX IF NOT EXISTS batches_state ON batches (state);
CREATE INDEX IF NOT EXISTS batches_open_flush ON batches (flush_at) WHERE state = 'open';
CREATE INDEX IF NOT EXISTS batches_subscriber_pending ON batches (subscriber, state, closed_at);

CREATE TABLE IF NOT EXISTS batch_events (
    batch_id TEXT NOT NULL REFERENCES batches(id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    event_seq INTEGER NOT NULL,
    PRIMARY KEY (batch_id, position)
);
CREATE INDEX IF NOT EXISTS batch_events_event ON batch_events (event_seq);

CREATE TABLE IF NOT EXISTS upstream_pushdowns (
    id TEXT PRIMARY KEY,
    peer_id TEXT NOT NULL,
    topic TEXT NOT NULL,
    shard_index INTEGER NOT NULL DEFAULT 0,
    filters_json TEXT NOT NULL,
    coalesce_seconds INTEGER NOT NULL,
    local_sub_count INTEGER NOT NULL DEFAULT 0,
    digest TEXT NOT NULL,
    synced_at INTEGER,
    last_error TEXT,
    updated_at INTEGER NOT NULL,
    UNIQUE (peer_id, topic, shard_index)
);
CREATE INDEX IF NOT EXISTS upstream_pushdowns_peer ON upstream_pushdowns (peer_id, topic);

-- =========================================================================
-- 3. Encrypted File Transfers
-- =========================================================================

CREATE TABLE IF NOT EXISTS transfers (
    id TEXT PRIMARY KEY,
    from_node TEXT NOT NULL,
    to_node TEXT NOT NULL,
    transfer_type TEXT NOT NULL,
    header_json TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    size INTEGER NOT NULL,
    sent_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending', 'delivered', 'rejected', 'expired')),
    reason TEXT,
    hold_until INTEGER NOT NULL DEFAULT 0,
    settled_at INTEGER
);
CREATE INDEX IF NOT EXISTS transfers_pending ON transfers (to_node, sent_at) WHERE state = 'pending';
CREATE INDEX IF NOT EXISTS transfers_expires ON transfers (expires_at) WHERE state = 'pending';
CREATE INDEX IF NOT EXISTS transfers_hold ON transfers (hold_until) WHERE state = 'pending' AND hold_until > 0;

-- =========================================================================
-- 4. Shared KV / Blackboard
-- =========================================================================

CREATE TABLE IF NOT EXISTS kv_entries (
    host_node TEXT NOT NULL DEFAULT 'local',
    namespace TEXT NOT NULL,
    key TEXT NOT NULL,
    value_json TEXT NOT NULL,
    content_type TEXT NOT NULL DEFAULT 'application/json',
    version INTEGER NOT NULL,
    write_model TEXT NOT NULL DEFAULT 'owner' CHECK (write_model IN ('owner', 'shared', 'allowlist')),
    owner_id TEXT,
    allowlist_json TEXT,
    writer_id TEXT NOT NULL,
    e2ee_epoch INTEGER,
    signature TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    expires_at INTEGER,
    PRIMARY KEY (host_node, namespace, key)
);
CREATE INDEX IF NOT EXISTS kv_entries_expires ON kv_entries (expires_at) WHERE expires_at IS NOT NULL;

CREATE TABLE IF NOT EXISTS kv_epochs (
    host_node TEXT NOT NULL DEFAULT 'local',
    namespace TEXT NOT NULL,
    epoch INTEGER NOT NULL,
    creator_node_id TEXT NOT NULL,
    key_envelope_json TEXT NOT NULL,
    members_json TEXT NOT NULL,
    signature TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (host_node, namespace, epoch)
);
CREATE INDEX IF NOT EXISTS kv_epochs_latest ON kv_epochs (host_node, namespace, epoch DESC);

-- =========================================================================
-- 5. Federation, Pairing, Keys & Directory Trust
-- =========================================================================

CREATE TABLE IF NOT EXISTS peers (
    peer_id TEXT PRIMARY KEY,
    endpoint TEXT,
    profile TEXT NOT NULL DEFAULT 'router' CHECK (profile IN ('local', 'router', 'p2p')),
    trust_tier TEXT NOT NULL DEFAULT 'peer' CHECK (trust_tier IN ('self', 'org', 'peer', 'guest')),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('pending', 'active', 'paused', 'revoked')),
    scopes_json TEXT NOT NULL DEFAULT '[]',
    auth_credential_ref TEXT,
    manifest_json TEXT,
    manifest_version INTEGER NOT NULL DEFAULT 0,
    manifest_etag TEXT,
    manifest_fetched_at INTEGER,
    observed_e2ee_caps_json TEXT NOT NULL DEFAULT '[]',
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS peers_status ON peers (status);

CREATE TABLE IF NOT EXISTS grants (
    id TEXT PRIMARY KEY,
    peer_id TEXT NOT NULL,
    direction TEXT NOT NULL DEFAULT 'inbound' CHECK (direction IN ('inbound', 'outbound')),
    signed_json TEXT NOT NULL,
    scopes_json TEXT NOT NULL DEFAULT '[]',
    trust_tier TEXT NOT NULL DEFAULT 'peer' CHECK (trust_tier IN ('self', 'org', 'peer', 'guest')),
    issued_at INTEGER NOT NULL,
    pair_by INTEGER,
    expires_at INTEGER,
    entry_json TEXT,
    paired_at INTEGER
);
CREATE INDEX IF NOT EXISTS grants_peer ON grants (peer_id, issued_at);

CREATE TABLE IF NOT EXISTS revocations (
    grant_id TEXT PRIMARY KEY,
    peer_id TEXT NOT NULL,
    signed_json TEXT NOT NULL,
    revoked_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS revocations_peer ON revocations (peer_id, revoked_at);

CREATE TABLE IF NOT EXISTS peer_keys (
    peer_id TEXT NOT NULL,
    kid TEXT NOT NULL,
    key_use TEXT NOT NULL CHECK (key_use IN ('signing', 'encryption', 'prekey', 'admin')),
    jwk_json TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'retired', 'revoked')),
    registered_at INTEGER NOT NULL,
    expires_at INTEGER,
    PRIMARY KEY (peer_id, kid)
);
CREATE INDEX IF NOT EXISTS peer_keys_peer_use ON peer_keys (peer_id, key_use, status);

CREATE TABLE IF NOT EXISTS directory_checkpoints (
    authority_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    root_hash TEXT NOT NULL,
    signed_json TEXT NOT NULL,
    issued_at INTEGER NOT NULL,
    recorded_at INTEGER NOT NULL,
    PRIMARY KEY (authority_id, version)
);
CREATE INDEX IF NOT EXISTS directory_checkpoints_latest ON directory_checkpoints (authority_id, version DESC);

-- =========================================================================
-- 6. Local Runtime, Mailbox, Mutes, Bridges & Immutable Security Gate Audit
-- =========================================================================

CREATE TABLE IF NOT EXISTS metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    backend_json TEXT NOT NULL,
    handle TEXT UNIQUE,
    last_seen INTEGER NOT NULL DEFAULT 0,
    delivery_mode TEXT NOT NULL DEFAULT 'full' CHECK (delivery_mode IN ('full', 'notify')),
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_last_seen ON sessions (last_seen);

CREATE TABLE IF NOT EXISTS mailbox (
    receipt TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    origin_node TEXT NOT NULL,
    item_id TEXT NOT NULL,
    text TEXT NOT NULL,
    received_at INTEGER NOT NULL,
    kind TEXT NOT NULL DEFAULT 'message' CHECK (kind IN ('message', 'event', 'plugin', 'transfer', 'kv')),
    source TEXT NOT NULL DEFAULT '',
    notified INTEGER NOT NULL DEFAULT 0,
    gate_state TEXT NOT NULL DEFAULT 'pending' CHECK (gate_state IN ('pending', 'delivered', 'quarantined', 'rejected')),
    gate_reason TEXT,
    traceparent TEXT,
    payload_sha256 TEXT,
    reviewed_at INTEGER,
    UNIQUE (origin_node, item_id, session_id)
);
CREATE INDEX IF NOT EXISTS mailbox_session_state ON mailbox (session_id, gate_state, received_at);
CREATE INDEX IF NOT EXISTS mailbox_quarantined ON mailbox (gate_state, received_at) WHERE gate_state = 'quarantined';

CREATE TABLE IF NOT EXISTS deliveries (
    origin_node TEXT NOT NULL,
    item_id TEXT NOT NULL,
    state TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (origin_node, item_id)
);
CREATE INDEX IF NOT EXISTS deliveries_created ON deliveries (created_at);

CREATE TABLE IF NOT EXISTS muted_sources (
    scope TEXT NOT NULL,
    pattern TEXT NOT NULL,
    muted_at INTEGER NOT NULL,
    muted_by TEXT NOT NULL,
    PRIMARY KEY (scope, pattern)
);

CREATE TABLE IF NOT EXISTS plugin_targets (
    plugin TEXT NOT NULL,
    target TEXT NOT NULL,
    session_id TEXT NOT NULL,
    set_at INTEGER NOT NULL,
    set_by TEXT NOT NULL,
    PRIMARY KEY (plugin, target)
);

CREATE TABLE IF NOT EXISTS bridge_links (
    plugin TEXT NOT NULL,
    target TEXT NOT NULL,
    session_id TEXT NOT NULL,
    linked_at INTEGER NOT NULL,
    linked_by TEXT NOT NULL,
    PRIMARY KEY (plugin, target, session_id)
);
CREATE INDEX IF NOT EXISTS bridge_links_session ON bridge_links (session_id);

CREATE TABLE IF NOT EXISTS gate_audit (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at INTEGER NOT NULL,
    direction TEXT NOT NULL CHECK (direction IN ('inbound', 'outbound', 'review')),
    stage TEXT NOT NULL,
    decision TEXT NOT NULL CHECK (decision IN ('allow', 'quarantine', 'block', 'error')),
    origin_node TEXT,
    source TEXT,
    session_id TEXT,
    receipt_id TEXT,
    event_type TEXT,
    trust_tier TEXT,
    confidence REAL,
    categories_json TEXT,
    reason TEXT,
    traceparent TEXT,
    payload_sha256 TEXT NOT NULL,
    reviewer TEXT
);
CREATE INDEX IF NOT EXISTS gate_audit_created ON gate_audit (created_at);
CREATE INDEX IF NOT EXISTS gate_audit_decision_created ON gate_audit (decision, created_at);

CREATE TRIGGER IF NOT EXISTS gate_audit_no_update
BEFORE UPDATE ON gate_audit
BEGIN
    SELECT RAISE(ABORT, 'gate_audit is immutable');
END;

CREATE TRIGGER IF NOT EXISTS gate_audit_no_delete
BEFORE DELETE ON gate_audit
BEGIN
    SELECT RAISE(ABORT, 'gate_audit is immutable');
END;
"#;
