//! Local runtime state (`metadata`, `sessions`, `mailbox` with Security Gate `gate_state`,
//! `deliveries`, `muted_sources`, `plugin_targets`, `bridge_links`, and immutable `gate_audit`
//! append log with human-only quarantine approval & rejection).

use std::collections::HashSet;

use rusqlite::types::Value as SqlValue;
use rusqlite::{OptionalExtension, params, params_from_iter};
use serde::{Deserialize, Serialize};

use crate::db::NodeDb;
use crate::error::{StoreError, StoreResult};
use crate::types::{
    DeliveryMode, GateDecision, GateDirection, GateState, MailboxKind, is_handle, sha256_hex,
    uuid_v4,
};

/// Registered local harness session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub backend_json: String,
    pub handle: Option<String>,
    pub last_seen: i64,
    pub delivery_mode: DeliveryMode,
    pub created_at: i64,
}

/// Source mute rule (`scope = "*"` for global or a specific `session_id`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MuteRule {
    pub scope: String,
    pub pattern: String,
    pub muted_at: i64,
    pub muted_by: String,
}

/// Input for installing a mute rule (e.g. standalone or atomically during quarantine rejection).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MuteRuleInput {
    pub scope: String,
    pub pattern: String,
}

/// Input to insert an item into a local session's mailbox.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MailboxInsert {
    pub session_id: String,
    pub origin_node: String,
    pub item_id: String,
    pub text: String,
    pub kind: MailboxKind,
    pub source: String,
    pub gate_state: GateState,
    pub gate_reason: Option<String>,
    pub traceparent: Option<String>,
}

/// Optional coalescing and TTL controls for [`LocalStateStore::put_in_mailbox_ex`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MailboxPutOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coalesce_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
}

/// Outcome of inserting an item into a local session's mailbox.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MailboxPutResult {
    Stored { receipt: String },
    Duplicate,
    QueueFull,
}

/// Mailbox item record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MailboxEntry {
    pub receipt: String,
    pub session_id: String,
    pub origin_node: String,
    pub item_id: String,
    pub text: String,
    pub received_at: i64,
    pub kind: MailboxKind,
    pub source: String,
    pub notified: bool,
    pub gate_state: GateState,
    pub gate_reason: Option<String>,
    pub traceparent: Option<String>,
    pub payload_sha256: Option<String>,
    pub reviewed_at: Option<i64>,
}

/// Extended mailbox item record including schema v3 coalescing, TTL, and missed-tick metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MailboxEntryEx {
    #[serde(flatten)]
    pub entry: MailboxEntry,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coalesce_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    pub missed_count: u64,
}

/// Metadata-only unread summary for a session (never leaks quarantined payload bodies!).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnreadDigest {
    pub unread: usize,
    pub unnotified: usize,
    pub messages: usize,
    pub events: usize,
    pub plugins: usize,
    pub transfers: usize,
    pub kv: usize,
    pub quarantined: usize,
    pub sources: Vec<String>,
}

/// Metadata-only pending mailbox item projection.
///
/// **Security invariant:** Queries producing this struct NEVER select `mailbox.text`,
/// `gate_reason`, or quarantined rows, ensuring untrusted payload bodies never cross the
/// storage boundary into status bars, summaries, or UI projections.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MailboxItemMeta {
    pub receipt: String,
    pub session_id: String,
    pub origin_node: String,
    pub item_id: String,
    pub received_at: i64,
    pub kind: MailboxKind,
    pub source: String,
    pub notified: bool,
}

/// Active plugin target handoff mapping `(plugin, target) -> session_id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginTargetHandoff {
    pub plugin: String,
    pub target: String,
    pub session_id: String,
    pub set_at: i64,
    pub set_by: String,
}

/// Chat bridge link binding `(plugin, target, session_id)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeLink {
    pub plugin: String,
    pub target: String,
    pub session_id: String,
    pub linked_at: i64,
    pub linked_by: String,
}

/// Input to append an immutable Security Gate audit record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GateAuditInput {
    pub direction: GateDirection,
    pub stage: String,
    pub decision: GateDecision,
    pub origin_node: Option<String>,
    pub source: Option<String>,
    pub session_id: Option<String>,
    pub receipt_id: Option<String>,
    pub event_type: Option<String>,
    pub trust_tier: Option<String>,
    pub confidence: Option<f64>,
    pub categories: Vec<String>,
    pub reason: Option<String>,
    pub traceparent: Option<String>,
    pub payload_sha256: String,
    pub reviewer: Option<String>,
}

/// Persisted immutable Security Gate audit record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GateAuditEntry {
    pub seq: i64,
    pub created_at: i64,
    pub direction: GateDirection,
    pub stage: String,
    pub decision: GateDecision,
    pub origin_node: Option<String>,
    pub source: Option<String>,
    pub session_id: Option<String>,
    pub receipt_id: Option<String>,
    pub event_type: Option<String>,
    pub trust_tier: Option<String>,
    pub confidence: Option<f64>,
    pub categories: Vec<String>,
    pub reason: Option<String>,
    pub traceparent: Option<String>,
    pub payload_sha256: String,
    pub reviewer: Option<String>,
}

/// Filter parameters for querying `gate_audit` (`hyp gate log`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GateAuditQuery {
    pub decision: Option<GateDecision>,
    pub direction: Option<GateDirection>,
    pub session_id: Option<String>,
    pub since_ms: Option<i64>,
    pub until_ms: Option<i64>,
    pub limit: Option<usize>,
}

/// Result of pruning stale sessions.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PruneReport {
    pub pruned_sessions: Vec<String>,
}

/// Local runtime state & Security Gate store view borrowed from [`NodeDb`].
pub struct LocalStateStore<'a> {
    db: &'a NodeDb,
}

impl<'a> LocalStateStore<'a> {
    pub(crate) fn new(db: &'a NodeDb) -> Self {
        Self { db }
    }

    // ---- Metadata ----

    pub fn get_metadata(&self, key: &str) -> StoreResult<Option<String>> {
        let val: Option<String> = self
            .db
            .conn()
            .query_row(
                "SELECT value FROM metadata WHERE key = ?1",
                params![key],
                |row| row.get(0),
            )
            .optional()?;
        Ok(val)
    }

    pub fn set_metadata(&self, key: &str, value: &str) -> StoreResult<()> {
        if key.is_empty() {
            return Err(StoreError::InvalidInput("metadata key must be non-empty".to_string()));
        }
        self.db.conn().execute(
            "INSERT INTO metadata (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    /// Sets `metadata[key] = value` if absent; fails closed with [`StoreError::InvalidState`]
    /// if already bound to a different value (protects identity & origin pinning).
    pub fn ensure_metadata(&self, key: &str, value: &str) -> StoreResult<()> {
        let tx = self.db.immediate_tx()?;
        tx.conn().execute(
            "INSERT OR IGNORE INTO metadata (key, value) VALUES (?1, ?2)",
            params![key, value],
        )?;
        let current: String = tx.conn().query_row(
            "SELECT value FROM metadata WHERE key = ?1",
            params![key],
            |row| row.get(0),
        )?;
        if current != value {
            return Err(StoreError::InvalidState(format!(
                "metadata key '{key}' is bound to '{current}', refusing to rebind to '{value}'"
            )));
        }
        tx.commit()?;
        Ok(())
    }

    // ---- Sessions ----

    /// Registers or updates a harness session.
    ///
    /// When a session already exists and both the existing `backend_json` and the incoming
    /// `backend_json` parse as JSON objects, keys from the incoming object are merged into
    /// the existing object so partial updates like `{"kind":"claude"}` NEVER clobber
    /// previously persisted metadata such as `herdrTerminalId`, `herdrCreatedMs`,
    /// `codexThreadId`, `t3ThreadId`, or `cwd`.
    pub fn register_session(
        &self,
        id: &str,
        backend_json: &str,
        now_ms: i64,
    ) -> StoreResult<Session> {
        if id.is_empty() {
            return Err(StoreError::InvalidInput("session id must be non-empty".to_string()));
        }
        let tx = self.db.immediate_tx()?;
        let existing_backend: Option<String> = tx
            .conn()
            .query_row(
                "SELECT backend_json FROM sessions WHERE id = ?1",
                params![id],
                |row| row.get(0),
            )
            .optional()?;
        let merged_backend = match existing_backend {
            Some(ref prev_raw) => merge_backend_json_strings(prev_raw, backend_json),
            None => backend_json.to_string(),
        };
        tx.conn().execute(
            "INSERT INTO sessions (id, backend_json, last_seen, delivery_mode, created_at)
             VALUES (?1, ?2, ?3, 'full', ?3)
             ON CONFLICT(id) DO UPDATE SET
               backend_json = excluded.backend_json,
               last_seen = excluded.last_seen",
            params![id, &merged_backend, now_ms],
        )?;
        let sess = tx.conn().query_row(
            "SELECT * FROM sessions WHERE id = ?1",
            params![id],
            decode_session_row,
        )??;
        tx.commit()?;
        Ok(sess)
    }

    /// Atomically merges non-null keys from `patch` (must be a JSON object) into
    /// `sessions.backend_json` for `session_id` inside a `BEGIN IMMEDIATE` transaction,
    /// creating the session row if it does not yet exist.
    ///
    /// Monotonically preserves existing metadata keys (`herdrTerminalId`, `herdrCreatedMs`,
    /// `herdrPid`, `codexThreadId`, `t3ThreadId`, `cwd`, etc.) that are absent or `null` in
    /// `patch`.
    pub fn merge_session_backend(
        &self,
        session_id: &str,
        patch: &serde_json::Value,
        now_ms: i64,
    ) -> StoreResult<Session> {
        if session_id.is_empty() {
            return Err(StoreError::InvalidInput(
                "session id must be non-empty".to_string(),
            ));
        }
        let Some(patch_obj) = patch.as_object() else {
            return Err(StoreError::InvalidInput(
                "session backend patch must be a JSON object".to_string(),
            ));
        };
        let tx = self.db.immediate_tx()?;
        let existing_backend: Option<String> = tx
            .conn()
            .query_row(
                "SELECT backend_json FROM sessions WHERE id = ?1",
                params![session_id],
                |row| row.get(0),
            )
            .optional()?;

        let mut merged = existing_backend
            .as_deref()
            .and_then(|raw| serde_json::from_str::<serde_json::Value>(raw).ok())
            .and_then(|v| match v {
                serde_json::Value::Object(map) => Some(map),
                _ => None,
            })
            .unwrap_or_default();

        for (k, v) in patch_obj {
            if !v.is_null() {
                merged.insert(k.clone(), v.clone());
            }
        }
        let serialized = serde_json::to_string(&serde_json::Value::Object(merged))?;

        tx.conn().execute(
            "INSERT INTO sessions (id, backend_json, last_seen, delivery_mode, created_at)
             VALUES (?1, ?2, ?3, 'full', ?3)
             ON CONFLICT(id) DO UPDATE SET
               backend_json = excluded.backend_json,
               last_seen = excluded.last_seen",
            params![session_id, &serialized, now_ms],
        )?;
        let sess = tx.conn().query_row(
            "SELECT * FROM sessions WHERE id = ?1",
            params![session_id],
            decode_session_row,
        )??;
        tx.commit()?;
        Ok(sess)
    }

    /// Touches `last_seen` for an existing session.
    pub fn touch_session(&self, id: &str, now_ms: i64) -> StoreResult<bool> {
        let changed = self.db.conn().execute(
            "UPDATE sessions SET last_seen = ?1 WHERE id = ?2",
            params![now_ms, id],
        )?;
        Ok(changed > 0)
    }

    /// Assigns or clears a session's enrolled handle (enforcing `UNIQUE(handle)`).
    pub fn set_session_handle(
        &self,
        id: &str,
        handle: Option<&str>,
        now_ms: i64,
    ) -> StoreResult<bool> {
        if let Some(h) = handle {
            if !is_handle(h) {
                return Err(StoreError::InvalidInput(format!("invalid handle '{h}'")));
            }
        }
        let res = self.db.conn().execute(
            "UPDATE sessions SET handle = ?1, last_seen = ?2 WHERE id = ?3",
            params![handle, now_ms, id],
        );
        match res {
            Ok(changed) => Ok(changed > 0),
            Err(rusqlite::Error::SqliteFailure(err, _))
                if err.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                Err(StoreError::IdConflict(format!(
                    "handle '{}' is already enrolled by another session",
                    handle.unwrap_or_default()
                )))
            }
            Err(err) => Err(err.into()),
        }
    }

    /// Sets a session's delivery mode (`full` or `notify`).
    pub fn set_delivery_mode(
        &self,
        id: &str,
        mode: DeliveryMode,
        now_ms: i64,
    ) -> StoreResult<bool> {
        let changed = self.db.conn().execute(
            "UPDATE sessions SET delivery_mode = ?1, last_seen = ?2 WHERE id = ?3",
            params![mode.as_str(), now_ms, id],
        )?;
        Ok(changed > 0)
    }

    pub fn get_session(&self, id: &str) -> StoreResult<Option<Session>> {
        self.db
            .conn()
            .query_row("SELECT * FROM sessions WHERE id = ?1", params![id], decode_session_row)
            .optional()?
            .transpose()
    }

    pub fn list_sessions(&self) -> StoreResult<Vec<Session>> {
        let mut stmt = self
            .db
            .conn()
            .prepare("SELECT * FROM sessions ORDER BY last_seen DESC, id ASC")?;
        let rows = stmt
            .query_map([], decode_session_row)?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter().collect()
    }

    pub fn session_by_handle(&self, handle: &str) -> StoreResult<Option<Session>> {
        self.db
            .conn()
            .query_row(
                "SELECT * FROM sessions WHERE handle = ?1",
                params![handle],
                decode_session_row,
            )
            .optional()?
            .transpose()
    }

    /// Matches either exact `session_id` or `<harness>:<thread_id>` suffix.
    pub fn session_by_thread_id(&self, thread_id: &str) -> StoreResult<Option<Session>> {
        if let Some(exact) = self.get_session(thread_id)? {
            return Ok(Some(exact));
        }
        let suffix = format!(":{thread_id}");
        Ok(self
            .list_sessions()?
            .into_iter()
            .find(|s| s.id.ends_with(&suffix)))
    }

    pub fn list_session_handles(&self) -> StoreResult<Vec<String>> {
        let mut stmt = self
            .db
            .conn()
            .prepare("SELECT handle FROM sessions WHERE handle IS NOT NULL ORDER BY handle ASC")?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Lists sessions whose persisted `backend_json` binds `herdrTerminalId == terminal_id`,
    /// ordered deterministically by `(last_seen DESC, id ASC)`.
    pub fn list_sessions_by_herdr_terminal(&self, terminal_id: &str) -> StoreResult<Vec<Session>> {
        if terminal_id.is_empty() {
            return Ok(Vec::new());
        }
        let sessions = self.list_sessions()?;
        Ok(sessions
            .into_iter()
            .filter(|s| {
                serde_json::from_str::<serde_json::Value>(&s.backend_json)
                    .ok()
                    .and_then(|v| {
                        v.get("herdrTerminalId")
                            .and_then(serde_json::Value::as_str)
                            .map(|tid| tid == terminal_id)
                    })
                    .unwrap_or(false)
            })
            .collect())
    }

    /// Removes inactive sessions older than `cutoff_ms` (skipping `active_session_ids`),
    /// cleaning up their mailbox, per-session mutes, bridge links, and plugin targets.
    pub fn prune_sessions(
        &self,
        cutoff_ms: i64,
        active_session_ids: &HashSet<String>,
    ) -> StoreResult<PruneReport> {
        let tx = self.db.immediate_tx()?;
        let mut stmt = tx
            .conn()
            .prepare("SELECT id FROM sessions WHERE last_seen > 0 AND last_seen < ?1")?;
        let candidates: Vec<String> = stmt
            .query_map(params![cutoff_ms], |row| row.get(0))?
            .collect::<Result<Vec<_>, _>>()?;
        drop(stmt);

        let stale: Vec<String> = candidates
            .into_iter()
            .filter(|id| !active_session_ids.contains(id))
            .collect();

        for id in &stale {
            tx.conn()
                .execute("DELETE FROM mailbox WHERE session_id = ?1", params![id])?;
            tx.conn()
                .execute("DELETE FROM muted_sources WHERE scope = ?1", params![id])?;
            tx.conn()
                .execute("DELETE FROM bridge_links WHERE session_id = ?1", params![id])?;
            tx.conn()
                .execute("DELETE FROM plugin_targets WHERE session_id = ?1", params![id])?;
            tx.conn().execute(
                "UPDATE wakeups SET state = 'cancelled', updated_at = ?1
                 WHERE owner_session_id = ?2 AND state IN ('active', 'paused')",
                params![cutoff_ms, id],
            )?;
            tx.conn()
                .execute("DELETE FROM sessions WHERE id = ?1", params![id])?;
        }
        tx.commit()?;
        Ok(PruneReport {
            pruned_sessions: stale,
        })
    }

    // ---- Mailbox & Security Gate Quarantine ----

    /// Inserts an item into a session's mailbox (either `pending` for immediate agent visibility
    /// or `quarantined` awaiting human CLI review).
    ///
    /// Enforces the per-session pending cap (default 100) for `GateState::Pending` items and
    /// atomically records the delivery receipt in `deliveries`.
    pub fn put_in_mailbox(
        &self,
        input: &MailboxInsert,
        now_ms: i64,
    ) -> StoreResult<MailboxPutResult> {
        self.put_in_mailbox_ex(input, &MailboxPutOptions::default(), now_ms)
    }

    /// Inserts an item into a session's mailbox with optional coalescing (`coalesce_key`) and
    /// TTL (`expires_at`).
    ///
    /// When `input.gate_state == GateState::Pending` and `opts.coalesce_key` is `Some(key)`,
    /// if a `pending` row already exists for `(session_id, key)`, it is superseded in place
    /// (updating `origin_node`, `item_id`, `text`, `received_at`, `kind`, `source`, `expires_at`,
    /// resetting `notified = 0`, and incrementing `missed_count = missed_count + 1`) while
    /// reusing the existing receipt.
    pub fn put_in_mailbox_ex(
        &self,
        input: &MailboxInsert,
        opts: &MailboxPutOptions,
        now_ms: i64,
    ) -> StoreResult<MailboxPutResult> {
        if input.session_id.is_empty() || input.origin_node.is_empty() || input.item_id.is_empty() {
            return Err(StoreError::InvalidInput(
                "session_id, origin_node, and item_id must be non-empty".to_string(),
            ));
        }
        if let Some(key) = opts.coalesce_key.as_deref() {
            if key.trim().is_empty() {
                return Err(StoreError::InvalidInput(
                    "coalesce_key must be non-empty when provided".to_string(),
                ));
            }
        }
        let max_pending = self.db.config().mailbox_max_pending_per_session;
        let payload_sha256 = sha256_hex(input.text.as_bytes());

        let tx = self.db.immediate_tx()?;

        // Coalesce in-place into an existing pending row for `(session_id, coalesce_key)` before
        // checking queue capacity, because superseding does not grow the pending queue.
        if input.gate_state == GateState::Pending {
            if let Some(coalesce_key) = opts.coalesce_key.as_deref() {
                let duplicate_exists: bool = tx.conn().query_row(
                    "SELECT EXISTS(
                         SELECT 1 FROM mailbox
                         WHERE origin_node = ?1 AND item_id = ?2 AND session_id = ?3
                     )",
                    params![&input.origin_node, &input.item_id, &input.session_id],
                    |row| row.get(0),
                )?;
                if duplicate_exists {
                    tx.commit()?;
                    return Ok(MailboxPutResult::Duplicate);
                }

                let existing_receipt: Option<String> = tx
                    .conn()
                    .query_row(
                        "SELECT receipt FROM mailbox
                         WHERE session_id = ?1 AND gate_state = 'pending' AND coalesce_key = ?2
                         ORDER BY received_at DESC, receipt ASC
                         LIMIT 1",
                        params![&input.session_id, coalesce_key],
                        |row| row.get(0),
                    )
                    .optional()?;

                if let Some(receipt) = existing_receipt {
                    tx.conn().execute(
                        "UPDATE mailbox
                         SET origin_node = ?1,
                             item_id = ?2,
                             text = ?3,
                             received_at = ?4,
                             kind = ?5,
                             source = ?6,
                             notified = 0,
                             gate_reason = ?7,
                             traceparent = ?8,
                             payload_sha256 = ?9,
                             expires_at = ?10,
                             missed_count = missed_count + 1
                         WHERE receipt = ?11 AND gate_state = 'pending'",
                        params![
                            &input.origin_node,
                            &input.item_id,
                            &input.text,
                            now_ms,
                            input.kind.as_str(),
                            &input.source,
                            input.gate_reason.as_deref(),
                            input.traceparent.as_deref(),
                            &payload_sha256,
                            opts.expires_at,
                            &receipt,
                        ],
                    )?;
                    tx.conn().execute(
                        "INSERT OR REPLACE INTO deliveries (origin_node, item_id, state, created_at)
                         VALUES (?1, ?2, 'submitted', ?3)",
                        params![&input.origin_node, &input.item_id, now_ms],
                    )?;
                    tx.commit()?;
                    return Ok(MailboxPutResult::Stored { receipt });
                }
            }

            let count: i64 = tx.conn().query_row(
                "SELECT COUNT(*) FROM mailbox WHERE session_id = ?1 AND gate_state = 'pending'",
                params![&input.session_id],
                |row| row.get(0),
            )?;
            if count as usize >= max_pending {
                return Ok(MailboxPutResult::QueueFull);
            }
        }

        let receipt = uuid_v4();
        let inserted = tx.conn().execute(
            "INSERT OR IGNORE INTO mailbox
             (receipt, session_id, origin_node, item_id, text, received_at, kind, source,
              notified, gate_state, gate_reason, traceparent, payload_sha256,
              coalesce_key, expires_at, missed_count)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0, ?9, ?10, ?11, ?12, ?13, ?14, 0)",
            params![
                &receipt,
                &input.session_id,
                &input.origin_node,
                &input.item_id,
                &input.text,
                now_ms,
                input.kind.as_str(),
                &input.source,
                input.gate_state.as_str(),
                input.gate_reason.as_deref(),
                input.traceparent.as_deref(),
                &payload_sha256,
                opts.coalesce_key.as_deref(),
                opts.expires_at,
            ],
        )?;

        if inserted == 0 {
            tx.commit()?;
            return Ok(MailboxPutResult::Duplicate);
        }

        let delivery_state = match input.gate_state {
            GateState::Quarantined => "quarantined",
            GateState::Rejected => "rejected",
            _ => "submitted",
        };
        tx.conn().execute(
            "INSERT OR REPLACE INTO deliveries (origin_node, item_id, state, created_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![&input.origin_node, &input.item_id, delivery_state, now_ms],
        )?;
        tx.commit()?;
        Ok(MailboxPutResult::Stored { receipt })
    }

    /// Removes pending mailbox entries whose `expires_at <= now_ms`.
    ///
    /// Takes zero write lock when no pending entries have expired.
    pub fn expire_pending_mailbox(&self, now_ms: i64) -> StoreResult<usize> {
        let has_expired: bool = self.db.conn().query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM mailbox
                 WHERE gate_state = 'pending' AND expires_at IS NOT NULL AND expires_at <= ?1
             )",
            params![now_ms],
            |row| row.get(0),
        )?;
        if !has_expired {
            return Ok(0);
        }

        let tx = self.db.immediate_tx()?;
        let removed = tx.conn().execute(
            "DELETE FROM mailbox
             WHERE gate_state = 'pending' AND expires_at IS NOT NULL AND expires_at <= ?1",
            params![now_ms],
        )?;
        tx.commit()?;
        Ok(removed)
    }

    /// Returns the earliest `expires_at` among pending mailbox entries, or `None` when none have TTLs.
    pub fn next_mailbox_ttl_deadline_ms(&self) -> StoreResult<Option<i64>> {
        let next: Option<i64> = self.db.conn().query_row(
            "SELECT MIN(expires_at) FROM mailbox
             WHERE gate_state = 'pending' AND expires_at IS NOT NULL",
            [],
            |row| row.get(0),
        )?;
        Ok(next)
    }

    /// Peeks up to `limit` **pending** (gate-allowed) mailbox items for `session_id`.
    ///
    /// **Security invariant:** Quarantined and rejected items are NEVER returned.
    pub fn peek_inbox(&self, session_id: &str, limit: usize) -> StoreResult<Vec<MailboxEntry>> {
        let mut stmt = self.db.conn().prepare(
            "SELECT * FROM mailbox
             WHERE session_id = ?1 AND gate_state = 'pending'
             ORDER BY received_at ASC, receipt ASC
             LIMIT ?2",
        )?;
        let rows = stmt
            .query_map(params![session_id, limit as i64], decode_mailbox_row)?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter().collect()
    }

    /// Atomically pops up to `limit` **pending** items for `session_id`, transitioning them to
    /// `gate_state = 'delivered'`. Quarantined items are never touched.
    pub fn drain_inbox(
        &self,
        session_id: &str,
        limit: usize,
        now_ms: i64,
    ) -> StoreResult<Vec<MailboxEntry>> {
        let tx = self.db.immediate_tx()?;
        let mut stmt = tx.conn().prepare(
            "SELECT * FROM mailbox
             WHERE session_id = ?1 AND gate_state = 'pending'
             ORDER BY received_at ASC, receipt ASC
             LIMIT ?2",
        )?;
        let entries = stmt
            .query_map(params![session_id, limit as i64], decode_mailbox_row)?
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .collect::<StoreResult<Vec<_>>>()?;
        drop(stmt);

        for entry in &entries {
            tx.conn().execute(
                "UPDATE mailbox SET gate_state = 'delivered', notified = 1, reviewed_at = COALESCE(reviewed_at, ?1)
                 WHERE session_id = ?2 AND receipt = ?3 AND gate_state = 'pending'",
                params![now_ms, session_id, &entry.receipt],
            )?;
        }
        tx.commit()?;
        Ok(entries)
    }

    /// Acknowledges specific receipts for `session_id`, transitioning `pending -> delivered`.
    pub fn acknowledge_inbox(
        &self,
        session_id: &str,
        receipts: &[&str],
        now_ms: i64,
    ) -> StoreResult<usize> {
        let tx = self.db.immediate_tx()?;
        let mut acked = 0usize;
        for &receipt in receipts {
            acked += tx.conn().execute(
                "UPDATE mailbox SET gate_state = 'delivered', notified = 1, reviewed_at = COALESCE(reviewed_at, ?1)
                 WHERE session_id = ?2 AND receipt = ?3 AND gate_state = 'pending'",
                params![now_ms, session_id, receipt],
            )?;
        }
        tx.commit()?;
        Ok(acked)
    }

    /// Count of `pending` (gate-allowed, undelivered) mailbox entries for `session_id`.
    pub fn pending_count(&self, session_id: &str) -> StoreResult<usize> {
        let n: i64 = self.db.conn().query_row(
            "SELECT COUNT(*) FROM mailbox WHERE session_id = ?1 AND gate_state = 'pending'",
            params![session_id],
            |row| row.get(0),
        )?;
        Ok(n.max(0) as usize)
    }

    /// Count of unnotified `pending` mailbox entries for `session_id`.
    pub fn unnotified_count(&self, session_id: &str) -> StoreResult<usize> {
        let n: i64 = self.db.conn().query_row(
            "SELECT COUNT(*) FROM mailbox
             WHERE session_id = ?1 AND gate_state = 'pending' AND notified = 0",
            params![session_id],
            |row| row.get(0),
        )?;
        Ok(n.max(0) as usize)
    }

    /// Marks all `pending` items for `session_id` as notified.
    pub fn mark_mailbox_notified(&self, session_id: &str) -> StoreResult<usize> {
        let changed = self.db.conn().execute(
            "UPDATE mailbox SET notified = 1
             WHERE session_id = ?1 AND gate_state = 'pending' AND notified = 0",
            params![session_id],
        )?;
        Ok(changed)
    }

    /// Builds a metadata-only unread digest for `session_id`.
    /// Reports quarantined count separately without exposing quarantined body text or sources.
    pub fn unread_digest(&self, session_id: &str) -> StoreResult<UnreadDigest> {
        let mut digest = UnreadDigest::default();
        let mut stmt = self.db.conn().prepare(
            "SELECT kind, source, notified FROM mailbox
             WHERE session_id = ?1 AND gate_state = 'pending'
             ORDER BY received_at DESC",
        )?;
        let rows: Vec<(String, String, i64)> = stmt
            .query_map(params![session_id], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let mut seen_sources = HashSet::new();
        for (kind_str, source, notified) in rows {
            digest.unread += 1;
            if notified == 0 {
                digest.unnotified += 1;
            }
            match MailboxKind::parse(&kind_str).unwrap_or(MailboxKind::Message) {
                MailboxKind::Message => digest.messages += 1,
                MailboxKind::Event => digest.events += 1,
                MailboxKind::Plugin => digest.plugins += 1,
                MailboxKind::Transfer => digest.transfers += 1,
                MailboxKind::Kv => digest.kv += 1,
            }
            let trimmed = source.trim();
            if !trimmed.is_empty() && seen_sources.insert(trimmed.to_string()) {
                digest.sources.push(trimmed.to_string());
            }
        }
        let quarantined: i64 = self.db.conn().query_row(
            "SELECT COUNT(*) FROM mailbox WHERE session_id = ?1 AND gate_state = 'quarantined'",
            params![session_id],
            |row| row.get(0),
        )?;
        digest.quarantined = quarantined.max(0) as usize;
        Ok(digest)
    }

    /// Count of quarantined mailbox entries globally (`session_id == None`) or for a specific
    /// session (`session_id == Some(sid)`). Never reads quarantined body text or sources.
    pub fn quarantined_count(&self, session_id: Option<&str>) -> StoreResult<usize> {
        let n: i64 = if let Some(sid) = session_id {
            self.db.conn().query_row(
                "SELECT COUNT(*) FROM mailbox WHERE session_id = ?1 AND gate_state = 'quarantined'",
                params![sid],
                |row| row.get(0),
            )?
        } else {
            self.db.conn().query_row(
                "SELECT COUNT(*) FROM mailbox WHERE gate_state = 'quarantined'",
                [],
                |row| row.get(0),
            )?
        };
        Ok(n.max(0) as usize)
    }

    /// Lists up to `limit` **pending** (gate-allowed) mailbox item metadata rows for `session_id`,
    /// ordered newest-first (`received_at DESC, receipt ASC`).
    ///
    /// **Security invariant:** Never selects `text`, `gate_reason`, or quarantined rows.
    pub fn list_pending_metadata(
        &self,
        session_id: &str,
        limit: usize,
    ) -> StoreResult<Vec<MailboxItemMeta>> {
        let mut stmt = self.db.conn().prepare(
            "SELECT receipt, session_id, origin_node, item_id, received_at, kind, source, notified
             FROM mailbox
             WHERE session_id = ?1 AND gate_state = 'pending'
             ORDER BY received_at DESC, receipt ASC
             LIMIT ?2",
        )?;
        let rows = stmt
            .query_map(params![session_id, limit as i64], decode_mailbox_meta_row)?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter().collect()
    }

    /// Lists quarantined items awaiting human review (`hyp gate review`).
    pub fn list_quarantined(
        &self,
        session_id: Option<&str>,
        limit: usize,
    ) -> StoreResult<Vec<MailboxEntry>> {
        if let Some(sid) = session_id {
            let mut stmt = self.db.conn().prepare(
                "SELECT * FROM mailbox
                 WHERE gate_state = 'quarantined' AND session_id = ?1
                 ORDER BY received_at ASC, receipt ASC
                 LIMIT ?2",
            )?;
            let rows = stmt
                .query_map(params![sid, limit as i64], decode_mailbox_row)?
                .collect::<Result<Vec<_>, _>>()?;
            rows.into_iter().collect()
        } else {
            let mut stmt = self.db.conn().prepare(
                "SELECT * FROM mailbox
                 WHERE gate_state = 'quarantined'
                 ORDER BY received_at ASC, receipt ASC
                 LIMIT ?1",
            )?;
            let rows = stmt
                .query_map(params![limit as i64], decode_mailbox_row)?
                .collect::<Result<Vec<_>, _>>()?;
            rows.into_iter().collect()
        }
    }

    /// Peeks up to `limit` **pending** (gate-allowed) mailbox items for `session_id`,
    /// including schema v3 coalescing, TTL, and missed-tick metadata.
    pub fn peek_inbox_ex(&self, session_id: &str, limit: usize) -> StoreResult<Vec<MailboxEntryEx>> {
        let mut stmt = self.db.conn().prepare(
            "SELECT * FROM mailbox
             WHERE session_id = ?1 AND gate_state = 'pending'
             ORDER BY received_at ASC, receipt ASC
             LIMIT ?2",
        )?;
        let rows = stmt
            .query_map(params![session_id, limit as i64], decode_mailbox_row_ex)?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter().collect()
    }

    /// Atomically pops up to `limit` **pending** items for `session_id` with extended v3 metadata,
    /// transitioning them to `gate_state = 'delivered'`. Quarantined items are never touched.
    pub fn drain_inbox_ex(
        &self,
        session_id: &str,
        limit: usize,
        now_ms: i64,
    ) -> StoreResult<Vec<MailboxEntryEx>> {
        let tx = self.db.immediate_tx()?;
        let mut stmt = tx.conn().prepare(
            "SELECT * FROM mailbox
             WHERE session_id = ?1 AND gate_state = 'pending'
             ORDER BY received_at ASC, receipt ASC
             LIMIT ?2",
        )?;
        let entries = stmt
            .query_map(params![session_id, limit as i64], decode_mailbox_row_ex)?
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .collect::<StoreResult<Vec<_>>>()?;
        drop(stmt);

        for item in &entries {
            tx.conn().execute(
                "UPDATE mailbox SET gate_state = 'delivered', notified = 1, reviewed_at = COALESCE(reviewed_at, ?1)
                 WHERE session_id = ?2 AND receipt = ?3 AND gate_state = 'pending'",
                params![now_ms, session_id, &item.entry.receipt],
            )?;
        }
        tx.commit()?;
        Ok(entries)
    }

    /// Looks up a single mailbox entry by `receipt_id` with extended v3 metadata.
    pub fn get_mailbox_entry_ex(&self, receipt_id: &str) -> StoreResult<Option<MailboxEntryEx>> {
        self.db
            .conn()
            .query_row(
                "SELECT * FROM mailbox WHERE receipt = ?1",
                params![receipt_id],
                decode_mailbox_row_ex,
            )
            .optional()?
            .transpose()
    }

    /// Looks up a single mailbox entry by `receipt_id`.
    pub fn get_mailbox_entry(&self, receipt_id: &str) -> StoreResult<Option<MailboxEntry>> {
        self.db
            .conn()
            .query_row(
                "SELECT * FROM mailbox WHERE receipt = ?1",
                params![receipt_id],
                decode_mailbox_row,
            )
            .optional()?
            .transpose()
    }

    /// Human-only quarantine approval (`hyp inbox approve <receipt>`).
    ///
    /// Atomically transitions a `quarantined` item to `pending` so it becomes visible to the
    /// target session, and appends an immutable `gate_audit` record. Fails closed if the receipt
    /// does not exist or is not in `quarantined` state.
    pub fn approve_quarantined(
        &self,
        receipt_id: &str,
        reviewer: &str,
        now_ms: i64,
    ) -> StoreResult<MailboxEntry> {
        if reviewer.is_empty() {
            return Err(StoreError::InvalidInput(
                "reviewer must be non-empty".to_string(),
            ));
        }
        let tx = self.db.immediate_tx()?;
        let entry: MailboxEntry = tx
            .conn()
            .query_row(
                "SELECT * FROM mailbox WHERE receipt = ?1",
                params![receipt_id],
                decode_mailbox_row,
            )
            .optional()?
            .transpose()?
            .ok_or_else(|| StoreError::NotFound(format!("receipt '{receipt_id}' not found")))?;

        if entry.gate_state != GateState::Quarantined {
            return Err(StoreError::InvalidState(format!(
                "receipt '{receipt_id}' is in state '{}', expected 'quarantined'",
                entry.gate_state.as_str()
            )));
        }

        tx.conn().execute(
            "UPDATE mailbox SET gate_state = 'pending', notified = 0, reviewed_at = ?1
             WHERE receipt = ?2 AND gate_state = 'quarantined'",
            params![now_ms, receipt_id],
        )?;
        tx.conn().execute(
            "INSERT OR REPLACE INTO deliveries (origin_node, item_id, state, created_at)
             VALUES (?1, ?2, 'approved', ?3)",
            params![&entry.origin_node, &entry.item_id, now_ms],
        )?;

        let payload_sha = entry
            .payload_sha256
            .clone()
            .unwrap_or_else(|| sha256_hex(entry.text.as_bytes()));
        insert_gate_audit_in_tx(
            tx.conn(),
            &GateAuditInput {
                direction: GateDirection::Review,
                stage: "human_review".to_string(),
                decision: GateDecision::Allow,
                origin_node: Some(entry.origin_node.clone()),
                source: Some(entry.source.clone()),
                session_id: Some(entry.session_id.clone()),
                receipt_id: Some(entry.receipt.clone()),
                event_type: Some(entry.kind.as_str().to_string()),
                trust_tier: None,
                confidence: Some(1.0),
                categories: vec!["human_approved".to_string()],
                reason: Some("approved by human reviewer".to_string()),
                traceparent: entry.traceparent.clone(),
                payload_sha256: payload_sha,
                reviewer: Some(reviewer.to_string()),
            },
            now_ms,
        )?;

        let updated = tx.conn().query_row(
            "SELECT * FROM mailbox WHERE receipt = ?1",
            params![receipt_id],
            decode_mailbox_row,
        )??;
        tx.commit()?;
        Ok(updated)
    }

    /// Human-only quarantine rejection (`hyp inbox reject <receipt> [--mute]`).
    ///
    /// Atomically transitions a `quarantined` item to `rejected`, optionally installs a mute rule
    /// in `muted_sources`, and appends an immutable `gate_audit` record.
    pub fn reject_quarantined(
        &self,
        receipt_id: &str,
        reviewer: &str,
        reason: &str,
        optional_mute: Option<&MuteRuleInput>,
        now_ms: i64,
    ) -> StoreResult<MailboxEntry> {
        if reviewer.is_empty() {
            return Err(StoreError::InvalidInput(
                "reviewer must be non-empty".to_string(),
            ));
        }
        let tx = self.db.immediate_tx()?;
        let entry: MailboxEntry = tx
            .conn()
            .query_row(
                "SELECT * FROM mailbox WHERE receipt = ?1",
                params![receipt_id],
                decode_mailbox_row,
            )
            .optional()?
            .transpose()?
            .ok_or_else(|| StoreError::NotFound(format!("receipt '{receipt_id}' not found")))?;

        if entry.gate_state != GateState::Quarantined {
            return Err(StoreError::InvalidState(format!(
                "receipt '{receipt_id}' is in state '{}', expected 'quarantined'",
                entry.gate_state.as_str()
            )));
        }

        tx.conn().execute(
            "UPDATE mailbox SET gate_state = 'rejected', gate_reason = ?1, reviewed_at = ?2
             WHERE receipt = ?3 AND gate_state = 'quarantined'",
            params![reason, now_ms, receipt_id],
        )?;
        tx.conn().execute(
            "INSERT OR REPLACE INTO deliveries (origin_node, item_id, state, created_at)
             VALUES (?1, ?2, 'rejected', ?3)",
            params![&entry.origin_node, &entry.item_id, now_ms],
        )?;

        if let Some(mute) = optional_mute {
            let normalized = mute.pattern.trim().to_lowercase();
            if !normalized.is_empty() && !mute.scope.is_empty() {
                tx.conn().execute(
                    "INSERT OR REPLACE INTO muted_sources (scope, pattern, muted_at, muted_by)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![&mute.scope, normalized, now_ms, reviewer],
                )?;
            }
        }

        let payload_sha = entry
            .payload_sha256
            .clone()
            .unwrap_or_else(|| sha256_hex(entry.text.as_bytes()));
        insert_gate_audit_in_tx(
            tx.conn(),
            &GateAuditInput {
                direction: GateDirection::Review,
                stage: "human_review".to_string(),
                decision: GateDecision::Block,
                origin_node: Some(entry.origin_node.clone()),
                source: Some(entry.source.clone()),
                session_id: Some(entry.session_id.clone()),
                receipt_id: Some(entry.receipt.clone()),
                event_type: Some(entry.kind.as_str().to_string()),
                trust_tier: None,
                confidence: Some(1.0),
                categories: vec!["human_rejected".to_string()],
                reason: Some(reason.to_string()),
                traceparent: entry.traceparent.clone(),
                payload_sha256: payload_sha,
                reviewer: Some(reviewer.to_string()),
            },
            now_ms,
        )?;

        let updated = tx.conn().query_row(
            "SELECT * FROM mailbox WHERE receipt = ?1",
            params![receipt_id],
            decode_mailbox_row,
        )??;
        tx.commit()?;
        Ok(updated)
    }

    // ---- Deliveries ----

    pub fn get_delivery(&self, origin_node: &str, item_id: &str) -> StoreResult<Option<String>> {
        let state: Option<String> = self
            .db
            .conn()
            .query_row(
                "SELECT state FROM deliveries WHERE origin_node = ?1 AND item_id = ?2",
                params![origin_node, item_id],
                |row| row.get(0),
            )
            .optional()?;
        Ok(state)
    }

    pub fn record_delivery(
        &self,
        origin_node: &str,
        item_id: &str,
        state: &str,
        now_ms: i64,
    ) -> StoreResult<()> {
        self.db.conn().execute(
            "INSERT OR REPLACE INTO deliveries (origin_node, item_id, state, created_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![origin_node, item_id, state, now_ms],
        )?;
        Ok(())
    }

    pub fn clear_delivery(&self, origin_node: &str, item_id: &str) -> StoreResult<bool> {
        let changed = self.db.conn().execute(
            "DELETE FROM deliveries WHERE origin_node = ?1 AND item_id = ?2",
            params![origin_node, item_id],
        )?;
        Ok(changed > 0)
    }

    pub fn prune_deliveries(&self, cutoff_ms: i64) -> StoreResult<usize> {
        let changed = self.db.conn().execute(
            "DELETE FROM deliveries WHERE created_at < ?1",
            params![cutoff_ms],
        )?;
        Ok(changed)
    }

    // ---- Muted Sources ----

    pub fn add_mute(
        &self,
        scope: &str,
        pattern: &str,
        muted_by: &str,
        now_ms: i64,
    ) -> StoreResult<MuteRule> {
        let normalized = pattern.trim().to_lowercase();
        if scope.is_empty() || normalized.is_empty() {
            return Err(StoreError::InvalidInput(
                "mute scope and pattern must be non-empty".to_string(),
            ));
        }
        self.db.conn().execute(
            "INSERT OR REPLACE INTO muted_sources (scope, pattern, muted_at, muted_by)
             VALUES (?1, ?2, ?3, ?4)",
            params![scope, &normalized, now_ms, muted_by],
        )?;
        Ok(MuteRule {
            scope: scope.to_string(),
            pattern: normalized,
            muted_at: now_ms,
            muted_by: muted_by.to_string(),
        })
    }

    pub fn remove_mute(&self, scope: &str, pattern: &str) -> StoreResult<bool> {
        let normalized = pattern.trim().to_lowercase();
        let changed = self.db.conn().execute(
            "DELETE FROM muted_sources WHERE scope = ?1 AND pattern = ?2",
            params![scope, normalized],
        )?;
        Ok(changed > 0)
    }

    pub fn list_mutes(&self, session_id: Option<&str>) -> StoreResult<Vec<MuteRule>> {
        if let Some(sid) = session_id {
            let mut stmt = self.db.conn().prepare(
                "SELECT scope, pattern, muted_at, muted_by FROM muted_sources
                 WHERE scope = '*' OR scope = ?1
                 ORDER BY scope ASC, pattern ASC",
            )?;
            let rows = stmt
                .query_map(params![sid], decode_mute_row)?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        } else {
            let mut stmt = self.db.conn().prepare(
                "SELECT scope, pattern, muted_at, muted_by FROM muted_sources
                 WHERE scope = '*'
                 ORDER BY pattern ASC",
            )?;
            let rows = stmt
                .query_map([], decode_mute_row)?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        }
    }

    /// Checks whether any candidate source string matches an active global (`*`) or per-session
    /// mute rule (case-insensitive exact match, plus trailing `*` prefix wildcard support).
    /// Returns the first matching mute pattern if muted.
    pub fn is_muted(&self, session_id: &str, candidates: &[&str]) -> StoreResult<Option<String>> {
        if candidates.is_empty() {
            return Ok(None);
        }
        let rules = self.list_mutes(Some(session_id))?;
        if rules.is_empty() {
            return Ok(None);
        }
        for &candidate in candidates {
            let low = candidate.trim().to_lowercase();
            if low.is_empty() {
                continue;
            }
            for rule in &rules {
                if rule.pattern == low {
                    return Ok(Some(rule.pattern.clone()));
                }
                if let Some(prefix) = rule.pattern.strip_suffix('*') {
                    if !prefix.is_empty() && low.starts_with(prefix) {
                        return Ok(Some(rule.pattern.clone()));
                    }
                }
            }
        }
        Ok(None)
    }

    // ---- Plugin Targets & Bridge Links ----

    pub fn get_plugin_target(
        &self,
        plugin: &str,
        target: &str,
    ) -> StoreResult<Option<PluginTargetHandoff>> {
        self.db
            .conn()
            .query_row(
                "SELECT plugin, target, session_id, set_at, set_by
                 FROM plugin_targets WHERE plugin = ?1 AND target = ?2",
                params![plugin, target],
                |row| {
                    Ok(PluginTargetHandoff {
                        plugin: row.get(0)?,
                        target: row.get(1)?,
                        session_id: row.get(2)?,
                        set_at: row.get(3)?,
                        set_by: row.get(4)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn set_plugin_target(&self, handoff: &PluginTargetHandoff) -> StoreResult<()> {
        self.db.conn().execute(
            "INSERT OR REPLACE INTO plugin_targets (plugin, target, session_id, set_at, set_by)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                &handoff.plugin,
                &handoff.target,
                &handoff.session_id,
                handoff.set_at,
                &handoff.set_by
            ],
        )?;
        Ok(())
    }

    pub fn remove_plugin_target(&self, plugin: &str, target: &str) -> StoreResult<bool> {
        let changed = self.db.conn().execute(
            "DELETE FROM plugin_targets WHERE plugin = ?1 AND target = ?2",
            params![plugin, target],
        )?;
        Ok(changed > 0)
    }

    pub fn add_bridge_link(&self, link: &BridgeLink) -> StoreResult<()> {
        self.db.conn().execute(
            "INSERT OR REPLACE INTO bridge_links (plugin, target, session_id, linked_at, linked_by)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                &link.plugin,
                &link.target,
                &link.session_id,
                link.linked_at,
                &link.linked_by
            ],
        )?;
        Ok(())
    }

    pub fn remove_bridge_link(
        &self,
        plugin: &str,
        target: &str,
        session_id: Option<&str>,
    ) -> StoreResult<usize> {
        let changed = if let Some(sid) = session_id {
            self.db.conn().execute(
                "DELETE FROM bridge_links WHERE plugin = ?1 AND target = ?2 AND session_id = ?3",
                params![plugin, target, sid],
            )?
        } else {
            self.db.conn().execute(
                "DELETE FROM bridge_links WHERE plugin = ?1 AND target = ?2",
                params![plugin, target],
            )?
        };
        Ok(changed)
    }

    pub fn bridge_links(&self, plugin: &str, target: &str) -> StoreResult<Vec<BridgeLink>> {
        let mut stmt = self.db.conn().prepare(
            "SELECT plugin, target, session_id, linked_at, linked_by
             FROM bridge_links WHERE plugin = ?1 AND target = ?2
             ORDER BY linked_at ASC, session_id ASC",
        )?;
        let rows = stmt
            .query_map(params![plugin, target], decode_bridge_link_row)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn bridge_links_for_session(&self, session_id: &str) -> StoreResult<Vec<BridgeLink>> {
        let mut stmt = self.db.conn().prepare(
            "SELECT plugin, target, session_id, linked_at, linked_by
             FROM bridge_links WHERE session_id = ?1
             ORDER BY plugin ASC, target ASC",
        )?;
        let rows = stmt
            .query_map(params![session_id], decode_bridge_link_row)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    // ---- Immutable Security Gate Audit Log ----

    /// Appends an immutable entry to `gate_audit` and returns its monotonic `seq`.
    pub fn append_gate_audit(&self, input: &GateAuditInput, now_ms: i64) -> StoreResult<i64> {
        let tx = self.db.immediate_tx()?;
        let seq = insert_gate_audit_in_tx(tx.conn(), input, now_ms)?;
        tx.commit()?;
        Ok(seq)
    }

    /// Queries the immutable `gate_audit` log with optional filters (`decision`, `direction`,
    /// `session_id`, `since_ms`, `until_ms`, `limit`), returned newest-first.
    pub fn query_gate_audit(&self, query: &GateAuditQuery) -> StoreResult<Vec<GateAuditEntry>> {
        let mut sql = String::from("SELECT * FROM gate_audit WHERE 1 = 1");
        let mut bind: Vec<SqlValue> = Vec::new();

        if let Some(decision) = query.decision {
            sql.push_str(" AND decision = ?");
            bind.push(SqlValue::Text(decision.as_str().to_string()));
        }
        if let Some(direction) = query.direction {
            sql.push_str(" AND direction = ?");
            bind.push(SqlValue::Text(direction.as_str().to_string()));
        }
        if let Some(sid) = &query.session_id {
            sql.push_str(" AND session_id = ?");
            bind.push(SqlValue::Text(sid.clone()));
        }
        if let Some(since) = query.since_ms {
            sql.push_str(" AND created_at >= ?");
            bind.push(SqlValue::Integer(since));
        }
        if let Some(until) = query.until_ms {
            sql.push_str(" AND created_at <= ?");
            bind.push(SqlValue::Integer(until));
        }
        sql.push_str(" ORDER BY seq DESC");
        if let Some(limit) = query.limit {
            sql.push_str(" LIMIT ?");
            bind.push(SqlValue::Integer(limit as i64));
        }

        let mut stmt = self.db.conn().prepare(&sql)?;
        let rows = stmt
            .query_map(params_from_iter(bind), decode_gate_audit_row)?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter().collect()
    }
}

fn insert_gate_audit_in_tx(
    conn: &rusqlite::Connection,
    input: &GateAuditInput,
    now_ms: i64,
) -> StoreResult<i64> {
    let categories_json = if input.categories.is_empty() {
        None
    } else {
        Some(serde_json::to_string(&input.categories)?)
    };
    let seq: i64 = conn.query_row(
        "INSERT INTO gate_audit
         (created_at, direction, stage, decision, origin_node, source, session_id, receipt_id,
          event_type, trust_tier, confidence, categories_json, reason, traceparent,
          payload_sha256, reviewer)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)
         RETURNING seq",
        params![
            now_ms,
            input.direction.as_str(),
            &input.stage,
            input.decision.as_str(),
            input.origin_node.as_deref(),
            input.source.as_deref(),
            input.session_id.as_deref(),
            input.receipt_id.as_deref(),
            input.event_type.as_deref(),
            input.trust_tier.as_deref(),
            input.confidence,
            categories_json.as_deref(),
            input.reason.as_deref(),
            input.traceparent.as_deref(),
            &input.payload_sha256,
            input.reviewer.as_deref()
        ],
        |row| row.get(0),
    )?;
    Ok(seq)
}

fn merge_backend_json_strings(existing_raw: &str, incoming_raw: &str) -> String {
    let existing_val = serde_json::from_str::<serde_json::Value>(existing_raw).ok();
    let incoming_val = serde_json::from_str::<serde_json::Value>(incoming_raw).ok();
    if let (Some(serde_json::Value::Object(mut base)), Some(serde_json::Value::Object(patch))) =
        (existing_val, incoming_val)
    {
        for (k, v) in patch {
            if !v.is_null() {
                base.insert(k, v);
            }
        }
        if let Ok(serialized) = serde_json::to_string(&serde_json::Value::Object(base)) {
            return serialized;
        }
    }
    incoming_raw.to_string()
}

fn decode_mailbox_meta_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<StoreResult<MailboxItemMeta>> {
    let receipt: String = row.get(0)?;
    let session_id: String = row.get(1)?;
    let origin_node: String = row.get(2)?;
    let item_id: String = row.get(3)?;
    let received_at: i64 = row.get(4)?;
    let kind_str: String = row.get(5)?;
    let source: String = row.get(6)?;
    let notified: i64 = row.get(7)?;

    Ok(MailboxKind::parse(&kind_str).map(|kind| MailboxItemMeta {
        receipt,
        session_id,
        origin_node,
        item_id,
        received_at,
        kind,
        source,
        notified: notified != 0,
    }))
}

fn decode_session_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoreResult<Session>> {
    let id: String = row.get("id")?;
    let backend_json: String = row.get("backend_json")?;
    let handle: Option<String> = row.get("handle")?;
    let last_seen: i64 = row.get("last_seen")?;
    let mode_str: String = row.get("delivery_mode")?;
    let created_at: i64 = row.get("created_at")?;
    Ok(DeliveryMode::parse(&mode_str).map(|delivery_mode| Session {
        id,
        backend_json,
        handle,
        last_seen,
        delivery_mode,
        created_at,
    }))
}

fn decode_mailbox_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoreResult<MailboxEntry>> {
    let receipt: String = row.get("receipt")?;
    let session_id: String = row.get("session_id")?;
    let origin_node: String = row.get("origin_node")?;
    let item_id: String = row.get("item_id")?;
    let text: String = row.get("text")?;
    let received_at: i64 = row.get("received_at")?;
    let kind_str: String = row.get("kind")?;
    let source: String = row.get("source")?;
    let notified: i64 = row.get("notified")?;
    let gate_state_str: String = row.get("gate_state")?;
    let gate_reason: Option<String> = row.get("gate_reason")?;
    let traceparent: Option<String> = row.get("traceparent")?;
    let payload_sha256: Option<String> = row.get("payload_sha256")?;
    let reviewed_at: Option<i64> = row.get("reviewed_at")?;

    Ok((|| {
        let kind = MailboxKind::parse(&kind_str)?;
        let gate_state = GateState::parse(&gate_state_str)?;
        Ok(MailboxEntry {
            receipt,
            session_id,
            origin_node,
            item_id,
            text,
            received_at,
            kind,
            source,
            notified: notified != 0,
            gate_state,
            gate_reason,
            traceparent,
            payload_sha256,
            reviewed_at,
        })
    })())
}

fn decode_mailbox_row_ex(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoreResult<MailboxEntryEx>> {
    let entry_res = decode_mailbox_row(row)?;
    let coalesce_key: Option<String> = row.get("coalesce_key")?;
    let expires_at: Option<i64> = row.get("expires_at")?;
    let missed_count: i64 = row.get("missed_count")?;
    Ok(entry_res.map(|entry| MailboxEntryEx {
        entry,
        coalesce_key,
        expires_at,
        missed_count: missed_count.max(0) as u64,
    }))
}

fn decode_mute_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<MuteRule> {
    Ok(MuteRule {
        scope: row.get(0)?,
        pattern: row.get(1)?,
        muted_at: row.get(2)?,
        muted_by: row.get(3)?,
    })
}

fn decode_bridge_link_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<BridgeLink> {
    Ok(BridgeLink {
        plugin: row.get(0)?,
        target: row.get(1)?,
        session_id: row.get(2)?,
        linked_at: row.get(3)?,
        linked_by: row.get(4)?,
    })
}

fn decode_gate_audit_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoreResult<GateAuditEntry>> {
    let seq: i64 = row.get("seq")?;
    let created_at: i64 = row.get("created_at")?;
    let direction_str: String = row.get("direction")?;
    let stage: String = row.get("stage")?;
    let decision_str: String = row.get("decision")?;
    let origin_node: Option<String> = row.get("origin_node")?;
    let source: Option<String> = row.get("source")?;
    let session_id: Option<String> = row.get("session_id")?;
    let receipt_id: Option<String> = row.get("receipt_id")?;
    let event_type: Option<String> = row.get("event_type")?;
    let trust_tier: Option<String> = row.get("trust_tier")?;
    let confidence: Option<f64> = row.get("confidence")?;
    let categories_json: Option<String> = row.get("categories_json")?;
    let reason: Option<String> = row.get("reason")?;
    let traceparent: Option<String> = row.get("traceparent")?;
    let payload_sha256: String = row.get("payload_sha256")?;
    let reviewer: Option<String> = row.get("reviewer")?;

    Ok((|| {
        let direction = GateDirection::parse(&direction_str)?;
        let decision = GateDecision::parse(&decision_str)?;
        let categories: Vec<String> = match categories_json {
            Some(j) => serde_json::from_str(&j)?,
            None => Vec::new(),
        };
        Ok(GateAuditEntry {
            seq,
            created_at,
            direction,
            stage,
            decision,
            origin_node,
            source,
            session_id,
            receipt_id,
            event_type,
            trust_tier,
            confidence,
            categories,
            reason,
            traceparent,
            payload_sha256,
            reviewer,
        })
    })())
}
