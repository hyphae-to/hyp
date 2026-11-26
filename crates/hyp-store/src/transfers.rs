//! Encrypted file transfer metadata (`transfers` table) + on-disk blob store
//! (`<state_dir>/transfers/`, `0700` dir, `0600` files) with atomic `.part` write+rename,
//! per-recipient & global quotas, TTL expiration with automatic disk deletion, orphan sweep,
//! and exact `next_deadline_ms()`.

use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};

use crate::db::{NodeDb, ensure_dir_0700, ensure_file_0600};
use crate::error::{StoreError, StoreResult};
use crate::types::string_enum;
use crate::types::{AckOutcome, is_node_id, is_safe_transfer_id, sha256_hex, uuid_v4};

/// Fail-closed size and queue quotas for pending encrypted transfers.
#[derive(Debug, Clone)]
pub struct TransferLimits {
    /// Maximum ciphertext byte size for a single transfer (default: 256 MiB + 4 KiB).
    pub max_bytes: u64,
    /// Maximum total pending transfer bytes queued per recipient node (default: 512 MiB).
    pub max_pending_bytes_per_recipient: u64,
    /// Maximum pending transfer count queued per recipient node (default: 20).
    pub max_pending_per_recipient: usize,
    /// Maximum total pending transfer bytes queued globally across all recipients (default: 2 GiB).
    pub max_pending_bytes_global: u64,
    /// Maximum pending transfer count queued globally across all recipients (default: 200).
    pub max_pending_global: usize,
    /// Default retry delay when a recipient acknowledges with `AckOutcome::Hold` (default: 30s).
    pub hold_retry_ms: i64,
}

impl Default for TransferLimits {
    fn default() -> Self {
        Self {
            max_bytes: 256 * 1024 * 1024 + 4096,
            max_pending_bytes_per_recipient: 512 * 1024 * 1024,
            max_pending_per_recipient: 20,
            max_pending_bytes_global: 2 * 1024 * 1024 * 1024,
            max_pending_global: 200,
            hold_retry_ms: 30_000,
        }
    }
}

string_enum! {
    /// Lifecycle state of a transfer row.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    pub enum TransferState {
        Pending => "pending",
        Delivered => "delivered",
        Rejected => "rejected",
        Expired => "expired",
    }
    InvalidInput: "transfer state";
}

/// Transfer submission metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferSubmit {
    pub id: String,
    pub from_node: String,
    pub to_node: String,
    pub transfer_type: String,
    pub header_json: String,
    /// Optional expected lowercase hex SHA-256 digest of the blob; verified fail-closed if set.
    pub expected_sha256: Option<String>,
    pub expires_at: i64,
}

/// Persisted transfer metadata row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferRecord {
    pub id: String,
    pub from_node: String,
    pub to_node: String,
    pub transfer_type: String,
    pub header_json: String,
    pub sha256: String,
    pub size: u64,
    pub sent_at: i64,
    pub expires_at: i64,
    pub state: TransferState,
    pub reason: Option<String>,
    pub hold_until: i64,
    pub settled_at: Option<i64>,
}

/// Result of submitting a transfer blob.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferSubmitResult {
    pub id: String,
    pub sha256: String,
    pub size: u64,
    pub deduplicated: bool,
}

/// Report of expired transfers cleaned during `TransferStore::tick()`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TransferTickReport {
    pub expired: usize,
    pub blobs_removed: usize,
}

/// Report of orphan `.part-*` and non-pending blob files removed during `sweep_orphans()`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OrphanSweepReport {
    pub part_files_removed: usize,
    pub orphan_blobs_removed: usize,
}

/// Transfer store view borrowed from [`NodeDb`].
pub struct TransferStore<'a> {
    db: &'a NodeDb,
}

impl<'a> TransferStore<'a> {
    pub(crate) fn new(db: &'a NodeDb) -> Self {
        Self { db }
    }

    fn limits(&self) -> &TransferLimits {
        &self.db.config().transfer_limits
    }

    fn blob_file(&self, id: &str) -> PathBuf {
        self.db.transfers_dir().join(id)
    }

    /// Allocates a unique `.part-<uuid>` staging path inside `<state_dir>/transfers/`.
    pub fn staging_path(&self, id: &str) -> StoreResult<PathBuf> {
        if !is_safe_transfer_id(id) {
            return Err(StoreError::InvalidInput(format!(
                "invalid transfer id '{id}' (must match [A-Za-z0-9_-]{{1,128}})"
            )));
        }
        ensure_dir_0700(self.db.transfers_dir())?;
        Ok(self
            .db
            .transfers_dir()
            .join(format!("{id}.part-{}", uuid_v4())))
    }

    /// Writes `blob` atomically via `.part-<uuid>` (`0600`) + rename and records metadata inside
    /// a `BEGIN IMMEDIATE` transaction enforcing per-recipient and global quotas fail-closed.
    pub fn submit(
        &self,
        input: &TransferSubmit,
        blob: &[u8],
        now_ms: i64,
    ) -> StoreResult<TransferSubmitResult> {
        self.validate_submit_metadata(input, now_ms)?;
        let size = blob.len() as u64;
        if size > self.limits().max_bytes {
            return Err(StoreError::TooLarge(format!(
                "transfer size {size} exceeds limit {}",
                self.limits().max_bytes
            )));
        }
        let actual_sha256 = sha256_hex(blob);
        if let Some(expected) = &input.expected_sha256 {
            if expected != &actual_sha256 {
                return Err(StoreError::InvalidInput(
                    "blob sha256 does not match expected_sha256".to_string(),
                ));
            }
        }

        let part_path = self.staging_path(&input.id)?;
        write_atomic_part_0600(&part_path, blob)?;
        self.commit_part_file(input, &part_path, size, &actual_sha256, now_ms)
    }

    /// Commits a transfer whose encrypted body was already streamed to a `.part-*` staging file.
    ///
    /// On any verification, quota, or DB error, the staging file is deleted fail-closed.
    pub fn commit_staged_file(
        &self,
        input: &TransferSubmit,
        part_path: &Path,
        now_ms: i64,
    ) -> StoreResult<TransferSubmitResult> {
        let result = (|| {
            self.validate_submit_metadata(input, now_ms)?;
            let bytes = fs::read(part_path)?;
            let size = bytes.len() as u64;
            if size > self.limits().max_bytes {
                return Err(StoreError::TooLarge(format!(
                    "transfer size {size} exceeds limit {}",
                    self.limits().max_bytes
                )));
            }
            let actual_sha256 = sha256_hex(&bytes);
            if let Some(expected) = &input.expected_sha256 {
                if expected != &actual_sha256 {
                    return Err(StoreError::InvalidInput(
                        "staged blob sha256 does not match expected_sha256".to_string(),
                    ));
                }
            }
            ensure_file_0600(part_path)?;
            self.commit_part_file(input, part_path, size, &actual_sha256, now_ms)
        })();
        if result.is_err() {
            let _ = fs::remove_file(part_path);
        }
        result
    }

    fn validate_submit_metadata(&self, input: &TransferSubmit, now_ms: i64) -> StoreResult<()> {
        if !is_safe_transfer_id(&input.id) {
            return Err(StoreError::InvalidInput(format!(
                "invalid transfer id '{}' (must match [A-Za-z0-9_-]{{1,128}})",
                input.id
            )));
        }
        if !is_node_id(&input.from_node) {
            return Err(StoreError::InvalidInput(format!(
                "invalid from_node '{}'",
                input.from_node
            )));
        }
        if !is_node_id(&input.to_node) {
            return Err(StoreError::InvalidInput(format!(
                "invalid to_node '{}'",
                input.to_node
            )));
        }
        if input.transfer_type.is_empty() {
            return Err(StoreError::InvalidInput(
                "transfer_type must be non-empty".to_string(),
            ));
        }
        if input.expires_at <= now_ms {
            return Err(StoreError::Expired(
                "transfer expires_at is already in the past".to_string(),
            ));
        }
        Ok(())
    }

    fn commit_part_file(
        &self,
        input: &TransferSubmit,
        part_path: &Path,
        size: u64,
        sha256: &str,
        now_ms: i64,
    ) -> StoreResult<TransferSubmitResult> {
        let tx = match self.db.immediate_tx() {
            Ok(tx) => tx,
            Err(err) => {
                let _ = fs::remove_file(part_path);
                return Err(err);
            }
        };

        // 1. Idempotency / conflict check inside BEGIN IMMEDIATE.
        let existing: Option<(String, String, i64)> = tx
            .conn()
            .query_row(
                "SELECT header_json, sha256, size FROM transfers WHERE id = ?1",
                params![&input.id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        if let Some((prev_header, prev_sha, prev_size)) = existing {
            let _ = fs::remove_file(part_path);
            if prev_header == input.header_json && prev_sha == sha256 && prev_size as u64 == size {
                tx.commit()?;
                return Ok(TransferSubmitResult {
                    id: input.id.clone(),
                    sha256: sha256.to_string(),
                    size,
                    deduplicated: true,
                });
            }
            return Err(StoreError::IdConflict(format!(
                "transfer id '{}' already exists with different content",
                input.id
            )));
        }

        // 2. Per-recipient pending count & byte quotas (fail-closed).
        let limits = self.limits();
        let (recip_count, recip_bytes): (i64, i64) = tx.conn().query_row(
            "SELECT COUNT(*), COALESCE(SUM(size), 0) FROM transfers
             WHERE to_node = ?1 AND state = 'pending'",
            params![&input.to_node],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if recip_count as usize >= limits.max_pending_per_recipient
            || (recip_bytes as u64).saturating_add(size) > limits.max_pending_bytes_per_recipient
        {
            let _ = fs::remove_file(part_path);
            return Err(StoreError::QuotaExceeded(format!(
                "recipient '{}' pending transfer quota exceeded ({recip_count} transfers, {recip_bytes} bytes)",
                input.to_node
            )));
        }

        // 3. Global pending count & byte quotas (fail-closed).
        let (global_count, global_bytes): (i64, i64) = tx.conn().query_row(
            "SELECT COUNT(*), COALESCE(SUM(size), 0) FROM transfers WHERE state = 'pending'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if global_count as usize >= limits.max_pending_global
            || (global_bytes as u64).saturating_add(size) > limits.max_pending_bytes_global
        {
            let _ = fs::remove_file(part_path);
            return Err(StoreError::QuotaExceeded(format!(
                "global pending transfer quota exceeded ({global_count} transfers, {global_bytes} bytes)"
            )));
        }

        // 4. Atomic rename into place before inserting row (so no row ever points at missing/partial file).
        let final_path = self.blob_file(&input.id);
        if let Err(err) = fs::rename(part_path, &final_path) {
            let _ = fs::remove_file(part_path);
            return Err(err.into());
        }
        let _ = ensure_file_0600(&final_path);

        if let Err(err) = tx.conn().execute(
            "INSERT INTO transfers
             (id, from_node, to_node, transfer_type, header_json, sha256, size, sent_at, expires_at, state)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'pending')",
            params![
                &input.id,
                &input.from_node,
                &input.to_node,
                &input.transfer_type,
                &input.header_json,
                sha256,
                size as i64,
                now_ms,
                input.expires_at
            ],
        ) {
            let _ = fs::remove_file(&final_path);
            return Err(err.into());
        }

        if let Err(err) = tx.commit() {
            let _ = fs::remove_file(&final_path);
            return Err(err);
        }

        Ok(TransferSubmitResult {
            id: input.id.clone(),
            sha256: sha256.to_string(),
            size,
            deduplicated: false,
        })
    }

    /// Returns the blob path on disk for `id` if pending and addressed to `recipient_node`.
    pub fn blob_path(&self, recipient_node: &str, id: &str) -> StoreResult<Option<PathBuf>> {
        if !is_safe_transfer_id(id) {
            return Ok(None);
        }
        let to_node: Option<String> = self
            .db
            .conn()
            .query_row(
                "SELECT to_node FROM transfers WHERE id = ?1 AND state = 'pending'",
                params![id],
                |row| row.get(0),
            )
            .optional()?;
        if to_node.as_deref() == Some(recipient_node) {
            Ok(Some(self.blob_file(id)))
        } else {
            Ok(None)
        }
    }

    /// Reads the pending transfer blob bytes for `recipient_node`.
    pub fn read_blob(&self, recipient_node: &str, id: &str) -> StoreResult<Option<Vec<u8>>> {
        let Some(path) = self.blob_path(recipient_node, id)? else {
            return Ok(None);
        };
        Ok(Some(fs::read(path)?))
    }

    /// Looks up transfer metadata by ID.
    pub fn get(&self, id: &str) -> StoreResult<Option<TransferRecord>> {
        self.db
            .conn()
            .query_row(
                "SELECT * FROM transfers WHERE id = ?1",
                params![id],
                decode_transfer_row,
            )
            .optional()?
            .transpose()
    }

    /// Returns the oldest due pending transfer for `recipient_node`, unless any pending transfer
    /// for that recipient is currently in flight, or the head transfer is held/expired.
    pub fn due_transfer<F>(
        &self,
        recipient_node: &str,
        in_flight: F,
        now_ms: i64,
    ) -> StoreResult<Option<TransferRecord>>
    where
        F: Fn(&str) -> bool,
    {
        let mut stmt = self.db.conn().prepare(
            "SELECT * FROM transfers
             WHERE to_node = ?1 AND state = 'pending'
             ORDER BY sent_at ASC, id ASC",
        )?;
        let rows = stmt
            .query_map(params![recipient_node], decode_transfer_row)?
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .collect::<StoreResult<Vec<_>>>()?;
        let Some(first) = rows.first() else {
            return Ok(None);
        };
        if rows.iter().any(|r| in_flight(&r.id)) {
            return Ok(None);
        }
        if first.hold_until > now_ms || first.expires_at <= now_ms {
            return Ok(None);
        }
        Ok(Some(first.clone()))
    }

    /// Acknowledges a pending transfer for `recipient_node`.
    /// Deletes the on-disk blob immediately when settled (`delivered` or `rejected`).
    pub fn ack(
        &self,
        recipient_node: &str,
        id: &str,
        outcome: &AckOutcome,
        now_ms: i64,
    ) -> StoreResult<bool> {
        let tx = self.db.immediate_tx()?;
        let rec: Option<TransferRecord> = tx
            .conn()
            .query_row(
                "SELECT * FROM transfers WHERE id = ?1 AND state = 'pending'",
                params![id],
                decode_transfer_row,
            )
            .optional()?
            .transpose()?;
        let Some(rec) = rec else {
            return Ok(false);
        };
        if rec.to_node != recipient_node {
            return Ok(false);
        }
        let delete_blob = match outcome {
            AckOutcome::Delivered => {
                tx.conn().execute(
                    "UPDATE transfers SET state = 'delivered', settled_at = ?1 WHERE id = ?2",
                    params![now_ms, id],
                )?;
                true
            }
            AckOutcome::Rejected { reason } => {
                tx.conn().execute(
                    "UPDATE transfers SET state = 'rejected', reason = ?1, settled_at = ?2 WHERE id = ?3",
                    params![reason, now_ms, id],
                )?;
                true
            }
            AckOutcome::Hold {
                reason,
                retry_after_ms,
            } => {
                let delay = retry_after_ms
                    .filter(|&d| d > 0)
                    .unwrap_or(self.limits().hold_retry_ms);
                tx.conn().execute(
                    "UPDATE transfers SET reason = ?1, hold_until = ?2 WHERE id = ?3",
                    params![reason, now_ms + delay, id],
                )?;
                false
            }
        };
        tx.commit()?;
        if delete_blob {
            let _ = fs::remove_file(self.blob_file(id));
        }
        Ok(true)
    }

    /// Rejects all pending transfers involving `node_id` (as sender or recipient) and deletes
    /// their blobs from disk.
    pub fn remove_node(&self, node_id: &str, now_ms: i64) -> StoreResult<usize> {
        let tx = self.db.immediate_tx()?;
        let mut stmt = tx.conn().prepare(
            "SELECT id FROM transfers
             WHERE state = 'pending' AND (to_node = ?1 OR from_node = ?1)",
        )?;
        let ids: Vec<String> = stmt
            .query_map(params![node_id], |row| row.get(0))?
            .collect::<Result<Vec<_>, _>>()?;
        drop(stmt);

        for id in &ids {
            tx.conn().execute(
                "UPDATE transfers SET state = 'rejected', reason = 'node_revoked', settled_at = ?1 WHERE id = ?2",
                params![now_ms, id],
            )?;
        }
        tx.commit()?;
        for id in &ids {
            let _ = fs::remove_file(self.blob_file(id));
        }
        Ok(ids.len())
    }

    /// Expires pending transfers whose `expires_at <= now_ms` and deletes their blobs from disk.
    pub fn tick(&self, now_ms: i64) -> StoreResult<TransferTickReport> {
        let tx = self.db.immediate_tx()?;
        let mut stmt = tx
            .conn()
            .prepare("SELECT id FROM transfers WHERE state = 'pending' AND expires_at <= ?1")?;
        let expired_ids: Vec<String> = stmt
            .query_map(params![now_ms], |row| row.get(0))?
            .collect::<Result<Vec<_>, _>>()?;
        drop(stmt);

        if expired_ids.is_empty() {
            return Ok(TransferTickReport::default());
        }
        for id in &expired_ids {
            tx.conn().execute(
                "UPDATE transfers SET state = 'expired', settled_at = ?1 WHERE id = ?2",
                params![now_ms, id],
            )?;
        }
        tx.commit()?;

        let mut blobs_removed = 0usize;
        for id in &expired_ids {
            if fs::remove_file(self.blob_file(id)).is_ok() {
                blobs_removed += 1;
            }
        }
        Ok(TransferTickReport {
            expired: expired_ids.len(),
            blobs_removed,
        })
    }

    /// Sweeps stale `.part-*` staging files and orphan on-disk blobs that have no corresponding
    /// `pending` row in `transfers`.
    pub fn sweep_orphans(&self) -> StoreResult<OrphanSweepReport> {
        let dir = self.db.transfers_dir();
        if !dir.exists() {
            return Ok(OrphanSweepReport::default());
        }
        let mut stmt = self
            .db
            .conn()
            .prepare("SELECT id FROM transfers WHERE state = 'pending'")?;
        let pending_ids: HashSet<String> = stmt
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<HashSet<_>, _>>()?;

        let mut report = OrphanSweepReport::default();
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                continue;
            };
            if name.contains(".part-") {
                if fs::remove_file(&path).is_ok() {
                    report.part_files_removed += 1;
                }
            } else if !pending_ids.contains(&name) && fs::remove_file(&path).is_ok() {
                report.orphan_blobs_removed += 1;
            }
        }
        Ok(report)
    }

    /// Computes the exact earliest timestamp (epoch ms) when a pending transfer expires or comes
    /// off hold; returns `None` when no pending transfers exist.
    pub fn next_deadline_ms(&self, now_ms: i64) -> StoreResult<Option<i64>> {
        let conn = self.db.conn();
        let exp: Option<i64> = conn.query_row(
            "SELECT MIN(expires_at) FROM transfers WHERE state = 'pending'",
            [],
            |row| row.get(0),
        )?;
        let hold: Option<i64> = conn.query_row(
            "SELECT MIN(hold_until) FROM transfers WHERE state = 'pending' AND hold_until > ?1",
            params![now_ms],
            |row| row.get(0),
        )?;
        Ok(match (exp, hold) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        })
    }
}

fn write_atomic_part_0600(part_path: &Path, data: &[u8]) -> StoreResult<()> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(part_path)?;
    file.write_all(data)?;
    file.sync_all()?;
    drop(file);
    ensure_file_0600(part_path)?;
    Ok(())
}

fn decode_transfer_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoreResult<TransferRecord>> {
    let id: String = row.get("id")?;
    let from_node: String = row.get("from_node")?;
    let to_node: String = row.get("to_node")?;
    let transfer_type: String = row.get("transfer_type")?;
    let header_json: String = row.get("header_json")?;
    let sha256: String = row.get("sha256")?;
    let size: i64 = row.get("size")?;
    let sent_at: i64 = row.get("sent_at")?;
    let expires_at: i64 = row.get("expires_at")?;
    let state_str: String = row.get("state")?;
    let reason: Option<String> = row.get("reason")?;
    let hold_until: i64 = row.get("hold_until")?;
    let settled_at: Option<i64> = row.get("settled_at")?;

    Ok(
        TransferState::parse(&state_str).map(|state| TransferRecord {
            id,
            from_node,
            to_node,
            transfer_type,
            header_json,
            sha256,
            size: size.max(0) as u64,
            sent_at,
            expires_at,
            state,
            reason,
            hold_until,
            settled_at,
        }),
    )
}
