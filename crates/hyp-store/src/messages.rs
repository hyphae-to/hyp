//! Direct messages (`MessageStore`), handles with liveness heartbeats, E2EE-safe `#channels`
//! (`ChannelStore`, zero `[#channel]` text mutation), `channel_epochs` storage, 7-day settled-row
//! pruning, and exact `next_deadline_ms()` calculation.

use std::collections::{BTreeMap, HashSet};

use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};

use crate::db::NodeDb;
use crate::error::{StoreError, StoreResult};
use crate::types::{
    AckOutcome, format_address, is_channel_name, is_handle, is_node_id, parse_address, sha256_hex,
};

const HOUR_MS: i64 = 60 * 60 * 1000;
const DAY_MS: i64 = 24 * HOUR_MS;

/// Maximum Unicode character length of an optional enrolled handle description.
pub const MAX_HANDLE_DESCRIPTION_CHARS: usize = 200;

/// Sanitizes an optional handle description for safe single-line display and bounded storage.
///
/// - Replaces any ASCII/Unicode control character (including `\r`, `\n`, `\t`) and whitespace run
///   with a single ASCII space.
/// - Trims leading and trailing whitespace.
/// - Truncates cleanly at [`MAX_HANDLE_DESCRIPTION_CHARS`] Unicode scalar values (`char`s) without
///   leaving a trailing space or splitting multibyte UTF-8 sequences.
/// - Returns `None` if `raw` is `None` or the normalized result is empty.
pub fn sanitize_handle_description(raw: Option<&str>) -> Option<String> {
    let raw = raw?;
    let mut out = String::new();
    let mut count = 0usize;
    let mut pending_space = false;

    for ch in raw.chars() {
        if ch.is_control() || ch.is_whitespace() {
            if count > 0 {
                pending_space = true;
            }
            continue;
        }
        if pending_space {
            // Only emit the separator space if there is room for both the space and `ch`.
            if count + 2 > MAX_HANDLE_DESCRIPTION_CHARS {
                break;
            }
            out.push(' ');
            count += 1;
            pending_space = false;
        }
        if count >= MAX_HANDLE_DESCRIPTION_CHARS {
            break;
        }
        out.push(ch);
        count += 1;
    }

    if out.is_empty() { None } else { Some(out) }
}

/// Operational limits for DM and `#channel` messages.
#[derive(Debug, Clone)]
pub struct MessageLimits {
    /// Time before an undelivered pending message expires (default: 24h).
    pub ttl_ms: i64,
    /// Maximum pending undelivered messages per recipient address (default: 100).
    pub max_pending_per_recipient: usize,
    /// Maximum non-rejected messages accepted per recipient per rolling hour (default: 30).
    pub max_per_hour_per_recipient: usize,
    /// Default retry delay when a recipient acknowledges with `AckOutcome::Hold` (default: 30s).
    pub hold_retry_ms: i64,
    /// How long settled (`delivered` / `rejected` / `expired`) rows are kept before pruning (default: 7d).
    pub settled_retention_ms: i64,
    /// Maximum UTF-8 byte length of message payload text (default: 32 KiB for E2EE wire envelope).
    pub max_text_bytes: usize,
    /// Minimum spacing between settled-row pruning sweeps in `tick()` (default: 60s).
    pub prune_interval_ms: i64,
}

impl Default for MessageLimits {
    fn default() -> Self {
        Self {
            ttl_ms: DAY_MS,
            max_pending_per_recipient: 100,
            max_per_hour_per_recipient: 30,
            hold_retry_ms: 30_000,
            settled_retention_ms: 7 * DAY_MS,
            max_text_bytes: 32 * 1024,
            prune_interval_ms: 60_000,
        }
    }
}

/// Enrolled handle record with liveness heartbeat metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandleRecord {
    pub node_id: String,
    pub handle: String,
    pub address: String,
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub registered_at: i64,
    pub last_heartbeat_at: i64,
}

/// Lifecycle state of a message row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MessageState {
    Pending,
    Delivered,
    Rejected,
    Expired,
}

impl MessageState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Delivered => "delivered",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn parse(s: &str) -> StoreResult<Self> {
        match s {
            "pending" => Ok(Self::Pending),
            "delivered" => Ok(Self::Delivered),
            "rejected" => Ok(Self::Rejected),
            "expired" => Ok(Self::Expired),
            other => Err(StoreError::InvalidInput(format!(
                "invalid message state '{other}'"
            ))),
        }
    }
}

/// Input to enqueue a direct or channel-scoped message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnqueueMessage {
    pub id: String,
    pub from_node: String,
    pub from_handle: String,
    pub to_addr: String,
    /// Optional structured channel name (`#incidents`). Preserved separately so `text` is never mutated.
    pub channel: Option<String>,
    pub text: String,
    pub origin_environment_id: Option<String>,
    pub origin_thread_id: Option<String>,
    pub e2ee_epoch: Option<u64>,
}

/// Persisted message record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageRecord {
    pub id: String,
    pub from_addr: String,
    pub to_addr: String,
    pub channel: Option<String>,
    pub text: String,
    pub digest: String,
    pub sent_at: i64,
    pub state: MessageState,
    pub reason: Option<String>,
    pub hold_until: i64,
    pub settled_at: Option<i64>,
    pub origin_environment_id: Option<String>,
    pub origin_thread_id: Option<String>,
    pub e2ee_epoch: Option<u64>,
}

/// Result of enqueueing a message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnqueueResult {
    pub id: String,
    pub deduplicated: bool,
}

/// Summary of a `MessageStore::tick()` run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MessageTickReport {
    pub expired: usize,
    pub settled_pruned: usize,
}

/// Result of joining a `#channel`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelMembership {
    pub host_node: String,
    pub channel: String,
    pub address: String,
    pub members: Vec<String>,
}

/// Channel directory entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelInfo {
    pub host_node: String,
    pub channel: String,
    pub members: Vec<String>,
}

/// Input to post a message to a `#channel`.
///
/// **E2EE invariant:** `text` is fanned out verbatim to each channel member without any
/// `[#channel]` prefix mutation; the channel name travels in the structured `channel` column.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostChannelInput {
    pub id: String,
    pub host_node: String,
    pub channel: String,
    pub from_node: String,
    pub from_handle: String,
    pub text: String,
    pub e2ee_epoch: Option<u64>,
}

/// Per-recipient fan-out delivery error during a `#channel` post.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelDeliveryFailure {
    pub to_addr: String,
    pub error: String,
}

/// Result of posting to a `#channel`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostChannelResult {
    pub host_node: String,
    pub channel: String,
    pub delivered_to: Vec<String>,
    pub failed: Vec<ChannelDeliveryFailure>,
}

/// Input to store a signed E2EE `#channel` epoch key & membership snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelEpochInput {
    pub host_node: String,
    pub channel: String,
    pub epoch: u64,
    pub creator_node_id: String,
    pub key_envelope_json: String,
    pub members: Vec<String>,
    pub signature: String,
}

/// Stored E2EE `#channel` epoch key metadata & membership snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelEpoch {
    pub host_node: String,
    pub channel: String,
    pub epoch: u64,
    pub creator_node_id: String,
    pub key_envelope_json: String,
    pub members: Vec<String>,
    pub signature: String,
    pub created_at: i64,
}

/// Handle and direct-message store view borrowed from [`NodeDb`].
pub struct MessageStore<'a> {
    db: &'a NodeDb,
}

impl<'a> MessageStore<'a> {
    pub(crate) fn new(db: &'a NodeDb) -> Self {
        Self { db }
    }

    fn limits(&self) -> &MessageLimits {
        &self.db.config().message_limits
    }

    // ---- Handles & Liveness ----

    /// Registers (or refreshes) an enrolled handle on `node_id`.
    pub fn register_handle(
        &self,
        node_id: &str,
        handle: &str,
        session_id: Option<&str>,
        now_ms: i64,
    ) -> StoreResult<HandleRecord> {
        self.register_handle_with_description(node_id, handle, session_id, None, now_ms)
    }

    /// Registers (or refreshes) an enrolled handle on `node_id` with an optional sanitized
    /// human-readable description.
    ///
    /// Overwrites `description` on conflict (`Some(...)` sets it after sanitization, `None` clears
    /// it explicitly), while [`Self::heartbeat_handle`] preserves any stored description.
    pub fn register_handle_with_description(
        &self,
        node_id: &str,
        handle: &str,
        session_id: Option<&str>,
        description: Option<&str>,
        now_ms: i64,
    ) -> StoreResult<HandleRecord> {
        if !is_node_id(node_id) {
            return Err(StoreError::InvalidInput(format!("invalid node_id '{node_id}'")));
        }
        if !is_handle(handle) {
            return Err(StoreError::InvalidInput(format!("invalid handle '{handle}'")));
        }
        let sanitized_desc = sanitize_handle_description(description);
        let tx = self.db.immediate_tx()?;
        tx.conn().execute(
            "INSERT INTO handles (node_id, handle, session_id, description, registered_at, last_heartbeat_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?5)
             ON CONFLICT(node_id, handle) DO UPDATE SET
               session_id = COALESCE(excluded.session_id, handles.session_id),
               description = excluded.description,
               last_heartbeat_at = excluded.last_heartbeat_at",
            params![
                node_id,
                handle,
                session_id,
                sanitized_desc.as_deref(),
                now_ms
            ],
        )?;
        let record = tx.conn().query_row(
            "SELECT node_id, handle, session_id, description, registered_at, last_heartbeat_at
             FROM handles WHERE node_id = ?1 AND handle = ?2",
            params![node_id, handle],
            decode_handle_row,
        )?;
        tx.commit()?;
        Ok(record)
    }

    /// Looks up a single enrolled handle record by `(node_id, handle)`.
    pub fn get_handle(&self, node_id: &str, handle: &str) -> StoreResult<Option<HandleRecord>> {
        self.db
            .conn()
            .query_row(
                "SELECT node_id, handle, session_id, description, registered_at, last_heartbeat_at
                 FROM handles WHERE node_id = ?1 AND handle = ?2",
                params![node_id, handle],
                decode_handle_row,
            )
            .optional()
            .map_err(Into::into)
    }

    /// Updates `last_heartbeat_at` for an enrolled handle. Returns `false` if not enrolled.
    pub fn heartbeat_handle(
        &self,
        node_id: &str,
        handle: &str,
        now_ms: i64,
    ) -> StoreResult<bool> {
        let changed = self.db.conn().execute(
            "UPDATE handles SET last_heartbeat_at = ?1 WHERE node_id = ?2 AND handle = ?3",
            params![now_ms, node_id, handle],
        )?;
        Ok(changed > 0)
    }

    /// Removes a handle, evicts it from all `#channels`, and rejects its pending messages with
    /// `not_enrolled`. Returns the number of rejected pending messages.
    pub fn remove_handle(&self, node_id: &str, handle: &str, now_ms: i64) -> StoreResult<usize> {
        let tx = self.db.immediate_tx()?;
        let dropped = remove_handle_in_tx(tx.conn(), node_id, handle, now_ms)?;
        tx.commit()?;
        Ok(dropped)
    }

    /// Atomically replaces the handle set for `node_id`.
    /// Removed handles are evicted from `channel_members` and their pending messages rejected.
    pub fn set_handles(
        &self,
        node_id: &str,
        handles: &[&str],
        now_ms: i64,
    ) -> StoreResult<Vec<HandleRecord>> {
        let with_descriptions: Vec<(&str, Option<&str>)> =
            handles.iter().map(|&h| (h, None)).collect();
        self.set_handles_with_descriptions(node_id, &with_descriptions, now_ms)
    }

    /// Atomically replaces the handle set and optional descriptions for `node_id`.
    /// Removed handles are evicted from `channel_members` and their pending messages rejected.
    pub fn set_handles_with_descriptions(
        &self,
        node_id: &str,
        handles: &[(&str, Option<&str>)],
        now_ms: i64,
    ) -> StoreResult<Vec<HandleRecord>> {
        if !is_node_id(node_id) {
            return Err(StoreError::InvalidInput(format!("invalid node_id '{node_id}'")));
        }
        let mut next: BTreeMap<String, Option<String>> = BTreeMap::new();
        for &(h, desc) in handles {
            if !is_handle(h) {
                return Err(StoreError::InvalidInput(format!("invalid handle '{h}'")));
            }
            next.insert(h.to_string(), sanitize_handle_description(desc));
        }

        let tx = self.db.immediate_tx()?;
        let mut stmt = tx
            .conn()
            .prepare("SELECT handle FROM handles WHERE node_id = ?1")?;
        let current: HashSet<String> = stmt
            .query_map(params![node_id], |row| row.get::<_, String>(0))?
            .collect::<Result<HashSet<_>, _>>()?;
        drop(stmt);

        for old in &current {
            if !next.contains_key(old) {
                remove_handle_in_tx(tx.conn(), node_id, old, now_ms)?;
            }
        }
        for (h, desc) in &next {
            if !current.contains(h) {
                tx.conn().execute(
                    "INSERT INTO handles (node_id, handle, description, registered_at, last_heartbeat_at)
                     VALUES (?1, ?2, ?3, ?4, ?4)",
                    params![node_id, h, desc.as_deref(), now_ms],
                )?;
            } else {
                tx.conn().execute(
                    "UPDATE handles SET description = ?1, last_heartbeat_at = ?2
                     WHERE node_id = ?3 AND handle = ?4",
                    params![desc.as_deref(), now_ms, node_id, h],
                )?;
            }
        }

        let mut list_stmt = tx.conn().prepare(
            "SELECT node_id, handle, session_id, description, registered_at, last_heartbeat_at
             FROM handles WHERE node_id = ?1 ORDER BY handle ASC",
        )?;
        let records = list_stmt
            .query_map(params![node_id], decode_handle_row)?
            .collect::<Result<Vec<_>, _>>()?;
        drop(list_stmt);
        tx.commit()?;
        Ok(records)
    }

    /// Lists enrolled handles, optionally filtered by `node_id`.
    pub fn list_handles(&self, node_id: Option<&str>) -> StoreResult<Vec<HandleRecord>> {
        if let Some(nid) = node_id {
            let mut stmt = self.db.conn().prepare(
                "SELECT node_id, handle, session_id, description, registered_at, last_heartbeat_at
                 FROM handles WHERE node_id = ?1 ORDER BY handle ASC",
            )?;
            let rows = stmt
                .query_map(params![nid], decode_handle_row)?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        } else {
            let mut stmt = self.db.conn().prepare(
                "SELECT node_id, handle, session_id, description, registered_at, last_heartbeat_at
                 FROM handles ORDER BY node_id ASC, handle ASC",
            )?;
            let rows = stmt
                .query_map([], decode_handle_row)?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        }
    }

    /// Checks whether `<node_id>/<handle>` is currently enrolled.
    pub fn is_enrolled(&self, address: &str) -> StoreResult<bool> {
        is_enrolled_conn(self.db.conn(), address)
    }

    /// Removes handles whose `last_heartbeat_at < cutoff_ms`, cleaning up their channel
    /// memberships and rejecting pending messages. Returns the pruned `<node_id>/<handle>` addresses.
    pub fn prune_stale_handles(&self, cutoff_ms: i64, now_ms: i64) -> StoreResult<Vec<String>> {
        let tx = self.db.immediate_tx()?;
        let mut stmt = tx.conn().prepare(
            "SELECT node_id, handle FROM handles WHERE last_heartbeat_at < ?1 ORDER BY node_id, handle",
        )?;
        let stale: Vec<(String, String)> = stmt
            .query_map(params![cutoff_ms], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<Result<Vec<_>, _>>()?;
        drop(stmt);

        let mut removed = Vec::with_capacity(stale.len());
        for (nid, handle) in stale {
            remove_handle_in_tx(tx.conn(), &nid, &handle, now_ms)?;
            removed.push(format_address(&nid, &handle));
        }
        tx.commit()?;
        Ok(removed)
    }

    // ---- Message Enqueue, Delivery, Ack & Pruning ----

    /// Idempotently enqueues a DM (or channel-tagged) message.
    ///
    /// Preserves `msg.text` verbatim (zero payload mutation for E2EE).
    pub fn enqueue(&self, msg: &EnqueueMessage, now_ms: i64) -> StoreResult<EnqueueResult> {
        let tx = self.db.immediate_tx()?;
        let res = enqueue_in_tx(tx.conn(), msg, self.limits(), now_ms)?;
        tx.commit()?;
        Ok(res)
    }

    /// Returns the oldest due pending message per handle belonging to `node_id`
    /// (FIFO per recipient, skipping in-flight, held, or expired messages).
    pub fn due_messages<F>(
        &self,
        node_id: &str,
        in_flight: F,
        now_ms: i64,
    ) -> StoreResult<Vec<MessageRecord>>
    where
        F: Fn(&str) -> bool,
    {
        let limits = self.limits();
        let handles = self.list_handles(Some(node_id))?;
        let mut due = Vec::new();
        for h in handles {
            let row: Option<MessageRecord> = self
                .db
                .conn()
                .query_row(
                    "SELECT * FROM messages
                     WHERE to_addr = ?1 AND state = 'pending'
                     ORDER BY sent_at ASC, id ASC
                     LIMIT 1",
                    params![&h.address],
                    decode_message_row,
                )
                .optional()?
                .transpose()?;
            let Some(msg) = row else {
                continue;
            };
            if in_flight(&msg.id)
                || msg.hold_until > now_ms
                || now_ms - msg.sent_at >= limits.ttl_ms
            {
                continue;
            }
            due.push(msg);
        }
        Ok(due)
    }

    /// Acknowledges a pending message for `recipient_node_id` (`delivered`, `hold`, or `rejected`).
    pub fn ack(
        &self,
        recipient_node_id: &str,
        message_id: &str,
        outcome: &AckOutcome,
        now_ms: i64,
    ) -> StoreResult<bool> {
        let tx = self.db.immediate_tx()?;
        let msg: Option<MessageRecord> = tx
            .conn()
            .query_row(
                "SELECT * FROM messages WHERE id = ?1 AND state = 'pending'",
                params![message_id],
                decode_message_row,
            )
            .optional()?
            .transpose()?;
        let Some(msg) = msg else {
            return Ok(false);
        };
        let Some((to_node, _)) = parse_address(&msg.to_addr) else {
            return Ok(false);
        };
        if to_node != recipient_node_id {
            return Ok(false);
        }

        match outcome {
            AckOutcome::Delivered => {
                tx.conn().execute(
                    "UPDATE messages SET state = 'delivered', settled_at = ?1 WHERE id = ?2",
                    params![now_ms, message_id],
                )?;
            }
            AckOutcome::Rejected { reason } => {
                tx.conn().execute(
                    "UPDATE messages SET state = 'rejected', reason = ?1, settled_at = ?2 WHERE id = ?3",
                    params![reason, now_ms, message_id],
                )?;
            }
            AckOutcome::Hold {
                reason,
                retry_after_ms,
            } => {
                let delay = retry_after_ms
                    .filter(|&d| d > 0)
                    .unwrap_or(self.limits().hold_retry_ms);
                tx.conn().execute(
                    "UPDATE messages SET reason = ?1, hold_until = ?2 WHERE id = ?3",
                    params![reason, now_ms + delay, message_id],
                )?;
            }
        }
        tx.commit()?;
        Ok(true)
    }

    /// Looks up a message by ID.
    pub fn get_message(&self, id: &str) -> StoreResult<Option<MessageRecord>> {
        self.db
            .conn()
            .query_row("SELECT * FROM messages WHERE id = ?1", params![id], decode_message_row)
            .optional()?
            .transpose()
    }

    /// Lists all pending messages addressed to `to_addr` in FIFO order.
    pub fn list_pending(&self, to_addr: &str) -> StoreResult<Vec<MessageRecord>> {
        let mut stmt = self.db.conn().prepare(
            "SELECT * FROM messages WHERE to_addr = ?1 AND state = 'pending' ORDER BY sent_at ASC, id ASC",
        )?;
        let rows = stmt
            .query_map(params![to_addr], decode_message_row)?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter().collect()
    }

    /// Expires pending messages past `ttl_ms` and prunes settled rows past `settled_retention_ms` (7d).
    pub fn tick(&self, now_ms: i64) -> StoreResult<MessageTickReport> {
        let limits = self.limits().clone();
        let should_prune = {
            let guard = self
                .db
                .message_last_prune_ms
                .lock()
                .expect("message_last_prune_ms mutex poisoned");
            guard.is_none_or(|last| now_ms - last >= limits.prune_interval_ms)
        };
        let has_expired: bool = self.db.conn().query_row(
            "SELECT EXISTS(SELECT 1 FROM messages WHERE state = 'pending' AND sent_at <= ?1)",
            params![now_ms - limits.ttl_ms],
            |row| row.get(0),
        )?;
        if !has_expired && !should_prune {
            return Ok(MessageTickReport::default());
        }

        let tx = self.db.immediate_tx()?;
        let expired = if has_expired {
            tx.conn().execute(
                "UPDATE messages SET state = 'expired', settled_at = ?1
                 WHERE state = 'pending' AND sent_at <= ?2",
                params![now_ms, now_ms - limits.ttl_ms],
            )?
        } else {
            0
        };
        let settled_pruned = if should_prune {
            tx.conn().execute(
                "DELETE FROM messages
                 WHERE state != 'pending' AND settled_at IS NOT NULL AND settled_at <= ?1",
                params![now_ms - limits.settled_retention_ms],
            )?
        } else {
            0
        };
        tx.commit()?;
        if should_prune {
            let mut guard = self
                .db
                .message_last_prune_ms
                .lock()
                .expect("message_last_prune_ms mutex poisoned");
            *guard = Some(now_ms);
        }
        Ok(MessageTickReport {
            expired,
            settled_pruned,
        })
    }

    /// Computes the exact earliest wake timestamp (epoch ms) across message expiry, hold retry,
    /// and settled-row retention pruning; returns `None` when completely idle.
    pub fn next_deadline_ms(&self, now_ms: i64) -> StoreResult<Option<i64>> {
        let limits = self.limits();
        let conn = self.db.conn();
        let mut earliest: Option<i64> = None;
        let mut consider = |ts: Option<i64>| {
            if let Some(t) = ts {
                earliest = Some(match earliest {
                    Some(prev) => prev.min(t),
                    None => t,
                });
            }
        };

        let oldest_pending: Option<i64> = conn.query_row(
            "SELECT MIN(sent_at) FROM messages WHERE state = 'pending'",
            [],
            |row| row.get(0),
        )?;
        consider(oldest_pending.map(|t| t + limits.ttl_ms));

        let next_hold: Option<i64> = conn.query_row(
            "SELECT MIN(hold_until) FROM messages WHERE state = 'pending' AND hold_until > ?1",
            params![now_ms],
            |row| row.get(0),
        )?;
        consider(next_hold);

        let oldest_settled: Option<i64> = conn.query_row(
            "SELECT MIN(settled_at) FROM messages WHERE state != 'pending' AND settled_at IS NOT NULL",
            [],
            |row| row.get(0),
        )?;
        if let Some(settled_at) = oldest_settled {
            let prune_target = settled_at + limits.settled_retention_ms;
            let last_prune = *self
                .db
                .message_last_prune_ms
                .lock()
                .expect("message_last_prune_ms mutex poisoned");
            let next_prune = match last_prune {
                Some(last) => prune_target.max(last + limits.prune_interval_ms),
                None => prune_target,
            };
            consider(Some(next_prune));
        }

        Ok(earliest)
    }
}

/// `#channel` membership, E2EE-safe fan-out, and `channel_epochs` store view borrowed from [`NodeDb`].
pub struct ChannelStore<'a> {
    db: &'a NodeDb,
}

impl<'a> ChannelStore<'a> {
    pub(crate) fn new(db: &'a NodeDb) -> Self {
        Self { db }
    }

    fn limits(&self) -> &MessageLimits {
        &self.db.config().message_limits
    }

    /// Adds an enrolled `<node_id>/<handle>` to `(host_node, channel)`.
    pub fn join(
        &self,
        host_node: &str,
        channel: &str,
        node_id: &str,
        handle: &str,
        now_ms: i64,
    ) -> StoreResult<ChannelMembership> {
        if !is_node_id(host_node) {
            return Err(StoreError::InvalidInput(format!("invalid host_node '{host_node}'")));
        }
        if !is_channel_name(channel) {
            return Err(StoreError::InvalidInput(format!(
                "invalid channel name '{channel}' (expected e.g. #incidents)"
            )));
        }
        let address = format_address(node_id, handle);
        let tx = self.db.immediate_tx()?;
        if !is_enrolled_conn(tx.conn(), &address)? {
            return Err(StoreError::NotFound(format!("handle '{address}' is not enrolled")));
        }
        tx.conn().execute(
            "INSERT OR REPLACE INTO channel_members (host_node, channel, address, joined_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![host_node, channel, &address, now_ms],
        )?;
        let members = enrolled_channel_members(tx.conn(), host_node, channel)?;
        tx.commit()?;
        Ok(ChannelMembership {
            host_node: host_node.to_string(),
            channel: channel.to_string(),
            address,
            members,
        })
    }

    /// Removes `<node_id>/<handle>` from `(host_node, channel)`. Returns `true` if previously a member.
    pub fn leave(
        &self,
        host_node: &str,
        channel: &str,
        node_id: &str,
        handle: &str,
    ) -> StoreResult<bool> {
        if !is_node_id(host_node) {
            return Err(StoreError::InvalidInput(format!("invalid host_node '{host_node}'")));
        }
        if !is_channel_name(channel) {
            return Err(StoreError::InvalidInput(format!("invalid channel name '{channel}'")));
        }
        let address = format_address(node_id, handle);
        let changed = self.db.conn().execute(
            "DELETE FROM channel_members WHERE host_node = ?1 AND channel = ?2 AND address = ?3",
            params![host_node, channel, address],
        )?;
        Ok(changed > 0)
    }

    /// Lists currently enrolled members of `(host_node, channel)` sorted lexicographically.
    pub fn members(&self, host_node: &str, channel: &str) -> StoreResult<Vec<String>> {
        enrolled_channel_members(self.db.conn(), host_node, channel)
    }

    /// Lists `(host_node, channel)` pairs joined by `address`, ordered deterministically by
    /// `(host_node ASC, channel ASC)`.
    pub fn list_channels_for_address(&self, address: &str) -> StoreResult<Vec<(String, String)>> {
        if address.is_empty() {
            return Ok(Vec::new());
        }
        let mut stmt = self.db.conn().prepare(
            "SELECT host_node, channel FROM channel_members
             WHERE address = ?1
             ORDER BY host_node ASC, channel ASC",
        )?;
        let rows = stmt
            .query_map(params![address], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Lists non-empty channels and their enrolled members, optionally filtered by `host_node`.
    pub fn list_channels(&self, host_node: Option<&str>) -> StoreResult<Vec<ChannelInfo>> {
        let rows: Vec<(String, String, String)> = if let Some(host) = host_node {
            let mut stmt = self.db.conn().prepare(
                "SELECT host_node, channel, address FROM channel_members
                 WHERE host_node = ?1 ORDER BY host_node ASC, channel ASC, address ASC",
            )?;
            stmt.query_map(params![host], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
                .collect::<Result<Vec<_>, _>>()?
        } else {
            let mut stmt = self.db.conn().prepare(
                "SELECT host_node, channel, address FROM channel_members
                 ORDER BY host_node ASC, channel ASC, address ASC",
            )?;
            stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
                .collect::<Result<Vec<_>, _>>()?
        };

        let mut grouped: BTreeMap<(String, String), Vec<String>> = BTreeMap::new();
        for (host, chan, addr) in rows {
            if is_enrolled_conn(self.db.conn(), &addr)? {
                grouped.entry((host, chan)).or_default().push(addr);
            }
        }
        Ok(grouped
            .into_iter()
            .map(|((host_node, channel), members)| ChannelInfo {
                host_node,
                channel,
                members,
            })
            .collect())
    }

    /// Fans out a `#channel` post to every enrolled member (except the sender) **WITHOUT mutating
    /// `input.text`**, storing the channel name in the structured `messages.channel` column to
    /// preserve E2EE ciphertext authentication.
    pub fn post(
        &self,
        input: &PostChannelInput,
        now_ms: i64,
    ) -> StoreResult<PostChannelResult> {
        if !is_node_id(&input.host_node) {
            return Err(StoreError::InvalidInput(format!(
                "invalid host_node '{}'",
                input.host_node
            )));
        }
        if !is_channel_name(&input.channel) {
            return Err(StoreError::InvalidInput(format!(
                "invalid channel name '{}'",
                input.channel
            )));
        }
        if input.id.is_empty() {
            return Err(StoreError::InvalidInput("post id must be non-empty".to_string()));
        }
        let sender_addr = format_address(&input.from_node, &input.from_handle);
        let tx = self.db.immediate_tx()?;
        if !is_enrolled_conn(tx.conn(), &sender_addr)? {
            return Err(StoreError::NotFound(format!(
                "sender handle '{sender_addr}' is not enrolled"
            )));
        }
        let members = enrolled_channel_members(tx.conn(), &input.host_node, &input.channel)?;
        if !members.contains(&sender_addr) {
            return Err(StoreError::Unauthorized(format!(
                "join '{}' before posting",
                input.channel
            )));
        }

        let limits = self.limits();
        let mut delivered_to = Vec::new();
        let mut failed = Vec::new();
        for recipient in members {
            if recipient == sender_addr {
                continue;
            }
            let msg = EnqueueMessage {
                id: format!("{}:{recipient}", input.id),
                from_node: input.from_node.clone(),
                from_handle: input.from_handle.clone(),
                to_addr: recipient.clone(),
                channel: Some(input.channel.clone()),
                // CRITICAL E2EE INVARIANT: Never prefix `[#channel]` onto payload text!
                text: input.text.clone(),
                origin_environment_id: None,
                origin_thread_id: None,
                e2ee_epoch: input.e2ee_epoch,
            };
            match enqueue_in_tx(tx.conn(), &msg, limits, now_ms) {
                Ok(_) => delivered_to.push(recipient),
                Err(err) => failed.push(ChannelDeliveryFailure {
                    to_addr: recipient,
                    error: err.to_string(),
                }),
            }
        }
        tx.commit()?;
        Ok(PostChannelResult {
            host_node: input.host_node.clone(),
            channel: input.channel.clone(),
            delivered_to,
            failed,
        })
    }

    // ---- E2EE Channel Epochs ----

    /// Stores a signed E2EE `#channel` epoch key envelope & membership snapshot.
    ///
    /// Enforces monotonic epoch progression: storing an older epoch fails closed with
    /// [`StoreError::EpochConflict`], while identical replay of an existing epoch is idempotent.
    pub fn put_epoch(
        &self,
        input: &ChannelEpochInput,
        now_ms: i64,
    ) -> StoreResult<ChannelEpoch> {
        if !is_node_id(&input.host_node) {
            return Err(StoreError::InvalidInput(format!(
                "invalid host_node '{}'",
                input.host_node
            )));
        }
        if !is_channel_name(&input.channel) {
            return Err(StoreError::InvalidInput(format!(
                "invalid channel '{}'",
                input.channel
            )));
        }
        if !is_node_id(&input.creator_node_id) {
            return Err(StoreError::InvalidInput(format!(
                "invalid creator_node_id '{}'",
                input.creator_node_id
            )));
        }
        if input.epoch == 0 {
            return Err(StoreError::InvalidInput("channel epoch must be >= 1".to_string()));
        }
        let mut sorted_members = input.members.clone();
        sorted_members.sort();
        sorted_members.dedup();
        let members_json = serde_json::to_string(&sorted_members)?;

        let tx = self.db.immediate_tx()?;
        let existing: Option<ChannelEpoch> = tx
            .conn()
            .query_row(
                "SELECT * FROM channel_epochs WHERE host_node = ?1 AND channel = ?2 AND epoch = ?3",
                params![&input.host_node, &input.channel, input.epoch as i64],
                decode_channel_epoch_row,
            )
            .optional()?
            .transpose()?;
        if let Some(prev) = existing {
            if prev.creator_node_id == input.creator_node_id
                && prev.key_envelope_json == input.key_envelope_json
                && prev.members == sorted_members
                && prev.signature == input.signature
            {
                tx.commit()?;
                return Ok(prev);
            }
            return Err(StoreError::EpochConflict {
                scope: format!("{}/{}", input.host_node, input.channel),
                message: format!("epoch {} already exists with different content", input.epoch),
            });
        }

        let latest: Option<i64> = tx.conn().query_row(
            "SELECT MAX(epoch) FROM channel_epochs WHERE host_node = ?1 AND channel = ?2",
            params![&input.host_node, &input.channel],
            |row| row.get(0),
        )?;
        if let Some(max_epoch) = latest {
            if (input.epoch as i64) < max_epoch {
                return Err(StoreError::EpochConflict {
                    scope: format!("{}/{}", input.host_node, input.channel),
                    message: format!(
                        "cannot store rolled-back epoch {} below current latest epoch {}",
                        input.epoch, max_epoch
                    ),
                });
            }
        }

        tx.conn().execute(
            "INSERT INTO channel_epochs
             (host_node, channel, epoch, creator_node_id, key_envelope_json, members_json, signature, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                &input.host_node,
                &input.channel,
                input.epoch as i64,
                &input.creator_node_id,
                &input.key_envelope_json,
                &members_json,
                &input.signature,
                now_ms
            ],
        )?;
        tx.commit()?;
        Ok(ChannelEpoch {
            host_node: input.host_node.clone(),
            channel: input.channel.clone(),
            epoch: input.epoch,
            creator_node_id: input.creator_node_id.clone(),
            key_envelope_json: input.key_envelope_json.clone(),
            members: sorted_members,
            signature: input.signature.clone(),
            created_at: now_ms,
        })
    }

    /// Returns the highest epoch stored for `(host_node, channel)`.
    pub fn latest_epoch(
        &self,
        host_node: &str,
        channel: &str,
    ) -> StoreResult<Option<ChannelEpoch>> {
        self.db
            .conn()
            .query_row(
                "SELECT * FROM channel_epochs
                 WHERE host_node = ?1 AND channel = ?2
                 ORDER BY epoch DESC LIMIT 1",
                params![host_node, channel],
                decode_channel_epoch_row,
            )
            .optional()?
            .transpose()
    }

    /// Looks up a specific epoch for `(host_node, channel)`.
    pub fn get_epoch(
        &self,
        host_node: &str,
        channel: &str,
        epoch: u64,
    ) -> StoreResult<Option<ChannelEpoch>> {
        self.db
            .conn()
            .query_row(
                "SELECT * FROM channel_epochs
                 WHERE host_node = ?1 AND channel = ?2 AND epoch = ?3",
                params![host_node, channel, epoch as i64],
                decode_channel_epoch_row,
            )
            .optional()?
            .transpose()
    }

    /// Lists all epochs stored for `(host_node, channel)` in ascending epoch order.
    pub fn list_epochs(&self, host_node: &str, channel: &str) -> StoreResult<Vec<ChannelEpoch>> {
        let mut stmt = self.db.conn().prepare(
            "SELECT * FROM channel_epochs
             WHERE host_node = ?1 AND channel = ?2
             ORDER BY epoch ASC",
        )?;
        let rows = stmt
            .query_map(params![host_node, channel], decode_channel_epoch_row)?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter().collect()
    }
}

// ---- Shared internal helpers ----

fn is_enrolled_conn(conn: &Connection, address: &str) -> StoreResult<bool> {
    let Some((node_id, handle)) = parse_address(address) else {
        return Ok(false);
    };
    let exists: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM handles WHERE node_id = ?1 AND handle = ?2",
            params![node_id, handle],
            |row| row.get(0),
        )
        .optional()?;
    Ok(exists.is_some())
}

fn remove_handle_in_tx(
    conn: &Connection,
    node_id: &str,
    handle: &str,
    now_ms: i64,
) -> StoreResult<usize> {
    conn.execute(
        "DELETE FROM handles WHERE node_id = ?1 AND handle = ?2",
        params![node_id, handle],
    )?;
    let addr = format_address(node_id, handle);
    conn.execute(
        "DELETE FROM channel_members WHERE address = ?1",
        params![&addr],
    )?;
    let dropped = conn.execute(
        "UPDATE messages SET state = 'rejected', reason = 'not_enrolled', settled_at = ?1
         WHERE to_addr = ?2 AND state = 'pending'",
        params![now_ms, &addr],
    )?;
    Ok(dropped)
}

fn enrolled_channel_members(
    conn: &Connection,
    host_node: &str,
    channel: &str,
) -> StoreResult<Vec<String>> {
    let mut stmt = conn.prepare(
        "SELECT address FROM channel_members
         WHERE host_node = ?1 AND channel = ?2
         ORDER BY address ASC",
    )?;
    let addrs: Vec<String> = stmt
        .query_map(params![host_node, channel], |row| row.get(0))?
        .collect::<Result<Vec<_>, _>>()?;
    let mut out = Vec::with_capacity(addrs.len());
    for addr in addrs {
        if is_enrolled_conn(conn, &addr)? {
            out.push(addr);
        }
    }
    Ok(out)
}

fn message_digest(from_addr: &str, to_addr: &str, channel: Option<&str>, text: &str) -> String {
    let payload = serde_json::json!([from_addr, to_addr, channel, text]);
    sha256_hex(payload.to_string().as_bytes())
}

fn enqueue_in_tx(
    conn: &Connection,
    msg: &EnqueueMessage,
    limits: &MessageLimits,
    now_ms: i64,
) -> StoreResult<EnqueueResult> {
    if msg.id.is_empty() {
        return Err(StoreError::InvalidInput("message id must be non-empty".to_string()));
    }
    if let Some(ch) = &msg.channel {
        if !is_channel_name(ch) {
            return Err(StoreError::InvalidInput(format!("invalid channel '{ch}'")));
        }
    }
    let from_addr = format_address(&msg.from_node, &msg.from_handle);
    if !is_enrolled_conn(conn, &from_addr)? {
        return Err(StoreError::Unauthorized(format!(
            "sender handle '{from_addr}' is not enrolled"
        )));
    }

    let digest = message_digest(&from_addr, &msg.to_addr, msg.channel.as_deref(), &msg.text);
    let existing_digest: Option<String> = conn
        .query_row(
            "SELECT digest FROM messages WHERE id = ?1",
            params![&msg.id],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(prev_digest) = existing_digest {
        if prev_digest == digest {
            return Ok(EnqueueResult {
                id: msg.id.clone(),
                deduplicated: true,
            });
        }
        return Err(StoreError::IdConflict(format!(
            "message id '{}' was already used for different content",
            msg.id
        )));
    }

    if msg.text.len() > limits.max_text_bytes {
        return Err(StoreError::TooLarge(format!(
            "message text is {} bytes; limit is {}",
            msg.text.len(),
            limits.max_text_bytes
        )));
    }
    if !is_enrolled_conn(conn, &msg.to_addr)? {
        return Err(StoreError::NotFound(format!(
            "recipient '{}' is not enrolled",
            msg.to_addr
        )));
    }

    let recent: i64 = conn.query_row(
        "SELECT COUNT(*) FROM messages
         WHERE to_addr = ?1 AND sent_at > ?2 AND state != 'rejected'",
        params![&msg.to_addr, now_ms - HOUR_MS],
        |row| row.get(0),
    )?;
    if recent as usize >= limits.max_per_hour_per_recipient {
        return Err(StoreError::RateLimited(format!(
            "'{}' already received {recent} messages in the last hour",
            msg.to_addr
        )));
    }

    let pending: i64 = conn.query_row(
        "SELECT COUNT(*) FROM messages WHERE to_addr = ?1 AND state = 'pending'",
        params![&msg.to_addr],
        |row| row.get(0),
    )?;
    if pending as usize >= limits.max_pending_per_recipient {
        return Err(StoreError::QuotaExceeded(format!(
            "'{}' has {pending} undelivered pending messages",
            msg.to_addr
        )));
    }

    conn.execute(
        "INSERT INTO messages
         (id, from_addr, to_addr, channel, text, digest, sent_at, state,
          origin_environment_id, origin_thread_id, e2ee_epoch)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'pending', ?8, ?9, ?10)",
        params![
            &msg.id,
            &from_addr,
            &msg.to_addr,
            msg.channel.as_deref(),
            &msg.text,
            &digest,
            now_ms,
            msg.origin_environment_id.as_deref(),
            msg.origin_thread_id.as_deref(),
            msg.e2ee_epoch.map(|e| e as i64)
        ],
    )?;

    Ok(EnqueueResult {
        id: msg.id.clone(),
        deduplicated: false,
    })
}

fn decode_handle_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<HandleRecord> {
    let node_id: String = row.get("node_id")?;
    let handle: String = row.get("handle")?;
    let address = format_address(&node_id, &handle);
    Ok(HandleRecord {
        node_id,
        handle,
        address,
        session_id: row.get("session_id")?,
        description: row.get("description")?,
        registered_at: row.get("registered_at")?,
        last_heartbeat_at: row.get("last_heartbeat_at")?,
    })
}

fn decode_message_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoreResult<MessageRecord>> {
    let id: String = row.get("id")?;
    let from_addr: String = row.get("from_addr")?;
    let to_addr: String = row.get("to_addr")?;
    let channel: Option<String> = row.get("channel")?;
    let text: String = row.get("text")?;
    let digest: String = row.get("digest")?;
    let sent_at: i64 = row.get("sent_at")?;
    let state_str: String = row.get("state")?;
    let reason: Option<String> = row.get("reason")?;
    let hold_until: i64 = row.get("hold_until")?;
    let settled_at: Option<i64> = row.get("settled_at")?;
    let origin_environment_id: Option<String> = row.get("origin_environment_id")?;
    let origin_thread_id: Option<String> = row.get("origin_thread_id")?;
    let e2ee_epoch: Option<i64> = row.get("e2ee_epoch")?;

    Ok(MessageState::parse(&state_str).map(|state| MessageRecord {
        id,
        from_addr,
        to_addr,
        channel,
        text,
        digest,
        sent_at,
        state,
        reason,
        hold_until,
        settled_at,
        origin_environment_id,
        origin_thread_id,
        e2ee_epoch: e2ee_epoch.map(|e| e as u64),
    }))
}

fn decode_channel_epoch_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<StoreResult<ChannelEpoch>> {
    let host_node: String = row.get("host_node")?;
    let channel: String = row.get("channel")?;
    let epoch: i64 = row.get("epoch")?;
    let creator_node_id: String = row.get("creator_node_id")?;
    let key_envelope_json: String = row.get("key_envelope_json")?;
    let members_json: String = row.get("members_json")?;
    let signature: String = row.get("signature")?;
    let created_at: i64 = row.get("created_at")?;

    Ok((|| {
        let members: Vec<String> = serde_json::from_str(&members_json)?;
        Ok(ChannelEpoch {
            host_node,
            channel,
            epoch: epoch as u64,
            creator_node_id,
            key_envelope_json,
            members,
            signature,
            created_at,
        })
    })())
}
