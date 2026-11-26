//! Shared KV / Blackboard store (`kv_entries`, `kv_epochs`) supporting all three write models
//! (`owner`, `shared` CAS with `VersionConflict`, `allowlist`), TTL expiry, namespace/prefix
//! listing, E2EE epoch metadata, and **atomic CloudEvent emission** (`to.hyphae.kv.set` /
//! `to.hyphae.kv.deleted`) inside the exact same `BEGIN IMMEDIATE` SQLite transaction.

use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::db::NodeDb;
use crate::error::{StoreError, StoreResult};
use crate::events::{IngestResult, ingest_in_tx};
use crate::types::{
    CloudEvent, WriteModel, epoch_ms_to_rfc3339, is_kv_key, is_kv_namespace, is_node_id,
    sha256_hex, uuid_v4,
};

/// Maximum UTF-8 byte length of an inline KV value included inside the emitted CloudEvent `data`.
/// Larger values are stored in full in `kv_entries` and emitted as metadata + SHA-256 digest
/// so CloudEvent size limits never block legitimate KV writes.
const MAX_INLINE_EVENT_VALUE_BYTES: usize = 6 * 1024;

/// Maximum UTF-8 byte length of a stored KV entry value (256 KiB).
pub const MAX_KV_VALUE_BYTES: usize = 256 * 1024;

/// Input to create or update a Shared KV entry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KvSetInput {
    pub host_node: String,
    pub namespace: String,
    pub key: String,
    pub value: Value,
    /// Media type (`"application/json"` or `"application/hyphae-e2ee+json"`).
    pub content_type: Option<String>,
    pub write_model: WriteModel,
    /// Designated owner for `WriteModel::Owner` (defaults to `writer_id` on create).
    pub owner_id: Option<String>,
    /// Explicit writer list for `WriteModel::Allowlist`.
    pub allowlist: Option<Vec<String>>,
    /// Identity performing this write.
    pub writer_id: String,
    /// Expected current version for optimistic concurrency (mandatory for `WriteModel::Shared`
    /// on updates; enforced whenever supplied on any write model).
    pub expected_version: Option<u64>,
    /// Optional E2EE namespace epoch used to encrypt `value`.
    pub e2ee_epoch: Option<u64>,
    /// Optional Ed25519 writer signature over the entry.
    pub signature: Option<String>,
    /// Optional TTL in milliseconds from `now_ms`.
    pub ttl_ms: Option<i64>,
}

/// Input to delete a Shared KV entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KvDeleteInput {
    pub host_node: String,
    pub namespace: String,
    pub key: String,
    pub writer_id: String,
    /// Expected current version (mandatory for `WriteModel::Shared`, enforced whenever supplied).
    pub expected_version: Option<u64>,
}

/// Persisted Shared KV entry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KvEntry {
    pub host_node: String,
    pub namespace: String,
    pub key: String,
    pub value: Value,
    pub content_type: String,
    pub version: u64,
    pub write_model: WriteModel,
    pub owner_id: Option<String>,
    pub allowlist: Vec<String>,
    pub writer_id: String,
    pub e2ee_epoch: Option<u64>,
    pub signature: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    pub expires_at: Option<i64>,
}

/// Metadata selected without loading or parsing the stored value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KvEntryMetadata {
    pub key: String,
    pub version: u64,
    pub writer_id: String,
    pub updated_at: i64,
    pub expires_at: Option<i64>,
    pub stored_size_bytes: u64,
    pub content_type: String,
    pub e2ee_epoch: Option<u64>,
}

/// Result of a KV `set` operation, including the atomically emitted `to.hyphae.kv.set` event.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KvSetResult {
    pub entry: KvEntry,
    pub event: IngestResult,
}

/// Result of a KV `delete` operation, including the atomically emitted `to.hyphae.kv.deleted` event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KvDeleteResult {
    pub deleted: bool,
    pub previous_version: Option<u64>,
    pub event: Option<IngestResult>,
}

/// Input to store a signed E2EE KV namespace epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KvEpochInput {
    pub host_node: String,
    pub namespace: String,
    pub epoch: u64,
    pub creator_node_id: String,
    pub key_envelope_json: String,
    pub members: Vec<String>,
    pub signature: String,
}

/// Persisted E2EE KV namespace epoch metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KvEpoch {
    pub host_node: String,
    pub namespace: String,
    pub epoch: u64,
    pub creator_node_id: String,
    pub key_envelope_json: String,
    pub members: Vec<String>,
    pub signature: String,
    pub created_at: i64,
}

/// Shared KV / Blackboard store view borrowed from [`NodeDb`].
pub struct KvStore<'a> {
    db: &'a NodeDb,
}

impl<'a> KvStore<'a> {
    pub(crate) fn new(db: &'a NodeDb) -> Self {
        Self { db }
    }

    /// Creates or updates a KV entry and atomically emits a `to.hyphae.kv.set` CloudEvent on
    /// `(origin_node = host_node, topic = "kv")` inside the exact same `BEGIN IMMEDIATE` transaction.
    pub fn set(&self, input: &KvSetInput, now_ms: i64) -> StoreResult<KvSetResult> {
        validate_kv_coords(&input.host_node, &input.namespace, &input.key)?;
        if input.writer_id.is_empty() {
            return Err(StoreError::InvalidInput(
                "writer_id must be non-empty".to_string(),
            ));
        }
        let content_type = input
            .content_type
            .clone()
            .unwrap_or_else(|| "application/json".to_string());
        if !content_type.contains('/') {
            return Err(StoreError::InvalidInput(format!(
                "invalid content_type '{content_type}'"
            )));
        }
        if let Some(ttl) = input.ttl_ms {
            if ttl <= 0 {
                return Err(StoreError::InvalidInput(
                    "ttl_ms must be positive".to_string(),
                ));
            }
        }
        let value_json = serde_json::to_string(&input.value)?;
        if value_json.len() > MAX_KV_VALUE_BYTES {
            return Err(StoreError::TooLarge(format!(
                "kv value is {} bytes; limit is {MAX_KV_VALUE_BYTES}",
                value_json.len()
            )));
        }
        let expires_at = input.ttl_ms.map(|ttl| now_ms + ttl);

        let tx = self.db.immediate_tx()?;

        let existing: Option<KvEntry> = tx
            .conn()
            .query_row(
                "SELECT * FROM kv_entries WHERE host_node = ?1 AND namespace = ?2 AND key = ?3",
                params![&input.host_node, &input.namespace, &input.key],
                decode_kv_row,
            )
            .optional()?
            .transpose()?;

        // Treat expired entries as absent so TTL expiry is consistent across get/set/delete.
        let live_existing = existing.filter(|e| e.expires_at.is_none_or(|exp| exp > now_ms));

        let (next_version, final_write_model, final_owner, final_allowlist, created_at) =
            if let Some(prev) = live_existing {
                // Enforce existing entry's write model fail-closed.
                match prev.write_model {
                    WriteModel::Owner => {
                        let owner = prev.owner_id.as_deref().unwrap_or(&prev.writer_id);
                        if input.writer_id != owner {
                            return Err(StoreError::Unauthorized(format!(
                                "writer '{}' is not the owner '{}' of '{}/{}/{}'",
                                input.writer_id, owner, input.host_node, input.namespace, input.key
                            )));
                        }
                        if let Some(exp) = input.expected_version {
                            if exp != prev.version {
                                return Err(StoreError::VersionConflict {
                                    current_version: prev.version,
                                });
                            }
                        }
                    }
                    WriteModel::Shared => {
                        if input.expected_version != Some(prev.version) {
                            return Err(StoreError::VersionConflict {
                                current_version: prev.version,
                            });
                        }
                    }
                    WriteModel::Allowlist => {
                        if !prev.allowlist.iter().any(|w| w == &input.writer_id) {
                            return Err(StoreError::Unauthorized(format!(
                                "writer '{}' is not in allowlist for '{}/{}/{}'",
                                input.writer_id, input.host_node, input.namespace, input.key
                            )));
                        }
                        if let Some(exp) = input.expected_version {
                            if exp != prev.version {
                                return Err(StoreError::VersionConflict {
                                    current_version: prev.version,
                                });
                            }
                        }
                    }
                }

                // Preserve existing write model & ACL metadata on value updates so a regular
                // `set` can never silently weaken an entry's security policy.
                (
                    prev.version + 1,
                    prev.write_model,
                    prev.owner_id,
                    prev.allowlist,
                    prev.created_at,
                )
            } else {
                // Creating a fresh key (or replacing an expired key).
                if let Some(exp) = input.expected_version {
                    if exp != 0 {
                        return Err(StoreError::VersionConflict { current_version: 0 });
                    }
                }
                let (owner, allowlist) = match input.write_model {
                    WriteModel::Owner => {
                        let owner = input
                            .owner_id
                            .clone()
                            .unwrap_or_else(|| input.writer_id.clone());
                        if owner != input.writer_id {
                            return Err(StoreError::Unauthorized(format!(
                                "writer '{}' cannot create owner-mode key owned by '{owner}'",
                                input.writer_id
                            )));
                        }
                        (Some(owner), Vec::new())
                    }
                    WriteModel::Shared => (input.owner_id.clone(), Vec::new()),
                    WriteModel::Allowlist => {
                        let mut list = input.allowlist.clone().unwrap_or_default();
                        list.sort();
                        list.dedup();
                        if list.is_empty() {
                            return Err(StoreError::InvalidInput(
                                "allowlist write model requires at least one allowed writer"
                                    .to_string(),
                            ));
                        }
                        if !list.iter().any(|w| w == &input.writer_id) {
                            return Err(StoreError::Unauthorized(format!(
                                "writer '{}' must be included in initial allowlist",
                                input.writer_id
                            )));
                        }
                        (input.owner_id.clone(), list)
                    }
                };
                (1u64, input.write_model, owner, allowlist, now_ms)
            };

        let allowlist_json = if final_allowlist.is_empty() {
            None
        } else {
            Some(serde_json::to_string(&final_allowlist)?)
        };

        tx.conn().execute(
            "INSERT INTO kv_entries
             (host_node, namespace, key, value_json, content_type, version, write_model,
              owner_id, allowlist_json, writer_id, e2ee_epoch, signature, created_at, updated_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)
             ON CONFLICT(host_node, namespace, key) DO UPDATE SET
               value_json = excluded.value_json,
               content_type = excluded.content_type,
               version = excluded.version,
               write_model = excluded.write_model,
               owner_id = excluded.owner_id,
               allowlist_json = excluded.allowlist_json,
               writer_id = excluded.writer_id,
               e2ee_epoch = excluded.e2ee_epoch,
               signature = excluded.signature,
               created_at = excluded.created_at,
               updated_at = excluded.updated_at,
               expires_at = excluded.expires_at",
            params![
                &input.host_node,
                &input.namespace,
                &input.key,
                &value_json,
                &content_type,
                next_version as i64,
                final_write_model.as_str(),
                final_owner.as_deref(),
                allowlist_json.as_deref(),
                &input.writer_id,
                input.e2ee_epoch.map(|e| e as i64),
                input.signature.as_deref(),
                created_at,
                now_ms,
                expires_at
            ],
        )?;

        let entry = KvEntry {
            host_node: input.host_node.clone(),
            namespace: input.namespace.clone(),
            key: input.key.clone(),
            value: input.value.clone(),
            content_type: content_type.clone(),
            version: next_version,
            write_model: final_write_model,
            owner_id: final_owner,
            allowlist: final_allowlist,
            writer_id: input.writer_id.clone(),
            e2ee_epoch: input.e2ee_epoch,
            signature: input.signature.clone(),
            created_at,
            updated_at: now_ms,
            expires_at,
        };

        // Atomically emit `to.hyphae.kv.set` CloudEvent inside the exact same transaction!
        let ce = build_kv_set_event(&entry, &value_json, now_ms);
        let event = ingest_in_tx(
            self.db,
            &tx,
            &input.host_node,
            "kv",
            "system:kv",
            &ce,
            now_ms,
        )?;

        tx.commit()?;
        Ok(KvSetResult { entry, event })
    }

    /// Deletes a KV entry (enforcing write model & CAS) and atomically emits a
    /// `to.hyphae.kv.deleted` CloudEvent inside the exact same `BEGIN IMMEDIATE` transaction.
    pub fn delete(&self, input: &KvDeleteInput, now_ms: i64) -> StoreResult<KvDeleteResult> {
        validate_kv_coords(&input.host_node, &input.namespace, &input.key)?;
        if input.writer_id.is_empty() {
            return Err(StoreError::InvalidInput(
                "writer_id must be non-empty".to_string(),
            ));
        }

        let tx = self.db.immediate_tx()?;
        let existing: Option<KvEntry> = tx
            .conn()
            .query_row(
                "SELECT * FROM kv_entries WHERE host_node = ?1 AND namespace = ?2 AND key = ?3",
                params![&input.host_node, &input.namespace, &input.key],
                decode_kv_row,
            )
            .optional()?
            .transpose()?;

        let live = existing.filter(|e| e.expires_at.is_none_or(|exp| exp > now_ms));
        let Some(prev) = live else {
            if let Some(exp) = input.expected_version {
                if exp > 0 {
                    return Err(StoreError::VersionConflict { current_version: 0 });
                }
            }
            // Clean up expired tombstone row if present.
            tx.conn().execute(
                "DELETE FROM kv_entries WHERE host_node = ?1 AND namespace = ?2 AND key = ?3",
                params![&input.host_node, &input.namespace, &input.key],
            )?;
            tx.commit()?;
            return Ok(KvDeleteResult {
                deleted: false,
                previous_version: None,
                event: None,
            });
        };

        match prev.write_model {
            WriteModel::Owner => {
                let owner = prev.owner_id.as_deref().unwrap_or(&prev.writer_id);
                if input.writer_id != owner {
                    return Err(StoreError::Unauthorized(format!(
                        "writer '{}' is not the owner '{}' of '{}/{}/{}'",
                        input.writer_id, owner, input.host_node, input.namespace, input.key
                    )));
                }
                if let Some(exp) = input.expected_version {
                    if exp != prev.version {
                        return Err(StoreError::VersionConflict {
                            current_version: prev.version,
                        });
                    }
                }
            }
            WriteModel::Shared => {
                if input.expected_version != Some(prev.version) {
                    return Err(StoreError::VersionConflict {
                        current_version: prev.version,
                    });
                }
            }
            WriteModel::Allowlist => {
                if !prev.allowlist.iter().any(|w| w == &input.writer_id) {
                    return Err(StoreError::Unauthorized(format!(
                        "writer '{}' is not in allowlist for '{}/{}/{}'",
                        input.writer_id, input.host_node, input.namespace, input.key
                    )));
                }
                if let Some(exp) = input.expected_version {
                    if exp != prev.version {
                        return Err(StoreError::VersionConflict {
                            current_version: prev.version,
                        });
                    }
                }
            }
        }

        tx.conn().execute(
            "DELETE FROM kv_entries WHERE host_node = ?1 AND namespace = ?2 AND key = ?3",
            params![&input.host_node, &input.namespace, &input.key],
        )?;

        let ce = build_kv_deleted_event(
            &input.host_node,
            &input.namespace,
            &input.key,
            prev.version,
            &input.writer_id,
            prev.e2ee_epoch,
            now_ms,
        );
        let event = ingest_in_tx(
            self.db,
            &tx,
            &input.host_node,
            "kv",
            "system:kv",
            &ce,
            now_ms,
        )?;

        tx.commit()?;
        Ok(KvDeleteResult {
            deleted: true,
            previous_version: Some(prev.version),
            event: Some(event),
        })
    }

    /// Reads a live (non-expired) KV entry.
    pub fn get(
        &self,
        host_node: &str,
        namespace: &str,
        key: &str,
        now_ms: i64,
    ) -> StoreResult<Option<KvEntry>> {
        let entry: Option<KvEntry> = self
            .db
            .conn()
            .query_row(
                "SELECT * FROM kv_entries
                 WHERE host_node = ?1 AND namespace = ?2 AND key = ?3
                   AND (expires_at IS NULL OR expires_at > ?4)",
                params![host_node, namespace, key, now_ms],
                decode_kv_row,
            )
            .optional()?
            .transpose()?;
        Ok(entry)
    }

    /// Lists live (non-expired) KV entries in `(host_node, namespace)` matching an optional key
    /// `prefix`, ordered lexicographically by `key`.
    pub fn list(
        &self,
        host_node: &str,
        namespace: &str,
        prefix: Option<&str>,
        now_ms: i64,
    ) -> StoreResult<Vec<KvEntry>> {
        let mut stmt = self.db.conn().prepare(
            "SELECT * FROM kv_entries
             WHERE host_node = ?1 AND namespace = ?2
               AND (expires_at IS NULL OR expires_at > ?3)
             ORDER BY key ASC",
        )?;
        let rows = stmt
            .query_map(params![host_node, namespace, now_ms], decode_kv_row)?
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .collect::<StoreResult<Vec<_>>>()?;

        Ok(match prefix {
            Some(p) if !p.is_empty() => rows.into_iter().filter(|e| e.key.starts_with(p)).collect(),
            _ => rows,
        })
    }

    /// Pages through live entry metadata in key order. The node authorizes each
    /// namespace, key and epoch before returning metadata to a caller.
    pub fn list_entry_metadata(
        &self,
        host_node: &str,
        namespace: &str,
        after: Option<&str>,
        limit: u32,
        now_ms: i64,
    ) -> StoreResult<Vec<KvEntryMetadata>> {
        let mut stmt = self.db.conn().prepare(
            "SELECT key, version, writer_id, updated_at, expires_at,
                    length(CAST(value_json AS BLOB)), content_type, e2ee_epoch
             FROM kv_entries
             WHERE host_node = ?1 AND namespace = ?2 AND key > ?3
               AND (expires_at IS NULL OR expires_at > ?4)
             ORDER BY key ASC
             LIMIT ?5",
        )?;
        let rows = stmt
            .query_map(
                params![host_node, namespace, after.unwrap_or(""), now_ms, limit],
                |row| {
                    Ok(KvEntryMetadata {
                        key: row.get(0)?,
                        version: row.get(1)?,
                        writer_id: row.get(2)?,
                        updated_at: row.get(3)?,
                        expires_at: row.get(4)?,
                        stored_size_bytes: row.get(5)?,
                        content_type: row.get(6)?,
                        e2ee_epoch: row.get(7)?,
                    })
                },
            )?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Lists namespaces with at least one live KV entry on `host_node`.
    pub fn list_namespaces(&self, host_node: &str, now_ms: i64) -> StoreResult<Vec<String>> {
        let mut stmt = self.db.conn().prepare(
            "SELECT DISTINCT namespace FROM kv_entries
             WHERE host_node = ?1 AND (expires_at IS NULL OR expires_at > ?2)
             ORDER BY namespace ASC",
        )?;
        let rows = stmt
            .query_map(params![host_node, now_ms], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Deletes expired KV entries (`expires_at <= now_ms`). Returns count removed.
    pub fn tick(&self, now_ms: i64) -> StoreResult<usize> {
        let has_expired: bool = self.db.conn().query_row(
            "SELECT EXISTS(SELECT 1 FROM kv_entries WHERE expires_at IS NOT NULL AND expires_at <= ?1)",
            params![now_ms],
            |row| row.get(0),
        )?;
        if !has_expired {
            return Ok(0);
        }
        let tx = self.db.immediate_tx()?;
        let deleted = tx.conn().execute(
            "DELETE FROM kv_entries WHERE expires_at IS NOT NULL AND expires_at <= ?1",
            params![now_ms],
        )?;
        tx.commit()?;
        Ok(deleted)
    }

    /// Returns the exact earliest TTL expiration timestamp among all `kv_entries`,
    /// or `None` when no expiring KV entries exist.
    pub fn next_deadline_ms(&self) -> StoreResult<Option<i64>> {
        let exp: Option<i64> = self.db.conn().query_row(
            "SELECT MIN(expires_at) FROM kv_entries WHERE expires_at IS NOT NULL",
            [],
            |row| row.get(0),
        )?;
        Ok(exp)
    }

    // ---- E2EE Namespace Epochs ----

    /// Stores a signed E2EE KV namespace epoch key & membership snapshot.
    /// Enforces monotonic epoch progression and idempotent identical replay.
    pub fn put_epoch(&self, input: &KvEpochInput, now_ms: i64) -> StoreResult<KvEpoch> {
        if !is_node_id(&input.host_node) {
            return Err(StoreError::InvalidInput(format!(
                "invalid host_node '{}'",
                input.host_node
            )));
        }
        if !is_kv_namespace(&input.namespace) {
            return Err(StoreError::InvalidInput(format!(
                "invalid kv namespace '{}'",
                input.namespace
            )));
        }
        if !is_node_id(&input.creator_node_id) {
            return Err(StoreError::InvalidInput(format!(
                "invalid creator_node_id '{}'",
                input.creator_node_id
            )));
        }
        if input.epoch == 0 {
            return Err(StoreError::InvalidInput(
                "kv epoch must be >= 1".to_string(),
            ));
        }
        let mut sorted_members = input.members.clone();
        sorted_members.sort();
        sorted_members.dedup();
        let members_json = serde_json::to_string(&sorted_members)?;

        let tx = self.db.immediate_tx()?;
        let existing: Option<KvEpoch> = tx
            .conn()
            .query_row(
                "SELECT * FROM kv_epochs WHERE host_node = ?1 AND namespace = ?2 AND epoch = ?3",
                params![&input.host_node, &input.namespace, input.epoch as i64],
                decode_kv_epoch_row,
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
                scope: format!("{}/kv/{}", input.host_node, input.namespace),
                message: format!(
                    "epoch {} already exists with different content",
                    input.epoch
                ),
            });
        }

        let latest: Option<i64> = tx.conn().query_row(
            "SELECT MAX(epoch) FROM kv_epochs WHERE host_node = ?1 AND namespace = ?2",
            params![&input.host_node, &input.namespace],
            |row| row.get(0),
        )?;
        if let Some(max_epoch) = latest {
            if (input.epoch as i64) < max_epoch {
                return Err(StoreError::EpochConflict {
                    scope: format!("{}/kv/{}", input.host_node, input.namespace),
                    message: format!(
                        "cannot store rolled-back epoch {} below current latest epoch {}",
                        input.epoch, max_epoch
                    ),
                });
            }
        }

        tx.conn().execute(
            "INSERT INTO kv_epochs
             (host_node, namespace, epoch, creator_node_id, key_envelope_json, members_json, signature, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                &input.host_node,
                &input.namespace,
                input.epoch as i64,
                &input.creator_node_id,
                &input.key_envelope_json,
                &members_json,
                &input.signature,
                now_ms
            ],
        )?;
        tx.commit()?;
        Ok(KvEpoch {
            host_node: input.host_node.clone(),
            namespace: input.namespace.clone(),
            epoch: input.epoch,
            creator_node_id: input.creator_node_id.clone(),
            key_envelope_json: input.key_envelope_json.clone(),
            members: sorted_members,
            signature: input.signature.clone(),
            created_at: now_ms,
        })
    }

    /// Returns the latest E2EE epoch for `(host_node, namespace)`.
    pub fn latest_epoch(&self, host_node: &str, namespace: &str) -> StoreResult<Option<KvEpoch>> {
        self.db
            .conn()
            .query_row(
                "SELECT * FROM kv_epochs
                 WHERE host_node = ?1 AND namespace = ?2
                 ORDER BY epoch DESC LIMIT 1",
                params![host_node, namespace],
                decode_kv_epoch_row,
            )
            .optional()?
            .transpose()
    }

    /// Returns a specific E2EE epoch for `(host_node, namespace)`.
    pub fn get_epoch(
        &self,
        host_node: &str,
        namespace: &str,
        epoch: u64,
    ) -> StoreResult<Option<KvEpoch>> {
        self.db
            .conn()
            .query_row(
                "SELECT * FROM kv_epochs
                 WHERE host_node = ?1 AND namespace = ?2 AND epoch = ?3",
                params![host_node, namespace, epoch as i64],
                decode_kv_epoch_row,
            )
            .optional()?
            .transpose()
    }

    /// Lists all E2EE epochs for `(host_node, namespace)` ordered ascending.
    pub fn list_epochs(&self, host_node: &str, namespace: &str) -> StoreResult<Vec<KvEpoch>> {
        let mut stmt = self.db.conn().prepare(
            "SELECT * FROM kv_epochs
             WHERE host_node = ?1 AND namespace = ?2
             ORDER BY epoch ASC",
        )?;
        let rows = stmt
            .query_map(params![host_node, namespace], decode_kv_epoch_row)?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter().collect()
    }
}

fn validate_kv_coords(host_node: &str, namespace: &str, key: &str) -> StoreResult<()> {
    if !is_node_id(host_node) {
        return Err(StoreError::InvalidInput(format!(
            "invalid host_node '{host_node}'"
        )));
    }
    if !is_kv_namespace(namespace) {
        return Err(StoreError::InvalidInput(format!(
            "invalid kv namespace '{namespace}'"
        )));
    }
    if !is_kv_key(key) {
        return Err(StoreError::InvalidInput(format!("invalid kv key '{key}'")));
    }
    Ok(())
}

fn build_kv_set_event(entry: &KvEntry, value_json: &str, now_ms: i64) -> CloudEvent {
    let data = if value_json.len() <= MAX_INLINE_EVENT_VALUE_BYTES {
        json!({
            "namespace": entry.namespace,
            "key": entry.key,
            "version": entry.version,
            "writer": entry.writer_id,
            "writeModel": entry.write_model.as_str(),
            "value": entry.value,
            "expiresAt": entry.expires_at,
        })
    } else {
        json!({
            "namespace": entry.namespace,
            "key": entry.key,
            "version": entry.version,
            "writer": entry.writer_id,
            "writeModel": entry.write_model.as_str(),
            "valueTruncated": true,
            "valueBytes": value_json.len(),
            "valueSha256": sha256_hex(value_json.as_bytes()),
            "expiresAt": entry.expires_at,
        })
    };

    let mut ce = CloudEvent::new(
        format!("kv-set-{}", uuid_v4()),
        format!("{}/kv/{}", entry.host_node, entry.namespace),
        "to.hyphae.kv.set",
        data,
    )
    .with_content_type(&entry.content_type)
    .with_subject(format!("{}/{}", entry.namespace, entry.key))
    .with_time(epoch_ms_to_rfc3339(now_ms))
    .with_extension("ns", &entry.namespace)
    .with_extension("key", &entry.key)
    .with_extension("version", entry.version.to_string())
    .with_extension("writer", &entry.writer_id);

    if let Some(epoch) = entry.e2ee_epoch {
        ce = ce.with_extension("epoch", epoch.to_string());
    }
    ce
}

fn build_kv_deleted_event(
    host_node: &str,
    namespace: &str,
    key: &str,
    previous_version: u64,
    writer_id: &str,
    e2ee_epoch: Option<u64>,
    now_ms: i64,
) -> CloudEvent {
    let data = json!({
        "namespace": namespace,
        "key": key,
        "previousVersion": previous_version,
        "writer": writer_id,
        "deleted": true,
    });

    let mut ce = CloudEvent::new(
        format!("kv-del-{}", uuid_v4()),
        format!("{host_node}/kv/{namespace}"),
        "to.hyphae.kv.deleted",
        data,
    )
    .with_subject(format!("{namespace}/{key}"))
    .with_time(epoch_ms_to_rfc3339(now_ms))
    .with_extension("ns", namespace)
    .with_extension("key", key)
    .with_extension("version", previous_version.to_string())
    .with_extension("writer", writer_id);

    if let Some(epoch) = e2ee_epoch {
        ce = ce.with_extension("epoch", epoch.to_string());
    }
    ce
}

fn decode_kv_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoreResult<KvEntry>> {
    let host_node: String = row.get("host_node")?;
    let namespace: String = row.get("namespace")?;
    let key: String = row.get("key")?;
    let value_json: String = row.get("value_json")?;
    let content_type: String = row.get("content_type")?;
    let version: i64 = row.get("version")?;
    let write_model_str: String = row.get("write_model")?;
    let owner_id: Option<String> = row.get("owner_id")?;
    let allowlist_json: Option<String> = row.get("allowlist_json")?;
    let writer_id: String = row.get("writer_id")?;
    let e2ee_epoch: Option<i64> = row.get("e2ee_epoch")?;
    let signature: Option<String> = row.get("signature")?;
    let created_at: i64 = row.get("created_at")?;
    let updated_at: i64 = row.get("updated_at")?;
    let expires_at: Option<i64> = row.get("expires_at")?;

    Ok((|| {
        let value: Value = serde_json::from_str(&value_json)?;
        let write_model = WriteModel::parse(&write_model_str)?;
        let allowlist: Vec<String> = match allowlist_json {
            Some(j) => serde_json::from_str(&j)?,
            None => Vec::new(),
        };
        Ok(KvEntry {
            host_node,
            namespace,
            key,
            value,
            content_type,
            version: version as u64,
            write_model,
            owner_id,
            allowlist,
            writer_id,
            e2ee_epoch: e2ee_epoch.map(|e| e as u64),
            signature,
            created_at,
            updated_at,
            expires_at,
        })
    })())
}

fn decode_kv_epoch_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoreResult<KvEpoch>> {
    let host_node: String = row.get("host_node")?;
    let namespace: String = row.get("namespace")?;
    let epoch: i64 = row.get("epoch")?;
    let creator_node_id: String = row.get("creator_node_id")?;
    let key_envelope_json: String = row.get("key_envelope_json")?;
    let members_json: String = row.get("members_json")?;
    let signature: String = row.get("signature")?;
    let created_at: i64 = row.get("created_at")?;

    Ok((|| {
        let members: Vec<String> = serde_json::from_str(&members_json)?;
        Ok(KvEpoch {
            host_node,
            namespace,
            epoch: epoch as u64,
            creator_node_id,
            key_envelope_json,
            members,
            signature,
            created_at,
        })
    })())
}
