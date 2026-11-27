//! Universal CloudEvents v1.0 pub/sub store, coalescing batches, hourly wake caps,
//! `PRAGMA data_version`-cohered compiled filter cache, upstream pushdown tracking,
//! 24h retention pruning, and exact `next_deadline_ms()` calculation.

use std::collections::{BTreeMap, HashSet};

use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};

use crate::db::{ImmediateTx, NodeDb};
use crate::error::{StoreError, StoreResult};
use crate::query::{query_opt, query_vec};
use crate::types::string_enum;
use crate::types::{
    AckOutcome, CloudEvent, DeliveryMode, Filter, check_filters, is_node_id, is_topic,
    matches_filters, parse_and_check_filters, sha256_hex, uuid_v4,
};

const HOUR_MS: i64 = 60 * 60 * 1000;

/// Operational limits for the universal CloudEvents bus.
#[derive(Debug, Clone)]
pub struct EventLimits {
    /// How long pending/settled batches and event bodies are retained (default: 24h).
    pub retention_ms: i64,
    /// Maximum closed pending batches queued per subscription before dropping oldest.
    pub max_pending_batches_per_subscription: usize,
    /// Default hourly wake cap (delivered batches per hour per subscription).
    pub max_wakes_per_hour_per_subscription: usize,
    /// Maximum events coalesced into a single batch before force-closing.
    pub max_batch_events: usize,
    /// Maximum age of an open batch since its first event before force-closing (default: 5m).
    pub max_batch_age_ms: i64,
    /// Maximum configurable `coalesce_seconds` per subscription (default: 600s).
    pub max_coalesce_seconds: i64,
    /// Maximum subscriptions allowed per subscriber (default: 200).
    pub max_subscriptions_per_subscriber: usize,
    /// How long `(origin_node, topic, publisher, source, event_id)` + digest are retained for idempotency (default: 7d).
    pub idempotency_ms: i64,
    /// Default delay when a batch is acknowledged with `AckOutcome::Hold` without explicit `retry_after_ms`.
    pub hold_retry_ms: i64,
    /// Minimum spacing between retention prune sweeps in `tick()` (default: 60s).
    pub prune_interval_ms: i64,
}

impl Default for EventLimits {
    fn default() -> Self {
        Self {
            retention_ms: 24 * HOUR_MS,
            max_pending_batches_per_subscription: 100,
            max_wakes_per_hour_per_subscription: 30,
            max_batch_events: 20,
            max_batch_age_ms: 5 * 60 * 1000,
            max_coalesce_seconds: 600,
            max_subscriptions_per_subscriber: 200,
            idempotency_ms: 7 * 24 * HOUR_MS,
            hold_retry_ms: 30_000,
            prune_interval_ms: 60_000,
        }
    }
}

/// Subscription create/update specification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscriptionSpec {
    pub id: String,
    pub origin_node: String,
    pub topic: String,
    pub subscriber: String,
    pub filters: Vec<Filter>,
    pub coalesce_seconds: i64,
    pub max_batch_age_ms: Option<i64>,
    pub max_wakes_per_hour: Option<usize>,
    pub mode: DeliveryMode,
}

/// Prefix used in the `metadata` table to persist local subscription metadata (`key`, `urgency`)
/// without requiring a SQLite schema version bump.
pub const SUBSCRIPTION_META_PREFIX: &str = "sub_meta:";

/// Optional persisted local metadata attached to a subscription row (`metadata` table).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionMeta {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub urgency: Option<String>,
}

/// Aggregated per-topic observation stats queried from the SQLite `events` table.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StoredTopicStats {
    pub topic: String,
    pub event_count: u64,
    pub last_received_at: Option<i64>,
    pub sources: Vec<String>,
    pub repos: Vec<String>,
}

/// Persisted subscription record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subscription {
    pub id: String,
    pub origin_node: String,
    pub topic: String,
    pub subscriber: String,
    pub filters: Vec<Filter>,
    pub filters_json: String,
    pub coalesce_seconds: i64,
    pub max_batch_age_ms: Option<i64>,
    pub max_wakes_per_hour: Option<usize>,
    pub mode: DeliveryMode,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Internal compiled subscription kept in the `PRAGMA data_version` cache.
#[derive(Debug, Clone)]
pub(crate) struct CompiledSubscription {
    pub id: String,
    pub origin_node: String,
    pub topic: String,
    pub subscriber: String,
    pub filters: Vec<Filter>,
    pub coalesce_seconds: i64,
    pub max_batch_age_ms: Option<i64>,
}

string_enum! {
    /// Batch lifecycle state.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    pub enum BatchState {
        Open => "open",
        Pending => "pending",
        Delivered => "delivered",
        Rejected => "rejected",
        Dropped => "dropped",
    }
    InvalidInput: "batch state";
}

/// Persisted coalesced event batch metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchRecord {
    pub id: String,
    pub subscription_id: String,
    pub origin_node: String,
    pub subscriber: String,
    pub topic: String,
    pub state: BatchState,
    pub event_count: usize,
    pub opened_at: i64,
    pub last_event_at: i64,
    pub flush_at: i64,
    pub closed_at: Option<i64>,
    pub hold_until: i64,
    pub reason: Option<String>,
    pub settled_at: Option<i64>,
}

/// A pending batch ready to be offered to its subscriber, with hydrated CloudEvents.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DueBatch {
    pub id: String,
    pub subscription_id: String,
    pub origin_node: String,
    pub subscriber: String,
    pub topic: String,
    pub mode: DeliveryMode,
    pub events: Vec<CloudEvent>,
    pub opened_at: i64,
    pub closed_at: i64,
}

/// Result of idempotent event ingestion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IngestResult {
    pub seq: i64,
    pub deduplicated: bool,
    pub matched: usize,
    pub batches_created: usize,
    pub batches_merged: usize,
}

/// Upstream subscription pushdown specification stored for syncing to a remote peer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpstreamPushdownInput {
    pub id: String,
    pub peer_id: String,
    pub topic: String,
    pub shard_index: i64,
    pub filters_json: String,
    pub coalesce_seconds: i64,
    pub local_sub_count: usize,
}

/// Persisted upstream subscription pushdown record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpstreamPushdown {
    pub id: String,
    pub peer_id: String,
    pub topic: String,
    pub shard_index: i64,
    pub filters_json: String,
    pub coalesce_seconds: i64,
    pub local_sub_count: usize,
    pub digest: String,
    pub synced_at: Option<i64>,
    pub last_error: Option<String>,
    pub updated_at: i64,
}

/// Diagnostics for the `PRAGMA data_version`-cohered subscription filter cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventCacheStats {
    pub data_version: Option<i64>,
    pub cached_topics: usize,
    pub hits: u64,
    pub misses: u64,
    pub invalidations: u64,
}

/// Summary of work performed during an `EventStore::tick()` pass.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EventTickReport {
    pub batches_closed: usize,
    pub batches_expired: usize,
    pub batches_pruned: usize,
    pub event_bodies_cleared: usize,
    pub events_pruned: usize,
}

/// Universal CloudEvents v1.0 store view borrowed from [`NodeDb`].
pub struct EventStore<'a> {
    db: &'a NodeDb,
}

impl<'a> EventStore<'a> {
    pub(crate) fn new(db: &'a NodeDb) -> Self {
        Self { db }
    }

    fn limits(&self) -> &EventLimits {
        &self.db.config().event_limits
    }

    /// Returns telemetry counters for the `PRAGMA data_version` compiled subscription cache.
    pub fn cache_stats(&self) -> EventCacheStats {
        let guard = self
            .db
            .event_cache
            .lock()
            .expect("event_cache mutex poisoned");
        EventCacheStats {
            data_version: guard.data_version,
            cached_topics: guard.by_topic.len(),
            hits: guard.hits,
            misses: guard.misses,
            invalidations: guard.invalidations,
        }
    }

    fn invalidate_cache(&self) {
        let mut guard = self
            .db
            .event_cache
            .lock()
            .expect("event_cache mutex poisoned");
        guard.by_topic.clear();
        guard.invalidations += 1;
    }

    // ---- Subscriptions ----

    fn validate_subscription_spec(&self, spec: &SubscriptionSpec) -> StoreResult<String> {
        if spec.id.is_empty() || spec.id.len() > 128 {
            return Err(StoreError::InvalidInput(
                "invalid subscription id".to_string(),
            ));
        }
        if !is_node_id(&spec.origin_node) {
            return Err(StoreError::InvalidInput(format!(
                "invalid origin_node '{}'",
                spec.origin_node
            )));
        }
        if !is_topic(&spec.topic) {
            return Err(StoreError::InvalidInput(format!(
                "invalid topic '{}'",
                spec.topic
            )));
        }
        if spec.subscriber.is_empty() || spec.subscriber.len() > 128 {
            return Err(StoreError::InvalidInput("invalid subscriber".to_string()));
        }
        if spec.coalesce_seconds < 0 || spec.coalesce_seconds > self.limits().max_coalesce_seconds {
            return Err(StoreError::InvalidInput(format!(
                "coalesce_seconds must be in 0..={}",
                self.limits().max_coalesce_seconds
            )));
        }
        if let Some(age) = spec.max_batch_age_ms {
            if age <= 0 {
                return Err(StoreError::InvalidInput(
                    "max_batch_age_ms must be positive".to_string(),
                ));
            }
        }
        if let Some(wakes) = spec.max_wakes_per_hour {
            if wakes == 0 {
                return Err(StoreError::InvalidInput(
                    "max_wakes_per_hour must be positive".to_string(),
                ));
            }
        }
        check_filters(&spec.filters)?;
        Ok(serde_json::to_string(&spec.filters)?)
    }

    /// Creates or updates a single subscription.
    ///
    /// Fails closed with [`StoreError::IdConflict`] if `spec.id` belongs to a different subscriber.
    /// Changing `(origin_node, topic)` drops old batches; changing coalesce/max-age updates `flush_at`
    /// on any open batch.
    pub fn upsert_subscription(
        &self,
        spec: &SubscriptionSpec,
        now_ms: i64,
    ) -> StoreResult<Subscription> {
        let filters_json = self.validate_subscription_spec(spec)?;
        let tx = self.db.immediate_tx()?;

        let existing = load_subscription_by_id(tx.conn(), &spec.id)?;
        if let Some(prev) = &existing {
            if prev.subscriber != spec.subscriber {
                return Err(StoreError::IdConflict(format!(
                    "subscription '{}' belongs to another subscriber",
                    spec.id
                )));
            }
            if prev.origin_node != spec.origin_node || prev.topic != spec.topic {
                tx.conn().execute(
                    "DELETE FROM batches WHERE subscription_id = ?1",
                    params![&spec.id],
                )?;
            }
            tx.conn().execute(
                "UPDATE subscriptions
                 SET origin_node = ?1, topic = ?2, filters_json = ?3, coalesce_seconds = ?4,
                     max_batch_age_ms = ?5, max_wakes_per_hour = ?6, mode = ?7, updated_at = ?8
                 WHERE id = ?9",
                params![
                    &spec.origin_node,
                    &spec.topic,
                    &filters_json,
                    spec.coalesce_seconds,
                    spec.max_batch_age_ms,
                    spec.max_wakes_per_hour.map(|v| v as i64),
                    spec.mode.as_str(),
                    now_ms,
                    &spec.id
                ],
            )?;
            recompute_open_batch_flush(
                tx.conn(),
                &spec.id,
                spec.coalesce_seconds,
                spec.max_batch_age_ms
                    .unwrap_or(self.limits().max_batch_age_ms),
            )?;
        } else {
            let count: i64 = tx.conn().query_row(
                "SELECT COUNT(*) FROM subscriptions WHERE subscriber = ?1",
                params![&spec.subscriber],
                |row| row.get(0),
            )?;
            if count as usize >= self.limits().max_subscriptions_per_subscriber {
                return Err(StoreError::QuotaExceeded(format!(
                    "subscriber '{}' reached max subscriptions ({})",
                    spec.subscriber,
                    self.limits().max_subscriptions_per_subscriber
                )));
            }
            tx.conn().execute(
                "INSERT INTO subscriptions
                 (id, origin_node, topic, subscriber, filters_json, coalesce_seconds,
                  max_batch_age_ms, max_wakes_per_hour, mode, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    &spec.id,
                    &spec.origin_node,
                    &spec.topic,
                    &spec.subscriber,
                    &filters_json,
                    spec.coalesce_seconds,
                    spec.max_batch_age_ms,
                    spec.max_wakes_per_hour.map(|v| v as i64),
                    spec.mode.as_str(),
                    now_ms,
                    now_ms
                ],
            )?;
        }
        let saved = load_subscription_by_id(tx.conn(), &spec.id)?
            .ok_or_else(|| StoreError::NotFound(format!("subscription '{}' vanished", spec.id)))?;
        tx.commit()?;
        self.invalidate_cache();
        Ok(saved)
    }

    /// Atomically replaces all subscriptions owned by `subscriber`.
    pub fn set_subscriptions(
        &self,
        subscriber: &str,
        specs: &[SubscriptionSpec],
        now_ms: i64,
    ) -> StoreResult<Vec<Subscription>> {
        if specs.len() > self.limits().max_subscriptions_per_subscriber {
            return Err(StoreError::QuotaExceeded(format!(
                "at most {} subscriptions per subscriber",
                self.limits().max_subscriptions_per_subscriber
            )));
        }
        let mut seen = HashSet::new();
        let mut validated = Vec::with_capacity(specs.len());
        for spec in specs {
            if spec.subscriber != subscriber {
                return Err(StoreError::InvalidInput(format!(
                    "spec subscriber '{}' does not match '{subscriber}'",
                    spec.subscriber
                )));
            }
            if !seen.insert(spec.id.clone()) {
                return Err(StoreError::InvalidInput(format!(
                    "duplicate subscription id '{}'",
                    spec.id
                )));
            }
            let filters_json = self.validate_subscription_spec(spec)?;
            validated.push((spec, filters_json));
        }

        let tx = self.db.immediate_tx()?;
        for (spec, _) in &validated {
            let owner: Option<String> = tx
                .conn()
                .query_row(
                    "SELECT subscriber FROM subscriptions WHERE id = ?1",
                    params![&spec.id],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(other) = owner {
                if other != subscriber {
                    return Err(StoreError::IdConflict(format!(
                        "subscription '{}' belongs to another subscriber",
                        spec.id
                    )));
                }
            }
        }

        let existing = load_subscriptions_of(tx.conn(), subscriber)?;
        let existing_by_id: BTreeMap<String, Subscription> =
            existing.into_iter().map(|s| (s.id.clone(), s)).collect();

        for prev in existing_by_id.values() {
            if !seen.contains(&prev.id) {
                tx.conn().execute(
                    "DELETE FROM batches WHERE subscription_id = ?1",
                    params![&prev.id],
                )?;
                tx.conn()
                    .execute("DELETE FROM subscriptions WHERE id = ?1", params![&prev.id])?;
                let meta_key = format!("{SUBSCRIPTION_META_PREFIX}{}", prev.id);
                tx.conn()
                    .execute("DELETE FROM metadata WHERE key = ?1", params![&meta_key])?;
            }
        }

        for (spec, filters_json) in validated {
            if let Some(prev) = existing_by_id.get(&spec.id) {
                if prev.origin_node == spec.origin_node
                    && prev.topic == spec.topic
                    && prev.filters_json == filters_json
                    && prev.coalesce_seconds == spec.coalesce_seconds
                    && prev.max_batch_age_ms == spec.max_batch_age_ms
                    && prev.max_wakes_per_hour == spec.max_wakes_per_hour
                    && prev.mode == spec.mode
                {
                    continue;
                }
                if prev.origin_node != spec.origin_node || prev.topic != spec.topic {
                    tx.conn().execute(
                        "DELETE FROM batches WHERE subscription_id = ?1",
                        params![&spec.id],
                    )?;
                }
                tx.conn().execute(
                    "UPDATE subscriptions
                     SET origin_node = ?1, topic = ?2, filters_json = ?3, coalesce_seconds = ?4,
                         max_batch_age_ms = ?5, max_wakes_per_hour = ?6, mode = ?7, updated_at = ?8
                     WHERE id = ?9",
                    params![
                        &spec.origin_node,
                        &spec.topic,
                        &filters_json,
                        spec.coalesce_seconds,
                        spec.max_batch_age_ms,
                        spec.max_wakes_per_hour.map(|v| v as i64),
                        spec.mode.as_str(),
                        now_ms,
                        &spec.id
                    ],
                )?;
                recompute_open_batch_flush(
                    tx.conn(),
                    &spec.id,
                    spec.coalesce_seconds,
                    spec.max_batch_age_ms
                        .unwrap_or(self.limits().max_batch_age_ms),
                )?;
            } else {
                tx.conn().execute(
                    "INSERT INTO subscriptions
                     (id, origin_node, topic, subscriber, filters_json, coalesce_seconds,
                      max_batch_age_ms, max_wakes_per_hour, mode, created_at, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                    params![
                        &spec.id,
                        &spec.origin_node,
                        &spec.topic,
                        &spec.subscriber,
                        &filters_json,
                        spec.coalesce_seconds,
                        spec.max_batch_age_ms,
                        spec.max_wakes_per_hour.map(|v| v as i64),
                        spec.mode.as_str(),
                        now_ms,
                        now_ms
                    ],
                )?;
            }
        }

        let result = load_subscriptions_of(tx.conn(), subscriber)?;
        tx.commit()?;
        self.invalidate_cache();
        Ok(result)
    }

    /// Deletes a single subscription and all of its batches.
    pub fn delete_subscription(&self, id: &str) -> StoreResult<bool> {
        let tx = self.db.immediate_tx()?;
        tx.conn().execute(
            "DELETE FROM batches WHERE subscription_id = ?1",
            params![id],
        )?;
        let changed = tx
            .conn()
            .execute("DELETE FROM subscriptions WHERE id = ?1", params![id])?;
        let meta_key = format!("{SUBSCRIPTION_META_PREFIX}{id}");
        tx.conn()
            .execute("DELETE FROM metadata WHERE key = ?1", params![&meta_key])?;
        tx.commit()?;
        if changed > 0 {
            self.invalidate_cache();
        }
        Ok(changed > 0)
    }

    /// Atomically deletes a single subscription and its batches ONLY when owned by `subscriber`.
    ///
    /// Fails closed (returns `Ok(false)` and leaves the row untouched) if the subscription does
    /// not exist or belongs to a different subscriber.
    pub fn delete_subscription_for_subscriber(
        &self,
        id: &str,
        subscriber: &str,
    ) -> StoreResult<bool> {
        let tx = self.db.immediate_tx()?;
        let changed = tx.conn().execute(
            "DELETE FROM subscriptions WHERE id = ?1 AND subscriber = ?2",
            params![id, subscriber],
        )?;
        if changed > 0 {
            tx.conn().execute(
                "DELETE FROM batches WHERE subscription_id = ?1",
                params![id],
            )?;
            let meta_key = format!("{SUBSCRIPTION_META_PREFIX}{id}");
            tx.conn()
                .execute("DELETE FROM metadata WHERE key = ?1", params![&meta_key])?;
        }
        tx.commit()?;
        if changed > 0 {
            self.invalidate_cache();
        }
        Ok(changed > 0)
    }

    /// Deletes all subscriptions and batches owned by `subscriber`.
    pub fn remove_subscriber(&self, subscriber: &str) -> StoreResult<usize> {
        let tx = self.db.immediate_tx()?;
        tx.conn().execute(
            "DELETE FROM batches WHERE subscription_id IN (SELECT id FROM subscriptions WHERE subscriber = ?1)",
            params![subscriber],
        )?;
        tx.conn().execute(
            "DELETE FROM metadata WHERE key IN (SELECT ?1 || id FROM subscriptions WHERE subscriber = ?2)",
            params![SUBSCRIPTION_META_PREFIX, subscriber],
        )?;
        let changed = tx.conn().execute(
            "DELETE FROM subscriptions WHERE subscriber = ?1",
            params![subscriber],
        )?;
        tx.commit()?;
        if changed > 0 {
            self.invalidate_cache();
        }
        Ok(changed)
    }

    /// Persists optional local metadata (`key`, `urgency`) for `subscription_id` in the
    /// `metadata` table under `sub_meta:<subscription_id>`.
    pub fn set_subscription_meta(
        &self,
        subscription_id: &str,
        meta: &SubscriptionMeta,
    ) -> StoreResult<()> {
        if subscription_id.is_empty() {
            return Err(StoreError::InvalidInput(
                "subscription_id must be non-empty".to_string(),
            ));
        }
        let meta_key = format!("{SUBSCRIPTION_META_PREFIX}{subscription_id}");
        if meta.key.is_none() && meta.urgency.is_none() {
            self.db
                .conn()
                .execute("DELETE FROM metadata WHERE key = ?1", params![&meta_key])?;
            return Ok(());
        }
        let encoded = serde_json::to_string(meta)?;
        self.db.conn().execute(
            "INSERT INTO metadata (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![&meta_key, &encoded],
        )?;
        Ok(())
    }

    /// Loads persisted local metadata for `subscription_id`, if present.
    pub fn get_subscription_meta(
        &self,
        subscription_id: &str,
    ) -> StoreResult<Option<SubscriptionMeta>> {
        let meta_key = format!("{SUBSCRIPTION_META_PREFIX}{subscription_id}");
        let raw: Option<String> = self
            .db
            .conn()
            .query_row(
                "SELECT value FROM metadata WHERE key = ?1",
                params![&meta_key],
                |row| row.get(0),
            )
            .optional()?;
        Ok(raw.and_then(|s| serde_json::from_str::<SubscriptionMeta>(&s).ok()))
    }

    /// Lists all persisted subscription metadata records keyed by `subscription_id`.
    pub fn list_subscription_meta(&self) -> StoreResult<BTreeMap<String, SubscriptionMeta>> {
        let prefix_like = format!("{SUBSCRIPTION_META_PREFIX}%");
        let rows = query_vec(
            self.db.conn(),
            "SELECT key, value FROM metadata WHERE key LIKE ?1",
            params![&prefix_like],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )?;
        let mut out = BTreeMap::new();
        for (raw_key, raw_val) in rows {
            if let Some(sub_id) = raw_key.strip_prefix(SUBSCRIPTION_META_PREFIX) {
                if let Ok(meta) = serde_json::from_str::<SubscriptionMeta>(&raw_val) {
                    out.insert(sub_id.to_string(), meta);
                }
            }
        }
        Ok(out)
    }

    /// Finds an existing subscription owned by `subscriber` whose persisted metadata `key`
    /// equals `sub_key` (returning the oldest match deterministically if multiple exist).
    pub fn find_subscription_by_key(
        &self,
        subscriber: &str,
        sub_key: &str,
    ) -> StoreResult<Option<Subscription>> {
        if subscriber.is_empty() || sub_key.is_empty() {
            return Ok(None);
        }
        let subs = load_subscriptions_of(self.db.conn(), subscriber)?;
        for sub in subs {
            if let Some(meta) = self.get_subscription_meta(&sub.id)? {
                if meta.key.as_deref() == Some(sub_key) {
                    return Ok(Some(sub));
                }
            }
        }
        Ok(None)
    }

    /// Queries stored event counts, last-received timestamps, distinct sources, and observed
    /// GitHub repos from the `events` table for any of `origin_nodes`, normalizing topic names
    /// by stripping any leading `"local."` prefix so bare `<topic>` and `local.<topic>` fold
    /// together consistently.
    pub fn topic_event_stats(
        &self,
        origin_nodes: &[&str],
    ) -> StoreResult<BTreeMap<String, StoredTopicStats>> {
        const MAX_OBSERVED_VALUES: usize = 50;
        const MAX_RECENT_BODIES: i64 = 256;

        let mut origins: Vec<&str> = Vec::new();
        for &origin in origin_nodes {
            if !origin.is_empty() && !origins.contains(&origin) {
                origins.push(origin);
            }
        }
        if origins.is_empty() {
            return Ok(BTreeMap::new());
        }

        let placeholders = (1..=origins.len())
            .map(|i| format!("?{i}"))
            .collect::<Vec<_>>()
            .join(", ");
        let origin_params = rusqlite::params_from_iter(origins.iter().copied());

        // 1. Aggregate event counts & latest `received_at` per raw topic.
        let count_sql = format!(
            "SELECT topic, COUNT(*), MAX(received_at)
             FROM events
             WHERE origin_node IN ({placeholders})
             GROUP BY topic"
        );
        let mut count_stmt = self.db.conn().prepare(&count_sql)?;
        let count_rows = count_stmt
            .query_map(origin_params, |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;

        if count_rows.is_empty() {
            return Ok(BTreeMap::new());
        }

        let mut stats: BTreeMap<String, StoredTopicStats> = BTreeMap::new();
        for (raw_topic, count, last_ts) in count_rows {
            let norm_topic = raw_topic
                .strip_prefix("local.")
                .unwrap_or(raw_topic.as_str())
                .to_string();
            let entry = stats
                .entry(norm_topic.clone())
                .or_insert_with(|| StoredTopicStats {
                    topic: norm_topic,
                    ..StoredTopicStats::default()
                });
            entry.event_count = entry.event_count.saturating_add(count.max(0) as u64);
            if let Some(ts) = last_ts {
                entry.last_received_at = Some(match entry.last_received_at {
                    Some(prev) => prev.max(ts),
                    None => ts,
                });
            }
        }

        // 2. Collect distinct sources (and infer `owner/repo` from `github.com/<owner>/<repo>`
        //    sources even when `events.body` was cleared for unmatched events).
        let source_sql = format!(
            "SELECT DISTINCT topic, source
             FROM events
             WHERE origin_node IN ({placeholders})
             ORDER BY topic ASC, source ASC"
        );
        let mut source_stmt = self.db.conn().prepare(&source_sql)?;
        let source_rows = source_stmt
            .query_map(rusqlite::params_from_iter(origins.iter().copied()), |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;

        for (raw_topic, source) in source_rows {
            let norm_topic = raw_topic
                .strip_prefix("local.")
                .unwrap_or(raw_topic.as_str());
            let Some(entry) = stats.get_mut(norm_topic) else {
                continue;
            };
            let trimmed_src = source.trim();
            if !trimmed_src.is_empty()
                && entry.sources.len() < MAX_OBSERVED_VALUES
                && !entry.sources.iter().any(|s| s == trimmed_src)
            {
                entry.sources.push(trimmed_src.to_string());
            }
            if let Some(repo) = extract_github_repo_from_source(trimmed_src) {
                if entry.repos.len() < MAX_OBSERVED_VALUES
                    && !entry.repos.iter().any(|r| r.eq_ignore_ascii_case(&repo))
                {
                    entry.repos.push(repo);
                }
            }
        }

        // 3. Extract observed `repo` extension attributes from recent non-null event bodies.
        let body_sql = format!(
            "SELECT topic, body
             FROM events
             WHERE origin_node IN ({placeholders}) AND body IS NOT NULL
             ORDER BY seq DESC
             LIMIT {MAX_RECENT_BODIES}"
        );
        let mut body_stmt = self.db.conn().prepare(&body_sql)?;
        let body_rows = body_stmt
            .query_map(rusqlite::params_from_iter(origins.iter().copied()), |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;

        for (raw_topic, body) in body_rows {
            let norm_topic = raw_topic
                .strip_prefix("local.")
                .unwrap_or(raw_topic.as_str());
            let Some(entry) = stats.get_mut(norm_topic) else {
                continue;
            };
            if entry.repos.len() >= MAX_OBSERVED_VALUES {
                continue;
            }
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&body) {
                if let Some(repo) = val
                    .get("repo")
                    .and_then(serde_json::Value::as_str)
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                {
                    if !entry.repos.iter().any(|r| r.eq_ignore_ascii_case(repo)) {
                        entry.repos.push(repo.to_string());
                    }
                }
            }
        }

        Ok(stats)
    }

    /// Lists subscriptions, optionally filtered by `subscriber`.
    pub fn list_subscriptions(&self, subscriber: Option<&str>) -> StoreResult<Vec<Subscription>> {
        if let Some(sub) = subscriber {
            load_subscriptions_of(self.db.conn(), sub)
        } else {
            let rows = query_vec(
                self.db.conn(),
                "SELECT * FROM subscriptions ORDER BY created_at, id",
                [],
                decode_subscription_row,
            )?;
            rows.into_iter().collect()
        }
    }

    /// Gets a subscription by ID.
    pub fn get_subscription(&self, id: &str) -> StoreResult<Option<Subscription>> {
        load_subscription_by_id(self.db.conn(), id)
    }

    // ---- Idempotent Event Ingestion & Coalescing ----

    /// Idempotently ingests a CloudEvent keyed by `(origin_node, topic, publisher, source, event_id)`
    /// inside a single `BEGIN IMMEDIATE` transaction, matching all compiled subscriptions and
    /// creating/merging coalescing batches.
    pub fn ingest(
        &self,
        origin_node: &str,
        topic: &str,
        publisher: &str,
        event: &CloudEvent,
        now_ms: i64,
    ) -> StoreResult<IngestResult> {
        let tx = self.db.immediate_tx()?;
        let result = ingest_in_tx(self.db, &tx, origin_node, topic, publisher, event, now_ms)?;
        tx.commit()?;
        Ok(result)
    }

    /// Checks whether `(origin_node, topic, publisher, source, event_id)` is already recorded.
    pub fn is_known_event(
        &self,
        origin_node: &str,
        topic: &str,
        publisher: &str,
        source: &str,
        event_id: &str,
    ) -> StoreResult<bool> {
        let exists: Option<i64> = self
            .db
            .conn()
            .query_row(
                "SELECT seq FROM events
                 WHERE origin_node = ?1 AND topic = ?2 AND publisher = ?3 AND source = ?4 AND event_id = ?5",
                params![origin_node, topic, publisher, source, event_id],
                |row| row.get(0),
            )
            .optional()?;
        Ok(exists.is_some())
    }

    // ---- Batch Claim, Wake-Cap & Ack ----

    /// Returns the oldest due `pending` batch per subscription for `subscriber`, skipping any
    /// batch that is in flight, held (`hold_until > now_ms`), expired, or wake-capped for the
    /// rolling 1-hour window.
    pub fn due_batches<F>(
        &self,
        subscriber: &str,
        in_flight: F,
        now_ms: i64,
    ) -> StoreResult<Vec<DueBatch>>
    where
        F: Fn(&str) -> bool,
    {
        let subs = load_subscriptions_of(self.db.conn(), subscriber)?;
        let limits = self.limits();
        let mut out = Vec::new();
        for sub in subs {
            let batch: Option<BatchRecord> = query_opt(
                self.db.conn(),
                "SELECT * FROM batches
                     WHERE subscription_id = ?1 AND state = 'pending'
                     ORDER BY closed_at ASC, rowid ASC
                     LIMIT 1",
                params![&sub.id],
                decode_batch_row,
            )?;
            let Some(batch) = batch else {
                continue;
            };
            if in_flight(&batch.id)
                || batch.hold_until > now_ms
                || now_ms - batch.opened_at >= limits.retention_ms
            {
                continue;
            }
            let cap = sub
                .max_wakes_per_hour
                .unwrap_or(limits.max_wakes_per_hour_per_subscription);
            let delivered_last_hour: i64 = self.db.conn().query_row(
                "SELECT COUNT(*) FROM batches
                 WHERE subscription_id = ?1 AND state = 'delivered' AND settled_at > ?2",
                params![&sub.id, now_ms - HOUR_MS],
                |row| row.get(0),
            )?;
            if delivered_last_hour as usize >= cap {
                continue;
            }
            let events = load_batch_events(self.db.conn(), &batch.id)?;
            out.push(DueBatch {
                id: batch.id,
                subscription_id: batch.subscription_id,
                origin_node: batch.origin_node,
                subscriber: batch.subscriber,
                topic: batch.topic,
                mode: sub.mode,
                events,
                opened_at: batch.opened_at,
                closed_at: batch.closed_at.unwrap_or(batch.last_event_at),
            });
        }
        Ok(out)
    }

    /// Convenience wrapper over [`EventStore::due_batches`] with no in-flight filter.
    pub fn claim_due_batches(&self, subscriber: &str, now_ms: i64) -> StoreResult<Vec<DueBatch>> {
        self.due_batches(subscriber, |_| false, now_ms)
    }

    /// If `subscription_id` is currently blocked by its hourly wake cap, returns the exact epoch
    /// millisecond timestamp when the oldest counted wake rolls out of the 1-hour window.
    pub fn wake_cap_unblock_at(
        &self,
        subscription_id: &str,
        now_ms: i64,
    ) -> StoreResult<Option<i64>> {
        let cap_opt: Option<Option<i64>> = self
            .db
            .conn()
            .query_row(
                "SELECT max_wakes_per_hour FROM subscriptions WHERE id = ?1",
                params![subscription_id],
                |row| row.get(0),
            )
            .optional()?;
        let cap = cap_opt
            .flatten()
            .map(|v| v as usize)
            .unwrap_or(self.limits().max_wakes_per_hour_per_subscription);
        if cap == 0 {
            return Ok(None);
        }
        let settled_at: Option<i64> = self
            .db
            .conn()
            .query_row(
                "SELECT settled_at FROM batches
                 WHERE subscription_id = ?1 AND state = 'delivered' AND settled_at > ?2
                 ORDER BY settled_at DESC
                 LIMIT 1 OFFSET ?3",
                params![subscription_id, now_ms - HOUR_MS, (cap - 1) as i64],
                |row| row.get(0),
            )
            .optional()?;
        Ok(settled_at.map(|ts| ts + HOUR_MS))
    }

    /// Acknowledges a pending batch (`delivered`, `hold`, or `rejected`) for its subscriber.
    pub fn ack_batch(
        &self,
        subscriber: &str,
        batch_id: &str,
        outcome: &AckOutcome,
        now_ms: i64,
    ) -> StoreResult<bool> {
        let tx = self.db.immediate_tx()?;
        let batch: Option<BatchRecord> = query_opt(
            tx.conn(),
            "SELECT * FROM batches WHERE id = ?1 AND state = 'pending'",
            params![batch_id],
            decode_batch_row,
        )?;
        let Some(batch) = batch else {
            return Ok(false);
        };
        if batch.subscriber != subscriber {
            return Ok(false);
        }
        match outcome {
            AckOutcome::Delivered => {
                tx.conn().execute(
                    "UPDATE batches SET state = 'delivered', settled_at = ?1 WHERE id = ?2",
                    params![now_ms, batch_id],
                )?;
            }
            AckOutcome::Rejected { reason } => {
                tx.conn().execute(
                    "UPDATE batches SET state = 'rejected', reason = ?1, settled_at = ?2 WHERE id = ?3",
                    params![reason, now_ms, batch_id],
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
                    "UPDATE batches SET reason = ?1, hold_until = ?2 WHERE id = ?3",
                    params![reason, now_ms + delay, batch_id],
                )?;
            }
        }
        tx.commit()?;
        Ok(true)
    }

    /// Lists all batches for a subscription ordered by creation time.
    pub fn list_batches(&self, subscription_id: &str) -> StoreResult<Vec<BatchRecord>> {
        let rows = query_vec(
            self.db.conn(),
            "SELECT * FROM batches WHERE subscription_id = ?1 ORDER BY opened_at ASC, rowid ASC",
            params![subscription_id],
            decode_batch_row,
        )?;
        rows.into_iter().collect()
    }

    // ---- Upstream Pushdowns ----

    /// Inserts or updates a compiled upstream pushdown record for `(peer_id, topic, shard_index)`.
    pub fn upsert_upstream_pushdown(
        &self,
        input: &UpstreamPushdownInput,
        now_ms: i64,
    ) -> StoreResult<UpstreamPushdown> {
        if !is_node_id(&input.peer_id) {
            return Err(StoreError::InvalidInput(format!(
                "invalid peer_id '{}'",
                input.peer_id
            )));
        }
        if !is_topic(&input.topic) {
            return Err(StoreError::InvalidInput(format!(
                "invalid topic '{}'",
                input.topic
            )));
        }
        parse_and_check_filters(&input.filters_json)?;
        let digest = sha256_hex(
            format!(
                "{}\0{}\0{}\0{}\0{}",
                input.peer_id,
                input.topic,
                input.shard_index,
                input.filters_json,
                input.coalesce_seconds
            )
            .as_bytes(),
        );
        let tx = self.db.immediate_tx()?;
        tx.conn().execute(
            "INSERT INTO upstream_pushdowns
             (id, peer_id, topic, shard_index, filters_json, coalesce_seconds, local_sub_count, digest, synced_at, last_error, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL, NULL, ?9)
             ON CONFLICT(peer_id, topic, shard_index) DO UPDATE SET
               id = excluded.id,
               filters_json = excluded.filters_json,
               coalesce_seconds = excluded.coalesce_seconds,
               local_sub_count = excluded.local_sub_count,
               digest = excluded.digest,
               synced_at = CASE WHEN upstream_pushdowns.digest = excluded.digest THEN upstream_pushdowns.synced_at ELSE NULL END,
               last_error = CASE WHEN upstream_pushdowns.digest = excluded.digest THEN upstream_pushdowns.last_error ELSE NULL END,
               updated_at = excluded.updated_at",
            params![
                &input.id,
                &input.peer_id,
                &input.topic,
                input.shard_index,
                &input.filters_json,
                input.coalesce_seconds,
                input.local_sub_count as i64,
                &digest,
                now_ms
            ],
        )?;
        let row = tx.conn().query_row(
            "SELECT * FROM upstream_pushdowns WHERE peer_id = ?1 AND topic = ?2 AND shard_index = ?3",
            params![&input.peer_id, &input.topic, input.shard_index],
            decode_pushdown_row,
        )?;
        tx.commit()?;
        Ok(row)
    }

    /// Marks an upstream pushdown as synced at `now_ms` and clears `last_error`.
    pub fn mark_pushdown_synced(&self, id: &str, now_ms: i64) -> StoreResult<bool> {
        let changed = self.db.conn().execute(
            "UPDATE upstream_pushdowns SET synced_at = ?1, last_error = NULL, updated_at = ?1 WHERE id = ?2",
            params![now_ms, id],
        )?;
        Ok(changed > 0)
    }

    /// Records the last sync error for an upstream pushdown.
    pub fn mark_pushdown_error(&self, id: &str, error: &str, now_ms: i64) -> StoreResult<bool> {
        let changed = self.db.conn().execute(
            "UPDATE upstream_pushdowns SET last_error = ?1, updated_at = ?2 WHERE id = ?3",
            params![error, now_ms, id],
        )?;
        Ok(changed > 0)
    }

    /// Lists upstream pushdown records, optionally filtered by `peer_id`.
    pub fn list_upstream_pushdowns(
        &self,
        peer_id: Option<&str>,
    ) -> StoreResult<Vec<UpstreamPushdown>> {
        if let Some(peer) = peer_id {
            query_vec(
                self.db.conn(),
                "SELECT * FROM upstream_pushdowns WHERE peer_id = ?1 ORDER BY topic, shard_index",
                params![peer],
                decode_pushdown_row,
            )
        } else {
            query_vec(
                self.db.conn(),
                "SELECT * FROM upstream_pushdowns ORDER BY peer_id, topic, shard_index",
                [],
                decode_pushdown_row,
            )
        }
    }

    /// Deletes an upstream pushdown record by ID.
    pub fn delete_upstream_pushdown(&self, id: &str) -> StoreResult<bool> {
        let changed = self
            .db
            .conn()
            .execute("DELETE FROM upstream_pushdowns WHERE id = ?1", params![id])?;
        Ok(changed > 0)
    }

    // ---- Housekeeping & Exact Deadline Scheduler ----

    /// Closes due open batches, drops expired pending batches, and prunes settled batches &
    /// old events past their 24h body / 7d idempotency TTLs.
    pub fn tick(&self, now_ms: i64) -> StoreResult<EventTickReport> {
        let limits = self.limits().clone();
        let should_prune = {
            let guard = self
                .db
                .event_cache
                .lock()
                .expect("event_cache mutex poisoned");
            guard
                .last_prune_ms
                .is_none_or(|last| now_ms - last >= limits.prune_interval_ms)
        };

        // Read-only quick check so we avoid acquiring a write lock when idle.
        let has_due_open: bool = self.db.conn().query_row(
            "SELECT EXISTS(SELECT 1 FROM batches WHERE state = 'open' AND flush_at <= ?1)",
            params![now_ms],
            |row| row.get(0),
        )?;
        let has_expired_pending: bool = self.db.conn().query_row(
            "SELECT EXISTS(SELECT 1 FROM batches WHERE state = 'pending' AND opened_at <= ?1)",
            params![now_ms - limits.retention_ms],
            |row| row.get(0),
        )?;

        if !should_prune && !has_due_open && !has_expired_pending {
            return Ok(EventTickReport::default());
        }

        let mut report = EventTickReport::default();
        let tx = self.db.immediate_tx()?;

        if has_due_open {
            let open_due = query_vec(tx.conn(), "SELECT * FROM batches WHERE state = 'open' AND flush_at <= ?1 ORDER BY flush_at ASC, rowid ASC", params![now_ms], decode_batch_row)?
                .into_iter()
                .collect::<StoreResult<Vec<_>>>()?;
            for batch in open_due {
                close_batch_in_tx(tx.conn(), &batch, &limits, now_ms)?;
                report.batches_closed += 1;
            }
        }

        if has_expired_pending {
            let expired = tx.conn().execute(
                "UPDATE batches SET state = 'dropped', reason = 'expired', settled_at = ?1
                 WHERE state = 'pending' AND opened_at <= ?2",
                params![now_ms, now_ms - limits.retention_ms],
            )?;
            report.batches_expired = expired;
        }

        if should_prune {
            let cutoff = now_ms - limits.retention_ms;
            report.batches_pruned = tx.conn().execute(
                "DELETE FROM batches
                 WHERE state IN ('delivered', 'rejected', 'dropped') AND settled_at <= ?1",
                params![cutoff],
            )?;
            report.event_bodies_cleared = tx.conn().execute(
                "UPDATE events SET body = NULL
                 WHERE body IS NOT NULL AND received_at <= ?1 AND NOT EXISTS (
                     SELECT 1 FROM batch_events be
                     JOIN batches b ON b.id = be.batch_id
                     WHERE be.event_seq = events.seq AND b.state IN ('open', 'pending')
                 )",
                params![cutoff],
            )?;
            report.events_pruned = tx.conn().execute(
                "DELETE FROM events
                 WHERE received_at <= ?1 AND NOT EXISTS (
                     SELECT 1 FROM batch_events be WHERE be.event_seq = events.seq
                 )",
                params![now_ms - limits.idempotency_ms],
            )?;
        }

        tx.commit()?;
        if should_prune {
            let mut guard = self
                .db
                .event_cache
                .lock()
                .expect("event_cache mutex poisoned");
            guard.last_prune_ms = Some(now_ms);
        }
        Ok(report)
    }

    /// Computes the exact earliest wake timestamp (epoch ms) when `tick()` or `due_batches()` has
    /// real work to do, returning `None` when completely idle.
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

        // 1. Earliest due flush time of any open batch.
        let open_flush: Option<i64> = conn.query_row(
            "SELECT MIN(flush_at) FROM batches WHERE state = 'open'",
            [],
            |row| row.get(0),
        )?;
        consider(open_flush);

        // 2. Earliest expiry of any pending batch.
        let oldest_pending: Option<i64> = conn.query_row(
            "SELECT MIN(opened_at) FROM batches WHERE state = 'pending'",
            [],
            |row| row.get(0),
        )?;
        if let Some(opened_at) = oldest_pending {
            consider(Some(opened_at + limits.retention_ms));
        }

        // 3. Earliest hold_until (> now_ms) of any pending batch.
        let next_hold: Option<i64> = conn.query_row(
            "SELECT MIN(hold_until) FROM batches WHERE state = 'pending' AND hold_until > ?1",
            params![now_ms],
            |row| row.get(0),
        )?;
        consider(next_hold);

        // 4. Earliest wake-cap unblock time for any subscription with a pending batch at/over cap.
        if oldest_pending.is_some() {
            let pending_subs: Vec<(String, Option<i64>)> = query_vec(
                conn,
                "SELECT DISTINCT b.subscription_id, s.max_wakes_per_hour
                 FROM batches b
                 LEFT JOIN subscriptions s ON s.id = b.subscription_id
                 WHERE b.state = 'pending'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            let mut wake_stmt = conn.prepare(
                "SELECT settled_at FROM batches
                 WHERE subscription_id = ?1 AND state = 'delivered' AND settled_at > ?2
                 ORDER BY settled_at DESC
                 LIMIT 1 OFFSET ?3",
            )?;
            for (sub_id, override_cap) in pending_subs {
                let cap = override_cap
                    .map(|v| v as usize)
                    .unwrap_or(limits.max_wakes_per_hour_per_subscription);
                if cap == 0 {
                    continue;
                }
                let ts: Option<i64> = wake_stmt
                    .query_row(params![sub_id, now_ms - HOUR_MS, (cap - 1) as i64], |row| {
                        row.get(0)
                    })
                    .optional()?;
                if let Some(settled_at) = ts {
                    consider(Some(settled_at + HOUR_MS));
                }
            }
        }

        // 5. Earliest retention prune time ONLY when settled batches or prunable events exist.
        let mut prune_target: Option<i64> = None;
        let mut consider_prune = |ts: Option<i64>| {
            if let Some(t) = ts {
                prune_target = Some(match prune_target {
                    Some(prev) => prev.min(t),
                    None => t,
                });
            }
        };

        let oldest_settled: Option<i64> = conn.query_row(
            "SELECT MIN(settled_at) FROM batches
             WHERE state IN ('delivered', 'rejected', 'dropped') AND settled_at IS NOT NULL",
            [],
            |row| row.get(0),
        )?;
        consider_prune(oldest_settled.map(|t| t + limits.retention_ms));

        let oldest_body: Option<i64> = conn.query_row(
            "SELECT MIN(received_at) FROM events
             WHERE body IS NOT NULL AND NOT EXISTS (
                 SELECT 1 FROM batch_events be
                 JOIN batches b ON b.id = be.batch_id
                 WHERE be.event_seq = events.seq AND b.state IN ('open', 'pending')
             )",
            [],
            |row| row.get(0),
        )?;
        consider_prune(oldest_body.map(|t| t + limits.retention_ms));

        let oldest_unreferenced: Option<i64> = conn.query_row(
            "SELECT MIN(received_at) FROM events
             WHERE NOT EXISTS (SELECT 1 FROM batch_events be WHERE be.event_seq = events.seq)",
            [],
            |row| row.get(0),
        )?;
        consider_prune(oldest_unreferenced.map(|t| t + limits.idempotency_ms));

        if let Some(target) = prune_target {
            let last_prune = self
                .db
                .event_cache
                .lock()
                .expect("event_cache mutex poisoned")
                .last_prune_ms;
            let next_prune = match last_prune {
                Some(last) => target.max(last + limits.prune_interval_ms),
                None => target,
            };
            consider(Some(next_prune));
        }

        Ok(earliest)
    }
}

/// Core event ingestion implementation operating inside an already-open `BEGIN IMMEDIATE`
/// transaction so both `EventStore::ingest` and `KvStore::set`/`delete` share identical
/// atomic idempotency, filter matching, and batch coalescing.
pub(crate) fn ingest_in_tx(
    db: &NodeDb,
    tx: &ImmediateTx<'_>,
    origin_node: &str,
    topic: &str,
    publisher: &str,
    event: &CloudEvent,
    now_ms: i64,
) -> StoreResult<IngestResult> {
    if !is_node_id(origin_node) {
        return Err(StoreError::InvalidInput(format!(
            "invalid origin_node '{origin_node}'"
        )));
    }
    if !is_topic(topic) {
        return Err(StoreError::InvalidInput(format!("invalid topic '{topic}'")));
    }
    if publisher.is_empty() {
        return Err(StoreError::InvalidInput(
            "publisher must be non-empty".to_string(),
        ));
    }
    let bytes = event.validate()?;
    let digest = event.digest();
    let conn = tx.conn();

    // Idempotency check inside the write transaction (eliminates TOCTOU duplicate races).
    let existing: Option<(i64, String, i64)> = conn
        .query_row(
            "SELECT seq, digest, matched FROM events
             WHERE origin_node = ?1 AND topic = ?2 AND publisher = ?3 AND source = ?4 AND event_id = ?5",
            params![origin_node, topic, publisher, &event.source, &event.id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    if let Some((seq, orig_digest, orig_matched)) = existing {
        if orig_digest != digest {
            return Err(StoreError::IdConflict(format!(
                "event '{}' from '{}' on '{origin_node}.{topic}' was already ingested with different content",
                event.id, event.source
            )));
        }
        return Ok(IngestResult {
            seq,
            deduplicated: true,
            matched: orig_matched as usize,
            batches_created: 0,
            batches_merged: 0,
        });
    }

    let body_json = serde_json::to_string(event)?;
    let seq: i64 = conn.query_row(
        "INSERT INTO events
         (origin_node, topic, publisher, source, event_id, digest, body, bytes, matched, received_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0, ?9)
         RETURNING seq",
        params![
            origin_node,
            topic,
            publisher,
            &event.source,
            &event.id,
            &digest,
            &body_json,
            bytes as i64,
            now_ms
        ],
        |row| row.get(0),
    )?;

    let subs = compiled_subscriptions_for(db, conn, origin_node, topic)?;
    let limits = &db.config().event_limits;
    let mut matched = 0usize;
    let mut batches_created = 0usize;
    let mut batches_merged = 0usize;

    for sub in &subs {
        if !matches_filters(&sub.filters, event) {
            continue;
        }
        matched += 1;
        let created = append_to_batch_in_tx(conn, sub, seq, limits, now_ms)?;
        if created {
            batches_created += 1;
        } else {
            batches_merged += 1;
        }
    }

    conn.execute(
        "UPDATE events SET matched = ?1, body = CASE WHEN ?1 = 0 THEN NULL ELSE body END WHERE seq = ?2",
        params![matched as i64, seq],
    )?;

    Ok(IngestResult {
        seq,
        deduplicated: false,
        matched,
        batches_created,
        batches_merged,
    })
}

/// Fetches compiled subscriptions for `(origin_node, topic)` using a local cache automatically
/// invalidated whenever `PRAGMA data_version` changes (multi-connection / multi-process coherence).
fn compiled_subscriptions_for(
    db: &NodeDb,
    conn: &Connection,
    origin_node: &str,
    topic: &str,
) -> StoreResult<Vec<CompiledSubscription>> {
    let data_version: i64 = conn.query_row("PRAGMA data_version", [], |row| row.get(0))?;
    let key = (origin_node.to_string(), topic.to_string());
    {
        let mut cache = db.event_cache.lock().expect("event_cache mutex poisoned");
        if cache.data_version != Some(data_version) {
            if cache.data_version.is_some() {
                cache.invalidations += 1;
            }
            cache.by_topic.clear();
            cache.data_version = Some(data_version);
        }
        if let Some(hit) = cache.by_topic.get(&key).cloned() {
            cache.hits += 1;
            return Ok(hit);
        }
        cache.misses += 1;
    }

    let rows = query_vec(
        conn,
        "SELECT * FROM subscriptions
         WHERE origin_node = ?1 AND topic = ?2
         ORDER BY created_at ASC, id ASC",
        params![origin_node, topic],
        decode_subscription_row,
    )?;
    let mut compiled = Vec::with_capacity(rows.len());
    for sub in rows.into_iter().flatten() {
        compiled.push(CompiledSubscription {
            id: sub.id,
            origin_node: sub.origin_node,
            topic: sub.topic,
            subscriber: sub.subscriber,
            filters: sub.filters,
            coalesce_seconds: sub.coalesce_seconds,
            max_batch_age_ms: sub.max_batch_age_ms,
        });
    }

    {
        let mut cache = db.event_cache.lock().expect("event_cache mutex poisoned");
        cache.data_version = Some(data_version);
        cache.by_topic.insert(key, compiled.clone());
    }
    Ok(compiled)
}

/// Appends `event_seq` to `sub`'s open batch (creating one if needed or if the existing open
/// batch's `flush_at` has already passed). Returns `true` if a new batch was created.
fn append_to_batch_in_tx(
    conn: &Connection,
    sub: &CompiledSubscription,
    event_seq: i64,
    limits: &EventLimits,
    now_ms: i64,
) -> StoreResult<bool> {
    let max_age_ms = sub.max_batch_age_ms.unwrap_or(limits.max_batch_age_ms);
    let coalesce_ms = sub.coalesce_seconds * 1000;

    let mut open: Option<BatchRecord> = query_opt(
        conn,
        "SELECT * FROM batches WHERE subscription_id = ?1 AND state = 'open' LIMIT 1",
        params![&sub.id],
        decode_batch_row,
    )?;

    if let Some(batch) = &open {
        let is_due = now_ms >= batch.flush_at
            || now_ms - batch.last_event_at >= coalesce_ms
            || now_ms - batch.opened_at >= max_age_ms;
        if is_due {
            close_batch_in_tx(conn, batch, limits, now_ms)?;
            open = None;
        }
    }

    let (mut batch, created) = if let Some(b) = open {
        (b, false)
    } else {
        let id = uuid_v4();
        let flush_at = (now_ms + coalesce_ms).min(now_ms + max_age_ms);
        conn.execute(
            "INSERT INTO batches
             (id, subscription_id, origin_node, subscriber, topic, state, event_count,
              opened_at, last_event_at, flush_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 'open', 0, ?6, ?6, ?7)",
            params![
                &id,
                &sub.id,
                &sub.origin_node,
                &sub.subscriber,
                &sub.topic,
                now_ms,
                flush_at
            ],
        )?;
        let fresh = BatchRecord {
            id,
            subscription_id: sub.id.clone(),
            origin_node: sub.origin_node.clone(),
            subscriber: sub.subscriber.clone(),
            topic: sub.topic.clone(),
            state: BatchState::Open,
            event_count: 0,
            opened_at: now_ms,
            last_event_at: now_ms,
            flush_at,
            closed_at: None,
            hold_until: 0,
            reason: None,
            settled_at: None,
        };
        (fresh, true)
    };

    let position = batch.event_count as i64;
    conn.execute(
        "INSERT INTO batch_events (batch_id, position, event_seq) VALUES (?1, ?2, ?3)",
        params![&batch.id, position, event_seq],
    )?;

    batch.event_count += 1;
    batch.last_event_at = now_ms;
    batch.flush_at = (now_ms + coalesce_ms).min(batch.opened_at + max_age_ms);

    conn.execute(
        "UPDATE batches SET event_count = ?1, last_event_at = ?2, flush_at = ?3 WHERE id = ?4",
        params![batch.event_count as i64, now_ms, batch.flush_at, &batch.id],
    )?;

    if batch.event_count >= limits.max_batch_events || sub.coalesce_seconds == 0 {
        close_batch_in_tx(conn, &batch, limits, now_ms)?;
    }

    Ok(created)
}

fn close_batch_in_tx(
    conn: &Connection,
    batch: &BatchRecord,
    limits: &EventLimits,
    now_ms: i64,
) -> StoreResult<()> {
    conn.execute(
        "UPDATE batches SET state = 'pending', closed_at = ?1 WHERE id = ?2 AND state = 'open'",
        params![now_ms, &batch.id],
    )?;

    // Enforce per-subscription pending batch cap by dropping oldest pending batches.
    let pending_ids: Vec<String> = query_vec(
        conn,
        "SELECT id FROM batches
         WHERE subscription_id = ?1 AND state = 'pending'
         ORDER BY closed_at ASC, rowid ASC",
        params![&batch.subscription_id],
        |row| row.get(0),
    )?;

    let excess = pending_ids
        .len()
        .saturating_sub(limits.max_pending_batches_per_subscription);
    for dropped_id in pending_ids.into_iter().take(excess) {
        conn.execute(
            "UPDATE batches SET state = 'dropped', reason = 'queue_full', settled_at = ?1 WHERE id = ?2",
            params![now_ms, dropped_id],
        )?;
    }
    Ok(())
}

fn recompute_open_batch_flush(
    conn: &Connection,
    subscription_id: &str,
    coalesce_seconds: i64,
    max_batch_age_ms: i64,
) -> StoreResult<()> {
    let coalesce_ms = coalesce_seconds * 1000;
    conn.execute(
        "UPDATE batches
         SET flush_at = MIN(last_event_at + ?1, opened_at + ?2)
         WHERE subscription_id = ?3 AND state = 'open'",
        params![coalesce_ms, max_batch_age_ms, subscription_id],
    )?;
    Ok(())
}

fn load_subscription_by_id(conn: &Connection, id: &str) -> StoreResult<Option<Subscription>> {
    query_opt(
        conn,
        "SELECT * FROM subscriptions WHERE id = ?1",
        params![id],
        decode_subscription_row,
    )
}

fn load_subscriptions_of(conn: &Connection, subscriber: &str) -> StoreResult<Vec<Subscription>> {
    let rows = query_vec(
        conn,
        "SELECT * FROM subscriptions WHERE subscriber = ?1 ORDER BY created_at ASC, id ASC",
        params![subscriber],
        decode_subscription_row,
    )?;
    rows.into_iter().collect()
}

fn load_batch_events(conn: &Connection, batch_id: &str) -> StoreResult<Vec<CloudEvent>> {
    let bodies: Vec<Option<String>> = query_vec(
        conn,
        "SELECT e.body FROM batch_events be
         JOIN events e ON e.seq = be.event_seq
         WHERE be.batch_id = ?1
         ORDER BY be.position ASC",
        params![batch_id],
        |row| row.get(0),
    )?;
    let mut out = Vec::with_capacity(bodies.len());
    for body in bodies.into_iter().flatten() {
        let ev: CloudEvent = serde_json::from_str(&body)?;
        out.push(ev);
    }
    Ok(out)
}

fn decode_subscription_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoreResult<Subscription>> {
    let id: String = row.get("id")?;
    let origin_node: String = row.get("origin_node")?;
    let topic: String = row.get("topic")?;
    let subscriber: String = row.get("subscriber")?;
    let filters_json: String = row.get("filters_json")?;
    let coalesce_seconds: i64 = row.get("coalesce_seconds")?;
    let max_batch_age_ms: Option<i64> = row.get("max_batch_age_ms")?;
    let max_wakes_per_hour: Option<i64> = row.get("max_wakes_per_hour")?;
    let mode_str: String = row.get("mode")?;
    let created_at: i64 = row.get("created_at")?;
    let updated_at: i64 = row.get("updated_at")?;

    Ok((|| {
        let filters = parse_and_check_filters(&filters_json)?;
        let mode = DeliveryMode::parse(&mode_str)?;
        Ok(Subscription {
            id,
            origin_node,
            topic,
            subscriber,
            filters,
            filters_json,
            coalesce_seconds,
            max_batch_age_ms,
            max_wakes_per_hour: max_wakes_per_hour.map(|v| v as usize),
            mode,
            created_at,
            updated_at,
        })
    })())
}

fn decode_batch_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoreResult<BatchRecord>> {
    let id: String = row.get("id")?;
    let subscription_id: String = row.get("subscription_id")?;
    let origin_node: String = row.get("origin_node")?;
    let subscriber: String = row.get("subscriber")?;
    let topic: String = row.get("topic")?;
    let state_str: String = row.get("state")?;
    let event_count: i64 = row.get("event_count")?;
    let opened_at: i64 = row.get("opened_at")?;
    let last_event_at: i64 = row.get("last_event_at")?;
    let flush_at: i64 = row.get("flush_at")?;
    let closed_at: Option<i64> = row.get("closed_at")?;
    let hold_until: i64 = row.get("hold_until")?;
    let reason: Option<String> = row.get("reason")?;
    let settled_at: Option<i64> = row.get("settled_at")?;

    Ok(BatchState::parse(&state_str).map(|state| BatchRecord {
        id,
        subscription_id,
        origin_node,
        subscriber,
        topic,
        state,
        event_count: event_count.max(0) as usize,
        opened_at,
        last_event_at,
        flush_at,
        closed_at,
        hold_until,
        reason,
        settled_at,
    }))
}

fn extract_github_repo_from_source(source: &str) -> Option<String> {
    let lower = source.to_ascii_lowercase();
    let rest = if lower.starts_with("https://github.com/") {
        &source["https://github.com/".len()..]
    } else if lower.starts_with("http://github.com/") {
        &source["http://github.com/".len()..]
    } else if lower.starts_with("github.com/") {
        &source["github.com/".len()..]
    } else {
        return None;
    };
    let mut parts = rest.trim_matches('/').split('/');
    let owner = parts.next()?.trim();
    let repo = parts.next()?.trim();
    if owner.is_empty() || repo.is_empty() {
        return None;
    }
    Some(format!("{owner}/{repo}"))
}

fn decode_pushdown_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<UpstreamPushdown> {
    Ok(UpstreamPushdown {
        id: row.get("id")?,
        peer_id: row.get("peer_id")?,
        topic: row.get("topic")?,
        shard_index: row.get("shard_index")?,
        filters_json: row.get("filters_json")?,
        coalesce_seconds: row.get("coalesce_seconds")?,
        local_sub_count: row.get::<_, i64>("local_sub_count")?.max(0) as usize,
        digest: row.get("digest")?,
        synced_at: row.get("synced_at")?,
        last_error: row.get("last_error")?,
        updated_at: row.get("updated_at")?,
    })
}
