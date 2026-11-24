//! McKeeman Reference-Model Differential Test (`AGENTS.md`):
//!
//! Feeds identical seeded 500-step stateful operation sequences (Shared KV CAS races + atomic
//! CloudEvent emission, handle/channel join/leave/post with zero ciphertext mutation + stale
//! handle pruning, CloudEvents idempotency + coalescing + hourly wake caps, Security Gate
//! quarantine/approve/reject + mutes + muted mailbox archival/transitions, `bridge_links`,
//! `plugin_targets` handoffs, and cascading `prune_sessions` cleanup) to BOTH:
//!   1. A tiny pure in-memory Rust specification oracle (`MemoryOracle`), and
//!   2. Real file-backed SQLite WAL `NodeDb`.
//!
//! Asserts identical outcomes and full observable post-state after EVERY step.
//! Honors `HYPHAE_TEST_SEED` (hex `0x...` or decimal u64) and logs `seed=0x... step=...` on failure.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use hyp_store::{
    AckOutcome, BatchState, BridgeLink, CloudEvent, DeliveryMode, EventLimits, Filter,
    GateDecision, GateDirection, GateState, KvDeleteInput, KvSetInput, MailboxEntry, MailboxInsert,
    MailboxKind, MailboxPutResult, MessageLimits, MuteRuleInput, NodeDb, PluginTargetHandoff,
    PostChannelInput, StoreConfig, StoreError, SubscriptionSpec, WriteModel, matches_filters,
};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde_json::json;
use tempfile::TempDir;

const HOUR_MS: i64 = 60 * 60 * 1000;
const META_MUTED_INDEX_PREFIX: &str = "delivery:muted:";
const MAX_ARCHIVE_RECEIPTS: usize = 500;
const MAILBOX_MAX_PENDING: usize = 100;

fn resolve_seed(default: u64) -> u64 {
    match std::env::var("HYPHAE_TEST_SEED") {
        Ok(raw) => {
            let trimmed = raw.trim();
            if let Some(hex) = trimmed
                .strip_prefix("0x")
                .or_else(|| trimmed.strip_prefix("0X"))
            {
                u64::from_str_radix(hex, 16)
                    .unwrap_or_else(|e| panic!("invalid hex HYPHAE_TEST_SEED={raw:?}: {e}"))
            } else {
                trimmed
                    .parse::<u64>()
                    .unwrap_or_else(|e| panic!("invalid decimal HYPHAE_TEST_SEED={raw:?}: {e}"))
            }
        }
        Err(_) => default,
    }
}

// =========================================================================
// Muted Mailbox Helpers (matching `hyp-node/src/delivery/inbox_query.rs`)
// =========================================================================

fn load_muted_index(db: &NodeDb, session_id: &str) -> Vec<String> {
    let key = format!("{META_MUTED_INDEX_PREFIX}{session_id}");
    match db.local().get_metadata(&key).unwrap() {
        Some(raw) => serde_json::from_str(&raw).unwrap_or_default(),
        None => Vec::new(),
    }
}

fn append_muted_index(db: &NodeDb, session_id: &str, receipt: &str) {
    let mut list = load_muted_index(db, session_id);
    if !list.iter().any(|r| r == receipt) {
        list.push(receipt.to_string());
    }
    if list.len() > MAX_ARCHIVE_RECEIPTS {
        let excess = list.len() - MAX_ARCHIVE_RECEIPTS;
        list.drain(0..excess);
    }
    let key = format!("{META_MUTED_INDEX_PREFIX}{session_id}");
    db.local()
        .set_metadata(&key, &serde_json::to_string(&list).unwrap())
        .unwrap();
}

/// Archives a newly arrived muted item directly into `NodeDb` `mailbox` with
/// `gate_state = Delivered, gate_reason = Some("muted")`, matching `archive_muted_entry`.
fn archive_muted_in_store(db: &NodeDb, insert: &MailboxInsert, now_ms: i64) -> MailboxPutResult {
    let muted_insert = MailboxInsert {
        gate_state: GateState::Delivered,
        gate_reason: Some("muted".to_string()),
        ..insert.clone()
    };
    let res = db.local().put_in_mailbox(&muted_insert, now_ms).unwrap();
    if let MailboxPutResult::Stored { ref receipt } = res {
        db.local()
            .record_delivery(&insert.origin_node, &insert.item_id, "muted", now_ms)
            .unwrap();
        append_muted_index(db, &insert.session_id, receipt);
    }
    res
}

/// Moves an already-pending mailbox item into the silent `muted` archive.
fn move_pending_to_muted_in_store(db: &NodeDb, session_id: &str, entry: &MailboxEntry, now_ms: i64) {
    let acked = db
        .local()
        .acknowledge_inbox(session_id, &[entry.receipt.as_str()], now_ms)
        .unwrap();
    assert_eq!(acked, 1);
    db.local()
        .record_delivery(&entry.origin_node, &entry.item_id, "muted", now_ms)
        .unwrap();
    append_muted_index(db, session_id, &entry.receipt);
}

/// Queries durably archived `muted` items for `session_id` (matching `query_inbox(state = Muted)`).
fn query_muted_in_store(db: &NodeDb, session_id: &str) -> Vec<MailboxEntry> {
    let mut out = Vec::new();
    for r in load_muted_index(db, session_id) {
        if let Some(entry) = db.local().get_mailbox_entry(&r).unwrap() {
            if entry.session_id == session_id
                && !matches!(entry.gate_state, GateState::Quarantined | GateState::Rejected)
            {
                out.push(entry);
            }
        }
    }
    out
}

fn muted_count_in_store(db: &NodeDb, session_id: &str) -> usize {
    query_muted_in_store(db, session_id).len()
}

// =========================================================================
// Pure In-Memory Reference Oracle
// =========================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
struct OracleKvEntry {
    value_json: String,
    version: u64,
    write_model: WriteModel,
    owner_id: Option<String>,
    allowlist: BTreeSet<String>,
    expires_at: Option<i64>,
}

#[derive(Debug, Clone)]
struct OracleSub {
    id: String,
    origin_node: String,
    topic: String,
    subscriber: String,
    filters: Vec<Filter>,
    coalesce_seconds: i64,
    max_wakes_per_hour: usize,
    created_order: usize,
}

#[derive(Debug, Clone)]
struct OracleBatch {
    id: usize,
    subscription_id: String,
    subscriber: String,
    state: BatchState,
    event_ids: Vec<String>,
    opened_at: i64,
    last_event_at: i64,
    flush_at: i64,
    closed_at: Option<i64>,
    hold_until: i64,
    settled_at: Option<i64>,
}

#[derive(Debug, Clone)]
struct OracleMessage {
    id: String,
    to_addr: String,
    channel: Option<String>,
    text: String,
    state: &'static str,
    hold_until: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OracleSession {
    id: String,
    backend_json: String,
    handle: Option<String>,
    last_seen: i64,
    created_at: i64,
}

#[derive(Debug, Clone)]
struct OracleMailboxItem {
    receipt: String,
    item_id: String,
    origin_node: String,
    session_id: String,
    text: String,
    received_at: i64,
    gate_state: GateState,
    muted: bool,
}

type EventIdempotencyKey = (String, String, String, String, String);

#[derive(Debug)]
struct MemoryOracle {
    // KV
    kv: BTreeMap<(String, String, String), OracleKvEntry>,
    // Handles (`(node, handle) -> last_heartbeat_at`) & Channels
    handles: BTreeMap<(String, String), i64>,
    channel_members: BTreeMap<(String, String), BTreeSet<String>>,
    messages: BTreeMap<String, OracleMessage>,
    // Events
    events_seen: BTreeMap<EventIdempotencyKey, (String, usize)>,
    subs: BTreeMap<String, OracleSub>,
    sub_seq: usize,
    batches: Vec<OracleBatch>,
    next_batch_id: usize,
    max_batch_events: usize,
    max_batch_age_ms: i64,
    max_pending_batches: usize,
    retention_ms: i64,
    hold_retry_ms: i64,
    // Local sessions, mailbox, mutes, bridge links, plugin targets, audit
    sessions: BTreeMap<String, OracleSession>,
    mailbox: Vec<OracleMailboxItem>,
    mutes: BTreeSet<(String, String)>,
    bridge_links: BTreeMap<(String, String, String), BridgeLink>,
    plugin_targets: BTreeMap<(String, String), PluginTargetHandoff>,
    audit_count: usize,
}

impl MemoryOracle {
    fn new(limits: &EventLimits) -> Self {
        Self {
            kv: BTreeMap::new(),
            handles: BTreeMap::new(),
            channel_members: BTreeMap::new(),
            messages: BTreeMap::new(),
            events_seen: BTreeMap::new(),
            subs: BTreeMap::new(),
            sub_seq: 0,
            batches: Vec::new(),
            next_batch_id: 1,
            max_batch_events: limits.max_batch_events,
            max_batch_age_ms: limits.max_batch_age_ms,
            max_pending_batches: limits.max_pending_batches_per_subscription,
            retention_ms: limits.retention_ms,
            hold_retry_ms: limits.hold_retry_ms,
            sessions: BTreeMap::new(),
            mailbox: Vec::new(),
            mutes: BTreeSet::new(),
            bridge_links: BTreeMap::new(),
            plugin_targets: BTreeMap::new(),
            audit_count: 0,
        }
    }

    fn is_enrolled(&self, addr: &str) -> bool {
        let Some((node, handle)) = addr.rsplit_once('/') else {
            return false;
        };
        self.handles
            .contains_key(&(node.to_string(), handle.to_string()))
    }

    fn kv_get(&self, host: &str, ns: &str, key: &str, now_ms: i64) -> Option<&OracleKvEntry> {
        self.kv
            .get(&(host.into(), ns.into(), key.into()))
            .filter(|e| e.expires_at.is_none_or(|exp| exp > now_ms))
    }

    fn kv_set(
        &mut self,
        input: &KvSetInput,
        now_ms: i64,
        synthetic_event_id: &str,
    ) -> Result<u64, &'static str> {
        let k = (
            input.host_node.clone(),
            input.namespace.clone(),
            input.key.clone(),
        );
        let live = self
            .kv
            .get(&k)
            .filter(|e| e.expires_at.is_none_or(|exp| exp > now_ms))
            .cloned();
        let value_json = serde_json::to_string(&input.value).unwrap();
        let expires_at = input.ttl_ms.map(|ttl| now_ms + ttl);

        let entry = if let Some(prev) = live {
            match prev.write_model {
                WriteModel::Owner => {
                    if prev.owner_id.as_deref() != Some(input.writer_id.as_str()) {
                        return Err("unauthorized");
                    }
                    if let Some(exp) = input.expected_version {
                        if exp != prev.version {
                            return Err("version_conflict");
                        }
                    }
                }
                WriteModel::Shared => {
                    if input.expected_version != Some(prev.version) {
                        return Err("version_conflict");
                    }
                }
                WriteModel::Allowlist => {
                    if !prev.allowlist.contains(&input.writer_id) {
                        return Err("unauthorized");
                    }
                    if let Some(exp) = input.expected_version {
                        if exp != prev.version {
                            return Err("version_conflict");
                        }
                    }
                }
            }
            OracleKvEntry {
                value_json,
                version: prev.version + 1,
                write_model: prev.write_model,
                owner_id: prev.owner_id,
                allowlist: prev.allowlist,
                expires_at,
            }
        } else {
            if let Some(exp) = input.expected_version {
                if exp != 0 {
                    return Err("version_conflict");
                }
            }
            let (owner_id, allowlist) = match input.write_model {
                WriteModel::Owner => {
                    let owner = input
                        .owner_id
                        .clone()
                        .unwrap_or_else(|| input.writer_id.clone());
                    if owner != input.writer_id {
                        return Err("unauthorized");
                    }
                    (Some(owner), BTreeSet::new())
                }
                WriteModel::Shared => (input.owner_id.clone(), BTreeSet::new()),
                WriteModel::Allowlist => {
                    let list: BTreeSet<String> = input
                        .allowlist
                        .clone()
                        .unwrap_or_default()
                        .into_iter()
                        .collect();
                    if list.is_empty() || !list.contains(&input.writer_id) {
                        return Err("unauthorized");
                    }
                    (input.owner_id.clone(), list)
                }
            };
            OracleKvEntry {
                value_json,
                version: 1,
                write_model: input.write_model,
                owner_id,
                allowlist,
                expires_at,
            }
        };

        let ver = entry.version;
        self.kv.insert(k, entry);

        // Emit matching CloudEvent on (host_node, "kv")
        let ce = CloudEvent::new(
            synthetic_event_id,
            format!("{}/kv/{}", input.host_node, input.namespace),
            "to.hyphae.kv.set",
            json!({ "key": input.key, "version": ver }),
        )
        .with_extension("ns", &input.namespace)
        .with_extension("key", &input.key)
        .with_extension("version", ver.to_string())
        .with_extension("writer", &input.writer_id);
        let _ = self.event_ingest(&input.host_node, "kv", "system:kv", &ce, now_ms);

        Ok(ver)
    }

    fn kv_delete(
        &mut self,
        input: &KvDeleteInput,
        now_ms: i64,
        synthetic_event_id: &str,
    ) -> Result<bool, &'static str> {
        let k = (
            input.host_node.clone(),
            input.namespace.clone(),
            input.key.clone(),
        );
        let live = self
            .kv
            .get(&k)
            .filter(|e| e.expires_at.is_none_or(|exp| exp > now_ms))
            .cloned();
        let Some(prev) = live else {
            if let Some(exp) = input.expected_version {
                if exp > 0 {
                    return Err("version_conflict");
                }
            }
            self.kv.remove(&k);
            return Ok(false);
        };

        match prev.write_model {
            WriteModel::Owner => {
                if prev.owner_id.as_deref() != Some(input.writer_id.as_str()) {
                    return Err("unauthorized");
                }
                if let Some(exp) = input.expected_version {
                    if exp != prev.version {
                        return Err("version_conflict");
                    }
                }
            }
            WriteModel::Shared => {
                if input.expected_version != Some(prev.version) {
                    return Err("version_conflict");
                }
            }
            WriteModel::Allowlist => {
                if !prev.allowlist.contains(&input.writer_id) {
                    return Err("unauthorized");
                }
                if let Some(exp) = input.expected_version {
                    if exp != prev.version {
                        return Err("version_conflict");
                    }
                }
            }
        }

        self.kv.remove(&k);
        let ce = CloudEvent::new(
            synthetic_event_id,
            format!("{}/kv/{}", input.host_node, input.namespace),
            "to.hyphae.kv.deleted",
            json!({ "key": input.key, "deleted": true }),
        )
        .with_extension("ns", &input.namespace)
        .with_extension("key", &input.key)
        .with_extension("version", prev.version.to_string())
        .with_extension("writer", &input.writer_id);
        let _ = self.event_ingest(&input.host_node, "kv", "system:kv", &ce, now_ms);
        Ok(true)
    }

    fn register_handle(&mut self, node: &str, handle: &str, now_ms: i64) {
        self.handles.insert((node.into(), handle.into()), now_ms);
    }

    fn remove_handle(&mut self, node: &str, handle: &str) {
        self.handles.remove(&(node.into(), handle.into()));
        let addr = format!("{node}/{handle}");
        for members in self.channel_members.values_mut() {
            members.remove(&addr);
        }
        for msg in self.messages.values_mut() {
            if msg.to_addr == addr && msg.state == "pending" {
                msg.state = "rejected";
            }
        }
    }

    fn prune_stale_handles(&mut self, cutoff_ms: i64) -> Vec<String> {
        let stale: Vec<(String, String)> = self
            .handles
            .iter()
            .filter(|(_, hb)| **hb < cutoff_ms)
            .map(|((n, h), _)| (n.clone(), h.clone()))
            .collect();
        let mut removed = Vec::with_capacity(stale.len());
        for (n, h) in stale {
            self.remove_handle(&n, &h);
            removed.push(format!("{n}/{h}"));
        }
        removed
    }

    fn channel_join(&mut self, host: &str, ch: &str, node: &str, handle: &str) -> bool {
        let addr = format!("{node}/{handle}");
        if !self.is_enrolled(&addr) {
            return false;
        }
        self.channel_members
            .entry((host.into(), ch.into()))
            .or_default()
            .insert(addr);
        true
    }

    fn channel_leave(&mut self, host: &str, ch: &str, node: &str, handle: &str) -> bool {
        let addr = format!("{node}/{handle}");
        self.channel_members
            .get_mut(&(host.into(), ch.into()))
            .is_some_and(|m| m.remove(&addr))
    }

    fn channel_post(&mut self, input: &PostChannelInput) -> Result<Vec<String>, &'static str> {
        let sender = format!("{}/{}", input.from_node, input.from_handle);
        if !self.is_enrolled(&sender) {
            return Err("not_enrolled");
        }
        let members: Vec<String> = self
            .channel_members
            .get(&(input.host_node.clone(), input.channel.clone()))
            .map(|set| {
                set.iter()
                    .filter(|a| self.is_enrolled(a))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        if !members.contains(&sender) {
            return Err("not_member");
        }
        let mut delivered = Vec::new();
        for recipient in members {
            if recipient == sender {
                continue;
            }
            let id = format!("{}:{recipient}", input.id);
            if !self.messages.contains_key(&id) {
                self.messages.insert(
                    id.clone(),
                    OracleMessage {
                        id,
                        to_addr: recipient.clone(),
                        channel: Some(input.channel.clone()),
                        text: input.text.clone(), // ZERO prefix mutation!
                        state: "pending",
                        hold_until: 0,
                    },
                );
            }
            delivered.push(recipient);
        }
        Ok(delivered)
    }

    fn upsert_subscription(&mut self, spec: &SubscriptionSpec) {
        if let Some(prev) = self.subs.get_mut(&spec.id) {
            if prev.origin_node != spec.origin_node || prev.topic != spec.topic {
                self.batches.retain(|b| b.subscription_id != spec.id);
            }
            prev.origin_node = spec.origin_node.clone();
            prev.topic = spec.topic.clone();
            prev.filters = spec.filters.clone();
            prev.coalesce_seconds = spec.coalesce_seconds;
            prev.max_wakes_per_hour = spec.max_wakes_per_hour.unwrap_or(30);
            let coalesce_ms = prev.coalesce_seconds * 1000;
            for b in &mut self.batches {
                if b.subscription_id == spec.id && b.state == BatchState::Open {
                    b.flush_at =
                        (b.last_event_at + coalesce_ms).min(b.opened_at + self.max_batch_age_ms);
                }
            }
        } else {
            self.sub_seq += 1;
            self.subs.insert(
                spec.id.clone(),
                OracleSub {
                    id: spec.id.clone(),
                    origin_node: spec.origin_node.clone(),
                    topic: spec.topic.clone(),
                    subscriber: spec.subscriber.clone(),
                    filters: spec.filters.clone(),
                    coalesce_seconds: spec.coalesce_seconds,
                    max_wakes_per_hour: spec.max_wakes_per_hour.unwrap_or(30),
                    created_order: self.sub_seq,
                },
            );
        }
    }

    fn event_ingest(
        &mut self,
        origin: &str,
        topic: &str,
        publisher: &str,
        event: &CloudEvent,
        now_ms: i64,
    ) -> Result<(bool, usize), &'static str> {
        let key = (
            origin.to_string(),
            topic.to_string(),
            publisher.to_string(),
            event.source.clone(),
            event.id.clone(),
        );
        let digest = event.digest();
        if let Some((orig_digest, orig_matched)) = self.events_seen.get(&key) {
            if orig_digest != &digest {
                return Err("id_conflict");
            }
            return Ok((true, *orig_matched));
        }

        let mut matching_subs: Vec<OracleSub> = self
            .subs
            .values()
            .filter(|s| s.origin_node == origin && s.topic == topic)
            .cloned()
            .collect();
        matching_subs.sort_by(|a, b| a.created_order.cmp(&b.created_order).then(a.id.cmp(&b.id)));

        let mut matched = 0usize;
        for sub in matching_subs {
            if !matches_filters(&sub.filters, event) {
                continue;
            }
            matched += 1;
            self.append_batch(&sub, &event.id, now_ms);
        }
        self.events_seen.insert(key, (digest, matched));
        Ok((false, matched))
    }

    fn append_batch(&mut self, sub: &OracleSub, event_id: &str, now_ms: i64) {
        let coalesce_ms = sub.coalesce_seconds * 1000;
        let open_idx = self
            .batches
            .iter()
            .position(|b| b.subscription_id == sub.id && b.state == BatchState::Open);
        let target_idx = if let Some(idx) = open_idx {
            let b = &self.batches[idx];
            if now_ms >= b.flush_at
                || now_ms - b.last_event_at >= coalesce_ms
                || now_ms - b.opened_at >= self.max_batch_age_ms
            {
                self.close_batch(idx, now_ms);
                None
            } else {
                Some(idx)
            }
        } else {
            None
        };

        let idx = if let Some(idx) = target_idx {
            idx
        } else {
            let id = self.next_batch_id;
            self.next_batch_id += 1;
            let flush_at = (now_ms + coalesce_ms).min(now_ms + self.max_batch_age_ms);
            self.batches.push(OracleBatch {
                id,
                subscription_id: sub.id.clone(),
                subscriber: sub.subscriber.clone(),
                state: BatchState::Open,
                event_ids: Vec::new(),
                opened_at: now_ms,
                last_event_at: now_ms,
                flush_at,
                closed_at: None,
                hold_until: 0,
                settled_at: None,
            });
            self.batches.len() - 1
        };

        let batch = &mut self.batches[idx];
        batch.event_ids.push(event_id.to_string());
        batch.last_event_at = now_ms;
        batch.flush_at = (now_ms + coalesce_ms).min(batch.opened_at + self.max_batch_age_ms);
        let should_close =
            batch.event_ids.len() >= self.max_batch_events || sub.coalesce_seconds == 0;
        if should_close {
            self.close_batch(idx, now_ms);
        }
    }

    fn close_batch(&mut self, idx: usize, now_ms: i64) {
        let sub_id = self.batches[idx].subscription_id.clone();
        self.batches[idx].state = BatchState::Pending;
        self.batches[idx].closed_at = Some(now_ms);

        let mut pending_indices: Vec<usize> = self
            .batches
            .iter()
            .enumerate()
            .filter(|(_, b)| b.subscription_id == sub_id && b.state == BatchState::Pending)
            .map(|(i, _)| i)
            .collect();
        pending_indices
            .sort_by_key(|&i| (self.batches[i].closed_at.unwrap_or(0), self.batches[i].id));
        let excess = pending_indices.len().saturating_sub(self.max_pending_batches);
        for drop_i in pending_indices.into_iter().take(excess) {
            self.batches[drop_i].state = BatchState::Dropped;
            self.batches[drop_i].settled_at = Some(now_ms);
        }
    }

    fn tick_events(&mut self, now_ms: i64) {
        let to_close: Vec<usize> = self
            .batches
            .iter()
            .enumerate()
            .filter(|(_, b)| b.state == BatchState::Open && b.flush_at <= now_ms)
            .map(|(i, _)| i)
            .collect();
        for idx in to_close {
            self.close_batch(idx, now_ms);
        }
        for b in &mut self.batches {
            if b.state == BatchState::Pending && b.opened_at <= now_ms - self.retention_ms {
                b.state = BatchState::Dropped;
                b.settled_at = Some(now_ms);
            }
        }
    }

    fn due_batches(&self, subscriber: &str, now_ms: i64) -> Vec<(String, usize)> {
        let mut subs: Vec<&OracleSub> = self
            .subs
            .values()
            .filter(|s| s.subscriber == subscriber)
            .collect();
        subs.sort_by(|a, b| a.created_order.cmp(&b.created_order).then(a.id.cmp(&b.id)));
        let mut out = Vec::new();
        for sub in subs {
            let next_pending = self
                .batches
                .iter()
                .filter(|b| b.subscription_id == sub.id && b.state == BatchState::Pending)
                .min_by_key(|b| (b.closed_at.unwrap_or(0), b.id));
            let Some(batch) = next_pending else {
                continue;
            };
            if batch.hold_until > now_ms || now_ms - batch.opened_at >= self.retention_ms {
                continue;
            }
            let delivered_1h = self
                .batches
                .iter()
                .filter(|b| {
                    b.subscription_id == sub.id
                        && b.state == BatchState::Delivered
                        && b.settled_at.is_some_and(|s| s > now_ms - HOUR_MS)
                })
                .count();
            if delivered_1h >= sub.max_wakes_per_hour {
                continue;
            }
            out.push((sub.id.clone(), batch.event_ids.len()));
        }
        out
    }

    fn ack_oldest_due_batch(
        &mut self,
        subscriber: &str,
        sub_id: &str,
        outcome: &AckOutcome,
        now_ms: i64,
    ) {
        let idx = self
            .batches
            .iter()
            .enumerate()
            .filter(|(_, b)| {
                b.subscription_id == sub_id
                    && b.subscriber == subscriber
                    && b.state == BatchState::Pending
            })
            .min_by_key(|(_, b)| (b.closed_at.unwrap_or(0), b.id))
            .map(|(i, _)| i);
        if let Some(i) = idx {
            match outcome {
                AckOutcome::Delivered => {
                    self.batches[i].state = BatchState::Delivered;
                    self.batches[i].settled_at = Some(now_ms);
                }
                AckOutcome::Rejected { .. } => {
                    self.batches[i].state = BatchState::Rejected;
                    self.batches[i].settled_at = Some(now_ms);
                }
                AckOutcome::Hold { retry_after_ms, .. } => {
                    let delay = retry_after_ms.unwrap_or(self.hold_retry_ms);
                    self.batches[i].hold_until = now_ms + delay;
                }
            }
        }
    }

    // ---- Local sessions, mutes, bridge links, plugin targets ----

    fn register_session(&mut self, id: &str, backend_json: &str, now_ms: i64) {
        self.sessions
            .entry(id.to_string())
            .and_modify(|s| {
                s.backend_json = backend_json.to_string();
                s.last_seen = now_ms;
            })
            .or_insert_with(|| OracleSession {
                id: id.to_string(),
                backend_json: backend_json.to_string(),
                handle: None,
                last_seen: now_ms,
                created_at: now_ms,
            });
    }

    fn touch_session(&mut self, id: &str, now_ms: i64) -> bool {
        if let Some(s) = self.sessions.get_mut(id) {
            s.last_seen = now_ms;
            true
        } else {
            false
        }
    }

    fn set_session_handle(
        &mut self,
        id: &str,
        handle: Option<&str>,
        now_ms: i64,
    ) -> Result<bool, &'static str> {
        if !self.sessions.contains_key(id) {
            return Ok(false);
        }
        if let Some(h) = handle {
            let taken_by_other = self
                .sessions
                .iter()
                .any(|(other_id, s)| other_id != id && s.handle.as_deref() == Some(h));
            if taken_by_other {
                return Err("id_conflict");
            }
        }
        let s = self.sessions.get_mut(id).unwrap();
        s.handle = handle.map(ToOwned::to_owned);
        s.last_seen = now_ms;
        Ok(true)
    }

    fn prune_sessions(&mut self, cutoff_ms: i64, active: &HashSet<String>) -> BTreeSet<String> {
        let stale: BTreeSet<String> = self
            .sessions
            .values()
            .filter(|s| s.last_seen > 0 && s.last_seen < cutoff_ms && !active.contains(&s.id))
            .map(|s| s.id.clone())
            .collect();

        for id in &stale {
            self.mailbox.retain(|m| &m.session_id != id);
            self.mutes.retain(|(scope, _)| scope != id);
            self.bridge_links.retain(|(_, _, sid), _| sid != id);
            self.plugin_targets.retain(|_, h| &h.session_id != id);
            self.sessions.remove(id);
        }
        stale
    }

    fn is_muted(&self, session_id: &str, candidate: &str) -> bool {
        let low = candidate.trim().to_lowercase();
        self.mutes.iter().any(|(scope, pat)| {
            if scope != "*" && scope != session_id {
                return false;
            }
            if pat == &low {
                return true;
            }
            pat.strip_suffix('*')
                .is_some_and(|p| !p.is_empty() && low.starts_with(p))
        })
    }

    fn pending_count(&self, session_id: &str) -> usize {
        self.mailbox
            .iter()
            .filter(|m| m.session_id == session_id && m.gate_state == GateState::Pending)
            .count()
    }

    fn add_bridge_link(&mut self, link: &BridgeLink) {
        self.bridge_links.insert(
            (
                link.plugin.clone(),
                link.target.clone(),
                link.session_id.clone(),
            ),
            link.clone(),
        );
    }

    fn remove_bridge_link(
        &mut self,
        plugin: &str,
        target: &str,
        session_id: Option<&str>,
    ) -> usize {
        let before = self.bridge_links.len();
        self.bridge_links.retain(|(p, t, sid), _| {
            if p != plugin || t != target {
                return true;
            }
            match session_id {
                Some(target_sid) => sid != target_sid,
                None => false,
            }
        });
        before - self.bridge_links.len()
    }

    fn bridge_links(&self, plugin: &str, target: &str) -> Vec<BridgeLink> {
        let mut out: Vec<BridgeLink> = self
            .bridge_links
            .values()
            .filter(|l| l.plugin == plugin && l.target == target)
            .cloned()
            .collect();
        out.sort_by(|a, b| a.linked_at.cmp(&b.linked_at).then(a.session_id.cmp(&b.session_id)));
        out
    }

    fn bridge_links_for_session(&self, session_id: &str) -> Vec<BridgeLink> {
        let mut out: Vec<BridgeLink> = self
            .bridge_links
            .values()
            .filter(|l| l.session_id == session_id)
            .cloned()
            .collect();
        out.sort_by(|a, b| a.plugin.cmp(&b.plugin).then(a.target.cmp(&b.target)));
        out
    }

    fn set_plugin_target(&mut self, handoff: &PluginTargetHandoff) {
        self.plugin_targets
            .insert((handoff.plugin.clone(), handoff.target.clone()), handoff.clone());
    }

    fn remove_plugin_target(&mut self, plugin: &str, target: &str) -> bool {
        self.plugin_targets
            .remove(&(plugin.to_string(), target.to_string()))
            .is_some()
    }

    fn get_plugin_target(&self, plugin: &str, target: &str) -> Option<PluginTargetHandoff> {
        self.plugin_targets
            .get(&(plugin.to_string(), target.to_string()))
            .cloned()
    }
}

fn run_differential_seed(seed: u64, steps: usize) {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("node.sqlite");

    let event_limits = EventLimits {
        max_batch_events: 4,
        max_wakes_per_hour_per_subscription: 3,
        max_pending_batches_per_subscription: 10,
        max_batch_age_ms: 20_000,
        hold_retry_ms: 5_000,
        retention_ms: 24 * HOUR_MS,
        ..EventLimits::default()
    };
    let config = StoreConfig {
        event_limits: event_limits.clone(),
        message_limits: MessageLimits {
            max_per_hour_per_recipient: 500,
            max_pending_per_recipient: 500,
            hold_retry_ms: 5_000,
            ..MessageLimits::default()
        },
        mailbox_max_pending_per_session: MAILBOX_MAX_PENDING,
        ..StoreConfig::default()
    };

    let db = NodeDb::open_with_config(&db_path, config).unwrap();
    let mut oracle = MemoryOracle::new(&event_limits);
    let mut rng = StdRng::seed_from_u64(seed);
    let mut now_ms = 1_700_000_000_000i64;

    // Seed initial handles, subscriptions, and sessions.
    let nodes = ["alice@mac", "bob@lap", "carol@dev"];
    let handles = ["claude", "codex"];
    let session_pool = ["sess-0", "sess-1", "sess-2", "sess-3", "sess-4"];
    let session_handles = ["alpha", "beta", "gamma", "delta"];
    let plugins = ["slack", "telegram"];
    let bridge_targets = ["ops", "eng", "alerts"];
    let channels = ["#incidents", "#deploy"];
    let kv_keys = ["plan/a", "plan/b", "lock/x", "state/y"];
    let writers = ["alice", "bob", "carol"];

    for (sid, kind) in [("sess-0", r#"{"kind":"claude"}"#), ("sess-1", r#"{"kind":"codex"}"#)] {
        db.local().register_session(sid, kind, now_ms).unwrap();
        oracle.register_session(sid, kind, now_ms);
    }

    // Two event subscriptions: one on `local.kv` (zero coalesce) and one on `acme.github` (coalesce=5s, cap=3/hr).
    let sub_kv = SubscriptionSpec {
        id: "sub-kv".into(),
        origin_node: "local".into(),
        topic: "kv".into(),
        subscriber: "sess-0".into(),
        filters: vec![Filter::exact("ns", "shared"), Filter::prefix("key", "plan/")],
        coalesce_seconds: 0,
        max_batch_age_ms: None,
        max_wakes_per_hour: Some(50),
        mode: DeliveryMode::Full,
    };
    db.events().upsert_subscription(&sub_kv, now_ms).unwrap();
    oracle.upsert_subscription(&sub_kv);

    let sub_gh = SubscriptionSpec {
        id: "sub-gh".into(),
        origin_node: "acme-team".into(),
        topic: "github".into(),
        subscriber: "sess-1".into(),
        filters: vec![Filter::exact("repo", "acme/app")],
        coalesce_seconds: 5,
        max_batch_age_ms: None,
        max_wakes_per_hour: Some(3),
        mode: DeliveryMode::Full,
    };
    db.events().upsert_subscription(&sub_gh, now_ms).unwrap();
    oracle.upsert_subscription(&sub_gh);

    let mut event_history: Vec<CloudEvent> = Vec::new();
    let mut muted_transitions = 0usize;
    let mut bridge_link_ops = 0usize;
    let mut plugin_handoff_ops = 0usize;
    let mut pruned_session_count = 0usize;

    for step in 0..steps {
        // Advance monotonic virtual clock slightly on every step (occasionally jump >1h for wake caps).
        let dt = match rng.gen_range(0..25) {
            0 => HOUR_MS + 1_000,
            1..=4 => 6_000,
            _ => rng.gen_range(100..2_000),
        };
        now_ms += dt;

        let op = rng.gen_range(0..22);
        match op {
            // 0..=2: KV set (owner / shared CAS / allowlist + optional TTL)
            0..=2 => {
                let key = kv_keys[rng.gen_range(0..kv_keys.len())];
                let writer = writers[rng.gen_range(0..writers.len())];
                let model = match rng.gen_range(0..3) {
                    0 => WriteModel::Owner,
                    1 => WriteModel::Shared,
                    _ => WriteModel::Allowlist,
                };
                let cur_ver = oracle
                    .kv_get("local", "shared", key, now_ms)
                    .map(|e| e.version)
                    .unwrap_or(0);
                let expected_version = match rng.gen_range(0..4) {
                    0 => Some(cur_ver),
                    1 => Some(cur_ver + 1), // deliberate CAS race mismatch
                    2 => Some(0),
                    _ => None,
                };
                let ttl_ms = if rng.gen_bool(0.25) {
                    Some(10_000)
                } else {
                    None
                };
                let input = KvSetInput {
                    host_node: "local".into(),
                    namespace: "shared".into(),
                    key: key.into(),
                    value: json!({ "step": step, "by": writer }),
                    content_type: None,
                    write_model: model,
                    owner_id: None,
                    allowlist: if model == WriteModel::Allowlist {
                        Some(vec!["alice".into(), "bob".into()])
                    } else {
                        None
                    },
                    writer_id: writer.into(),
                    expected_version,
                    e2ee_epoch: None,
                    signature: None,
                    ttl_ms,
                };
                let real_res = db.kv().set(&input, now_ms);
                let oracle_res = oracle.kv_set(&input, now_ms, &format!("oracle-kv-set-{step}"));
                match (&real_res, &oracle_res) {
                    (Ok(r), Ok(v)) => assert_eq!(
                        r.entry.version, *v,
                        "seed=0x{seed:016x} step={step}: KV set version mismatch"
                    ),
                    (Err(StoreError::VersionConflict { .. }), Err("version_conflict")) => {}
                    (Err(StoreError::Unauthorized(_)), Err("unauthorized")) => {}
                    _ => panic!(
                        "seed=0x{seed:016x} step={step}: KV set divergence real={real_res:?} oracle={oracle_res:?}"
                    ),
                }
            }

            // 3: KV delete
            3 => {
                let key = kv_keys[rng.gen_range(0..kv_keys.len())];
                let writer = writers[rng.gen_range(0..writers.len())];
                let cur_ver = oracle
                    .kv_get("local", "shared", key, now_ms)
                    .map(|e| e.version)
                    .unwrap_or(0);
                let expected_version = if rng.gen_bool(0.7) {
                    Some(cur_ver)
                } else {
                    Some(cur_ver + 2)
                };
                let input = KvDeleteInput {
                    host_node: "local".into(),
                    namespace: "shared".into(),
                    key: key.into(),
                    writer_id: writer.into(),
                    expected_version,
                };
                let real_res = db.kv().delete(&input, now_ms);
                let oracle_res =
                    oracle.kv_delete(&input, now_ms, &format!("oracle-kv-del-{step}"));
                match (&real_res, &oracle_res) {
                    (Ok(r), Ok(deleted)) => assert_eq!(
                        r.deleted, *deleted,
                        "seed=0x{seed:016x} step={step}: KV delete mismatch"
                    ),
                    (Err(StoreError::VersionConflict { .. }), Err("version_conflict")) => {}
                    (Err(StoreError::Unauthorized(_)), Err("unauthorized")) => {}
                    _ => panic!(
                        "seed=0x{seed:016x} step={step}: KV delete divergence real={real_res:?} oracle={oracle_res:?}"
                    ),
                }
            }

            // 4: Register, remove, or prune stale handles
            4 => {
                if rng.gen_bool(0.2) {
                    let cutoff = now_ms - rng.gen_range(3_000..15_000);
                    let real_pruned = db.messages().prune_stale_handles(cutoff, now_ms).unwrap();
                    let oracle_pruned = oracle.prune_stale_handles(cutoff);
                    assert_eq!(
                        real_pruned, oracle_pruned,
                        "seed=0x{seed:016x} step={step}: prune_stale_handles mismatch"
                    );
                } else {
                    let node = nodes[rng.gen_range(0..nodes.len())];
                    let handle = handles[rng.gen_range(0..handles.len())];
                    if rng.gen_bool(0.75) {
                        db.messages()
                            .register_handle(node, handle, None, now_ms)
                            .unwrap();
                        oracle.register_handle(node, handle, now_ms);
                    } else {
                        db.messages().remove_handle(node, handle, now_ms).unwrap();
                        oracle.remove_handle(node, handle);
                    }
                }
            }

            // 5: Channel join / leave
            5 => {
                let node = nodes[rng.gen_range(0..nodes.len())];
                let handle = handles[rng.gen_range(0..handles.len())];
                let ch = channels[rng.gen_range(0..channels.len())];
                if rng.gen_bool(0.7) {
                    let real_ok = db.channels().join("acme-team", ch, node, handle, now_ms).is_ok();
                    let oracle_ok = oracle.channel_join("acme-team", ch, node, handle);
                    assert_eq!(
                        real_ok, oracle_ok,
                        "seed=0x{seed:016x} step={step}: channel join mismatch"
                    );
                } else {
                    let real_left = db.channels().leave("acme-team", ch, node, handle).unwrap();
                    let oracle_left = oracle.channel_leave("acme-team", ch, node, handle);
                    assert_eq!(
                        real_left, oracle_left,
                        "seed=0x{seed:016x} step={step}: channel leave mismatch"
                    );
                }
            }

            // 6: Channel post (verifying zero ciphertext text mutation!)
            6 => {
                let node = nodes[rng.gen_range(0..nodes.len())];
                let handle = handles[rng.gen_range(0..handles.len())];
                let ch = channels[rng.gen_range(0..channels.len())];
                let payload = format!("{{\"e2ee\":\"ct-step-{step}\"}}");
                let input = PostChannelInput {
                    id: format!("chpost-{step}"),
                    host_node: "acme-team".into(),
                    channel: ch.into(),
                    from_node: node.into(),
                    from_handle: handle.into(),
                    text: payload,
                    e2ee_epoch: Some(1),
                };
                let real_res = db.channels().post(&input, now_ms);
                let oracle_res = oracle.channel_post(&input);
                match (&real_res, &oracle_res) {
                    (Ok(r), Ok(exp)) => {
                        assert_eq!(
                            &r.delivered_to, exp,
                            "seed=0x{seed:016x} step={step}: channel fan-out recipients mismatch"
                        );
                    }
                    (Err(StoreError::NotFound(_)), Err("not_enrolled")) => {}
                    (Err(StoreError::Unauthorized(_)), Err("not_member")) => {}
                    _ => panic!(
                        "seed=0x{seed:016x} step={step}: channel post divergence real={real_res:?} oracle={oracle_res:?}"
                    ),
                }
            }

            // 7..=8: Event ingest (fresh, exact duplicate replay, or conflicting payload replay)
            7..=8 => {
                let ev = if !event_history.is_empty() && rng.gen_bool(0.3) {
                    let mut chosen = event_history[rng.gen_range(0..event_history.len())].clone();
                    if rng.gen_bool(0.35) {
                        // Mutated content -> expect IdConflict!
                        chosen.data = json!({ "tampered": step });
                    }
                    chosen
                } else {
                    let repo = if rng.gen_bool(0.75) {
                        "acme/app"
                    } else {
                        "acme/ignored"
                    };
                    let fresh = CloudEvent::new(
                        format!("ev-{step}"),
                        format!("github.com/{repo}"),
                        "com.github.pr",
                        json!({ "step": step }),
                    )
                    .with_extension("repo", repo);
                    event_history.push(fresh.clone());
                    fresh
                };
                let real_res = db
                    .events()
                    .ingest("acme-team", "github", "gh", &ev, now_ms);
                let oracle_res =
                    oracle.event_ingest("acme-team", "github", "gh", &ev, now_ms);
                match (&real_res, &oracle_res) {
                    (Ok(r), Ok((dedup, matched))) => {
                        assert_eq!(
                            (r.deduplicated, r.matched),
                            (*dedup, *matched),
                            "seed=0x{seed:016x} step={step}: event ingest mismatch"
                        );
                    }
                    (Err(StoreError::IdConflict(_)), Err("id_conflict")) => {}
                    _ => panic!(
                        "seed=0x{seed:016x} step={step}: event ingest divergence real={real_res:?} oracle={oracle_res:?}"
                    ),
                }
            }

            // 9: Event tick + claim & ack due batches (checking wake cap & hold!)
            9 => {
                db.events().tick(now_ms).unwrap();
                oracle.tick_events(now_ms);
                for sub_owner in ["sess-0", "sess-1"] {
                    let real_due = db.events().claim_due_batches(sub_owner, now_ms).unwrap();
                    let oracle_due = oracle.due_batches(sub_owner, now_ms);
                    let real_summary: Vec<(String, usize)> = real_due
                        .iter()
                        .map(|b| (b.subscription_id.clone(), b.events.len()))
                        .collect();
                    assert_eq!(
                        real_summary, oracle_due,
                        "seed=0x{seed:016x} step={step}: due_batches mismatch for {sub_owner}"
                    );
                    if let Some(batch) = real_due.first() {
                        let outcome = match rng.gen_range(0..5) {
                            0 => AckOutcome::Hold {
                                reason: "busy".into(),
                                retry_after_ms: None,
                            },
                            1 => AckOutcome::Rejected {
                                reason: "bad".into(),
                            },
                            _ => AckOutcome::Delivered,
                        };
                        assert!(
                            db.events()
                                .ack_batch(sub_owner, &batch.id, &outcome, now_ms)
                                .unwrap()
                        );
                        oracle.ack_oldest_due_batch(
                            sub_owner,
                            &batch.subscription_id,
                            &outcome,
                            now_ms,
                        );
                    }
                }
            }

            // 10: Add or remove mute rule (global `*` or per-session)
            10 => {
                let scope = match rng.gen_range(0..4) {
                    0 => "*",
                    1 => "sess-0",
                    2 => "sess-2",
                    _ => "sess-3",
                };
                let pat = match rng.gen_range(0..3) {
                    0 => "guest@ext/bot",
                    1 => "spam@ext/*",
                    _ => "alerts:noisy",
                };
                if rng.gen_bool(0.7) {
                    db.local().add_mute(scope, pat, "human", now_ms).unwrap();
                    oracle.mutes.insert((scope.into(), pat.into()));
                } else {
                    let r = db.local().remove_mute(scope, pat).unwrap();
                    let o = oracle.mutes.remove(&(scope.into(), pat.into()));
                    assert_eq!(
                        r, o,
                        "seed=0x{seed:016x} step={step}: remove_mute mismatch"
                    );
                }
            }

            // 11..=12: Put item into mailbox (pending, quarantined, OR muted archival)
            11..=12 => {
                let live_sessions: Vec<String> = oracle.sessions.keys().cloned().collect();
                let sid = live_sessions[rng.gen_range(0..live_sessions.len())].clone();
                let source = match rng.gen_range(0..4) {
                    0 => "guest@ext/bot",
                    1 => "spam@ext/promo",
                    2 => "bob@lap/codex",
                    _ => "alerts:noisy",
                };
                let real_muted = db.local().is_muted(&sid, &[source]).unwrap().is_some();
                let oracle_muted = oracle.is_muted(&sid, source);
                assert_eq!(
                    real_muted, oracle_muted,
                    "seed=0x{seed:016x} step={step}: is_muted mismatch for sid='{sid}' source='{source}'"
                );

                let item_id = format!("mb-{step}");
                let text = format!("body-{step}");
                let origin = "remote".to_string();

                // Either source is muted OR explicitly exercise direct muted archival (~20%).
                if real_muted || rng.gen_bool(0.2) {
                    let insert = MailboxInsert {
                        session_id: sid.clone(),
                        origin_node: origin.clone(),
                        item_id: item_id.clone(),
                        text: text.clone(),
                        kind: MailboxKind::Message,
                        source: source.into(),
                        gate_state: GateState::Delivered,
                        gate_reason: Some("muted".into()),
                        traceparent: None,
                    };
                    if let MailboxPutResult::Stored { receipt } =
                        archive_muted_in_store(&db, &insert, now_ms)
                    {
                        muted_transitions += 1;
                        oracle.mailbox.push(OracleMailboxItem {
                            receipt,
                            item_id,
                            origin_node: origin,
                            session_id: sid,
                            text,
                            received_at: now_ms,
                            gate_state: GateState::Delivered,
                            muted: true,
                        });
                    }
                } else {
                    let gate_state = if rng.gen_bool(0.45) {
                        GateState::Quarantined
                    } else {
                        GateState::Pending
                    };
                    let oracle_full =
                        gate_state == GateState::Pending && oracle.pending_count(&sid) >= MAILBOX_MAX_PENDING;
                    let res = db
                        .local()
                        .put_in_mailbox(
                            &MailboxInsert {
                                session_id: sid.clone(),
                                origin_node: origin.clone(),
                                item_id: item_id.clone(),
                                text: text.clone(),
                                kind: MailboxKind::Message,
                                source: source.into(),
                                gate_state,
                                gate_reason: if gate_state == GateState::Quarantined {
                                    Some("review_required".into())
                                } else {
                                    None
                                },
                                traceparent: None,
                            },
                            now_ms,
                        )
                        .unwrap();
                    match res {
                        MailboxPutResult::QueueFull => {
                            assert!(
                                oracle_full,
                                "seed=0x{seed:016x} step={step}: unexpected QueueFull for {sid}"
                            );
                        }
                        MailboxPutResult::Stored { receipt } => {
                            assert!(
                                !oracle_full,
                                "seed=0x{seed:016x} step={step}: expected QueueFull for {sid}"
                            );
                            oracle.mailbox.push(OracleMailboxItem {
                                receipt,
                                item_id,
                                origin_node: origin,
                                session_id: sid,
                                text,
                                received_at: now_ms,
                                gate_state,
                                muted: false,
                            });
                        }
                        MailboxPutResult::Duplicate => {
                            panic!("seed=0x{seed:016x} step={step}: unexpected Duplicate for unique {item_id}");
                        }
                    }
                }
            }

            // 13: Move an existing pending item to muted OR approve/reject a quarantined item
            13 => {
                if rng.gen_bool(0.35) {
                    if let Some(idx) = oracle
                        .mailbox
                        .iter()
                        .position(|m| m.gate_state == GateState::Pending)
                    {
                        let sid = oracle.mailbox[idx].session_id.clone();
                        let receipt = oracle.mailbox[idx].receipt.clone();
                        let entry = db.local().get_mailbox_entry(&receipt).unwrap().unwrap();
                        move_pending_to_muted_in_store(&db, &sid, &entry, now_ms);
                        oracle.mailbox[idx].gate_state = GateState::Delivered;
                        oracle.mailbox[idx].muted = true;
                        muted_transitions += 1;
                    }
                } else if let Some(idx) = oracle
                    .mailbox
                    .iter()
                    .position(|m| m.gate_state == GateState::Quarantined)
                {
                    let receipt = oracle.mailbox[idx].receipt.clone();
                    let sid = oracle.mailbox[idx].session_id.clone();
                    if rng.gen_bool(0.55) {
                        let approved = db
                            .local()
                            .approve_quarantined(&receipt, "human@cli", now_ms)
                            .unwrap();
                        assert_eq!(approved.gate_state, GateState::Pending);
                        oracle.mailbox[idx].gate_state = GateState::Pending;
                        oracle.audit_count += 1;
                    } else {
                        let opt_mute = if rng.gen_bool(0.4) {
                            Some(MuteRuleInput {
                                scope: sid,
                                pattern: "guest@ext/bot".into(),
                            })
                        } else {
                            None
                        };
                        let rejected = db
                            .local()
                            .reject_quarantined(
                                &receipt,
                                "human@cli",
                                "unsafe",
                                opt_mute.as_ref(),
                                now_ms,
                            )
                            .unwrap();
                        assert_eq!(rejected.gate_state, GateState::Rejected);
                        oracle.mailbox[idx].gate_state = GateState::Rejected;
                        if let Some(m) = opt_mute {
                            oracle.mutes.insert((m.scope, m.pattern));
                        }
                        oracle.audit_count += 1;
                    }
                }
            }

            // 14: Drain pending mailbox items for a session
            14 => {
                let sid = session_pool[rng.gen_range(0..session_pool.len())];
                let drained = db.local().drain_inbox(sid, 3, now_ms).unwrap();
                let mut oracle_pending_indices: Vec<usize> = oracle
                    .mailbox
                    .iter()
                    .enumerate()
                    .filter(|(_, m)| m.session_id == sid && m.gate_state == GateState::Pending)
                    .map(|(i, _)| i)
                    .collect();
                oracle_pending_indices.sort_by_key(|&i| {
                    (
                        oracle.mailbox[i].received_at,
                        oracle.mailbox[i].receipt.clone(),
                    )
                });
                let expected_ids: Vec<String> = oracle_pending_indices
                    .iter()
                    .take(3)
                    .map(|&i| oracle.mailbox[i].item_id.clone())
                    .collect();
                for &i in oracle_pending_indices.iter().take(3) {
                    oracle.mailbox[i].gate_state = GateState::Delivered;
                }
                let real_ids: Vec<String> = drained.into_iter().map(|e| e.item_id).collect();
                assert_eq!(
                    real_ids, expected_ids,
                    "seed=0x{seed:016x} step={step}: drain_inbox mismatch for {sid}"
                );
            }

            // 15: Ack a pending channel message
            15 => {
                let target_msg = oracle
                    .messages
                    .values()
                    .find(|m| m.state == "pending" && m.hold_until <= now_ms)
                    .cloned();
                if let Some(m) = target_msg {
                    let to_node = m.to_addr.rsplit_once('/').unwrap().0;
                    let outcome = if rng.gen_bool(0.3) {
                        AckOutcome::Hold {
                            reason: "busy".into(),
                            retry_after_ms: Some(4_000),
                        }
                    } else {
                        AckOutcome::Delivered
                    };
                    assert!(db.messages().ack(to_node, &m.id, &outcome, now_ms).unwrap());
                    let entry = oracle.messages.get_mut(&m.id).unwrap();
                    match outcome {
                        AckOutcome::Delivered => entry.state = "delivered",
                        AckOutcome::Hold { retry_after_ms, .. } => {
                            entry.hold_until = now_ms + retry_after_ms.unwrap_or(5_000);
                        }
                        AckOutcome::Rejected { .. } => entry.state = "rejected",
                    }
                }
            }

            // 16..=17: Bridge links (`add_bridge_link`, `remove_bridge_link`)
            16..=17 => {
                let plugin = plugins[rng.gen_range(0..plugins.len())];
                let target = bridge_targets[rng.gen_range(0..bridge_targets.len())];
                let sid = session_pool[rng.gen_range(0..session_pool.len())];
                bridge_link_ops += 1;
                if rng.gen_bool(0.65) {
                    let link = BridgeLink {
                        plugin: plugin.into(),
                        target: target.into(),
                        session_id: sid.into(),
                        linked_at: now_ms,
                        linked_by: format!("actor-{}", step % 3),
                    };
                    db.local().add_bridge_link(&link).unwrap();
                    oracle.add_bridge_link(&link);
                } else {
                    let target_sid = if rng.gen_bool(0.7) { Some(sid) } else { None };
                    let real_removed = db
                        .local()
                        .remove_bridge_link(plugin, target, target_sid)
                        .unwrap();
                    let oracle_removed = oracle.remove_bridge_link(plugin, target, target_sid);
                    assert_eq!(
                        real_removed, oracle_removed,
                        "seed=0x{seed:016x} step={step}: remove_bridge_link count mismatch"
                    );
                }
            }

            // 18: Plugin target handoffs (`set_plugin_target`, `remove_plugin_target`, primary holder)
            18 => {
                let plugin = plugins[rng.gen_range(0..plugins.len())];
                let target = bridge_targets[rng.gen_range(0..bridge_targets.len())];
                plugin_handoff_ops += 1;
                if rng.gen_bool(0.8) {
                    let live_sessions: Vec<String> = oracle.sessions.keys().cloned().collect();
                    let sid = live_sessions[rng.gen_range(0..live_sessions.len())].clone();
                    let handoff = PluginTargetHandoff {
                        plugin: plugin.into(),
                        target: target.into(),
                        session_id: sid,
                        set_at: now_ms,
                        set_by: format!("handoff-{}", step % 4),
                    };
                    db.local().set_plugin_target(&handoff).unwrap();
                    oracle.set_plugin_target(&handoff);
                } else {
                    let real_removed = db.local().remove_plugin_target(plugin, target).unwrap();
                    let oracle_removed = oracle.remove_plugin_target(plugin, target);
                    assert_eq!(
                        real_removed, oracle_removed,
                        "seed=0x{seed:016x} step={step}: remove_plugin_target mismatch"
                    );
                }
            }

            // 19..=20: Session lifecycle (register / touch / set_session_handle with UNIQUE conflict checks)
            19..=20 => {
                let sid = session_pool[rng.gen_range(0..session_pool.len())];
                match rng.gen_range(0..3) {
                    0 => {
                        let backend = format!(r#"{{"kind":"harness","step":{step}}}"#);
                        db.local().register_session(sid, &backend, now_ms).unwrap();
                        oracle.register_session(sid, &backend, now_ms);
                    }
                    1 => {
                        let real_touched = db.local().touch_session(sid, now_ms).unwrap();
                        let oracle_touched = oracle.touch_session(sid, now_ms);
                        assert_eq!(
                            real_touched, oracle_touched,
                            "seed=0x{seed:016x} step={step}: touch_session mismatch for {sid}"
                        );
                    }
                    _ => {
                        let handle = if rng.gen_bool(0.75) {
                            Some(session_handles[rng.gen_range(0..session_handles.len())])
                        } else {
                            None
                        };
                        let real_res = db.local().set_session_handle(sid, handle, now_ms);
                        let oracle_res = oracle.set_session_handle(sid, handle, now_ms);
                        match (&real_res, &oracle_res) {
                            (Ok(r), Ok(o)) => assert_eq!(
                                r, o,
                                "seed=0x{seed:016x} step={step}: set_session_handle bool mismatch"
                            ),
                            (Err(StoreError::IdConflict(_)), Err("id_conflict")) => {}
                            _ => panic!(
                                "seed=0x{seed:016x} step={step}: set_session_handle divergence real={real_res:?} oracle={oracle_res:?}"
                            ),
                        }
                    }
                }
            }

            // 21: Cascading `prune_sessions` cleanup (sessions, handles, mailbox, per-session mutes, bridge_links, plugin_targets)
            _ => {
                let mut active: HashSet<String> = HashSet::new();
                // Keep event-sub anchor sessions active, plus optionally protect one ephemeral session.
                active.insert("sess-0".into());
                active.insert("sess-1".into());
                if rng.gen_bool(0.3) {
                    active.insert("sess-2".into());
                }
                let cutoff = now_ms - rng.gen_range(1_500..8_000);
                let report = db.local().prune_sessions(cutoff, &active).unwrap();
                let real_pruned: BTreeSet<String> = report.pruned_sessions.into_iter().collect();
                let oracle_pruned = oracle.prune_sessions(cutoff, &active);
                assert_eq!(
                    real_pruned, oracle_pruned,
                    "seed=0x{seed:016x} step={step}: prune_sessions set mismatch (cutoff={cutoff})"
                );
                pruned_session_count += real_pruned.len();
            }
        }

        // =====================================================================
        // FULL POST-STEP STATE EQUIVALENCE ASSERTION
        // =====================================================================

        // 1. Live KV entries identical (keys, versions, values).
        let real_kv = db.kv().list("local", "shared", None, now_ms).unwrap();
        let oracle_kv: Vec<(String, u64, String)> = oracle
            .kv
            .iter()
            .filter(|((h, ns, _), e)| {
                h == "local" && ns == "shared" && e.expires_at.is_none_or(|exp| exp > now_ms)
            })
            .map(|((_, _, k), e)| (k.clone(), e.version, e.value_json.clone()))
            .collect();
        let real_kv_norm: Vec<(String, u64, String)> = real_kv
            .into_iter()
            .map(|e| (e.key, e.version, serde_json::to_string(&e.value).unwrap()))
            .collect();
        assert_eq!(
            real_kv_norm, oracle_kv,
            "seed=0x{seed:016x} step={step}: KV state diverged"
        );

        // 2. Enrolled router handles identical.
        let real_handles: BTreeSet<(String, String)> = db
            .messages()
            .list_handles(None)
            .unwrap()
            .into_iter()
            .map(|h| (h.node_id, h.handle))
            .collect();
        let oracle_handles: BTreeSet<(String, String)> = oracle.handles.keys().cloned().collect();
        assert_eq!(
            real_handles, oracle_handles,
            "seed=0x{seed:016x} step={step}: handles diverged"
        );

        // 3. Channel memberships identical.
        for ch in channels {
            let real_members = db.channels().members("acme-team", ch).unwrap();
            let oracle_members: Vec<String> = oracle
                .channel_members
                .get(&("acme-team".into(), ch.into()))
                .map(|set| {
                    set.iter()
                        .filter(|a| oracle.is_enrolled(a))
                        .cloned()
                        .collect()
                })
                .unwrap_or_default();
            assert_eq!(
                real_members, oracle_members,
                "seed=0x{seed:016x} step={step}: channel '{ch}' members diverged"
            );
        }

        // 4. Pending channel messages identical (INCLUDING exact verbatim text!).
        for (id, om) in &oracle.messages {
            let rm = db.messages().get_message(id).unwrap().unwrap();
            assert_eq!(
                rm.text, om.text,
                "seed=0x{seed:016x} step={step}: message '{id}' text was mutated!"
            );
            assert_eq!(rm.channel, om.channel);
            assert_eq!(rm.state.as_str(), om.state);
        }

        // 5. Event batch states & event counts per subscription identical.
        for sub_id in ["sub-kv", "sub-gh"] {
            let real_batches: Vec<(BatchState, usize)> = db
                .events()
                .list_batches(sub_id)
                .unwrap()
                .into_iter()
                .map(|b| (b.state, b.event_count))
                .collect();
            let oracle_batches: Vec<(BatchState, usize)> = oracle
                .batches
                .iter()
                .filter(|b| b.subscription_id == sub_id)
                .map(|b| (b.state, b.event_ids.len()))
                .collect();
            assert_eq!(
                real_batches, oracle_batches,
                "seed=0x{seed:016x} step={step}: event batches diverged for '{sub_id}'"
            );
        }

        // 6. Sessions & session handles identical (verifying cascading prune_sessions cleanup!).
        let real_sessions: BTreeMap<String, OracleSession> = db
            .local()
            .list_sessions()
            .unwrap()
            .into_iter()
            .map(|s| {
                (
                    s.id.clone(),
                    OracleSession {
                        id: s.id,
                        backend_json: s.backend_json,
                        handle: s.handle,
                        last_seen: s.last_seen,
                        created_at: s.created_at,
                    },
                )
            })
            .collect();
        assert_eq!(
            real_sessions, oracle.sessions,
            "seed=0x{seed:016x} step={step}: sessions table diverged"
        );
        let real_session_handles = db.local().list_session_handles().unwrap();
        let mut oracle_session_handles: Vec<String> = oracle
            .sessions
            .values()
            .filter_map(|s| s.handle.clone())
            .collect();
        oracle_session_handles.sort();
        assert_eq!(
            real_session_handles, oracle_session_handles,
            "seed=0x{seed:016x} step={step}: session handles diverged"
        );

        // 7. Mailbox pending, quarantined, muted items & mutes identical across ALL sessions
        //    (zero quarantine/muted leaks into `peek_inbox`, muted items remain queryable!).
        for &sid in &session_pool {
            let real_pending: BTreeMap<String, String> = db
                .local()
                .peek_inbox(sid, 1_000)
                .unwrap()
                .into_iter()
                .map(|e| (e.item_id, e.text))
                .collect();
            let oracle_pending: BTreeMap<String, String> = oracle
                .mailbox
                .iter()
                .filter(|m| m.session_id == sid && m.gate_state == GateState::Pending)
                .map(|m| (m.item_id.clone(), m.text.clone()))
                .collect();
            assert_eq!(
                real_pending, oracle_pending,
                "seed=0x{seed:016x} step={step}: pending mailbox diverged for '{sid}'"
            );
            assert_eq!(
                db.local().pending_count(sid).unwrap(),
                oracle_pending.len(),
                "seed=0x{seed:016x} step={step}: pending_count diverged for '{sid}'"
            );

            let real_quarantined: BTreeSet<String> = db
                .local()
                .list_quarantined(Some(sid), 1_000)
                .unwrap()
                .into_iter()
                .map(|e| e.item_id)
                .collect();
            let oracle_quarantined: BTreeSet<String> = oracle
                .mailbox
                .iter()
                .filter(|m| m.session_id == sid && m.gate_state == GateState::Quarantined)
                .map(|m| m.item_id.clone())
                .collect();
            assert_eq!(
                real_quarantined, oracle_quarantined,
                "seed=0x{seed:016x} step={step}: quarantined mailbox diverged for '{sid}'"
            );

            let real_muted_entries = query_muted_in_store(&db, sid);
            let real_muted_map: BTreeMap<String, (String, String)> = real_muted_entries
                .iter()
                .map(|e| (e.item_id.clone(), (e.origin_node.clone(), e.text.clone())))
                .collect();
            let oracle_muted_map: BTreeMap<String, (String, String)> = oracle
                .mailbox
                .iter()
                .filter(|m| m.session_id == sid && m.muted)
                .map(|m| (m.item_id.clone(), (m.origin_node.clone(), m.text.clone())))
                .collect();
            assert_eq!(
                real_muted_map, oracle_muted_map,
                "seed=0x{seed:016x} step={step}: muted mailbox items diverged for '{sid}'"
            );
            assert_eq!(
                muted_count_in_store(&db, sid),
                oracle_muted_map.len(),
                "seed=0x{seed:016x} step={step}: muted_count diverged for '{sid}'"
            );
            // Security/UX invariant: muted items MUST NEVER appear in peek_inbox!
            for muted_item_id in oracle_muted_map.keys() {
                assert!(
                    !real_pending.contains_key(muted_item_id),
                    "seed=0x{seed:016x} step={step}: muted item '{muted_item_id}' leaked into peek_inbox for '{sid}'"
                );
            }
            for entry in &real_muted_entries {
                assert_eq!(
                    db.local()
                        .get_delivery(&entry.origin_node, &entry.item_id)
                        .unwrap()
                        .as_deref(),
                    Some("muted"),
                    "seed=0x{seed:016x} step={step}: muted item missing delivery='muted' state"
                );
            }

            // Per-session + global mutes identical (verifies prune_sessions cleans per-session mutes only).
            let real_mutes: BTreeSet<(String, String)> = db
                .local()
                .list_mutes(Some(sid))
                .unwrap()
                .into_iter()
                .map(|m| (m.scope, m.pattern))
                .collect();
            let oracle_mutes: BTreeSet<(String, String)> = oracle
                .mutes
                .iter()
                .filter(|(scope, _)| scope == "*" || scope == sid)
                .cloned()
                .collect();
            assert_eq!(
                real_mutes, oracle_mutes,
                "seed=0x{seed:016x} step={step}: muted_sources diverged for '{sid}'"
            );

            // Bridge links per session identical.
            let real_sess_links = db.local().bridge_links_for_session(sid).unwrap();
            let oracle_sess_links = oracle.bridge_links_for_session(sid);
            assert_eq!(
                real_sess_links, oracle_sess_links,
                "seed=0x{seed:016x} step={step}: bridge_links_for_session diverged for '{sid}'"
            );
        }

        // 8. Bridge links per `(plugin, target)` and `plugin_targets` handoffs identical.
        for &plugin in &plugins {
            for &target in &bridge_targets {
                let real_links = db.local().bridge_links(plugin, target).unwrap();
                let oracle_links = oracle.bridge_links(plugin, target);
                assert_eq!(
                    real_links, oracle_links,
                    "seed=0x{seed:016x} step={step}: bridge_links({plugin}, {target}) diverged"
                );

                let real_handoff = db.local().get_plugin_target(plugin, target).unwrap();
                let oracle_handoff = oracle.get_plugin_target(plugin, target);
                assert_eq!(
                    real_handoff, oracle_handoff,
                    "seed=0x{seed:016x} step={step}: plugin_target({plugin}, {target}) diverged"
                );
            }
        }

        // 9. Immutable gate_audit review count identical.
        let real_audit_reviews = db
            .local()
            .query_gate_audit(&hyp_store::GateAuditQuery {
                direction: Some(GateDirection::Review),
                decision: None,
                session_id: None,
                since_ms: None,
                until_ms: None,
                limit: None,
            })
            .unwrap()
            .len();
        assert_eq!(
            real_audit_reviews, oracle.audit_count,
            "seed=0x{seed:016x} step={step}: gate_audit review count diverged"
        );
        let _ = GateDecision::Allow;
    }

    if steps >= 250 {
        assert!(
            muted_transitions > 0
                && bridge_link_ops > 0
                && plugin_handoff_ops > 0
                && pruned_session_count > 0,
            "seed=0x{seed:016x}: insufficient coverage across new ops (muted={muted_transitions}, bridge_links={bridge_link_ops}, handoffs={plugin_handoff_ops}, pruned_sessions={pruned_session_count})"
        );
    }
}

#[test]
fn differential_oracle_500_steps_primary_seed() {
    run_differential_seed(resolve_seed(0x5EED_CAFE_0001), 500);
}

#[test]
fn differential_oracle_multi_seed_matrix() {
    if std::env::var("HYPHAE_TEST_SEED").is_ok() {
        run_differential_seed(resolve_seed(0xA11C_E001), 250);
    } else {
        for seed in [0xA11C_E001u64, 0xB0B0_2026u64, 0xCA75_DEADu64] {
            run_differential_seed(seed, 250);
        }
    }
}
