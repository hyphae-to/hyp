//! Universal 3-tier delivery urgency (`interrupt`/`queue`/`notify` + silent `mute` archive),
//! Focus Mode (`* -> notify`), adaptive Burst Protection ("noisy mode"),
//! token-budget-aware hybrid batch packing, and filtered paginated inbox queries
//! (`docs/architecture-v2.md` §2.5).

pub mod burst;
pub mod inbox_query;
pub mod packer;
pub mod policy;

use std::collections::HashMap;
use std::sync::Mutex;

use hyp_store::{MailboxEntry, NodeDb};

pub use burst::{BurstAssessment, BurstTracker};
pub use inbox_query::{
    InboxFilter, InboxItemState, InboxItemView, InboxQuery, InboxQueryResult, InboxStateFilter,
    archive_muted_entry, load_session_policy, move_pending_to_muted, muted_count, query_inbox,
    record_delivered_receipts, save_session_policy,
};
pub use packer::{
    PackableItem, PackedDeliveryBatch, QuarantineDigestNotice, estimate_tokens,
    pack_delivery_batch, pack_inbox_digest, xml_escape_attr,
};
pub use policy::{
    BurstProtectionConfig, DEFAULT_BURST_MAX_EVENTS_PER_WINDOW,
    DEFAULT_BURST_MIN_DELIVERY_INTERVAL_SECS, DEFAULT_BURST_NOISY_COOLDOWN_SECS,
    DEFAULT_BURST_WINDOW_SECS, DEFAULT_MAX_BATCH_TOKENS, DEFAULT_MAX_INLINE_ITEMS,
    DEFAULT_MAX_SINGLE_ITEM_SHARE, DEFAULT_MIDTURN_QUEUE_DIGEST_SECONDS, DeliveryError,
    DeliveryRule, DeliveryTargetContext, DeliveryUrgency, ParsedMailboxSource,
    SessionDeliveryPolicy, gate_reason_urgency_cap,
};

/// Result of classifying a single inbound item through [`DeliveryEngine`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryClassification {
    /// Urgency computed from session policy, Focus Mode, overrides, and Stage 1 downgrade.
    pub policy_urgency: DeliveryUrgency,
    /// Final urgency after applying per-source Adaptive Burst Protection.
    pub effective_urgency: DeliveryUrgency,
    /// Burst tracker assessment (Noisy Mode / demotion / delivery interval throttle).
    pub burst: BurstAssessment,
    /// Normalized source key used for burst tracking.
    pub burst_source_key: String,
    /// Parsed structured source attributes.
    pub parsed: ParsedMailboxSource,
}

/// Stateful per-session delivery engine combining [`SessionDeliveryPolicy`], [`BurstTracker`],
/// [`pack_delivery_batch`], and [`query_inbox`].
#[derive(Debug, Default)]
pub struct DeliveryEngine {
    policies: Mutex<HashMap<String, SessionDeliveryPolicy>>,
    bursts: Mutex<HashMap<String, BurstTracker>>,
}

impl DeliveryEngine {
    pub fn new() -> Self {
        Self::default()
    }

    /// Loads or returns the cached [`SessionDeliveryPolicy`] for `session_id`.
    pub fn policy(
        &self,
        db: &NodeDb,
        session_id: &str,
    ) -> Result<SessionDeliveryPolicy, DeliveryError> {
        {
            let guard = self.policies.lock().expect("policies lock poisoned");
            if let Some(p) = guard.get(session_id) {
                return Ok(p.clone());
            }
        }
        let loaded = load_session_policy(db, session_id)?;
        let mut guard = self.policies.lock().expect("policies lock poisoned");
        guard.insert(session_id.to_string(), loaded.clone());
        Ok(loaded)
    }

    /// Updates and persists a session's [`SessionDeliveryPolicy`].
    pub fn set_policy(
        &self,
        db: &NodeDb,
        session_id: &str,
        policy: SessionDeliveryPolicy,
    ) -> Result<(), DeliveryError> {
        for rule in &policy.overrides {
            rule.validate()?;
        }
        save_session_policy(db, session_id, &policy)?;
        let mut guard = self.policies.lock().expect("policies lock poisoned");
        guard.insert(session_id.to_string(), policy);
        Ok(())
    }

    /// Mutates and persists a session's policy atomically.
    pub fn update_policy<F>(
        &self,
        db: &NodeDb,
        session_id: &str,
        f: F,
    ) -> Result<SessionDeliveryPolicy, DeliveryError>
    where
        F: FnOnce(&mut SessionDeliveryPolicy),
    {
        let mut current = self.policy(db, session_id)?;
        f(&mut current);
        self.set_policy(db, session_id, current.clone())?;
        Ok(current)
    }

    /// Classifies an inbound mailbox entry using the session's policy + per-source burst tracker.
    pub fn classify_entry(
        &self,
        db: &NodeDb,
        session_id: &str,
        entry: &MailboxEntry,
        subscription_mode: Option<DeliveryUrgency>,
        gate_downgraded_to_notify: bool,
        now_ms: i64,
    ) -> Result<DeliveryClassification, DeliveryError> {
        self.classify_entry_with_cap(
            db,
            session_id,
            entry,
            subscription_mode,
            gate_downgraded_to_notify.then_some(DeliveryUrgency::Notify),
            now_ms,
        )
    }

    /// Classifies an inbound mailbox entry with an explicit optional Stage 1 urgency ceiling
    /// (`Some(DeliveryUrgency::Queue)` for `CapToQueue` or `Some(DeliveryUrgency::Notify)` for
    /// `DowngradeToNotify`).
    pub fn classify_entry_with_cap(
        &self,
        db: &NodeDb,
        session_id: &str,
        entry: &MailboxEntry,
        subscription_mode: Option<DeliveryUrgency>,
        gate_max_urgency: Option<DeliveryUrgency>,
        now_ms: i64,
    ) -> Result<DeliveryClassification, DeliveryError> {
        let policy = self.policy(db, session_id)?;
        let parsed = ParsedMailboxSource::from_entry(entry);
        let policy_urgency = policy.resolve_urgency_with_cap(
            &parsed.as_context(),
            subscription_mode,
            gate_max_urgency,
        );
        let burst_key = parsed.burst_source_key();
        let burst = {
            let mut guard = self.bursts.lock().expect("bursts lock poisoned");
            let tracker = guard.entry(session_id.to_string()).or_default();
            tracker.record_and_evaluate(&burst_key, policy_urgency, &policy.burst, now_ms)
        };
        Ok(DeliveryClassification {
            policy_urgency,
            effective_urgency: burst.effective_urgency,
            burst,
            burst_source_key: burst_key,
            parsed,
        })
    }

    /// Records a completed delivery for `source_key` on `session_id` (updates `min_delivery_interval_secs`).
    pub fn record_delivery(&self, session_id: &str, source_key: &str, now_ms: i64) {
        let mut guard = self.bursts.lock().expect("bursts lock poisoned");
        let tracker = guard.entry(session_id.to_string()).or_default();
        tracker.record_delivery(source_key, now_ms);
    }

    /// Returns whether `source_key` on `session_id` is currently in Noisy Mode.
    pub fn is_source_noisy(&self, session_id: &str, source_key: &str, now_ms: i64) -> bool {
        let guard = self.bursts.lock().expect("bursts lock poisoned");
        guard
            .get(session_id)
            .is_some_and(|t| t.is_noisy(source_key, now_ms))
    }

    /// Queries a session's mailbox via [`query_inbox`].
    pub fn query_inbox(
        &self,
        db: &NodeDb,
        session_id: &str,
        query: &InboxQuery,
        now_ms: i64,
    ) -> Result<InboxQueryResult, DeliveryError> {
        query_inbox(db, session_id, query, now_ms)
    }
}
