//! Inbox screening, digest reads and commits, and live delivery routing.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use hyp_delivery_digest::selection::needs_midturn_reminder_timestamp;
use hyp_delivery_digest::{
    BuiltDigestBatch, DigestCandidate, DigestPolicy, DrainScope, InboxDigest, build_digest,
};
use hyp_harness_transport::transport::herdr::is_valid_herdr_template;
use hyp_harness_transport::transport::openclaw::{
    REASON_OPENCLAW_GATEWAY_UNAVAILABLE, REASON_OPENCLAW_INVALID_SESSION_KEY,
    REASON_OPENCLAW_SESSION_MISSING,
};
use hyp_harness_transport::transport::{PushMode, PushOutcome};
use hyp_node::delivery::{
    DeliveryUrgency, PackableItem, PackedDeliveryBatch, gate_reason_urgency_cap,
    move_pending_to_muted, muted_count, strictest_urgency_cap, urgency_cap_gate_reason,
};
use hyp_node::engine::ChannelMode;
use hyp_node::gates::{GateDecision, InboundContext, TrustTier as GateTrustTier};
use hyp_proto::cloudevent::{CONTENT_TYPE_JSON, CloudEvent as ProtoCloudEvent};
use hyp_store::{
    DaemonNoticeKind, GateState, MailboxEntry, MailboxKind, MailboxVisibility, parse_address,
    sha256_hex,
};
use serde_json::json;
use tokio::sync::oneshot;

use super::{
    ChannelDeliverCommand, ClassifiedItemMeta, ClaudeChannelWake, DaemonStateLock,
    LocalDaemonInner, OpenClawWakeAck, OpenClawWakeCommand, SessionFlushMode,
    SubscriptionRecordMeta, TransportHints, WaiterKind, cap_trust_tier_to_external_webhook,
    extract_backend_str, maybe_spawn_transport_probe, parse_gate_trust_tier, parse_human_auth_meta,
    raw_has_external_webhook_origin,
};

impl LocalDaemonInner {
    pub(super) fn is_announcement_channel(&self, channel: Option<&str>) -> bool {
        let Some(ch) = channel else {
            return false;
        };
        self.node.get_channel_policy(ch).mode == ChannelMode::Announcement
    }

    /// Finds the session subscription matching a mailbox entry's `origin_node` + `source`
    /// (`<origin>.<topic>`, or `local.<topic>` for this node) and projects it through `pick`.
    fn lookup_subscription<T>(
        &self,
        session_id: &str,
        origin_node: &str,
        source: &str,
        pick: impl FnOnce(&SubscriptionRecordMeta) -> Option<T>,
    ) -> Option<T> {
        let guard = self.sub_meta.lock_state("sub_meta lock poisoned");
        let list = guard.get(session_id)?;
        let src_low = source.to_ascii_lowercase();
        let origin_low = origin_node.to_ascii_lowercase();
        let my_id_low = self.node.node_id().as_str().to_ascii_lowercase();
        list.iter()
            .find(|s| {
                let s_orig = s.origin_node.to_ascii_lowercase();
                let s_topic = s.topic.to_ascii_lowercase();
                let expected = format!("{s_orig}.{s_topic}");
                src_low == expected
                    || (origin_low == s_orig && src_low.ends_with(&format!(".{s_topic}")))
                    || ((s_orig == "local" || s_orig == my_id_low)
                        && (origin_low == "local" || origin_low == my_id_low)
                        && src_low == format!("local.{s_topic}"))
            })
            .and_then(pick)
    }

    pub(super) fn lookup_subscription_urgency(
        &self,
        session_id: &str,
        origin_node: &str,
        source: &str,
    ) -> Option<DeliveryUrgency> {
        self.lookup_subscription(session_id, origin_node, source, |s| Some(s.urgency))
    }

    fn lookup_subscription_key(
        &self,
        session_id: &str,
        origin_node: &str,
        source: &str,
    ) -> Option<String> {
        self.lookup_subscription(session_id, origin_node, source, |s| {
            s.key.clone().filter(|k| !k.trim().is_empty())
        })
    }

    pub(super) fn record_item_meta(
        &self,
        session_id: &str,
        receipt: String,
        meta: ClassifiedItemMeta,
    ) {
        let mut guard = self.item_meta.lock_state("item_meta lock poisoned");
        guard
            .entry(session_id.to_string())
            .or_default()
            .insert(receipt, meta);
    }

    /// Reconciles any newly arrived raw `Pending` entries in `NodeDb` for `session_id` through
    /// optional `SecurityGatePipeline` + `DeliveryEngine`:
    /// - Serialized per `session_id` via an async mutex so concurrent reconciles NEVER double-classify
    ///   items or race past Stage 2 awaits (G3).
    /// - `Allow` items are durably promoted (`reviewed_at = now_ms`) before exposure to delivery/inbox.
    /// - `Quarantine` / `Block` items are transitioned in place to `quarantined` / `rejected` (never
    ///   leaked as `delivered` or visible to agents).
    /// - `Hold` items (`rate_limited`, `gate_busy`) are retained untouched (`reviewed_at = NULL`,
    ///   invisible to agents) and scheduled for a bounded delayed retry (G4).
    /// - `Mute` items are silently archived (`move_pending_to_muted`) and NEVER trigger a wake.
    /// - `Interrupt`/`Queue`/`Notify` items are tagged with their resolved urgency & burst metadata.
    ///
    /// Returns `true` if at least one non-muted gate-cleared item is eligible for delivery/digest wake.
    pub(super) async fn reconcile_session_inbox(self: &Arc<Self>, session_id: &str) -> bool {
        let _reconcile_guard = self.reconcile_lock_for(session_id).lock_owned().await;
        self.sweep_expired_mutes_and_policies(self.current_time_ms());

        let mut wake_needed = false;
        let mut held_in_this_call: HashSet<String> = HashSet::new();
        let mut held_min_retry_ms: Option<u64> = None;

        // Loop up to a bounded number of passes so items arriving mid-Stage-2-await are screened
        // before releasing the per-session reconcile lock (G3).
        for _pass in 0..8 {
            let pending = {
                let db = self.node.db();
                db.local().peek_inbox(session_id, 500).unwrap_or_default()
            };
            if pending.is_empty() {
                break;
            }

            let now = self.current_time_ms();
            let mut processed_any = false;

            for entry in pending {
                if held_in_this_call.contains(&entry.receipt) {
                    continue;
                }

                let already_dismissed = self
                    .dismissed_receipts
                    .lock_state("dismissed lock poisoned")
                    .contains(&entry.receipt);
                if already_dismissed {
                    let db = self.node.db();
                    let _ = db.local().transition_mailbox_gate_state(
                        session_id,
                        &entry.receipt,
                        GateState::Rejected,
                        Some("gate_dismissed"),
                        now,
                    );
                    processed_any = true;
                    continue;
                }

                // Items already explicitly approved by a human operator (`reviewed_at.is_some()`),
                // previously promoted by `SecurityGatePipeline` (`reviewed_at.is_some()`), or
                // carrying verified human authority (`mailbox.human_auth_json` present) skip re-gating.
                let already_human_verified = {
                    let db = self.node.db();
                    db.human()
                        .get_mailbox_human_auth(&entry.receipt)
                        .ok()
                        .flatten()
                        .is_some()
                };
                let active_gate = self.current_gate();
                let needs_gate =
                    active_gate.is_some() && entry.reviewed_at.is_none() && !already_human_verified;

                if needs_gate {
                    // G3: Clear any stale cached classification before screening (e.g. after a
                    // coalesced UPDATE overwrote `text` and reset `reviewed_at` / `human_auth_json`).
                    let mut guard = self.item_meta.lock_state("item_meta lock poisoned");
                    if let Some(map) = guard.get_mut(session_id) {
                        map.remove(&entry.receipt);
                    }
                } else {
                    let existing_meta = {
                        let mut guard = self.item_meta.lock_state("item_meta lock poisoned");
                        let cached = guard
                            .get(session_id)
                            .and_then(|m| m.get(&entry.receipt).cloned());
                        match cached {
                            Some(meta)
                                if meta.item_id == entry.item_id
                                    && meta.payload_sha256 == entry.payload_sha256
                                    && (entry.notified || !meta.notified) =>
                            {
                                Some(meta)
                            }
                            Some(_) => {
                                // G3: Coalesced overwrite changed item_id / payload_sha256 / notified;
                                // invalidate cached classification so it is re-classified cleanly!
                                if let Some(map) = guard.get_mut(session_id) {
                                    map.remove(&entry.receipt);
                                }
                                None
                            }
                            None => None,
                        }
                    };
                    if let Some(meta) = existing_meta {
                        if meta.urgency.triggers_delivery_or_digest() && !meta.notified {
                            wake_needed = true;
                        }
                        continue;
                    }
                }

                processed_any = true;
                let mut gate_cap = gate_reason_urgency_cap(entry.gate_reason.as_deref());

                if needs_gate {
                    if let Some(pipeline) = active_gate {
                        let parsed = hyp_node::delivery::ParsedMailboxSource::from_entry(&entry);
                        let effective_origin = self.effective_gate_origin(&entry, &parsed);
                        let trust_tier = self.resolve_entry_trust_tier(&entry, &effective_origin);
                        let ce = ProtoCloudEvent {
                            specversion: "1.0".into(),
                            id: entry.item_id.clone(),
                            source: entry.source.clone(),
                            event_type: format!("to.hyphae.mailbox.{}", entry.kind.as_str()),
                            datacontenttype: Some(CONTENT_TYPE_JSON.into()),
                            dataschema: None,
                            subject: parsed.channel.clone().or(parsed.topic.clone()),
                            time: None,
                            data: Some(json!({ "text": entry.text })),
                            data_base64: None,
                            extensions: BTreeMap::new(),
                        };
                        let ctx = InboundContext {
                            session_id: session_id.to_string(),
                            origin_node: effective_origin,
                            sender: entry.source.clone(),
                            trust_tier,
                            e2ee_verified: true,
                            identity_verified: true,
                            kind: entry.kind,
                            channel: parsed.channel,
                            topic: parsed.topic,
                            bridge: parsed.bridge,
                            event: ce,
                            transfer_paths: Vec::new(),
                            rendered_text: Some(entry.text.clone()),
                            human_auth: None,
                        };
                        match pipeline
                            .evaluate_existing_mailbox_entry(&entry.receipt, &ctx, now)
                            .await
                        {
                            Ok(eval) => match eval.decision {
                                GateDecision::Allow { max_urgency } => {
                                    gate_cap = strictest_urgency_cap(gate_cap, max_urgency);
                                    let reason_str = urgency_cap_gate_reason(gate_cap);
                                    // Ensure `self.node.db()` records gate approval even if the
                                    // pipeline uses a separate `NodeDb` handle.
                                    let db = self.node.db();
                                    let _ = db.local().mark_mailbox_gate_approved(
                                        session_id,
                                        &entry.receipt,
                                        reason_str,
                                        now,
                                    );
                                }
                                GateDecision::Quarantine { reason, .. } => {
                                    let db = self.node.db();
                                    let _ = db.local().transition_mailbox_gate_state(
                                        session_id,
                                        &entry.receipt,
                                        GateState::Quarantined,
                                        Some(&reason),
                                        now,
                                    );
                                    drop(db);
                                    self.record_quarantine_notice(
                                        session_id,
                                        Some(&entry.receipt),
                                        &entry.source,
                                        trust_tier,
                                        &reason,
                                        now,
                                    );
                                    let mut guard =
                                        self.item_meta.lock_state("item_meta lock poisoned");
                                    if let Some(map) = guard.get_mut(session_id) {
                                        map.remove(&entry.receipt);
                                    }
                                    continue;
                                }
                                GateDecision::Block { reason } => {
                                    let db = self.node.db();
                                    let _ = db.local().transition_mailbox_gate_state(
                                        session_id,
                                        &entry.receipt,
                                        GateState::Rejected,
                                        Some(&reason),
                                        now,
                                    );
                                    let mut guard =
                                        self.item_meta.lock_state("item_meta lock poisoned");
                                    if let Some(map) = guard.get_mut(session_id) {
                                        map.remove(&entry.receipt);
                                    }
                                    continue;
                                }
                                GateDecision::Hold { retry_after_ms, .. } => {
                                    // G4 (P0): Do NOT acknowledge or delete the mailbox row! Keep it
                                    // unscreened (`reviewed_at = NULL`, invisible to agents) and
                                    // schedule a bounded delayed retry after `retry_after_ms`.
                                    held_in_this_call.insert(entry.receipt.clone());
                                    held_min_retry_ms = Some(
                                        held_min_retry_ms
                                            .map_or(retry_after_ms, |m| m.min(retry_after_ms)),
                                    );
                                    continue;
                                }
                            },
                            Err(_) => {
                                // Fail closed on gate error: quarantine in place (never mark delivered).
                                let db = self.node.db();
                                let _ = db.local().transition_mailbox_gate_state(
                                    session_id,
                                    &entry.receipt,
                                    GateState::Quarantined,
                                    Some("gate_evaluation_error"),
                                    now,
                                );
                                drop(db);
                                self.record_quarantine_notice(
                                    session_id,
                                    Some(&entry.receipt),
                                    &entry.source,
                                    trust_tier,
                                    "gate_evaluation_error",
                                    now,
                                );
                                let mut guard =
                                    self.item_meta.lock_state("item_meta lock poisoned");
                                if let Some(map) = guard.get_mut(session_id) {
                                    map.remove(&entry.receipt);
                                }
                                continue;
                            }
                        }
                    }
                }

                if let Some(u) = self
                    .classify_and_route_pending_entry(session_id, &entry.receipt, gate_cap, now)
                    .await
                {
                    if u.triggers_delivery_or_digest() {
                        wake_needed = true;
                    }
                }
            }

            if !processed_any {
                break;
            }
        }

        if let Some(retry_ms) = held_min_retry_ms {
            self.schedule_gate_hold_retry(session_id, retry_ms);
        } else {
            self.cancel_gate_hold_retry(session_id);
        }

        wake_needed
    }

    pub(super) async fn classify_and_route_pending_entry(
        &self,
        session_id: &str,
        receipt: &str,
        gate_cap: Option<DeliveryUrgency>,
        now: i64,
    ) -> Option<DeliveryUrgency> {
        let entry = {
            let db = self.node.db();
            db.local().get_mailbox_entry(receipt).ok().flatten()?
        };
        if entry.gate_state != GateState::Pending {
            return None;
        }
        let sub_mode =
            self.lookup_subscription_urgency(session_id, &entry.origin_node, &entry.source);
        let classification = {
            let db = self.node.db();
            self.delivery
                .classify_entry(&db, session_id, &entry, sub_mode, gate_cap, now)
                .ok()?
        };

        if classification.effective_urgency == DeliveryUrgency::Mute {
            let db = self.node.db();
            let _ = move_pending_to_muted(&db, session_id, &entry, now);
            return Some(DeliveryUrgency::Mute);
        }

        let is_announcement =
            self.is_announcement_channel(classification.parsed.channel.as_deref());
        let is_wake_notice = entry.trusted_daemon_notice(self.node.node_id().as_str())
            == Some(DaemonNoticeKind::Wake);
        self.record_item_meta(
            session_id,
            entry.receipt,
            ClassifiedItemMeta {
                item_id: entry.item_id,
                payload_sha256: entry.payload_sha256,
                urgency: classification.effective_urgency,
                burst_demoted: classification.burst.demoted,
                burst_source_key: classification.burst_source_key,
                channel: classification.parsed.channel,
                is_announcement,
                notified: entry.notified,
                claude_channel_wake: ClaudeChannelWake::Fresh,
                is_wake_notice,
            },
        );
        Some(classification.effective_urgency)
    }

    /// Defense-in-depth origin node resolution for Security Gate trust-tier classification.
    ///
    /// Even if a legacy or Direct P2P mailbox entry recorded `origin_node == self.node.node_id()`
    /// (or `"local"`), any entry whose sender address belongs to a remote peer MUST resolve
    /// against that remote peer node so it can never be misclassified as `GateTrustTier::SelfHost`.
    fn effective_gate_origin(
        &self,
        entry: &MailboxEntry,
        parsed: &hyp_node::delivery::ParsedMailboxSource,
    ) -> String {
        let my_id = self.node.node_id().as_str();
        if entry.origin_node == "local" || entry.origin_node == my_id {
            let remote_sender_node = parsed
                .sender_addr
                .as_deref()
                .and_then(parse_address)
                .map(|(node, _)| node)
                .or_else(|| parse_address(&entry.source).map(|(node, _)| node))
                .or_else(|| {
                    (entry.kind == MailboxKind::Transfer && !entry.source.is_empty())
                        .then_some(entry.source.as_str())
                });
            if let Some(sender_node) = remote_sender_node {
                if sender_node != "local" && sender_node != my_id {
                    return sender_node.to_string();
                }
            }
        }
        entry.origin_node.clone()
    }

    /// Resolves the fail-closed [`GateTrustTier`] for an unverified inbound mailbox entry (G2 + Hub Tier Cap).
    ///
    /// Security invariants:
    /// - `MailboxKind::Plugin` and `bridge:*` origins ALWAYS resolve to `GateTrustTier::Bridge`.
    /// - ALL `MailboxKind::Event` items (both local AND hub-relayed remote events!) and ANY item
    ///   whose source/envelope indicates webhook/adapter origin or `hyphaesourcekind == "external-webhook"`
    ///   are strictly capped at `ExternalWebhook` (keeping `Bridge` if already `Bridge`), so a
    ///   GitHub/external webhook ingested by an `Org` Team Hub NEVER skips Stage 2 as `Org`!
    /// - Local `MailboxKind::Kv` resolves to `GateTrustTier::ExternalWebhook` (`G2`).
    /// - Only genuine same-node `MailboxKind::Message` DMs/posts (without external-webhook origin)
    ///   resolve to `GateTrustTier::SelfHost`.
    /// - Remote origins can NEVER escalate to `GateTrustTier::SelfHost`.
    fn resolve_entry_trust_tier(
        &self,
        entry: &MailboxEntry,
        effective_origin: &str,
    ) -> GateTrustTier {
        if entry.kind == MailboxKind::Plugin || effective_origin.starts_with("bridge:") {
            return GateTrustTier::Bridge;
        }

        let is_webhook_or_event = entry.kind == MailboxKind::Event
            || raw_has_external_webhook_origin(&entry.source, &entry.text);

        let is_local_origin =
            effective_origin == "local" || effective_origin == self.node.node_id().as_str();

        // Preserve explicit non-SelfHost trust tier recorded when `ingest_inbound` retained a Hold,
        // still enforcing the ExternalWebhook cap on events/webhooks!
        if let Some(held_tier) = entry
            .gate_reason
            .as_deref()
            .and_then(|r| r.strip_prefix("gate_held:"))
            .and_then(parse_gate_trust_tier)
        {
            match held_tier {
                GateTrustTier::SelfHost | GateTrustTier::HumanVerified => {}
                other => {
                    return if is_webhook_or_event {
                        cap_trust_tier_to_external_webhook(other)
                    } else {
                        other
                    };
                }
            }
        }

        if is_local_origin {
            if is_webhook_or_event {
                return GateTrustTier::ExternalWebhook;
            }
            return match entry.kind {
                MailboxKind::Message => GateTrustTier::SelfHost,
                MailboxKind::Event | MailboxKind::Kv => GateTrustTier::ExternalWebhook,
                MailboxKind::Transfer => GateTrustTier::Peer,
                MailboxKind::Plugin => GateTrustTier::Bridge,
            };
        }

        let peer_tier = self.resolve_peer_trust_tier(effective_origin);
        if is_webhook_or_event {
            cap_trust_tier_to_external_webhook(peer_tier)
        } else {
            peer_tier
        }
    }

    pub(super) fn resolve_peer_trust_tier(&self, peer_node: &str) -> GateTrustTier {
        if peer_node == "local" || peer_node == self.node.node_id().as_str() {
            return GateTrustTier::SelfHost;
        }
        let db = self.node.db();
        if let Ok(Some(peer)) = db.peers().get_peer(peer_node) {
            return match GateTrustTier::from(peer.trust_tier) {
                GateTrustTier::SelfHost => GateTrustTier::Peer,
                other => other,
            };
        }
        GateTrustTier::Peer
    }

    /// Builds a unified RFC 0004 metadata-only XML [`PackedDeliveryBatch`] for `session_id`
    /// from pending unread items.
    ///
    /// - Excludes already-notified items so push transports and hooks NEVER re-emit in a loop.
    /// - Strictly returns `None` when zero eligible unread items exist (even if `muted_count > 0`!).
    /// - **Security invariant (G3/G4):** When a `SecurityGatePipeline` is active, ONLY gate-cleared
    ///   rows (`reviewed_at IS NOT NULL OR human_auth_json IS NOT NULL`) are ever packed or delivered.
    async fn build_batch_for_session(
        self: &Arc<Self>,
        session_id: &str,
    ) -> Option<PackedDeliveryBatch> {
        self.build_batch_for_session_scoped(session_id, DrainScope::PushFlush)
            .await
            .map(|built| built.batch)
    }

    /// Builds a unified RFC 0004 metadata-only XML [`PackedDeliveryBatch`] for `session_id`
    /// filtered by `scope`.
    ///
    /// Scope semantics:
    /// - `DrainScope::MidTurn` (`PostToolUse`):
    ///   1. If any unnotified `Interrupt` exists -> returns `<hyphae-inbox ... urgency="interrupt">`
    ///      immediately (`is_midturn_queue_reminder == false`).
    ///   2. Otherwise, if `midturn_queue_digest_seconds > 0` AND unread `Queue` items exist AND
    ///      `now - max(last_midturn_digest_at_ms, oldest_unread_queue_received_at_ms) >= interval_ms`
    ///      -> returns ONE `<hyphae-inbox ... urgency="queue">` reminder (`is_midturn_queue_reminder == true`).
    /// - `DrainScope::TurnBoundary` (`Stop`): packs unnotified `Interrupt` + `Queue` digests; returns
    ///   `None` if `batch.notify_only` so TurnEnd never forces an extra turn for an FYI.
    /// - `DrainScope::PreTurn` / `DrainScope::All`: packs unnotified `Interrupt` + `Queue` + `Notify`
    ///   digests. Already-notified items never re-dump unless a new unnotified item arrives.
    /// - `DrainScope::PushFlush`: excludes Focus-buffered `Notify` items during VIP wakes (#32).
    pub(super) async fn build_batch_for_session_scoped(
        self: &Arc<Self>,
        session_id: &str,
        scope: DrainScope,
    ) -> Option<BuiltDigestBatch> {
        self.reconcile_session_inbox(session_id).await;

        let now = self.current_time_ms();
        let gate_active = self.current_gate().is_some();
        let (policy, session_handle, pending, muted, human_auth_by_receipt) = {
            let db = self.node.db();
            let policy = self.delivery.policy(&db, session_id).ok()?;
            let session_handle = db
                .local()
                .get_session(session_id)
                .ok()
                .flatten()
                .and_then(|s| s.handle);
            let pending = db
                .local()
                .peek_inbox_with_visibility(
                    session_id,
                    500,
                    MailboxVisibility::for_gate(gate_active),
                )
                .ok()?;
            let muted = muted_count(&db, session_id).unwrap_or(0);
            let mut auth_map: HashMap<String, (Option<String>, Option<String>)> = HashMap::new();
            for entry in &pending {
                if let Ok(Some(raw)) = db.human().get_mailbox_human_auth(&entry.receipt) {
                    if let Some(parsed_auth) = parse_human_auth_meta(&raw) {
                        auth_map.insert(entry.receipt.clone(), parsed_auth);
                    }
                }
            }
            (policy, session_handle, pending, muted, auth_map)
        };

        if pending.is_empty() {
            return None;
        }

        let meta_snapshot: HashMap<String, ClassifiedItemMeta> = self
            .item_meta
            .lock_state("item_meta lock poisoned")
            .get(session_id)
            .cloned()
            .unwrap_or_default();

        let mut candidates = Vec::with_capacity(pending.len());

        for entry in pending {
            let meta = meta_snapshot.get(&entry.receipt);
            let urgency = meta.map(|m| m.urgency).unwrap_or(policy.default_mode);
            if urgency == DeliveryUrgency::Mute {
                continue;
            }
            let burst_demoted = meta.is_some_and(|m| m.burst_demoted);
            let already_notified = entry.notified || meta.is_some_and(|m| m.notified);

            let parsed = hyp_node::delivery::ParsedMailboxSource::from_entry(&entry);
            let channel = meta.and_then(|m| m.channel.clone()).or(parsed.channel);
            let is_announcement = meta
                .map(|m| m.is_announcement)
                .unwrap_or_else(|| self.is_announcement_channel(channel.as_deref()));
            let human_verified = human_auth_by_receipt.contains_key(&entry.receipt);
            let is_system_notice = entry
                .trusted_daemon_notice(self.node.node_id().as_str())
                .is_some();
            let (topic, subscription_key) =
                if matches!(entry.kind, MailboxKind::Event | MailboxKind::Kv) {
                    let qualified_topic = if entry.source.contains('.') {
                        Some(entry.source.clone())
                    } else {
                        parsed
                            .topic
                            .as_deref()
                            .map(|t| format!("{}.{t}", entry.origin_node))
                            .or_else(|| Some(entry.source.clone()))
                    };
                    let sub_key =
                        self.lookup_subscription_key(session_id, &entry.origin_node, &entry.source);
                    (qualified_topic, sub_key)
                } else {
                    (None, None)
                };

            let item = PackableItem {
                id: entry.receipt,
                urgency,
                kind: entry.kind,
                source: entry.source,
                channel,
                is_announcement,
                created_at_ms: entry.received_at,
                burst_demoted,
                is_system_notice,
                topic,
                subscription_key,
                human_verified,
            };

            candidates.push(DigestCandidate {
                item,
                already_notified,
            });
        }

        let q_notices = self.peek_unsurfaced_quarantine_receipts(session_id);
        let last_midturn_digest_at_ms = if needs_midturn_reminder_timestamp(
            &candidates,
            scope,
            self.config.midturn_queue_digest_seconds,
        ) {
            self.session_runtime()
                .get(session_id)
                .and_then(|runtime| runtime.last_midturn_digest_at_ms)
        } else {
            None
        };
        let mut built = build_digest(
            session_handle.as_deref(),
            candidates,
            DigestPolicy {
                focus_mode: policy.focus_mode,
                midturn_queue_digest_seconds: self.config.midturn_queue_digest_seconds,
                last_midturn_digest_at_ms,
            },
            scope,
            now,
            muted,
            &q_notices,
        )?;
        const LARGE_SUBSCRIPTION_LIST: u64 = 20;
        const REVIEW_INTERVAL_MS: i64 = 7 * 24 * 60 * 60 * 1_000;
        if let Ok(Some(count)) = self.node.db().local().subscription_review_count(
            session_id,
            LARGE_SUBSCRIPTION_LIST,
            now.saturating_sub(REVIEW_INTERVAL_MS),
        ) {
            built.batch.add_subscription_review(count);
        }
        Some(built)
    }

    pub(super) fn record_subscription_review_if_shown(
        &self,
        session_id: &str,
        batch: &PackedDeliveryBatch,
    ) {
        if batch.includes_subscription_review() {
            let _ = self
                .node
                .db()
                .local()
                .record_subscription_review(session_id, self.current_time_ms());
        }
    }

    /// Commits a delivered [`PackedDeliveryBatch`]:
    /// - All counted digest receipts stay `unread` (`Pending`) in `NodeDb` and are marked
    ///   `notified = 1`, so neither hooks nor push transports duplicate the same digest until a
    ///   new item arrives or the agent reads them via `hyp_inbox`.
    pub(super) fn commit_delivered_batch(&self, session_id: &str, batch: &PackedDeliveryBatch) {
        let now = self.current_time_ms();
        {
            let db = self.node.db();
            let notified_ids: Vec<&str> = batch.receipt_ids.iter().map(String::as_str).collect();
            mark_receipts_notified(&db, session_id, &notified_ids);
        }

        self.record_subscription_review_if_shown(session_id, batch);

        // G10: Mark quarantine notices as surfaced only once their rendered digest actually commits.
        self.mark_surfaced_quarantine_notices(session_id, &batch.quarantined_receipts);

        let mut sources_delivered: HashSet<String> = HashSet::new();
        {
            let mut guard = self.item_meta.lock_state("item_meta lock poisoned");
            if let Some(map) = guard.get_mut(session_id) {
                for id in &batch.receipt_ids {
                    if let Some(m) = map.get_mut(id) {
                        m.notified = true;
                        sources_delivered.insert(m.burst_source_key.clone());
                    }
                }
            }
        }
        for src in sources_delivered {
            self.delivery.record_delivery(session_id, &src, now);
        }
        // Any successful delivery or hook drain cancels pending Tier 3 Hold retries immediately.
        self.cancel_hold_retry(session_id);
        self.cancel_activity_grace(session_id);
        self.bump_ui_rev();
    }

    /// Restores Focus-buffered `Notify` pending items when Focus Mode turns OFF (`focus off` /
    /// `mode: queue`): re-evaluates every pending item under the updated non-Focus policy,
    /// clears any stale `notified = 1` flag in SQLite for promoted items that were never delivered
    /// or actively nudged, and evicts their stale `item_meta` entries so the immediate
    /// `flush_session` re-classifies them to `Queue`/`Interrupt` and delivers them cleanly.
    pub(super) fn restore_focus_buffered_items(&self, session_id: &str) -> usize {
        let gate_active = self.current_gate().is_some();
        let meta_snapshot: HashMap<String, ClassifiedItemMeta> = self
            .item_meta
            .lock_state("item_meta lock poisoned")
            .get(session_id)
            .cloned()
            .unwrap_or_default();

        let promoted: Vec<String> = {
            let db = self.node.db();
            let Ok(policy) = self.delivery.policy(&db, session_id) else {
                return 0;
            };
            if policy.focus_mode {
                return 0;
            }
            let pending = db
                .local()
                .peek_inbox_with_visibility(
                    session_id,
                    500,
                    MailboxVisibility::for_gate(gate_active),
                )
                .unwrap_or_default();
            let mut receipts = Vec::new();
            for entry in pending {
                if let Some(meta) = meta_snapshot.get(&entry.receipt) {
                    // Never re-clear a burst-demoted item.
                    if meta.burst_demoted {
                        continue;
                    }
                }
                let parsed = hyp_node::delivery::ParsedMailboxSource::from_entry(&entry);
                let sub_mode =
                    self.lookup_subscription_urgency(session_id, &entry.origin_node, &entry.source);
                let gate_cap = gate_reason_urgency_cap(entry.gate_reason.as_deref());
                let restored_urgency =
                    policy.resolve_urgency(&parsed.as_context(), sub_mode, gate_cap);
                if matches!(
                    restored_urgency,
                    DeliveryUrgency::Interrupt | DeliveryUrgency::Queue
                ) {
                    receipts.push(entry.receipt);
                }
            }
            if !receipts.is_empty() {
                let refs: Vec<&str> = receipts.iter().map(String::as_str).collect();
                clear_receipts_notified(&db, session_id, &refs);
            }
            receipts
        };

        if !promoted.is_empty() {
            let mut guard = self.item_meta.lock_state("item_meta lock poisoned");
            if let Some(map) = guard.get_mut(session_id) {
                for receipt in &promoted {
                    map.remove(receipt);
                }
            }
        }
        promoted.len()
    }

    pub(super) fn collect_pending_sessions_for_flush(&self) -> Vec<(String, String)> {
        if *self.shutdown_rx.borrow() {
            return Vec::new();
        }
        // 1. Materialize any queued/due local topic batches into `mailbox` BEFORE scanning sessions.
        let _ = self.node.flush_pending_local_topic_batches();

        // 2. Collect sessions that currently have pending mailbox entries (excluding internal
        //    `local-ingest:` staging rows, which are handled by `sweep_approved_local_ingest_on_startup`).
        let db = self.node.db();
        let mut backend_by_id: HashMap<String, String> = HashMap::new();
        for s in db.local().list_sessions().unwrap_or_default() {
            backend_by_id.insert(s.id, s.backend_json);
        }
        let pending_ids = db.local().list_pending_session_ids().unwrap_or_default();
        let mut out = Vec::new();
        for sid in pending_ids {
            if sid.starts_with("local-ingest:") {
                continue;
            }
            let backend_json = backend_by_id
                .remove(&sid)
                .unwrap_or_else(|| "{}".to_string());
            out.push((sid, backend_json));
        }
        out
    }

    /// Sweeps pending local topic batches into local mailboxes, reconciles every session with
    /// pending unread/unscreened entries (strictly enforcing Security Gates, mutes, and Focus
    /// Mode), hydrates native push transports from persisted `sessions.backend_json` when
    /// `auto_detect_transports` is enabled, and flushes deliverable batches at-most-once.
    pub(super) async fn flush_all_pending_sessions(self: &Arc<Self>) {
        let pending_sessions = self.collect_pending_sessions_for_flush();
        self.flush_pending_session_list(pending_sessions).await;
    }

    pub(super) async fn flush_pending_session_list(
        self: &Arc<Self>,
        pending_sessions: Vec<(String, String)>,
    ) {
        if pending_sessions.is_empty() || *self.shutdown_rx.borrow() {
            return;
        }

        // 3. Reconcile, optionally hydrate persisted push transports, and flush each session
        //    concurrently so one slow external transport probe never stalls other sessions.
        let mut join_set = tokio::task::JoinSet::new();
        for (sid, backend_json) in pending_sessions {
            let daemon = Arc::clone(self);
            join_set.spawn(async move {
                if *daemon.shutdown_rx.borrow() {
                    return;
                }

                // Respect any active Tier 3 Hold backoff or active-turn hook grace timer rather
                // than firing an unsolicited extra push attempt ahead of schedule.
                let retry_or_grace_active = daemon
                    .session_runtime()
                    .get(&sid)
                    .is_some_and(|runtime| runtime.has_pending_retry_or_grace());
                if retry_or_grace_active {
                    return;
                }

                // Always enforce Security Gates, mutes, Focus Mode, and urgency classification first.
                let wake_needed = daemon.reconcile_session_inbox(&sid).await;
                if !wake_needed {
                    return;
                }

                let has_unnotified = {
                    let db = daemon.node.db();
                    db.local().unnotified_count(&sid).unwrap_or(0) > 0
                };
                if !has_unnotified {
                    return;
                }

                // Hydrate persisted push transport (Herdr / T3 / OpenClaw / Codex Queue) if enabled
                // and no push transport is attached yet.
                if daemon.config.auto_detect_transports
                    && daemon.current_transport_priority(&sid) == 0
                {
                    let hints = TransportHints::from_session_backend(&sid, &backend_json);
                    maybe_spawn_transport_probe(&daemon, &sid, hints);

                    let probe_rx = daemon
                        .pending_probes
                        .lock_state("pending_probes lock poisoned")
                        .get(&sid)
                        .cloned();
                    if let Some(mut rx) = probe_rx {
                        let mut shutdown_rx = daemon.shutdown_rx.clone();
                        let wait_probe = async {
                            while !*rx.borrow() {
                                if rx.changed().await.is_err() {
                                    break;
                                }
                            }
                        };
                        tokio::select! {
                            _ = tokio::time::timeout(Duration::from_secs(5), wait_probe) => {}
                            _ = shutdown_rx.changed() => {
                                if *shutdown_rx.borrow() {
                                    return;
                                }
                            }
                        }
                    }
                }

                if *daemon.shutdown_rx.borrow() {
                    return;
                }

                // Re-check backoff guard before flushing in case a live send just entered Hold.
                let retry_active = daemon
                    .session_runtime()
                    .get(&sid)
                    .is_some_and(|runtime| runtime.has_transport_retry());
                if retry_active {
                    return;
                }

                // Strictly at-most-once flush: respects per-session `flushing` lock, `notified`,
                // `nudge_pending`, `delivered_at`, Security Gates, mutes, and Focus Mode.
                let _ = daemon.flush_session(&sid).await;
            });
        }

        let mut shutdown_rx = self.shutdown_rx.clone();
        loop {
            tokio::select! {
                res = join_set.join_next() => {
                    if res.is_none() {
                        break;
                    }
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        join_set.abort_all();
                        return;
                    }
                }
            }
        }

        // 4. Refresh UI projection revision so `ui/state.json` and `inspect.watch` reflect
        //    post-flush mailbox state immediately.
        self.bump_ui_rev();
    }

    /// Flushes eligible batches to live transports (native push, then `watch`/`wait`, then a best-effort Claude notice).
    ///
    /// On transient `PushTransport` `Hold` outcomes (`herdr_working`, `herdr_send_guard_refused`,
    /// `herdr_agent_not_ready`, `t3_server_unreachable`, `codex_queue_unavailable`), schedules
    /// a bounded Tier 3 retry backoff task (zero polling when idle).
    ///
    /// Returns `Some(terminal_reason)` if a transport reported terminal target unavailability
    /// (`herdr_target_unavailable`, `t3_thread_deleted`, `t3_thread_not_found`).
    pub(super) async fn flush_session(self: &Arc<Self>, session_id: &str) -> Option<String> {
        self.flush_session_with_report(session_id).await.0
    }

    /// Flushes eligible batches and returns `(terminal_error, delivered_any)`.
    async fn flush_session_with_report(
        self: &Arc<Self>,
        session_id: &str,
    ) -> (Option<String>, bool) {
        self.flush_session_inner(session_id, SessionFlushMode::Normal)
            .await
    }

    pub(super) async fn flush_session_inner(
        self: &Arc<Self>,
        session_id: &str,
        flush_mode: SessionFlushMode,
    ) -> (Option<String>, bool) {
        let lock = self.flush_lock_for(session_id);
        let guard = if flush_mode == SessionFlushMode::ClaudeIdleWake {
            lock.lock().await
        } else if let Ok(guard) = lock.try_lock() {
            guard
        } else {
            // An arrival can race the final snapshot of the in-flight flush.
            self.defer_interrupt_wake(session_id);
            return (None, false);
        };
        let result = if *self.shutdown_rx.borrow() {
            (None, false)
        } else {
            self.flush_session_locked(session_id, flush_mode).await
        };
        drop(guard);
        drop(lock);
        self.update_runtime(session_id, |_| ());
        result
    }

    pub(super) async fn flush_session_locked(
        self: &Arc<Self>,
        session_id: &str,
        flush_mode: SessionFlushMode,
    ) -> (Option<String>, bool) {
        let mut terminal_error: Option<String> = None;
        let mut delivered_any = false;
        let claude_idle_wake = flush_mode == SessionFlushMode::ClaudeIdleWake;
        let normal_grace = flush_mode == SessionFlushMode::Normal;

        loop {
            let Some(batch) = self.build_batch_for_session(session_id).await else {
                self.cancel_hold_retry(session_id);
                break;
            };

            if claude_idle_wake {
                if !self.has_pending_claude_idle_wake(session_id, &batch) {
                    break;
                }
                if let Some((_, remaining)) = self.active_session_lease(session_id) {
                    self.schedule_activity_grace_flush(session_id, remaining, flush_mode);
                    break;
                }
            }

            // Priority 1: Native OpenClaw Gateway plugin wake service (`openclaw.service.ready`).
            // Targets the EXACT existing `(agentId, sessionKey)` with `createIfMissing: false` —
            // zero webhook token required, zero isolated cron spawns, strictly metadata-only nudge!
            if !batch.notify_only && self.openclaw_plugin_wake_available_for(session_id) {
                let oc_service_entry = self
                    .openclaw_service
                    .lock_state("openclaw_service lock poisoned")
                    .as_ref()
                    .map(|s| (s.conn_id, s.tx.clone()));
                if let (Some((service_conn_id, tx)), Some((session_key, agent_id))) = (
                    oc_service_entry,
                    self.resolve_openclaw_session_target(session_id),
                ) {
                    if normal_grace {
                        if let Some((act_harness, remaining)) =
                            self.active_session_lease(session_id)
                        {
                            if batch.max_urgency == DeliveryUrgency::Interrupt {
                                if Self::can_drain_mid_turn(act_harness)
                                    && !self.config.interrupt_hook_grace.is_zero()
                                {
                                    let delay = self.config.interrupt_hook_grace.min(remaining);
                                    self.schedule_activity_grace_flush(
                                        session_id,
                                        delay,
                                        SessionFlushMode::InterruptGraceExpired,
                                    );
                                    break;
                                }
                            } else if batch.max_urgency == DeliveryUrgency::Queue
                                && Self::can_drain_turn_end(act_harness)
                                && !self.config.queue_activity_lease.is_zero()
                            {
                                self.schedule_activity_grace_flush(
                                    session_id,
                                    remaining,
                                    SessionFlushMode::Normal,
                                );
                                break;
                            }
                        }
                    }

                    let batch_id = compute_batch_idempotency_id(session_id, &batch);
                    let digest_xml = batch.confirmed_digest().as_str().to_owned();
                    let delivery_id = self.next_seq();
                    let (ack_tx, ack_rx) = oneshot::channel();
                    let sent = tx
                        .send(OpenClawWakeCommand {
                            delivery_id,
                            session_id: session_id.to_string(),
                            session_key,
                            agent_id,
                            batch_id,
                            text: digest_xml,
                            ack_tx,
                        })
                        .is_ok();
                    if sent {
                        let ack = tokio::time::timeout(
                            hyp_harness_transport::transport::openclaw::DEFAULT_OPENCLAW_DELIVER_TIMEOUT,
                            ack_rx,
                        )
                        .await
                        .ok()
                        .and_then(Result::ok)
                        .unwrap_or(OpenClawWakeAck {
                            ok: false,
                            reason: Some(REASON_OPENCLAW_GATEWAY_UNAVAILABLE.to_string()),
                        });
                        if ack.ok {
                            self.commit_delivered_batch(session_id, &batch);
                            delivered_any = true;
                            continue;
                        }
                        if matches!(
                            ack.reason.as_deref(),
                            Some(
                                REASON_OPENCLAW_SESSION_MISSING
                                    | REASON_OPENCLAW_INVALID_SESSION_KEY
                            )
                        ) {
                            self.session_runtime()
                                .entry(session_id.to_owned())
                                .or_default()
                                .openclaw_session_missing = true;
                            terminal_error = ack.reason;
                            self.cancel_hold_retry(session_id);
                            self.bump_ui_rev();
                            break;
                        }
                        let still_connected = self
                            .openclaw_service
                            .lock_state("openclaw_service lock poisoned")
                            .as_ref()
                            .is_some_and(|s| s.conn_id == service_conn_id);
                        if still_connected {
                            self.schedule_hold_retry(session_id);
                            break;
                        }
                    }
                }
            }

            // Priority 2: Attached native external PushTransport (Herdr > T3 Code > OpenClaw > Codex Queue).
            // Issue #34: Lazily hydrate persisted push transport when none is attached yet (bounded
            // by LAZY_HYDRATE_COOLDOWN so dead targets never enter a probe loop).
            let mut deferred_transient_hold = false;
            if !batch.notify_only
                && !claude_idle_wake
                && self.config.auto_detect_transports
                && self.current_transport_priority(session_id) == 0
                && terminal_error.is_none()
            {
                self.maybe_lazy_hydrate_transport(session_id).await;
            }
            let push_transport = self.attached_push_transport(session_id);
            if let Some(transport) = push_transport {
                // Notify-only FYI batches NEVER wake an idle agent via an external L2 push
                // transport (no wasted LLM turn for Focus Mode / burst-demoted chatter).
                // They remain cleanly unread for TurnStart (`pre_turn`) digests and passive UIs,
                // while `watch` and `wait` still receive them below.
                if !batch.notify_only {
                    let push_mode = if !claude_idle_wake
                        && batch.max_urgency == DeliveryUrgency::Interrupt
                        && transport.supports_interrupt()
                    {
                        PushMode::Interrupt
                    } else {
                        PushMode::Queue
                    };
                    if push_mode == PushMode::Interrupt && self.defer_interrupt_wake(session_id) {
                        break;
                    }

                    // Unified Active-Turn Hook Grace / Activity Lease Deferral:
                    // When a hook-capable session is actively running a turn (`Active`), let
                    // in-turn hooks drain first instead of nudging the input box immediately:
                    //   - `Interrupt`: short grace window (`interrupt_hook_grace`) for `PostToolUse`
                    //     to drain mid-turn; if no tool hook drains in time, falls back to L2!
                    //   - `Queue`: wait for TurnEnd (`Stop` / `agent_end`) or `queue_activity_lease`
                    //     expiry with no more tool calls before firing L2 wake nudge!
                    if normal_grace {
                        if let Some((act_harness, remaining)) =
                            self.active_session_lease(session_id)
                        {
                            if batch.max_urgency == DeliveryUrgency::Interrupt {
                                if Self::can_drain_mid_turn(act_harness)
                                    && !self.config.interrupt_hook_grace.is_zero()
                                {
                                    let delay = self.config.interrupt_hook_grace.min(remaining);
                                    self.schedule_activity_grace_flush(
                                        session_id,
                                        delay,
                                        SessionFlushMode::InterruptGraceExpired,
                                    );
                                    break;
                                }
                            } else if batch.max_urgency == DeliveryUrgency::Queue
                                && Self::can_drain_turn_end(act_harness)
                                && !self.config.queue_activity_lease.is_zero()
                            {
                                self.schedule_activity_grace_flush(
                                    session_id,
                                    remaining,
                                    SessionFlushMode::Normal,
                                );
                                break;
                            }
                        }
                    }

                    let batch_id = compute_batch_idempotency_id(session_id, &batch);
                    let outcome = transport
                        .deliver_digest(batch.confirmed_digest(), &batch_id, push_mode)
                        .await;
                    if push_mode == PushMode::Interrupt
                        && matches!(
                            outcome,
                            PushOutcome::Delivered
                                | PushOutcome::Hold {
                                    interrupted: true,
                                    ..
                                }
                                | PushOutcome::Reject {
                                    interrupted: true,
                                    ..
                                }
                        )
                    {
                        self.start_interrupt_wake_cooldown(session_id);
                    }
                    match outcome {
                        PushOutcome::Delivered => {
                            self.commit_delivered_batch(session_id, &batch);
                            delivered_any = true;
                            continue;
                        }
                        PushOutcome::Hold { ref reason, .. }
                            if reason.is_herdr_active_or_guarded() =>
                        {
                            // Target is actively working or has an in-progress user draft;
                            // preserve unread in durable SQLite and schedule bounded Tier 3 retry.
                            if !claude_idle_wake {
                                self.schedule_hold_retry(session_id);
                            }
                            break;
                        }
                        PushOutcome::Hold { ref reason, .. }
                            if reason.is_transiently_unavailable() =>
                        {
                            // Transient transport unavailability: fall through to any live waiter;
                            // if none delivers, schedule bounded Tier 3 retry before exiting.
                            deferred_transient_hold = true;
                        }
                        PushOutcome::Hold { ref reason, .. }
                        | PushOutcome::Reject { ref reason, .. } => {
                            if reason.is_terminal_target_error() {
                                terminal_error = Some(reason.as_str().to_owned());
                                self.record_lazy_hydrate_attempt(session_id);
                                if self
                                    .unregister_matching_session_transport(session_id, &transport)
                                {
                                    let _ = self.write_ui_state_snapshot();
                                }
                            }
                            self.cancel_hold_retry(session_id);
                            // Preserve unread in durable SQLite; fall through to any live
                            // `watch`/`wait` waiter if one is attached, else exit flush loop.
                        }
                    }
                }
            }

            // Priority 3: Streaming watcher (`hyp watch` / streaming `wait.subscribe`)
            let stream_tx = self
                .session_runtime()
                .get(session_id)
                .map(|runtime| &runtime.waiters)
                .and_then(|list| {
                    list.iter()
                        .find(|w| w.mode == WaiterKind::Stream)
                        .map(|w| w.tx.clone())
                });
            if let Some(tx) = stream_tx {
                let pkt = json!({
                    "type": "wait.items",
                    "items": [{
                        "router": self.node.node_id().as_str(),
                        "received": self.current_time_ms() / 1000,
                        "text": batch.confirmed_digest(),
                        "notifyOnly": batch.notify_only,
                        "mutedCount": batch.muted_count,
                    }]
                });
                if tx.send(pkt).is_ok() {
                    self.commit_delivered_batch(session_id, &batch);
                    delivered_any = true;
                    continue;
                }
            }

            // Priority 3: One-shot blocking waiter (`hyp wait` / one-shot `wait.subscribe`)
            let once_waiter = self
                .update_runtime(session_id, |runtime| {
                    runtime
                        .waiters
                        .iter()
                        .position(|waiter| waiter.mode == WaiterKind::Once)
                        .map(|index| runtime.waiters.remove(index))
                })
                .flatten();
            if let Some(waiter) = once_waiter {
                let pkt = json!({
                    "type": "wait.items",
                    "items": [{
                        "router": self.node.node_id().as_str(),
                        "received": self.current_time_ms() / 1000,
                        "text": batch.confirmed_digest(),
                        "notifyOnly": batch.notify_only,
                        "mutedCount": batch.muted_count,
                    }]
                });
                if waiter.tx.send(pkt).is_ok() {
                    self.commit_delivered_batch(session_id, &batch);
                    delivered_any = true;
                    continue;
                }
            }

            // Priority 4 (Issue #33): Opt-in Tier 4 allowlisted Herdr cold-spawn (`hc run <tpl> <nudge>`).
            // Strictly fail-closed:
            // - NEVER runs for Notify-only / Focus-buffered / muted batches (`batch.notify_only == true`).
            // - NEVER runs solely for a daemon-generated host sleep/wake notice (Issue #29).
            // - NEVER runs when a live push transport or waiter exists, or a live transport is only
            //   transiently holding (`deferred_transient_hold`). An authenticated Claude
            //   channel connection also means a session process is already running.
            // - NEVER runs when `herdr_spawn_allowlist` is empty or does not match the session's
            //   persisted `herdrTemplate` verbatim.
            // - Strictly enforces `maxConcurrentSpawns: 1` (`active_cold_spawns`) and uses a
            //   metadata-only `<hyphae-wake>` nudge (zero untrusted DM body in argv).
            let has_non_wake_deliverable = {
                let guard = self.item_meta.lock_state("item_meta lock poisoned");
                let map = guard.get(session_id);
                batch.receipt_ids.iter().any(|receipt| {
                    !map.and_then(|m| m.get(receipt))
                        .is_some_and(|meta| meta.is_wake_notice)
                })
            };
            if !batch.notify_only
                && has_non_wake_deliverable
                && !deferred_transient_hold
                && !claude_idle_wake
                && !self.config.delivery_retry.herdr_spawn_allowlist.is_empty()
                && !self.has_live_transport(session_id)
                && self
                    .session_runtime()
                    .get(session_id)
                    .is_none_or(|runtime| runtime.channel.is_none())
            {
                let herdr_template = {
                    let db = self.node.db();
                    db.local()
                        .get_session(session_id)
                        .ok()
                        .flatten()
                        .and_then(|s| {
                            extract_backend_str(&s.backend_json, "herdrTemplate")
                                .or_else(|| extract_backend_str(&s.backend_json, "herdr_template"))
                                .filter(|t| is_valid_herdr_template(t))
                        })
                };
                if let Some(template) = herdr_template {
                    if self
                        .config
                        .delivery_retry
                        .herdr_spawn_allowlist
                        .iter()
                        .any(|allowed| allowed == &template)
                    {
                        let spawn_key = format!("herdr-cold:{session_id}:{template}");
                        if self
                            .try_herdr_cold_spawn(
                                &spawn_key,
                                &template,
                                batch.confirmed_digest().as_str(),
                            )
                            .await
                            .is_delivered()
                        {
                            self.commit_delivered_batch(session_id, &batch);
                            delivered_any = true;
                            terminal_error = None;
                            continue;
                        }
                    }
                }
            }

            if deferred_transient_hold && !claude_idle_wake {
                self.schedule_hold_retry(session_id);
            } else if !batch.notify_only {
                self.try_claude_channel_notice(session_id, &batch, flush_mode);
            }
            break;
        }

        (terminal_error, delivered_any)
    }

    fn has_pending_claude_idle_wake(&self, session_id: &str, batch: &PackedDeliveryBatch) -> bool {
        let guard = self.item_meta.lock_state("item_meta lock poisoned");
        guard.get(session_id).is_some_and(|meta_by_receipt| {
            batch.receipt_ids.iter().any(|receipt| {
                meta_by_receipt.get(receipt).is_some_and(|meta| {
                    meta.claude_channel_wake == ClaudeChannelWake::WaitingForIdle
                        && meta.eligible_for_claude_channel_wake()
                })
            })
        })
    }

    /// Claude may discard a channel notice. Keep receipts eligible for a confirmed wake.
    fn try_claude_channel_notice(
        self: &Arc<Self>,
        session_id: &str,
        batch: &PackedDeliveryBatch,
        flush_mode: SessionFlushMode,
    ) {
        let tx = self
            .session_runtime()
            .get(session_id)
            .and_then(|runtime| runtime.channel.as_ref())
            .map(|channel| channel.tx.clone());
        let Some(tx) = tx else {
            return;
        };
        let active_lease = self
            .active_session_lease(session_id)
            .map(|(_, remaining)| remaining);
        let (notify, await_idle) = {
            let mut guard = self.item_meta.lock_state("item_meta lock poisoned");
            let Some(meta_by_receipt) = guard.get_mut(session_id) else {
                return;
            };
            let mut notify = false;
            let mut await_idle = false;
            for receipt in &batch.receipt_ids {
                let Some(meta) = meta_by_receipt.get_mut(receipt) else {
                    continue;
                };
                if !meta.eligible_for_claude_channel_wake()
                    || meta.claude_channel_wake == ClaudeChannelWake::Attempted
                {
                    continue;
                }
                if active_lease.is_some() {
                    notify |= flush_mode != SessionFlushMode::ClaudeIdleWake
                        && meta.claude_channel_wake == ClaudeChannelWake::Fresh
                        && meta.urgency == DeliveryUrgency::Interrupt;
                    meta.claude_channel_wake = ClaudeChannelWake::WaitingForIdle;
                    await_idle = true;
                } else {
                    meta.claude_channel_wake = ClaudeChannelWake::Attempted;
                    notify = true;
                }
            }
            (notify, await_idle)
        };
        if await_idle {
            if let Some(remaining) = active_lease {
                self.schedule_activity_grace_flush(
                    session_id,
                    remaining,
                    SessionFlushMode::ClaudeIdleWake,
                );
            }
        }
        if notify {
            let idle_digest = if flush_mode == SessionFlushMode::ClaudeIdleWake
                && batch.max_urgency == DeliveryUrgency::Interrupt
            {
                InboxDigest::count_only(batch.receipt_ids.len(), DeliveryUrgency::Queue)
            } else {
                None
            };
            // Keep at most one queued notice while a reader is slow or its pipe stops draining.
            let _ = tx.try_send(ChannelDeliverCommand {
                session_id: session_id.to_owned(),
                text: idle_digest
                    .as_ref()
                    .unwrap_or(&batch.rendered)
                    .as_str()
                    .to_owned(),
            });
        }
    }
}

impl ClassifiedItemMeta {
    fn eligible_for_claude_channel_wake(&self) -> bool {
        !self.notified
            && !self.burst_demoted
            && matches!(
                self.urgency,
                DeliveryUrgency::Interrupt | DeliveryUrgency::Queue
            )
    }
}

/// Marks ONLY the specified `pending` mailbox receipts as `notified = 1` in SQLite without
/// touching unrelated pending rows (e.g. Focus-buffered `Notify` items or `Queue` items held
/// during a `MidTurn` interrupt).
fn mark_receipts_notified(db: &hyp_store::NodeDb, session_id: &str, receipts: &[&str]) {
    if receipts.is_empty() {
        return;
    }
    let conn = db.connection();
    for receipt in receipts {
        let _ = conn.execute(
            "UPDATE mailbox SET notified = 1
             WHERE session_id = ?1 AND receipt = ?2 AND gate_state = 'pending' AND notified = 0",
            rusqlite::params![session_id, receipt],
        );
    }
}

/// Clears `notified = 0` ONLY for the specified `pending` mailbox receipts in SQLite (used when
/// Focus Mode turns OFF so Focus-buffered items that were never delivered promote cleanly back
/// into active push delivery).
fn clear_receipts_notified(db: &hyp_store::NodeDb, session_id: &str, receipts: &[&str]) {
    if receipts.is_empty() {
        return;
    }
    let conn = db.connection();
    for receipt in receipts {
        let _ = conn.execute(
            "UPDATE mailbox SET notified = 0
             WHERE session_id = ?1 AND receipt = ?2 AND gate_state = 'pending' AND notified = 1",
            rusqlite::params![session_id, receipt],
        );
    }
}

fn compute_batch_idempotency_id(session_id: &str, batch: &PackedDeliveryBatch) -> String {
    let mut ids: Vec<&str> = batch.receipt_ids.iter().map(String::as_str).collect();
    ids.sort_unstable();
    let material = format!("{session_id}:{}", ids.join(","));
    let digest = sha256_hex(material.as_bytes());
    digest[..24].to_string()
}
