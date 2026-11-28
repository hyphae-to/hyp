use crate::adapters::github_public::canonicalize_repo;
use crate::adapters::{CompiledSubscription, GitHubPublicAdapter, NodeAdapter};
use crate::engine::config::{
    NodeError, proto_ce_to_store, proto_filter_to_store, store_ce_to_proto, store_filter_to_proto,
};
use crate::engine::peer_link::{
    PublishEventRequest, PutSubscriptionsRequest, SubscriptionInputWire,
};
use crate::gates::VerifiedHumanClaim;
use hyp_crypto::e2ee::{KvContext, KvEnvelopeV1, open_kv_entry};
use hyp_crypto::rfc3339::format_rfc3339_millis;
use hyp_proto::address::{LOCAL_NODE_ID, NodeId, NodeScope, resolve_topic};
use hyp_proto::cloudevent::{
    CONTENT_TYPE_E2EE_JSON, CONTENT_TYPE_JSON, CloudEvent as ProtoCloudEvent,
    TYPE_HUMAN_REVOCATION_V1,
};
use hyp_proto::filter::{
    DiagnosticSeverity, Filter as ProtoFilter, LocalSubscription, ObservedTopicStats,
    SubscriptionDiagnostic, TopicCatalogEntry, compile_upstream_pushdown, diagnose_subscription,
};
use hyp_proto::scopes::extract_confined_values;
use hyp_store::{
    AckOutcome, DeliveryMode, DueBatch, GateAuditInput, GateDecision as StoreGateDecision,
    GateDirection, GateState, IngestResult, MailboxInsert, MailboxKind, MailboxPutOptions,
    MailboxPutResult, Subscription, SubscriptionSpec, TrustTier, UpstreamPushdownInput, now_ms,
    sha256_hex, uuid_v4,
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::Arc;

use super::{
    AuthenticatedPeer, PeerAction, UnifiedNode, extract_signed_human_revocation,
    map_provenance_err, peer_may_see_topic,
};

/// Request for `UnifiedNode::subscribe_local_or_remote`.
#[derive(Debug, Clone)]
pub struct SubscribeRequest {
    pub id: Option<String>,
    pub subscriber_session: String,
    /// Qualified topic (`local.<topic>`, `<node-id>.<topic>`, or shorthand `<topic>`).
    pub qualified_topic: String,
    pub filters: Vec<ProtoFilter>,
    pub coalesce_seconds: u32,
    pub mode: DeliveryMode,
}

/// Result of `UnifiedNode::subscribe_local_or_remote`.
#[derive(Debug, Clone)]
pub struct SubscribeResult {
    pub subscription: Subscription,
    pub origin_node: String,
    pub topic: String,
    pub diagnostics: Vec<SubscriptionDiagnostic>,
    pub pushdown_shards: usize,
}

impl UnifiedNode {
    /// Subscribes `subscriber_session` to a local (`local.<topic>`) or remote
    /// (`<node-id>.<topic>`) event stream: persists locally, compiles & syncs upstream
    /// pushdown shards (`compile_upstream_pushdown`) to remote peers, and surfaces reachability
    /// diagnostics back to the caller (§2.2).
    pub async fn subscribe_local_or_remote(
        &self,
        req: SubscribeRequest,
    ) -> Result<SubscribeResult, NodeError> {
        let known_peers: Vec<NodeId> = {
            let db = self.db();
            db.peers()
                .list_peers(None)?
                .into_iter()
                .filter_map(|p| NodeId::new(p.peer_id).ok())
                .collect()
        };
        let default_node = match self.default_remote_peer().await {
            Some(pid) => NodeScope::Remote(NodeId::new(pid)?),
            None => NodeScope::Local,
        };
        let resolved = resolve_topic(&req.qualified_topic, &known_peers, &default_node)?;
        let topic_str = resolved.topic.as_str().to_string();
        let origin_node_str = match &resolved.node {
            NodeScope::Local => self.config.node_id.to_string(),
            NodeScope::Remote(peer_id) => peer_id.to_string(),
        };

        let store_filters: Vec<hyp_store::Filter> =
            req.filters.iter().map(proto_filter_to_store).collect();
        let sub_id = req.id.unwrap_or_else(uuid_v4);
        let now = now_ms();

        // Fail-closed subscribe-time validation against attached `github-public` adapter for local topic.
        let local_gh_adapter = if resolved.node == NodeScope::Local {
            self.github_public_adapter()
                .filter(|a| a.topic() == topic_str)
        } else {
            None
        };
        let mut local_adapter_diags = Vec::new();
        if let Some(ref adapter) = local_gh_adapter {
            let diags = adapter
                .validate_subscription(&topic_str, &req.filters)
                .await;
            if let Some(first_err) = diags
                .iter()
                .find(|d| d.severity == DiagnosticSeverity::Error)
            {
                return Err(NodeError::SubscriptionRejected {
                    detail: first_err.message.clone(),
                    diagnostics: diags,
                });
            }
            local_adapter_diags = diags;
        }

        let subscription = {
            let db = self.db();
            db.events().upsert_subscription(
                &SubscriptionSpec {
                    id: sub_id,
                    origin_node: origin_node_str.clone(),
                    topic: topic_str.clone(),
                    subscriber: req.subscriber_session.clone(),
                    filters: store_filters,
                    coalesce_seconds: i64::from(req.coalesce_seconds),
                    max_batch_age_ms: None,
                    max_wakes_per_hour: None,
                    mode: req.mode,
                },
                now,
            )?
        };

        if resolved.node == NodeScope::Local {
            if let Some(ref adapter) = local_gh_adapter {
                self.sync_github_public_subscriptions(adapter).await?;
            }
            let catalog = self.local_topic_catalog();
            let mut diagnostics = diagnose_subscription(&topic_str, &req.filters, &catalog);
            diagnostics.extend(local_adapter_diags);
            return Ok(SubscribeResult {
                subscription,
                origin_node: origin_node_str,
                topic: topic_str,
                diagnostics,
                pushdown_shards: 0,
            });
        }

        // Compile upstream pushdown plan across ALL local subscriptions on `(origin_node, topic)`.
        let local_subs_for_topic: Vec<LocalSubscription> = {
            let db = self.db();
            db.events()
                .list_subscriptions(None)?
                .into_iter()
                .filter(|s| s.origin_node == origin_node_str && s.topic == topic_str)
                .map(|s| LocalSubscription {
                    filters: s.filters.iter().map(store_filter_to_proto).collect(),
                    coalesce_seconds: s.coalesce_seconds.max(0) as u32,
                })
                .collect()
        };

        let plan = compile_upstream_pushdown(&topic_str, &local_subs_for_topic);
        let shard_count = plan.shards.len();

        // Persist upstream_pushdowns locally.
        {
            let db = self.db();
            for (idx, shard) in plan.shards.iter().enumerate() {
                let filters_json = serde_json::to_string(&shard.filters)?;
                db.events().upsert_upstream_pushdown(
                    &UpstreamPushdownInput {
                        id: shard.id.clone(),
                        peer_id: origin_node_str.clone(),
                        topic: topic_str.clone(),
                        shard_index: idx as i64,
                        filters_json,
                        coalesce_seconds: i64::from(shard.coalesce_seconds),
                        local_sub_count: local_subs_for_topic.len(),
                    },
                    now,
                )?;
            }
            // Remove stale shards if shard count shrank.
            for existing in db
                .events()
                .list_upstream_pushdowns(Some(&origin_node_str))?
            {
                if existing.topic == topic_str && (existing.shard_index as usize) >= shard_count {
                    let _ = db.events().delete_upstream_pushdown(&existing.id);
                }
            }
        }

        // Sync compiled pushdown shards to remote peer via `PUT /v1/subscriptions`.
        let link = self.require_peer_link(&origin_node_str).await?;
        let wire_subs: Vec<SubscriptionInputWire> = plan
            .shards
            .iter()
            .map(|shard| SubscriptionInputWire {
                id: shard.id.clone(),
                topic: topic_str.clone(),
                filters: shard.filters.clone(),
                coalesce_seconds: i64::from(shard.coalesce_seconds),
                max_batch_age_ms: None,
                max_wakes_per_hour: None,
                mode: DeliveryMode::Full,
            })
            .collect();

        let sync_res = link
            .put_subscriptions(&PutSubscriptionsRequest {
                subscriptions: wire_subs,
                replace_topic: Some(topic_str.clone()),
            })
            .await;

        match sync_res {
            Ok(resp) => {
                let synced_at = now_ms();
                let db = self.db();
                for shard in &plan.shards {
                    let _ = db.events().mark_pushdown_synced(&shard.id, synced_at);
                }
                Ok(SubscribeResult {
                    subscription,
                    origin_node: origin_node_str,
                    topic: topic_str,
                    diagnostics: resp.diagnostics,
                    pushdown_shards: shard_count,
                })
            }
            Err(err) => {
                let err_at = now_ms();
                let err_msg = err.to_string();
                let db = self.db();
                for shard in &plan.shards {
                    let _ = db.events().mark_pushdown_error(&shard.id, &err_msg, err_at);
                }
                Err(err)
            }
        }
    }

    /// Builds the local `TopicCatalogEntry` snapshot for `diagnose_subscription`.
    pub fn local_topic_catalog(&self) -> Vec<TopicCatalogEntry> {
        let mut observed_by_topic: BTreeMap<String, ObservedTopicStats> = {
            let db = self.db();
            db.events()
                .topic_event_stats(&[self.config.node_id.as_str(), LOCAL_NODE_ID])
                .unwrap_or_default()
                .into_iter()
                .map(|(topic, st)| {
                    (
                        topic,
                        ObservedTopicStats {
                            event_count: st.event_count,
                            last_event_at: st.last_received_at.map(format_rfc3339_millis),
                            sources: st.sources,
                            repos: st.repos,
                        },
                    )
                })
                .collect()
        };

        let mut catalog: Vec<TopicCatalogEntry> = self
            .config
            .topics
            .iter()
            .map(|t| {
                let bare = t.topic.strip_prefix("local.").unwrap_or(t.topic.as_str());
                let observed = observed_by_topic.remove(bare).unwrap_or_default();
                TopicCatalogEntry {
                    topic: t.topic.clone(),
                    has_provisioned_publisher: t.has_provisioned_publisher,
                    metadata: t.metadata.clone(),
                    observed,
                }
            })
            .collect();

        if let Some(gh) = self.github_public_adapter() {
            let gh_topic = gh.topic();
            if !catalog.iter().any(|c| c.topic == gh_topic) {
                let bare = gh_topic.strip_prefix("local.").unwrap_or(gh_topic);
                let observed = observed_by_topic.remove(bare).unwrap_or_default();
                catalog.push(TopicCatalogEntry {
                    topic: gh_topic.to_string(),
                    has_provisioned_publisher: true,
                    metadata: None,
                    observed,
                });
            }
        }
        if !catalog.iter().any(|c| c.topic == "kv") {
            let observed = observed_by_topic.remove("kv").unwrap_or_default();
            catalog.push(TopicCatalogEntry {
                topic: "kv".to_string(),
                has_provisioned_publisher: true,
                metadata: None,
                observed,
            });
        }
        if self.config.local_ingest.enabled {
            for ingest_topic in self.config.local_ingest.advertised_topics() {
                if !catalog.iter().any(|c| c.topic == ingest_topic) {
                    let bare = ingest_topic
                        .strip_prefix("local.")
                        .unwrap_or(ingest_topic.as_str());
                    let observed = observed_by_topic.remove(bare).unwrap_or_default();
                    catalog.push(TopicCatalogEntry {
                        topic: ingest_topic,
                        has_provisioned_publisher: true,
                        metadata: None,
                        observed,
                    });
                }
            }
        }

        // Include any local topics that already have stored events in SQLite even if not
        // statically declared in `config.topics` so diagnostics report accurate counts.
        for (topic, observed) in observed_by_topic {
            if observed.event_count > 0 && !catalog.iter().any(|c| c.topic == topic) {
                catalog.push(TopicCatalogEntry {
                    topic,
                    has_provisioned_publisher: true,
                    metadata: None,
                    observed,
                });
            }
        }

        catalog
    }

    /// Recomputes all active compiled subscriptions for `adapter.topic()` from `EventStore`
    /// across all peers and notifies the demand-driven `GitHubPublicAdapter`.
    pub(super) async fn sync_github_public_subscriptions(
        &self,
        adapter: &Arc<GitHubPublicAdapter>,
    ) -> Result<(), NodeError> {
        let target_topic = adapter.topic().to_string();
        let compiled: Vec<CompiledSubscription> = {
            let db = self.db();
            db.events()
                .list_subscriptions(None)?
                .into_iter()
                .filter(|s| s.topic == target_topic)
                .map(|s| CompiledSubscription {
                    id: s.id,
                    subscriber: s.subscriber,
                    topic: s.topic,
                    filters: s.filters.iter().map(store_filter_to_proto).collect(),
                    coalesce_seconds: s.coalesce_seconds.max(0) as u32,
                })
                .collect()
        };
        adapter
            .on_subscriptions_changed(&target_topic, &compiled)
            .await;
        Ok(())
    }

    /// Server-side handler for `PUT /v1/subscriptions`: checks `stream:subscribe` scope &
    /// dynamic `guest-ro` constraints, runs fail-closed `GitHubPublicAdapter::validate_subscription`
    /// BEFORE saving, persists in `EventStore`, and immediately syncs active subscriptions into
    /// `GitHubPublicAdapter::on_subscriptions_changed`.
    pub async fn handle_server_put_subscriptions(
        &self,
        caller: &AuthenticatedPeer,
        req: PutSubscriptionsRequest,
    ) -> Result<(Vec<Subscription>, Vec<SubscriptionDiagnostic>), NodeError> {
        let mut catalog = self.local_topic_catalog();
        // Issue #25 (B6): Never expose local-only topic names in remote subscription diagnostics.
        if caller.peer_id != self.config.node_id.as_str() {
            catalog.retain(|entry| !self.is_local_only_topic(&entry.topic));
        }
        let gh_adapter = self.github_public_adapter();
        let mut all_diagnostics = Vec::new();
        let mut specs = Vec::with_capacity(req.subscriptions.len());
        let mut incoming_guest_repos: BTreeSet<String> = BTreeSet::new();
        let incoming_namespaced_ids: HashSet<String> = req
            .subscriptions
            .iter()
            .map(|s| format!("{}::{}", caller.peer_id, s.id))
            .collect();

        for sub in &req.subscriptions {
            match caller
                .scopes
                .check_stream_subscribe(&sub.topic, &sub.filters)
            {
                Ok(approval) => {
                    // Issue #25 (B6): Local-only topics (`exposeTopic: false`, the default for
                    // subprocess `plugins[]` bridges & sources) MUST fail closed with 403 Forbidden
                    // for remote peers — EVEN IF the peer holds wildcard `stream:subscribe=*`
                    // (`member`, `observer`, `full` presets). Checked after scope verification so
                    // unprivileged peers cannot probe local-only topic names.
                    if caller.peer_id != self.config.node_id.as_str()
                        && self.is_local_only_topic(&sub.topic)
                    {
                        return Err(NodeError::TopicLocalOnly {
                            topic: sub.topic.clone(),
                        });
                    }
                    if caller.trust_tier == TrustTier::Guest {
                        let Some(confined_repos) =
                            extract_confined_values(&sub.filters, "exact", "repo")
                        else {
                            self.require_scope(
                                caller,
                                false,
                                &format!("stream:subscribe={}[require=exact.repo]", sub.topic),
                            )?;
                            unreachable!();
                        };
                        if confined_repos.is_empty() {
                            self.require_scope(
                                caller,
                                false,
                                &format!("stream:subscribe={}[require=exact.repo]", sub.topic),
                            )?;
                        }
                        for raw_repo in confined_repos {
                            let canonical = canonicalize_repo(&raw_repo)
                                .unwrap_or_else(|| raw_repo.to_ascii_lowercase());
                            incoming_guest_repos.insert(canonical);
                        }
                    }

                    // Fail-closed subscribe-time validation against attached `github-public` adapter
                    // BEFORE writing anything to SQLite!
                    if let Some(ref adapter) = gh_adapter {
                        if sub.topic == adapter.topic() {
                            let adapter_diags = adapter
                                .validate_subscription(&sub.topic, &sub.filters)
                                .await;
                            if let Some(first_err) = adapter_diags
                                .iter()
                                .find(|d| d.severity == DiagnosticSeverity::Error)
                            {
                                return Err(NodeError::SubscriptionRejected {
                                    detail: first_err.message.clone(),
                                    diagnostics: adapter_diags,
                                });
                            }
                            all_diagnostics.extend(adapter_diags);
                        }
                    }

                    let diags = diagnose_subscription(&sub.topic, &sub.filters, &catalog);
                    all_diagnostics.extend(diags);
                    let store_filters: Vec<hyp_store::Filter> =
                        sub.filters.iter().map(proto_filter_to_store).collect();
                    let namespaced_id = format!("{}::{}", caller.peer_id, sub.id);
                    let mut effective_wakes =
                        match (sub.max_wakes_per_hour, approval.max_batches_per_hour) {
                            (Some(a), Some(b)) => Some(a.min(b as usize)),
                            (Some(a), None) => Some(a),
                            (None, Some(b)) => Some(b as usize),
                            (None, None) => None,
                        };
                    if caller.trust_tier == TrustTier::Guest {
                        let cap = self.config.guest_pairing.max_batches_per_hour as usize;
                        effective_wakes = Some(effective_wakes.map_or(cap, |w| w.min(cap)));
                    }
                    specs.push(SubscriptionSpec {
                        id: namespaced_id,
                        origin_node: self.config.node_id.to_string(),
                        topic: sub.topic.clone(),
                        subscriber: caller.peer_id.clone(),
                        filters: store_filters,
                        coalesce_seconds: sub.coalesce_seconds,
                        max_batch_age_ms: sub.max_batch_age_ms,
                        max_wakes_per_hour: effective_wakes,
                        mode: sub.mode,
                    });
                }
                Err(hyp_proto::scopes::ScopeDenial::Denied { missing_scope, .. }) => {
                    self.require_scope(caller, false, &missing_scope)?;
                }
            }
        }

        // Cumulative per-guest repo cap across ALL active subscriptions for this guest peer!
        if caller.trust_tier == TrustTier::Guest {
            let max_repos = self.config.guest_pairing.max_repos_per_guest;
            let mut total_repos = incoming_guest_repos;
            {
                let db = self.db();
                for existing in db.events().list_subscriptions(Some(&caller.peer_id))? {
                    if incoming_namespaced_ids.contains(&existing.id) {
                        continue;
                    }
                    if req.replace_topic.as_deref() == Some(existing.topic.as_str()) {
                        continue;
                    }
                    let proto_filters: Vec<ProtoFilter> =
                        existing.filters.iter().map(store_filter_to_proto).collect();
                    if let Some(existing_repos) =
                        extract_confined_values(&proto_filters, "exact", "repo")
                    {
                        for raw_repo in existing_repos {
                            let canonical = canonicalize_repo(&raw_repo)
                                .unwrap_or_else(|| raw_repo.to_ascii_lowercase());
                            total_repos.insert(canonical);
                        }
                    }
                }
            }
            if total_repos.len() > max_repos {
                self.require_scope(
                    caller,
                    false,
                    &format!("stream:subscribe=github[maxValues={max_repos}]"),
                )?;
            }
        }

        let now = now_ms();
        let saved = {
            let db = self.db();
            if let Some(ref replace_topic) = req.replace_topic {
                let keep_ids: HashSet<&str> = specs.iter().map(|s| s.id.as_str()).collect();
                for existing in db.events().list_subscriptions(Some(&caller.peer_id))? {
                    if existing.topic == *replace_topic && !keep_ids.contains(existing.id.as_str())
                    {
                        let _ = db.events().delete_subscription(&existing.id);
                    }
                }
            }
            let mut out = Vec::with_capacity(specs.len());
            for spec in &specs {
                let mut s = db.events().upsert_subscription(spec, now)?;
                let prefix = format!("{}::", caller.peer_id);
                if let Some(stripped) = s.id.strip_prefix(&prefix) {
                    s.id = stripped.to_string();
                }
                out.push(s);
            }
            out
        };

        if let Some(ref adapter) = gh_adapter {
            let gh_topic = adapter.topic();
            let touches_gh = req.replace_topic.as_deref() == Some(gh_topic)
                || req.subscriptions.iter().any(|s| s.topic == gh_topic);
            if touches_gh {
                self.sync_github_public_subscriptions(adapter).await?;
            }
        }

        Ok((saved, all_diagnostics))
    }

    /// Server-side handler for `DELETE /v1/subscriptions?id=...`: deletes only caller-owned
    /// subscriptions and notifies `GitHubPublicAdapter::on_subscriptions_changed` so pollers tear
    /// down cleanly when refcount drops to `0`.
    pub async fn handle_server_delete_subscription(
        &self,
        caller: &AuthenticatedPeer,
        id: &str,
    ) -> Result<bool, NodeError> {
        let namespaced = format!("{}::{id}", caller.peer_id);
        let deleted = {
            let db = self.db();
            let owned_ids: HashSet<String> = db
                .events()
                .list_subscriptions(Some(&caller.peer_id))?
                .into_iter()
                .map(|s| s.id)
                .collect();
            if owned_ids.contains(&namespaced) {
                db.events().delete_subscription(&namespaced)?
            } else if owned_ids.contains(id) {
                db.events().delete_subscription(id)?
            } else {
                false
            }
        };

        if deleted {
            if let Some(adapter) = self.github_public_adapter() {
                self.sync_github_public_subscriptions(&adapter).await?;
            }
        }
        Ok(deleted)
    }

    /// Publishes an event onto a local or remote topic, stamping provenance hop headers.
    pub async fn publish_event(
        &self,
        qualified_topic: &str,
        mut event: ProtoCloudEvent,
    ) -> Result<IngestResult, NodeError> {
        let known_peers: Vec<NodeId> = {
            let db = self.db();
            db.peers()
                .list_peers(None)?
                .into_iter()
                .filter_map(|p| NodeId::new(p.peer_id).ok())
                .collect()
        };
        let resolved = resolve_topic(qualified_topic, &known_peers, &NodeScope::Local)?;
        let topic = resolved.topic.as_str().to_string();

        match resolved.node {
            NodeScope::Local => {
                let my_id = self.config.node_id.to_string();
                self.ingest_inbound_event(&my_id, &topic, &event)
            }
            NodeScope::Remote(peer_id) => {
                let max_hops = self.config.forwarding.effective_max_hops();
                event
                    .record_hop(&self.config.node_id, Some(&peer_id), max_hops)
                    .map_err(map_provenance_err)?;
                let link = self.require_peer_link(peer_id.as_str()).await?;
                link.publish_event(&PublishEventRequest { topic, event })
                    .await
            }
        }
    }

    /// Validates routing loop & hop-limit guards (`hyphaevia`, `hyphaehops`) and forwarding
    /// policy, then ingests `event` into local `EventStore` inside `BEGIN IMMEDIATE`.
    pub fn ingest_inbound_event(
        &self,
        caller_node: &str,
        topic: &str,
        event: &ProtoCloudEvent,
    ) -> Result<IngestResult, NodeError> {
        self.ingest_inbound_event_inner(caller_node, None, topic, event)
    }

    /// Authenticated variant of [`Self::ingest_inbound_event`] used by `POST /v1/events`:
    /// enforces BOTH local `forwarding` allowlist policy AND caller's explicit `forward:via`
    /// scope when ingesting foreign-origin transit events (`P1-7`).
    pub fn ingest_inbound_event_for_caller(
        &self,
        caller: &AuthenticatedPeer,
        topic: &str,
        event: &ProtoCloudEvent,
    ) -> Result<IngestResult, NodeError> {
        self.ingest_inbound_event_inner(&caller.peer_id, Some(caller), topic, event)
    }

    /// Returns `true` iff `topic` is owned by an attached provisioned source/webhook adapter
    /// (preventing remote peers from spoofing adapter-owned webhook streams via `POST /v1/events`).
    fn is_adapter_owned_topic(&self, topic: &str) -> bool {
        if let Some(gh) = self.github_public_adapter() {
            if gh.topic() == topic {
                return true;
            }
        }
        if self
            .github_webhooks
            .lock()
            .expect("github_webhooks lock poisoned")
            .values()
            .any(|a| a.topic() == topic)
        {
            return true;
        }
        self.config.topics.iter().any(|t| {
            t.topic == topic
                && t.has_provisioned_publisher
                && matches!(
                    t.kind.as_deref(),
                    Some(
                        "github-public"
                            | "github-webhook"
                            | "prometheus-webhook"
                            | "webhook-stream"
                            | "source"
                    )
                )
        })
    }

    fn ingest_inbound_event_inner(
        &self,
        caller_node: &str,
        caller: Option<&AuthenticatedPeer>,
        topic: &str,
        event: &ProtoCloudEvent,
    ) -> Result<IngestResult, NodeError> {
        // Local-only topic protection (Issue #25 / B6): reject remote peers attempting
        // `POST /v1/events` onto a local-only topic with `403 topic_local_only`.
        if caller_node != self.config.node_id.as_str() && self.is_local_only_topic(topic) {
            return Err(NodeError::TopicLocalOnly {
                topic: topic.to_string(),
            });
        }
        // Adapter-owned topic protection: reject remote peers attempting `POST /v1/events` onto
        // an adapter-owned webhook/source topic with `403 not_granted`.
        if caller_node != self.config.node_id.as_str() && self.is_adapter_owned_topic(topic) {
            let missing = format!("stream:publish={topic}");
            if let Some(peer) = caller {
                return Err(NodeError::ScopeDenied {
                    missing_scope: missing.clone(),
                    current_scopes: peer.scopes.raw_scopes().to_vec(),
                    escalation_note: self
                        .config
                        .escalation
                        .resolve(&missing)
                        .map(|n| n.as_str().to_string()),
                });
            }
            return Err(NodeError::ScopeDenied {
                missing_scope: missing,
                current_scopes: Vec::new(),
                escalation_note: None,
            });
        }

        let val = serde_json::to_value(event)?;
        let (mut validated, _) = hyp_proto::cloudevent::check_cloudevent_v2(&val)?;

        // Enforce strict cycle detection & hop limit cap (§2.3).
        let max_hops = self.config.forwarding.effective_max_hops();
        let prov = validated
            .check_forwarding(&self.config.node_id, None, max_hops)
            .map_err(map_provenance_err)?;

        // Determine effective origin & detect foreign transit cleanly even when `hyphaeorigin`
        // is omitted (never bypassing foreign-origin checks when `hyphaevia` or `hyphaehops`
        // indicates transit!).
        let foreign_origin: Option<String> = if caller_node != self.config.node_id.as_str() {
            if let Some(orig) = prov.origin.as_ref() {
                if orig.as_str() != caller_node && orig != &self.config.node_id {
                    Some(orig.as_str().to_string())
                } else {
                    prov.via
                        .iter()
                        .find(|v| v.as_str() != caller_node && *v != &self.config.node_id)
                        .map(|v| v.as_str().to_string())
                }
            } else if !prov.via.is_empty() {
                let first_via = &prov.via[0];
                validated.set_extension(hyp_proto::cloudevent::EXT_ORIGIN, first_via.as_str());
                prov.via
                    .iter()
                    .find(|v| v.as_str() != caller_node && *v != &self.config.node_id)
                    .map(|v| v.as_str().to_string())
            } else if prov.hops > 0 {
                return Err(NodeError::BadRequest(
                    "hyphaehops > 0 requires hyphaeorigin or hyphaevia".into(),
                ));
            } else {
                // Direct event from remote peer with omitted `hyphaeorigin`: default origin to `caller_node`.
                validated.set_extension(hyp_proto::cloudevent::EXT_ORIGIN, caller_node);
                None
            }
        } else {
            prov.origin
                .as_ref()
                .filter(|orig| orig.as_str() != caller_node && *orig != &self.config.node_id)
                .map(|orig| orig.as_str().to_string())
        };

        // Enforce default-deny transit forwarding + explicit `forward:via` for foreign-origin events (§2.3).
        if let Some(orig) = foreign_origin {
            let policy_ok = self.config.forwarding.permits(caller_node, "*", topic);
            let scope_ok = match caller {
                Some(peer) => peer.scopes.may_forward_via(&orig),
                None => true,
            };
            if !policy_ok || !scope_ok {
                if let Some(peer) = caller {
                    let missing = format!("forward:via={orig}");
                    return Err(NodeError::ScopeDenied {
                        missing_scope: missing.clone(),
                        current_scopes: peer.scopes.raw_scopes().to_vec(),
                        escalation_note: self
                            .config
                            .escalation
                            .resolve(&missing)
                            .map(|n| n.as_str().to_string()),
                    });
                }
                return Err(NodeError::Unauthorized(format!(
                    "transit forwarding denied by default policy for origin '{orig}' from '{caller_node}' on topic '{topic}'"
                )));
            }
        }

        // Record this node's hop in `hyphaeorigin`/`hyphaevia`/`hyphaehops` if cross-node.
        if caller_node != self.config.node_id.as_str() {
            validated
                .record_hop(&self.config.node_id, None, max_hops)
                .map_err(map_provenance_err)?;
        }

        // H4: Auto-process signed `to.hyphae.human.revocation.v1` events fail-closed when this
        // node has enrolled human authorities (blind relay hubs without authorities still validate
        // structure before fanning out to downstream nodes).
        if validated.event_type == TYPE_HUMAN_REVOCATION_V1 {
            let data_val = validated.data.as_ref().ok_or_else(|| {
                NodeError::BadRequest(
                    "to.hyphae.human.revocation.v1 event missing data payload".into(),
                )
            })?;
            let signed_rev = extract_signed_human_revocation(data_val)?;
            let has_authorities = {
                let db = self.db();
                !db.human().list_authorities(true)?.is_empty()
            };
            if has_authorities {
                self.apply_human_revocation(
                    &signed_rev,
                    caller_node == self.config.node_id.as_str(),
                )?;
            }
        }

        let store_ev = proto_ce_to_store(&validated)?;
        let now = now_ms();
        let res = {
            let db = self.db();
            db.events().ingest(
                self.config.node_id.as_str(),
                topic,
                caller_node,
                &store_ev,
                now,
            )?
        };
        self.notify_all_inbox_subscribers();
        self.notify_scheduler();
        Ok(res)
    }

    /// Closes due batches and flushes them into local session mailboxes, including
    /// subscriptions to remote topics. Peer pushdown batches belong to the SSE transport.
    pub fn flush_pending_local_topic_batches(&self) -> usize {
        let now = now_ms();
        let _ = self.db().events().tick(now);
        let total = self.flush_session_batch_routes(now, true);
        self.notify_scheduler();
        total
    }

    pub(super) fn flush_session_batch_routes(&self, now: i64, include_local_origin: bool) -> usize {
        let my_id = self.node_id().as_str();
        let routes = self
            .db()
            .events()
            .pending_session_batch_routes(my_id)
            .unwrap_or_default();
        let mut total = 0;
        for (origin, topic) in routes {
            if !include_local_origin && origin == my_id {
                continue;
            }
            if let Ok((_, batches)) = self.deliver_session_topic_batches(
                &origin,
                &topic,
                &MailboxPutOptions::default(),
                None,
                None,
                now,
            ) {
                total += batches;
            }
        }
        total
    }

    /// Like [`Self::deliver_local_topic_batches`], recording an explicit Stage 1 `gate_reason`
    /// (e.g. `"capped_to_queue"` or `"downgraded_to_notify"`).
    pub fn deliver_local_topic_batches(
        &self,
        topic: &str,
        put_opts: &MailboxPutOptions,
        human_auth: Option<&VerifiedHumanClaim>,
        gate_reason: Option<&str>,
        now_ms: i64,
    ) -> Result<usize, NodeError> {
        let bare_topic = topic
            .strip_prefix(&format!("{LOCAL_NODE_ID}."))
            .unwrap_or(topic);
        let _ = self.db().events().tick(now_ms);
        let (sessions_woken, _batches) = self.deliver_session_topic_batches(
            self.node_id().as_str(),
            bare_topic,
            put_opts,
            human_auth,
            gate_reason,
            now_ms,
        )?;
        self.notify_scheduler();
        Ok(sessions_woken)
    }

    fn deliver_session_topic_batches(
        &self,
        origin: &str,
        topic: &str,
        put_opts: &MailboxPutOptions,
        human_auth: Option<&VerifiedHumanClaim>,
        gate_reason: Option<&str>,
        now_ms: i64,
    ) -> Result<(usize, usize), NodeError> {
        let my_id = self.config.node_id.to_string();
        let auth_json = match human_auth {
            Some(claim) => Some(serde_json::to_string(claim)?),
            None => None,
        };
        let mut sessions_to_wake = BTreeSet::new();
        let mut batches_materialized = 0usize;

        {
            let db = self.db();
            let remote_peers: HashSet<String> = db
                .peers()
                .list_peers(None)?
                .into_iter()
                .map(|p| p.peer_id)
                .filter(|pid| pid != &my_id)
                .collect();

            let local_subscribers: BTreeSet<String> = db
                .events()
                .list_subscriptions(None)?
                .into_iter()
                .filter(|s| {
                    s.origin_node == origin
                        && s.topic == topic
                        && !remote_peers.contains(&s.subscriber)
                })
                .map(|s| s.subscriber)
                .collect();

            for subscriber in local_subscribers {
                // `claim_due_batches` yields at most one pending batch per subscription per call,
                // so drain boundedly while making progress to flush batches queued across downtime.
                const MAX_DRAIN_ROUNDS: usize = 64;
                for round in 1..=MAX_DRAIN_ROUNDS {
                    let due = db.events().claim_due_batches(&subscriber, now_ms)?;
                    let mut progressed = false;
                    for local_batch in due {
                        if local_batch.origin_node != origin || local_batch.topic != topic {
                            continue;
                        }
                        let kind = if local_batch.topic == "kv" {
                            MailboxKind::Kv
                        } else {
                            MailboxKind::Event
                        };
                        let traceparent = local_batch
                            .events
                            .first()
                            .and_then(|ev| {
                                ev.extensions.get(hyp_proto::cloudevent::EXT_TRACEPARENT)
                            })
                            .cloned();
                        let payload_text = serde_json::to_string(&json!({
                            "batchId": local_batch.id,
                            "originNode": local_batch.origin_node,
                            "topic": local_batch.topic,
                            "events": local_batch.events,
                        }))?;
                        let put = db.local().put_in_mailbox_ex(
                            &MailboxInsert {
                                session_id: subscriber.clone(),
                                origin_node: origin.to_owned(),
                                item_id: format!("batch:{}", local_batch.id),
                                text: payload_text,
                                kind,
                                source: format!(
                                    "{}.{}",
                                    if origin == my_id { "local" } else { origin },
                                    topic
                                ),
                                gate_state: GateState::Pending,
                                gate_reason: gate_reason.map(str::to_string),
                                traceparent,
                            },
                            put_opts,
                            now_ms,
                        )?;
                        match put {
                            MailboxPutResult::Stored { receipt } => {
                                if let Some(ref json_str) = auth_json {
                                    let _ =
                                        db.human().set_mailbox_human_auth(&receipt, json_str)?;
                                }
                                db.events().ack_batch(
                                    &subscriber,
                                    &local_batch.id,
                                    &AckOutcome::Delivered,
                                    now_ms,
                                )?;
                                sessions_to_wake.insert(subscriber.clone());
                                batches_materialized += 1;
                                progressed = true;
                            }
                            MailboxPutResult::Duplicate => {
                                db.events().ack_batch(
                                    &subscriber,
                                    &local_batch.id,
                                    &AckOutcome::Delivered,
                                    now_ms,
                                )?;
                                progressed = true;
                            }
                            MailboxPutResult::QueueFull => {
                                let _ = db.events().ack_batch(
                                    &subscriber,
                                    &local_batch.id,
                                    &AckOutcome::Hold {
                                        reason: "local_inbox_full".to_string(),
                                        retry_after_ms: Some(5_000),
                                    },
                                    now_ms,
                                );
                            }
                        }
                    }
                    if !progressed {
                        break;
                    }
                    if round == MAX_DRAIN_ROUNDS && origin != my_id {
                        // A high-cap subscription can still have ready batches. Yield this DB
                        // pass and schedule the rest without waiting for another peer event.
                        self.notify_scheduler();
                    }
                }
            }
        }

        let delivered = sessions_to_wake.len();
        for sid in sessions_to_wake {
            self.notify_local_session(&sid);
        }
        Ok((delivered, batches_materialized))
    }

    /// Ingests an inbound `DueBatch` delivered from remote peer `origin_node` inside
    /// `BEGIN IMMEDIATE` BEFORE the caller acknowledges upstream, enforcing loop/hop guards,
    /// transparently decrypting `kv.e2ee.v1` events, and delivering matching events to local
    /// session mailboxes!
    pub async fn handle_inbound_peer_batch(
        &self,
        origin_node: &str,
        batch: DueBatch,
    ) -> Result<(), NodeError> {
        // P1-6: Verify active peer status & stream/KV scope fail-closed on pulled SSE batches.
        if origin_node != self.config.node_id.as_str() {
            let auth_peer = match self.authorize_peer_action(
                origin_node,
                PeerAction::StreamDeliver {
                    topic: &batch.topic,
                },
            ) {
                Ok(peer) => peer,
                Err(err) => {
                    self.record_peer_scope_denied_audit(
                        origin_node,
                        &format!("stream.{}", batch.topic),
                        &err.to_string(),
                        batch.id.as_bytes(),
                    );
                    return Err(err);
                }
            };
            if batch.topic == "kv"
                && !peer_may_see_topic(&auth_peer.scopes, "kv")
                && !auth_peer.scopes.may_stream_publish("kv")
            {
                for ev in &batch.events {
                    let ns = ev.extensions.get("ns").map(String::as_str).unwrap_or("");
                    let key = ev.extensions.get("key").map(String::as_str).unwrap_or("");
                    if let Err(err) = self.require_scope(
                        &auth_peer,
                        auth_peer.scopes.may_kv_read(ns, key),
                        &format!("kv:read={ns}/{key}"),
                    ) {
                        self.record_peer_scope_denied_audit(
                            origin_node,
                            "stream.kv",
                            &err.to_string(),
                            batch.id.as_bytes(),
                        );
                        return Err(err);
                    }
                }
            }
        }

        let max_hops = self.config.forwarding.effective_max_hops();
        let origin_link = self.peer_link(origin_node).await;

        // 1. Validate loop/hop provenance, apply H4 human revocations, and decrypt `kv.e2ee.v1`.
        let mut prepared_events = Vec::with_capacity(batch.events.len());
        for mut ev in batch.events {
            let proto_ev = store_ce_to_proto(&ev);
            proto_ev
                .check_forwarding(&self.config.node_id, None, max_hops)
                .map_err(map_provenance_err)?;

            // H4 / N4: Auto-apply signed `to.hyphae.human.revocation.v1` events fail-closed
            // per-event: log + audit any malformed/unauthorized revocation event and continue
            // processing the remaining events in the batch rather than poisoning the whole batch!
            if ev.event_type == TYPE_HUMAN_REVOCATION_V1 {
                let apply_res = extract_signed_human_revocation(&ev.data)
                    .and_then(|signed_rev| self.ingest_human_revocation(&signed_rev));
                if let Err(err) = apply_res {
                    eprintln!(
                        "hyphae: ignoring invalid to.hyphae.human.revocation.v1 event '{}' from '{}': {err}",
                        ev.id, origin_node
                    );
                    let now = now_ms();
                    let db = self.db();
                    let _ = db.local().append_gate_audit(
                        &GateAuditInput {
                            direction: GateDirection::Inbound,
                            stage: "human_revocation".to_string(),
                            decision: StoreGateDecision::Block,
                            origin_node: Some(origin_node.to_string()),
                            source: Some(ev.source.clone()),
                            session_id: None,
                            receipt_id: None,
                            event_type: Some(TYPE_HUMAN_REVOCATION_V1.to_string()),
                            trust_tier: Some("peer".to_string()),
                            confidence: None,
                            categories: vec!["human.revocation_rejected".to_string()],
                            reason: Some(err.to_string()),
                            traceparent: None,
                            payload_sha256: sha256_hex(ev.id.as_bytes()),
                            reviewer: None,
                        },
                        now,
                    );
                    continue;
                }
            }

            // Transparently decrypt E2EE KV delta CloudEvents!
            if ev.event_type == "to.hyphae.kv.set" && ev.datacontenttype == CONTENT_TYPE_E2EE_JSON {
                if let Some(val_obj) = ev.data.get("value").cloned() {
                    if let Ok(kv_env) = serde_json::from_value::<KvEnvelopeV1>(val_obj.clone()) {
                        let ns = ev.extensions.get("ns").cloned().unwrap_or_default();
                        let key = ev.extensions.get("key").cloned().unwrap_or_default();
                        let writer = ev.extensions.get("writer").cloned().unwrap_or_default();
                        let version: u64 = ev
                            .extensions
                            .get("version")
                            .and_then(|s| s.parse().ok())
                            .unwrap_or(kv_env.version);
                        let writer_grant_id = val_obj
                            .get("writerGrantId")
                            .and_then(Value::as_str)
                            .unwrap_or("self")
                            .to_string();
                        if let Ok((writer_pk, _)) =
                            self.resolve_peer_keys(&writer, origin_link.as_ref()).await
                        {
                            if let Ok(rk) = self
                                .get_or_fetch_kv_room_key(
                                    origin_node,
                                    &ns,
                                    kv_env.epoch,
                                    origin_link.as_ref(),
                                )
                                .await
                            {
                                let min_epoch = self.current_min_epoch("kv", origin_node, &ns);
                                let max_seen = self.get_kv_seen_version(origin_node, &ns, &key);
                                let ctx = KvContext {
                                    host_node: origin_node,
                                    namespace: &ns,
                                    key: &key,
                                    version,
                                    writer_node_id: &writer,
                                    writer_grant_id: &writer_grant_id,
                                };
                                let pt_bytes = open_kv_entry(
                                    &kv_env, &ctx, &rk, &writer_pk, min_epoch, max_seen,
                                )?;
                                let pt_val: Value = serde_json::from_slice(&pt_bytes)?;
                                self.record_kv_seen_version(origin_node, &ns, &key, version);
                                if let Some(data_map) = ev.data.as_object_mut() {
                                    data_map.insert("value".to_string(), pt_val);
                                    data_map.insert("decrypted".to_string(), json!(true));
                                }
                                ev.datacontenttype = CONTENT_TYPE_JSON.to_string();
                            }
                        }
                    }
                }
            }
            prepared_events.push(ev);
        }

        // 2. Durable local ingest inside BEGIN IMMEDIATE per event + route to local session mailboxes.
        let now = now_ms();
        {
            let db = self.db();
            for ev in &prepared_events {
                db.events()
                    .ingest(origin_node, &batch.topic, origin_node, ev, now)?;
            }
            db.events().tick(now)?;
        }
        self.deliver_session_topic_batches(
            origin_node,
            &batch.topic,
            &MailboxPutOptions::default(),
            None,
            None,
            now,
        )?;
        self.notify_scheduler();
        Ok(())
    }
}
