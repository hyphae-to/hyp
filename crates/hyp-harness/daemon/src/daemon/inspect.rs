//! Metadata queries, inspect streaming, and debounced on-disk UI snapshots.

use super::{
    ClassifiedItemMeta, DaemonStateLock, INSPECT_WATCH_DEBOUNCE_MS, LocalDaemonInner,
    MAX_SOCKET_LINE_BYTES, MAX_SUMMARY_QUEUED_ITEMS, SubscriptionRecordMeta,
    UI_PROJECTOR_DEBOUNCE_MS, UI_STATE_SCHEMA_VERSION, is_valid_session_id, is_valid_terminal_id,
    read_bounded_line_async, write_ndjson_line_async,
};
use hyp_node::delivery::{DeliveryRule, DeliveryUrgency, muted_count};
use hyp_session_view::{
    BridgeTarget, Channel, Mute, QueuedItem, Rule, SessionCounts, SessionDetails, SessionViewInput,
    SubscriptionView, UnreadBreakdown, render_session,
};
use hyp_store::{MailboxVisibility, format_address};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, HashMap};
use std::io;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, BufReader};
use tokio::sync::watch;
use tokio::task::JoinHandle;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SummaryDetail {
    Compact,
    Full,
}

impl SummaryDetail {
    fn from_packet(packet: &Map<String, Value>) -> Result<Self, (&'static str, String)> {
        match packet.get("detail") {
            None | Some(Value::Null) => Ok(Self::Full),
            Some(Value::String(s)) => match s.trim().to_ascii_lowercase().as_str() {
                "compact" => Ok(Self::Compact),
                "full" => Ok(Self::Full),
                other => Err((
                    "invalid_request",
                    format!("Expected detail 'compact' | 'full', got '{other}'"),
                )),
            },
            Some(_) => Err(("invalid_request", "Expected string 'detail'".to_string())),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub(super) struct SessionSelector {
    pub(super) session_id: Option<String>,
    pub(super) herdr_terminal_id: Option<String>,
    pub(super) herdr_created_ms: Option<i64>,
    pub(super) handle: Option<String>,
    pub(super) cwd: Option<String>,
}

impl SessionSelector {
    pub(super) fn from_packet(packet: &Map<String, Value>) -> Result<Self, (&'static str, String)> {
        let session_id = match packet.get("sessionId") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) => {
                let trimmed = s.trim();
                if !is_valid_session_id(trimmed) {
                    return Err(("invalid_session", "Invalid sessionId".to_string()));
                }
                Some(trimmed.to_string())
            }
            Some(_) => return Err(("invalid_session", "Expected string sessionId".to_string())),
        };

        let herdr_terminal_id = match packet.get("herdrTerminalId") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) => {
                let trimmed = s.trim();
                if !is_valid_terminal_id(trimmed) {
                    return Err((
                        "invalid_herdr_terminal",
                        "Invalid herdrTerminalId".to_string(),
                    ));
                }
                Some(trimmed.to_string())
            }
            Some(_) => {
                return Err((
                    "invalid_herdr_terminal",
                    "Expected string herdrTerminalId".to_string(),
                ));
            }
        };

        let herdr_created_ms = match packet.get("herdrCreatedMs") {
            None | Some(Value::Null) => None,
            Some(v) => match v.as_i64() {
                Some(ms) => Some(ms),
                None => {
                    return Err((
                        "invalid_request",
                        "Expected integer herdrCreatedMs".to_string(),
                    ));
                }
            },
        };

        let handle = match packet.get("handle") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) => {
                let clean = s.trim().strip_prefix('@').unwrap_or(s.trim());
                if clean.is_empty() || clean.chars().any(char::is_control) {
                    return Err(("invalid_request", "Invalid handle".to_string()));
                }
                Some(clean.to_string())
            }
            Some(_) => return Err(("invalid_request", "Expected string handle".to_string())),
        };

        let cwd = match packet.get("cwd") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) => {
                let trimmed = s.trim();
                if trimmed.is_empty()
                    || trimmed.len() > 1024
                    || trimmed.chars().any(char::is_control)
                {
                    return Err(("invalid_request", "Invalid cwd".to_string()));
                }
                Some(trimmed.to_string())
            }
            Some(_) => return Err(("invalid_request", "Expected string cwd".to_string())),
        };

        Ok(Self {
            session_id,
            herdr_terminal_id,
            herdr_created_ms,
            handle,
            cwd,
        })
    }

    fn has_target(&self) -> bool {
        self.session_id.is_some()
            || self.herdr_terminal_id.is_some()
            || self.handle.is_some()
            || self.cwd.is_some()
    }
}

pub(super) fn extract_backend_str(backend_json: &str, key: &str) -> Option<String> {
    serde_json::from_str::<Value>(backend_json)
        .ok()
        .and_then(|v| {
            v.get(key)
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(ToString::to_string)
        })
}

fn extract_backend_i64(backend_json: &str, key: &str) -> Option<i64> {
    serde_json::from_str::<Value>(backend_json)
        .ok()
        .and_then(|v| v.get(key).and_then(Value::as_i64))
}

fn summarize_filter_node(filter: &hyp_store::Filter) -> String {
    match filter {
        hyp_store::Filter::Exact(map) => map
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(", "),
        hyp_store::Filter::Prefix(map) => map
            .iter()
            .map(|(k, v)| format!("{k}^={v}"))
            .collect::<Vec<_>>()
            .join(", "),
        hyp_store::Filter::Suffix(map) => map
            .iter()
            .map(|(k, v)| format!("{k}$={v}"))
            .collect::<Vec<_>>()
            .join(", "),
        hyp_store::Filter::All(list) => list
            .iter()
            .map(summarize_filter_node)
            .collect::<Vec<_>>()
            .join(" AND "),
        hyp_store::Filter::Any(list) => {
            let inner = list
                .iter()
                .map(summarize_filter_node)
                .collect::<Vec<_>>()
                .join(" OR ");
            format!("({inner})")
        }
        hyp_store::Filter::Not(inner) => format!("!({})", summarize_filter_node(inner)),
    }
}

fn summarize_filters(filters: &[hyp_store::Filter]) -> String {
    if filters.is_empty() {
        return String::new();
    }
    filters
        .iter()
        .map(summarize_filter_node)
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(", ")
}

pub(super) fn validate_control_pattern(raw: &str) -> Result<String, (&'static str, String)> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.chars().any(char::is_control) {
        return Err((
            "invalid_request",
            "Pattern must be non-empty and contain no control characters".to_string(),
        ));
    }
    let rule = DeliveryRule::new(trimmed, DeliveryUrgency::Mute);
    rule.validate()
        .map_err(|e| ("invalid_request", e.to_string()))?;
    Ok(rule.target)
}

type HerdrCandidateRank = (bool, i64, bool, bool);

impl LocalDaemonInner {
    fn session_herdr_terminal_id(&self, sess: &hyp_store::Session) -> Option<String> {
        let from_transport = self
            .attached_push_transport(&sess.id)
            .and_then(|transport| transport.herdr_terminal_id().map(ToString::to_string));
        from_transport.or_else(|| {
            extract_backend_str(&sess.backend_json, "herdrTerminalId")
                .filter(|tid| is_valid_terminal_id(tid))
        })
    }

    fn session_herdr_created_ms(&self, sess: &hyp_store::Session) -> Option<i64> {
        let from_transport = self
            .attached_push_transport(&sess.id)
            .and_then(|transport| transport.herdr_created_ms());
        from_transport.or_else(|| extract_backend_i64(&sess.backend_json, "herdrCreatedMs"))
    }

    fn rank_herdr_candidate(
        &self,
        sess: &hyp_store::Session,
        expected_created_ms: Option<i64>,
    ) -> HerdrCandidateRank {
        let pinned_created = self.session_herdr_created_ms(sess);
        let exact_created_match = match (expected_created_ms, pinned_created) {
            (Some(exp), Some(actual)) => exp == actual,
            _ => false,
        };
        let enrolled = sess.handle.is_some();
        let has_live = self.has_live_transport(&sess.id);
        (exact_created_match, sess.last_seen, enrolled, has_live)
    }

    pub(super) fn resolve_session_by_herdr_terminal(
        &self,
        terminal_id: &str,
        expected_created_ms: Option<i64>,
    ) -> Option<hyp_store::Session> {
        if !is_valid_terminal_id(terminal_id) {
            return None;
        }
        let transports: Vec<_> = self
            .session_runtime()
            .iter()
            .filter_map(|(session_id, runtime)| {
                runtime
                    .attached_transport
                    .as_ref()
                    .map(|attached| (session_id.clone(), Arc::clone(&attached.transport)))
            })
            .collect();
        let transport_ids: Vec<_> = transports
            .into_iter()
            .filter_map(|(session_id, transport)| {
                (transport.herdr_terminal_id() == Some(terminal_id)).then_some(session_id)
            })
            .collect();
        let mut candidate_map: HashMap<String, hyp_store::Session> = HashMap::new();
        {
            let db = self.node.db();
            if let Ok(by_tid) = db.local().list_sessions_by_herdr_terminal(terminal_id) {
                for sess in by_tid {
                    candidate_map.insert(sess.id.clone(), sess);
                }
            }
            let indexed_ids: Vec<String> = self
                .herdr_terminal_index
                .lock_state("herdr_terminal_index lock poisoned")
                .get(terminal_id)
                .cloned()
                .unwrap_or_default();
            for sid in indexed_ids.into_iter().chain(transport_ids) {
                if !candidate_map.contains_key(&sid) {
                    if let Ok(Some(sess)) = db.local().get_session(&sid) {
                        candidate_map.insert(sess.id.clone(), sess);
                    }
                }
            }
        }

        let mut best: Option<((bool, i64, bool, bool), hyp_store::Session)> = None;
        for sess in candidate_map.into_values() {
            if let Some(exp) = expected_created_ms {
                if let Some(actual) = self.session_herdr_created_ms(&sess) {
                    if actual != exp {
                        continue;
                    }
                }
            }
            let rank = self.rank_herdr_candidate(&sess, expected_created_ms);
            let is_better = match best {
                None => true,
                Some((prev_rank, ref prev_sess)) => {
                    rank > prev_rank || (rank == prev_rank && sess.id < prev_sess.id)
                }
            };
            if is_better {
                best = Some((rank, sess));
            }
        }
        best.map(|(_, s)| s)
    }

    pub(super) fn resolve_session(&self, sel: &SessionSelector) -> Option<hyp_store::Session> {
        if let Some(ref sid) = sel.session_id {
            let db = self.node.db();
            let sess = db.local().get_session(sid).ok().flatten()?;
            if let Some(exp) = sel.herdr_created_ms {
                if let Some(actual) = self.session_herdr_created_ms(&sess) {
                    if actual != exp {
                        return None;
                    }
                }
            }
            return Some(sess);
        }
        if let Some(ref tid) = sel.herdr_terminal_id {
            return self.resolve_session_by_herdr_terminal(tid, sel.herdr_created_ms);
        }
        if let Some(ref handle) = sel.handle {
            let db = self.node.db();
            return db.local().session_by_handle(handle).ok().flatten();
        }
        if let Some(ref cwd) = sel.cwd {
            let db = self.node.db();
            let sessions = db.local().list_sessions().unwrap_or_default();
            let mut best: Option<((i64, bool, bool), hyp_store::Session)> = None;
            for sess in sessions {
                if extract_backend_str(&sess.backend_json, "cwd").as_deref() != Some(cwd.as_str()) {
                    continue;
                }
                let rank = (
                    sess.last_seen,
                    sess.handle.is_some(),
                    self.has_live_transport(&sess.id),
                );
                let is_better = match best {
                    None => true,
                    Some((prev_rank, ref prev_sess)) => {
                        rank > prev_rank || (rank == prev_rank && sess.id < prev_sess.id)
                    }
                };
                if is_better {
                    best = Some((rank, sess));
                }
            }
            return best.map(|(_, s)| s);
        }
        None
    }

    /// Builds the strictly metadata-only `daemon` status header without blocking or mutating DB state.
    fn build_daemon_summary_json(&self) -> Value {
        self.build_daemon_summary_json_with_online(true)
    }

    fn build_daemon_summary_json_with_online(&self, online: bool) -> Value {
        let (peers_online, quarantined_global) = {
            let db = self.node.db();
            let peers = db
                .peers()
                .list_peers(Some(hyp_store::PeerStatus::Active))
                .map(|v| v.len())
                .unwrap_or(0);
            let quarantined = db.local().quarantined_count(None).unwrap_or(0);
            (peers, quarantined)
        };
        json!({
            "online": online,
            "pid": std::process::id(),
            "nodeId": self.node.node_id().as_str(),
            "version": self.node.config().hyphae_version,
            "profile": self.node.config().profile,
            "peersOnline": peers_online,
            "quarantinedGlobal": quarantined_global,
        })
    }

    /// Builds a strictly metadata-only session summary object (ZERO message bodies, ZERO
    /// CloudEvent `data`, ZERO quarantined payloads or sources).
    ///
    /// Strictly read-only and non-blocking: never awaits `wait_for_pending_probe` and never
    /// calls `reconcile_session_inbox`.
    fn build_session_summary_obj(&self, sess: &hyp_store::Session, detail: SummaryDetail) -> Value {
        let node_id = self.node.node_id().as_str();
        let harness = extract_backend_str(&sess.backend_json, "kind")
            .or_else(|| {
                sess.id
                    .split_once(':')
                    .map(|(prefix, _)| prefix.to_string())
            })
            .unwrap_or_else(|| "unknown".to_string());
        let address = sess.handle.as_deref().map(|h| format_address(node_id, h));
        let herdr_terminal_id = self.session_herdr_terminal_id(sess);
        let herdr_created_ms = self.session_herdr_created_ms(sess);
        let transport_kind = self.active_transport_kind(&sess.id);

        let now = self.current_time_ms();
        self.sweep_expired_mutes_and_policies(now);
        let visibility = MailboxVisibility::for_gate(self.current_gate().is_some());
        let (
            policy,
            digest,
            muted_archived,
            mutes,
            subs,
            bridge_entries,
            channel_pairs,
            queued_meta,
        ) = {
            let db = self.node.db();
            let policy = self.delivery.policy(&db, &sess.id).unwrap_or_default();
            let digest = db
                .local()
                .unread_digest_with_visibility(&sess.id, visibility)
                .unwrap_or_default();
            let muted_archived = muted_count(&db, &sess.id).unwrap_or(0);
            let mutes = db
                .local()
                .list_mutes_at(Some(&sess.id), now)
                .unwrap_or_default();
            let subs = db
                .events()
                .list_subscriptions(Some(&sess.id))
                .unwrap_or_default();
            let bridge_links = db
                .local()
                .bridge_links_for_session(&sess.id)
                .unwrap_or_default();
            let mut bridge_entries = Vec::with_capacity(bridge_links.len());
            for link in bridge_links {
                let is_primary = db
                    .local()
                    .get_plugin_target(&link.plugin, &link.target)
                    .ok()
                    .flatten()
                    .is_some_and(|h| h.session_id == sess.id);
                bridge_entries.push(BridgeTarget {
                    plugin: link.plugin,
                    target: link.target,
                    primary: is_primary,
                });
            }
            let channel_pairs = match address.as_deref() {
                Some(addr) => db
                    .channels()
                    .list_channels_for_address(addr)
                    .unwrap_or_default(),
                None => Vec::new(),
            };
            let queued_meta = if detail == SummaryDetail::Full {
                db.local()
                    .list_pending_metadata_with_visibility(
                        &sess.id,
                        MAX_SUMMARY_QUEUED_ITEMS,
                        visibility,
                    )
                    .unwrap_or_default()
            } else {
                Vec::new()
            };
            (
                policy,
                digest,
                muted_archived,
                mutes,
                subs,
                bridge_entries,
                channel_pairs,
                queued_meta,
            )
        };

        let input = SessionViewInput {
            session_id: sess.id.clone(),
            harness,
            handle: sess.handle.clone(),
            address,
            herdr_terminal_id,
            herdr_created_ms,
            last_seen: sess.last_seen,
            transport_kind: transport_kind.map(str::to_owned),
            delivery_mode: policy.default_mode.as_str().to_owned(),
            focus_mode: policy.focus_mode,
            focus_allow_interrupt_vips: policy.focus_allow_interrupt_vips,
            muted_all: mutes.iter().any(|m| m.pattern == "*")
                || policy
                    .overrides
                    .iter()
                    .any(|r| r.is_wildcard() && r.delivery == DeliveryUrgency::Mute),
            counts: SessionCounts {
                subscriptions: subs.len(),
                bridges: bridge_entries.len(),
                queued: digest.unread,
                unnotified: digest.unnotified,
                quarantined: digest.quarantined,
                muted_rules: mutes.len(),
                muted_archived,
                channels: channel_pairs.len(),
            },
            bridges: bridge_entries,
            unread: UnreadBreakdown {
                messages: digest.messages,
                events: digest.events,
                plugins: digest.plugins,
                transfers: digest.transfers,
                kv: digest.kv,
                sources: digest.sources,
            },
        };
        let details = if detail == SummaryDetail::Full {
            let stored_meta = {
                let db = self.node.db();
                db.events().list_subscription_meta().unwrap_or_default()
            };
            let sub_meta_map: HashMap<String, SubscriptionRecordMeta> = self
                .sub_meta
                .lock()
                .expect("sub_meta lock poisoned")
                .get(&sess.id)
                .map(|list| list.iter().map(|m| (m.id.clone(), m.clone())).collect())
                .unwrap_or_default();

            let subscriptions = subs
                .into_iter()
                .map(|s| {
                    let meta = sub_meta_map.get(&s.id);
                    let persisted = stored_meta.get(&s.id);
                    let key = meta
                        .and_then(|m| m.key.clone())
                        .or_else(|| persisted.and_then(|m| m.key.clone()));
                    let mode_str = meta
                        .map(|m| m.urgency.as_str().to_string())
                        .or_else(|| persisted.and_then(|m| m.urgency.clone()))
                        .unwrap_or_else(|| {
                            DeliveryUrgency::from_store_mode(s.mode)
                                .as_str()
                                .to_string()
                        });
                    let filter_summary = summarize_filters(&s.filters);
                    SubscriptionView {
                        id: s.id,
                        key,
                        origin_node: s.origin_node,
                        topic: s.topic,
                        mode: mode_str,
                        coalesce_seconds: s.coalesce_seconds,
                        filters: s.filters,
                        filter_summary,
                    }
                })
                .collect();

            let item_meta_map: HashMap<String, ClassifiedItemMeta> = self
                .item_meta
                .lock()
                .expect("item_meta lock poisoned")
                .get(&sess.id)
                .cloned()
                .unwrap_or_default();

            // Strictly metadata-only: `queued_meta` never even selected `mailbox.text` from SQLite!
            let queued_items = queued_meta
                .into_iter()
                .map(|item| {
                    let cached = item_meta_map.get(&item.receipt);
                    let urgency = match cached {
                        Some(m) => m.urgency,
                        None => {
                            let parsed = hyp_node::delivery::ParsedMailboxSource::parse(
                                &item.origin_node,
                                &item.source,
                                item.kind,
                            );
                            let sub_mode = self.lookup_subscription_urgency(
                                &sess.id,
                                &item.origin_node,
                                &item.source,
                            );
                            policy.resolve_urgency(&parsed.as_context(), sub_mode, None)
                        }
                    };
                    let notified = item.notified || cached.is_some_and(|m| m.notified);
                    QueuedItem {
                        receipt: item.receipt,
                        kind: item.kind.as_str(),
                        source: item.source,
                        origin_node: item.origin_node,
                        received_at: item.received_at,
                        notified,
                        urgency: urgency.as_str(),
                    }
                })
                .collect();

            let mutes = mutes
                .into_iter()
                .map(|m| Mute {
                    pattern: m.pattern,
                    global: m.scope == "*",
                    muted_at: m.muted_at,
                    expires_at: m.expires_at,
                })
                .collect();
            let rules = policy
                .overrides
                .into_iter()
                .map(|r| Rule {
                    target: r.target,
                    delivery: r.delivery.as_str(),
                })
                .collect();
            let channels = channel_pairs
                .into_iter()
                .map(|(host_node, channel)| {
                    let mode = self.node.get_channel_policy(&channel).mode.as_str();
                    Channel {
                        host_node,
                        channel,
                        mode,
                    }
                })
                .collect();
            Some(SessionDetails {
                subscriptions,
                queued_items,
                mutes,
                rules,
                channels,
            })
        } else {
            None
        };
        render_session(node_id, input, details)
    }

    fn build_single_session_summary_envelope(
        &self,
        sel: &SessionSelector,
        detail: SummaryDetail,
    ) -> Value {
        let rev = self.current_ui_rev();
        let updated_at = self.current_time_ms();
        let daemon_block = self.build_daemon_summary_json();
        let session_val = match self.resolve_session(sel) {
            Some(sess) => self.build_session_summary_obj(&sess, detail),
            None => Value::Null,
        };
        json!({
            "schemaVersion": UI_STATE_SCHEMA_VERSION,
            "rev": rev,
            "updatedAt": updated_at,
            "daemon": daemon_block,
            "session": session_val,
        })
    }

    fn build_all_sessions_summary_envelope_with_online(
        &self,
        detail: SummaryDetail,
        online: bool,
        include_kv: bool,
    ) -> Value {
        let rev = self.current_ui_rev();
        let updated_at = self.current_time_ms();
        let daemon_block = self.build_daemon_summary_json_with_online(online);
        let sessions = {
            let db = self.node.db();
            db.local().list_sessions().unwrap_or_default()
        };

        let mut sessions_json: Vec<Value> = Vec::with_capacity(sessions.len());
        let mut terminal_winners: BTreeMap<String, (HerdrCandidateRank, String)> = BTreeMap::new();

        for sess in &sessions {
            sessions_json.push(self.build_session_summary_obj(sess, detail));
            if let Some(tid) = self.session_herdr_terminal_id(sess) {
                let rank = self.rank_herdr_candidate(sess, None);
                let replace = match terminal_winners.get(&tid) {
                    None => true,
                    Some((prev_rank, prev_sid)) => {
                        rank > *prev_rank || (rank == *prev_rank && sess.id < *prev_sid)
                    }
                };
                if replace {
                    terminal_winners.insert(tid, (rank, sess.id.clone()));
                }
            }
        }

        let by_herdr_terminal: BTreeMap<String, String> = terminal_winners
            .into_iter()
            .map(|(tid, (_, sid))| (tid, sid))
            .collect();

        let mut snapshot = json!({
            "schemaVersion": UI_STATE_SCHEMA_VERSION,
            "rev": rev,
            "updatedAt": updated_at,
            "daemon": daemon_block,
            "sessions": sessions_json,
            "byHerdrTerminal": by_herdr_terminal,
        });
        if include_kv && detail == SummaryDetail::Full {
            snapshot["kv"] = json!(self.node.inspect_local_kv(updated_at).ok());
        }
        snapshot
    }

    pub(super) fn write_ui_state_snapshot(&self) -> io::Result<()> {
        self.write_ui_state_snapshot_with_online(true)
    }

    pub(super) fn write_ui_state_snapshot_with_online(&self, online: bool) -> io::Result<()> {
        let ui_dir = self.node.config().state_dir.join("ui");
        let snapshot =
            self.build_all_sessions_summary_envelope_with_online(SummaryDetail::Full, online, true);
        let rev = snapshot
            .get("rev")
            .and_then(Value::as_u64)
            .unwrap_or_else(|| self.current_ui_rev());
        let bytes = serde_json::to_vec(&snapshot)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        write_ui_state_atomic(&ui_dir, rev, &bytes)
    }
}

fn write_ui_state_atomic(ui_dir: &Path, rev: u64, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write as _;

    std::fs::create_dir_all(ui_dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(ui_dir, std::fs::Permissions::from_mode(0o700))?;
    }

    let tmp_name = format!(".state.json.tmp.{}.{rev}", std::process::id());
    let tmp_path = ui_dir.join(tmp_name);
    let dest_path = ui_dir.join("state.json");

    let write_res: io::Result<()> = (|| {
        #[cfg(unix)]
        let mut file = {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp_path)?
        };
        #[cfg(not(unix))]
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp_path)?;

        file.write_all(bytes)?;
        file.flush()?;
        drop(file);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600))?;
        }

        #[cfg(unix)]
        {
            std::fs::rename(&tmp_path, &dest_path)?;
        }
        #[cfg(not(unix))]
        {
            if std::fs::rename(&tmp_path, &dest_path).is_err() {
                let _ = std::fs::remove_file(&dest_path);
                std::fs::rename(&tmp_path, &dest_path)?;
            }
        }
        Ok(())
    })();

    if write_res.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
    }
    write_res
}

pub(super) fn spawn_ui_state_projector(
    inner: Arc<LocalDaemonInner>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> JoinHandle<()> {
    let mut rev_rx = inner.subscribe_ui_rev();
    let mut last_written = *rev_rx.borrow_and_update();
    tokio::spawn(async move {
        loop {
            if *rev_rx.borrow_and_update() == last_written {
                let changed = tokio::select! {
                    res = rev_rx.changed() => res.is_ok(),
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            break;
                        }
                        continue;
                    }
                };
                if !changed {
                    break;
                }
            }
            // Coalesce burst mutations cleanly over UI_PROJECTOR_DEBOUNCE_MS (~100 ms).
            let debounce = tokio::time::sleep(Duration::from_millis(UI_PROJECTOR_DEBOUNCE_MS));
            tokio::pin!(debounce);
            let mut stopped = false;
            loop {
                tokio::select! {
                    _ = &mut debounce => break,
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            stopped = true;
                            break;
                        }
                    }
                }
            }
            if stopped {
                break;
            }
            let latest = *rev_rx.borrow_and_update();
            if latest != last_written {
                let _ = inner.write_ui_state_snapshot();
                last_written = latest;
            }
        }
    })
}

pub(super) fn handle_session_summary(
    daemon: &LocalDaemonInner,
    packet: &Map<String, Value>,
) -> Value {
    let sel = match SessionSelector::from_packet(packet) {
        Ok(s) => s,
        Err((code, msg)) => return json!({ "ok": false, "code": code, "error": msg }),
    };
    let detail = match SummaryDetail::from_packet(packet) {
        Ok(d) => d,
        Err((code, msg)) => return json!({ "ok": false, "code": code, "error": msg }),
    };
    let result = daemon.build_single_session_summary_envelope(&sel, detail);
    json!({ "ok": true, "result": result })
}

pub(super) fn handle_sessions_summary(
    daemon: &LocalDaemonInner,
    packet: &Map<String, Value>,
    include_kv: bool,
) -> Value {
    let detail = match SummaryDetail::from_packet(packet) {
        Ok(d) => d,
        Err((code, msg)) => return json!({ "ok": false, "code": code, "error": msg }),
    };
    let result = daemon.build_all_sessions_summary_envelope_with_online(detail, true, include_kv);
    json!({ "ok": true, "result": result })
}

fn build_inspect_snapshot_packet(
    daemon: &LocalDaemonInner,
    sel: &SessionSelector,
    detail: SummaryDetail,
    include_kv: bool,
) -> Value {
    let mut envelope = if sel.has_target() {
        daemon.build_single_session_summary_envelope(sel, detail)
    } else {
        daemon.build_all_sessions_summary_envelope_with_online(detail, true, include_kv)
    };
    if let Some(obj) = envelope.as_object_mut() {
        obj.insert("type".into(), json!("inspect.snapshot"));
    }
    envelope
}

pub(super) async fn run_inspect_watch<R, W>(
    daemon: &Arc<LocalDaemonInner>,
    packet: &Map<String, Value>,
    include_kv: bool,
    reader: &mut BufReader<R>,
    write_half: &mut W,
    shutdown_rx: &mut watch::Receiver<bool>,
) where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let sel = match SessionSelector::from_packet(packet) {
        Ok(s) => s,
        Err((code, msg)) => {
            let _ = write_ndjson_line_async(
                write_half,
                &json!({ "type": "inspect.error", "code": code, "error": msg }),
            )
            .await;
            return;
        }
    };
    let detail = match SummaryDetail::from_packet(packet) {
        Ok(d) => d,
        Err((code, msg)) => {
            let _ = write_ndjson_line_async(
                write_half,
                &json!({ "type": "inspect.error", "code": code, "error": msg }),
            )
            .await;
            return;
        }
    };

    let mut rev_rx = daemon.subscribe_ui_rev();
    let initial = build_inspect_snapshot_packet(daemon, &sel, detail, include_kv);
    let mut last_sent_rev = initial
        .get("rev")
        .and_then(Value::as_u64)
        .unwrap_or_else(|| *rev_rx.borrow_and_update());
    let _ = rev_rx.borrow_and_update();

    if write_ndjson_line_async(write_half, &initial).await.is_err() {
        return;
    }

    loop {
        enum WatchEv {
            RevChanged,
            ClientClosed,
            Shutdown,
            IgnoreLine,
        }

        let ev = tokio::select! {
            res = rev_rx.changed() => {
                if res.is_ok() {
                    WatchEv::RevChanged
                } else {
                    WatchEv::Shutdown
                }
            }
            line = read_bounded_line_async(reader, MAX_SOCKET_LINE_BYTES) => {
                match line {
                    Ok(None) | Err(_) => WatchEv::ClientClosed,
                    Ok(Some(_)) => WatchEv::IgnoreLine,
                }
            }
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    WatchEv::Shutdown
                } else {
                    WatchEv::IgnoreLine
                }
            }
        };

        match ev {
            WatchEv::ClientClosed | WatchEv::Shutdown => break,
            WatchEv::IgnoreLine => continue,
            WatchEv::RevChanged => {
                let debounce = tokio::time::sleep(Duration::from_millis(INSPECT_WATCH_DEBOUNCE_MS));
                tokio::pin!(debounce);
                let mut exit_now = false;
                loop {
                    tokio::select! {
                        _ = &mut debounce => break,
                        line = read_bounded_line_async(reader, MAX_SOCKET_LINE_BYTES) => {
                            if !matches!(line, Ok(Some(_))) {
                                exit_now = true;
                                break;
                            }
                        }
                        _ = shutdown_rx.changed() => {
                            if *shutdown_rx.borrow() {
                                exit_now = true;
                                break;
                            }
                        }
                    }
                }
                if exit_now {
                    break;
                }
                let latest = *rev_rx.borrow_and_update();
                if latest == last_sent_rev {
                    continue;
                }
                let snap = build_inspect_snapshot_packet(daemon, &sel, detail, include_kv);
                last_sent_rev = snap.get("rev").and_then(Value::as_u64).unwrap_or(latest);
                if write_ndjson_line_async(write_half, &snap).await.is_err() {
                    break;
                }
            }
        }
    }
}
