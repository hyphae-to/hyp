//! Unified Filtered & Paginated Inbox Query (`query_inbox`) and durable `muted` / `delivered`
//! archival helpers backed by `NodeDb` (`docs/architecture-v2.md` §2.5).
//!
//! Security invariant:
//! - `query_inbox` NEVER exposes `quarantined` or `rejected` items under ANY state filter,
//!   explicit `ids` lookup, or metadata count. Quarantine review is strictly human-CLI-only.

use std::collections::{BTreeMap, HashSet};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hyp_proto::cloudevent::{CONTENT_TYPE_JSON, CloudEvent as ProtoCloudEvent};
use hyp_proto::filter::{Filter as ProtoFilter, matches_filters};
use hyp_store::{
    GateState, MailboxEntry, MailboxInsert, MailboxKind, MailboxPutResult, NodeDb,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::delivery::policy::{
    DeliveryError, ParsedMailboxSource, SessionDeliveryPolicy, normalize_channel_lower,
};

const MAX_LIMIT: usize = 50;
const DEFAULT_LIMIT: usize = 20;
const MAX_ARCHIVE_RECEIPTS: usize = 500;
const PREVIEW_MAX_CHARS: usize = 140;

const META_POLICY_PREFIX: &str = "delivery:policy:";
const META_MUTED_INDEX_PREFIX: &str = "delivery:muted:";
const META_DELIVERED_INDEX_PREFIX: &str = "delivery:delivered:";

/// Allowed mailbox states exposed to agents via `hyp_inbox` (NEVER includes `quarantined`/`rejected`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InboxStateFilter {
    #[default]
    Unread,
    Muted,
    Delivered,
    All,
}

impl InboxStateFilter {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unread => "unread",
            Self::Muted => "muted",
            Self::Delivered => "delivered",
            Self::All => "all",
        }
    }

    /// Parses a state string fail-closed, rejecting `"quarantined"` and `"rejected"`.
    pub fn parse(raw: &str) -> Result<Self, DeliveryError> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "unread" | "pending" => Ok(Self::Unread),
            "muted" | "mute" => Ok(Self::Muted),
            "delivered" | "read" => Ok(Self::Delivered),
            "all" => Ok(Self::All),
            "quarantined" | "quarantine" | "rejected" => {
                Err(DeliveryError::ForbiddenState(raw.trim().to_string()))
            }
            other => Err(DeliveryError::InvalidState(other.to_string())),
        }
    }
}

/// Structured filter parameters for [`query_inbox`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InboxFilter {
    /// Matches sender address, handle, `@handle`, or source (case-insensitive exact or prefix wildcard).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    /// Matches `origin_node` or sender node ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    /// Matches event stream topic name (e.g. `"github"` or `"public.hyphae.to.github"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub topic: Option<String>,
    /// Matches `#channel` name (with or without leading `#`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
    /// Matches mailbox item kind (`message` | `event` | `plugin` | `transfer` | `kv`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<MailboxKind>,
    /// Optional CloudEvents Subscriptions API v1.0 filter AST predicates (logical AND).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ce_filters: Vec<ProtoFilter>,
}

/// Query request for [`query_inbox`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InboxQuery {
    #[serde(default)]
    pub state: InboxStateFilter,
    #[serde(default)]
    pub filter: InboxFilter,
    /// Deterministic opaque cursor from a previous [`InboxQueryResult::next_cursor`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// Page size clamped to `1..=50` (default `20`).
    #[serde(default = "default_limit")]
    pub limit: usize,
    /// When `true`, omits full `text` and returns a concise 1-line `preview`.
    #[serde(default)]
    pub summary_only: bool,
    /// When `true`, acknowledges returned `unread` items (or explicit `ids`) to `delivered`.
    #[serde(default)]
    pub ack: bool,
    /// Optional explicit receipt IDs to read and/or acknowledge.
    #[serde(default)]
    pub ids: Vec<String>,
}

fn default_limit() -> usize {
    DEFAULT_LIMIT
}

impl Default for InboxQuery {
    fn default() -> Self {
        Self {
            state: InboxStateFilter::Unread,
            filter: InboxFilter::default(),
            cursor: None,
            limit: DEFAULT_LIMIT,
            summary_only: false,
            ack: false,
            ids: Vec::new(),
        }
    }
}

/// Logical state reported for an item returned by [`query_inbox`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InboxItemState {
    Unread,
    Muted,
    Delivered,
}

impl InboxItemState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unread => "unread",
            Self::Muted => "muted",
            Self::Delivered => "delivered",
        }
    }
}

/// Single item projection returned by [`query_inbox`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InboxItemView {
    pub receipt: String,
    pub item_id: String,
    pub state: InboxItemState,
    pub kind: MailboxKind,
    pub origin_node: String,
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub topic: Option<String>,
    pub received_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview: Option<String>,
}

/// Paginated response returned by [`query_inbox`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InboxQueryResult {
    pub state: InboxStateFilter,
    pub items: Vec<InboxItemView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    pub has_more: bool,
    pub total_matched: usize,
    pub unread_count: usize,
    pub muted_count: usize,
    pub acked_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CursorPayload {
    t: i64,
    r: String,
}

fn encode_cursor(received_at: i64, receipt: &str) -> String {
    let json = serde_json::to_vec(&CursorPayload {
        t: received_at,
        r: receipt.to_string(),
    })
    .unwrap_or_default();
    URL_SAFE_NO_PAD.encode(json)
}

fn decode_cursor(raw: &str) -> Result<CursorPayload, DeliveryError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(raw.trim().as_bytes())
        .map_err(|e| DeliveryError::InvalidCursor(format!("base64url decode failed: {e}")))?;
    let payload: CursorPayload = serde_json::from_slice(&bytes)
        .map_err(|e| DeliveryError::InvalidCursor(format!("malformed cursor payload: {e}")))?;
    if payload.r.is_empty() {
        return Err(DeliveryError::InvalidCursor(
            "cursor receipt must be non-empty".to_string(),
        ));
    }
    Ok(payload)
}

// ============================================================================
// Durable Policy & Muted/Delivered Archival Helpers (NodeDb `metadata` + `mailbox`)
// ============================================================================

/// Persists a session's [`SessionDeliveryPolicy`] in `NodeDb` `metadata`.
pub fn save_session_policy(
    db: &NodeDb,
    session_id: &str,
    policy: &SessionDeliveryPolicy,
) -> Result<(), DeliveryError> {
    let key = format!("{META_POLICY_PREFIX}{session_id}");
    let encoded = serde_json::to_string(policy)?;
    db.local().set_metadata(&key, &encoded)?;
    Ok(())
}

/// Loads a session's persisted [`SessionDeliveryPolicy`] (or `SessionDeliveryPolicy::default()`).
pub fn load_session_policy(db: &NodeDb, session_id: &str) -> Result<SessionDeliveryPolicy, DeliveryError> {
    let key = format!("{META_POLICY_PREFIX}{session_id}");
    match db.local().get_metadata(&key)? {
        Some(raw) => Ok(serde_json::from_str(&raw)?),
        None => Ok(SessionDeliveryPolicy::default()),
    }
}

/// Archives a newly arrived muted item directly into `NodeDb` `mailbox` with
/// `gate_state = Delivered, gate_reason = Some("muted")` and records its receipt in the session's
/// muted index.
///
/// Guarantees the item NEVER appears in `peek_inbox`, `drain_inbox`, `pending_count`, or
/// `list_quarantined`, while remaining durably inspectable via `query_inbox(state = Muted)`.
pub fn archive_muted_entry(
    db: &NodeDb,
    insert: &MailboxInsert,
    now_ms: i64,
) -> Result<MailboxPutResult, DeliveryError> {
    let muted_insert = MailboxInsert {
        gate_state: GateState::Delivered,
        gate_reason: Some("muted".to_string()),
        ..insert.clone()
    };
    let res = db.local().put_in_mailbox(&muted_insert, now_ms)?;
    if let MailboxPutResult::Stored { ref receipt } = res {
        let _ = db
            .local()
            .record_delivery(&insert.origin_node, &insert.item_id, "muted", now_ms);
        append_receipt_index(db, META_MUTED_INDEX_PREFIX, &insert.session_id, &[receipt.clone()])?;
    }
    Ok(res)
}

/// Moves an already-inserted `Pending` mailbox entry out of `unread` (`Pending`) and into the
/// silent `muted` archive without triggering any wake or standalone digest.
pub fn move_pending_to_muted(
    db: &NodeDb,
    session_id: &str,
    entry: &MailboxEntry,
    now_ms: i64,
) -> Result<(), DeliveryError> {
    let _ = db
        .local()
        .acknowledge_inbox(session_id, &[entry.receipt.as_str()], now_ms)?;
    let _ = db
        .local()
        .record_delivery(&entry.origin_node, &entry.item_id, "muted", now_ms);
    append_receipt_index(db, META_MUTED_INDEX_PREFIX, session_id, &[entry.receipt.clone()])?;
    Ok(())
}

/// Records receipts transitioned to `delivered` so `query_inbox(state = Delivered | All)` can
/// inspect them durably across restarts.
pub fn record_delivered_receipts(
    db: &NodeDb,
    session_id: &str,
    receipts: &[String],
) -> Result<(), DeliveryError> {
    if receipts.is_empty() {
        return Ok(());
    }
    append_receipt_index(db, META_DELIVERED_INDEX_PREFIX, session_id, receipts)
}

/// Returns the number of durably archived `muted` entries for `session_id`.
pub fn muted_count(db: &NodeDb, session_id: &str) -> Result<usize, DeliveryError> {
    let receipts = load_receipt_index(db, META_MUTED_INDEX_PREFIX, session_id)?;
    let mut count = 0usize;
    for r in receipts {
        if let Some(entry) = db.local().get_mailbox_entry(&r)? {
            if entry.session_id == session_id
                && !matches!(entry.gate_state, GateState::Quarantined | GateState::Rejected)
            {
                count += 1;
            }
        }
    }
    Ok(count)
}

fn load_receipt_index(
    db: &NodeDb,
    prefix: &str,
    session_id: &str,
) -> Result<Vec<String>, DeliveryError> {
    let key = format!("{prefix}{session_id}");
    match db.local().get_metadata(&key)? {
        Some(raw) => Ok(serde_json::from_str(&raw).unwrap_or_default()),
        None => Ok(Vec::new()),
    }
}

fn append_receipt_index(
    db: &NodeDb,
    prefix: &str,
    session_id: &str,
    new_receipts: &[String],
) -> Result<(), DeliveryError> {
    let mut list = load_receipt_index(db, prefix, session_id)?;
    let mut seen: HashSet<String> = list.iter().cloned().collect();
    for r in new_receipts {
        if seen.insert(r.clone()) {
            list.push(r.clone());
        }
    }
    if list.len() > MAX_ARCHIVE_RECEIPTS {
        let excess = list.len() - MAX_ARCHIVE_RECEIPTS;
        list.drain(0..excess);
    }
    let key = format!("{prefix}{session_id}");
    let encoded = serde_json::to_string(&list)?;
    db.local().set_metadata(&key, &encoded)?;
    Ok(())
}

// ============================================================================
// Unified Filtered & Paginated Inbox Query (`query_inbox`)
// ============================================================================

/// Queries a session's `NodeDb` mailbox with state filtering (`unread` | `muted` | `delivered` | `all`),
/// structured attribute & CloudEvents filters, deterministic keyset cursor pagination, optional
/// summary mode, and optional acknowledgment.
///
/// **Hard security invariant:** NEVER returns or counts `quarantined` or `rejected` items.
pub fn query_inbox(
    db: &NodeDb,
    session_id: &str,
    query: &InboxQuery,
    now_ms: i64,
) -> Result<InboxQueryResult, DeliveryError> {
    if !query.filter.ce_filters.is_empty() {
        let val = serde_json::to_value(&query.filter.ce_filters)?;
        hyp_proto::filter::validate_filters(&val)
            .map_err(|e| DeliveryError::InvalidFilter(e.to_string()))?;
    }

    let cursor = match query.cursor.as_deref() {
        Some(raw) if !raw.trim().is_empty() => Some(decode_cursor(raw)?),
        _ => None,
    };

    let limit = query.limit.clamp(1, MAX_LIMIT);

    // Track muted receipts so we never misclassify a muted entry as normal `delivered`.
    let muted_receipts = load_receipt_index(db, META_MUTED_INDEX_PREFIX, session_id)?;
    let muted_set: HashSet<String> = muted_receipts.iter().cloned().collect();
    let delivered_receipts = load_receipt_index(db, META_DELIVERED_INDEX_PREFIX, session_id)?;

    let mut candidates: Vec<(InboxItemState, MailboxEntry)> = Vec::new();
    let mut seen_receipts: HashSet<String> = HashSet::new();

    if !query.ids.is_empty() {
        // Explicit receipt lookup (strictly scoped to `session_id` and NEVER exposing quarantined/rejected!).
        for id in &query.ids {
            if let Some(entry) = db.local().get_mailbox_entry(id)? {
                if entry.session_id != session_id {
                    continue;
                }
                if matches!(entry.gate_state, GateState::Quarantined | GateState::Rejected) {
                    continue;
                }
                let item_state = classify_entry_state(&entry, &muted_set);
                if state_matches_filter(item_state, query.state)
                    && seen_receipts.insert(entry.receipt.clone())
                {
                    candidates.push((item_state, entry));
                }
            }
        }
    } else {
        if matches!(query.state, InboxStateFilter::Unread | InboxStateFilter::All) {
            let pending = db.local().peek_inbox(session_id, 10_000)?;
            for entry in pending {
                if matches!(entry.gate_state, GateState::Quarantined | GateState::Rejected) {
                    continue;
                }
                if seen_receipts.insert(entry.receipt.clone()) {
                    candidates.push((InboxItemState::Unread, entry));
                }
            }
        }
        if matches!(query.state, InboxStateFilter::Muted | InboxStateFilter::All) {
            for r in &muted_receipts {
                if let Some(entry) = db.local().get_mailbox_entry(r)? {
                    if entry.session_id != session_id
                        || matches!(entry.gate_state, GateState::Quarantined | GateState::Rejected)
                    {
                        continue;
                    }
                    if seen_receipts.insert(entry.receipt.clone()) {
                        candidates.push((InboxItemState::Muted, entry));
                    }
                }
            }
        }
        if matches!(query.state, InboxStateFilter::Delivered | InboxStateFilter::All) {
            for r in &delivered_receipts {
                if muted_set.contains(r) {
                    continue;
                }
                if let Some(entry) = db.local().get_mailbox_entry(r)? {
                    if entry.session_id != session_id
                        || entry.gate_state != GateState::Delivered
                        || entry.gate_reason.as_deref() == Some("muted")
                    {
                        continue;
                    }
                    if seen_receipts.insert(entry.receipt.clone()) {
                        candidates.push((InboxItemState::Delivered, entry));
                    }
                }
            }
        }
    }

    // Apply structured + CloudEvents filters.
    let mut matched: Vec<(InboxItemState, MailboxEntry, ParsedMailboxSource)> = candidates
        .into_iter()
        .filter_map(|(st, entry)| {
            let parsed = ParsedMailboxSource::from_entry(&entry);
            if matches_inbox_filter(&entry, &parsed, &query.filter) {
                Some((st, entry, parsed))
            } else {
                None
            }
        })
        .collect();

    // Deterministic keyset order: `(received_at ASC, receipt ASC)`.
    matched.sort_by(|(_, a, _), (_, b, _)| {
        a.received_at
            .cmp(&b.received_at)
            .then_with(|| a.receipt.cmp(&b.receipt))
    });

    let total_matched = matched.len();

    // Apply keyset cursor (`(received_at, receipt) > (cursor.t, cursor.r)`).
    let after_cursor: Vec<(InboxItemState, MailboxEntry, ParsedMailboxSource)> = match cursor {
        Some(ref c) => matched
            .into_iter()
            .filter(|(_, e, _)| (e.received_at, e.receipt.as_str()) > (c.t, c.r.as_str()))
            .collect(),
        None => matched,
    };

    let has_more = after_cursor.len() > limit;
    let page: Vec<(InboxItemState, MailboxEntry, ParsedMailboxSource)> =
        after_cursor.into_iter().take(limit).collect();

    let next_cursor = if has_more {
        page.last()
            .map(|(_, e, _)| encode_cursor(e.received_at, &e.receipt))
    } else {
        None
    };

    // Acknowledge unread items if `ack == true`.
    let mut acked_count = 0usize;
    if query.ack {
        let to_ack: Vec<String> = page
            .iter()
            .filter(|(st, _, _)| *st == InboxItemState::Unread)
            .map(|(_, e, _)| e.receipt.clone())
            .collect();
        if !to_ack.is_empty() {
            let refs: Vec<&str> = to_ack.iter().map(String::as_str).collect();
            acked_count = db.local().acknowledge_inbox(session_id, &refs, now_ms)?;
            record_delivered_receipts(db, session_id, &to_ack)?;
        }
    }

    let items: Vec<InboxItemView> = page
        .into_iter()
        .map(|(st, entry, parsed)| {
            let (text, preview) = if query.summary_only {
                (None, Some(make_preview(&entry.text)))
            } else {
                (Some(entry.text), None)
            };
            InboxItemView {
                receipt: entry.receipt,
                item_id: entry.item_id,
                state: st,
                kind: entry.kind,
                origin_node: entry.origin_node,
                source: entry.source,
                channel: parsed.channel,
                topic: parsed.topic,
                received_at: entry.received_at,
                text,
                preview,
            }
        })
        .collect();

    let unread_count = db.local().pending_count(session_id)?;
    let muted_total = muted_count(db, session_id)?;

    Ok(InboxQueryResult {
        state: query.state,
        items,
        next_cursor,
        has_more,
        total_matched,
        unread_count,
        muted_count: muted_total,
        acked_count,
    })
}

fn classify_entry_state(entry: &MailboxEntry, muted_set: &HashSet<String>) -> InboxItemState {
    if entry.gate_state == GateState::Pending {
        InboxItemState::Unread
    } else if muted_set.contains(&entry.receipt) || entry.gate_reason.as_deref() == Some("muted") {
        InboxItemState::Muted
    } else {
        InboxItemState::Delivered
    }
}

fn state_matches_filter(item_state: InboxItemState, filter: InboxStateFilter) -> bool {
    match filter {
        InboxStateFilter::All => true,
        InboxStateFilter::Unread => item_state == InboxItemState::Unread,
        InboxStateFilter::Muted => item_state == InboxItemState::Muted,
        InboxStateFilter::Delivered => item_state == InboxItemState::Delivered,
    }
}

fn matches_inbox_filter(
    entry: &MailboxEntry,
    parsed: &ParsedMailboxSource,
    filter: &InboxFilter,
) -> bool {
    if let Some(kind) = filter.kind {
        if entry.kind != kind {
            return false;
        }
    }

    if let Some(ref node_pat) = filter.node {
        let pat = node_pat.trim().to_ascii_lowercase();
        if !pat.is_empty() {
            let origin_low = parsed.origin_node.to_ascii_lowercase();
            let sender_node = parsed
                .sender_addr
                .as_deref()
                .and_then(|a| a.split_once('/').map(|(n, _)| n.to_ascii_lowercase()));
            if origin_low != pat && sender_node.as_deref() != Some(pat.as_str()) {
                return false;
            }
        }
    }

    if let Some(ref ch_pat) = filter.channel {
        let pat = normalize_channel_lower(ch_pat);
        if parsed
            .channel
            .as_deref()
            .map(normalize_channel_lower)
            .as_deref()
            != Some(pat.as_str())
        {
            return false;
        }
    }

    if let Some(ref topic_pat) = filter.topic {
        let pat = topic_pat.trim().to_ascii_lowercase();
        if !pat.is_empty() {
            let t_low = parsed.topic.as_deref().map(str::to_ascii_lowercase);
            let src_low = parsed.source.to_ascii_lowercase();
            let qualified = t_low
                .as_deref()
                .map(|t| format!("{}.{t}", parsed.origin_node.to_ascii_lowercase()));
            if t_low.as_deref() != Some(pat.as_str())
                && qualified.as_deref() != Some(pat.as_str())
                && src_low != pat
            {
                return false;
            }
        }
    }

    if let Some(ref from_pat) = filter.from {
        let pat = from_pat.trim().to_ascii_lowercase();
        if !pat.is_empty() && !matches_from_pattern(&pat, parsed) {
            return false;
        }
    }

    if !filter.ce_filters.is_empty() && !matches_ce_filters(entry, parsed, &filter.ce_filters) {
        return false;
    }

    true
}

fn matches_from_pattern(pat: &str, parsed: &ParsedMailboxSource) -> bool {
    let src_low = parsed.source.to_ascii_lowercase();
    let addr_low = parsed.sender_addr.as_deref().map(str::to_ascii_lowercase);
    let handle_low = parsed.sender_handle.as_deref().map(str::to_ascii_lowercase);

    if let Some(h) = pat.strip_prefix('@') {
        return handle_low.as_deref() == Some(h) || src_low == pat;
    }
    if let Some(prefix) = pat.strip_suffix('*') {
        return src_low.starts_with(prefix)
            || addr_low.as_deref().is_some_and(|a| a.starts_with(prefix));
    }
    src_low == pat
        || addr_low.as_deref() == Some(pat)
        || handle_low.as_deref() == Some(pat)
}

fn matches_ce_filters(
    entry: &MailboxEntry,
    parsed: &ParsedMailboxSource,
    filters: &[ProtoFilter],
) -> bool {
    // 1. If `entry.text` is a serialized batch containing `events: [CloudEvent, ...]`, match if any event matches.
    if let Ok(val) = serde_json::from_str::<Value>(&entry.text) {
        if let Some(events) = val.get("events").and_then(Value::as_array) {
            for ev_val in events {
                if let Ok(ce) = serde_json::from_value::<ProtoCloudEvent>(ev_val.clone()) {
                    if matches_filters(filters, &ce) {
                        return true;
                    }
                }
            }
            return false;
        }
        if let Ok(ce) = serde_json::from_value::<ProtoCloudEvent>(val) {
            return matches_filters(filters, &ce);
        }
    }

    // 2. Otherwise synthesize a CloudEvent projection of the mailbox entry.
    let mut extensions = BTreeMap::new();
    extensions.insert("origin".to_string(), Value::String(entry.origin_node.clone()));
    extensions.insert("kind".to_string(), Value::String(entry.kind.as_str().to_string()));
    if let Some(ref ch) = parsed.channel {
        extensions.insert("channel".to_string(), Value::String(ch.clone()));
    }
    if let Some(ref topic) = parsed.topic {
        extensions.insert("topic".to_string(), Value::String(topic.clone()));
    }
    if let Some(ref handle) = parsed.sender_handle {
        extensions.insert("handle".to_string(), Value::String(handle.clone()));
    }
    let ce = ProtoCloudEvent {
        specversion: "1.0".to_string(),
        id: entry.item_id.clone(),
        source: entry.source.clone(),
        event_type: format!("to.hyphae.mailbox.{}", entry.kind.as_str()),
        datacontenttype: Some(CONTENT_TYPE_JSON.to_string()),
        dataschema: None,
        subject: parsed.channel.clone().or_else(|| parsed.topic.clone()),
        time: None,
        data: Some(json!({
            "text": entry.text,
            "source": entry.source,
            "originNode": entry.origin_node,
            "kind": entry.kind.as_str(),
            "channel": parsed.channel,
            "topic": parsed.topic,
        })),
        data_base64: None,
        extensions,
    };
    matches_filters(filters, &ce)
}

pub(crate) fn make_preview(text: &str) -> String {
    let first_line = text
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with("External data follows"))
        .unwrap_or("");
    if first_line.chars().count() <= PREVIEW_MAX_CHARS {
        first_line.to_string()
    } else {
        let head: String = first_line.chars().take(PREVIEW_MAX_CHARS - 1).collect();
        format!("{head}…")
    }
}
