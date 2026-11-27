//! Pure metadata-only session projection. Inputs contain no runtime or database handles.
use serde::Serialize;
use serde_json::{Value, json};

/// Metadata and resolved delivery state needed to render a session.
pub struct SessionViewInput {
    pub session_id: String,
    pub harness: String,
    pub handle: Option<String>,
    pub address: Option<String>,
    pub herdr_terminal_id: Option<String>,
    pub herdr_created_ms: Option<i64>,
    pub last_seen: i64,
    pub transport_kind: Option<String>,
    pub delivery_mode: String,
    pub focus_mode: bool,
    pub focus_allow_interrupt_vips: bool,
    pub muted_all: bool,
    pub bridges: Vec<BridgeTarget>,
    pub counts: SessionCounts,
    pub unread: UnreadBreakdown,
}

/// Counts already screened for the caller's mailbox visibility.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionCounts {
    pub subscriptions: usize,
    pub bridges: usize,
    pub queued: usize,
    pub unnotified: usize,
    pub quarantined: usize,
    pub muted_rules: usize,
    pub muted_archived: usize,
    pub channels: usize,
}

/// Message-free unread categories and source labels.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UnreadBreakdown {
    pub messages: usize,
    pub events: usize,
    pub plugins: usize,
    pub transfers: usize,
    pub kv: usize,
    pub sources: Vec<String>,
}

pub struct BridgeTarget {
    pub plugin: String,
    pub target: String,
    pub primary: bool,
}

/// Subscription filters retain the caller's structured filter representation.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionView<F> {
    pub id: String,
    pub key: Option<String>,
    pub origin_node: String,
    pub topic: String,
    pub mode: String,
    pub coalesce_seconds: i64,
    pub filters: Vec<F>,
    pub filter_summary: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QueuedItem {
    pub receipt: String,
    pub kind: &'static str,
    pub source: String,
    pub origin_node: String,
    pub received_at: i64,
    pub notified: bool,
    pub urgency: &'static str,
}

pub struct Mute {
    pub pattern: String,
    pub global: bool,
    pub muted_at: i64,
    pub expires_at: Option<i64>,
}

#[derive(Serialize)]
pub struct Rule {
    pub target: String,
    pub delivery: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Channel {
    pub host_node: String,
    pub channel: String,
    pub mode: &'static str,
}

pub struct SessionDetails<F> {
    pub subscriptions: Vec<SubscriptionView<F>>,
    pub queued_items: Vec<QueuedItem>,
    pub mutes: Vec<Mute>,
    pub rules: Vec<Rule>,
    pub channels: Vec<Channel>,
}

/// Render a session from visibility-filtered metadata. Compact snapshots omit the details key.
pub fn render_session<F: Serialize>(
    node_id: &str,
    mut input: SessionViewInput,
    details: Option<SessionDetails<F>>,
) -> Value {
    const MAX_SOURCES: usize = 20;
    input.unread.sources.truncate(MAX_SOURCES);
    let bridges: Vec<String> = input
        .bridges
        .iter()
        .take(8)
        .map(|b| format!("{}:{}", b.plugin, b.target))
        .collect();
    let mut session = json!({
        "sessionId": input.session_id,
        "harness": input.harness,
        "enrolled": input.handle.is_some(),
        "handle": input.handle,
        "address": input.address,
        "herdrTerminalId": input.herdr_terminal_id,
        "herdrCreatedMs": input.herdr_created_ms,
        "lastSeen": input.last_seen,
        "transportKind": input.transport_kind,
        "hasLiveTransport": input.transport_kind.is_some(),
        "deliveryMode": input.delivery_mode,
        "focusMode": input.focus_mode,
        "focusAllowInterruptVips": input.focus_allow_interrupt_vips,
        "mutedAll": input.muted_all,
        "bridges": bridges,
        "counts": input.counts,
        "unreadBreakdown": input.unread,
    });
    if let Some(details) = details {
        let bridges: Vec<Value> = input
            .bridges
            .into_iter()
            .map(|b| {
                json!({
                    "plugin": b.plugin,
                    "target": b.target,
                    "label": format!("{}:{}", b.plugin, b.target),
                    "role": if b.primary { "primary" } else { "reader" },
                })
            })
            .collect();
        let channels: Vec<String> = details
            .channels
            .iter()
            .map(|entry| {
                if entry.host_node == node_id || entry.host_node == "local" {
                    entry.channel.clone()
                } else {
                    format!("{}/{}", entry.host_node, entry.channel)
                }
            })
            .collect();
        let mutes: Vec<Value> = details
            .mutes
            .into_iter()
            .map(|mute| {
                let mut entry = json!({
                    "pattern": mute.pattern,
                    "scope": if mute.global { "connector" } else { "session" },
                    "mutedAt": mute.muted_at,
                });
                if let Some(expires_at) = mute.expires_at {
                    entry["expiresAt"] = json!(expires_at);
                }
                entry
            })
            .collect();
        session["details"] = json!({
            "bridges": bridges,
            "subscriptions": details.subscriptions,
            "queuedItems": details.queued_items,
            "mutes": mutes,
            "rules": details.rules,
            "channels": channels,
            "channelEntries": details.channels,
        });
    }
    session
}
