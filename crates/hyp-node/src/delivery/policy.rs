//! Universal 3-tier delivery urgency (`interrupt` / `queue` / `notify` + silent `mute` archive),
//! per-source ordered override rules, Focus Mode (`* -> notify`), and burst protection parameters
//! (`docs/architecture-v2.md` §2.5).

use std::fmt;
use std::str::FromStr;

use hyp_store::{DeliveryMode, MailboxEntry, MailboxKind, parse_address};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Default estimated token budget per delivered batch (~4800 chars, §2.5).
pub const DEFAULT_MAX_BATCH_TOKENS: usize = 1_200;
/// Default maximum items packed inline before spilling to a 1-line digest footer (§2.5).
pub const DEFAULT_MAX_INLINE_ITEMS: usize = 6;
/// Default maximum fraction of `max_batch_tokens` any single item may consume before preview truncation.
pub const DEFAULT_MAX_SINGLE_ITEM_SHARE: f32 = 0.60;

/// Default burst detection rolling window (seconds).
pub const DEFAULT_BURST_WINDOW_SECS: u64 = 60;
/// Default max arrivals per source inside `window_secs` before engaging Noisy Mode.
pub const DEFAULT_BURST_MAX_EVENTS_PER_WINDOW: usize = 10;
/// Default cooldown duration (seconds) a source stays in Noisy Mode after tripping burst ceiling.
pub const DEFAULT_BURST_NOISY_COOLDOWN_SECS: u64 = 300;
/// Default minimum interval (seconds) between deliveries/digests for a noisy source.
pub const DEFAULT_BURST_MIN_DELIVERY_INTERVAL_SECS: u64 = 30;
/// Default interval (seconds) between mid-turn `PostToolUse` `queue` digest reminders (30 min; `0` = disabled).
pub const DEFAULT_MIDTURN_QUEUE_DIGEST_SECONDS: u64 = 1_800;

/// Maps a persisted mailbox `gate_reason` (written by Stage 1) to its effective [`DeliveryUrgency`] ceiling.
pub fn gate_reason_urgency_cap(gate_reason: Option<&str>) -> Option<DeliveryUrgency> {
    match gate_reason {
        Some("downgraded_to_notify") => Some(DeliveryUrgency::Notify),
        Some("capped_to_queue") => Some(DeliveryUrgency::Queue),
        _ => None,
    }
}

/// Errors returned by the Delivery Engine, policy validation, or filtered inbox queries.
#[derive(Debug, Error)]
pub enum DeliveryError {
    #[error("invalid delivery urgency: '{0}'")]
    InvalidUrgency(String),

    #[error("invalid delivery rule: {0}")]
    InvalidRule(String),

    #[error("invalid inbox state: '{0}' (expected unread | muted | delivered | all)")]
    InvalidState(String),

    #[error("forbidden inbox state '{0}': quarantined and rejected items are human-CLI-only")]
    ForbiddenState(String),

    #[error("invalid pagination cursor: {0}")]
    InvalidCursor(String),

    #[error("invalid filter: {0}")]
    InvalidFilter(String),

    #[error("storage error: {0}")]
    Store(#[from] hyp_store::StoreError),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Universal 3-tier delivery urgency plus silent `mute` archive (`docs/architecture-v2.md` §2.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeliveryUrgency {
    /// Wakes an active or idle agent thread immediately.
    Interrupt,
    /// Held cleanly until the agent's next turn / idle boundary, coalesced into a batch.
    Queue,
    /// Full body stays in local inbox (`unread`); still emits a slim 1-line digest on next turn/idle.
    Notify,
    /// Silent durable archive (`state = 'muted'`). NEVER wakes or triggers a standalone digest;
    /// piggybacks `· N muted` onto other deliveries and stays inspectable via `hyp_inbox(state:"muted")`.
    Mute,
}

impl DeliveryUrgency {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Interrupt => "interrupt",
            Self::Queue => "queue",
            Self::Notify => "notify",
            Self::Mute => "mute",
        }
    }

    pub fn parse(s: &str) -> Result<Self, DeliveryError> {
        match s.trim().to_ascii_lowercase().as_str() {
            "interrupt" => Ok(Self::Interrupt),
            "queue" | "full" => Ok(Self::Queue),
            "notify" => Ok(Self::Notify),
            "mute" | "muted" => Ok(Self::Mute),
            other => Err(DeliveryError::InvalidUrgency(other.to_string())),
        }
    }

    /// True when this urgency tier triggers an immediate live wake (active or idle).
    pub const fn is_immediate_interrupt(self) -> bool {
        matches!(self, Self::Interrupt)
    }

    /// True when this urgency tier is permitted to wake a waiter / emit a turn-boundary batch or digest.
    ///
    /// **Strict `mute` invariant:** `Mute` ALWAYS returns `false`.
    pub const fn triggers_delivery_or_digest(self) -> bool {
        !matches!(self, Self::Mute)
    }

    /// True when this item is silently archived (`state = 'muted'`).
    pub const fn is_muted(self) -> bool {
        matches!(self, Self::Mute)
    }

    /// Maps a legacy `hyp_store::DeliveryMode` (`full` | `notify`) to `DeliveryUrgency`.
    pub const fn from_store_mode(mode: DeliveryMode) -> Self {
        match mode {
            DeliveryMode::Full => Self::Queue,
            DeliveryMode::Notify => Self::Notify,
        }
    }

    /// Maps `DeliveryUrgency` down to the legacy 2-state `hyp_store::DeliveryMode`.
    pub const fn to_store_mode(self) -> DeliveryMode {
        match self {
            Self::Interrupt | Self::Queue => DeliveryMode::Full,
            Self::Notify | Self::Mute => DeliveryMode::Notify,
        }
    }

    /// Priority rank used for sorting items inside a batch (lower rank = higher priority).
    pub const fn rank(self) -> u8 {
        match self {
            Self::Interrupt => 0,
            Self::Queue => 1,
            Self::Notify => 2,
            Self::Mute => 3,
        }
    }
}

impl fmt::Display for DeliveryUrgency {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for DeliveryUrgency {
    type Err = DeliveryError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// Ordered per-source delivery urgency override rule (§2.5).
///
/// Supported target patterns:
/// - `@alice` — handle shorthand (matches any peer with handle `alice`, e.g. `node/alice`)
/// - `<node>/<handle>` — exact qualified peer address (e.g. `bob@laptop/codex`)
/// - `<node>/*` — all handles on `<node>`
/// - `#channel` or `<node>/#channel` — channel posts
/// - `<node>.<topic>` or `topic:<topic>` — event stream topic
/// - `<node>.*` — all streams from `<node>`
/// - `<plugin>:<target>` or `plugin:<plugin>` — chat bridge targets
/// - `*` — global wildcard
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeliveryRule {
    pub target: String,
    pub delivery: DeliveryUrgency,
}

impl DeliveryRule {
    pub fn new(target: impl Into<String>, delivery: DeliveryUrgency) -> Self {
        Self {
            target: normalize_rule_target(&target.into()),
            delivery,
        }
    }

    pub fn validate(&self) -> Result<(), DeliveryError> {
        let norm = normalize_rule_target(&self.target);
        if norm.is_empty() {
            return Err(DeliveryError::InvalidRule(
                "rule target must be non-empty".to_string(),
            ));
        }
        if norm.len() > 256 {
            return Err(DeliveryError::InvalidRule(
                "rule target exceeds 256 bytes".to_string(),
            ));
        }
        Ok(())
    }

    /// Returns `true` if this rule targets the global wildcard `"*"`.
    pub fn is_wildcard(&self) -> bool {
        normalize_rule_target(&self.target) == "*"
    }

    /// Evaluates whether this rule matches `ctx` and returns a specificity score
    /// `(tier, prefix_len)` when matched (higher wins).
    pub fn match_specificity(&self, ctx: &DeliveryTargetContext<'_>) -> Option<(u8, usize)> {
        let pat = normalize_rule_target(&self.target);
        if pat.is_empty() {
            return None;
        }
        if pat == "*" {
            return Some((1, 0));
        }

        let origin = ctx.origin_node.trim().to_ascii_lowercase();
        let source = ctx.source.trim().to_ascii_lowercase();
        let sender_addr = ctx.sender_addr.map(|s| s.trim().to_ascii_lowercase());
        let sender_handle = ctx.sender_handle.map(|s| s.trim().to_ascii_lowercase());
        let channel = ctx.channel.map(normalize_channel_lower);
        let topic = ctx.topic.map(|s| s.trim().to_ascii_lowercase());
        let bridge = ctx.bridge.map(|s| s.trim().to_ascii_lowercase());

        // 1. `@handle` shorthand (tier 4: exact unqualified peer handle)
        if let Some(handle_pat) = pat.strip_prefix('@') {
            if !handle_pat.is_empty() {
                if sender_handle.as_deref() == Some(handle_pat) {
                    return Some((4, handle_pat.len()));
                }
                if source == format!("@{handle_pat}") || source == handle_pat {
                    return Some((4, handle_pat.len()));
                }
            }
            return None;
        }

        // 2. `#channel` shorthand (tier 4: exact unqualified channel)
        if pat.starts_with('#') {
            if channel.as_deref() == Some(pat.as_str()) {
                return Some((4, pat.len()));
            }
            if source == pat {
                return Some((4, pat.len()));
            }
            return None;
        }

        // 3. `topic:<topic>` shorthand (tier 4)
        if let Some(topic_pat) = pat.strip_prefix("topic:") {
            if !topic_pat.is_empty() {
                if topic_pat == "*" && topic.is_some() {
                    return Some((2, 6));
                }
                if let Some(prefix) = topic_pat.strip_suffix('*') {
                    if topic.as_deref().is_some_and(|t| t.starts_with(prefix)) {
                        return Some((3, prefix.len()));
                    }
                } else if topic.as_deref() == Some(topic_pat) {
                    return Some((4, topic_pat.len()));
                }
            }
            return None;
        }

        // 4. `plugin:<plugin>` shorthand (tier 4)
        if let Some(plugin_pat) = pat.strip_prefix("plugin:") {
            if !plugin_pat.is_empty() {
                if let Some(ref br) = bridge {
                    if br == plugin_pat || br.starts_with(&format!("{plugin_pat}:")) {
                        return Some((4, plugin_pat.len()));
                    }
                }
            }
            return None;
        }

        // 5. Qualified `<node>/#channel` (tier 5)
        if let Some((node_pat, ch_pat)) = pat.split_once("/#") {
            let full_ch = format!("#{ch_pat}");
            if channel.as_deref() == Some(full_ch.as_str())
                && (node_pat == origin || (node_pat == "local" && origin == "local"))
            {
                return Some((5, pat.len()));
            }
            if source.starts_with(&format!("{pat}:")) || source == pat {
                return Some((5, pat.len()));
            }
            return None;
        }

        // 6. Scoped trailing wildcard: `<node>.*`, `<node>/*`, or general `<prefix>*` (tier 3)
        if let Some(prefix) = pat.strip_suffix('*') {
            if prefix.is_empty() {
                return Some((1, 0));
            }
            if let Some(node_prefix) = prefix.strip_suffix('.') {
                // `<node>.*` matches any stream/topic on `<node>`
                if origin == node_prefix
                    && (topic.is_some()
                        || ctx.kind == MailboxKind::Event
                        || ctx.kind == MailboxKind::Kv)
                {
                    return Some((3, prefix.len()));
                }
                if source.starts_with(prefix) {
                    return Some((3, prefix.len()));
                }
                return None;
            }
            if let Some(node_prefix) = prefix.strip_suffix('/') {
                // `<node>/*` matches any peer/channel originating from `<node>`
                if origin == node_prefix
                    || sender_addr
                        .as_deref()
                        .is_some_and(|a| a.starts_with(prefix))
                    || source.starts_with(prefix)
                {
                    return Some((3, prefix.len()));
                }
                return None;
            }
            // Generic prefix wildcard
            if source.starts_with(prefix)
                || sender_addr
                    .as_deref()
                    .is_some_and(|a| a.starts_with(prefix))
                || bridge.as_deref().is_some_and(|b| b.starts_with(prefix))
            {
                return Some((3, prefix.len()));
            }
            return None;
        }

        // 7. Exact qualified `<node>/<handle>`, `<node>.<topic>`, `<plugin>:<target>`, or exact source (tier 5)
        if source == pat {
            return Some((5, pat.len()));
        }
        if sender_addr.as_deref() == Some(pat.as_str()) {
            return Some((5, pat.len()));
        }
        if bridge.as_deref() == Some(pat.as_str()) {
            return Some((5, pat.len()));
        }
        if let Some(ref t) = topic {
            let qualified = format!("{origin}.{t}");
            if pat == qualified {
                return Some((5, pat.len()));
            }
        }

        None
    }
}

/// Adaptive burst protection ("Noisy Mode") configuration (§2.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BurstProtectionConfig {
    /// Rolling window duration in seconds (default `60`).
    pub window_secs: u64,
    /// Maximum arrivals from a single source inside `window_secs` before tripping Noisy Mode (default `10`).
    pub max_events_per_window: usize,
    /// Cooldown duration in seconds a noisy source stays demoted (default `300`).
    pub noisy_cooldown_secs: u64,
    /// Minimum interval in seconds between deliveries/digests for a noisy source (default `30`).
    pub min_delivery_interval_secs: u64,
}

impl Default for BurstProtectionConfig {
    fn default() -> Self {
        Self {
            window_secs: DEFAULT_BURST_WINDOW_SECS,
            max_events_per_window: DEFAULT_BURST_MAX_EVENTS_PER_WINDOW,
            noisy_cooldown_secs: DEFAULT_BURST_NOISY_COOLDOWN_SECS,
            min_delivery_interval_secs: DEFAULT_BURST_MIN_DELIVERY_INTERVAL_SECS,
        }
    }
}

/// Per-session universal delivery policy, Focus Mode, token-budget batching, and burst settings (§2.5).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionDeliveryPolicy {
    /// Default urgency when no override matches (`Queue` normally; `Notify` in Focus Mode).
    pub default_mode: DeliveryUrgency,
    /// Focus Mode (`* -> notify`): demotes normal traffic to held 1-line digest notifications.
    pub focus_mode: bool,
    /// When Focus Mode is active, allow explicit `Interrupt` overrides (e.g. `@oncall`) to still wake.
    pub focus_allow_interrupt_vips: bool,
    /// Ordered per-source overrides evaluated by specificity (exact > shorthand > wildcard > `*`),
    /// with earlier rules breaking ties at equal specificity.
    #[serde(default)]
    pub overrides: Vec<DeliveryRule>,
    /// Maximum estimated tokens per packed delivery batch (default `1200`, ~`chars / 4`).
    pub max_batch_tokens: usize,
    /// Maximum number of items packed inline before spilling remaining items to footer (default `6`).
    pub max_inline_items: usize,
    /// Maximum share of `max_batch_tokens` a single item may occupy before preview truncation (default `0.60`).
    pub max_single_item_share: f32,
    /// Adaptive per-source burst protection ("Noisy Mode") settings.
    #[serde(default)]
    pub burst: BurstProtectionConfig,
    /// Optional per-session override for periodic mid-turn `PostToolUse` `queue` digest reminders
    /// (seconds; `0` disables). When `None`, falls back to the daemon's configured default (`1800`s).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub midturn_queue_digest_seconds: Option<u64>,
}

impl Default for SessionDeliveryPolicy {
    fn default() -> Self {
        Self {
            default_mode: DeliveryUrgency::Queue,
            focus_mode: false,
            focus_allow_interrupt_vips: true,
            overrides: Vec::new(),
            max_batch_tokens: DEFAULT_MAX_BATCH_TOKENS,
            max_inline_items: DEFAULT_MAX_INLINE_ITEMS,
            max_single_item_share: DEFAULT_MAX_SINGLE_ITEM_SHARE,
            burst: BurstProtectionConfig::default(),
            midturn_queue_digest_seconds: None,
        }
    }
}

impl SessionDeliveryPolicy {
    /// Creates a Focus Mode policy (`* -> notify`) that still lets explicit `Interrupt` VIPs wake.
    pub fn focus_mode() -> Self {
        Self {
            default_mode: DeliveryUrgency::Notify,
            focus_mode: true,
            focus_allow_interrupt_vips: true,
            ..Self::default()
        }
    }

    /// Enables or disables Focus Mode while configuring VIP `Interrupt` pass-through.
    pub fn with_focus_mode(mut self, enabled: bool, allow_interrupt_vips: bool) -> Self {
        self.focus_mode = enabled;
        self.focus_allow_interrupt_vips = allow_interrupt_vips;
        if enabled {
            self.default_mode = DeliveryUrgency::Notify;
        } else if self.default_mode == DeliveryUrgency::Notify {
            self.default_mode = DeliveryUrgency::Queue;
        }
        self
    }

    /// Builder helper to upsert a delivery rule.
    pub fn with_rule(mut self, target: impl Into<String>, delivery: DeliveryUrgency) -> Self {
        self.upsert_rule(DeliveryRule::new(target, delivery));
        self
    }

    /// Inserts or updates a rule matching the same normalized target in place.
    pub fn upsert_rule(&mut self, rule: DeliveryRule) {
        let norm = normalize_rule_target(&rule.target);
        if let Some(existing) = self
            .overrides
            .iter_mut()
            .find(|r| normalize_rule_target(&r.target) == norm)
        {
            existing.target = norm;
            existing.delivery = rule.delivery;
        } else {
            self.overrides.push(DeliveryRule {
                target: norm,
                delivery: rule.delivery,
            });
        }
    }

    /// Removes any rule with the given normalized target. Returns `true` if a rule was removed.
    pub fn remove_rule(&mut self, target: &str) -> bool {
        let norm = normalize_rule_target(target);
        let before = self.overrides.len();
        self.overrides
            .retain(|r| normalize_rule_target(&r.target) != norm);
        self.overrides.len() != before
    }

    /// Resolves the effective `DeliveryUrgency` for an inbound item according to:
    /// 1. Specificity-ordered `overrides` (exact qualified > exact shorthand > scoped wildcard > `*`).
    /// 2. Focus Mode (`* -> notify`, optionally preserving explicit `Interrupt` VIPs when
    ///    `focus_allow_interrupt_vips == true`, while always preserving `Mute`).
    /// 3. Optional per-subscription urgency (`subscription_mode`).
    /// 4. Session `default_mode`.
    /// 5. Security Gate Stage 1 `downgraded_to_notify` ceiling (can step `Interrupt`/`Queue` down
    ///    to `Notify`, never promotes `Mute`).
    pub fn resolve_urgency(
        &self,
        ctx: &DeliveryTargetContext<'_>,
        subscription_mode: Option<DeliveryUrgency>,
        gate_downgraded_to_notify: bool,
    ) -> DeliveryUrgency {
        self.resolve_urgency_with_cap(
            ctx,
            subscription_mode,
            gate_downgraded_to_notify.then_some(DeliveryUrgency::Notify),
        )
    }

    /// Resolves effective `DeliveryUrgency` with an optional Stage 1 urgency ceiling
    /// (`Some(DeliveryUrgency::Queue)` for RFC 0004 `CapToQueue`, `Some(DeliveryUrgency::Notify)`
    /// for `DowngradeToNotify`). Only steps urgency down (higher rank); never promotes `Mute`
    /// or `Notify` upward.
    pub fn resolve_urgency_with_cap(
        &self,
        ctx: &DeliveryTargetContext<'_>,
        subscription_mode: Option<DeliveryUrgency>,
        gate_max_urgency: Option<DeliveryUrgency>,
    ) -> DeliveryUrgency {
        let mut best_specific: Option<((u8, usize), DeliveryUrgency)> = None;
        let mut wildcard_urgency: Option<DeliveryUrgency> = None;

        for rule in &self.overrides {
            if let Some(score) = rule.match_specificity(ctx) {
                if rule.is_wildcard() {
                    if wildcard_urgency.is_none() {
                        wildcard_urgency = Some(rule.delivery);
                    }
                    continue;
                }
                let better = match best_specific {
                    None => true,
                    Some((prev_score, _)) => score > prev_score,
                };
                if better {
                    best_specific = Some((score, rule.delivery));
                }
            }
        }

        let resolved = if let Some((_, urgency)) = best_specific {
            if urgency == DeliveryUrgency::Mute {
                DeliveryUrgency::Mute
            } else if self.focus_mode {
                if urgency == DeliveryUrgency::Interrupt && self.focus_allow_interrupt_vips {
                    DeliveryUrgency::Interrupt
                } else {
                    DeliveryUrgency::Notify
                }
            } else {
                urgency
            }
        } else if self.focus_mode {
            if wildcard_urgency == Some(DeliveryUrgency::Mute) {
                DeliveryUrgency::Mute
            } else {
                DeliveryUrgency::Notify
            }
        } else if let Some(wu) = wildcard_urgency {
            wu
        } else if let Some(sub_u) = subscription_mode {
            sub_u
        } else {
            self.default_mode
        };

        if let Some(cap) = gate_max_urgency {
            if resolved.rank() < cap.rank() {
                return cap;
            }
        }
        resolved
    }

    /// Clamps and returns the effective single-item token ceiling.
    pub fn max_single_item_tokens(&self) -> usize {
        let share = if self.max_single_item_share.is_finite() {
            self.max_single_item_share.clamp(0.10, 1.0)
        } else {
            DEFAULT_MAX_SINGLE_ITEM_SHARE
        };
        let cap = ((self.max_batch_tokens as f32) * share).floor() as usize;
        cap.max(32).min(self.max_batch_tokens.max(32))
    }
}

/// Borrowed parsed metadata used to match an inbound item against [`DeliveryRule`] targets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryTargetContext<'a> {
    pub origin_node: &'a str,
    pub source: &'a str,
    pub sender_addr: Option<&'a str>,
    pub sender_handle: Option<&'a str>,
    pub channel: Option<&'a str>,
    pub topic: Option<&'a str>,
    pub bridge: Option<&'a str>,
    pub kind: MailboxKind,
}

/// Owned parsed fields extracted from a `MailboxEntry` (used by both policy matching and inbox queries).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedMailboxSource {
    pub origin_node: String,
    pub source: String,
    pub sender_addr: Option<String>,
    pub sender_handle: Option<String>,
    pub channel: Option<String>,
    pub topic: Option<String>,
    pub bridge: Option<String>,
    pub kind: MailboxKind,
}

impl ParsedMailboxSource {
    /// Extracts structured sender, handle, channel, topic, and bridge metadata from a `MailboxEntry`.
    pub fn from_entry(entry: &MailboxEntry) -> Self {
        Self::parse(&entry.origin_node, &entry.source, entry.kind)
    }

    /// Extracts structured metadata from raw `(origin_node, source, kind)` fields.
    pub fn parse(origin_node: &str, source: &str, kind: MailboxKind) -> Self {
        let origin = origin_node.trim().to_string();
        let src = source.trim().to_string();
        let mut sender_addr: Option<String> = None;
        let mut sender_handle: Option<String> = None;
        let mut channel: Option<String> = None;
        let mut topic: Option<String> = None;
        let mut bridge: Option<String> = None;

        match kind {
            MailboxKind::Message | MailboxKind::Transfer => {
                // Format 1: `<host>/#channel:<sender_node>/<sender_handle>` (UnifiedNode channel post)
                if let Some((left, right)) = src.split_once(':') {
                    if let Some((_, ch)) = left.split_once("/#") {
                        channel = Some(format!("#{ch}"));
                        sender_addr = Some(right.to_string());
                        if let Some((_, handle)) = parse_address(right) {
                            sender_handle = Some(handle.to_string());
                        }
                    } else if left.starts_with('#') {
                        channel = Some(left.to_string());
                        sender_addr = Some(right.to_string());
                        if let Some((_, handle)) = parse_address(right) {
                            sender_handle = Some(handle.to_string());
                        }
                    }
                }
                // Format 2: bare `#channel`
                if channel.is_none() && src.starts_with('#') {
                    channel = Some(src.clone());
                }
                // Format 3: `<node>/<handle>` DM
                if sender_addr.is_none() {
                    if let Some((_, handle)) = parse_address(&src) {
                        sender_addr = Some(src.clone());
                        sender_handle = Some(handle.to_string());
                    } else if let Some(h) = src.strip_prefix('@') {
                        if !h.is_empty() {
                            sender_handle = Some(h.to_string());
                        }
                    }
                }
            }
            MailboxKind::Event | MailboxKind::Kv => {
                // Format: `<origin_node>.<topic>` (e.g. `public.hyphae.to.github` or `local.github`)
                let prefix = format!("{origin}.");
                if let Some(rest) = src.strip_prefix(&prefix) {
                    if !rest.is_empty() {
                        topic = Some(rest.to_string());
                    }
                } else if let Some(rest) = src.strip_prefix("local.") {
                    if !rest.is_empty() {
                        topic = Some(rest.to_string());
                    }
                } else if let Some(rest) = src.strip_prefix("topic:") {
                    if !rest.is_empty() {
                        topic = Some(rest.to_string());
                    }
                } else if !src.is_empty() {
                    if let Some((_, last)) = src.rsplit_once('.') {
                        topic = Some(last.to_string());
                    } else {
                        topic = Some(src.clone());
                    }
                }
            }
            MailboxKind::Plugin => {
                if !src.is_empty() {
                    bridge = Some(src.clone());
                }
            }
        }

        Self {
            origin_node: origin,
            source: src,
            sender_addr,
            sender_handle,
            channel,
            topic,
            bridge,
            kind,
        }
    }

    pub fn as_context(&self) -> DeliveryTargetContext<'_> {
        DeliveryTargetContext {
            origin_node: &self.origin_node,
            source: &self.source,
            sender_addr: self.sender_addr.as_deref(),
            sender_handle: self.sender_handle.as_deref(),
            channel: self.channel.as_deref(),
            topic: self.topic.as_deref(),
            bridge: self.bridge.as_deref(),
            kind: self.kind,
        }
    }

    /// Stable normalized source key for per-source burst tracking.
    pub fn burst_source_key(&self) -> String {
        if let Some(ref ch) = self.channel {
            return format!(
                "{}/{}",
                self.origin_node.to_ascii_lowercase(),
                ch.to_ascii_lowercase()
            );
        }
        if let Some(ref t) = self.topic {
            return format!(
                "{}.{}",
                self.origin_node.to_ascii_lowercase(),
                t.to_ascii_lowercase()
            );
        }
        if let Some(ref br) = self.bridge {
            return br.to_ascii_lowercase();
        }
        if let Some(ref addr) = self.sender_addr {
            return addr.to_ascii_lowercase();
        }
        self.source.to_ascii_lowercase()
    }
}

pub(crate) fn normalize_rule_target(raw: &str) -> String {
    raw.trim().to_ascii_lowercase()
}

pub(crate) fn normalize_channel_lower(raw: &str) -> String {
    let low = raw.trim().to_ascii_lowercase();
    if low.starts_with('#') {
        low
    } else {
        format!("#{low}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_specificity_and_focus_mode_with_vip_override() {
        let policy = SessionDeliveryPolicy::focus_mode()
            .with_rule("@oncall", DeliveryUrgency::Interrupt)
            .with_rule("#deploys", DeliveryUrgency::Mute)
            .with_rule("public.hyphae.to.*", DeliveryUrgency::Notify);

        let oncall =
            ParsedMailboxSource::parse("acme-team", "ops@host/oncall", MailboxKind::Message);
        assert_eq!(
            policy.resolve_urgency(&oncall.as_context(), None, false),
            DeliveryUrgency::Interrupt
        );

        // Strict Focus Mode disables VIP interrupt pass-through.
        let strict_focus = policy.clone().with_focus_mode(true, false);
        assert_eq!(
            strict_focus.resolve_urgency(&oncall.as_context(), None, false),
            DeliveryUrgency::Notify
        );

        // Normal peer demoted to Notify in Focus Mode.
        let alice =
            ParsedMailboxSource::parse("acme-team", "alice@mac/claude", MailboxKind::Message);
        assert_eq!(
            policy.resolve_urgency(&alice.as_context(), None, false),
            DeliveryUrgency::Notify
        );

        // Muted channel stays Mute even in Focus Mode.
        let deploy = ParsedMailboxSource::parse(
            "acme-team",
            "acme-team/#deploys:ci@runner/bot",
            MailboxKind::Message,
        );
        assert_eq!(
            policy.resolve_urgency(&deploy.as_context(), None, false),
            DeliveryUrgency::Mute
        );

        // Stage 1 gate downgrade steps VIP Interrupt down to Notify.
        assert_eq!(
            policy.resolve_urgency(&oncall.as_context(), None, true),
            DeliveryUrgency::Notify
        );
    }

    #[test]
    fn exact_topic_beats_wildcard_regardless_of_rule_order() {
        let policy = SessionDeliveryPolicy::default()
            .with_rule("public.hyphae.to.*", DeliveryUrgency::Notify)
            .with_rule("public.hyphae.to.security", DeliveryUrgency::Interrupt);

        let sec = ParsedMailboxSource::parse(
            "public.hyphae.to",
            "public.hyphae.to.security",
            MailboxKind::Event,
        );
        let gh = ParsedMailboxSource::parse(
            "public.hyphae.to",
            "public.hyphae.to.github",
            MailboxKind::Event,
        );

        assert_eq!(
            policy.resolve_urgency(&sec.as_context(), None, false),
            DeliveryUrgency::Interrupt
        );
        assert_eq!(
            policy.resolve_urgency(&gh.as_context(), None, false),
            DeliveryUrgency::Notify
        );
    }
}
